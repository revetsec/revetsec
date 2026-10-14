#!/usr/bin/env python3
# Copyright 2026 Revetware LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Qualify the actual Soklet SCIM example with pinned independent clients."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = Path(__file__).resolve().parent
PINS = json.loads((HERE / "pins.json").read_text())
REQUIRED_OUTCOMES = ["user-create", "group-create-with-member", "membership-add", "membership-remove",
                     "group-update", "user-update-deactivate", "unchanged-sync-no-write", "delete-and-empty-collection"]
ENTERPRISE_URI = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"


def identified_default_fixture_errors(report, wire):
    errors = [row for row in report.get("checks", []) if row.get("status") in {"ERROR", "CRITICAL", "DEVIATION"}]
    if (len(errors) != 2 or {(row.get("title"), row.get("resourceType")) for row in errors}
            != {("check_add_attribute", "User"), ("check_replace_attribute", "User")}):
        return False
    if any(ENTERPRISE_URI not in row.get("reason", "") or "Invalid attribute path" not in row.get("reason", "") for row in errors):
        return False
    captured = set()
    for row in wire:
        body = row.get("requestBodyShape", {})
        operations = body.get("Operations", []) if isinstance(body, dict) else []
        if len(operations) == 1:
            operation = operations[0]
            if operation.get("path") == ENTERPRISE_URI and operation.get("value", {}).get("schemas") == [ENTERPRISE_URI]:
                captured.add(operation.get("op"))
    return captured == {"add", "replace"}


def checked(*arguments, timeout=300, **keywords):
    return subprocess.run(arguments, check=True, text=True, capture_output=True, timeout=timeout, **keywords)


def digest_tree(directory):
    digest = hashlib.sha256()
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            digest.update(str(path.relative_to(directory)).encode() + b"\0")
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def prepare_application(directory, classes, class_path):
    application = directory / "application"
    shutil.copytree(classes, application / "classes")
    (application / "libraries").mkdir()
    for index, entry in enumerate(class_path.split(os.pathsep)):
        jar = Path(entry).resolve()
        if jar.is_file() and jar.suffix == ".jar":
            shutil.copyfile(jar, application / "libraries" / (str(index) + "-" + jar.name))
        elif jar.resolve() != classes.resolve():
            raise ValueError("the runtime class path may contain only jars and the supplied classes directory")
    (directory / "Dockerfile").write_text(
        "FROM " + PINS["java"]["image"] + "\nCOPY application /app\nUSER 10001:10001\n"
        'ENTRYPOINT ["java","-cp","/app/classes:/app/libraries/*","example.playground.ScimPlayground"]\n')
    return digest_tree(application)


def prepare_tls(directory, openssl):
    tls = directory / "tls"
    tls.mkdir()
    ca_config = tls / "ca.cnf"
    ca_config.write_text("[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ca\n"
                         "[dn]\nCN=Revetsec disposable SCIM CA\n[ca]\n"
                         "basicConstraints=critical,CA:TRUE,pathlen:0\n"
                         "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
                         "authorityKeyIdentifier=keyid:always\n")
    checked(openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-config", str(ca_config), "-keyout", str(tls / "ca.key"), "-out", str(tls / "ca.crt"))
    checked(openssl, "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=scim-target",
            "-keyout", str(tls / "leaf.key"), "-out", str(tls / "leaf.csr"))
    extensions = tls / "extensions.cnf"
    extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                          "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,DNS:scim-target,IP:127.0.0.1\n"
                          "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    checked(openssl, "x509", "-req", "-in", str(tls / "leaf.csr"), "-CA", str(tls / "ca.crt"),
            "-CAkey", str(tls / "ca.key"), "-CAcreateserial", "-days", "2", "-extfile", str(extensions),
            "-out", str(tls / "leaf.crt"))
    for hostname in ("localhost", "scim-target"):
        checked(openssl, "verify", "-CAfile", str(tls / "ca.crt"), "-verify_hostname", hostname, str(tls / "leaf.crt"))
    rejected = subprocess.run([openssl, "verify", "-CAfile", str(tls / "ca.crt"), "-verify_hostname",
                               "foreign.example.test", str(tls / "leaf.crt")], capture_output=True, timeout=20)
    if rejected.returncode == 0:
        raise RuntimeError("foreign hostname unexpectedly accepted")
    return tls


def wait_ready(url, ca_file, token):
    context = ssl.create_default_context(cafile=str(ca_file))
    deadline = time.monotonic() + 60
    while True:
        try:
            request = urllib.request.Request(url + "/ServiceProviderConfig", headers={"Authorization": "Bearer " + token})
            with urllib.request.urlopen(request, context=context, timeout=5) as response:
                if response.status == 200:
                    # This is an actual trust-negative control, not just cert metadata.
                    try:
                        urllib.request.urlopen(request, context=ssl.create_default_context(), timeout=5)
                    except urllib.error.URLError as rejected:
                        if isinstance(rejected.reason, ssl.SSLCertVerificationError):
                            return
                        raise RuntimeError("default-trust control failed for a reason other than certificate validation") from rejected
                    raise RuntimeError("private CA unexpectedly trusted by the default store")
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("SCIM example did not become ready within 60 seconds")
            time.sleep(min(0.1, remaining))


def edge_binding(docker, container):
    deadline = time.monotonic() + 20
    while True:
        state = json.loads(checked(docker, "inspect", container).stdout)[0]
        ports = state["NetworkSettings"]["Ports"].get("8443/tcp")
        if ports:
            return ports[0]
        if state["State"]["Status"] in {"exited", "dead"}:
            logs = checked(docker, "logs", container)
            print((logs.stdout + logs.stderr)[-3000:], file=sys.stderr)
            raise RuntimeError("TLS edge exited before publishing its loopback port")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("TLS edge did not publish a loopback port")
        time.sleep(min(0.1, remaining))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--classes", type=Path, required=True)
    parser.add_argument("--class-path-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--mode", choices=("tester", "both"), default="both",
                        help="PR tester-only qualification or tester plus outbound-client qualification")
    parser.add_argument("--diagnostic-request-directory", type=Path,
                        help="Explicit private directory for capped synthetic non-credential failure captures")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output directory must be new to prevent stale qualification evidence")
    args.output.mkdir(parents=True)
    started = time.monotonic()
    run_id = os.environ.get("GITHUB_RUN_ID")
    report = {"formatVersion": 1, "outcome": "failed", "requiredOutcomes": [],
              "mode": args.mode,
              "githubRunId": run_id, "githubRunAttempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
              "githubEvent": os.environ.get("GITHUB_EVENT_NAME", "local"),
              "githubSha": os.environ.get("GITHUB_SHA"), "evidenceKind": "live-independent-clients",
              "pinsSha256": hashlib.sha256((HERE / "pins.json").read_bytes()).hexdigest()}
    tooling = hashlib.sha256()
    for name in ("run.py", "tester.py", "authentik-outbound.py", "authentik-default-shape.py", "requirements.txt", "python-pins.json"):
        tooling.update(name.encode() + b"\0" + hashlib.sha256((HERE / name).read_bytes()).digest())
    report["toolingSha256"] = tooling.hexdigest()
    stage = "prepare-application"
    containers = []
    network = "revetsec-scim-" + secrets.token_hex(6)
    frontend = network + "-edge"
    image = network + ":qualification"
    network_created = False
    frontend_created = False
    image_created = False
    try:
        with tempfile.TemporaryDirectory(prefix="revetsec-scim-private-") as temporary:
            private = Path(temporary)
            report["applicationArtifactSha256"] = prepare_application(private, args.classes, args.class_path_file.read_text().strip())
            tls = prepare_tls(private, args.openssl)
            token = secrets.token_urlsafe(36)
            products = ("java", "caddy") if args.mode == "tester" else ("java", "caddy", "postgres", "authentik")
            for product in products:
                stage = "pull-" + product
                checked(args.docker, "pull", PINS[product]["image"], timeout=900)
            if args.mode == "both":
                stage = "reproduce-pinned-default-mode-defect"
                with (HERE / "authentik-default-shape.py").open() as script:
                    reproduced = checked(args.docker, "run", "--rm", "-i", "--network", "none", "--entrypoint", "python",
                                         PINS["authentik"]["image"], "-", stdin=script, timeout=30)
                defect = json.loads(reproduced.stdout)
                if defect["productionGroupClientSha256"] != PINS["authentik"]["defaultModeDisposition"]["productionGroupClientSha256"]:
                    raise RuntimeError("the pinned default-mode defect source changed")
                (args.output / "authentik-default-mode-defect.json").write_text(json.dumps(defect, indent=2) + "\n")
                report["defaultModeDisposition"] = defect["outcome"]
            stage = "build-application"
            checked(args.docker, "build", "-t", image, str(private), timeout=300)
            image_created = True
            checked(args.docker, "network", "create", "--internal", network)
            network_created = True
            # Docker 29 does not allocate host port bindings on an internal-only
            # network. Only the edge joins this separate loopback publication bridge.
            checked(args.docker, "network", "create", frontend)
            frontend_created = True

            def start(name, *arguments, network_name=None):
                full_name = network + "-" + name
                checked(args.docker, "run", "-d", "--name", full_name, "--network", network_name or network,
                        "--network-alias", name, *arguments)
                containers.append(full_name)
                return full_name

            stage = "start-application-and-tls-edge"
            app = start("scim-app", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
                        "--tmpfs", "/tmp", "-e", "SCIM_HTTP_HOST=0.0.0.0", "-e", "SCIM_HTTP_PORT=8082",
                        "-e", "SCIM_BASE_URI=https://scim-target:8443/scim/v2/", "-e", "SCIM_BEARER_TOKEN=" + token, image)
            caddyfile = private / "Caddyfile"
            caddyfile.write_text("{\n admin off\n auto_https off\n}\n:8443 {\n tls /tls/leaf.crt /tls/leaf.key\n"
                                 " reverse_proxy scim-app:8082\n}\n")
            edge_tls = private / "edge-tls"
            edge_tls.mkdir()
            for name in ("leaf.crt", "leaf.key"):
                shutil.copyfile(tls / name, edge_tls / name)
                (edge_tls / name).chmod(0o444)
            # The official caddy binary has a NET_BIND_SERVICE file capability;
            # excluding it from the bounding set prevents exec even on port8443.
            edge = start("scim-target", "-p", "127.0.0.1::8443", "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE",
                         "--security-opt", "no-new-privileges",
                         "--tmpfs", "/data", "--tmpfs", "/config",
                         "--mount", "type=bind,source=" + str(edge_tls) + ",target=/tls,readonly",
                         "--mount", "type=bind,source=" + str(caddyfile) + ",target=/etc/caddy/Caddyfile,readonly",
                         PINS["caddy"]["image"], network_name=frontend)
            checked(args.docker, "network", "connect", "--alias", "scim-target", network, edge)
            binding = edge_binding(args.docker, edge)
            base_url = "https://localhost:" + binding["HostPort"] + "/scim/v2"
            stage = "wait-verified-tls-application"
            wait_ready(base_url, tls / "ca.crt", token)
            environment = os.environ.copy()
            environment["SCIM_BEARER_TOKEN"] = token
            tester_command = [args.python, str(HERE / "tester.py"), "--base-url", base_url,
                              "--ca-file", str(tls / "ca.crt")]
            default_command = tester_command + ["--profile", "default", "--output", str(args.output / "tester-default.json")]
            if args.diagnostic_request_directory:
                default_command.extend(["--diagnostic-request-directory", str(args.diagnostic_request_directory)])
            default = subprocess.run(default_command, env=environment, text=True, capture_output=True, timeout=600)
            (args.output / "tester-default-console.txt").write_text(default.stdout)
            (args.output / "tester-default-error.txt").write_text(default.stderr)
            default_file = args.output / "tester-default.json"
            default_report = json.loads(default_file.read_text()) if default_file.is_file() else {}
            default_wire_file = args.output / "tester-default-wire-errors.json"
            default_wire = json.loads(default_wire_file.read_text()) if default_wire_file.is_file() else []
            default_identified = identified_default_fixture_errors(default_report, default_wire)
            report["testerDefaultOutcome"] = "failed-with-identified-fixture-defect" if default_identified else "unexplained"
            checked(args.docker, "restart", app)
            wait_ready(base_url, tls / "ca.crt", token)
            completed = subprocess.run(tester_command + ["--profile", "configured", "--output", str(args.output / "tester.json")],
                                       env=environment, text=True, capture_output=True, timeout=600)
            (args.output / "tester-console.txt").write_text(completed.stdout)
            tester_report_file = args.output / "tester.json"
            tester_report = json.loads(tester_report_file.read_text()) if tester_report_file.is_file() else {}
            tester_passed = (default_identified and completed.returncode == 0 and tester_report.get("outcome") == "passed"
                             and tester_report.get("tool") == "scim2-tester" and tester_report.get("version") == "0.5.2"
                             and tester_report.get("profile") == "configured" and tester_report.get("missingRequiredTags") == [])
            report["testerProfile"] = "discovered-extension-schemas-field-excluded"
            if not tester_passed:
                (args.output / "tester-error.txt").write_text(completed.stderr)

            if args.mode == "tester":
                report["testerOutcome"] = "passed" if tester_passed else "failed"
                report["authentikOutcome"] = "not-run"
                report["evidenceKind"] = "live-independent-tester"
                report["tlsControls"] = ["scoped-ca-positive", "default-trust-negative", "foreign-hostname-negative"]
                report["outcome"] = report["testerOutcome"]
                print(json.dumps({"outcome": report["outcome"], "mode": args.mode}))
                raise SystemExit(0 if tester_passed else 1)

            # Clients get independent fresh application state. Tester setup/cleanup
            # failures must not contaminate the outbound client's outcome checks.
            stage = "reset-application-for-outbound-client"
            checked(args.docker, "restart", app)
            wait_ready(base_url, tls / "ca.crt", token)
            password = secrets.token_urlsafe(36)
            stage = "start-authentik-database"
            database = start("database", "--tmpfs", "/var/lib/postgresql/data", "-e", "POSTGRES_USER=authentik",
                             "-e", "POSTGRES_DB=authentik", "-e", "POSTGRES_PASSWORD=" + password, PINS["postgres"]["image"])
            ready_deadline = time.monotonic() + 30
            while subprocess.run([args.docker, "exec", database, "pg_isready", "-U", "authentik", "-d", "authentik"],
                                 capture_output=True, timeout=5).returncode:
                remaining = ready_deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("private authentik database did not become ready")
                time.sleep(min(0.1, remaining))
            authentik_options = ["--network", network, "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
                                 "-e", "AUTHENTIK_POSTGRESQL__HOST=database", "-e", "AUTHENTIK_POSTGRESQL__USER=authentik",
                                 "-e", "AUTHENTIK_POSTGRESQL__NAME=authentik", "-e", "AUTHENTIK_POSTGRESQL__PASSWORD=" + password,
                                 "-e", "AUTHENTIK_SECRET_KEY=" + secrets.token_urlsafe(48),
                                 "-e", "AUTHENTIK_ERROR_REPORTING__ENABLED=false", "-e", "AUTHENTIK_LOG_LEVEL=warning",
                                 "-e", "SCIM_BASE_URI=https://scim-target:8443/scim/v2/", "-e", "SCIM_BEARER_TOKEN=" + token,
                                 "-e", "REQUESTS_CA_BUNDLE=/qualification/ca.crt", "--mount",
                                 "type=bind,source=" + str(tls / "ca.crt") + ",target=/qualification/ca.crt,readonly"]
            migration_container = network + "-migrate"
            containers.append(migration_container)
            migrated = checked(args.docker, "run", "--rm", "--name", migration_container, *authentik_options, "--entrypoint", "python",
                               PINS["authentik"]["image"], "-m", "lifecycle.migrate", timeout=600)
            # No credentials or raw payloads are retained. Migration logs are metadata only.
            (args.output / "authentik-migrations.txt").write_text(migrated.stdout)
            with (HERE / "authentik-outbound.py").open() as script:
                stage = "authentik-outbound"
                outbound_container = network + "-outbound"
                containers.append(outbound_container)
                outbound = checked(args.docker, "run", "--rm", "--name", outbound_container, "-i", *authentik_options,
                                   PINS["authentik"]["image"], "shell", stdin=script, timeout=300)
            marker = "REVETSEC_SCIM_OUTBOUND="
            summaries = [line[len(marker):] for line in outbound.stdout.splitlines() if line.startswith(marker)]
            if len(summaries) != 1:
                raise RuntimeError("authentik did not produce exactly one completed outcome record")
            client_report = json.loads(summaries[0])
            (args.output / "authentik.json").write_text(json.dumps(client_report, indent=2) + "\n")
            if (client_report["requiredOutcomes"] != REQUIRED_OUTCOMES
                    or client_report["compatibilityMode"] != PINS["authentik"]["qualifyingCompatibilityMode"]
                    or client_report.get("outcome") != "passed"
                    or client_report.get("certificateVerification") is not True
                    or client_report.get("dryRun") is not False):
                raise RuntimeError("authentik required outcome set is incomplete")
            report["requiredOutcomes"] = client_report["requiredOutcomes"]
            report["testerOutcome"] = "passed" if tester_passed else "failed"
            report["authentikOutcome"] = client_report["outcome"]
            report["authentikCompatibilityMode"] = client_report["compatibilityMode"]
            report["tlsControls"] = ["scoped-ca-positive", "default-trust-negative", "foreign-hostname-negative"]
            if not tester_passed:
                stage = "combined-required-outcomes"
                raise RuntimeError("independent tester reported failures; inspect tester.json")
            report["outcome"] = "passed"
    except (subprocess.SubprocessError, OSError, RuntimeError, ValueError) as failure:
        # Commands can carry ephemeral passwords in their args; never stringify a
        # CalledProcessError. Capture a fixed failure class and the failing executable.
        report["failureClass"] = type(failure).__name__
        report["failedStage"] = stage
        if isinstance(failure, subprocess.CalledProcessError):
            diagnostic = (failure.stdout or "") + (failure.stderr or "")
            for sensitive in (locals().get("token"), locals().get("password")):
                if sensitive:
                    diagnostic = diagnostic.replace(sensitive, "[redacted]")
            # A bounded console excerpt aids repair. The fixture has synthetic identities;
            # commands and their secret-bearing environment arguments are never rendered.
            print(diagnostic[-12000:], file=sys.stderr)
        print("SCIM qualification failed at " + stage + ": " + type(failure).__name__, file=sys.stderr)
    finally:
        for container in reversed(containers):
            subprocess.run([args.docker, "rm", "-fv", container], capture_output=True, timeout=30)
        if frontend_created:
            subprocess.run([args.docker, "network", "rm", frontend], capture_output=True, timeout=30)
        if network_created:
            subprocess.run([args.docker, "network", "rm", network], capture_output=True, timeout=30)
        if image_created:
            subprocess.run([args.docker, "image", "rm", image], capture_output=True, timeout=30)
        report["elapsedSeconds"] = round(time.monotonic() - started, 3)
        (args.output / "qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("outcome", "githubEvent", "elapsedSeconds")}))
    raise SystemExit(0 if report["outcome"] == "passed" else 1)


if __name__ == "__main__":
    main()
