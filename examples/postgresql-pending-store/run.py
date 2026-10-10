#!/usr/bin/env python3
"""Run the application storage examples against an owned, cached PostgreSQL container.

This is a local protocol check. It never archives callback state or database credentials.
"""
from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
import os
from pathlib import Path
import re
import select
import secrets
import socket
import subprocess
import tempfile
import threading
import time
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlsplit
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parent
APP_ROOT = ROOT.parent / "self-issued"
IMAGE = "sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a"


def docker(*args: str, input_text: str | None = None) -> str:
    result = subprocess.run(["docker", *args], input=input_text, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError("Owned PostgreSQL operation failed: " + " ".join(args[:2]))
    return result.stdout.strip()


def check(condition: bool, label: str) -> None:
    if not condition:
        raise RuntimeError("PostgreSQL example check failed: " + label)
    print(label + ": PASS", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("java-home", "core-jar", "pyranid-jar", "driver-jar", "jspecify-jar", "jsr305-jar"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--adapter-jar", type=Path)
    parser.add_argument("--framework-jar", type=Path)
    args = parser.parse_args()
    if (args.adapter_jar is None) != (args.framework_jar is None):
        parser.error("Supply both the Soklet adapter and framework JARs for the application lane")
    paths = [args.core_jar, args.pyranid_jar, args.driver_jar, args.jspecify_jar, args.jsr305_jar]
    app_lane = args.adapter_jar is not None
    if app_lane:
        paths.extend((args.adapter_jar, args.framework_jar))
    if not all(path.is_file() for path in paths) or not (args.java_home / "bin/java").is_file():
        parser.error("All input JARs and the Java home must exist")
    if app_lane and hashlib.sha256(args.framework_jar.read_bytes()).hexdigest() != (
            "c454eac7ff5fd58d564a2c1603133ed1c47a01210d2910be4d60f392ebe1184f"):
        parser.error("Use the pinned Soklet 4.0.0 framework JAR for the application lane")
    check(docker("image", "inspect", "--format", "{{.Id}}", IMAGE) == IMAGE, "cached-image")

    with tempfile.TemporaryDirectory(prefix="revetsec-pending-") as work_name:
        work = Path(work_name)
        classes = work / "classes"
        classes.mkdir()
        classpath = os.pathsep.join(map(str, [classes, *paths]))
        sources = [ROOT / "src/main/java/example/pending/PostgresqlPyranidDataSource.java",
                   ROOT / "src/main/java/example/pending/PostgresqlPendingAuthorizationStore.java",
                   ROOT / "src/main/java/example/pending/PostgresqlClientMetadataCache.java",
                   ROOT / "src/main/java/example/pending/PostgresqlIssuerStore.java",
                   ROOT / "src/test/java/example/pending/PendingStoreProbe.java",
                   ROOT / "src/test/java/example/pending/ClientMetadataCacheProbe.java",
                   ROOT / "src/test/java/example/pending/IssuerStoreProbe.java",
                   ROOT / "src/test/java/example/pending/RsaFixtureSigner.java"]
        if app_lane:
            sources.extend(sorted((APP_ROOT / "src/main/java/example/issuer").glob("*.java")))
            sources.append(ROOT / "src/test/java/example/issuer/PostgresqlBrowserSessions.java")
            sources.append(ROOT / "src/test/java/example/issuer/PostgresqlIssuerApplicationProbe.java")
        compiled = subprocess.run([str(args.java_home / "bin/javac"), "--release", "17", "-proc:none", "-Xlint:all",
                                   "-Werror", "-cp", os.pathsep.join(map(str, paths)), "-d", str(classes),
                                   *map(str, sources)], capture_output=True, text=True, timeout=60)
        if compiled.returncode:
            raise RuntimeError("Warning-fatal example compilation failed:\n" + compiled.stderr[-4000:])
        print("warning-fatal-compile: PASS", flush=True)

        suffix = secrets.token_hex(5)
        name = "revetsec-pending-" + suffix
        network = name + "-net"
        volume = name + "-data"
        password = secrets.token_urlsafe(24)
        oidc_secret = secrets.token_urlsafe(48)
        issuer_time = str(1791288000)
        issuer_secrets = work / "issuer-secrets"
        issuer_secrets.mkdir(mode=0o700)
        def unused_loopback_port() -> int:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", 0))
                return int(listener.getsockname()[1])

        app_http_port = unused_loopback_port()
        app_mcp_port = unused_loopback_port()
        while app_mcp_port == app_http_port:
            app_mcp_port = unused_loopback_port()
        db_port = unused_loopback_port()
        while db_port in (app_http_port, app_mcp_port):
            db_port = unused_loopback_port()
        env_file = work / "postgres.env"
        env_file.write_text("POSTGRES_PASSWORD=" + password + "\nPOSTGRES_DB=pending_fixture\n")
        env_file.chmod(0o600)
        created: list[tuple[str, str]] = []
        try:
            docker("network", "create", "--label", "com.revetsec.owned-fixture=true", network)
            created.append(("network", network))
            docker("volume", "create", "--label", "com.revetsec.owned-fixture=true", volume)
            created.append(("volume", volume))
            docker("run", "-d", "--pull=never", "--name", name, "--network", network,
                   "-p", "127.0.0.1:" + str(db_port) + ":5432", "--env-file", str(env_file),
                   "--mount", "type=volume,source=" + volume + ",target=/var/lib/postgresql", IMAGE)
            created.append(("container", name))

            def ready() -> None:
                for _ in range(80):
                    result = subprocess.run(["docker", "exec", name, "pg_isready", "-h", "127.0.0.1",
                                             "-U", "postgres", "-d", "pending_fixture"], capture_output=True,
                                            timeout=10)
                    if result.returncode == 0:
                        return
                    time.sleep(0.25)
                raise RuntimeError("Owned PostgreSQL primary did not become ready")

            ready()
            schema = (ROOT / "schema.sql").read_text()
            docker("exec", "-i", name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres",
                   "-d", "pending_fixture", input_text=schema + "\nINSERT INTO pending_authorization_clock "
                   "(namespace,observed_seconds,observed_nanos) VALUES ('fixture',0,0),('fixture_clock',0,0);\n"
                   "INSERT INTO cimd_cache_namespace(namespace,next_order) VALUES ('fixture_cache',0);\n")
            docker("exec", "-i", name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres",
                   "-d", "pending_fixture", input_text="INSERT INTO issuer_store_namespace(namespace) "
                   "VALUES ('fixture_issuer'),('fixture_issuer_unknown'),('fixture_issuer_fence'),"
                   "('fixture_issuer_app');\n")
            docker("exec", "-i", name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres",
                   "-d", "pending_fixture", input_text="INSERT INTO issuer_browser_namespace"
                   "(namespace,observed_seconds,observed_nanos) VALUES ('fixture_issuer_browser',0,0);\n")

            def db_env() -> dict[str, str]:
                port = int(docker("port", name, "5432/tcp").rsplit(":", 1)[1])
                if port != db_port:
                    raise RuntimeError("Owned PostgreSQL loopback port changed")
                return dict(os.environ, REVETSEC_TEST_DB_URL=("jdbc:postgresql://127.0.0.1:" + str(port)
                                + "/pending_fixture?sslmode=disable&gssEncMode=disable"),
                            REVETSEC_TEST_DB_USER="postgres", REVETSEC_TEST_DB_PASSWORD=password,
                            REVETSEC_TEST_OIDC_SECRET=oidc_secret,
                            REVETSEC_TEST_ISSUER_TIME=issuer_time,
                            REVETSEC_TEST_ISSUER_SECRET_DIR=str(issuer_secrets),
                            REVETSEC_TEST_ISSUER_HTTP_PORT=str(app_http_port),
                            REVETSEC_TEST_ISSUER_MCP_PORT=str(app_mcp_port))

            current_db_env = db_env()

            def run_probe(probe: str, *arguments: str) -> str:
                class_name = probe if probe.startswith("example.") else "example.pending." + probe
                done = subprocess.run([str(args.java_home / "bin/java"), "-cp", classpath,
                                       class_name, *arguments], env=current_db_env,
                                      input="", capture_output=True, text=True, timeout=20)
                if done.returncode:
                    classes = re.findall(r"(?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*(?:Exception|Error)", done.stderr)
                    missing = re.search(r"ClassNotFoundException: ([A-Za-z0-9_.$/]+)", done.stderr)
                    raise RuntimeError("JVM probe failed in " + arguments[0]
                                       + ", exit=" + str(done.returncode) + ", types=" + ",".join(classes[:5])
                                       + (", missing=" + missing.group(1) if missing else ""))
                return done.stdout.strip()

            def run(*arguments: str) -> str:
                return run_probe("PendingStoreProbe", *arguments)

            def run_cache(*arguments: str) -> str:
                return run_probe("ClientMetadataCacheProbe", *arguments)

            def run_issuer(*arguments: str) -> str:
                return run_probe("IssuerStoreProbe", *arguments)

            def issuer_pair(output: str, label: str) -> tuple[str, str]:
                match = re.fullmatch(r"PAIR:([A-Za-z0-9_.-]+)\t([A-Za-z0-9_.-]+)", output)
                check(match is not None, label)
                assert match is not None
                return match.group(1), match.group(2)

            def key_generation(value: str) -> None:
                pending = issuer_secrets / "key-generation.pending"
                pending.write_text(value, encoding="ascii")
                pending.replace(issuer_secrets / "key-generation.txt")

            def token_key_id(value: str) -> str:
                encoded = value.split(".", 1)[0]
                return str(json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))["kid"])

            for mode, expected in (("duplicate", "DUPLICATE_REJECTED"), ("expiry", "EXPIRED_ABSENT"),
                                   ("zero-budget", "ZERO_BUDGET_NO_MUTATION"),
                                   ("long-budget", "LONG_BUDGET_BOUNDED"),
                                   ("unknown-consume", "UNKNOWN_COMMIT_NO_RELEASE"),
                                   ("capacity", "CAPACITY_NO_EVICTION"), ("future-fence", "ROLLBACK_FENCED")):
                check(run(mode) == expected, mode)

            def cache_hit(version: int) -> str:
                nonce = base64.urlsafe_b64encode(version.to_bytes(4, "big") + bytes(28)).rstrip(b"=").decode("ascii")
                return "HIT:" + nonce + ":synthetic-encrypted-envelope-" + str(version)

            check(run_cache("cas", "1", "0", "11") == "TRUE", "cache-insert")
            check(run_cache("read", "1") == cache_hit(11), "cache-cross-jvm-read")
            check(run_cache("cas", "1", "12", "13") == "FALSE", "cache-stale-version-no-write")
            check(run_cache("read", "1") == cache_hit(11), "cache-stale-version-preserves-entry")

            contenders = [subprocess.Popen([str(args.java_home / "bin/java"), "-cp", classpath,
                            "example.pending.ClientMetadataCacheProbe", "race", "1", "11", str(version)],
                            env=current_db_env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True) for version in (13, 14)]
            try:
                check(all(proc.stdout is not None and proc.stdout.readline().strip() == "READY"
                          for proc in contenders), "cache-race-ready")
                for proc in contenders:
                    assert proc.stdin is not None
                    proc.stdin.write("go\n")
                    proc.stdin.flush()
                outcomes = []
                for proc in contenders:
                    output, _ = proc.communicate(timeout=15)
                    check(proc.returncode == 0, "cache-race-jvm")
                    outcomes.append(output.strip())
                check(sorted(outcomes) == ["FALSE", "TRUE"], "cache-cross-jvm-cas-single-winner")
                check(run_cache("read", "1") in (cache_hit(13), cache_hit(14)),
                      "cache-race-winner-retained")
            finally:
                for proc in contenders:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait(timeout=5)

            check(run_cache("cas", "2", "0", "21") == "TRUE", "cache-second-insert")
            check(run_cache("cas", "3", "0", "31") == "TRUE", "cache-capacity-evicts-oldest")
            check(run_cache("read", "1") == "MISS" and run_cache("read", "2") == cache_hit(21)
                  and run_cache("read", "3") == cache_hit(31), "cache-eviction-bounded")
            check(run_cache("unknown", "4", "41") == "UNKNOWN_WRITE_REPORTED",
                  "cache-unknown-commit-fails-closed")
            check(run_cache("read", "4") == cache_hit(41), "cache-unknown-commit-reconciled")
            check(run_cache("close-failure", "4") == "CONFIRMED_READ",
                  "cache-confirmed-close-failure-keeps-result")

            check(run_issuer("keygen") == "KEYS_READY", "issuer-ephemeral-keys")
            if app_lane:
                def run_app(*arguments: str) -> str:
                    return run_probe("example.issuer.PostgresqlIssuerApplicationProbe", *arguments)

                app_access, app_refresh = issuer_pair(run_app("fresh"),
                                                      "application-fresh-issuer-grant")
                check(run_app("established-active", app_access) == "ACTIVE",
                      "application-established-startup-keeps-token")
                check(run_app("fresh-again") == "FRESH_CONFLICT",
                      "application-fresh-reinitialization-refused")
                check(run_app("wrong-seal") == "SEALED_FENCE_REJECTED",
                      "application-wrong-sealing-key-rejected")
                app_rotated_access, app_rotated_refresh = issuer_pair(
                    run_app("established-refresh", app_refresh),
                    "application-established-startup-rotates-refresh")
                check(app_rotated_refresh != app_refresh, "application-refresh-credential-changed")
                check(run_app("established-active", app_rotated_access) == "ACTIVE",
                      "application-new-token-active-across-jvms")
                check(run_app("browser-smoke") == "BROWSER_SMOKE",
                      "application-shared-browser-store-smoke")
                browser_created = re.fullmatch(r"SESSION:([A-Za-z0-9_-]{43})",run_app("browser-create"))
                check(browser_created is not None,"application-shared-browser-race-created")
                assert browser_created is not None
                browser_id = browser_created.group(1)
                browser_contenders = [subprocess.Popen([str(args.java_home / "bin/java"), "-cp", classpath,
                                      "example.issuer.PostgresqlIssuerApplicationProbe", "browser-claim", browser_id],
                                      env=current_db_env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True) for _ in range(2)]
                try:
                    check(all(proc.stdout is not None and proc.stdout.readline().strip() == "READY"
                              for proc in browser_contenders),"application-shared-browser-race-ready")
                    for proc in browser_contenders:
                        assert proc.stdin is not None
                        proc.stdin.write("go\n")
                        proc.stdin.flush()
                    browser_outcomes = []
                    for proc in browser_contenders:
                        output, _ = proc.communicate(timeout=15)
                        check(proc.returncode == 0,"application-shared-browser-race-jvm")
                        browser_outcomes.append(output.strip())
                    check(sorted(browser_outcomes) == ["FALSE","TRUE"],
                          "application-shared-browser-claim-single-winner")
                finally:
                    for proc in browser_contenders:
                        if proc.poll() is None:
                            proc.kill()
                            proc.wait(timeout=5)
                check(run_app("browser-pending",browser_id) == "NONE",
                      "application-shared-browser-claim-persists")

                def issuer_http(method: str, path: str, body: bytes | None = None,
                                headers: dict[str, str] | None = None,
                                port: int = app_http_port, host: str = "127.0.0.1") -> tuple[int, dict[str, str], bytes]:
                    connection = HTTPConnection(host, port, timeout=10)
                    try:
                        connection.request(method, path, body=body, headers=headers or {})
                        response = connection.getresponse()
                        content = response.read(32_769)
                        if len(content) > 32_768:
                            raise RuntimeError("Application HTTP response exceeded fixture bound")
                        return response.status, {name.lower(): value for name, value in response.getheaders()}, content
                    finally:
                        connection.close()

                def hidden_fields(page: bytes) -> dict[str, str]:
                    fields = re.findall(r"<input type='hidden' name='(csrf|flow)' value='([A-Za-z0-9_-]+)'>",
                                        page.decode("utf-8"))
                    check(len(fields) == 2 and {name for name, _ in fields} == {"csrf", "flow"},
                          "application-browser-form-fields")
                    return dict(fields)

                server = subprocess.Popen([str(args.java_home / "bin/java"), "-cp", classpath,
                                           "example.issuer.PostgresqlIssuerApplicationProbe", "serve"],
                                          env=current_db_env, stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    check(server.stdout is not None
                          and bool(select.select([server.stdout], [], [], 10)[0])
                          and server.stdout.readline().strip() == "READY",
                          "application-established-soklet-ready")
                    opener = build_opener(ProxyHandler({}))
                    origin = "http://127.0.0.1:" + str(app_http_port)
                    resource = "http://127.0.0.1:" + str(app_mcp_port) + "/mcp"
                    with opener.open(Request(origin + "/.well-known/oauth-authorization-server"),
                                     timeout=5) as response:
                        metadata = json.loads(response.read(32_768))
                        check(response.status == 200 and metadata.get("issuer") == origin,
                              "application-established-http-metadata")
                    with opener.open(Request(origin + "/jwks"), timeout=5) as response:
                        jwks = json.loads(response.read(32_768))
                        check(response.status == 200 and len(jwks.get("keys", [])) == 1
                              and jwks["keys"][0].get("kid") == "fixture",
                              "application-established-http-jwks")
                    auth = base64.b64encode(("resource-client:" + "C" * 42 + "A").encode("ascii")).decode("ascii")
                    request = Request(origin + "/introspect",
                                      data=urlencode({"token": app_rotated_access}).encode("ascii"),
                                      headers={"Content-Type": "application/x-www-form-urlencoded",
                                               "Authorization": "Basic " + auth}, method="POST")
                    with opener.open(request, timeout=5) as response:
                        verdict = json.loads(response.read(32_768))
                        check(response.status == 200 and verdict.get("active") is True,
                              "application-established-http-introspection")
                    mcp_body = (b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
                                b'"params":{"name":"whoami","arguments":{}}}')
                    mcp_headers = {"Content-Type": "application/json",
                                   "Accept": "application/json, text/event-stream",
                                   "MCP-Protocol-Version": "2025-11-25"}
                    mcp_url = "http://127.0.0.1:" + str(app_mcp_port) + "/mcp"
                    try:
                        opener.open(Request(mcp_url, data=mcp_body, headers=mcp_headers,
                                            method="POST"), timeout=5)
                    except HTTPError as denied:
                        check(denied.code == 401, "application-mcp-requires-bearer")
                        denied.close()
                    else:
                        check(False, "application-mcp-requires-bearer")
                    mcp_headers["Authorization"] = "Bearer " + app_rotated_access
                    with opener.open(Request(mcp_url, data=mcp_body, headers=mcp_headers,
                                             method="POST"), timeout=5) as response:
                        body = response.read(32_768).decode("utf-8")
                        check(response.status == 200 and "Checked identity partition" in body
                              and app_rotated_access not in body and "demo-user" not in body,
                              "application-established-mcp-accepts-persisted-token")
                    first_partition = re.search(r"Checked identity partition: ([A-Za-z0-9_-]{43});", body)
                    check(first_partition is not None, "application-admission-partition-present")
                    check(token_key_id(app_rotated_access) == "fixture",
                          "application-first-generation-signed-token")
                    key_generation("g2")
                    with opener.open(Request(origin + "/jwks"), timeout=5) as response:
                        published = json.loads(response.read(32_768))
                        check(response.status == 200
                              and {key.get("kid") for key in published.get("keys", [])}
                              == {"fixture", "fixture-next"},
                              "application-rotation-publishes-overlap")
                    rotated_body = urlencode({"grant_type": "refresh_token", "client_id": "demo-public",
                                              "refresh_token": app_rotated_refresh,
                                              "resource": resource}).encode("ascii")
                    status, _, content = issuer_http("POST", "/token", rotated_body,
                        {"Content-Type": "application/x-www-form-urlencoded"})
                    rotated = json.loads(content)
                    next_access = rotated.get("access_token", "")
                    check(status == 200 and token_key_id(next_access) == "fixture-next",
                          "application-rotation-signs-with-new-key")
                    with opener.open(request, timeout=5) as response:
                        verdict = json.loads(response.read(32_768))
                        check(response.status == 200 and verdict.get("active") is True,
                              "application-rotation-retains-old-token")
                    check(run_app("established-active", next_access) == "ACTIVE",
                          "application-rotation-new-token-active-across-jvms")
                    key_generation("g3")
                    status, _, content = issuer_http("GET", "/jwks")
                    check(status == 503 and b'"keys"' not in content,
                          "application-early-key-removal-fails-closed")
                    try:
                        opener.open(Request(mcp_url, data=mcp_body, headers=mcp_headers,
                                            method="POST"), timeout=5)
                    except HTTPError as unavailable:
                        check(unavailable.code == 503 and unavailable.headers.get("WWW-Authenticate") is None,
                              "application-early-key-removal-withholds-resource-admission")
                        unavailable.close()
                    else:
                        check(False, "application-early-key-removal-withholds-resource-admission")
                    key_generation("g2")
                    with opener.open(request, timeout=5) as response:
                        verdict = json.loads(response.read(32_768))
                        check(response.status == 200 and verdict.get("active") is True,
                              "application-key-overlap-recovers-after-rejection")
                    check(run_app("established-refresh", app_refresh) == "REJECTED",
                          "application-used-refresh-rejected")
                    try:
                        opener.open(Request(mcp_url, data=mcp_body, headers=mcp_headers,
                                            method="POST"), timeout=5)
                    except HTTPError as denied:
                        check(denied.code == 401, "application-live-mcp-sees-cross-jvm-revocation")
                        denied.close()
                    else:
                        check(False, "application-live-mcp-sees-cross-jvm-revocation")
                    with opener.open(request, timeout=5) as response:
                        verdict = json.loads(response.read(32_768))
                        check(response.status == 200 and verdict.get("active") is False,
                              "application-live-introspection-sees-cross-jvm-revocation")

                    authorization = urlencode({"response_type": "code", "client_id": "demo-public",
                                               "redirect_uri": "https://client.example/cb", "resource": resource,
                                               "scope": "mcp:discover mcp:whoami", "state": "fixture-http",
                                               "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                                               "code_challenge_method": "S256"})
                    status, headers, page = issuer_http("GET", "/authorize?" + authorization)
                    first_cookie = headers.get("set-cookie", "").split(";", 1)[0]
                    check(status == 200 and b"Demo login" in page
                          and bool(re.fullmatch(r"RevetsecIssuerDev=[A-Za-z0-9_-]+", first_cookie))
                          and headers.get("referrer-policy") == "same-origin",
                          "application-http-authorization-login")
                    login = hidden_fields(page)
                    status, headers, _ = issuer_http("POST", "/login",
                        urlencode({**login, "key": "A" * 43}).encode("ascii"),
                        {"Content-Type": "application/x-www-form-urlencoded", "Origin": origin,
                         "Cookie": first_cookie})
                    rotated_cookie = headers.get("set-cookie", "").split(";", 1)[0]
                    check(status == 303 and headers.get("location") == "/consent"
                          and bool(re.fullmatch(r"RevetsecIssuerDev=[A-Za-z0-9_-]+", rotated_cookie))
                          and rotated_cookie != first_cookie,
                          "application-http-login-rotates-session")
                    status, headers, page = issuer_http("GET", "/consent", headers={"Cookie": rotated_cookie})
                    check(status == 200 and b"Consent" in page
                          and b"https://client.example/cb" in page
                          and headers.get("referrer-policy") == "same-origin",
                          "application-http-consent-displays-checked-client")
                    consent = hidden_fields(page)
                    consent_body = urlencode({**consent, "decision": "approve"}).encode("ascii")
                    consent_headers = {"Content-Type": "application/x-www-form-urlencoded",
                                       "Origin": origin, "Cookie": rotated_cookie}
                    status, headers, _ = issuer_http("POST", "/consent", consent_body, consent_headers)
                    callback = urlsplit(headers.get("location", ""))
                    callback_values = parse_qs(callback.query, strict_parsing=True)
                    codes = callback_values.get("code", [])
                    check(status == 303 and callback.scheme == "https"
                          and callback.netloc == "client.example" and callback.path == "/cb"
                          and callback_values.get("state") == ["fixture-http"]
                          and len(codes) == 1 and bool(re.fullmatch(r"[A-Za-z0-9_-]+", codes[0]))
                          and headers.get("referrer-policy") == "no-referrer",
                          "application-http-consent-issues-code")
                    http_code = codes[0]
                    status, _, _ = issuer_http("POST", "/consent", consent_body, consent_headers)
                    check(status == 403, "application-http-consent-single-use")
                    second_env = dict(current_db_env, REVETSEC_TEST_ISSUER_BIND_HOST="::1")
                    second_server = subprocess.Popen([str(args.java_home / "bin/java"), "-cp", classpath,
                                                      "example.issuer.PostgresqlIssuerApplicationProbe", "serve"],
                                                     env=second_env, stdin=subprocess.PIPE,
                                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    try:
                        check(second_server.stdout is not None
                              and bool(select.select([second_server.stdout], [], [], 10)[0])
                              and second_server.stdout.readline().strip() == "READY",
                              "application-second-live-soklet-ready")

                        def second_http(method: str, path: str, body: bytes | None = None,
                                        headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
                            return issuer_http(method, path, body,
                                               {**(headers or {}), "Host": "127.0.0.1:" + str(app_http_port)},
                                               app_http_port, "::1")

                        status, _, page = issuer_http("GET", "/authorize?" + authorization,
                                                      headers={"Cookie": rotated_cookie})
                        live_fields = hidden_fields(page)
                        check(status == 200 and b"Consent" in page,
                              "application-live-nodes-start-authorization")
                        status, _, page = second_http("GET", "/consent",
                                                      headers={"Cookie": rotated_cookie})
                        check(status == 200 and b"Consent" in page
                              and hidden_fields(page) == live_fields,
                              "application-live-nodes-share-browser-consent")
                        live_body = urlencode({**live_fields, "decision": "approve"}).encode("ascii")
                        status, headers, _ = second_http("POST", "/consent", live_body, consent_headers)
                        live_callback = urlsplit(headers.get("location", ""))
                        live_codes = parse_qs(live_callback.query).get("code", [])
                        check(status == 303 and live_callback.scheme == "https"
                              and live_callback.netloc == "client.example" and len(live_codes) == 1,
                              "application-live-second-node-issues-code")
                        code_body_live = urlencode({"grant_type": "authorization_code", "client_id": "demo-public",
                                                    "code": live_codes[0],
                                                    "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                                                    "resource": resource,
                                                    "redirect_uri": "https://client.example/cb"}).encode("ascii")
                        status, _, content = issuer_http("POST", "/token", code_body_live,
                                                         {"Content-Type": "application/x-www-form-urlencoded"})
                        live_access = json.loads(content).get("access_token", "")
                        check(status == 200 and bool(re.fullmatch(r"[A-Za-z0-9_.-]+", live_access)),
                              "application-live-cross-node-code-redeemed")
                        status, _, content = issuer_http("POST", "/mcp", mcp_body,
                            {**mcp_headers, "Authorization": "Bearer " + live_access,
                             "Host": "127.0.0.1:" + str(app_mcp_port)}, app_mcp_port, "::1")
                        check(status == 200 and b"Checked identity partition" in content
                              and live_access.encode("ascii") not in content,
                              "application-live-second-node-admits-token")
                        status, _, _ = second_http("POST", "/consent", live_body, consent_headers)
                        check(status == 403, "application-live-second-node-rejects-consent-replay")

                        status, _, page = issuer_http("GET", "/authorize?" + authorization,
                                                      headers={"Cookie": rotated_cookie})
                        race_fields = hidden_fields(page)
                        check(status == 200 and b"Consent" in page,
                              "application-live-consent-race-created")
                        status, _, page = second_http("GET", "/consent",
                                                      headers={"Cookie": rotated_cookie})
                        check(status == 200 and hidden_fields(page) == race_fields,
                              "application-live-consent-race-visible-on-both")
                        race_body = urlencode({**race_fields, "decision": "approve"}).encode("ascii")
                        barrier = threading.Barrier(2)

                        def race_claim(host: str) -> tuple[int, dict[str, str], bytes]:
                            barrier.wait(timeout=5)
                            return issuer_http("POST", "/consent", race_body,
                                {**consent_headers, "Host": "127.0.0.1:" + str(app_http_port)}, app_http_port, host)

                        with ThreadPoolExecutor(max_workers=2) as pool:
                            first = pool.submit(race_claim, "127.0.0.1")
                            second = pool.submit(race_claim, "::1")
                            race_outcomes = [first.result(timeout=20), second.result(timeout=20)]
                        check(sorted(result[0] for result in race_outcomes) == [303, 403]
                              and all(b"code=" not in result[2] for result in race_outcomes),
                              "application-live-consent-race-one-winner")
                        winner = next(result for result in race_outcomes if result[0] == 303)
                        race_callback = urlsplit(winner[1].get("location", ""))
                        race_codes = parse_qs(race_callback.query).get("code", [])
                        check(race_callback.scheme == "https" and race_callback.netloc == "client.example"
                              and len(race_codes) == 1,
                              "application-live-consent-race-checked-callback")
                        race_code_body = urlencode({"grant_type": "authorization_code", "client_id": "demo-public",
                                                   "code": race_codes[0],
                                                   "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                                                   "resource": resource,
                                                   "redirect_uri": "https://client.example/cb"}).encode("ascii")
                        status, _, content = second_http("POST", "/token", race_code_body,
                            {"Content-Type": "application/x-www-form-urlencoded"})
                        race_access = json.loads(content).get("access_token", "")
                        check(status == 200 and bool(re.fullmatch(r"[A-Za-z0-9_.-]+", race_access)),
                              "application-live-consent-race-code-redeemed")
                        docker("stop", name)
                        try:
                            for node, route in (("first", issuer_http), ("second", second_http)):
                                status, _, content = route("GET", "/consent",
                                                           headers={"Cookie": rotated_cookie})
                                check(status == 503 and b"code=" not in content,
                                      "application-live-" + node + "-browser-outage-unavailable")
                            for node, host in (("first", "127.0.0.1"), ("second", "::1")):
                                status, response_headers, content = issuer_http("POST", "/mcp", mcp_body,
                                    {**mcp_headers, "Authorization": "Bearer " + live_access,
                                     "Host": "127.0.0.1:" + str(app_mcp_port)}, app_mcp_port, host)
                                check(status == 503 and "www-authenticate" not in response_headers
                                      and live_access.encode("ascii") not in content,
                                      "application-live-" + node + "-mcp-outage-unavailable")
                        finally:
                            docker("start", name)
                            ready()
                            current_db_env = db_env()
                    finally:
                        if second_server.stdin is not None:
                            second_server.stdin.close()
                        try:
                            second_server.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            second_server.kill()
                            second_server.wait(timeout=5)
                        if second_server.stdout is not None:
                            second_server.stdout.close()
                        if second_server.stderr is not None:
                            second_server.stderr.close()
                        check(second_server.returncode == 0, "application-second-live-soklet-stopped")
                    status, _, page = issuer_http("GET", "/authorize?" + authorization,
                                                   headers={"Cookie": rotated_cookie})
                    check(status == 200 and b"Consent" in page,
                          "application-shared-session-starts-next-consent")
                    pending_restart_fields = hidden_fields(page)
                finally:
                    if server.stdin is not None:
                        server.stdin.close()
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait(timeout=5)
                    if server.stdout is not None:
                        server.stdout.close()
                    if server.stderr is not None:
                        server.stderr.close()
                    check(server.returncode == 0, "application-established-soklet-stopped")
                check(run_app("established-active", app_rotated_access) == "INACTIVE",
                      "application-refresh-replay-revokes-family")

                server = subprocess.Popen([str(args.java_home / "bin/java"), "-cp", classpath,
                                           "example.issuer.PostgresqlIssuerApplicationProbe", "serve"],
                                          env=current_db_env, stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    check(server.stdout is not None
                          and bool(select.select([server.stdout], [], [], 10)[0])
                          and server.stdout.readline().strip() == "READY",
                          "application-restarted-soklet-ready")
                    status, _, _ = issuer_http("GET", "/consent", headers={"Cookie": first_cookie})
                    check(status == 403, "application-restart-keeps-rotated-cookie-invalid")
                    status, _, page = issuer_http("GET", "/consent", headers={"Cookie": rotated_cookie})
                    check(status == 200 and b"Consent" in page
                          and hidden_fields(page) == pending_restart_fields,
                          "application-restart-retains-browser-session-and-consent")
                    resumed_body = urlencode({**pending_restart_fields, "decision": "approve"}).encode("ascii")
                    status, headers, _ = issuer_http("POST", "/consent", resumed_body, consent_headers)
                    resumed_callback = urlsplit(headers.get("location", ""))
                    resumed_codes = parse_qs(resumed_callback.query).get("code", [])
                    check(status == 303 and resumed_callback.scheme == "https"
                          and resumed_callback.netloc == "client.example"
                          and len(resumed_codes) == 1
                          and bool(re.fullmatch(r"[A-Za-z0-9_-]+", resumed_codes[0])),
                          "application-cross-jvm-consent-issues-code")
                    status, _, _ = issuer_http("POST", "/consent", resumed_body, consent_headers)
                    check(status == 403, "application-cross-jvm-consent-single-use")
                    code_body = urlencode({"grant_type": "authorization_code", "client_id": "demo-public",
                                           "code": http_code,
                                           "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                                           "resource": resource,
                                           "redirect_uri": "https://client.example/cb"}).encode("ascii")
                    status, headers, content = issuer_http("POST", "/token", code_body,
                        {"Content-Type": "application/x-www-form-urlencoded"})
                    issued = json.loads(content)
                    http_access = issued.get("access_token", "")
                    check(status == 200 and issued.get("token_type") == "Bearer"
                          and bool(re.fullmatch(r"[A-Za-z0-9_.-]+", http_access))
                          and bool(re.fullmatch(r"[A-Za-z0-9_.-]+", issued.get("refresh_token", "")))
                          and headers.get("cache-control") == "no-store",
                          "application-http-code-redeemed-after-restart")
                    resumed_code_body = urlencode({"grant_type": "authorization_code", "client_id": "demo-public",
                                           "code": resumed_codes[0],
                                           "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                                           "resource": resource,
                                           "redirect_uri": "https://client.example/cb"}).encode("ascii")
                    status, _, resumed_content = issuer_http("POST", "/token", resumed_code_body,
                        {"Content-Type": "application/x-www-form-urlencoded"})
                    resumed_token = json.loads(resumed_content).get("access_token", "")
                    check(status == 200 and bool(re.fullmatch(r"[A-Za-z0-9_.-]+", resumed_token)),
                          "application-cross-jvm-consent-code-redeemed")
                    mcp_headers["Authorization"] = "Bearer " + http_access
                    with opener.open(Request(mcp_url, data=mcp_body, headers=mcp_headers,
                                             method="POST"), timeout=5) as response:
                        body = response.read(32_768).decode("utf-8")
                        check(response.status == 200 and "Checked identity partition" in body
                              and http_access not in body and "demo-user" not in body,
                              "application-restarted-mcp-accepts-http-code-token")
                        check(first_partition.group(1) in body,
                              "application-admission-partition-stable-across-jvms")

                    introspect_body = urlencode({"token": http_access}).encode("ascii")
                    introspect_headers = {"Content-Type": "application/x-www-form-urlencoded",
                                          "Authorization": "Basic " + auth}
                    refresh_body = urlencode({"grant_type": "refresh_token", "client_id": "demo-public",
                                              "refresh_token": issued["refresh_token"],
                                              "resource": resource}).encode("ascii")
                    docker("stop", name)
                    try:
                        status, _, content = issuer_http("GET", "/consent",
                                                          headers={"Cookie": rotated_cookie})
                        check(status == 503 and b"code=" not in content,
                              "application-browser-session-outage-is-unavailable")
                        try:
                            opener.open(Request(mcp_url, data=mcp_body, headers=mcp_headers,
                                                method="POST"), timeout=10)
                        except HTTPError as unavailable:
                            check(unavailable.code == 503
                                  and unavailable.headers.get("WWW-Authenticate") is None
                                  and http_access.encode("ascii") not in unavailable.read(32_768),
                                  "application-live-mcp-outage-is-unavailable")
                            unavailable.close()
                        else:
                            check(False, "application-live-mcp-outage-is-unavailable")
                        status, _, content = issuer_http("POST", "/introspect",
                                                          introspect_body, introspect_headers)
                        check(status == 503 and http_access.encode("ascii") not in content
                              and b'"active":true' not in content,
                              "application-live-introspection-outage-is-unavailable")
                        status, _, content = issuer_http("POST", "/token", refresh_body,
                            {"Content-Type": "application/x-www-form-urlencoded"})
                        check(status == 503 and b'"access_token"' not in content
                              and b'"refresh_token"' not in content
                              and issued["refresh_token"].encode("ascii") not in content,
                              "application-live-token-outage-withholds-credentials")
                    finally:
                        docker("start", name)
                        ready()
                        current_db_env = db_env()

                    with opener.open(Request(mcp_url, data=mcp_body, headers=mcp_headers,
                                             method="POST"), timeout=5) as response:
                        check(response.status == 200 and "Checked identity partition" in
                              response.read(32_768).decode("utf-8"),
                              "application-live-mcp-recovers-after-primary-return")
                    status, _, content = issuer_http("POST", "/introspect",
                                                      introspect_body, introspect_headers)
                    check(status == 200 and json.loads(content).get("active") is True,
                          "application-live-introspection-recovers-after-primary-return")
                    status, _, content = issuer_http("POST", "/token", code_body,
                        {"Content-Type": "application/x-www-form-urlencoded"})
                    replay = json.loads(content)
                    check(status == 400 and "access_token" not in replay and "refresh_token" not in replay,
                          "application-http-code-replay-denied")
                    try:
                        opener.open(Request(mcp_url, data=mcp_body, headers=mcp_headers,
                                            method="POST"), timeout=5)
                    except HTTPError as denied:
                        check(denied.code == 401, "application-http-code-replay-revokes-live-grant")
                        denied.close()
                    else:
                        check(False, "application-http-code-replay-revokes-live-grant")
                finally:
                    if server.stdin is not None:
                        server.stdin.close()
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait(timeout=5)
                    if server.stdout is not None:
                        server.stdout.close()
                    if server.stderr is not None:
                        server.stderr.close()
                    check(server.returncode == 0, "application-restarted-soklet-stopped")
                check(run_app("established-active", http_access) == "INACTIVE",
                      "application-http-code-replay-revocation-persists")
            check(run_issuer("unknown-init") == "UNKNOWN", "issuer-uncertain-commit-reported")
            check(run_issuer("reconcile-unknown") == "CONFLICT",
                  "issuer-uncertain-commit-reconciled")
            check(run_issuer("init") == "INITIALIZED", "issuer-primary-initialized")
            code = run_issuer("issue")
            check(bool(re.fullmatch(r"[A-Za-z0-9_-]+", code)), "issuer-cross-jvm-code-issued")
            first = run_issuer("redeem", code)
            check(first.startswith("TOKEN:"), "issuer-cross-jvm-code-redeemed")
            first_token = first.removeprefix("TOKEN:")
            check(run_issuer("active", first_token) == "ACTIVE", "issuer-first-token-active")
            check(run_issuer("active-short-budget", first_token) == "ACTIVE",
                  "issuer-short-budget-unblocked-control")
            holder = subprocess.Popen(["docker", "exec", "-i", name, "psql", "-X", "-q", "-t", "-A",
                                       "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "pending_fixture"],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True, bufsize=1)
            try:
                assert holder.stdin is not None
                holder.stdin.write("BEGIN;\nSELECT 'READY' FROM issuer_store_namespace "
                                   "WHERE namespace='fixture_issuer' FOR UPDATE;\n")
                holder.stdin.flush()
                check(holder.stdout is not None
                      and bool(select.select([holder.stdout], [], [], 5)[0])
                      and holder.stdout.readline().strip() == "READY", "issuer-namespace-lock-held")
                began = time.monotonic()
                check(run_issuer("active-short-budget", first_token) == "STORE_UNAVAILABLE"
                      and time.monotonic() - began < 3,
                      "issuer-locked-read-respects-budget")
                began = time.monotonic()
                check(run_issuer("revoke-short-budget") == "STORE_UNAVAILABLE"
                      and time.monotonic() - began < 3,
                      "issuer-locked-revocation-respects-budget")
            finally:
                if holder.stdin is not None:
                    if holder.poll() is None:
                        try:
                            holder.stdin.write("ROLLBACK;\n")
                            holder.stdin.flush()
                        except BrokenPipeError:
                            pass
                    try:
                        holder.stdin.close()
                    except BrokenPipeError:
                        pass
                try:
                    holder.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    holder.kill()
                    holder.wait(timeout=5)
                if holder.stdout is not None:
                    holder.stdout.close()
                if holder.stderr is not None:
                    holder.stderr.close()
            check(holder.returncode == 0, "issuer-namespace-lock-released")
            check(run_issuer("active", first_token) == "ACTIVE",
                  "issuer-blocked-revocation-keeps-grant")
            check(run_issuer("active-small-cap", first_token) == "ACTIVE",
                  "issuer-capacity-reduction-keeps-read-barrier")
            check(run_issuer("issue-small-cap") == "CAPACITY_REFUSED",
                  "issuer-capacity-refusal-releases-no-code")
            check(run_issuer("active", first_token) == "ACTIVE",
                  "issuer-capacity-refusal-keeps-existing-grant")
            check(run_issuer("fence-init") == "INITIALIZED", "issuer-separate-fence-initialized")
            fence_code = run_issuer("fence-issue")
            check(bool(re.fullmatch(r"[A-Za-z0-9_-]+", fence_code)),
                  "issuer-separate-fence-code-issued")
            fence_token_output = run_issuer("fence-redeem", fence_code)
            check(fence_token_output.startswith("TOKEN:"), "issuer-separate-fence-code-redeemed")
            fence_token = fence_token_output.removeprefix("TOKEN:")
            check(run_issuer("fence-active", fence_token) == "ACTIVE",
                  "issuer-separate-fence-token-active")
            damaged_rows = docker("exec", "-i", name, "psql", "-X", "-q", "-t", "-A",
                                  "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "pending_fixture",
                                  input_text="BEGIN;\nSELECT 1 FROM issuer_store_namespace "
                                  "WHERE namespace='fixture_issuer_fence' FOR UPDATE;\n"
                                  "SELECT count(*) FROM issuer_store_entry WHERE "
                                  "namespace='fixture_issuer_fence' AND kind='SUBJECT_STATE';\n"
                                  "DELETE FROM issuer_store_entry WHERE namespace='fixture_issuer_fence' "
                                  "AND kind='SUBJECT_STATE';\nCOMMIT;\n")
            check(damaged_rows.splitlines() == ["1", "1"],
                  "issuer-test-damage-removed-one-subject-fence")
            try:
                run_issuer("fence-active", fence_token)
            except RuntimeError as failure:
                check("OAuthServerStoreException" in str(failure),
                      "issuer-missing-subject-fence-fails-closed")
            else:
                check(False, "issuer-missing-subject-fence-fails-closed")
            check(run_issuer("active", first_token) == "ACTIVE",
                  "issuer-damaged-namespace-isolated")
            unknown_code = run_issuer("issue")
            check(bool(re.fullmatch(r"[A-Za-z0-9_-]+", unknown_code)),
                  "issuer-unknown-redemption-code-issued")
            check(run_issuer("unknown-redeem", unknown_code) == "UNKNOWN_NO_CREDENTIALS",
                  "issuer-unknown-redemption-withholds-credentials")
            check(run_issuer("redeem", unknown_code) == "REJECTED",
                  "issuer-unknown-redemption-reconciles-as-used")
            check(run_issuer("active", first_token) == "ACTIVE",
                  "issuer-unknown-redemption-isolates-other-grant")
            code = run_issuer("issue")
            contenders = [subprocess.Popen([str(args.java_home / "bin/java"), "-cp", classpath,
                            "example.pending.IssuerStoreProbe", "race", code], env=current_db_env,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True) for _ in range(2)]
            try:
                check(all(proc.stdout is not None and proc.stdout.readline().strip() == "READY"
                          for proc in contenders), "issuer-race-ready")
                for proc in contenders:
                    assert proc.stdin is not None
                    proc.stdin.write("go\n")
                    proc.stdin.flush()
                outcomes = []
                for proc in contenders:
                    output, error = proc.communicate(timeout=20)
                    if proc.returncode:
                        types = re.findall(r"(?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*(?:Exception|Error)", error)
                        raise RuntimeError("Issuer race JVM failed, types=" + ",".join(types[:5]))
                    check(True, "issuer-race-jvm")
                    outcomes.append(output.strip())
                winners = [outcome.removeprefix("TOKEN:") for outcome in outcomes
                           if outcome.startswith("TOKEN:")]
                check(len(winners) == 1 and outcomes.count("REJECTED") == 1,
                      "issuer-cross-jvm-code-single-winner")
                check(run_issuer("active", winners[0]) == "INACTIVE:TOKEN_REVOKED",
                      "issuer-race-replay-revokes-grant")
                check(run_issuer("active", first_token) == "ACTIVE",
                      "issuer-other-grant-remains-active")
                check(run_issuer("redeem", code) == "REJECTED", "issuer-code-replay-rejected")
            finally:
                for proc in contenders:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait(timeout=5)

            refresh_code = run_issuer("issue")
            original_access, original_refresh = issuer_pair(
                run_issuer("redeem-pair", refresh_code), "issuer-refresh-grant-issued")
            rotated_access, rotated_refresh = issuer_pair(
                run_issuer("refresh", original_refresh), "issuer-cross-jvm-refresh-rotated")
            check(rotated_refresh != original_refresh, "issuer-refresh-credential-changed")
            check(run_issuer("active", original_access) == "ACTIVE"
                  and run_issuer("active", rotated_access) == "ACTIVE",
                  "issuer-both-access-tokens-active-before-replay")
            check(run_issuer("refresh", original_refresh) == "REJECTED",
                  "issuer-used-refresh-rejected")
            check(run_issuer("active", original_access) == "INACTIVE:TOKEN_REVOKED"
                  and run_issuer("active", rotated_access) == "INACTIVE:TOKEN_REVOKED",
                  "issuer-refresh-replay-revokes-descendants")
            check(run_issuer("refresh", rotated_refresh) == "REJECTED",
                  "issuer-revoked-refresh-descendant-rejected")
            check(run_issuer("active", first_token) == "ACTIVE",
                  "issuer-refresh-replay-isolates-other-grant")

            refresh_race_code = run_issuer("issue")
            race_access, race_refresh = issuer_pair(
                run_issuer("redeem-pair", refresh_race_code), "issuer-refresh-race-grant-issued")
            contenders = [subprocess.Popen([str(args.java_home / "bin/java"), "-cp", classpath,
                            "example.pending.IssuerStoreProbe", "refresh-race", race_refresh],
                            env=current_db_env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True) for _ in range(2)]
            try:
                check(all(proc.stdout is not None and proc.stdout.readline().strip() == "READY"
                          for proc in contenders), "issuer-refresh-race-ready")
                for proc in contenders:
                    assert proc.stdin is not None
                    proc.stdin.write("go\n")
                    proc.stdin.flush()
                outcomes = []
                for proc in contenders:
                    output, error = proc.communicate(timeout=20)
                    if proc.returncode:
                        types = re.findall(r"(?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*(?:Exception|Error)", error)
                        raise RuntimeError("Issuer refresh race JVM failed, types=" + ",".join(types[:5]))
                    check(True, "issuer-refresh-race-jvm")
                    outcomes.append(output.strip())
                winners = [outcome for outcome in outcomes if outcome.startswith("PAIR:")]
                check(len(winners) == 1 and outcomes.count("REJECTED") == 1,
                      "issuer-cross-jvm-refresh-single-winner")
                race_rotated_access, race_rotated_refresh = issuer_pair(
                    winners[0], "issuer-refresh-race-winner-pair")
                check(race_rotated_refresh != race_refresh,
                      "issuer-refresh-race-credential-rotated")
                check(run_issuer("active", race_access) == "INACTIVE:TOKEN_REVOKED"
                      and run_issuer("active", race_rotated_access) == "INACTIVE:TOKEN_REVOKED",
                      "issuer-refresh-race-replay-revokes-grant")
                check(run_issuer("active", first_token) == "ACTIVE",
                      "issuer-refresh-race-isolates-other-grant")
            finally:
                for proc in contenders:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait(timeout=5)

            unknown_refresh_code = run_issuer("issue")
            unknown_access, unknown_refresh = issuer_pair(
                run_issuer("redeem-pair", unknown_refresh_code), "issuer-unknown-refresh-grant-issued")
            check(run_issuer("unknown-refresh", unknown_refresh) == "UNKNOWN_NO_CREDENTIALS",
                  "issuer-unknown-refresh-withholds-credentials")
            check(run_issuer("active", unknown_access) == "ACTIVE",
                  "issuer-unknown-refresh-keeps-prior-access-until-replay")
            check(run_issuer("refresh", unknown_refresh) == "REJECTED",
                  "issuer-unknown-refresh-reconciles-as-used")
            check(run_issuer("active", unknown_access) == "INACTIVE:TOKEN_REVOKED",
                  "issuer-unknown-refresh-replay-revokes-grant")
            check(run_issuer("active", first_token) == "ACTIVE",
                  "issuer-unknown-refresh-isolates-other-grant")

            state = run("issue", "binding-main")
            check(run("callback", state, "other-binding") == "REJECTED:PENDING_AUTHORIZATION_NOT_FOUND",
                  "binding-isolation")
            check(run("callback", state, "binding-main") == "DENIED", "cross-jvm-completion")
            check(run("callback", state, "binding-main") == "REJECTED:PENDING_AUTHORIZATION_NOT_FOUND",
                  "replay-rejected")

            state = run("issue", "binding-race")
            contenders = [subprocess.Popen([str(args.java_home / "bin/java"), "-cp", classpath,
                            "example.pending.PendingStoreProbe", "callback-race", state, "binding-race"],
                            env=current_db_env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True) for _ in range(2)]
            try:
                check(all(proc.stdout is not None and proc.stdout.readline().strip() == "READY"
                          for proc in contenders), "race-ready")
                for proc in contenders:
                    assert proc.stdin is not None
                    proc.stdin.write("go\n")
                    proc.stdin.flush()
                outcomes = []
                for proc in contenders:
                    output, _ = proc.communicate(timeout=15)
                    check(proc.returncode == 0, "race-jvm")
                    outcomes.append(output.strip())
                check(sorted(outcomes) == ["DENIED", "REJECTED:PENDING_AUTHORIZATION_NOT_FOUND"],
                      "cross-jvm-single-winner")
            finally:
                for proc in contenders:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait(timeout=5)

            requests: list[bool] = []
            oidc_requests: list[bool] = []
            rsa_requests: list[bool] = []
            jwks_requests: list[str] = []
            request_lock = threading.Lock()
            current_challenge = ""
            current_nonce = ""
            wrong_nonce = False
            bad_signature = False
            rsa_signer: subprocess.Popen[str] | None = None
            jwks_body: bytes | None = None
            signer_lock = threading.Lock()

            def encoded(value: bytes) -> str:
                return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

            def rsa_token(claims: dict[str, object]) -> str:
                payload = json.dumps(claims, separators=(",", ":"))
                with signer_lock:
                    if rsa_signer is None or rsa_signer.stdin is None or rsa_signer.stdout is None:
                        raise RuntimeError("RSA fixture signer is unavailable")
                    rsa_signer.stdin.write(payload + "\n")
                    rsa_signer.stdin.flush()
                    if not select.select([rsa_signer.stdout], [], [], 5)[0]:
                        raise RuntimeError("RSA fixture signer timed out")
                    compact = rsa_signer.stdout.readline().strip()
                    if compact.count(".") != 2:
                        raise RuntimeError("RSA fixture signer returned no compact token")
                    return compact

            class TokenHandler(BaseHTTPRequestHandler):
                def log_message(self, format: str, *arguments: object) -> None:
                    pass

                def do_GET(self) -> None:
                    with request_lock:
                        jwks_requests.append(self.path)
                    if self.path != "/jwks" or jwks_body is None:
                        self.send_error(404)
                        return
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Cache-Control", "max-age=60")
                    self.send_header("Content-Length", str(len(jwks_body)))
                    self.end_headers()
                    self.wfile.write(jwks_body)

                def do_POST(self) -> None:
                    length = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(length) if 0 < length <= 4096 else b""
                    try:
                        form = parse_qs(body.decode("ascii"), strict_parsing=True)
                    except (UnicodeDecodeError, ValueError):
                        form = {}
                    is_hmac = form.get("client_id") == ["distributed-oidc-probe"]
                    is_rsa = form.get("client_id") == ["distributed-rsa-probe"]
                    expected = {"grant_type", "code", "redirect_uri", "code_verifier", "client_id"}
                    if is_hmac:
                        expected.add("client_secret")
                    valid = (self.path == "/token" and 0 < length <= 4096
                             and self.headers.get("Content-Type") == "application/x-www-form-urlencoded"
                             and self.headers.get("Accept") == "application/json"
                             and set(form) == expected
                             and form.get("grant_type") == ["authorization_code"]
                             and form.get("code") == ["test-only-code"]
                             and form.get("redirect_uri") == ["https://consumer.example/callback"]
                             and form.get("client_id") == ["distributed-oidc-probe" if is_hmac
                                                            else "distributed-rsa-probe" if is_rsa
                                                            else "distributed-probe"]
                             and (not is_hmac or form.get("client_secret") == [oidc_secret])
                             and len(form.get("code_verifier", [])) == 1
                             and re.fullmatch(r"[A-Za-z0-9_-]{43}", form["code_verifier"][0]) is not None
                             and encoded(hashlib.sha256(form["code_verifier"][0].encode("ascii")).digest())
                             == current_challenge)
                    with request_lock:
                        requests.append(valid)
                        oidc_requests.append(is_hmac or is_rsa)
                        rsa_requests.append(is_rsa)
                    if valid and (is_hmac or is_rsa):
                        now = int(time.time())
                        claims = {"iss": issuer, "sub": "synthetic-subject",
                                  "aud": "distributed-rsa-probe" if is_rsa else "distributed-oidc-probe",
                                  "iat": now, "exp": now + 300,
                                  "nonce": "wrong-test-nonce" if wrong_nonce else current_nonce}
                        if is_rsa:
                            compact = rsa_token(claims)
                            if bad_signature:
                                parts = compact.split(".")
                                signature = parts[2]
                                parts[2] = ("A" if signature[0] != "A" else "B") + signature[1:]
                                compact = ".".join(parts)
                        else:
                            signing_input = (encoded(b'{"alg":"HS256","typ":"JWT"}') + "."
                                             + encoded(json.dumps(claims, separators=(",", ":")).encode("utf-8")))
                            signature = encoded(hmac.new(oidc_secret.encode("ascii"), signing_input.encode("ascii"),
                                                         hashlib.sha256).digest())
                            compact = signing_input + "." + signature
                        response = json.dumps({"access_token": "test-only-token", "token_type": "Bearer",
                                               "expires_in": 60, "id_token": compact},
                                              separators=(",", ":")).encode("utf-8")
                    else:
                        response = (b'{"access_token":"test-only-token","token_type":"Bearer","expires_in":60}'
                                    if valid else b'{"error":"invalid_request"}')
                    self.send_response(200 if valid else 400)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Pragma", "no-cache")
                    self.send_header("Content-Length", str(len(response)))
                    self.end_headers()
                    self.wfile.write(response)

            with ThreadingHTTPServer(("127.0.0.1", 0), TokenHandler) as token_server:
                token_thread = threading.Thread(target=token_server.serve_forever, daemon=True)
                token_thread.start()
                try:
                    issuer = "http://127.0.0.1:" + str(token_server.server_port)
                    check(run("issue-code-unknown", "binding-unknown-save", issuer)
                          == "UNCERTAIN_SAVE_NO_REDIRECT", "unknown-save-no-redirect")
                    check(requests == [], "unknown-save-no-token-request")
                    state, current_challenge = run("issue-code", "binding-code", issuer).split("\t", 1)
                    check(run("callback-code", state, "other-binding", issuer)
                          == "REJECTED:PENDING_AUTHORIZATION_NOT_FOUND", "code-binding-isolation")
                    check(requests == [], "wrong-binding-no-token-request")
                    check(run("callback-code", state, "binding-code", issuer) == "SUCCEEDED",
                          "cross-jvm-code-redemption")
                    check(requests == [True], "one-valid-token-request")
                    check(run("callback-code", state, "binding-code", issuer)
                          == "REJECTED:PENDING_AUTHORIZATION_NOT_FOUND", "code-replay-rejected")
                    check(requests == [True], "code-replay-no-token-request")

                    state, current_challenge = run("issue-code", "binding-unknown-consume", issuer).split("\t", 1)
                    check(run("callback-code-unknown", state, "binding-unknown-consume", issuer)
                          == "FAILED:PENDING_AUTHORIZATION_STORE_UNAVAILABLE", "unknown-consume-no-tokens")
                    check(requests == [True], "unknown-consume-no-token-request")
                    check(run("callback-code", state, "binding-unknown-consume", issuer)
                          == "REJECTED:PENDING_AUTHORIZATION_NOT_FOUND", "unknown-consume-replay-rejected")
                    check(requests == [True], "unknown-consume-replay-no-token-request")

                    state, current_challenge = run("issue-code", "binding-code-race", issuer).split("\t", 1)
                    contenders = [subprocess.Popen([str(args.java_home / "bin/java"), "-cp", classpath,
                                    "example.pending.PendingStoreProbe", "callback-code-race", state,
                                    "binding-code-race", issuer], env=current_db_env, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
                    try:
                        check(all(proc.stdout is not None and proc.stdout.readline().strip() == "READY"
                                  for proc in contenders), "code-race-ready")
                        for proc in contenders:
                            assert proc.stdin is not None
                            proc.stdin.write("go\n")
                            proc.stdin.flush()
                        outcomes = []
                        for proc in contenders:
                            output, _ = proc.communicate(timeout=15)
                            check(proc.returncode == 0, "code-race-jvm")
                            outcomes.append(output.strip())
                        check(sorted(outcomes) == ["REJECTED:PENDING_AUTHORIZATION_NOT_FOUND", "SUCCEEDED"],
                              "cross-jvm-code-single-winner")
                        check(requests == [True, True], "exactly-one-race-redemption")
                    finally:
                        for proc in contenders:
                            if proc.poll() is None:
                                proc.kill()
                                proc.wait(timeout=5)

                    state, current_challenge, current_nonce = run(
                        "issue-oidc", "binding-oidc", issuer).split("\t", 2)
                    check(run("callback-oidc", state, "other-binding", issuer)
                          == "REJECTED:PENDING_AUTHORIZATION_NOT_FOUND", "oidc-binding-isolation")
                    check(requests == [True, True], "oidc-wrong-binding-no-token-request")
                    check(run("callback-oidc", state, "binding-oidc", issuer) == "AUTHENTICATED",
                          "cross-jvm-oidc-authentication")
                    check(requests == [True, True, True] and oidc_requests == [False, False, True],
                          "one-valid-oidc-token-request")
                    check(run("callback-oidc", state, "binding-oidc", issuer)
                          == "REJECTED:PENDING_AUTHORIZATION_NOT_FOUND", "oidc-replay-rejected")
                    check(requests == [True, True, True], "oidc-replay-no-token-request")

                    state, current_challenge, current_nonce = run(
                        "issue-oidc", "binding-oidc-bad-nonce", issuer).split("\t", 2)
                    wrong_nonce = True
                    check(run("callback-oidc", state, "binding-oidc-bad-nonce", issuer)
                          == "REJECTED_ID_TOKEN:NONCE_MISMATCH", "oidc-bad-nonce-withholds-identity")
                    wrong_nonce = False
                    check(requests == [True, True, True, True], "oidc-bad-nonce-one-token-request")
                    check(run("callback-oidc", state, "binding-oidc-bad-nonce", issuer)
                          == "REJECTED:PENDING_AUTHORIZATION_NOT_FOUND", "oidc-bad-nonce-replay-rejected")
                    check(requests == [True, True, True, True], "oidc-bad-nonce-replay-no-token-request")

                    state, current_challenge, current_nonce = run(
                        "issue-oidc", "binding-oidc-race", issuer).split("\t", 2)
                    contenders = [subprocess.Popen([str(args.java_home / "bin/java"), "-cp", classpath,
                                    "example.pending.PendingStoreProbe", "callback-oidc-race", state,
                                    "binding-oidc-race", issuer], env=current_db_env, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
                    try:
                        check(all(proc.stdout is not None and proc.stdout.readline().strip() == "READY"
                                  for proc in contenders), "oidc-race-ready")
                        for proc in contenders:
                            assert proc.stdin is not None
                            proc.stdin.write("go\n")
                            proc.stdin.flush()
                        outcomes = []
                        for proc in contenders:
                            output, _ = proc.communicate(timeout=15)
                            check(proc.returncode == 0, "oidc-race-jvm")
                            outcomes.append(output.strip())
                        check(sorted(outcomes) == ["AUTHENTICATED", "REJECTED:PENDING_AUTHORIZATION_NOT_FOUND"],
                              "cross-jvm-oidc-single-winner")
                        check(requests == [True] * 5 and oidc_requests == [False, False, True, True, True],
                              "exactly-one-oidc-race-redemption")
                        check(jwks_requests == [], "oidc-hmac-no-jwks-request")
                    finally:
                        for proc in contenders:
                            if proc.poll() is None:
                                proc.kill()
                                proc.wait(timeout=5)

                    rsa_signer = subprocess.Popen([str(args.java_home / "bin/java"), "-cp", classpath,
                                                    "example.pending.RsaFixtureSigner"], env=current_db_env,
                                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                   stderr=subprocess.PIPE, text=True, bufsize=1)
                    try:
                        if rsa_signer.stdout is None or not select.select([rsa_signer.stdout], [], [], 10)[0]:
                            raise RuntimeError("RSA fixture signer did not start")
                        public = rsa_signer.stdout.readline().strip().split("\t")
                        if (len(public) != 2 or not re.fullmatch(r"[A-Za-z0-9_-]{300,}", public[0])
                                or not re.fullmatch(r"[A-Za-z0-9_-]+", public[1])):
                            raise RuntimeError("RSA fixture signer returned no public key")
                        jwks_body = json.dumps({"keys": [{"kty": "RSA", "n": public[0], "e": public[1],
                                                           "kid": "fixture-rsa", "use": "sig", "alg": "RS256"}]},
                                               separators=(",", ":")).encode("ascii")

                        state, current_challenge, current_nonce = run(
                            "issue-oidc-rsa", "binding-rsa", issuer).split("\t", 2)
                        check(run("callback-oidc-rsa", state, "other-binding", issuer)
                              == "REJECTED:PENDING_AUTHORIZATION_NOT_FOUND", "rsa-binding-isolation")
                        check(len(requests) == 5 and jwks_requests == [], "rsa-wrong-binding-no-io")
                        check(run("callback-oidc-rsa", state, "binding-rsa", issuer) == "AUTHENTICATED",
                              "cross-jvm-rsa-authentication")
                        check(len(requests) == 6 and rsa_requests[-1] and jwks_requests == ["/jwks"],
                              "rsa-token-and-jwks-once")
                        check(run("callback-oidc-rsa", state, "binding-rsa", issuer)
                              == "REJECTED:PENDING_AUTHORIZATION_NOT_FOUND", "rsa-replay-rejected")
                        check(len(requests) == 6 and jwks_requests == ["/jwks"], "rsa-replay-no-io")

                        state, current_challenge, current_nonce = run(
                            "issue-oidc-rsa", "binding-rsa-bad-signature", issuer).split("\t", 2)
                        bad_signature = True
                        check(run("callback-oidc-rsa", state, "binding-rsa-bad-signature", issuer)
                              == "REJECTED_ID_TOKEN:ID_TOKEN_SIGNATURE_INVALID",
                              "rsa-bad-signature-withholds-identity")
                        bad_signature = False
                        check(len(requests) == 7 and jwks_requests == ["/jwks", "/jwks"],
                              "rsa-bad-signature-single-fetch")

                        state, current_challenge, current_nonce = run(
                            "issue-oidc-rsa", "binding-rsa-race", issuer).split("\t", 2)
                        contenders = [subprocess.Popen([str(args.java_home / "bin/java"), "-cp", classpath,
                                        "example.pending.PendingStoreProbe", "callback-oidc-rsa-race", state,
                                        "binding-rsa-race", issuer], env=current_db_env, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
                        try:
                            check(all(proc.stdout is not None and proc.stdout.readline().strip() == "READY"
                                      for proc in contenders), "rsa-race-ready")
                            for proc in contenders:
                                assert proc.stdin is not None
                                proc.stdin.write("go\n")
                                proc.stdin.flush()
                            outcomes = []
                            for proc in contenders:
                                output, _ = proc.communicate(timeout=15)
                                check(proc.returncode == 0, "rsa-race-jvm")
                                outcomes.append(output.strip())
                            check(sorted(outcomes) == ["AUTHENTICATED", "REJECTED:PENDING_AUTHORIZATION_NOT_FOUND"],
                                  "cross-jvm-rsa-single-winner")
                            check(len(requests) == 8 and rsa_requests[-1]
                                  and jwks_requests == ["/jwks", "/jwks", "/jwks"],
                                  "exactly-one-rsa-race-redemption")
                        finally:
                            for proc in contenders:
                                if proc.poll() is None:
                                    proc.kill()
                                    proc.wait(timeout=5)
                    finally:
                        if rsa_signer.stdin is not None:
                            rsa_signer.stdin.close()
                        try:
                            rsa_signer.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            rsa_signer.kill()
                            rsa_signer.wait(timeout=5)
                finally:
                    token_server.shutdown()
                    token_thread.join(timeout=5)

            state = run("issue", "binding-lock")
            holder = subprocess.Popen([str(args.java_home / "bin/java"), "-cp", classpath,
                        "example.pending.PendingStoreProbe", "hold"], env=current_db_env, stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                check(holder.stdout is not None and holder.stdout.readline().strip() == "READY", "lock-ready")
                check(run("callback-short", state, "binding-lock") == "FAILED:PENDING_AUTHORIZATION_STORE_UNAVAILABLE",
                      "blocked-consume-fails-closed")
                holder.communicate(timeout=5)
                check(holder.returncode == 0, "lock-release")
                check(run("callback", state, "binding-lock") == "DENIED", "timeout-left-record")
            finally:
                if holder.poll() is None:
                    holder.kill()
                    holder.wait(timeout=5)

            state = run("issue", "binding-restart")
            docker("stop", name)
            check(run("callback", state, "binding-restart") == "FAILED:PENDING_AUTHORIZATION_STORE_UNAVAILABLE",
                  "database-outage-fails-closed")
            check(run_cache("read", "4").startswith("CACHE_FAILURE:"), "cache-outage-is-failure")
            try:
                run_issuer("active", first_token)
            except RuntimeError as failure:
                check("OAuthServerStoreException" in str(failure), "issuer-outage-fails-closed")
            else:
                check(False, "issuer-outage-fails-closed")
            docker("start", name)
            ready()
            current_db_env = db_env()
            check(run("callback", state, "binding-restart") == "DENIED", "restart-retains-pending")
            check(run_cache("read", "4") == cache_hit(41), "restart-retains-cache")
            check(run_issuer("active", first_token) == "ACTIVE", "restart-retains-active-issuer-grant")
            check(run_issuer("active", rotated_access) == "INACTIVE:TOKEN_REVOKED",
                  "restart-retains-refresh-replay-revocation")
            check(run_issuer("unknown-subject-revoke") == "UNKNOWN_REVOCATION_REPORTED",
                  "issuer-unknown-subject-revocation-not-success")
            check(run_issuer("active", first_token) == "INACTIVE:TOKEN_REVOKED",
                  "issuer-unknown-subject-revocation-reconciled-across-jvms")
            new_code = run_issuer("issue")
            check(bool(re.fullmatch(r"[A-Za-z0-9_-]+", new_code)),
                  "issuer-new-code-after-subject-revocation")
            new_token_output = run_issuer("redeem", new_code)
            check(new_token_output.startswith("TOKEN:"), "issuer-new-grant-after-subject-revocation")
            new_token = new_token_output.removeprefix("TOKEN:")
            check(run_issuer("active", new_token) == "ACTIVE",
                  "issuer-new-subject-epoch-active")
            check(run_issuer("subject-revoke") == "SUBJECT_REVOKED",
                  "issuer-confirmed-subject-revocation")
            check(run_issuer("active", new_token) == "INACTIVE:TOKEN_REVOKED",
                  "issuer-confirmed-subject-revocation-visible")
            global_code = run_issuer("issue")
            global_token_output = run_issuer("redeem", global_code)
            check(global_token_output.startswith("TOKEN:"), "issuer-grant-before-global-revocation")
            global_token = global_token_output.removeprefix("TOKEN:")
            check(run_issuer("active", global_token) == "ACTIVE",
                  "issuer-pre-global-grant-active")
            check(run_issuer("revoke") == "REVOKED", "issuer-cross-jvm-revocation")
            check(run_issuer("active", global_token) == "INACTIVE:TOKEN_REVOKED",
                  "issuer-cross-jvm-revocation-visible")
        finally:
            if ("container", name) in created:
                subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60)
            if ("volume", volume) in created:
                subprocess.run(["docker", "volume", "rm", volume], capture_output=True, timeout=60)
            if ("network", network) in created:
                subprocess.run(["docker", "network", "rm", network], capture_output=True, timeout=60)
            env_file.unlink(missing_ok=True)
    print("postgresql-storage-examples: PASS", flush=True)


if __name__ == "__main__":
    main()
