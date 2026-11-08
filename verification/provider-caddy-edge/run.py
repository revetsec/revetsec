#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
"""Run isolated current-artifact provider qualification through exact pinned Caddy."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).resolve().parent
CADDY_IMAGE = "sha256:0c994536bddb66445885237f1a5dcc1916bccea922661c76b4e9fc24061f9b52"
JAVA_IMAGE = "sha256:b468c3fc688b14450571494f588bd939378e7fd542ed5a73f8efc13f17872a87"
NODE_IMAGE = "sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d"
ALPINE_IMAGE = "sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"
FRAMEWORK_SHA256 = "56e37d0e8ef781822de1618595f43366df00bb29e7b486cdc5901623b83845a9"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(command, **kwargs):
    return subprocess.run(command, capture_output=True, text=True, timeout=kwargs.pop("timeout", 30), **kwargs)


def required(command, **kwargs):
    result = execute(command, **kwargs)
    if result.returncode:
        raise RuntimeError("Owned qualification command failed")
    return result.stdout.strip()


def canonical_process_output(result):
    """Frame captured text streams so stdout/stderr boundaries are unambiguous."""
    stdout = result.stdout.encode("utf-8")
    stderr = result.stderr.encode("utf-8")
    return (b"revetsec-process-streams-v1\0"
            + len(stdout).to_bytes(8, "big") + stdout
            + len(stderr).to_bytes(8, "big") + stderr)


def process_output_receipt(result):
    stdout_bytes = result.stdout.encode("utf-8")
    stderr_bytes = result.stderr.encode("utf-8")
    return {
        "sha256": hashlib.sha256(canonical_process_output(result)).hexdigest(),
        "framing": "revetsec-process-streams-v1-length-prefixed-utf8",
        "stdoutBytes": len(stdout_bytes),
        "stderrBytes": len(stderr_bytes),
    }


def certificates(directory, public):
    directory.mkdir(mode=0o700)
    public.mkdir()
    def openssl(*arguments, expected=0):
        result = subprocess.run(["openssl", *arguments], cwd=directory, capture_output=True, timeout=30)
        if result.returncode != expected:
            raise RuntimeError("Owned TLS preparation failed")
    openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "ca.key")
    openssl("req", "-x509", "-new", "-key", "ca.key", "-sha256", "-days", "1", "-subj", "/CN=Revetsec-provider-Caddy-owned-CA", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", "ca.pem")
    openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "leaf.key")
    openssl("req", "-new", "-key", "leaf.key", "-subj", "/CN=app.example", "-out", "leaf.csr")
    (directory / "leaf.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:app.example\n")
    openssl("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "1", "-sha256", "-extfile", "leaf.ext", "-out", "leaf.pem")
    openssl("verify", "-CAfile", "ca.pem", "-verify_hostname", "app.example", "leaf.pem")
    openssl("verify", "-CAfile", "ca.pem", "-verify_hostname", "wrong.example", "leaf.pem", expected=2)
    for name in ["ca.pem", "leaf.pem"]:
        shutil.copyfile(directory / name, public / name)
    return {"caSha256": digest(directory / "ca.pem"), "leafSha256": digest(directory / "leaf.pem"), "subjectAltName": "DNS:app.example", "lifetimeDays": 1, "normalVerification": True, "systemTrustChanged": False}


def image_id(image):
    return required(["docker", "image", "inspect", "--format", "{{.Id}}", image])


def safe_topology(name):
    raw = required(["docker", "inspect", name])
    item = json.loads(raw)[0]
    return {"name": name, "image": item["Image"], "networkMode": item["HostConfig"]["NetworkMode"], "readOnlyRootfs": item["HostConfig"]["ReadonlyRootfs"], "capDrop": item["HostConfig"]["CapDrop"], "portBindings": item["HostConfig"]["PortBindings"], "running": item["State"]["Running"]}


def stack(mode, work, output, selection, credential):
    token = secrets.token_hex(5)
    prefix = f"revetsec-provider-caddy-{token}-{mode}"
    names = {kind: prefix + "-" + kind for kind in ["net", "backend", "caddy"]}
    output.mkdir()
    config = (SOURCE / "Caddyfile").read_text()
    if mode == "plant":
        before = 'expression `{orig_uri}.contains("?")`'
        after = 'expression `{orig_query} != ""`'
        if config.count(before) != 1:
            raise RuntimeError("Caddy calibration replacement unavailable")
        config = config.replace(before, after)
    config_path = work / f"Caddyfile-{mode}"
    config_path.write_text(config)
    shutil.copyfile(config_path, output / "Caddyfile")
    logs = {}
    log_streams = {}
    try:
        required(["docker", "run", "-d", "--name", names["net"], "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=8m", ALPINE_IMAGE, "sleep", "300"])
        required(["docker", "run", "-d", "--name", names["backend"], "--network", "container:" + names["net"], "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m", "--env", "REVETSEC_PROVIDER_FIXTURE_CREDENTIAL=" + credential, "--env", "REVETSEC_PROVIDER_CORE_JAR=/runtime/core.jar", "--env", "REVETSEC_PROVIDER_CORE_SHA256=" + selection["artifacts"]["core"]["sha256"], "--mount", f"type=bind,src={work / 'runtime'},dst=/runtime,readonly", "--mount", f"type=bind,src={selection['testClasses']},dst=/test,readonly", JAVA_IMAGE, "java", "-Djava.io.tmpdir=/tmp", "-cp", "/test:/runtime/carrier.jar:/runtime/common.jar:/runtime/core.jar:/runtime/framework.jar", "example.provider.soklet.ProviderSokletSocketFixture", "18080"])
        required(["docker", "run", "-d", "--name", names["caddy"], "--network", "container:" + names["net"], "--read-only", "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m", "--env", "XDG_DATA_HOME=/tmp/data", "--env", "XDG_CONFIG_HOME=/tmp/config", "--env", "REVETSEC_PROVIDER_FIXTURE_CREDENTIAL=" + credential, "--mount", f"type=bind,src={config_path},dst=/run/Caddyfile,readonly", "--mount", f"type=bind,src={work / 'tls'},dst=/tls,readonly", CADDY_IMAGE, "caddy", "run", "--config", "/run/Caddyfile", "--adapter", "caddyfile"])
        time.sleep(.5)
        result = execute(["docker", "run", "--rm", "--network", "container:" + names["net"], "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m", "--env", "REVETSEC_CADDY_PROBE_MODE=" + mode, "--env", "REVETSEC_PROVIDER_FIXTURE_CREDENTIAL=" + credential, "--mount", f"type=bind,src={SOURCE / 'probe.mjs'},dst=/probe.mjs,readonly", "--mount", f"type=bind,src={work / 'tls'},dst=/tls,readonly", "--mount", f"type=bind,src={output},dst=/evidence", NODE_IMAGE, "node", "/probe.mjs"], timeout=180)
        probe_receipt = process_output_receipt(result)
        logs["probe"] = probe_receipt.pop("sha256")
        log_streams["probe"] = probe_receipt
        topology = {kind: safe_topology(name) for kind, name in names.items()}
        for kind in ["backend", "caddy"]:
            log_result = execute(["docker", "logs", names[kind]])
            if log_result.returncode:
                raise RuntimeError("Owned qualification log capture failed")
            log_receipt = process_output_receipt(log_result)
            logs[kind] = log_receipt.pop("sha256")
            log_streams[kind] = log_receipt
        observed = json.loads((output / "RESULT.json").read_text())
        return {"exit": result.returncode, "result": observed, "topology": topology, "logSha256": logs, "logStreams": log_streams, "configSha256": digest(config_path)}
    finally:
        for name in [names["caddy"], names["backend"], names["net"]]:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=20)
        remaining = execute(["docker", "ps", "-a", "--filter", "name=" + prefix, "--format", "{{.Names}}"])
        if remaining.returncode or remaining.stdout.strip():
            raise RuntimeError("Owned container cleanup failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.output.is_absolute() or args.output.exists():
        parser.error("Use a new absolute output directory")
    artifact_paths = {
        "core": ROOT / "target/revetsec-1.0.0-SNAPSHOT.jar",
        "common": ROOT / "examples/provider-backend-tokens/target/revetsec-provider-backend-tokens-1.0.0-SNAPSHOT.jar",
        "carrier": ROOT / "examples/provider-backend-tokens-soklet/target/provider-backend-tokens-soklet-1.0.0-SNAPSHOT.jar",
        "framework": ROOT / "examples/provider-backend-tokens-soklet/target/lib/soklet-4.0.0.jar",
    }
    test_classes = ROOT / "examples/provider-backend-tokens-soklet/target/test-classes"
    sources = [
        ROOT / "examples/provider-backend-tokens/src/main/java/example/provider/ProviderTokens.java",
        ROOT / "examples/provider-backend-tokens/src/main/java/example/provider/BackendApplication.java",
        ROOT / "examples/provider-backend-tokens-soklet/src/main/java/example/provider/soklet/SokletProviderTokensRecipe.java",
        ROOT / "examples/provider-backend-tokens-soklet/src/test/java/example/provider/ProviderFixture.java",
        ROOT / "examples/provider-backend-tokens-soklet/src/test/java/example/provider/soklet/ProviderSokletSocketFixture.java",
        SOURCE / "Caddyfile", SOURCE / "probe.mjs", SOURCE / "run.py", SOURCE / "test_run.py",
    ]
    if any(not path.is_file() for path in [*artifact_paths.values(), *sources]) or not test_classes.is_dir():
        parser.error("Build current candidate artifacts and test classes first")
    selection = {"artifacts": {key: {"path": str(path), "sha256": digest(path)} for key, path in artifact_paths.items()}, "testClasses": str(test_classes), "sourceSha256": {str(path.relative_to(ROOT)): digest(path) for path in sources}, "images": {name: image_id(value) for name, value in {"caddy": CADDY_IMAGE, "java21": JAVA_IMAGE, "node24": NODE_IMAGE, "alpine": ALPINE_IMAGE}.items()}, "frameworkPinExpected": FRAMEWORK_SHA256}
    if selection["artifacts"]["framework"]["sha256"] != FRAMEWORK_SHA256:
        parser.error("Pinned Soklet framework differs")
    args.output.mkdir(parents=True)
    (args.output / "SELECTED-INPUTS.json").write_text(json.dumps(selection, indent=2) + "\n")
    receipt = {"status": "FAILED", "productionSourceChanged": False, "actualDeploymentDesignated": False, "ownerDeploymentGate": "OPEN", "selectedInputSha256": digest(args.output / "SELECTED-INPUTS.json")}
    with tempfile.TemporaryDirectory(prefix="revetsec-provider-caddy-") as temporary:
        work = Path(temporary)
        runtime = work / "runtime"
        runtime.mkdir()
        for key, path in artifact_paths.items():
            shutil.copyfile(path, runtime / (key + ".jar"))
        receipt["certificate"] = certificates(work / "tls", args.output / "certificates")
        credential = secrets.token_urlsafe(32)
        try:
            control = stack("control", work, args.output / "control", selection, credential)
            plant = stack("plant", work, args.output / "calibration", selection, credential)
            receipt["control"] = {"exit": control["exit"], "success": control["result"].get("success"), "checks": len(control["result"].get("checks", [])), "queryCases": len(control["result"].get("queryCases", [])), "failingBefore": control["result"].get("failingBefore"), "topology": control["topology"], "logSha256": control["logSha256"], "logStreams": control["logStreams"], "configSha256": control["configSha256"]}
            expected = {"type": "AssertionError", "check": "bare-query-valid-completion-never-dispatches"}
            detected = plant["exit"] == 1 and plant["result"].get("failure") == expected and plant["result"].get("plantEffect", {}).get("status") == 200 and plant["result"].get("plantEffect", {}).get("sessionsDelta") == 1 and plant["result"].get("plantEffect", {}).get("lookupsDelta") == 1 and plant["result"].get("plantEffect", {}).get("dispatchDelta") == 1
            receipt["calibration"] = {"exit": plant["exit"], "detected": detected, "expectedFailure": expected, "effect": plant["result"].get("plantEffect"), "topology": plant["topology"], "logSha256": plant["logSha256"], "logStreams": plant["logStreams"], "configSha256": plant["configSha256"], "plant": "nonempty-query-only"}
            receipt["sourcesStable"] = selection["sourceSha256"] == {str(path.relative_to(ROOT)): digest(path) for path in sources}
            receipt["artifactsStable"] = selection["artifacts"] == {key: {"path": str(path), "sha256": digest(path)} for key, path in artifact_paths.items()}
            receipt["privateRuntimeRemoved"] = False
            if control["exit"] == 0 and control["result"].get("success") and control["result"].get("observerClosed") and len(control["result"].get("queryCases", [])) == 40 and all(item.get("passed") for item in control["result"].get("queryCases", [])) and detected and receipt["sourcesStable"] and receipt["artifactsStable"]:
                receipt["status"] = "PASS_LOCAL_PINNED_CADDY_CURRENT_CANDIDATE"
        except BaseException as failure:
            receipt["failure"] = {"type": type(failure).__name__, "phase": "qualification-or-cleanup"}
    receipt["privateRuntimeRemoved"] = not work.exists()
    receipt["scope"] = "Disposable provider-only Caddy edge and current candidate; no deployed-ingress or owner-designation claim"
    receipt["sealedHistoricalPacketsModified"] = False
    (args.output / "RESULT.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return 0 if receipt["status"] == "PASS_LOCAL_PINNED_CADDY_CURRENT_CANDIDATE" and receipt["privateRuntimeRemoved"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
