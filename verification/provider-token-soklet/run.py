#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Run the source-bound private Soklet/fake-provider component matrix after the normal Maven build."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import zipfile
from matrix import exercise

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inputs(args):
    examples = args.examples_root.resolve()
    common = examples / "provider-backend-tokens/target/revetsec-provider-backend-tokens-1.0.0-SNAPSHOT.jar"
    carrier = examples / "provider-backend-tokens-soklet/target/provider-backend-tokens-soklet-1.0.0-SNAPSHOT.jar"
    fixtures = examples / "provider-backend-tokens-soklet/target/test-classes"
    # These are the actual copies selected by the normal Maven JAR manifests.
    core = common.parent / "lib/revetsec-1.0.0-SNAPSHOT.jar"
    framework = carrier.parent / "lib/soklet-4.0.0.jar"
    java = args.java_home.resolve() / "bin/java"
    for path in [common, carrier, core, framework, java]:
        if not path.is_file():
            raise ValueError("Required built input is unavailable")
    for path in [common, carrier, core, framework]:
        if path.stat().st_size > 16_777_216:
            raise ValueError("Built input exceeds verification ceiling")
    if digest(core) != args.core_sha256 or digest(framework) != args.framework_sha256:
        raise ValueError("Selected runtime artifact digest mismatch")
    if not (fixtures / "example/provider/soklet/ProviderSokletSocketFixture.class").is_file():
        raise ValueError("Private socket fixture is unavailable")
    if any((fixtures / "com/revetsec").rglob("*.class")):
        raise ValueError("Test classes must not shadow the selected core")
    allowed = {digest(path) for path in [common, carrier, core, framework]}
    for jar in [common, carrier, core, framework]:
        with zipfile.ZipFile(jar) as archive:
            manifest = archive.read("META-INF/MANIFEST.MF").decode("utf-8").replace("\r\n ", "")
        for line in manifest.splitlines():
            if line.startswith("Class-Path: "):
                for name in line.removeprefix("Class-Path: ").split():
                    dependency = jar.parent / name
                    if ":" in name or name.startswith("/") or not dependency.is_file() or digest(dependency) not in allowed:
                        raise ValueError("Unselected manifest runtime dependency")
    watched = [common, carrier, core, framework, Path(__file__), Path(__file__).with_name("matrix.py")]
    for module in ["provider-backend-tokens", "provider-backend-tokens-soklet"]:
        watched.extend(sorted((examples / module / "src").rglob("*.java")))
    return java, common, carrier, fixtures, core, framework, watched


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--examples-root", type=Path, default=ROOT / "examples")
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--core-sha256", required=True)
    parser.add_argument("--framework-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        selected = inputs(args)
        if not args.output.is_absolute() or args.output.exists():
            raise ValueError("Output must be a new absolute directory")
    except (OSError, ValueError) as failure:
        parser.error(str(failure))
    java, common, carrier, fixtures, core, framework, watched = selected
    before = {str(path): digest(path) for path in watched}
    args.output.mkdir(parents=True)
    with socket.socket() as available:
        available.bind(("127.0.0.1", 0))
        port = available.getsockname()[1]
    environment = os.environ.copy()
    environment.update(REVETSEC_PROVIDER_CORE_JAR=str(core.resolve()),
                       REVETSEC_PROVIDER_CORE_SHA256=args.core_sha256,
                       REVETSEC_PROVIDER_FIXTURE_CREDENTIAL=secrets.token_urlsafe(24))
    classpath = os.pathsep.join(map(str, [common, carrier, fixtures, core, framework]))
    receipt = {
        "status": "IN_PROGRESS", "success": False, "qualifiedProfile": False,
        "checks": [], "requests": [], "sourceHashesBefore": before,
        "selectedCoreSha256": args.core_sha256, "selectedFrameworkSha256": args.framework_sha256,
        "classpath": [str(path) for path in [common, carrier, fixtures, core, framework]],
        "runtimeAnnotationsAndJUnitAbsent": True,
        "scope": "Actual owned Soklet/fake-JWKS application components; trusted TLS/query-rejection edge, browser, hosted provider and distributed/profile qualification remain open."
    }
    process = None
    try:
        with (args.output / "server.log").open("w") as log:
            process = subprocess.Popen([str(java), "-cp", classpath,
                                        "example.provider.soklet.ProviderSokletSocketFixture", str(port)],
                                       env=environment, stdout=log, stderr=subprocess.STDOUT)
            exercise(port, environment["REVETSEC_PROVIDER_FIXTURE_CREDENTIAL"], process, receipt)
    except Exception as failure:
        receipt["success"] = False
        receipt["failure"] = {"type": type(failure).__name__,
                              "checkpoint": receipt["checks"][-1]["name"] if receipt["checks"] else "startup",
                              "message": str(failure)[:200]}
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        receipt["ownedProcessStopped"] = process is None or process.poll() is not None
        with socket.socket() as probe:
            probe.settimeout(1)
            receipt["ownedListenerClosed"] = probe.connect_ex(("127.0.0.1", port)) != 0
        receipt["sourceHashesAfter"] = {}
        for path in watched:
            try:
                receipt["sourceHashesAfter"][str(path)] = digest(path)
            except OSError:
                receipt["sourceHashesAfter"][str(path)] = "UNREADABLE_OR_MISSING"
        receipt["sourceStable"] = receipt["sourceHashesAfter"] == before
        if not all(receipt[key] for key in ["ownedProcessStopped", "ownedListenerClosed", "sourceStable"]):
            receipt["success"] = False
        receipt["status"] = "COMPONENT_CHECKS_PASS_PROFILE_GAPS_OPEN" if receipt["success"] else "FAIL"
        (args.output / "RESULT.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({key: receipt.get(key) for key in ["status", "failure", "sourceStable", "ownedProcessStopped", "ownedListenerClosed"]}
                     | {"observations": len(receipt["checks"]), "qualifiedProfile": False}))
    return 0 if receipt["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
