#
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
#

"""Runs the scripted-IdP M0 spike end to end and prints the measurements.

Builds the image (never pushes it), runs the selftest into a host directory, cross-checks
the outputs with each given JDK (spike/Crosscheck.java), shows that the cross-check fails
on tampered copies, and times `serve` from `docker run` to the first good /health.

  python3 spike/run_spike.py --java-home /path/to/jdk-17 [--java-home ...] [--no-cache]

Needs Docker, a JDK and Python 3.9+; nothing else on the host.
"""

import argparse
import http.client
import json
import os
import pathlib
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
CROSSCHECK = ROOT / "spike" / "Crosscheck.java"

# Throwaway TLS for the startup measurement, made with the image's own pyca/cryptography.
MAKE_TLS = """
import datetime, ipaddress, pathlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                       x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256()))
out = pathlib.Path("/tls")
(out / "server.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
(out / "server.key").write_bytes(key.private_bytes(serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
for path in out.iterdir():
    path.chmod(0o444)
"""


def run(command, check=True, **kwargs):
    print("+ " + " ".join(str(part) for part in command), flush=True)
    return subprocess.run([str(part) for part in command], check=check, text=True, **kwargs)


def build(tag, no_cache):
    started = time.monotonic()
    run(["docker", "build", *(["--no-cache"] if no_cache else []), "-t", tag, ROOT])
    seconds = time.monotonic() - started
    size = int(run(["docker", "image", "inspect", "-f", "{{.Size}}", tag], capture_output=True).stdout.strip())
    return {"buildSeconds": round(seconds, 1), "imageBytes": size}


def selftest(tag, out):
    out.mkdir(parents=True)
    out.chmod(0o777)  # the container runs as uid 65534
    started = time.monotonic()
    result = run(["docker", "run", "--rm", "-v", f"{out}:/out", tag, "selftest", "--out", "/out"], check=False)
    return {"ok": result.returncode == 0, "seconds": round(time.monotonic() - started, 1)}


def crosscheck(java_home, out, expect_ok=True):
    result = run([pathlib.Path(java_home) / "bin" / "java", CROSSCHECK, out], check=False,
                 capture_output=True)
    print(result.stdout + result.stderr, end="")
    fails = [line.split(":")[0].split()[1] for line in result.stdout.splitlines() if line.startswith("FAIL ")]
    return {"ok": (result.returncode == 0) == expect_ok, "exit": result.returncode, "failed": fails}


def tampered_copy(out, work):
    """A copy in which case1's signed content and case4's GCM ciphertext are each altered by one character."""
    copy = work / "tampered"
    shutil.copytree(out, copy)
    case1 = copy / "case1-response-assertion-rsa-sha256.xml"
    case1.write_bytes(case1.read_bytes().replace(b">user-1<", b">user-X<", 1))
    case4 = next(copy.glob("case4-*.xml"))
    data = case4.read_bytes()
    at = data.rindex(b"<xenc:CipherValue>") + len(b"<xenc:CipherValue>")
    case4.write_bytes(data[:at] + (b"B" if data[at:at + 1] == b"A" else b"A") + data[at + 1:])
    return copy


def serve_startup(tag, work):
    tls = work / "tls"
    tls.mkdir()
    tls.chmod(0o777)
    # The container (uid 65534) owns the files it writes, so MAKE_TLS sets their modes itself. On rootful
    # Linux Docker the host user could not chmod them; Docker Desktop hides that by mapping ownership.
    run(["docker", "run", "--rm", "-v", f"{tls}:/tls", "--entrypoint", "python", tag, "-c", MAKE_TLS])
    context = ssl.create_default_context(cafile=str(tls / "server.crt"))
    name = f"scripted-idp-spike-{os.getpid()}"
    started = time.monotonic()
    run(["docker", "run", "-d", "--name", name, "-p", "127.0.0.1::8443", "-v", f"{tls}:/run/tls:ro",
         "-e", "SCRIPTED_IDP_TLS_CERT=/run/tls/server.crt", "-e", "SCRIPTED_IDP_TLS_KEY=/run/tls/server.key",
         tag, "serve"], capture_output=True)
    try:
        port = run(["docker", "port", name, "8443/tcp"], capture_output=True).stdout.strip().rsplit(":", 1)[1]
        health = None
        while health is None and time.monotonic() - started < 30:
            try:
                with urllib.request.urlopen(f"https://localhost:{port}/health", context=context, timeout=2) as response:
                    health = json.load(response)
            except (OSError, http.client.HTTPException):
                time.sleep(0.02)
        ready = time.monotonic() - started
        stop_started = time.monotonic()
        run(["docker", "stop", "-t", "10", name], capture_output=True)
        stop = time.monotonic() - stop_started
    finally:
        run(["docker", "rm", "-f", name], check=False, capture_output=True)
    return {"ok": health is not None and health.get("status") == "ok", "runToHealthySeconds": round(ready, 2),
            "stopSeconds": round(stop, 2), "health": health}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--java-home", action="append", required=True, help="JDK to run Crosscheck.java with")
    parser.add_argument("--tag", default="revetsec-scripted-idp:spike")
    parser.add_argument("--no-cache", action="store_true", help="rebuild every layer (the base image stays pulled)")
    parser.add_argument("--out", type=pathlib.Path, help="selftest output directory (default: a new temp dir)")
    args = parser.parse_args()

    work = pathlib.Path(tempfile.mkdtemp(prefix="scripted-idp-spike-"))
    out = args.out or work / "out"
    report = {"image": build(args.tag, args.no_cache), "selftest": selftest(args.tag, out), "crosscheck": {}}
    tampered = tampered_copy(out, work)
    for java_home in args.java_home:
        report["crosscheck"][java_home] = crosscheck(java_home, out)
        negative = crosscheck(java_home, tampered, expect_ok=False)
        negative["ok"] = negative["ok"] and set(negative["failed"]) == {"case1", "case4"}
        report["crosscheck"][java_home + " (tampered copy)"] = negative
    report["serve"] = serve_startup(args.tag, work)

    print(json.dumps(report, indent=2))
    print(f"outputs: {out}")
    checks = [report["selftest"], report["serve"], *report["crosscheck"].values()]
    return 0 if all(check["ok"] for check in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
