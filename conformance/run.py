#!/usr/bin/env python3
# Copyright 2026 Revetware LLC.
# Licensed under the Apache License, Version 2.0. See ../LICENSE.
"""Build and drive a fresh local OIDF suite. No publication or hosted credentials."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid
from verify_report import verify

HERE = Path(__file__).resolve().parent
CORE = HERE.parent
IMAGES = [
 "registry.gitlab.com/openid/conformance-suite@sha256:69495f453a920c262f66e5e72abd12501c33e05ce88051cddf300c00621a4d70",
 "registry.gitlab.com/openid/conformance-suite/nginx@sha256:6ea3f4b8854f1f3626c81350900962d9e5f86424791d8e72b378a26ee2f4c105",
 "mongo:6.0.13@sha256:b415b12f638e2685d06c58ab7fb5943577c50fadec6d9340ef67d21aeac72070",
]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--maven", default="mvn")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--repository-tail", type=Path)
    parser.add_argument("--pull-images", action="store_true", help="Explicitly fetch the pinned images before starting")
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise ValueError("Use a fresh output directory")
    output.mkdir(parents=True)
    java_home = Path(os.environ["JAVA_HOME"])
    project = "revetsec-oidf-" + uuid.uuid4().hex[:16]
    with tempfile.TemporaryDirectory(prefix="revetsec-oidf-") as temp:
        temp = Path(temp)
        env = dict(os.environ, REVETSEC_OIDF_TLS_DIR=str(temp))
        compose = ["docker", "compose", "-p", project, "-f", str(HERE / "compose.yml")]
        def call(command, logfile, cwd=CORE):
            with (output / logfile).open("ab") as log:
                subprocess.run(command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=600)
        mvn = [args.maven, "-B", "-ntp", "-Dmaven.repo.local=" + str(temp / "repository")]
        if args.offline:
            mvn.append("-o")
        if args.repository_tail:
            mvn.append("-Dmaven.repo.local.tail=" + str(args.repository_tail.resolve()))
        call(mvn + ["-Dmaven.javadoc.skip=true", "-DskipTests", "install"], "core-build.log")
        call(mvn + ["-f", str(HERE / "pom.xml"), "clean", "package"], "driver-build.log")
        call(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "2",
            "-subj", "/CN=localhost.emobix.co.uk", "-addext", "subjectAltName=DNS:localhost.emobix.co.uk,DNS:localhost,IP:127.0.0.1",
            "-keyout", str(temp / "suite.key"), "-out", str(temp / "suite.crt")], "tls-generation.log")
        (temp / "suite.key").chmod(0o600)
        shutil.copyfile(temp / "suite.crt", output / "suite.crt")
        for image in IMAGES:
            if args.pull_images:
                call(["docker", "pull", image], "image-pull.log")
        images = subprocess.check_output(["docker", "image", "inspect", *IMAGES], env=env)
        (output / "images.json").write_bytes(images)
        attempted = False
        try:
            attempted = True
            call(compose + ["up", "-d", "--pull", "never"], "startup.log")
            ids = subprocess.check_output(compose + ["ps", "-q", "nginx"], env=env, text=True).strip()
            info = json.loads(subprocess.check_output(["docker", "inspect", ids], env=env, text=True))[0]
            ports = info["NetworkSettings"]["Ports"]
            for port in ("8443/tcp", "8444/tcp"):
                if ports[port] != [{"HostIp": "127.0.0.1", "HostPort": port.split("/")[0]}]:
                    raise ValueError("Suite port is not bound exclusively to loopback")
            (output / "proxy-inspect.json").write_text(json.dumps(info, indent=2))
            # curl verifies the generated certificate AND its hostname, with an explicit loopback resolution.
            ready = False
            for _ in range(60):
                probe = subprocess.run(["curl", "--fail", "--silent", "--show-error", "--max-time", "2", "--cacert", str(temp / "suite.crt"),
                    "--resolve", "localhost.emobix.co.uk:8443:127.0.0.1", "https://localhost.emobix.co.uk:8443/api/server"], capture_output=True)
                if probe.returncode == 0:
                    server = json.loads(probe.stdout)
                    if server.get("tag") != "release-v5.3.1" or server.get("revision") != "440eec8":
                        raise ValueError("Unexpected suite revision")
                    ready = True
                    break
                time.sleep(1)
            if not ready:
                raise TimeoutError("Local suite did not become ready")
            (temp / "hosts").write_text("127.0.0.1 localhost.emobix.co.uk localhost\n")
            classpath = str(HERE / "target/classes") + os.pathsep + str(CORE / "target/revetsec-1.0.0-SNAPSHOT.jar")
            call([str(java_home / "bin/java"), "-Djdk.net.hosts.file=" + str(temp / "hosts"), "-cp", classpath, "example.OidfDriver", str(temp / "suite.crt"), str(output / "suite"), str(HERE / "plans.json")], "driver.log")
            dispositions = verify(output / "suite")
            (output / "suite/dispositions.json").write_text(json.dumps(dispositions, indent=2) + "\n")
            print("OIDF gate passed: 60 executed modules, four documented unsigned-token skips, five source-selected comprehensive profile exclusions")
        finally:
            if attempted:
                try:
                    call(compose + ["logs", "--no-color"], "containers.log")
                finally:
                    call(compose + ["down", "-v", "--timeout", "0"], "teardown.log")

if __name__ == "__main__":
    main()
