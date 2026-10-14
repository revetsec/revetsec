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

"""Qualify the narrow compiled SCIM PATCH recipe against one owned PostgreSQL primary."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent
CORE = ROOT.parent.parent


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("java-home", "core-jar", "pyranid-jar", "driver-jar", "jspecify-jar", "jsr305-jar", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    image = json.loads((CORE / "interop/scim/pins.json").read_text())["postgres"]["image"]
    sources = [ROOT / "src/main/java/example/pending/PostgresqlPyranidDataSource.java",
               ROOT / "src/main/java/example/pending/PostgresqlScimPatch.java",
               ROOT / "src/test/java/example/pending/ScimStoreProbe.java"]
    inputs = sources + [ROOT / "scim-schema.sql", Path(__file__), CORE / "interop/scim/pins.json"]
    jars = [args.core_jar, args.pyranid_jar, args.driver_jar, args.jspecify_jar, args.jsr305_jar]
    args.output.mkdir(parents=True, exist_ok=True)
    receipt = {"success": False, "checks": [], "postgresImage": image, "ownedContainerRemoved": False,
               "ownedVolumeRemoved": False, "sourceInputs": {str(path.relative_to(CORE)): sha(path) for path in inputs},
               "artifacts": {path.name: sha(path) for path in jars}}
    checks = receipt["checks"]
    def check(condition, name):
        if not condition: raise RuntimeError(name)
        checks.append(name)
    def docker(*command, input_text=None, required=True):
        result = subprocess.run(["docker", *command], input=input_text, capture_output=True, text=True, timeout=45)
        if required and result.returncode: raise RuntimeError("owned-postgres-command-failed-" + command[0])
        return result
    name = "revetsec-scim-store-" + secrets.token_hex(6)
    volume = name + "-data"
    created_container = False; created_volume = False
    children = []
    try:
        docker("image", "inspect", image)
        with tempfile.TemporaryDirectory(prefix="revetsec-scim-store-") as temporary:
            work = Path(temporary); classes = work / "classes"; classes.mkdir()
            artifacts = work / "artifacts"; artifacts.mkdir()
            private_jars = []
            for index, path in enumerate(jars):
                private = artifacts / (str(index) + "-" + path.name)
                private.write_bytes(path.read_bytes())
                if sha(private) != receipt["artifacts"][path.name]:
                    raise RuntimeError("input-artifact-changed-before-private-copy")
                private_jars.append(private)
            classpath = os.pathsep.join([str(classes), *map(str, private_jars)])
            compiled = subprocess.run([str(args.java_home / "bin/javac"), "--release", "17", "-parameters", "-proc:none",
                "-Xlint:all", "-Werror", "-cp", classpath, "-d", str(classes), *map(str, sources)],
                capture_output=True, text=True, timeout=60)
            if compiled.returncode: raise RuntimeError("warning-fatal-scim-recipe-compile: " + compiled.stderr[-3000:])
            check(True, "warning-fatal-recipe-and-probe-compiled-release17")
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0)); port = reservation.getsockname()[1]
            password = secrets.token_urlsafe(24)
            environment_file = work / "postgres.env"
            environment_file.write_text("POSTGRES_PASSWORD=" + password + "\nPOSTGRES_DB=scim_fixture\n"); environment_file.chmod(0o600)
            docker("volume", "create", "--label", "com.revetsec.owned-fixture=true", volume); created_volume = True
            docker("run", "--pull=never", "-d", "--name", name, "--label", "com.revetsec.owned-fixture=true",
                   "--memory", "256m", "--cpus", "1", "--security-opt", "no-new-privileges",
                   "-p", "127.0.0.1:" + str(port) + ":5432", "--env-file", str(environment_file),
                   "--mount", "type=volume,source=" + volume + ",target=/var/lib/postgresql/data", image)
            created_container = True
            def ready():
                deadline = time.monotonic() + 25
                while time.monotonic() < deadline:
                    if docker("exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "scim_fixture", required=False).returncode == 0:
                        return
                    time.sleep(0.1)
                raise RuntimeError("bounded-owned-postgres-readiness")
            ready()
            sql = (ROOT / "scim-schema.sql").read_text()
            timestamp = "2026-10-13T00:00:00Z"
            for tenant in ("basic", "rollback", "unknown", "cap", "race", "persist", "isolated"):
                sql += "\nINSERT INTO scim_fixture_tenant(tenant) VALUES ('" + tenant + "');\n"
                for index, username in ((1, "alice"), (2, "bob"), (3, "carol")):
                    sql += f"INSERT INTO scim_fixture_resource(tenant,id,kind,user_name,name_key,display_name,active,version,created,modified) VALUES ('{tenant}','u{index}','User','{username}','{username}','original',true,1,'{timestamp}','{timestamp}');\n"
                sql += f"INSERT INTO scim_fixture_resource(tenant,id,kind,display_name,version,created,modified) VALUES ('{tenant}','g','Group','original',1,'{timestamp}','{timestamp}');\n"
                sql += f"INSERT INTO scim_fixture_member(tenant,group_id,ordinal,user_id) VALUES ('{tenant}','g',0,'u1'),('{tenant}','g',1,'u2');\n"
            for index in range(1, 41):
                identity = "large" + str(index) + "x" * 100
                sql += f"INSERT INTO scim_fixture_resource(tenant,id,kind,user_name,name_key,display_name,active,version,created,modified) VALUES ('cap','{identity}','User','large{index}','large{index}','original',true,1,'{timestamp}','{timestamp}');\n"
            docker("exec", "-i", name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "scim_fixture", input_text=sql)
            environment = dict(os.environ)
            environment.update(REVETSEC_TEST_DB_USER="postgres", REVETSEC_TEST_DB_PASSWORD=password,
                               REVETSEC_TEST_DB_URL="jdbc:postgresql://127.0.0.1:" + str(port) + "/scim_fixture")
            environment.pop("JAVA_TOOL_OPTIONS", None); environment.pop("JDK_JAVA_OPTIONS", None)
            command = [str(args.java_home / "bin/java"), "-cp", classpath, "example.pending.ScimStoreProbe"]
            def probe(mode, expected):
                result = subprocess.run([*command, mode], capture_output=True, text=True, env=environment, timeout=30)
                check(result.returncode == 0 and result.stdout.strip() == expected, "real-postgres-" + mode)
            probe("basic", "BASIC_PASS")
            probe("rollback", "ROLLBACK_PASS")
            probe("unknown", "UNKNOWN_PASS")
            probe("cap", "CAP_PASS")
            for label in ("left", "right"):
                child = subprocess.Popen([*command, "race", label], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, text=True, env=environment)
                children.append(child)
            for child in children:
                assert child.stdout is not None
                readable, _, _ = select.select([child.stdout], [], [], 15)
                check(bool(readable) and child.stdout.readline().strip() == "RACE_READY", "two-jvm-race-node-ready")
            for child in children:
                assert child.stdin is not None; child.stdin.write("GO\n"); child.stdin.flush()
            results = []
            for child in children:
                output, _ = child.communicate(timeout=15)
                check(child.returncode == 0, "two-jvm-race-node-completed"); results.append(output.strip())
            check(sorted(results) == ["RACE_COMMITTED", "RACE_REJECTED_412"], "two-jvm-race-one-commit-one-stale-version")
            children.clear()
            probe("verify-race", "RACE_PASS")
            probe("persist", "PERSISTED_PASS")
            docker("stop", "--time", "3", name)
            probe("outage", "OUTAGE_PASS")
            docker("start", name); ready()
            probe("recovered", "RECOVERED_PASS")
            receipt["success"] = True
    except Exception as failure:
        receipt["failure"] = str(failure)[:3000]
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
                try: child.wait(timeout=5)
                except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=5)
        if created_container:
            docker("rm", "-f", name, required=False)
            receipt["ownedContainerRemoved"] = docker("inspect", name, required=False).returncode != 0
        if created_volume:
            docker("volume", "rm", volume, required=False)
            receipt["ownedVolumeRemoved"] = docker("volume", "inspect", volume, required=False).returncode != 0
        if receipt["sourceInputs"] != {str(path.relative_to(CORE)): sha(path) for path in inputs}:
            receipt["success"] = False; receipt["failure"] = "source-changed-during-qualification"
        (args.output / "RESULT.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"success": receipt["success"], "checks": len(checks), "ownedContainerRemoved": receipt["ownedContainerRemoved"],
                      "ownedVolumeRemoved": receipt["ownedVolumeRemoved"]}))
    if not receipt["success"] or not receipt["ownedContainerRemoved"] or not receipt["ownedVolumeRemoved"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
