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

"""Build/run the self-issued example from exact authored core/helper copies; all work stays private."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(source):
    names = sorted(set(subprocess.check_output(["git", "ls-files", "--cached", "--others",
                    "--exclude-standard", "-z"], cwd=source).decode().split("\0")) - {""})
    rows = []
    for name in names:
        path = source / name
        if not path.is_file() or path.is_symlink() or ".." in Path(name).parts:
            raise RuntimeError("Unexpected authored source entry")
        rows.append({"path": name, "sha256": digest(path)})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--maven", type=Path, required=True)
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--core-source", type=Path, required=True)
    parser.add_argument("--adapter-source", type=Path, required=True)
    parser.add_argument("--framework-jar", type=Path, required=True)
    parser.add_argument("--repository-tail", type=Path)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    args.core_source = args.core_source.resolve()
    args.adapter_source = args.adapter_source.resolve()
    if digest(args.framework_jar) != "c454eac7ff5fd58d564a2c1603133ed1c47a01210d2910be4d60f392ebe1184f":
        parser.error("Use the pinned Soklet framework JAR")
    if (not args.work.is_absolute() or args.work.exists() or not args.maven.is_file()
            or not (args.java_home / "bin/keytool").is_file()
            or args.work.resolve().is_relative_to(args.core_source)
            or args.work.resolve().is_relative_to(args.adapter_source)):
        parser.error("Use new absolute private work outside core and existing toolchain paths")
    args.work.mkdir(mode=0o700, parents=True)
    rows = inventory(args.core_source)
    (args.work / "SOURCE-INVENTORY.json").write_text(json.dumps(rows, indent=2) + "\n")
    core = args.work / "core"
    for row in rows:
        target = core / row["path"]; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(args.core_source / row["path"], target)
    shutil.copytree(args.core_source / ".git", core / ".git")
    if inventory(core) != rows:
        raise RuntimeError("Private core copy changed")
    adapter = args.work / "adapter"
    adapter_rows = inventory(args.adapter_source)
    (args.work / "ADAPTER-INVENTORY.json").write_text(json.dumps(adapter_rows, indent=2) + "\n")
    for row in adapter_rows:
        target = adapter / row["path"]; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(args.adapter_source / row["path"], target)
    shutil.copytree(args.adapter_source / ".git", adapter / ".git")
    if inventory(adapter) != adapter_rows: raise RuntimeError("Private adapter source changed")
    fw = args.work / "repository/com/soklet/soklet/4.0.0"; fw.mkdir(parents=True)
    shutil.copy2(args.framework_jar, fw / "soklet-4.0.0.jar")
    (fw / "soklet-4.0.0.pom").write_text('<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>com.soklet</groupId><artifactId>soklet</artifactId><version>4.0.0</version></project>')
    example = args.work / "example"
    # Read the example from the same frozen input as the library, never from another checkout.
    shutil.copytree(core / "examples/self-issued", example)
    env = {**os.environ, "JAVA_HOME": str(args.java_home), "PATH": str(args.java_home / "bin") + os.pathsep + os.environ["PATH"]}
    records = []

    def run(label, command, cwd):
        command = [str(x) for x in command]
        with (args.work / (label + ".log")).open("w") as log:
            code = subprocess.run(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                  stdout=log, stderr=subprocess.STDOUT).returncode
        records.append({"label": label, "command": command, "cwd": str(cwd), "exit": code})
        (args.work / "COMMANDS.json").write_text(json.dumps(records, indent=2) + "\n")
        if code:
            raise RuntimeError("Example step failed: " + label + "; see private log")

    command = [args.maven, "-B", "-ntp", "-Dmaven.repo.local=" + str(args.work / "repository"), "-Dmaven.javadoc.skip=true"]
    if args.offline: command.append("-o")
    if args.repository_tail: command.append("-Dmaven.repo.local.tail=" + str(args.repository_tail.resolve()))
    run("core-install", command + ["-DskipTests", "clean", "install"], core)
    run("adapter-install", command + ["-DskipTests", "clean", "install"], adapter)
    run("example-verify", command + ["clean", "verify"], example)
    test_cp = example / "target/test-classpath.txt"
    run("test-classpath", command + ["dependency:build-classpath", "-DincludeScope=test", "-Dmdep.outputFile=" + str(test_cp)], example)
    audit_cp = example / "target/audit-classpath.txt"
    audit_cp.write_text(str(example / "target/classes") + os.pathsep + test_cp.read_text().strip())
    checker = core / "verification/examples/NullabilityAudit.java"
    source_list = example / "target/audit-sources.txt"
    source_list.write_text("\n".join(str(p) for p in [*sorted((example / "src").rglob("*.java")), checker]) + "\n")
    run("explicit-nullability", [args.java_home / "bin/java", "-cp", audit_cp.read_text(), checker, source_list, audit_cp, example / "target/nullability-audit.json"], example)
    runtime = [Path(x) for x in (example / "target/runtime-classpath.txt").read_text().strip().split(os.pathsep)]
    if sorted(p.name for p in runtime) != ["revetsec-1.0.0-SNAPSHOT.jar", "revetsec-soklet-1.0.0-SNAPSHOT.jar", "soklet-4.0.0.jar"]:
        raise RuntimeError("Example runtime must contain exactly core, helper and framework JARs")
    cp = os.pathsep.join([str(example / "target/test-classes"), str(example / "target/classes"), *map(str, runtime)])
    run("annotation-free-runtime", [args.java_home / "bin/java", "-cp", cp,
        "example.issuer.RuntimeSmoke", args.work / "CAPTURE.json"], example)
    capture = json.loads((args.work / "CAPTURE.json").read_text())
    if not all(capture[k] for k in ("freshInitialization", "httpMetadata", "annotationFreeRuntime")) or capture["externalServices"]:
        raise RuntimeError("Runtime capture failed")
    if inventory(core) != rows or inventory(args.core_source) != rows or inventory(adapter) != adapter_rows or inventory(args.adapter_source) != adapter_rows:
        raise RuntimeError("Authored source changed during the build")
    artifacts = [*runtime, *sorted((example / "target").glob("*.jar"))]
    result = {"status": "PASS", "sourceInventorySha256": digest(args.work / "SOURCE-INVENTORY.json"),
              "runtimeDependencies": [str(p) for p in runtime], "artifacts": {str(p): digest(p) for p in artifacts},
              "nullability": json.loads((example / "target/nullability-audit.json").read_text()),
              "captureSha256": digest(args.work / "CAPTURE.json"), "adapterInventorySha256": digest(args.work / "ADAPTER-INVENTORY.json"), "ciPinsQualified": False, "durableOrDistributedStoreQualified": False, "independentConsumerQualified": False}
    (args.work / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Self-issued example built, tested, attributed and run without annotation dependencies; local source qualification only.")


if __name__ == "__main__":
    main()
