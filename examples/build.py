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

"""Build unpublished examples using source pins and a private Maven repository."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PINS = json.loads((ROOT / "examples/pins.json").read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--maven", required=True, type=Path)
    parser.add_argument("--java-home", required=True, type=Path)
    parser.add_argument("--core-source", required=True, type=Path)
    parser.add_argument("--adapter-source", required=True, type=Path)
    parser.add_argument("--framework-source", type=Path)
    parser.add_argument("--framework-jar", type=Path)
    parser.add_argument("--repository-tail", type=Path)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    if (not args.work.is_absolute() or args.work.exists() or not args.maven.is_file()
            or not (args.java_home / "bin/java").is_file()
            or bool(args.framework_source) == bool(args.framework_jar)):
        parser.error("Use a new absolute work directory, real tools, and one framework source or pinned JAR")
    args.work.mkdir(parents=True, mode=0o700)
    env = {**os.environ, "JAVA_HOME": str(args.java_home),
           "PATH": str(args.java_home / "bin") + os.pathsep + os.environ["PATH"]}
    repo = args.work / "repository"
    records = []

    def run(label, command, cwd):
        with (args.work / (label + ".log")).open("w") as log:
            result = subprocess.run(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                    stdout=log, stderr=subprocess.STDOUT)
        records.append({"label": label, "command": [str(x) for x in command],
                        "cwd": str(cwd), "exit": result.returncode})
        (args.work / "COMMANDS.json").write_text(json.dumps(records, indent=2) + "\n")
        if result.returncode:
            raise RuntimeError("Build failed: " + label + "; see " + str(args.work / (label + ".log")))

    def copy_source(label, source, require_exact=False):
        source = source.resolve()
        revision = PINS[label]["revision"]
        actual = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        if require_exact and actual != revision:
            raise RuntimeError("Framework source must match its exact pin")
        # Docs, examples and CI can evolve without changing the pinned library artifact.
        subprocess.run(["git", "-C", str(source), "diff", "--exit-code", revision,
                        "--", "pom.xml", "src/main"], check=True, stdout=subprocess.DEVNULL)
        untracked = subprocess.check_output(["git", "-C", str(source), "ls-files", "--others",
                                             "--exclude-standard", "--", "src/main"], text=True)
        if untracked.strip():
            raise RuntimeError("Untracked library source does not match the selected artifact pin")
        destination = args.work / label
        shutil.copytree(source, destination, ignore=shutil.ignore_patterns(
            "target", "node_modules", ".gradle", "__pycache__"))
        return destination

    command = [str(args.maven), "-B", "-ntp", "-Dmaven.repo.local=" + str(repo),
               "-Dmaven.javadoc.skip=true", "-Dgpg.skip=true"]
    if args.offline:
        command.append("-o")
    if args.repository_tail:
        command.append("-Dmaven.repo.local.tail=" + str(args.repository_tail.resolve()))
    core = copy_source("core", args.core_source)
    adapter = copy_source("adapter", args.adapter_source)
    run("core-install", command + ["-DskipTests", "clean", "install"], core)
    run("adapter-install", command + ["-DskipTests", "clean", "install"], adapter)
    if args.framework_source:
        framework = copy_source("framework", args.framework_source, require_exact=True)
        run("framework-install", command + ["-Dmaven.test.skip=true", "clean", "install"], framework)
        framework_jar = framework / "target/soklet-4.0.0.jar"
        if sha(framework_jar) != PINS["framework"]["jar_sha256"]:
            raise RuntimeError("Framework source build does not match its recorded artifact pin")
    else:
        framework_jar = args.framework_jar.resolve()
        if sha(framework_jar) != PINS["framework"]["jar_sha256"]:
            raise RuntimeError("Framework JAR checksum does not match the approved source-built artifact")
        framework_path = repo / "com/soklet/soklet/4.0.0"
        framework_path.mkdir(parents=True, exist_ok=True)
        shutil.copy2(framework_jar, framework_path / "soklet-4.0.0.jar")
        (framework_path / "soklet-4.0.0.pom").write_text(
            '<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>'
            '<groupId>com.soklet</groupId><artifactId>soklet</artifactId><version>4.0.0</version></project>')
    result = {"pins": PINS, "builtWithJava": str(args.java_home), "examples": {}}
    for name in ("barebones-oidc", "playground"):
        example = args.work / "examples" / name
        shutil.copytree(ROOT / "examples" / name, example,
                        ignore=shutil.ignore_patterns("target", "__pycache__"))
        run(name + "-verify", command + ["clean", "verify"], example)
        test_dependencies = example / "target/test-classpath.txt"
        run(name + "-test-classpath", command + ["dependency:build-classpath", "-DincludeScope=test",
            "-Dmdep.outputFile=" + str(test_dependencies)], example)
        audit_classpath = example / "target/audit-classpath.txt"
        audit_classpath.write_text(str(example / "target/classes") + os.pathsep + test_dependencies.read_text().strip())
        source_list = example / "target/audit-sources.txt"
        checker = ROOT / "verification/examples/NullabilityAudit.java"
        source_list.write_text("\n".join(str(path) for path in [
            *sorted((example / "src/main/java").rglob("*.java")),
            *sorted((example / "src/test/java").rglob("*.java")), checker]) + "\n")
        run(name + "-explicit-nullability", [str(args.java_home / "bin/java"), "-cp",
            audit_classpath.read_text(), str(checker), str(source_list), str(audit_classpath),
            str(example / "target/nullability-audit.json")], example)
        dependencies = [Path(x) for x in (example / "target/runtime-classpath.txt").read_text().strip().split(os.pathsep)]
        expected = {"revetsec-1.0.0-SNAPSHOT.jar", "revetsec-soklet-1.0.0-SNAPSHOT.jar", "soklet-4.0.0.jar"}
        if len(dependencies) != 3 or {x.name for x in dependencies} != expected:
            raise RuntimeError("Unexpected runtime dependencies for " + name)
        framework_dependency = next(x for x in dependencies if x.name.startswith("soklet-"))
        if sha(framework_dependency) != PINS["framework"]["jar_sha256"]:
            raise RuntimeError("Pinned framework artifact changed")
        artifacts = [*dependencies, *sorted((example / "target").glob("*.jar"))]
        result["examples"][name] = {"directory": str(example), "runtimeDependencies": [str(x) for x in dependencies],
                                    "nullability": json.loads((example / "target/nullability-audit.json").read_text()),
                                    "artifacts": {str(x): sha(x) for x in artifacts}}
    (args.work / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Both examples built and tested; runtime has only core, adapter and declared Soklet dependency JARs.")


if __name__ == "__main__":
    main()
