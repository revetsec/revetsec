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

"""Compile the Soklet TOTP integration against exact local JARs into a new private directory."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import zipfile


ROOT = Path(__file__).resolve().parent
FRAMEWORK_PIN = json.loads((ROOT.parent / "pins.json").read_text())["framework"]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True, help="new private output directory")
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--core-jar", type=Path, required=True)
    parser.add_argument("--soklet-jar", type=Path, required=True)
    parser.add_argument("--jspecify-jar", type=Path, required=True)
    parser.add_argument("--jsr305-jar", type=Path, required=True)
    parser.add_argument("--socket-check", action="store_true", help="exercise an actual loopback Soklet listener")
    args = parser.parse_args()

    work = args.work.resolve()
    repository = ROOT.parents[1]
    if work.exists() or work == repository or repository in work.parents:
        parser.error("--work must be a new private directory outside the source tree")
    jars = [args.core_jar, args.soklet_jar, args.jspecify_jar, args.jsr305_jar]
    for jar in jars:
        if not jar.is_file():
            parser.error("a required JAR is missing")
    if digest(args.soklet_jar) != FRAMEWORK_PIN["jar_sha256"]:
        parser.error("Soklet JAR does not match the pinned 4.0.0 artifact")
    with zipfile.ZipFile(args.core_jar) as jar:
        if "com/revetsec/totp/TotpAuthenticator.class" not in jar.namelist():
            parser.error("core JAR predates the TOTP API")

    javac = args.java_home / "bin" / "javac"
    java = args.java_home / "bin" / "java"
    if not javac.is_file() or not java.is_file():
        parser.error("--java-home must contain javac and java")
    compiler = subprocess.check_output([str(javac), "-version"], text=True).strip()
    compiler_version = re.fullmatch(r"javac (\d+)(?:\..*)?", compiler)
    if compiler_version is None or int(compiler_version.group(1)) < FRAMEWORK_PIN["minimum_java"]:
        parser.error("The Soklet TOTP application requires JDK 21 or newer")
    work.mkdir(mode=0o700, parents=True)
    classes = work / "classes"
    classes.mkdir()
    copied = work / "lib"
    copied.mkdir()
    runtime = []
    compile_jars = []
    for index, jar in enumerate(jars):
        target = copied / ("core.jar", "soklet.jar", "jspecify.jar", "jsr305.jar")[index]
        shutil.copyfile(jar, target)
        compile_jars.append(target)
        if index < 2:
            runtime.append(target)
    java_files = sorted((ROOT / "src" / "main" / "java").rglob("*.java"))
    java_files.extend(sorted((ROOT / "src" / "test" / "java").rglob("*.java")))
    if not java_files:
        parser.error("TOTP Java sources missing")
    subprocess.run([str(javac), "--release", "21", "-proc:none", "-Xlint:all,-serial", "-Werror",
                    "-cp", ":".join(map(str, compile_jars)), "-d", str(classes),
                    *map(str, java_files)], check=True)
    auditor = repository / "verification" / "examples" / "NullabilityAudit.java"
    if not auditor.is_file():
        parser.error("example nullability auditor missing")
    audit_classes = work / "nullability-audit-classes"
    audit_classes.mkdir()
    subprocess.run([str(javac), "--release", "17", "-proc:none", "-Xlint:all,-serial", "-Werror",
                    "-cp", ":".join(map(str, compile_jars)), "-d", str(audit_classes), str(auditor)], check=True)
    (work / "audit-sources.txt").write_text("".join(str(source) + "\n" for source in [*java_files, auditor]))
    (work / "audit-classpath.txt").write_text(":".join([str(classes), *map(str, compile_jars)]) + "\n")
    subprocess.run([str(java), "-cp", str(audit_classes), "NullabilityAudit",
                    str(work / "audit-sources.txt"), str(work / "audit-classpath.txt"),
                    str(work / "nullability-audit.json"), "21"], check=True)
    classpath = ":".join([str(classes), *map(str, runtime)])
    subprocess.run([str(java), "-cp", classpath, "example.totp.TotpExampleChecks"], check=True)
    subprocess.run([str(java), "-cp", classpath, "example.totp.TotpExampleLifecycleChecks"], check=True)
    if args.socket_check:
        subprocess.run([str(java), "-cp", classpath, "example.totp.TotpExampleSocketChecks"], check=True)
    (work / "CLASSPATH").write_text(classpath + "\n")
    (work / "BUILD.txt").write_text(
        "core sha256: " + digest(args.core_jar) + "\n"
        + "soklet sha256: " + digest(args.soklet_jar) + "\n"
        + "explicit signature nullability: passed\n"
        + "route checks: passed\n"
        + "socket checks: " + ("passed" if args.socket_check else "not run") + "\n")
    print("TOTP integration compiled and checked. CLASSPATH: " + str(work / "CLASSPATH"))


if __name__ == "__main__":
    main()
