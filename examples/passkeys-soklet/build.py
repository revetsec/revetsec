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

"""Compile the disposable Soklet passkey app against exact local JARs into a new private directory."""

import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import zipfile


ROOT = Path(__file__).resolve().parent
SOKLET_4_SHA256 = "f7f62f967045a8eb8f943a90d49d499b4c5b755d20ab901e12a34fe1d004319b"


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
    if digest(args.soklet_jar) != SOKLET_4_SHA256:
        parser.error("Soklet JAR does not match the pinned 4.0.0 artifact")
    with zipfile.ZipFile(args.core_jar) as jar:
        if "com/revetsec/webauthn/InMemoryWebAuthnStore.class" not in jar.namelist():
            parser.error("core JAR predates the public WebAuthn store")

    javac = args.java_home / "bin" / "javac"
    java = args.java_home / "bin" / "java"
    if not javac.is_file() or not java.is_file():
        parser.error("--java-home must contain javac and java")
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
        parser.error("passkey Java sources missing")
    subprocess.run([str(javac), "--release", "17", "-proc:none", "-Xlint:all,-serial", "-Werror",
                    "-cp", ":".join(map(str, compile_jars)), "-d", str(classes),
                    *map(str, java_files)], check=True)
    shutil.copytree(ROOT / "src" / "main" / "resources", classes, dirs_exist_ok=True)
    classpath = ":".join([str(classes), *map(str, runtime)])
    subprocess.run([str(java), "-cp", classpath, "example.passkeys.PasskeyChecks"], check=True)
    if args.socket_check:
        subprocess.run([str(java), "-cp", classpath, "example.passkeys.PasskeySocketChecks"], check=True)
    (work / "CLASSPATH").write_text(classpath + "\n")
    (work / "BUILD.txt").write_text(
        "core sha256: " + digest(args.core_jar) + "\n"
        + "soklet sha256: " + digest(args.soklet_jar) + "\n"
        + "route checks: passed\n"
        + "socket checks: " + ("passed" if args.socket_check else "not run") + "\n")
    print("Passkey demo compiled and checked. Run with: " + str(java)
          + ' -cp "$(cat ' + str(work / "CLASSPATH") + ')" example.passkeys.PasskeyPlayground')


if __name__ == "__main__":
    main()
