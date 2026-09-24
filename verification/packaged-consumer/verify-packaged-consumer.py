#!/usr/bin/env python3
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

"""Verify the installed RevetSec JAR and POM as a Maven consumer sees them (plan 10.3, INV-L1).

Install core first, for example:

    mvn -B -ntp -Dmaven.javadoc.skip=true -DskipTests install

then run this script with the same JAVA_HOME and local repository. It fails unless:

1. the installed POM is byte-identical to the core pom.xml, and the installed JAR to
   target/<artifact>-<version>.jar when that file exists;
2. the installed POM passes verification/verify-published-pom.py: zero compile,
   runtime or system dependencies, no parent, no repositories;
3. the JAR holds classes only under com/revetsec/, has no module-info.class, carries
   META-INF/LICENSE and META-INF/NOTICE, and declares Automatic-Module-Name: com.revetsec;
4. a Maven consumer (this directory, copied to a scratch directory) compiles against
   the installed artifact, and its resolved runtime class path is exactly that JAR;
5. the consumer runs on the class path and resolves the automatic module com.revetsec;
6. jdeps finds only the INV-L1 modules (java.base, java.net.http, java.xml,
   java.xml.crypto, java.logging). The only classes it may report as not found are
   RevetSec's provided-scope annotations, which the JVM ignores when absent; and no
   class file names one of them in a CONSTANT_Class entry (a class literal, cast,
   instanceof or call), which the JVM would resolve and fail on at run time.
"""

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
DEFAULT_CORE_DIRECTORY = SCRIPT_DIRECTORY.parent.parent
POM_VERIFIER_PATH = SCRIPT_DIRECTORY.parent / "verify-published-pom.py"

EXPECTED_GROUP_ID = "com.revetsec"
EXPECTED_ARTIFACT_ID = "revetsec"
AUTOMATIC_MODULE_NAME = "com.revetsec"
CLASS_PREFIX = "com/revetsec/"
REQUIRED_ENTRIES = ("META-INF/MANIFEST.MF", "META-INF/LICENSE", "META-INF/NOTICE")
CONSUMER_MAIN_CLASS = "example.PackagedConsumer"
CONSUMER_SOURCES = ("pom.xml", "src")

# INV-L1 (plan 9.2): the only JDK modules RevetSec may need.
INV_L1_MODULES = frozenset({"java.base", "java.net.http", "java.xml", "java.xml.crypto", "java.logging"})

# Provided-scope annotation packages (plan 10.2: JSpecify, jsr305 concurrency markers, Error Prone
# annotations). Class files may name them in annotations, and the JVM ignores annotations whose
# types are absent, so jdeps reporting them as "not found" is expected. Any other missing class
# would be a real run-time dependency outside the JDK.
PROVIDED_ANNOTATION_PACKAGES = frozenset({
    "org.jspecify.annotations",
    "javax.annotation.concurrent",
    "com.google.errorprone.annotations",
})

JDEPS_DEPENDENCY_LINE = re.compile(r"^\s+(?P<origin>\S+)\s+->\s+(?P<target>\S+)\s+(?P<location>\S.*?)\s*$")
MODULE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*$")


class VerificationError(Exception):
    """The packaged artifact breaks a consumer-visible rule."""


def load_pom_verifier():
    # Keep the checkout clean: loading the sibling script must not leave a __pycache__ behind.
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("verify_published_pom", POM_VERIFIER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_core_coordinates(pom_verifier, core_directory):
    project = pom_verifier.load_pom(core_directory / "pom.xml")
    coordinates = (
        pom_verifier.literal_text(project, "m:groupId", "a groupId"),
        pom_verifier.literal_text(project, "m:artifactId", "an artifactId"),
        pom_verifier.literal_text(project, "m:version", "a version"),
    )
    if coordinates[:2] != (EXPECTED_GROUP_ID, EXPECTED_ARTIFACT_ID):
        raise VerificationError(
            f"{core_directory / 'pom.xml'} builds {coordinates[0]}:{coordinates[1]}, "
            f"expected {EXPECTED_GROUP_ID}:{EXPECTED_ARTIFACT_ID}"
        )
    return coordinates


def installed_artifact_paths(repository, group_id, artifact_id, version):
    directory = Path(repository).joinpath(*group_id.split("."), artifact_id, version)
    jar = directory / f"{artifact_id}-{version}.jar"
    pom = directory / f"{artifact_id}-{version}.pom"
    missing = [str(path) for path in (jar, pom) if not path.is_file()]
    if missing:
        raise VerificationError(
            "Installed artifact not found (run `mvn -DskipTests -Dmaven.javadoc.skip=true install` on core "
            "with the same local repository first): " + ", ".join(missing)
        )
    return jar, pom


def check_installed_matches_build(core_directory, artifact_id, version, installed_jar, installed_pom):
    """Return notes; raise VerificationError when the installed files are not the ones just built."""
    notes = []
    if (core_directory / "pom.xml").read_bytes() != installed_pom.read_bytes():
        raise VerificationError(f"Installed POM {installed_pom} differs from {core_directory / 'pom.xml'}")
    notes.append("installed POM is byte-identical to core pom.xml")
    built_jar = core_directory / "target" / f"{artifact_id}-{version}.jar"
    if built_jar.is_file():
        if built_jar.read_bytes() != installed_jar.read_bytes():
            raise VerificationError(f"Installed JAR {installed_jar} differs from {built_jar}")
        notes.append(f"installed JAR is byte-identical to {built_jar.relative_to(core_directory)}")
    else:
        notes.append(f"{built_jar} not present; JAR identity not compared")
    return notes


def jar_violations(jar):
    """Return (violations, packages) for the JAR's entries and manifest."""
    violations = []
    packages = set()
    with zipfile.ZipFile(jar) as archive:
        names = archive.namelist()
        for name in names:
            if name.endswith("/"):
                continue
            path = name
            versioned = re.match(r"^META-INF/versions/\d+/(?P<path>.+)$", name)
            if versioned:
                path = versioned.group("path")
            elif name.startswith("META-INF/"):
                continue
            if path == "module-info.class":
                violations.append(f"{name}: a module descriptor is present; the plan uses Automatic-Module-Name")
            elif not path.startswith(CLASS_PREFIX):
                violations.append(f"{name}: outside {CLASS_PREFIX}; the JAR must not bundle other code or resources")
            elif path.endswith(".class"):
                packages.add(path.rsplit("/", 1)[0].replace("/", "."))
        for required in REQUIRED_ENTRIES:
            if required not in names:
                violations.append(f"{required} is missing")
        if "META-INF/MANIFEST.MF" in names:
            manifest = archive.read("META-INF/MANIFEST.MF").decode("utf-8", errors="replace")
            automatic_module_name = manifest_attribute(manifest, "Automatic-Module-Name")
            if automatic_module_name != AUTOMATIC_MODULE_NAME:
                violations.append(
                    f"Automatic-Module-Name is {automatic_module_name!r}, expected {AUTOMATIC_MODULE_NAME!r}"
                )
    if not packages:
        violations.append(f"no class files under {CLASS_PREFIX}")
    return violations, sorted(packages)


def manifest_attribute(manifest, name):
    """Return a main-section manifest attribute, joining continuation lines."""
    logical_lines = []
    for line in manifest.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if line == "":
            break
        if line.startswith(" ") and logical_lines:
            logical_lines[-1] += line[1:]
        else:
            logical_lines.append(line)
    for line in logical_lines:
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() == name.lower():
            return value.strip()
    return None


# Constant-pool entry sizes after the tag byte (JVMS 4.4); Utf8 is variable-length.
CONSTANT_POOL_ENTRY_SIZES = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4, 15: 3, 16: 2, 17: 4,
                             18: 4, 19: 2, 20: 2}
CONSTANT_UTF8 = 1
CONSTANT_CLASS = 7
CONSTANT_LONG = 5
CONSTANT_DOUBLE = 6


def class_constant_names(class_bytes):
    """Return the binary names (dotted) of every CONSTANT_Class entry in a class file.

    These are the classes the JVM resolves at run time (class literals, casts, instanceof, field and
    method owners, new). Annotation types appear only as descriptors in attributes, never here,
    unless code also uses the type directly.
    """
    if len(class_bytes) < 10 or class_bytes[:4] != b"\xca\xfe\xba\xbe":
        raise VerificationError("not a class file")
    (count,) = struct.unpack_from(">H", class_bytes, 8)
    offset = 10
    utf8 = {}
    class_name_indexes = []
    index = 1
    try:
        while index < count:
            tag = class_bytes[offset]
            offset += 1
            if tag == CONSTANT_UTF8:
                (length,) = struct.unpack_from(">H", class_bytes, offset)
                offset += 2
                size = length
            elif tag in CONSTANT_POOL_ENTRY_SIZES:
                size = CONSTANT_POOL_ENTRY_SIZES[tag]
            else:
                raise VerificationError(f"unknown constant-pool tag {tag} at entry {index}")
            if offset + size > len(class_bytes):
                raise VerificationError(f"constant-pool entry {index} runs past the end of the class file")
            if tag == CONSTANT_UTF8:
                utf8[index] = class_bytes[offset:offset + size].decode("utf-8", errors="replace")
            elif tag == CONSTANT_CLASS:
                class_name_indexes.append(struct.unpack_from(">H", class_bytes, offset)[0])
            offset += size
            index += 2 if tag in (CONSTANT_LONG, CONSTANT_DOUBLE) else 1
    except (IndexError, struct.error) as exception:
        raise VerificationError(f"truncated constant pool: {exception}") from exception
    names = set()
    for name_index in class_name_indexes:
        name = utf8.get(name_index, "")
        name = name.lstrip("[")
        if name.startswith("L") and name.endswith(";"):
            name = name[1:-1]
        names.add(name.replace("/", "."))
    return names


def provided_annotation_class_references(jar):
    """Return violations for class files that name a provided-scope annotation type in a CONSTANT_Class."""
    violations = []
    with zipfile.ZipFile(jar) as archive:
        for name in archive.namelist():
            if not name.endswith(".class"):
                continue
            try:
                referenced = class_constant_names(archive.read(name))
            except VerificationError as exception:
                violations.append(f"{name}: cannot parse class file: {exception}")
                continue
            for target in sorted(referenced):
                if target.rpartition(".")[0] in PROVIDED_ANNOTATION_PACKAGES:
                    violations.append(
                        f"{name} references {target} as a class; provided-scope annotations may appear only as "
                        "annotations, because the JVM resolves class references at run time"
                    )
    return violations


def parse_jdeps_modules(output):
    """Parse `jdeps --print-module-deps` output: one comma-separated line, possibly empty."""
    text = output.strip()
    if not text:
        return []
    modules = [module.strip() for module in text.split(",")]
    for module in modules:
        if not MODULE_NAME.match(module):
            raise VerificationError(f"Unexpected jdeps --print-module-deps output: {output!r}")
    return modules


def jdeps_class_violations(output, jar_name):
    """Check `jdeps -verbose:class -filter:none` output; return (violations, dependencies)."""
    violations = []
    dependencies = []
    for line in output.splitlines():
        match = JDEPS_DEPENDENCY_LINE.match(line)
        if not match:
            continue
        origin, target, location = match.group("origin", "target", "location")
        dependencies.append({"origin": origin, "target": target, "location": location})
        if location == jar_name:
            continue
        if location == "not found":
            package = target.rpartition(".")[0]
            if package not in PROVIDED_ANNOTATION_PACKAGES:
                violations.append(f"{origin} -> {target}: not found and not a provided-scope annotation")
        elif location not in INV_L1_MODULES:
            violations.append(f"{origin} -> {target}: in {location}, outside the INV-L1 modules")
    return violations, dependencies


def run(command, *, cwd=None, env=None, description):
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        raise VerificationError(
            f"{description} failed with exit code {result.returncode}: {' '.join(map(str, command))}\n"
            f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
        )
    return result.stdout


def java_environment(java_home):
    environment = dict(os.environ)
    environment["JAVA_HOME"] = str(java_home)
    environment["PATH"] = str(Path(java_home) / "bin") + os.pathsep + environment.get("PATH", "")
    # A caller's JAVA_TOOL_OPTIONS (for example a locale leg) must not change the tools' output format.
    environment.pop("JAVA_TOOL_OPTIONS", None)
    environment.pop("JDK_JAVA_OPTIONS", None)
    return environment


def build_consumer(maven, java_home, repository, version, work_directory, maven_arguments=()):
    consumer_directory = work_directory / "packaged-consumer"
    if consumer_directory.exists():
        shutil.rmtree(consumer_directory)
    consumer_directory.mkdir(parents=True)
    for name in CONSUMER_SOURCES:
        source = SCRIPT_DIRECTORY / name
        if source.is_dir():
            shutil.copytree(source, consumer_directory / name)
        else:
            shutil.copy2(source, consumer_directory / name)
    run(
        [
            maven, "-B", "-ntp", "-nsu",
            f"-Dmaven.repo.local={repository}",
            f"-Drevetsec.version={version}",
            *maven_arguments,
            "-f", str(consumer_directory / "pom.xml"),
            "clean", "compile",
        ],
        env=java_environment(java_home),
        description="Maven consumer build",
    )
    classpath_file = consumer_directory / "target" / "runtime-classpath.txt"
    if not classpath_file.is_file():
        raise VerificationError(f"The consumer build did not write {classpath_file}")
    entries = [entry for entry in classpath_file.read_text(encoding="utf-8").strip().split(os.pathsep) if entry]
    return consumer_directory, entries


def classpath_violations(entries, installed_jar):
    expected = Path(installed_jar).resolve()
    resolved = [Path(entry).resolve() for entry in entries]
    if resolved == [expected]:
        return []
    return [
        "The consumer's resolved runtime class path must be exactly the installed RevetSec JAR "
        f"{expected}, found {[str(path) for path in resolved]}"
    ]


def verify(arguments):
    pom_verifier = load_pom_verifier()
    core_directory = arguments.core_directory.resolve()
    repository = arguments.repository.expanduser().resolve()
    java_home = arguments.java_home.resolve()
    jdeps = java_home / "bin" / "jdeps"
    java = java_home / "bin" / "java"
    for tool in (jdeps, java):
        if not tool.is_file():
            raise VerificationError(f"{tool} not found; pass --java-home or set JAVA_HOME to a JDK")

    group_id, artifact_id, version = read_core_coordinates(pom_verifier, core_directory)
    installed_jar, installed_pom = installed_artifact_paths(repository, group_id, artifact_id, version)
    evidence = {
        "formatVersion": 1,
        "checkedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "coordinates": f"{group_id}:{artifact_id}:{version}",
        "installedJar": {"path": str(installed_jar), "sha256": sha256(installed_jar)},
        "installedPom": {"path": str(installed_pom), "sha256": sha256(installed_pom)},
        "javaHome": str(java_home),
    }
    report = []

    report.extend(check_installed_matches_build(core_directory, artifact_id, version, installed_jar, installed_pom))

    try:
        verified_pom = pom_verifier.verify_pom(installed_pom, (group_id, artifact_id, version))
    except pom_verifier.PomPolicyError as exception:
        raise VerificationError(f"Installed POM breaks the zero-dependency policy: {exception}") from exception
    evidence["pom"] = verified_pom.as_dict()
    report.append(
        f"installed POM declares {len(verified_pom.dependencies)} dependencies, "
        "none compile, runtime or system scoped"
    )

    violations, packages = jar_violations(installed_jar)
    if violations:
        raise VerificationError("JAR content violations:\n" + "\n".join(f"  - {item}" for item in violations))
    evidence["packages"] = packages
    report.append(f"JAR holds classes only under {CLASS_PREFIX} ({len(packages)} packages), with LICENSE and NOTICE")
    report.append(f"Automatic-Module-Name: {AUTOMATIC_MODULE_NAME}")

    work_directory = arguments.work_directory
    if work_directory is None:
        temporary = tempfile.TemporaryDirectory(prefix="revetsec-packaged-consumer-")
        work_directory = Path(temporary.name)
    else:
        temporary = None
        work_directory = work_directory.resolve()
        work_directory.mkdir(parents=True, exist_ok=True)
    try:
        consumer_directory, entries = build_consumer(
            arguments.maven, java_home, repository, version, work_directory, arguments.maven_arg
        )
        violations = classpath_violations(entries, installed_jar)
        if violations:
            raise VerificationError("\n".join(violations))
        evidence["consumerRuntimeClasspath"] = entries
        report.append("Maven consumer compiled; its resolved runtime class path is exactly the RevetSec JAR")

        consumer_output = run(
            [
                str(java), "-cp",
                os.pathsep.join([str(consumer_directory / "target" / "classes"), *entries]),
                CONSUMER_MAIN_CLASS, str(installed_jar),
            ],
            env=java_environment(java_home),
            description="Consumer run",
        )
        evidence["consumerOutput"] = consumer_output.splitlines()
        report.append("consumer ran on the class path and resolved the automatic module com.revetsec")
    finally:
        if temporary is not None:
            temporary.cleanup()

    release = str(arguments.jdeps_release)
    module_output = run(
        [str(jdeps), "--multi-release", release, "--ignore-missing-deps", "--print-module-deps", str(installed_jar)],
        env=java_environment(java_home),
        description="jdeps --print-module-deps",
    )
    modules = parse_jdeps_modules(module_output)
    outside = sorted(set(modules) - INV_L1_MODULES)
    if outside:
        raise VerificationError(f"jdeps lists modules outside INV-L1: {outside} (all: {modules})")
    class_output = run(
        [str(jdeps), "--multi-release", release, "-verbose:class", "-filter:none", str(installed_jar)],
        env=java_environment(java_home),
        description="jdeps -verbose:class",
    )
    violations, dependencies = jdeps_class_violations(class_output, installed_jar.name)
    violations.extend(provided_annotation_class_references(installed_jar))
    if violations:
        raise VerificationError("jdeps class-level violations:\n" + "\n".join(f"  - {item}" for item in violations))
    not_found = sorted({item["target"] for item in dependencies if item["location"] == "not found"})
    evidence["jdeps"] = {
        "release": release,
        "printModuleDeps": modules,
        "providedAnnotationsNotFound": not_found,
    }
    report.append(
        f"jdeps --print-module-deps: {','.join(modules) if modules else '(none)'}; "
        f"allowed: {','.join(sorted(INV_L1_MODULES))}"
    )
    if not_found:
        report.append(
            f"jdeps not-found classes, all provided-scope annotations used only as annotations: {', '.join(not_found)}"
        )

    evidence["result"] = "PASS"
    evidence["checks"] = report
    return evidence


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--core-directory", type=Path, default=DEFAULT_CORE_DIRECTORY,
                        help="the core checkout (default: this script's repository)")
    parser.add_argument("--repository", type=Path, default=Path("~/.m2/repository"),
                        help="the Maven local repository core was installed into (default: ~/.m2/repository)")
    parser.add_argument("--java-home", type=Path, default=os.environ.get("JAVA_HOME"),
                        help="the JDK for Maven, the consumer and jdeps (default: $JAVA_HOME)")
    parser.add_argument("--maven", default=shutil.which("mvn"),
                        help="the Maven executable (default: mvn on PATH)")
    parser.add_argument("--maven-arg", action="append", default=[], metavar="ARG",
                        help="an extra argument for the consumer's Maven build, for example "
                             "-Dmaven.repo.local.tail=$HOME/.m2/repository (repeatable)")
    parser.add_argument("--jdeps-release", type=int, default=17,
                        help="the --multi-release version jdeps analyzes (default: 17)")
    parser.add_argument("--work-directory", type=Path,
                        help="where to build the consumer (default: a temporary directory, removed afterwards)")
    parser.add_argument("--output", type=Path,
                        help="a directory to write packaged-consumer-result.json into")
    arguments = parser.parse_args(argv)
    if arguments.java_home is None:
        parser.error("--java-home is required when JAVA_HOME is not set")
    if not arguments.maven:
        parser.error("--maven is required when mvn is not on PATH")

    try:
        evidence = verify(arguments)
    except (VerificationError, OSError, zipfile.BadZipFile) as exception:
        print(f"Packaged-consumer verification FAILED: {exception}", file=sys.stderr)
        if arguments.output is not None:
            arguments.output.mkdir(parents=True, exist_ok=True)
            (arguments.output / "packaged-consumer-result.json").write_text(
                json.dumps({"formatVersion": 1, "result": "FAIL", "error": str(exception)}, indent=2) + "\n",
                encoding="utf-8",
            )
        return 1

    if arguments.output is not None:
        arguments.output.mkdir(parents=True, exist_ok=True)
        (arguments.output / "packaged-consumer-result.json").write_text(
            json.dumps(evidence, indent=2) + "\n", encoding="utf-8"
        )
    print(f"Packaged-consumer verification passed for {evidence['coordinates']}")
    for line in evidence["checks"]:
        print(f"  - {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
