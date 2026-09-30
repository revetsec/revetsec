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

"""Verify the installed Revetsec JAR and POM as Maven and Gradle consumers see them (plan 10.3, INV-L1).

Install core first, for example:

    mvn -B -ntp -Dmaven.javadoc.skip=true -DskipTests install

download the pinned Gradle distribution (GRADLE_DISTRIBUTION_URL below), then run this
script with the same JAVA_HOME and local repository. It fails unless:

1. the installed POM is byte-identical to the core pom.xml, and the installed JAR to
   target/<artifact>-<version>.jar when that file exists;
2. the installed POM passes verification/verify-published-pom.py: zero compile,
   runtime or system dependencies, no parent, no repositories;
3. the JAR holds classes only under com/revetsec/, has no module-info.class, carries
   META-INF/LICENSE and META-INF/NOTICE, and declares Automatic-Module-Name: com.revetsec;
4. a Maven consumer (this directory's pom.xml and src/, copied to a scratch directory)
   compiles against the installed artifact, and its resolved runtime class path is
   exactly that JAR;
5. the Gradle distribution has the pinned SHA-256 (checked before anything is extracted
   from it), and a Gradle consumer (this directory's build.gradle, settings.gradle and
   src/, copied to a scratch directory) built offline by that Gradle on this JDK resolves
   the installed artifact from the same local repository: its runtimeClasspath and
   compileClasspath are exactly that JAR, and the Revetsec component has no dependency;
6. each consumer runs on the class path, resolves the automatic module com.revetsec, and
   calls the public API of com.revetsec, com.revetsec.json, com.revetsec.jose, com.revetsec.oauth and com.revetsec.oidc:
   PackagedConsumer prints its public-api= line only after every call behaved as
   documented. Both consumers compile it with warnings as errors against nothing but the
   Revetsec JAR, so the build proves the published signatures resolve without the
   provided-scope annotation JARs;
7. jdeps finds only the INV-L1 modules (java.base, java.net.http, java.xml,
   java.xml.crypto, java.logging). The only classes it may report as not found are
   Revetsec's provided-scope annotations, which the JVM ignores when absent; and no
   class file names one of them in a CONSTANT_Class entry (a class literal, cast,
   instanceof or call), which the JVM would resolve and fail on at run time;
8. the installed JAR and POM are unchanged after both consumer builds.
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
import stat
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
# PackagedConsumer prints this line last, and only after every public API call behaved as documented.
PUBLIC_API_LINE_PREFIX = "public-api="
# The groups of public API calls PackagedConsumer makes, in order; its public-api= line names each (M1, WP-10b;
# com.revetsec.jose from M2, com.revetsec.oauth from M3 and com.revetsec.oidc from M4).
PUBLIC_API_CALLS = ("com.revetsec.json", "StateSealer", "OutboundUriPolicy", "com.revetsec.jose", "com.revetsec.oauth", "com.revetsec.oidc")
MAVEN_CONSUMER_SOURCES = ("pom.xml", "src")
GRADLE_CONSUMER_SOURCES = ("build.gradle", "settings.gradle", "src")

# The Gradle distribution the Gradle consumer builds with, pinned by SHA-256. 9.8.0 was the current release on
# 2026-09-24, and its release highlights list Java 27 support. That day it built and ran this consumer on Corretto
# 17, 21, 25, 26 and 27, so one distribution serves the whole JDK matrix. The digest is the one Gradle
# publishes at GRADLE_DISTRIBUTION_URL + ".sha256", and it matched the downloaded archive. Dependabot does not
# update this pin. Move it together with the download URL in .github/workflows/ci.yml, CONTRIBUTING.md and
# verification/README.md; test_verify_packaged_consumer.py fails while they disagree.
GRADLE_VERSION = "9.8.0"
GRADLE_DISTRIBUTION_SHA256 = "bafd5ce9cfaea0fbccfdc8439a1ac42fbd4cd9c89dc9a988228d8a2639a58e6c"
GRADLE_DISTRIBUTION_URL = f"https://services.gradle.org/distributions/gradle-{GRADLE_VERSION}-bin.zip"
# Written by build.gradle's resolutionReport task.
GRADLE_REPORT = Path("build", "revetsec-consumer", "resolution.json")
GRADLE_REPORT_FORMAT_VERSION = 1
GRADLE_CONFIGURATIONS = ("runtimeClasspath", "compileClasspath")

# INV-L1 (plan 9.2): the only JDK modules Revetsec may need.
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


def copy_consumer_sources(names, consumer_directory):
    """Copy the named consumer sources from this directory into a fresh consumer_directory."""
    if consumer_directory.exists():
        shutil.rmtree(consumer_directory)
    consumer_directory.mkdir(parents=True)
    for name in names:
        source = SCRIPT_DIRECTORY / name
        if source.is_dir():
            shutil.copytree(source, consumer_directory / name)
        else:
            shutil.copy2(source, consumer_directory / name)


def build_consumer(maven, java_home, repository, version, work_directory, maven_arguments=()):
    consumer_directory = work_directory / "maven-consumer"
    copy_consumer_sources(MAVEN_CONSUMER_SOURCES, consumer_directory)
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
        "The consumer's resolved runtime class path must be exactly the installed Revetsec JAR "
        f"{expected}, found {[str(path) for path in resolved]}"
    ]


def check_gradle_distribution_digest(archive, expected_sha256=GRADLE_DISTRIBUTION_SHA256):
    """Raise VerificationError unless the archive's SHA-256 is the pinned one. Nothing is extracted before this."""
    actual = sha256(archive)
    if actual != expected_sha256:
        raise VerificationError(
            f"Gradle distribution {archive} has SHA-256 {actual}, expected the pinned {expected_sha256} "
            f"(Gradle {GRADLE_VERSION}, {GRADLE_DISTRIBUTION_URL})"
        )
    return actual


def gradle_distribution_member_violation(info, root):
    """Return why a distribution archive member is unsafe to extract, or None."""
    name = info.filename
    if "\\" in name or "\0" in name:
        return f"{name!r}: backslash or NUL in the entry name"
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return f"{name!r}: absolute entry name"
    parts = name.rstrip("/").split("/")
    if any(part in ("", ".", "..") for part in parts):
        return f"{name!r}: empty, '.' or '..' path segment"
    if parts[0] != root:
        return f"{name!r}: outside the distribution root {root}/"
    mode = info.external_attr >> 16
    if stat.S_ISLNK(mode):
        return f"{name!r}: symbolic link"
    return None


def unpack_gradle_distribution(archive, destination, expected_sha256=GRADLE_DISTRIBUTION_SHA256,
                               version=GRADLE_VERSION):
    """Check the pinned digest, then extract the distribution into destination; return the gradle launcher.

    Every member must lie under gradle-<version>/, with no absolute path, '..' segment or symbolic link. Regular
    files keep their owner-executable bit, so bin/gradle stays runnable; nothing gets set-id or world-write bits.
    """
    check_gradle_distribution_digest(archive, expected_sha256)
    root = f"gradle-{version}"
    destination = Path(destination)
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    with zipfile.ZipFile(archive) as distribution:
        members = distribution.infolist()
        violations = [gradle_distribution_member_violation(info, root) for info in members]
        violations = [violation for violation in violations if violation is not None]
        if violations:
            raise VerificationError(
                "Unsafe Gradle distribution entries:\n" + "\n".join(f"  - {item}" for item in violations)
            )
        for info in members:
            target = destination.joinpath(*info.filename.rstrip("/").split("/"))
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with distribution.open(info) as source, open(target, "xb") as sink:
                shutil.copyfileobj(source, sink)
            executable = (info.external_attr >> 16) & stat.S_IXUSR
            target.chmod(0o755 if executable else 0o644)
    launcher = destination / root / "bin" / "gradle"
    if not launcher.is_file() or launcher.is_symlink() or not os.access(launcher, os.X_OK):
        raise VerificationError(f"The Gradle distribution has no executable {root}/bin/gradle")
    return launcher


def gradle_environment(java_home, gradle_user_home):
    environment = java_environment(java_home)
    # A fresh Gradle user home: no init scripts, gradle.properties or caches from the caller's ~/.gradle.
    environment["GRADLE_USER_HOME"] = str(gradle_user_home)
    # Launcher JVM options from the caller must not change what runs.
    environment.pop("GRADLE_OPTS", None)
    environment.pop("JAVA_OPTS", None)
    return environment


def build_gradle_consumer(gradle, java_home, repository, version, work_directory):
    """Build the Gradle consumer offline; return (consumer directory, parsed resolution report)."""
    consumer_directory = work_directory / "gradle-consumer"
    copy_consumer_sources(GRADLE_CONSUMER_SOURCES, consumer_directory)
    gradle_user_home = work_directory / "gradle-user-home"
    if gradle_user_home.exists():
        shutil.rmtree(gradle_user_home)
    run(
        [
            str(gradle),
            "--offline", "--no-daemon", "--no-build-cache", "--no-configuration-cache",
            "--console=plain", "--warning-mode=fail", "--stacktrace",
            "--project-dir", str(consumer_directory),
            f"-Prevetsec.repository={repository}",
            f"-Prevetsec.version={version}",
            "clean", "classes", "resolutionReport",
        ],
        env=gradle_environment(java_home, gradle_user_home),
        description="Gradle consumer build",
    )
    return consumer_directory, read_gradle_report(consumer_directory / GRADLE_REPORT)


def read_gradle_report(path):
    if not path.is_file():
        raise VerificationError(f"The Gradle consumer build did not write {path}")
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise VerificationError(f"{path} is not valid JSON: {exception}") from exception
    if not isinstance(report, dict):
        raise VerificationError(f"{path} does not hold a JSON object")
    return report


def gradle_report_violations(report, installed_jar, coordinates, java_home, gradle_version=GRADLE_VERSION):
    """Check build.gradle's resolution report; return violations (empty when it shows zero dependencies)."""
    violations = []
    if report.get("formatVersion") != GRADLE_REPORT_FORMAT_VERSION:
        return [
            f"Gradle report formatVersion is {report.get('formatVersion')!r}, expected {GRADLE_REPORT_FORMAT_VERSION}"
        ]
    if report.get("gradleVersion") != gradle_version:
        violations.append(
            f"Gradle {report.get('gradleVersion')!r} ran the consumer build, expected the pinned {gradle_version}"
        )
    gradle_java_home = report.get("gradleJavaHome")
    if not isinstance(gradle_java_home, str) or Path(gradle_java_home).resolve() != Path(java_home).resolve():
        violations.append(f"Gradle ran on the JDK at {gradle_java_home!r}, expected {Path(java_home).resolve()}")
    expected_jar = Path(installed_jar).resolve()
    configurations = report.get("configurations")
    if not isinstance(configurations, dict):
        return violations + ["Gradle report has no configurations object"]
    for name in GRADLE_CONFIGURATIONS:
        resolution = configurations.get(name)
        if not isinstance(resolution, dict):
            violations.append(f"{name}: missing from the Gradle report")
            continue
        components = resolution.get("components")
        if components != [{"id": coordinates, "dependencies": []}]:
            violations.append(
                f"{name}: must resolve exactly {coordinates} with no dependency of its own, found {components!r}"
            )
        unresolved = resolution.get("unresolved")
        if unresolved != []:
            violations.append(f"{name}: unresolved dependencies {unresolved!r}")
        files = resolution.get("files")
        if (not isinstance(files, list) or len(files) != 1 or not isinstance(files[0], dict)
                or files[0].get("component") != coordinates or not isinstance(files[0].get("path"), str)
                or Path(files[0]["path"]).resolve() != expected_jar):
            violations.append(f"{name}: must be exactly the installed Revetsec JAR {expected_jar}, found {files!r}")
    return violations


def consumer_output_violations(lines, description):
    """Return violations unless the consumer's output ends with the public-api= line naming every call group."""
    api_lines = [line for line in lines if line.startswith(PUBLIC_API_LINE_PREFIX)]
    if len(api_lines) != 1 or not lines or lines[-1] != api_lines[0]:
        return [
            f"{description} must print exactly one {PUBLIC_API_LINE_PREFIX} line, last; PackagedConsumer prints it "
            f"only after calling the public API, found {api_lines!r}"
        ]
    called = api_lines[0][len(PUBLIC_API_LINE_PREFIX):].split(",")
    if called != list(PUBLIC_API_CALLS):
        return [f"{description} called {called!r}, expected {list(PUBLIC_API_CALLS)!r}"]
    return []


def run_consumer(java, java_home, classes_directory, entries, installed_jar, description):
    output = run(
        [
            str(java), "-cp",
            os.pathsep.join([str(classes_directory), *entries]),
            CONSUMER_MAIN_CLASS, str(installed_jar),
        ],
        env=java_environment(java_home),
        description=description,
    )
    lines = output.splitlines()
    violations = consumer_output_violations(lines, description)
    if violations:
        raise VerificationError("\n".join(violations))
    return lines


def verify(arguments):
    pom_verifier = load_pom_verifier()
    core_directory = arguments.core_directory.resolve()
    repository = arguments.repository.expanduser().resolve()
    java_home = arguments.java_home.resolve()
    gradle_distribution = arguments.gradle_distribution.resolve()
    jdeps = java_home / "bin" / "jdeps"
    java = java_home / "bin" / "java"
    for tool in (jdeps, java):
        if not tool.is_file():
            raise VerificationError(f"{tool} not found; pass --java-home or set JAVA_HOME to a JDK")
    if not gradle_distribution.is_file():
        raise VerificationError(
            f"{gradle_distribution} not found; download {GRADLE_DISTRIBUTION_URL} and pass it as --gradle-distribution"
        )
    # Fail before any build on a wrong archive; unpack_gradle_distribution checks the digest again before extracting.
    check_gradle_distribution_digest(gradle_distribution)

    group_id, artifact_id, version = read_core_coordinates(pom_verifier, core_directory)
    coordinates = f"{group_id}:{artifact_id}:{version}"
    installed_jar, installed_pom = installed_artifact_paths(repository, group_id, artifact_id, version)
    evidence = {
        "formatVersion": 2,
        "checkedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "coordinates": coordinates,
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
        maven_output = run_consumer(
            java, java_home, consumer_directory / "target" / "classes", entries, installed_jar, "Maven consumer run"
        )
        evidence["mavenConsumer"] = {"runtimeClasspath": entries, "output": maven_output}
        report.append("Maven consumer compiled; its resolved runtime class path is exactly the Revetsec JAR")
        report.append(
            f"Maven consumer ran on the class path, resolved the automatic module com.revetsec and called the "
            f"public API: {', '.join(PUBLIC_API_CALLS)}"
        )

        # unpack_gradle_distribution checks the pinned SHA-256 before it extracts anything.
        gradle = unpack_gradle_distribution(gradle_distribution, work_directory / "gradle-distribution")
        distribution_sha256 = GRADLE_DISTRIBUTION_SHA256
        consumer_directory, gradle_report = build_gradle_consumer(
            gradle, java_home, repository, version, work_directory
        )
        violations = gradle_report_violations(gradle_report, installed_jar, coordinates, java_home)
        if violations:
            raise VerificationError(
                "Gradle consumer resolution violations:\n" + "\n".join(f"  - {item}" for item in violations)
            )
        runtime_entries = [item["path"] for item in gradle_report["configurations"]["runtimeClasspath"]["files"]]
        gradle_output = run_consumer(
            java, java_home, consumer_directory / "build" / "classes" / "java" / "main", runtime_entries, installed_jar,
            "Gradle consumer run",
        )
        evidence["gradleConsumer"] = {
            "gradleVersion": gradle_report["gradleVersion"],
            "distribution": {"url": GRADLE_DISTRIBUTION_URL, "sha256": distribution_sha256},
            "gradleJavaVersion": gradle_report.get("gradleJavaVersion"),
            "configurations": gradle_report["configurations"],
            "output": gradle_output,
        }
        report.append(
            f"Gradle {gradle_report['gradleVersion']} (pinned SHA-256 {distribution_sha256[:12]}...) built the "
            f"consumer offline on Java {gradle_report.get('gradleJavaVersion')}"
        )
        report.append(
            f"Gradle consumer's runtimeClasspath and compileClasspath are exactly the Revetsec JAR; "
            f"{coordinates} resolves with zero dependencies"
        )
        report.append(
            f"Gradle consumer ran on the class path, resolved the automatic module com.revetsec and called the "
            f"public API: {', '.join(PUBLIC_API_CALLS)}"
        )
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

    for label, path, recorded in (("JAR", installed_jar, evidence["installedJar"]["sha256"]),
                                  ("POM", installed_pom, evidence["installedPom"]["sha256"])):
        if sha256(path) != recorded:
            raise VerificationError(f"Installed {label} {path} changed while the consumers were built")
    report.append("installed JAR and POM are unchanged after both consumer builds")

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
                        help="the JDK for Maven, Gradle, the consumers and jdeps (default: $JAVA_HOME)")
    parser.add_argument("--maven", default=shutil.which("mvn"),
                        help="the Maven executable (default: mvn on PATH)")
    parser.add_argument("--maven-arg", action="append", default=[], metavar="ARG",
                        help="an extra argument for the consumer's Maven build, for example "
                             "-Dmaven.repo.local.tail=$HOME/.m2/repository (repeatable)")
    parser.add_argument("--gradle-distribution", type=Path, required=True, metavar="ZIP",
                        help=f"the Gradle distribution archive downloaded from {GRADLE_DISTRIBUTION_URL}; "
                             "its SHA-256 must be the pinned one")
    parser.add_argument("--jdeps-release", type=int, default=17,
                        help="the --multi-release version jdeps analyzes (default: 17)")
    parser.add_argument("--work-directory", type=Path,
                        help="where to build the consumers (default: a temporary directory, removed afterwards)")
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
                json.dumps({"formatVersion": 2, "result": "FAIL", "error": str(exception)}, indent=2) + "\n",
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
