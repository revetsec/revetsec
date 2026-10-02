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

"""Seeded-violation tests for verify-packaged-consumer.py's offline checks.

Run: PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s verification/packaged-consumer -p 'test_*.py'
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import unittest
import zipfile

sys.dont_write_bytecode = True

SCRIPT = Path(__file__).resolve().parent / "verify-packaged-consumer.py"
REPOSITORY_ROOT = Path(__file__).resolve().parent.parent.parent
SPEC = importlib.util.spec_from_file_location("verify_packaged_consumer", SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)

MANIFEST = "Manifest-Version: 1.0\r\nAutomatic-Module-Name: com.revetsec\r\nCreated-By: Maven JAR Plugin\r\n\r\n"

# Captured from `jdeps --multi-release 17 -verbose:class -filter:none` (JDK 21) on a package-info-only JAR.
JDEPS_CLEAN = """revetsec-1.0.0-SNAPSHOT.jar -> java.base
revetsec-1.0.0-SNAPSHOT.jar -> not found
   com.revetsec.internal.A                            -> com.revetsec.internal.B                            revetsec-1.0.0-SNAPSHOT.jar
   com.revetsec.internal.A                            -> java.util.logging.Logger                           java.logging
   com.revetsec.json.package-info                     -> java.lang.Object                                   java.base
   com.revetsec.json.package-info                     -> org.jspecify.annotations.NullMarked                not found
   com.revetsec.package-info                          -> java.lang.Object                                   java.base
   com.revetsec.package-info                          -> javax.annotation.concurrent.ThreadSafe             not found
"""


class JarContentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.jar = Path(self.temporary.name) / "revetsec-1.0.0-SNAPSHOT.jar"

    def write_jar(self, entries, manifest=MANIFEST):
        with zipfile.ZipFile(self.jar, "w") as archive:
            if manifest is not None:
                archive.writestr("META-INF/MANIFEST.MF", manifest)
            for name, content in entries.items():
                archive.writestr(name, content)

    def good_entries(self, **extra):
        entries = {
            "META-INF/": b"",
            "META-INF/LICENSE": b"Apache-2.0",
            "META-INF/NOTICE": b"Revetware",
            "META-INF/maven/com.revetsec/revetsec/pom.xml": b"<project/>",
            "com/revetsec/": b"",
            "com/revetsec/package-info.class": b"\xca\xfe\xba\xbe",
            "com/revetsec/json/package-info.class": b"\xca\xfe\xba\xbe",
            "com/revetsec/internal/xml/schema.xsd": b"<xs/>",
        }
        entries.update(extra)
        return entries

    def test_clean_jar_passes(self):
        self.write_jar(self.good_entries())
        violations, packages = VERIFIER.jar_violations(self.jar)
        self.assertEqual(violations, [])
        self.assertEqual(packages, ["com.revetsec", "com.revetsec.json"])

    def test_bundled_foreign_class_rejected(self):
        self.write_jar(self.good_entries(**{"org/json/JSONObject.class": b"\xca\xfe\xba\xbe"}))
        violations, _ = VERIFIER.jar_violations(self.jar)
        self.assertTrue(any("org/json/JSONObject.class: outside com/revetsec/" in item for item in violations))

    def test_root_resource_rejected(self):
        self.write_jar(self.good_entries(**{"logging.properties": b"x"}))
        violations, _ = VERIFIER.jar_violations(self.jar)
        self.assertTrue(any("logging.properties: outside" in item for item in violations))

    def test_versioned_foreign_class_rejected(self):
        self.write_jar(self.good_entries(**{"META-INF/versions/21/shaded/Thing.class": b"\xca\xfe\xba\xbe"}))
        violations, _ = VERIFIER.jar_violations(self.jar)
        self.assertTrue(any("META-INF/versions/21/shaded/Thing.class" in item for item in violations))

    def test_module_descriptor_rejected(self):
        self.write_jar(self.good_entries(**{"module-info.class": b"\xca\xfe\xba\xbe"}))
        violations, _ = VERIFIER.jar_violations(self.jar)
        self.assertTrue(any("module descriptor" in item for item in violations))

    def test_missing_license_and_notice_rejected(self):
        entries = self.good_entries()
        del entries["META-INF/LICENSE"]
        del entries["META-INF/NOTICE"]
        self.write_jar(entries)
        violations, _ = VERIFIER.jar_violations(self.jar)
        self.assertIn("META-INF/LICENSE is missing", violations)
        self.assertIn("META-INF/NOTICE is missing", violations)

    def test_missing_manifest_rejected(self):
        self.write_jar(self.good_entries(), manifest=None)
        violations, _ = VERIFIER.jar_violations(self.jar)
        self.assertIn("META-INF/MANIFEST.MF is missing", violations)

    def test_wrong_automatic_module_name_rejected(self):
        self.write_jar(self.good_entries(), manifest="Manifest-Version: 1.0\r\nAutomatic-Module-Name: revetsec\r\n\r\n")
        violations, _ = VERIFIER.jar_violations(self.jar)
        self.assertTrue(any("Automatic-Module-Name is 'revetsec'" in item for item in violations))

    def test_missing_automatic_module_name_rejected(self):
        self.write_jar(self.good_entries(), manifest="Manifest-Version: 1.0\r\n\r\n")
        violations, _ = VERIFIER.jar_violations(self.jar)
        self.assertTrue(any("Automatic-Module-Name is None" in item for item in violations))

    def test_automatic_module_name_in_named_section_ignored(self):
        manifest = "Manifest-Version: 1.0\r\n\r\nName: com/revetsec/\r\nAutomatic-Module-Name: com.revetsec\r\n\r\n"
        self.write_jar(self.good_entries(), manifest=manifest)
        violations, _ = VERIFIER.jar_violations(self.jar)
        self.assertTrue(any("Automatic-Module-Name is None" in item for item in violations))

    def test_no_classes_rejected(self):
        entries = {name: content for name, content in self.good_entries().items() if not name.endswith(".class")}
        self.write_jar(entries)
        violations, _ = VERIFIER.jar_violations(self.jar)
        self.assertIn("no class files under com/revetsec/", violations)

    def test_manifest_continuation_lines_joined(self):
        manifest = "Manifest-Version: 1.0\nAutomatic-Module-Name: com.rev\n etsec\n\n"
        self.assertEqual(VERIFIER.manifest_attribute(manifest, "Automatic-Module-Name"), "com.revetsec")


class JdepsTests(unittest.TestCase):
    JAR = "revetsec-1.0.0-SNAPSHOT.jar"

    def test_module_list_parsing(self):
        self.assertEqual(VERIFIER.parse_jdeps_modules("java.base\n"), ["java.base"])
        self.assertEqual(VERIFIER.parse_jdeps_modules(""), [])
        self.assertEqual(
            VERIFIER.parse_jdeps_modules("java.base,java.logging,java.xml.crypto\n"),
            ["java.base", "java.logging", "java.xml.crypto"],
        )

    def test_unexpected_module_output_rejected(self):
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.parse_jdeps_modules("Error: Missing dependencies: classes not found\n")

    def test_clean_class_level_output_passes(self):
        violations, dependencies = VERIFIER.jdeps_class_violations(JDEPS_CLEAN, self.JAR)
        self.assertEqual(violations, [])
        self.assertEqual(len(dependencies), 6)

    def test_module_outside_inv_l1_rejected(self):
        output = JDEPS_CLEAN + (
            "   com.revetsec.internal.A                            -> java.sql.Connection"
            "                                java.sql\n"
        )
        violations, _ = VERIFIER.jdeps_class_violations(output, self.JAR)
        self.assertEqual(violations, ["com.revetsec.internal.A -> java.sql.Connection: in java.sql, outside the INV-L1 modules"])

    def test_jdk_internal_api_rejected(self):
        output = (
            "   com.revetsec.internal.A                            -> sun.misc.Unsafe"
            "                                    JDK internal API (jdk.unsupported)\n"
        )
        violations, _ = VERIFIER.jdeps_class_violations(output, self.JAR)
        self.assertEqual(len(violations), 1)
        self.assertIn("JDK internal API (jdk.unsupported)", violations[0])

    def test_missing_non_annotation_class_rejected(self):
        output = (
            "   com.revetsec.internal.A                            -> com.fasterxml.jackson.core.JsonParser"
            "              not found\n"
        )
        violations, _ = VERIFIER.jdeps_class_violations(output, self.JAR)
        self.assertEqual(
            violations,
            ["com.revetsec.internal.A -> com.fasterxml.jackson.core.JsonParser: not found and not a provided-scope annotation"],
        )

    def test_missing_class_in_annotation_subpackage_rejected(self):
        output = (
            "   com.revetsec.internal.A                            -> org.jspecify.annotations.impl.Helper"
            "               not found\n"
        )
        violations, _ = VERIFIER.jdeps_class_violations(output, self.JAR)
        self.assertEqual(len(violations), 1)


def utf8(text):
    data = text.encode("utf-8")
    return bytes([1]) + len(data).to_bytes(2, "big") + data


def class_ref(index):
    return bytes([7]) + index.to_bytes(2, "big")


def class_file(entries, slots):
    """A class-file prefix: magic, version 61.0 and a constant pool with `slots` used slots."""
    return b"\xca\xfe\xba\xbe" + (0).to_bytes(2, "big") + (61).to_bytes(2, "big") + (slots + 1).to_bytes(2, "big") + b"".join(entries)


class ConstantPoolTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.jar = Path(self.temporary.name) / "revetsec-1.0.0-SNAPSHOT.jar"

    def test_class_entries_are_collected_across_wide_constants(self):
        data = class_file(
            [
                utf8("com/revetsec/internal/A"),                     # 1
                class_ref(1),                                        # 2
                bytes([5]) + (42).to_bytes(8, "big"),               # 3-4 (Long takes two slots)
                utf8("[Lorg/jspecify/annotations/Nullable;"),        # 5
                class_ref(5),                                        # 6
                bytes([12]) + (1).to_bytes(2, "big") + (5).to_bytes(2, "big"),  # 7 NameAndType
                utf8("Lorg/jspecify/annotations/NullMarked;"),       # 8 (annotation descriptor only)
            ],
            slots=8,
        )
        self.assertEqual(
            VERIFIER.class_constant_names(data),
            {"com.revetsec.internal.A", "org.jspecify.annotations.Nullable"},
        )

    def test_unknown_tag_rejected(self):
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.class_constant_names(class_file([bytes([2, 0, 0])], slots=1))

    def test_truncated_pool_rejected(self):
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.class_constant_names(class_file([utf8("abc")[:3]], slots=1))

    def test_not_a_class_file_rejected(self):
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.class_constant_names(b"PK\x03\x04")

    def write_jar(self, class_bytes):
        with zipfile.ZipFile(self.jar, "w") as archive:
            archive.writestr("com/revetsec/Probe.class", class_bytes)

    def test_annotation_used_only_as_annotation_passes(self):
        self.write_jar(class_file([utf8("Lorg/jspecify/annotations/NullMarked;"), utf8("com/revetsec/Probe"), class_ref(2)], slots=3))
        self.assertEqual(VERIFIER.provided_annotation_class_references(self.jar), [])

    def test_annotation_referenced_as_class_rejected(self):
        self.write_jar(class_file([utf8("org/jspecify/annotations/NullMarked"), class_ref(1)], slots=2))
        violations = VERIFIER.provided_annotation_class_references(self.jar)
        self.assertEqual(len(violations), 1)
        self.assertIn("references org.jspecify.annotations.NullMarked as a class", violations[0])

    def test_unparseable_class_rejected(self):
        self.write_jar(b"\xca\xfe\xba\xbe\x00")
        self.assertEqual(len(VERIFIER.provided_annotation_class_references(self.jar)), 1)


class ClasspathTests(unittest.TestCase):
    def test_exactly_the_installed_jar_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            jar = Path(directory) / "revetsec.jar"
            jar.write_bytes(b"")
            self.assertEqual(VERIFIER.classpath_violations([str(jar)], jar), [])

    def test_transitive_dependency_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            jar = Path(directory) / "revetsec.jar"
            other = Path(directory) / "jspecify-1.0.1.jar"
            violations = VERIFIER.classpath_violations([str(jar), str(other)], jar)
            self.assertEqual(len(violations), 1)
            self.assertIn("jspecify-1.0.1.jar", violations[0])

    def test_empty_classpath_rejected(self):
        self.assertEqual(len(VERIFIER.classpath_violations([], Path("/nonexistent/revetsec.jar"))), 1)


class ConsumerOutputTests(unittest.TestCase):
    """PackagedConsumer's public-api= line must come last and name every group of public API calls."""

    API_LINE = VERIFIER.PUBLIC_API_LINE_PREFIX + ",".join(VERIFIER.PUBLIC_API_CALLS)

    def lines(self, *last):
        return ["jar=/repository/revetsec.jar", "automatic-module-name=com.revetsec", *last]

    def test_output_ending_with_the_public_api_line_passes(self):
        self.assertEqual(VERIFIER.consumer_output_violations(self.lines(self.API_LINE), "Maven consumer run"), [])

    def test_output_without_the_public_api_line_is_rejected(self):
        violations = VERIFIER.consumer_output_violations(self.lines(), "Gradle consumer run")
        self.assertEqual(len(violations), 1)
        self.assertIn("Gradle consumer run", violations[0])

    def test_empty_output_is_rejected(self):
        self.assertEqual(len(VERIFIER.consumer_output_violations([], "Maven consumer run")), 1)

    def test_a_public_api_line_that_is_not_last_is_rejected(self):
        output = self.lines(self.API_LINE, "runtime=17.0.20.1+10-LTS")
        self.assertEqual(len(VERIFIER.consumer_output_violations(output, "Maven consumer run")), 1)

    def test_a_repeated_public_api_line_is_rejected(self):
        output = self.lines(self.API_LINE, self.API_LINE)
        self.assertEqual(len(VERIFIER.consumer_output_violations(output, "Maven consumer run")), 1)

    def test_a_missing_or_reordered_call_group_is_rejected(self):
        calls = list(VERIFIER.PUBLIC_API_CALLS)
        for changed in (calls[:-1], list(reversed(calls)), calls + ["Extra"]):
            with self.subTest(changed=changed):
                output = self.lines(VERIFIER.PUBLIC_API_LINE_PREFIX + ",".join(changed))
                self.assertEqual(len(VERIFIER.consumer_output_violations(output, "Maven consumer run")), 1)

    # javac 17, 21, 25 and 26 (not 27) warn when a class the consumer compiles against carries a provided-scope
    # annotation with an element (jsr305 @GuardedBy("lock")) on any member, private ones included, and the annotation
    # JAR is absent. The consumer compile catches that only for the types PackagedConsumer uses, so it must use every
    # exported one.
    EXPORTED_TOP_LEVEL = re.compile(
        r"^public\s+(?:(?:final|abstract|sealed|non-sealed|static|strictfp)\s+)*(?:class|interface|enum|record|@interface)"
        r"\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
    EXPORTED_NESTED = re.compile(
        r"^\tpublic\s+(?:(?:final|abstract|sealed|non-sealed|static|strictfp)\s+)*(?:class|interface|enum|record)"
        r"\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)

    def exported_public_types(self):
        root = REPOSITORY_ROOT / "src" / "main" / "java" / "com" / "revetsec"
        types = []
        for source in sorted(root.rglob("*.java")):
            relative = source.relative_to(root)
            if relative.parts[0] == "internal" or source.name == "package-info.java":
                continue
            package = ".".join(("com", "revetsec", *relative.parts[:-1]))
            text = source.read_text(encoding="utf-8")
            for match in self.EXPORTED_TOP_LEVEL.finditer(text):
                types.append((package, match.group("name"), None))
                for nested in self.EXPORTED_NESTED.finditer(text):
                    types.append((package, match.group("name"), nested.group("name")))
        return types

    # Comments, string and character literals, and import lines: a type named only there is not used.
    NOT_CODE = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|^import\s[^\n]*',
                          re.DOTALL | re.MULTILINE)

    def test_packaged_consumer_uses_every_exported_public_type(self):
        source = (VERIFIER.SCRIPT_DIRECTORY / "src" / "main" / "java" / "example" / "PackagedConsumer.java").read_text(
            encoding="utf-8")
        code = self.NOT_CODE.sub(" ", source)
        types = self.exported_public_types()
        self.assertIn(("com.revetsec", "StateSealer", "Builder"), types)
        self.assertIn(("com.revetsec.json", "JsonObject", "Builder"), types)
        for package, name, nested in types:
            with self.subTest(type=f"{package}.{name}" + (f".{nested}" if nested else "")):
                self.assertIn(f"import {package}.{name};", source)
                self.assertRegex(code, rf"(?<![A-Za-z0-9_$.]){name}(?![A-Za-z0-9_$])")
                if nested:
                    self.assertRegex(code, rf"(?<![A-Za-z0-9_$.]){name}\.{nested}(?![A-Za-z0-9_$])")

    def test_packaged_consumer_prints_the_line_and_every_call_group(self):
        source = (VERIFIER.SCRIPT_DIRECTORY / "src" / "main" / "java" / "example" / "PackagedConsumer.java").read_text(
            encoding="utf-8")
        self.assertIn(f'System.out.println("{VERIFIER.PUBLIC_API_LINE_PREFIX}" + String.join(",", calledApi));', source)
        positions = [source.find(f'calledApi.add("{call}");') for call in VERIFIER.PUBLIC_API_CALLS]
        self.assertNotIn(-1, positions)


class GradlePinTests(unittest.TestCase):
    """The Gradle pin lives in the script; the CI job and CONTRIBUTING.md must download exactly that archive."""

    DISTRIBUTION_URL = re.compile(r"https?://[A-Za-z0-9.-]*gradle\.org/\S*?gradle-[^\s\"'/]+\.zip")
    DISTRIBUTION_NAME = re.compile(r"gradle-(?P<version>[0-9][^\s\"'/]*?)-(?:bin|all)\.zip")

    def assert_downloads_only_the_pin(self, path):
        text = path.read_text(encoding="utf-8")
        self.assertEqual(sorted(set(self.DISTRIBUTION_URL.findall(text))), [VERIFIER.GRADLE_DISTRIBUTION_URL],
                         f"{path} must download exactly {VERIFIER.GRADLE_DISTRIBUTION_URL}")
        versions = {match.group("version") for match in self.DISTRIBUTION_NAME.finditer(text)}
        self.assertEqual(versions, {VERIFIER.GRADLE_VERSION}, f"{path} names another Gradle distribution")

    def test_pin_is_well_formed(self):
        self.assertRegex(VERIFIER.GRADLE_VERSION, r"^[0-9]+\.[0-9]+(\.[0-9]+)?$")
        self.assertRegex(VERIFIER.GRADLE_DISTRIBUTION_SHA256, r"^[0-9a-f]{64}$")
        self.assertEqual(
            VERIFIER.GRADLE_DISTRIBUTION_URL,
            f"https://services.gradle.org/distributions/gradle-{VERIFIER.GRADLE_VERSION}-bin.zip",
        )

    def test_ci_downloads_the_pinned_distribution_and_passes_it_to_the_verifier(self):
        workflow = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
        self.assert_downloads_only_the_pin(workflow)
        archive = f'"${{RUNNER_TEMP}}/gradle-{VERIFIER.GRADLE_VERSION}-bin.zip"'
        text = workflow.read_text(encoding="utf-8")
        self.assertIn(f"--output {archive}", text)
        self.assertIn(f"--gradle-distribution {archive}", text)

    def test_contributing_and_the_verification_readme_download_the_pinned_distribution(self):
        self.assert_downloads_only_the_pin(REPOSITORY_ROOT / "CONTRIBUTING.md")
        self.assert_downloads_only_the_pin(REPOSITORY_ROOT / "verification" / "README.md")

    def test_the_documents_name_only_the_pinned_gradle_version_in_prose_too(self):
        # A pin bump that moves the URLs but leaves "Gradle <old version>" in a gate table or a paragraph would
        # tell contributors to run a version CI no longer checks.
        prose_version = re.compile(r"\bGradle (?P<version>[0-9]+\.[0-9]+(?:\.[0-9]+)?)\b")
        for path in (REPOSITORY_ROOT / "CONTRIBUTING.md", REPOSITORY_ROOT / "verification" / "README.md"):
            text = path.read_text(encoding="utf-8")
            versions = {match.group("version") for match in prose_version.finditer(text)}
            with self.subTest(path=path.name):
                self.assertEqual(versions, {VERIFIER.GRADLE_VERSION}, f"{path} names another Gradle version")

    def test_gradle_consumer_sources_exist_and_write_the_report_the_script_reads(self):
        for name in VERIFIER.GRADLE_CONSUMER_SOURCES + VERIFIER.MAVEN_CONSUMER_SOURCES:
            self.assertTrue((VERIFIER.SCRIPT_DIRECTORY / name).exists(), name)
        build = (VERIFIER.SCRIPT_DIRECTORY / "build.gradle").read_text(encoding="utf-8")
        self.assertIn(f"'{VERIFIER.GRADLE_REPORT.relative_to('build').as_posix()}'", build)
        self.assertIn(f"formatVersion   : {VERIFIER.GRADLE_REPORT_FORMAT_VERSION},", build)
        for configuration in VERIFIER.GRADLE_CONFIGURATIONS:
            self.assertIn(f"{configuration}: describeResolution(", build)

    def test_gradle_distribution_is_required_on_the_command_line(self):
        with contextlib.redirect_stderr(io.StringIO()) as errors, self.assertRaises(SystemExit) as raised:
            VERIFIER.main(["--java-home", "/nonexistent", "--maven", "mvn"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--gradle-distribution", errors.getvalue())


class GradleArchiveCheckOrderTests(unittest.TestCase):
    """verify() rejects a missing or wrong Gradle archive before it reads core's POM or builds anything."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        # A stand-in JDK: verify() only checks that bin/java and bin/jdeps exist before the archive check.
        self.java_home = self.directory / "jdk"
        (self.java_home / "bin").mkdir(parents=True)
        for tool in ("java", "jdeps"):
            (self.java_home / "bin" / tool).write_bytes(b"")
        self.archive = self.directory / f"gradle-{VERIFIER.GRADLE_VERSION}-bin.zip"
        self.work = self.directory / "work"
        self.output = self.directory / "result"

    def run_main(self):
        # Every other input is missing: reaching core's pom.xml, the repository or Maven would fail differently.
        arguments = [
            "--core-directory", str(self.directory / "no-core"),
            "--repository", str(self.directory / "no-repository"),
            "--java-home", str(self.java_home),
            "--maven", str(self.directory / "no-maven"),
            "--gradle-distribution", str(self.archive),
            "--work-directory", str(self.work),
            "--output", str(self.output),
        ]
        with contextlib.redirect_stderr(io.StringIO()) as errors, contextlib.redirect_stdout(io.StringIO()):
            code = VERIFIER.main(arguments)
        self.assertEqual(code, 1)
        result = json.loads((self.output / "packaged-consumer-result.json").read_text(encoding="utf-8"))
        self.assertEqual(result["result"], "FAIL")
        self.assertFalse(self.work.exists(), "a consumer work directory was created before the archive check")
        return errors.getvalue()

    def test_a_wrong_archive_fails_on_its_digest_first(self):
        self.archive.write_bytes(b"<html>not the pinned Gradle distribution</html>")
        self.assertIn(f"expected the pinned {VERIFIER.GRADLE_DISTRIBUTION_SHA256}", self.run_main())

    def test_a_missing_archive_names_the_pinned_url(self):
        self.assertIn(f"download {VERIFIER.GRADLE_DISTRIBUTION_URL}", self.run_main())


def zip_member(name, mode, directory=False):
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = ((stat.S_IFDIR if directory else stat.S_IFREG) | mode) << 16
    return info


class GradleDistributionTests(unittest.TestCase):
    VERSION = VERIFIER.GRADLE_VERSION
    ROOT = f"gradle-{VERIFIER.GRADLE_VERSION}"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.archive = self.directory / f"{self.ROOT}-bin.zip"
        self.destination = self.directory / "unpacked"

    def write_distribution(self, members):
        """members: (ZipInfo, bytes) pairs. Returns the archive's SHA-256."""
        with zipfile.ZipFile(self.archive, "w") as archive:
            for info, content in members:
                archive.writestr(info, content)
        return hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def good_members(self, *extra):
        return [
            (zip_member(f"{self.ROOT}/", 0o755, directory=True), b""),
            (zip_member(f"{self.ROOT}/bin/", 0o755, directory=True), b""),
            (zip_member(f"{self.ROOT}/bin/gradle", 0o755), b"#!/bin/sh\necho gradle\n"),
            (zip_member(f"{self.ROOT}/lib/gradle-launcher.jar", 0o644), b"PK"),
            *extra,
        ]

    def unpack(self, expected_sha256):
        return VERIFIER.unpack_gradle_distribution(self.archive, self.destination, expected_sha256, self.VERSION)

    def assert_rejected_before_extraction(self, members, message):
        digest = self.write_distribution(members)
        with self.assertRaises(VERIFIER.VerificationError) as raised:
            self.unpack(digest)
        self.assertIn(message, str(raised.exception))
        self.assertEqual(list(self.destination.rglob("*")) if self.destination.exists() else [], [])
        self.assertEqual(sorted(path.name for path in self.directory.iterdir()), [self.archive.name, "unpacked"])

    def test_matching_digest_extracts_an_executable_launcher(self):
        digest = self.write_distribution(self.good_members())
        launcher = self.unpack(digest)
        self.assertEqual(launcher, self.destination / self.ROOT / "bin" / "gradle")
        self.assertTrue(os.access(launcher, os.X_OK))
        library = self.destination / self.ROOT / "lib" / "gradle-launcher.jar"
        self.assertEqual(library.read_bytes(), b"PK")
        self.assertEqual(stat.S_IMODE(library.stat().st_mode), 0o644)

    def test_set_id_and_world_write_bits_are_dropped(self):
        digest = self.write_distribution(self.good_members((zip_member(f"{self.ROOT}/bin/tool", 0o6777), b"x")))
        self.unpack(digest)
        self.assertEqual(stat.S_IMODE((self.destination / self.ROOT / "bin" / "tool").stat().st_mode), 0o755)

    def test_digest_mismatch_is_rejected_before_anything_is_extracted(self):
        self.write_distribution(self.good_members())
        with self.assertRaises(VERIFIER.VerificationError) as raised:
            self.unpack(VERIFIER.GRADLE_DISTRIBUTION_SHA256)
        self.assertIn(f"expected the pinned {VERIFIER.GRADLE_DISTRIBUTION_SHA256}", str(raised.exception))
        self.assertFalse(self.destination.exists())

    def test_a_non_zip_with_the_wrong_digest_fails_on_the_digest_not_the_format(self):
        self.archive.write_bytes(b"<html>301 Moved Permanently</html>")
        with self.assertRaises(VERIFIER.VerificationError) as raised:
            self.unpack(VERIFIER.GRADLE_DISTRIBUTION_SHA256)
        self.assertIn("SHA-256", str(raised.exception))

    def test_parent_segment_is_rejected(self):
        self.assert_rejected_before_extraction(
            self.good_members((zip_member(f"{self.ROOT}/../evil", 0o644), b"x")), "'..' path segment")

    def test_absolute_entry_is_rejected(self):
        self.assert_rejected_before_extraction(
            self.good_members((zip_member("/tmp/evil", 0o644), b"x")), "absolute entry name")

    def test_entry_outside_the_distribution_root_is_rejected(self):
        self.assert_rejected_before_extraction(
            self.good_members((zip_member("gradle-0.0/bin/gradle", 0o755), b"x")), "outside the distribution root")

    def test_symbolic_link_is_rejected(self):
        link = zipfile.ZipInfo(f"{self.ROOT}/lib/link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.assert_rejected_before_extraction(self.good_members((link, b"/etc/passwd")), "symbolic link")

    def test_backslash_entry_is_rejected(self):
        self.assert_rejected_before_extraction(
            self.good_members((zip_member(f"{self.ROOT}\\..\\evil", 0o644), b"x")), "backslash")

    def test_missing_launcher_is_rejected(self):
        members = [member for member in self.good_members() if not member[0].filename.endswith("bin/gradle")]
        digest = self.write_distribution(members)
        with self.assertRaises(VERIFIER.VerificationError) as raised:
            self.unpack(digest)
        self.assertIn("no executable", str(raised.exception))

    def test_launcher_without_an_executable_bit_is_rejected(self):
        members = [member for member in self.good_members() if not member[0].filename.endswith("bin/gradle")]
        members.append((zip_member(f"{self.ROOT}/bin/gradle", 0o644), b"#!/bin/sh\n"))
        digest = self.write_distribution(members)
        with self.assertRaises(VERIFIER.VerificationError):
            self.unpack(digest)


class GradleReportTests(unittest.TestCase):
    COORDINATES = "com.revetsec:revetsec:1.0.0-SNAPSHOT"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        directory = Path(self.temporary.name)
        self.jar = directory / "repository/com/revetsec/revetsec/1.0.0-SNAPSHOT/revetsec-1.0.0-SNAPSHOT.jar"
        self.jar.parent.mkdir(parents=True)
        self.jar.write_bytes(b"PK")
        self.java_home = directory / "jdk"
        self.java_home.mkdir()

    def resolution(self, **overrides):
        resolution = {
            "components": [{"id": self.COORDINATES, "dependencies": []}],
            "unresolved": [],
            "files": [{"component": self.COORDINATES, "path": str(self.jar)}],
        }
        resolution.update(overrides)
        return resolution

    def report(self, runtime=None, compile=None, **overrides):
        report = {
            "formatVersion": 1,
            "gradleVersion": VERIFIER.GRADLE_VERSION,
            "gradleJavaHome": str(self.java_home),
            "gradleJavaVersion": "27+35-FR",
            "configurations": {
                "runtimeClasspath": runtime if runtime is not None else self.resolution(),
                "compileClasspath": compile if compile is not None else self.resolution(),
            },
        }
        report.update(overrides)
        return report

    def violations(self, report):
        return VERIFIER.gradle_report_violations(report, self.jar, self.COORDINATES, self.java_home)

    def test_clean_report_passes(self):
        self.assertEqual(self.violations(self.report()), [])

    def test_another_gradle_version_is_rejected(self):
        violations = self.violations(self.report(gradleVersion="9.1.0"))
        self.assertEqual(len(violations), 1)
        self.assertIn(f"expected the pinned {VERIFIER.GRADLE_VERSION}", violations[0])

    def test_gradle_on_another_jdk_is_rejected(self):
        violations = self.violations(self.report(gradleJavaHome="/opt/other-jdk"))
        self.assertEqual(len(violations), 1)
        self.assertIn("Gradle ran on the JDK at '/opt/other-jdk'", violations[0])

    def test_transitive_runtime_component_is_rejected(self):
        runtime = self.resolution(components=[
            {"id": self.COORDINATES, "dependencies": ["org.jspecify:jspecify:1.0.1"]},
            {"id": "org.jspecify:jspecify:1.0.1", "dependencies": []},
        ])
        violations = self.violations(self.report(runtime=runtime))
        self.assertEqual(len(violations), 1)
        self.assertTrue(violations[0].startswith("runtimeClasspath: must resolve exactly"))
        self.assertIn("org.jspecify:jspecify:1.0.1", violations[0])

    def test_dependency_of_the_revetsec_component_is_rejected_on_the_compile_classpath_too(self):
        compile = self.resolution(components=[{"id": self.COORDINATES, "dependencies": ["com.example:leak:1.0"]}])
        violations = self.violations(self.report(compile=compile))
        self.assertEqual(len(violations), 1)
        self.assertTrue(violations[0].startswith("compileClasspath: must resolve exactly"))

    def test_unresolved_dependency_is_rejected(self):
        violations = self.violations(self.report(runtime=self.resolution(unresolved=["com.example:leak:1.0"])))
        self.assertEqual(violations, ["runtimeClasspath: unresolved dependencies ['com.example:leak:1.0']"])

    def test_extra_runtime_file_is_rejected(self):
        files = self.resolution()["files"] + [{"component": "org.jspecify:jspecify:1.0.1", "path": "/tmp/jspecify.jar"}]
        violations = self.violations(self.report(runtime=self.resolution(files=files)))
        self.assertEqual(len(violations), 1)
        self.assertIn("jspecify.jar", violations[0])

    def test_jar_from_another_location_is_rejected(self):
        copy = Path(self.temporary.name) / "gradle-cache" / self.jar.name
        files = [{"component": self.COORDINATES, "path": str(copy)}]
        violations = self.violations(self.report(runtime=self.resolution(files=files)))
        self.assertEqual(len(violations), 1)
        self.assertIn("must be exactly the installed Revetsec JAR", violations[0])

    def test_empty_class_path_is_rejected(self):
        violations = self.violations(self.report(compile=self.resolution(components=[], files=[])))
        self.assertEqual(len(violations), 2)

    def test_missing_configuration_is_rejected(self):
        report = self.report()
        del report["configurations"]["compileClasspath"]
        self.assertEqual(self.violations(report), ["compileClasspath: missing from the Gradle report"])

    def test_malformed_report_fields_fail_closed(self):
        wrong_component = [{"component": "com.revetsec:other:1.0.0", "path": str(self.jar)}]
        cases = {
            "no configurations object": (self.report(configurations=None), "no configurations object"),
            "no gradleJavaHome": (self.report(gradleJavaHome=None), "Gradle ran on the JDK at None"),
            "file owned by another component": (
                self.report(runtime=self.resolution(files=wrong_component)), "runtimeClasspath: must be exactly"),
            "file without a path": (
                self.report(compile=self.resolution(files=[{"component": self.COORDINATES}])),
                "compileClasspath: must be exactly"),
        }
        for name, (report, message) in cases.items():
            with self.subTest(name):
                violations = self.violations(report)
                self.assertEqual(len(violations), 1, violations)
                self.assertIn(message, violations[0])

    def test_unknown_format_version_is_rejected(self):
        self.assertEqual(len(self.violations(self.report(formatVersion=2))), 1)

    def test_report_file_must_exist_and_hold_a_json_object(self):
        path = Path(self.temporary.name) / "resolution.json"
        cases = ((None, "did not write"), ("[]", "does not hold a JSON object"), ("{", "not valid JSON"))
        for content, message in cases:
            if content is not None:
                path.write_text(content, encoding="utf-8")
            with self.subTest(content=content), self.assertRaises(VERIFIER.VerificationError) as raised:
                VERIFIER.read_gradle_report(path)
            self.assertIn(message, str(raised.exception))
        path.write_text(json.dumps(self.report()), encoding="utf-8")
        self.assertEqual(VERIFIER.read_gradle_report(path)["gradleVersion"], VERIFIER.GRADLE_VERSION)


class AnnotationFreeSourceTests(unittest.TestCase):
    def test_only_type_annotations_and_imports_are_erased(self):
        source = '\n'.join([
            'import org.jspecify.annotations.NonNull;',
            'import org.jspecify.annotations.Nullable;',
            'class Consumer {',
            '  // @NonNull comment survives',
            '  String literal = "@Nullable literal survives";',
            '  /* @Nullable block survives */',
            '  @NonNull java.util.List<@Nullable String> call(String @NonNull [] values) {',
            '    return java.util.List.of("value");',
            '  }',
            '}',
        ])
        expected = '\n'.join([
            'class Consumer {',
            '  // @NonNull comment survives',
            '  String literal = "@Nullable literal survives";',
            '  /* @Nullable block survives */',
            '  java.util.List<String> call(String [] values) {',
            '    return java.util.List.of("value");',
            '  }',
            '}',
        ])
        self.assertEqual(expected, VERIFIER.annotation_free_source(source))

    def test_qualified_tokens_and_text_blocks_preserve_literal_contents(self):
        source = 'class C { String s = """\n@NonNull literal\n"""; java.lang.@org.jspecify.annotations.NonNull String value() { return s; } }'
        expected = 'class C { String s = """\n@NonNull literal\n"""; java.lang.String value() { return s; } }'
        self.assertEqual(expected, VERIFIER.annotation_free_source(source))


if __name__ == "__main__":
    unittest.main()
