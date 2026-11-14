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

"""Guard the Java 17 core / Java 21 Soklet boundary without running Maven or Docker."""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
PINS = json.loads((ROOT / "examples/pins.json").read_text())
CONFIG_PATHS = (
    ".github/workflows/ci.yml", ".github/workflows/scim-interop.yml", "pom.xml",
    "examples/barebones-oidc/pom.xml", "examples/playground/pom.xml",
    "examples/self-issued/pom.xml", "examples/rsa-oidc/pom.xml",
    "examples/passkeys-soklet/pom.xml", "examples/totp-soklet/pom.xml",
    "verification/examples/NullabilityAudit.java",
)


def load_script(name, relative_path):
    specification = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def job(workflow, name):
    match = re.search(r"^  " + re.escape(name) + r":\n(.*?)(?=^  [\w-]+:\n|\Z)",
                      workflow, re.M | re.S)
    if match is None:
        raise AssertionError("Missing workflow job: " + name)
    return match.group(1)


def matrix(job_text, key):
    match = re.search(r"^        " + key + r": (\[[^\n]+\])$", job_text, re.M)
    if match is None:
        raise AssertionError("Missing literal Java matrix: " + key)
    return [int(value) for value in re.findall(r"['\"](\d+)['\"]", match.group(1))]


def compiler_releases(pom):
    root = ET.fromstring(pom)
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    values = [element.text for element in root.findall(".//m:configuration/m:release", ns)]
    values.extend(element.text for element in root.findall("./m:properties/m:maven.compiler.release", ns))
    return values


def check_configuration(files, pins):
    """Check relationships between independently maintained build entry points."""
    core_release = 17
    minimum = pins["framework"]["minimum_java"]
    if minimum <= core_release:
        raise AssertionError("Framework minimum Java must remain above core Java 17")
    if pins["framework"]["repository"] != "https://repo.maven.apache.org/maven2":
        raise AssertionError("Framework repository must be canonical Maven Central")
    if pins["framework"]["coordinates"] != "com.soklet:soklet:4.0.0":
        raise AssertionError("Framework coordinates drift")
    for name in ("jar_sha256", "pom_sha256"):
        if re.fullmatch(r"[0-9a-f]{64}", pins["framework"].get(name, "")) is None:
            raise AssertionError("Framework published checksum is invalid: " + name)
    for path, expected in (("pom.xml", core_release), ("examples/rsa-oidc/pom.xml", core_release),
                           *(("examples/" + name + "/pom.xml", minimum)
                             for name in ("barebones-oidc", "playground", "self-issued", "passkeys-soklet", "totp-soklet"))):
        releases = compiler_releases(files[path])
        if not releases or set(releases) != {str(expected)}:
            raise AssertionError("Compiler release drift: " + path)

    ci = files[".github/workflows/ci.yml"]
    core_matrix = matrix(job(ci, "test"), "jdk")
    if min(core_matrix) != core_release:
        raise AssertionError("Core test matrix must retain Java 17")
    for name, key in (("packaged-consumer", "jdk"), ("rsa-oidc-examples", "java")):
        if min(matrix(job(ci, name), key)) != core_release:
            raise AssertionError("Core-only consumer matrix must retain Java 17: " + name)
    examples = job(ci, "examples")
    if set(matrix(examples, "java")) != {minimum, max(core_matrix)}:
        raise AssertionError("Soklet example matrix must exercise its minimum and newest core JDK")

    for label, workflow in (("examples", examples),
                            ("SCIM", job(files[".github/workflows/scim-interop.yml"], "qualify"))):
        found = re.search(r"repository: revetsec/revetsec-soklet\n\s+ref: ([^\s]+)", workflow)
        if found is None or found.group(1) != pins["adapter"]["revision"]:
            raise AssertionError(label + " checkout pin drift: revetsec/revetsec-soklet")
        for forbidden in ("repository: soklet/soklet\n", ".scim-inputs/framework",
                          ".example-inputs/framework", "-f soklet/pom.xml"):
            if forbidden in workflow:
                raise AssertionError(label + " retains a Soklet source-commit pin")
        for name in ("jar_sha256", "pom_sha256"):
            if pins["framework"][name] not in workflow:
                raise AssertionError(label + " framework checksum drift: " + name)
        if "https://repo.maven.apache.org/maven2" not in workflow:
            raise AssertionError(label + " framework repository drift")
        if label == "examples":
            if "--framework-jar" not in workflow or "--framework-pom" not in workflow:
                raise AssertionError("Examples must supply both published framework artifacts")

    audit = files["verification/examples/NullabilityAudit.java"]
    if not re.search(r'arguments\.length\s*==\s*4\s*\?\s*arguments\[3\]\s*:\s*"17"', audit):
        raise AssertionError("Nullability audit must retain Java 17 as its default")
    if '"--release", release' not in audit:
        raise AssertionError("Nullability audit must pass its selected source release to javac")


class SokletBaselineConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.files = {path: (ROOT / path).read_text() for path in CONFIG_PATHS}

    def test_current_workflows_and_poms_form_one_coherent_baseline(self):
        check_configuration(self.files, PINS)

    def test_guard_detects_independent_pin_and_central_artifact_drift(self):
        replacements = (
            (".github/workflows/ci.yml", PINS["adapter"]["revision"], "a" * 40, "checkout pin"),
            (".github/workflows/ci.yml", PINS["framework"]["jar_sha256"], "c" * 64, "checksum"),
            (".github/workflows/ci.yml", PINS["framework"]["pom_sha256"], "d" * 64, "checksum"),
            (".github/workflows/scim-interop.yml", PINS["framework"]["jar_sha256"], "e" * 64, "checksum"),
            (".github/workflows/scim-interop.yml", PINS["framework"]["pom_sha256"], "f" * 64, "checksum"),
            (".github/workflows/scim-interop.yml", "https://repo.maven.apache.org/maven2",
             "https://example.invalid/maven2", "repository"),
        )
        for path, before, after, reason in replacements:
            with self.subTest(path=path, reason=reason):
                altered = {**self.files, path: self.files[path].replace(before, after)}
                self.assertNotEqual(altered[path], self.files[path])
                with self.assertRaisesRegex(AssertionError, reason):
                    check_configuration(altered, PINS)

    def test_guard_detects_lost_java17_core_and_java21_soklet_coverage(self):
        replacements = (
            ("pom.xml", "<release>17</release>", "<release>21</release>", "Compiler release"),
            ("examples/playground/pom.xml", "<maven.compiler.release>21</maven.compiler.release>", "<maven.compiler.release>17</maven.compiler.release>", "Compiler release"),
            (".github/workflows/ci.yml", "java: ['21', '27']", "java: ['17', '27']", "Soklet example matrix"),
            (".github/workflows/ci.yml", "jdk: ['17', '21', '25', '27']",
             "jdk: ['21', '25', '27']", "Core test matrix"),
            ("verification/examples/NullabilityAudit.java", 'arguments[3] : "17"',
             'arguments[3] : "21"', "audit must retain"),
        )
        for path, before, after, reason in replacements:
            with self.subTest(path=path, reason=reason):
                altered = {**self.files, path: self.files[path].replace(before, after)}
                self.assertNotEqual(altered[path], self.files[path])
                with self.assertRaisesRegex(AssertionError, reason):
                    check_configuration(altered, PINS)

    def test_guard_rejects_reintroduced_framework_source_checkout(self):
        path = ".github/workflows/scim-interop.yml"
        altered = {**self.files, path: self.files[path] + "\nrepository: soklet/soklet\n"}
        with self.assertRaisesRegex(AssertionError, "source-commit pin"):
            check_configuration(altered, PINS)


class SokletBaselineRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.examples = load_script("baseline_examples_build", "verification/examples/verify_packaged_examples.py")
        cls.postgres = load_script("baseline_postgres_run", "examples/postgresql-pending-store/run.py")
        with mock.patch.dict(sys.modules, {"run": cls.postgres}):
            cls.webauthn = load_script("baseline_postgres_webauthn", "examples/postgresql-pending-store/run_webauthn.py")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="revetsec-soklet-baseline-test-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.java = self.work / "jdk"
        (self.java / "bin").mkdir(parents=True)
        for name in ("java", "javac"):
            (self.java / "bin" / name).touch()
        self.jars = {}
        for name in ("core", "framework", "adapter", "pyranid", "driver", "jspecify", "jsr305"):
            self.jars[name] = self.work / (name + ".jar")
            self.jars[name].write_bytes(name.encode())
        self.framework_pom = self.work / "framework.pom"
        self.framework_pom.write_bytes(b"published framework POM")
        self.framework_pin = {
            **PINS["framework"],
            "jar_sha256": hashlib.sha256(self.jars["framework"].read_bytes()).hexdigest(),
            "pom_sha256": hashlib.sha256(self.framework_pom.read_bytes()).hexdigest(),
        }
        self.maven = self.work / "mvn"
        self.maven.touch()
        for name in ("core-source", "adapter-source"):
            (self.work / name).mkdir()

    def postgres_arguments(self):
        result = ["run.py", "--java-home", str(self.java)]
        for name in ("core", "pyranid", "driver", "jspecify", "jsr305"):
            result.extend(("--" + name + "-jar", str(self.jars[name])))
        return result

    def examples_arguments(self):
        return ["build.py", "--work", str(self.work / "output"), "--maven", str(self.maven),
                "--java-home", str(self.java), "--core-source", str(self.work / "core-source"),
                "--adapter-source", str(self.work / "adapter-source"),
                "--framework-jar", str(self.jars["framework"]),
                "--framework-pom", str(self.framework_pom)]

    def test_all_runners_read_the_canonical_framework_pin(self):
        self.assertEqual(self.examples.PINS, PINS)
        for script in (self.postgres, self.webauthn):
            with self.subTest(script=script.__name__):
                self.assertEqual(script.FRAMEWORK_PIN, PINS["framework"])

    def test_postgres_selects_core17_or_soklet21_independently_of_host_jdk(self):
        for compiler, soklet, expected in (("17.0.20", False, "17"), ("21.0.11", False, "17"),
                                          ("27", False, "17"), ("21.0.11", True, "21"),
                                          ("27", True, "21")):
            with self.subTest(compiler=compiler, soklet=soklet), mock.patch.object(
                    self.postgres.subprocess, "check_output", return_value="javac " + compiler):
                self.assertEqual(self.postgres.java_release_for(self.java, soklet), expected)
        for compiler in ("javac 17.0.20", "unexpected compiler output"):
            with self.subTest(compiler=compiler), mock.patch.object(
                    self.postgres.subprocess, "check_output", return_value=compiler):
                with self.assertRaisesRegex(RuntimeError, "requires JDK 21"):
                    self.postgres.java_release_for(self.java, True)

    def test_optional_postgres_soklet_lanes_reject_java17_before_docker_or_compilation(self):
        for script, extra in ((self.postgres, ["--adapter-jar", str(self.jars["adapter"]),
                                              "--framework-jar", str(self.jars["framework"])]),
                              (self.webauthn, ["--soklet-jar", str(self.jars["framework"])])):
            with self.subTest(script=script.__name__), mock.patch.object(
                    script, "FRAMEWORK_PIN", self.framework_pin), mock.patch.object(
                    script.subprocess, "check_output", return_value="javac 17.0.20"), mock.patch.object(
                    script.subprocess, "run") as run, mock.patch.object(script, "docker") as docker, \
                    mock.patch.object(sys, "argv", self.postgres_arguments() + extra):
                with self.assertRaisesRegex(RuntimeError, "requires JDK 21"):
                    script.main()
                run.assert_not_called()
                docker.assert_not_called()

    def test_examples_reject_java17_before_copying_or_building(self):
        with mock.patch.object(sys, "argv", self.examples_arguments()), mock.patch.object(
                self.examples.subprocess, "check_output", return_value="javac 17.0.20"), mock.patch.object(
                self.examples.subprocess, "run") as run, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                self.examples.main()
            run.assert_not_called()
        self.assertFalse((self.work / "output").exists())

    def test_examples_require_both_published_framework_artifacts(self):
        for omitted in ("--framework-jar", "--framework-pom"):
            arguments = self.examples_arguments()
            index = arguments.index(omitted)
            del arguments[index:index + 2]
            with self.subTest(omitted=omitted), mock.patch.object(sys, "argv", arguments), \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    self.examples.main()
            self.assertFalse((self.work / "output").exists())

    def test_wrong_framework_jar_never_reaches_adapter_or_example_build(self):
        calls = []
        def check_output(command, **unused):
            if command[-1] == "-version":
                return "javac 27"
            return "" if "ls-files" in command else PINS["core"]["revision"]
        def run(command, **unused):
            calls.append(command)
            return SimpleNamespace(returncode=0)
        with mock.patch.object(sys, "argv", self.examples_arguments()), mock.patch.object(
                self.examples.subprocess, "check_output", side_effect=check_output), mock.patch.object(
                self.examples.subprocess, "run", side_effect=run):
            with self.assertRaisesRegex(RuntimeError, "Framework JAR checksum"):
                self.examples.main()
        maven_calls = [command for command in calls if command[0] == str(self.maven)]
        self.assertEqual(len(maven_calls), 1)  # Only core installation precedes JAR admission.
        self.assertFalse((self.work / "output/examples").exists())

    def test_wrong_framework_pom_never_reaches_adapter_or_example_build(self):
        calls = []
        def check_output(command, **unused):
            if command[-1] == "-version":
                return "javac 27"
            return "" if "ls-files" in command else PINS["core"]["revision"]
        def run(command, **unused):
            calls.append(command)
            return SimpleNamespace(returncode=0)
        framework = {**PINS["framework"], "jar_sha256": hashlib.sha256(
            self.jars["framework"].read_bytes()).hexdigest()}
        with mock.patch.object(sys, "argv", self.examples_arguments()), mock.patch.object(
                self.examples.subprocess, "check_output", side_effect=check_output), mock.patch.object(
                self.examples.subprocess, "run", side_effect=run), mock.patch.object(
                self.examples, "PINS", {**PINS, "framework": framework}):
            with self.assertRaisesRegex(RuntimeError, "Framework POM checksum"):
                self.examples.main()
        maven_calls = [command for command in calls if command[0] == str(self.maven)]
        self.assertEqual(len(maven_calls), 1)
        self.assertFalse((self.work / "output/examples").exists())



class SelfIssuedInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = load_script("baseline_self_issued_build", "verification/examples/verify_self_issued.py")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="revetsec-authored-inventory-test-")
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name)

    def test_tracked_deletions_are_excluded_but_current_and_new_files_are_hashed(self):
        deleted = "links/soklet-3.5.1/element-list"
        authored = {"links/soklet-4.0.0/element-list": b"com.soklet\n",
                    "new example.java": b"// newly authored source\n"}
        for name, content in authored.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        listed = "\0".join([deleted, *reversed(authored), deleted, ""]).encode()
        with mock.patch.object(self.builder.subprocess, "check_output",
                               side_effect=[listed, (deleted + "\0").encode()]) as git:
            rows = self.builder.inventory(self.source)
        self.assertEqual(rows, [{"path": name, "sha256": hashlib.sha256(authored[name]).hexdigest()}
                                for name in sorted(authored)])
        self.assertEqual(git.call_args_list, [
            mock.call(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                      cwd=self.source),
            mock.call(["git", "ls-files", "--deleted", "-z"], cwd=self.source),
        ])

    def test_missing_files_without_an_exact_tracked_deletion_still_fail(self):
        for deleted in (b"", b"other/missing.java\0"):
            with self.subTest(deleted=deleted), mock.patch.object(
                    self.builder.subprocess, "check_output", side_effect=[b"missing.java\0", deleted]):
                with self.assertRaisesRegex(RuntimeError, "Unexpected authored source entry"):
                    self.builder.inventory(self.source)

    def test_symlinks_to_existing_files_still_fail(self):
        target = self.source / "real.java"
        target.write_text("// source target\n")
        (self.source / "linked.java").symlink_to(target)
        with mock.patch.object(self.builder.subprocess, "check_output",
                               side_effect=[b"real.java\0linked.java\0", b""]):
            with self.assertRaisesRegex(RuntimeError, "Unexpected authored source entry"):
                self.builder.inventory(self.source)


class RsaInventoryTests(SelfIssuedInventoryTests):
    @classmethod
    def setUpClass(cls):
        cls.builder = load_script("baseline_rsa_build", "verification/examples/verify_rsa_oidc.py")


if __name__ == "__main__":
    unittest.main()
