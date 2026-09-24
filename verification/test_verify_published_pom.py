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

"""Seeded-violation tests for verify-published-pom.py.

Run: PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s verification -p 'test_*.py'
"""

import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True

SCRIPT = Path(__file__).resolve().parent / "verify-published-pom.py"
SPEC = importlib.util.spec_from_file_location("verify_published_pom", SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)

EXPECTED = ("com.revetsec", "revetsec", "1.0.0-SNAPSHOT")
POM_OPEN = '<?xml version="1.0" encoding="UTF-8"?>\n<project xmlns="http://maven.apache.org/POM/4.0.0">'
COORDINATES = """
<modelVersion>4.0.0</modelVersion>
<groupId>com.revetsec</groupId><artifactId>revetsec</artifactId><version>1.0.0-SNAPSHOT</version>
<packaging>jar</packaging>
"""
PROVIDED_AND_TEST = """
<dependencies>
  <dependency><groupId>org.jspecify</groupId><artifactId>jspecify</artifactId><version>1.0.1</version>
    <scope>provided</scope></dependency>
  <dependency><groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter-api</artifactId><version>6.1.3</version>
    <scope>test</scope></dependency>
</dependencies>
<dependencyManagement><dependencies>
  <dependency><groupId>org.junit</groupId><artifactId>junit-bom</artifactId><version>6.1.3</version>
    <type>pom</type><scope>import</scope></dependency>
</dependencies></dependencyManagement>
<build><plugins><plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-compiler-plugin</artifactId>
  <dependencies><dependency><groupId>com.google.errorprone</groupId><artifactId>error_prone_core</artifactId>
  <version>2.50.0</version></dependency></dependencies></plugin></plugins></build>
<profiles><profile><id>integration</id><dependencies>
  <dependency><groupId>org.testcontainers</groupId><artifactId>testcontainers</artifactId><version>2.0.5</version>
    <scope>test</scope></dependency>
</dependencies></profile></profiles>
"""


def pom(body, coordinates=COORDINATES, opening=POM_OPEN):
    return f"{opening}{coordinates}{body}</project>\n"


def dependency(scope_element):
    return (
        "<dependencies><dependency><groupId>com.example</groupId><artifactId>library</artifactId>"
        f"<version>1.0</version>{scope_element}</dependency></dependencies>"
    )


class PublishedPomTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "revetsec-1.0.0-SNAPSHOT.pom"

    def verify(self, text, expected=EXPECTED):
        self.path.write_text(text, encoding="utf-8")
        return VERIFIER.verify_pom(self.path, expected)

    def assert_rejected(self, text, message, expected=EXPECTED):
        with self.assertRaises(VERIFIER.PomPolicyError) as raised:
            self.verify(text, expected)
        self.assertIn(message, str(raised.exception))

    def test_provided_and_test_dependencies_pass(self):
        verified = self.verify(pom(PROVIDED_AND_TEST))
        self.assertEqual(verified.coordinates, "com.revetsec:revetsec:1.0.0-SNAPSHOT")
        self.assertEqual(
            [(item.scope, item.coordinates) for item in verified.dependencies],
            [
                ("provided", "org.jspecify:jspecify:jar:1.0.1"),
                ("test", "org.junit.jupiter:junit-jupiter-api:jar:6.1.3"),
                ("test", "org.testcontainers:testcontainers:jar:2.0.5"),
            ],
        )

    def test_no_dependencies_pass(self):
        self.assertEqual(self.verify(pom("")).dependencies, [])

    def test_missing_scope_is_compile_and_rejected(self):
        self.assert_rejected(pom(dependency("")), "com.example:library:jar:1.0 has scope 'compile'")

    def test_blank_scope_is_compile_and_rejected(self):
        self.assert_rejected(pom(dependency("<scope> </scope>")), "has scope 'compile'")

    def test_explicit_compile_scope_rejected(self):
        self.assert_rejected(pom(dependency("<scope>compile</scope>")), "has scope 'compile'")

    def test_runtime_scope_rejected(self):
        self.assert_rejected(pom(dependency("<scope>runtime</scope>")), "has scope 'runtime'")

    def test_system_scope_rejected(self):
        self.assert_rejected(pom(dependency("<scope>system</scope>")), "has scope 'system'")

    def test_property_scope_rejected(self):
        self.assert_rejected(pom(dependency("<scope>${library.scope}</scope>")), "cannot be verified statically")

    def test_optional_compile_dependency_still_rejected(self):
        self.assert_rejected(pom(dependency("<optional>true</optional>")), "has scope 'compile'")

    def test_profile_compile_dependency_rejected(self):
        body = f"<profiles><profile><id>jdk21</id>{dependency('<scope>runtime</scope>')}</profile></profiles>"
        self.assert_rejected(pom(body), "profile jdk21 dependencies: com.example:library:jar:1.0 has scope 'runtime'")

    def test_classifier_is_reported(self):
        body = (
            "<dependencies><dependency><groupId>com.example</groupId><artifactId>library</artifactId>"
            "<version>1.0</version><classifier>tests</classifier></dependency></dependencies>"
        )
        self.assert_rejected(pom(body), "com.example:library:jar:tests:1.0")

    def test_parent_rejected(self):
        body = "<parent><groupId>com.example</groupId><artifactId>parent</artifactId><version>1</version></parent>"
        self.assert_rejected(pom(body), "declares a <parent>")

    def test_repository_rejected(self):
        body = "<repositories><repository><id>other</id><url>https://repo.example</url></repository></repositories>"
        self.assert_rejected(pom(body), "repositories: declares a <repository>")

    def test_profile_repository_rejected(self):
        body = (
            "<profiles><profile><id>extra</id><repositories><repository><id>other</id>"
            "<url>https://repo.example</url></repository></repositories></profile></profiles>"
        )
        self.assert_rejected(pom(body), "profile extra repositories: declares a <repository>")

    def test_doctype_rejected(self):
        opening = '<?xml version="1.0"?>\n<!DOCTYPE project [<!ENTITY x "y">]>\n<project xmlns="http://maven.apache.org/POM/4.0.0">'
        self.assert_rejected(pom("", opening=opening), "DOCTYPE or entity declaration")

    def test_wrong_namespace_rejected(self):
        self.assert_rejected(pom("", opening='<project xmlns="urn:example">'), "root element must be <project>")

    def test_malformed_xml_rejected(self):
        self.assert_rejected(POM_OPEN + COORDINATES + "<dependencies>", "not well-formed XML")

    def test_wrong_coordinates_rejected(self):
        self.assert_rejected(pom(""), "expected com.revetsec:revetsec:1.0.0", ("com.revetsec", "revetsec", "1.0.0"))

    def test_non_literal_version_rejected(self):
        coordinates = COORDINATES.replace("<version>1.0.0-SNAPSHOT</version>", "<version>${revision}</version>")
        self.assert_rejected(pom("", coordinates=coordinates), "a version as a literal")

    def test_non_jar_packaging_rejected(self):
        coordinates = COORDINATES.replace("<packaging>jar</packaging>", "<packaging>pom</packaging>")
        self.assert_rejected(pom("", coordinates=coordinates), "packaging is 'pom'")

    def test_every_violation_is_listed(self):
        body = (
            "<parent><groupId>g</groupId><artifactId>p</artifactId><version>1</version></parent>"
            + dependency("<scope>runtime</scope>")
        )
        with self.assertRaises(VERIFIER.PomPolicyError) as raised:
            self.verify(pom(body))
        self.assertIn("declares a <parent>", str(raised.exception))
        self.assertIn("has scope 'runtime'", str(raised.exception))

    def test_command_line_exit_codes(self):
        self.path.write_text(pom(PROVIDED_AND_TEST), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(VERIFIER.main([str(self.path), "--expect", "com.revetsec:revetsec:1.0.0-SNAPSHOT"]), 0)
        self.assertIn("zero compile, runtime and system dependencies", output.getvalue())
        self.path.write_text(pom(dependency("")), encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(VERIFIER.main([str(self.path)]), 1)
        self.assertIn("has scope 'compile'", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
