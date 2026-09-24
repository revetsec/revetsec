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

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.dont_write_bytecode = True

SCRIPT = Path(__file__).resolve().parent / "verify-packaged-consumer.py"
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


if __name__ == "__main__":
    unittest.main()
