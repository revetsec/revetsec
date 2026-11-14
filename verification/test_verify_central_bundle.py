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

"""Seeded-violation tests for verify-central-bundle.py."""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile


SCRIPT = Path(__file__).resolve().parent / "verify-central-bundle.py"
SPEC = importlib.util.spec_from_file_location("verify_central_bundle", SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)
EXPECTED = ("com.revetsec", "revetsec", "1.0.0")


def jar_bytes(entries):
	output = io.BytesIO()
	with zipfile.ZipFile(output, "w") as archive:
		for name, data in entries.items():
			archive.writestr(name, data)
	return output.getvalue()


def pom_bytes(dependency=""):
	return f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.revetsec</groupId><artifactId>revetsec</artifactId><version>1.0.0</version>
  <packaging>jar</packaging>
  <name>Revetsec</name><description>Security library</description><url>https://www.revetsec.com</url>
  <licenses><license><name>The Apache License, Version 2.0</name>
    <url>http://www.apache.org/licenses/LICENSE-2.0.txt</url></license></licenses>
  <developers><developer><name>Mark Allen</name><email>mark@revetware.com</email>
    <organization>Revetware LLC</organization><organizationUrl>https://www.revetware.com</organizationUrl>
  </developer></developers>
  <scm><connection>scm:git:git@github.com:revetsec/revetsec.git</connection>
    <developerConnection>scm:git:git@github.com:revetsec/revetsec.git</developerConnection>
    <url>https://github.com/revetsec/revetsec</url><tag>v1.0.0</tag></scm>{dependency}
</project>
""".encode()


def sbom_bytes(components=None):
	purl = "pkg:maven/com.revetsec/revetsec@1.0.0?type=jar"
	document = {
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"version": 1,
		"metadata": {
			"component": {
				"type": "library",
				"group": "com.revetsec",
				"name": "revetsec",
				"version": "1.0.0",
				"purl": purl,
			},
			"properties": [
				{"name": "maven.goal", "value": "makeBom"},
				{"name": "maven.scopes", "value": ""},
				{"name": "cdx:reproducible", "value": "enabled"},
			],
		},
		"dependencies": [{"ref": purl, "dependsOn": []}],
	}
	if components is not None:
		document["components"] = components
	return json.dumps(document, sort_keys=True).encode()


class CentralBundleTests(unittest.TestCase):
	def setUp(self):
		self.temporary = tempfile.TemporaryDirectory()
		self.addCleanup(self.temporary.cleanup)
		self.bundle = Path(self.temporary.name) / "central-bundle.zip"

	def payloads(self):
		prefix = "revetsec-1.0.0"
		return {
			f"{prefix}.pom": pom_bytes(),
			f"{prefix}.jar": jar_bytes({
				"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
				"META-INF/LICENSE": b"license",
				"META-INF/NOTICE": b"notice",
				"com/revetsec/Example.class": b"class",
			}),
			f"{prefix}-sources.jar": jar_bytes({"com/revetsec/Example.java": b"class Example {}"}),
			f"{prefix}-javadoc.jar": jar_bytes({"index.html": b"docs", "element-list": b"com.revetsec\n"}),
			f"{prefix}-cyclonedx.json": sbom_bytes(),
		}

	def write_bundle(self, payloads=None, omit=None, extra=None, corrupt_checksum=None, bundle=None):
		payloads = payloads or self.payloads()
		bundle = bundle or self.bundle
		omit = set(omit or ())
		files = dict(payloads)
		for name in payloads:
			files[f"{name}.asc"] = b"dummy detached signature"
			for algorithm in VERIFIER.CHECKSUMS:
				value = hashlib.new(algorithm, payloads[name]).hexdigest()
				files[f"{name}.{algorithm}"] = value.encode()
		if corrupt_checksum:
			files[corrupt_checksum] = b"0" * VERIFIER.HEX_LENGTHS[corrupt_checksum.rsplit(".", 1)[1]]
		if extra:
			files.update(extra)
		root = "com/revetsec/revetsec/1.0.0/"
		with zipfile.ZipFile(bundle, "w") as archive:
			for name, data in files.items():
				if name not in omit:
					archive.writestr(root + name, data)

	def verify(self):
		return VERIFIER.verify_bundle(self.bundle, EXPECTED, skip_signature_verification=True)

	def assert_rejected(self, message):
		with self.assertRaises(VERIFIER.BundlePolicyError) as raised:
			self.verify()
		self.assertIn(message, str(raised.exception))

	def test_complete_bundle_passes(self):
		self.write_bundle()
		result = self.verify()
		self.assertEqual(result["coordinates"], "com.revetsec:revetsec:1.0.0")
		self.assertEqual(set(result["payloads"]), set(self.payloads()))
		self.assertFalse(result["signaturesVerified"])
		self.assertIsNone(result["signingFingerprint"])

	def test_two_valid_bundles_with_identical_payloads_are_reproducible(self):
		comparison_bundle = Path(self.temporary.name) / "comparison-bundle.zip"
		self.write_bundle()
		self.write_bundle(
			bundle=comparison_bundle,
			extra={"revetsec-1.0.0.jar.asc": b"different detached signature"},
		)
		first = self.verify()
		second = VERIFIER.verify_bundle(
			comparison_bundle, EXPECTED, skip_signature_verification=True
		)
		comparison = VERIFIER.compare_payloads(first, second)
		self.assertNotEqual(first["sha256"], second["sha256"])
		self.assertTrue(comparison["payloadsMatch"])
		self.assertEqual(comparison["bundle"], str(comparison_bundle))

	def test_compare_to_cli_reports_matching_payloads(self):
		comparison_bundle = Path(self.temporary.name) / "comparison-bundle.zip"
		self.write_bundle()
		self.write_bundle(bundle=comparison_bundle)
		output = io.StringIO()
		with contextlib.redirect_stdout(output):
			status = VERIFIER.main([
				str(self.bundle),
				"--compare-to", str(comparison_bundle),
				"--expect", "com.revetsec:revetsec:1.0.0",
				"--skip-signature-verification",
			])
		self.assertEqual(status, 0)
		result = json.loads(output.getvalue())
		self.assertTrue(result["comparison"]["payloadsMatch"])

	def test_compare_to_cli_writes_create_new_reproducibility_receipt(self):
		comparison_bundle = Path(self.temporary.name) / "comparison-bundle.zip"
		receipt_path = Path(self.temporary.name) / "reproducibility.json"
		self.write_bundle()
		self.write_bundle(
			bundle=comparison_bundle,
			extra={"revetsec-1.0.0.jar.asc": b"independent detached signature"},
		)
		with contextlib.redirect_stdout(io.StringIO()):
			status = VERIFIER.main([
				str(self.bundle),
				"--compare-to", str(comparison_bundle),
				"--expect", "com.revetsec:revetsec:1.0.0",
				"--skip-signature-verification",
				"--output", str(receipt_path),
			])
		self.assertEqual(status, 0)
		receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
		self.assertEqual(receipt["schema"], "revetsec.central-bundle-reproducibility.v1")
		self.assertEqual(receipt["coordinates"], "com.revetsec:revetsec:1.0.0")
		self.assertEqual(receipt["firstBundle"]["sha256"], self.verify()["sha256"])
		self.assertTrue(receipt["payloadsMatch"])
		self.assertFalse(receipt["firstBundle"]["signaturesVerified"])
		with self.assertRaises(VERIFIER.BundlePolicyError):
			VERIFIER.write_receipt(receipt_path, receipt)

	def test_payload_difference_fails_reproducibility_comparison(self):
		comparison_bundle = Path(self.temporary.name) / "comparison-bundle.zip"
		self.write_bundle()
		changed = self.payloads()
		changed["revetsec-1.0.0.jar"] = jar_bytes({
			"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
			"META-INF/LICENSE": b"license",
			"META-INF/NOTICE": b"notice",
			"com/revetsec/Example.class": b"changed class",
		})
		self.write_bundle(payloads=changed, bundle=comparison_bundle)
		first = self.verify()
		second = VERIFIER.verify_bundle(
			comparison_bundle, EXPECTED, skip_signature_verification=True
		)
		with self.assertRaises(VERIFIER.BundlePolicyError) as raised:
			VERIFIER.compare_payloads(first, second)
		self.assertIn("revetsec-1.0.0.jar", str(raised.exception))

	def test_signature_verification_is_required_by_default(self):
		self.write_bundle()
		with self.assertRaises(VERIFIER.BundlePolicyError) as raised:
			VERIFIER.verify_bundle(self.bundle, EXPECTED)
		self.assertIn("requires --keyring", str(raised.exception))

	def test_signature_verification_requires_expected_fingerprint(self):
		self.write_bundle()
		with self.assertRaises(VERIFIER.BundlePolicyError) as raised:
			VERIFIER.verify_bundle(self.bundle, EXPECTED, keyring=Path("release-keyring.gpg"))
		self.assertIn("requires --expect-fingerprint", str(raised.exception))

	def test_gpgv_status_binds_signing_subkey_to_expected_primary_key(self):
		signing = "B" * 40
		primary = "A" * 40
		keyring = Path(self.temporary.name) / "release-keyring.gpg"
		keyring.write_bytes(b"test keyring")
		status = (
			f"[GNUPG:] VALIDSIG {signing} 2026-11-13 1794528000 0 4 0 1 10 00 "
			f"{primary}\n"
		)
		completed = mock.Mock(returncode=0, stdout=status, stderr="")
		with mock.patch.object(VERIFIER.subprocess, "run", return_value=completed):
			self.assertEqual(
				VERIFIER.verify_signatures(
					Path(self.temporary.name), ["revetsec-1.0.0.jar"],
					keyring, primary,
				),
				primary,
			)
		with mock.patch.object(VERIFIER.subprocess, "run", return_value=completed):
			with self.assertRaises(VERIFIER.BundlePolicyError) as raised:
				VERIFIER.verify_signatures(
					Path(self.temporary.name), ["revetsec-1.0.0.jar"],
					keyring, "C" * 40,
				)
		self.assertIn("expected", str(raised.exception))

	def test_gpgv_status_requires_exactly_one_valid_signature(self):
		with self.assertRaises(VERIFIER.BundlePolicyError) as raised:
			VERIFIER.parse_valid_signature("[GNUPG:] GOODSIG test\n", "revetsec-1.0.0.jar")
		self.assertIn("exactly one valid signature", str(raised.exception))

	def test_missing_signature_is_rejected(self):
		self.write_bundle(omit={"revetsec-1.0.0.jar.asc"})
		self.assert_rejected("missing required files")

	def test_missing_checksum_is_rejected(self):
		self.write_bundle(omit={"revetsec-1.0.0.pom.sha512"})
		self.assert_rejected("missing required files")

	def test_bad_checksum_is_rejected(self):
		self.write_bundle(corrupt_checksum="revetsec-1.0.0-sources.jar.sha256")
		self.assert_rejected("incorrect sha256 checksum")

	def test_unexpected_file_is_rejected(self):
		self.write_bundle(extra={"notes.txt": b"not published"})
		self.assert_rejected("unexpected files")

	def test_unsafe_path_is_rejected(self):
		self.write_bundle()
		with zipfile.ZipFile(self.bundle, "a") as archive:
			archive.writestr("../outside", b"bad")
		self.assert_rejected("unsafe path")

	def test_compile_dependency_in_pom_is_rejected(self):
		payloads = self.payloads()
		payloads["revetsec-1.0.0.pom"] = pom_bytes(
			"<dependencies><dependency><groupId>example</groupId><artifactId>bad</artifactId>"
			"<version>1</version></dependency></dependencies>"
		)
		self.write_bundle(payloads=payloads)
		self.assert_rejected("scope 'compile'")

	def test_dependency_component_in_sbom_is_rejected(self):
		payloads = self.payloads()
		payloads["revetsec-1.0.0-cyclonedx.json"] = sbom_bytes([
			{"type": "library", "name": "unexpected", "version": "1"}
		])
		self.write_bundle(payloads=payloads)
		self.assert_rejected("no dependency components")

	def test_missing_main_jar_notice_is_rejected(self):
		payloads = self.payloads()
		payloads["revetsec-1.0.0.jar"] = jar_bytes({
			"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
			"META-INF/LICENSE": b"license",
			"com/revetsec/Example.class": b"class",
		})
		self.write_bundle(payloads=payloads)
		self.assert_rejected("missing META-INF/NOTICE")

	def test_snapshot_coordinates_are_rejected(self):
		self.write_bundle()
		with self.assertRaises(VERIFIER.BundlePolicyError) as raised:
			VERIFIER.verify_bundle(
				self.bundle,
				("com.revetsec", "revetsec", "1.0.0-SNAPSHOT"),
				skip_signature_verification=True,
			)
		self.assertIn("cannot contain a SNAPSHOT", str(raised.exception))

	def test_unsafe_coordinate_characters_are_rejected(self):
		for coordinates in (
			"com.revetsec:../revetsec:1.0.0",
			"com.revetsec:revetsec:1.0.0/other",
			"com.revetsec:revetsec:https://example.com",
		):
			with self.subTest(coordinates=coordinates):
				with self.assertRaises(VERIFIER.argparse.ArgumentTypeError):
					VERIFIER.parse_coordinates(coordinates)


if __name__ == "__main__":
	unittest.main()
