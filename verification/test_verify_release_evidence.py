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

"""Seeded-failure tests for verify-release-evidence.py."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile


DIRECTORY = Path(__file__).resolve().parent
SCRIPT = DIRECTORY / "verify-release-evidence.py"
SPEC = importlib.util.spec_from_file_location("verify_release_evidence", SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)

FIXTURES_PATH = DIRECTORY / "test_verify_central_bundle.py"
FIXTURES_SPEC = importlib.util.spec_from_file_location("central_bundle_fixtures", FIXTURES_PATH)
FIXTURES = importlib.util.module_from_spec(FIXTURES_SPEC)
FIXTURES_SPEC.loader.exec_module(FIXTURES)
EXPECTED = ("com.revetsec", "revetsec", "1.0.0")
COMMIT = "a" * 40


class ReleaseEvidenceTests(unittest.TestCase):
	def setUp(self):
		self.temporary = tempfile.TemporaryDirectory()
		self.addCleanup(self.temporary.cleanup)
		self.root = Path(self.temporary.name)
		self.evidence = self.root / "release-evidence"
		self.evidence.mkdir()
		self.bundle = self.root / "central-bundle.zip"
		prefix = "revetsec-1.0.0"
		self.payloads = {
			f"{prefix}.pom": FIXTURES.pom_bytes(),
			f"{prefix}.jar": FIXTURES.jar_bytes({
				"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
				"META-INF/LICENSE": b"license",
				"META-INF/NOTICE": b"notice",
				"com/revetsec/Example.class": b"class",
			}),
			f"{prefix}-sources.jar": FIXTURES.jar_bytes({"com/revetsec/Example.java": b"class Example {}"}),
			f"{prefix}-javadoc.jar": FIXTURES.jar_bytes({"index.html": b"docs", "element-list": b"com.revetsec\n"}),
			f"{prefix}-cyclonedx.json": FIXTURES.sbom_bytes(),
		}
		self.write_evidence()
		self.write_bundle()

	def manifest(self):
		return "".join(
			f"{hashlib.sha256(data).hexdigest()}  release-evidence/{name}\n"
			for name, data in self.payloads.items()
		).encode("ascii")

	def write_evidence(self):
		for name, data in self.payloads.items():
			(self.evidence / name).write_bytes(data)
		(self.evidence / "SHA256SUMS").write_bytes(self.manifest())
		attestations = {
			"schema": "revetsec.release-attestations.v1",
			"repository": "revetsec/revetsec",
			"run": {
				"id": 123,
				"attempt": 1,
				"url": "https://github.com/revetsec/revetsec/actions/runs/123",
			},
			"source": {"ref": "refs/tags/v1.0.0", "sha": COMMIT},
			"attestations": {
				"provenance": {
					"id": 1,
					"url": "https://github.com/revetsec/revetsec/attestations/1",
				},
				"sbom": {
					"id": 2,
					"url": "https://github.com/revetsec/revetsec/attestations/2",
				},
			},
		}
		(self.evidence / "ATTESTATIONS.json").write_text(
			json.dumps(attestations, indent=2, sort_keys=True) + "\n", encoding="utf-8"
		)

	def write_bundle(self, payloads=None):
		payloads = self.payloads if payloads is None else payloads
		files = dict(payloads)
		for name, data in payloads.items():
			files[f"{name}.asc"] = f"signature for {name}".encode()
			for algorithm in VERIFIER.BUNDLE_VERIFIER.CHECKSUMS:
				files[f"{name}.{algorithm}"] = hashlib.new(algorithm, data).hexdigest().encode()
		root = "com/revetsec/revetsec/1.0.0/"
		with zipfile.ZipFile(self.bundle, "w") as archive:
			for name, data in files.items():
				archive.writestr(root + name, data)

	def verify(self, evidence=None):
		return VERIFIER.verify_evidence(
			evidence or self.evidence,
			self.bundle,
			EXPECTED,
			COMMIT,
			skip_signature_verification=True,
		)

	def test_exact_hosted_evidence_matches_signed_bundle(self):
		result = self.verify()
		self.assertEqual(result["coordinates"], "com.revetsec:revetsec:1.0.0")
		self.assertTrue(result["exactBundleContent"])
		self.assertFalse(result["signaturesVerified"])
		self.assertIsNone(result["signingFingerprint"])
		self.assertEqual(len(result["payloads"]), 5)
		self.assertEqual(result["source"]["sha"], COMMIT)
		self.assertEqual(result["attestations"]["sbom"]["id"], 2)

	def test_changed_evidence_with_updated_manifest_is_rejected(self):
		name = "revetsec-1.0.0.jar"
		self.payloads[name] = FIXTURES.jar_bytes({
			"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
			"META-INF/LICENSE": b"license",
			"META-INF/NOTICE": b"notice",
			"com/revetsec/Changed.class": b"changed",
		})
		self.write_evidence()
		with self.assertRaises(VERIFIER.EvidencePolicyError) as raised:
			self.verify()
		self.assertIn("differs from the approved signed bundle", str(raised.exception))

	def test_incorrect_hosted_checksum_is_rejected(self):
		manifest = (self.evidence / "SHA256SUMS").read_text(encoding="ascii")
		(self.evidence / "SHA256SUMS").write_text("0" * 64 + manifest[64:], encoding="ascii")
		with self.assertRaises(VERIFIER.EvidencePolicyError) as raised:
			self.verify()
		self.assertIn("incorrect hosted SHA-256", str(raised.exception))

	def test_extra_file_is_rejected(self):
		(self.evidence / "unattested.txt").write_text("extra", encoding="utf-8")
		with self.assertRaises(VERIFIER.EvidencePolicyError) as raised:
			self.verify()
		self.assertIn("unexpected=['unattested.txt']", str(raised.exception))

	def test_missing_file_is_rejected(self):
		(self.evidence / "revetsec-1.0.0-sources.jar").unlink()
		with self.assertRaises(VERIFIER.EvidencePolicyError) as raised:
			self.verify()
		self.assertIn("missing=['revetsec-1.0.0-sources.jar']", str(raised.exception))

	def test_attestation_manifest_wrong_source_commit_is_rejected(self):
		path = self.evidence / "ATTESTATIONS.json"
		document = json.loads(path.read_text(encoding="utf-8"))
		document["source"]["sha"] = "9" * 40
		path.write_text(json.dumps(document) + "\n", encoding="utf-8")
		with self.assertRaises(VERIFIER.EvidencePolicyError) as raised:
			self.verify()
		self.assertIn("source differs", str(raised.exception))

	def test_attestation_manifest_wrong_url_is_rejected(self):
		path = self.evidence / "ATTESTATIONS.json"
		document = json.loads(path.read_text(encoding="utf-8"))
		document["attestations"]["sbom"]["url"] = (
			"https://github.com/revetsec/other/attestations/2"
		)
		path.write_text(json.dumps(document) + "\n", encoding="utf-8")
		with self.assertRaises(VERIFIER.EvidencePolicyError) as raised:
			self.verify()
		self.assertIn("sbom URL differs", str(raised.exception))

	def test_prefixed_zip_is_accepted(self):
		archive = self.root / "evidence.zip"
		with zipfile.ZipFile(archive, "w") as output:
			for path in self.evidence.iterdir():
				output.write(path, f"release-evidence/{path.name}")
		self.assertTrue(self.verify(archive)["exactBundleContent"])

	def test_unsafe_zip_member_is_rejected(self):
		archive = self.root / "unsafe.zip"
		with zipfile.ZipFile(archive, "w") as output:
			output.writestr("../escape", b"unsafe")
		with self.assertRaises(VERIFIER.EvidencePolicyError) as raised:
			self.verify(archive)
		self.assertIn("unsafe path", str(raised.exception))

	def test_join_receipt_is_create_new(self):
		result = self.verify()
		receipt = self.root / "join.json"
		VERIFIER.write_receipt(receipt, result)
		self.assertIn("revetsec.release-evidence-join.v1", receipt.read_text(encoding="utf-8"))
		with self.assertRaises(VERIFIER.EvidencePolicyError) as raised:
			VERIFIER.write_receipt(receipt, result)
		self.assertIn("already exists", str(raised.exception))


if __name__ == "__main__":
	unittest.main()
