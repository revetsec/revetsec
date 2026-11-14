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

"""Policy tests for verify-release-attestations.py."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile


DIRECTORY = Path(__file__).resolve().parent
SCRIPT = DIRECTORY / "verify-release-attestations.py"
SPEC = importlib.util.spec_from_file_location("verify_release_attestations", SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)
FIXTURES_PATH = DIRECTORY / "test_verify_central_bundle.py"
FIXTURES_SPEC = importlib.util.spec_from_file_location("central_bundle_fixtures", FIXTURES_PATH)
FIXTURES = importlib.util.module_from_spec(FIXTURES_SPEC)
FIXTURES_SPEC.loader.exec_module(FIXTURES)
EXPECTED = ("com.revetsec", "revetsec", "1.0.0")
COMMIT = "a" * 40


class ReleaseAttestationTests(unittest.TestCase):
	def setUp(self):
		self.temporary = tempfile.TemporaryDirectory()
		self.addCleanup(self.temporary.cleanup)
		self.root = Path(self.temporary.name)
		self.bundle = self.root / "central-bundle.zip"
		self.hosted = self.root / "hosted.json"
		prefix = "revetsec-1.0.0"
		self.payloads = {
			f"{prefix}.pom": FIXTURES.pom_bytes(),
			f"{prefix}.jar": FIXTURES.jar_bytes({
				"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
				"META-INF/LICENSE": b"license",
				"META-INF/NOTICE": b"notice",
				"com/revetsec/Example.class": b"class",
			}),
			f"{prefix}-sources.jar": FIXTURES.jar_bytes({
				"com/revetsec/Example.java": b"class Example {}"
			}),
			f"{prefix}-javadoc.jar": FIXTURES.jar_bytes({
				"index.html": b"docs", "element-list": b"com.revetsec\n"
			}),
			f"{prefix}-cyclonedx.json": FIXTURES.sbom_bytes(),
		}
		self.write_bundle()
		bundle_result = VERIFIER.BUNDLE_VERIFIER.verify_bundle(
			self.bundle, EXPECTED, skip_signature_verification=True
		)
		self.hosted_document = {
			"schema": "revetsec.release-evidence-join.v1",
			"verifiedAt": "2026-11-13T22:00:00Z",
			"coordinates": "com.revetsec:revetsec:1.0.0",
			"evidence": "/download/release-evidence.zip",
			"approvedBundle": {
				"path": str(self.bundle), "sha256": bundle_result["sha256"],
			},
			"payloads": bundle_result["payloads"],
			"run": {
				"id": 123, "attempt": 1,
				"url": "https://github.com/revetsec/revetsec/actions/runs/123",
			},
			"source": {"ref": "refs/tags/v1.0.0", "sha": COMMIT},
			"attestations": {
				"provenance": {
					"id": 1, "url": "https://github.com/revetsec/revetsec/attestations/1",
				},
				"sbom": {
					"id": 2, "url": "https://github.com/revetsec/revetsec/attestations/2",
				},
			},
			"signaturesVerified": True,
			"signingFingerprint": None,
			"exactBundleContent": True,
		}
		self.write_hosted()
		self.commands = []
		self.empty_timestamps = False
		self.wrong_sbom = False

	def write_bundle(self):
		files = dict(self.payloads)
		for name, data in self.payloads.items():
			files[f"{name}.asc"] = f"signature for {name}".encode()
			for algorithm in VERIFIER.BUNDLE_VERIFIER.CHECKSUMS:
				files[f"{name}.{algorithm}"] = hashlib.new(algorithm, data).hexdigest().encode()
		with zipfile.ZipFile(self.bundle, "w") as archive:
			for name, data in files.items():
				archive.writestr(f"com/revetsec/revetsec/1.0.0/{name}", data)

	def write_hosted(self):
		self.hosted.write_text(
			json.dumps(self.hosted_document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
		)

	def runner(self, arguments, timeout):
		self.commands.append(arguments)
		self.assertEqual(timeout, 9)
		if arguments[1:] == ["--version"]:
			return "gh version 2.102.0 (test)\n"
		path = Path(arguments[3])
		predicate_type = arguments[arguments.index("--predicate-type") + 1]
		statement = {
			"predicateType": predicate_type,
			"subject": [{
				"name": path.name,
				"digest": {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()},
			}],
			"predicate": {},
		}
		if predicate_type == VERIFIER.CYCLONEDX_PREDICATE:
			statement["predicate"] = (
				{"bomFormat": "wrong"}
				if self.wrong_sbom
				else json.loads(self.payloads["revetsec-1.0.0-cyclonedx.json"])
			)
		return json.dumps([{
			"attestation": {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"},
			"verificationResult": {
				"statement": statement,
				"signature": {"certificate": {}},
				"verifiedTimestamps": [] if self.empty_timestamps else [{"type": "tlog"}],
			},
		}])

	def verify(self):
		return VERIFIER.verify_attestations(
			self.bundle,
			self.hosted,
			EXPECTED,
			COMMIT,
			gh="/test/gh",
			timeout_seconds=9,
			skip_signature_verification=True,
			command_runner=self.runner,
		)

	def test_all_payload_provenance_and_exact_sbom_pass(self):
		result = self.verify()
		self.assertEqual(result["schema"], VERIFIER.SCHEMA)
		self.assertEqual(result["result"], "PASS")
		self.assertEqual(set(result["provenance"]["subjects"]), set(self.payloads))
		self.assertTrue(result["sbom"]["predicateMatchesSbom"])
		self.assertFalse(result["approvedBundle"]["signaturesVerified"])
		self.assertIsNone(result["approvedBundle"]["signingFingerprint"])
		self.assertEqual(len(self.commands), 7)
		for command in self.commands[1:]:
			self.assertIn("--deny-self-hosted-runners", command)
			self.assertIn("revetsec/revetsec/.github/workflows/release-evidence.yml", command)
			self.assertIn(COMMIT, command)

	def test_verified_timestamp_is_required(self):
		self.empty_timestamps = True
		with self.assertRaises(VERIFIER.AttestationPolicyError) as raised:
			self.verify()
		self.assertIn("no timestamped", str(raised.exception))

	def test_vulnerable_github_cli_is_rejected(self):
		def old_runner(arguments, timeout):
			if arguments[1:] == ["--version"]:
				return "gh version 2.101.0 (test)\n"
			return self.runner(arguments, timeout)
		with self.assertRaises(VERIFIER.AttestationPolicyError) as raised:
			VERIFIER.verify_attestations(
				self.bundle,
				self.hosted,
				EXPECTED,
				COMMIT,
				gh="/test/gh",
				timeout_seconds=9,
				skip_signature_verification=True,
				command_runner=old_runner,
			)
		self.assertIn("2.102.0 or newer", str(raised.exception))

	def test_cyclonedx_predicate_must_equal_release_sbom(self):
		self.wrong_sbom = True
		with self.assertRaises(VERIFIER.AttestationPolicyError) as raised:
			self.verify()
		self.assertIn("differs from the exact release SBOM", str(raised.exception))

	def test_hosted_evidence_bundle_identity_is_enforced(self):
		self.hosted_document["approvedBundle"]["sha256"] = "9" * 64
		self.write_hosted()
		with self.assertRaises(VERIFIER.AttestationPolicyError) as raised:
			self.verify()
		self.assertIn("different approved bundle", str(raised.exception))

	def test_hosted_evidence_source_identity_is_enforced(self):
		self.hosted_document["source"]["sha"] = "9" * 40
		self.write_hosted()
		with self.assertRaises(VERIFIER.AttestationPolicyError) as raised:
			self.verify()
		self.assertIn("source differs", str(raised.exception))

	def test_receipt_write_is_create_new(self):
		result = self.verify()
		path = self.root / "attestations.json"
		VERIFIER.write_receipt(path, result)
		self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["result"], "PASS")
		with self.assertRaises(VERIFIER.AttestationPolicyError):
			VERIFIER.write_receipt(path, result)


if __name__ == "__main__":
	unittest.main()
