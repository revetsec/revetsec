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

"""Seeded-violation tests for verify-release-record-seal.py."""

from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


DIRECTORY = Path(__file__).resolve().parent
SCRIPT = DIRECTORY / "verify-release-record-seal.py"
SPEC = importlib.util.spec_from_file_location("verify_release_record_seal", SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)
FIXTURE_PATH = DIRECTORY / "test_verify_release_record.py"
FIXTURE_SPEC = importlib.util.spec_from_file_location("release_record_fixtures", FIXTURE_PATH)
FIXTURES = importlib.util.module_from_spec(FIXTURE_SPEC)
FIXTURE_SPEC.loader.exec_module(FIXTURES)
PRIMARY = "A" * 40
SIGNING = "B" * 40
SIGNED_AT = datetime(2026, 11, 13, 23, 5, tzinfo=timezone.utc)
VERIFIED_AT = datetime(2026, 11, 13, 23, 6, tzinfo=timezone.utc)


class ReleaseRecordSealTests(unittest.TestCase):
	def fixture(self, root):
		record = FIXTURES.ReleaseRecordTests().complete_record()
		FIXTURES.ReleaseRecordTests().materialize_evidence(root, record)
		record_path = Path(root) / "RELEASE_RECORD.json"
		record_path.write_text(
			json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
		)
		signature_path = Path(root) / "RELEASE_RECORD.json.asc"
		signature_path.write_bytes(b"test detached signature")
		return record, record_path, signature_path

	def details(self, **changes):
		result = {
			"signingFingerprint": SIGNING,
			"primaryFingerprint": PRIMARY,
			"signedAt": SIGNED_AT,
		}
		result.update(changes)
		return result

	def verify(self, root, record_path, signature_path, details=None):
		return VERIFIER.verify_seal(
			record_path,
			signature_path,
			root,
			Path(root) / "unused-test-keyring.gpg",
			signature_checker=lambda: details or self.details(),
			now=VERIFIED_AT,
		)

	def test_complete_signed_record_passes(self):
		with tempfile.TemporaryDirectory() as temporary:
			record, record_path, signature_path = self.fixture(temporary)
			result = self.verify(temporary, record_path, signature_path)
			self.assertEqual(result["schema"], VERIFIER.SCHEMA)
			self.assertEqual(result["version"], record["version"])
			self.assertEqual(result["record"]["sha256"], hashlib.sha256(
				record_path.read_bytes()
			).hexdigest())
			self.assertEqual(result["signature"]["primaryFingerprint"], PRIMARY)
			self.assertTrue(result["evidenceGraphVerified"])

	def test_signature_must_use_recorded_primary_key(self):
		with tempfile.TemporaryDirectory() as temporary:
			_record, record_path, signature_path = self.fixture(temporary)
			with self.assertRaises(VERIFIER.RecordSealPolicyError) as raised:
				self.verify(
					temporary, record_path, signature_path,
					details=self.details(primaryFingerprint="C" * 40),
				)
			self.assertIn("recorded primary fingerprint", str(raised.exception))

	def test_signature_must_follow_recorded_release_time(self):
		with tempfile.TemporaryDirectory() as temporary:
			_record, record_path, signature_path = self.fixture(temporary)
			with self.assertRaises(VERIFIER.RecordSealPolicyError) as raised:
				self.verify(
					temporary, record_path, signature_path,
					details=self.details(
						signedAt=datetime(2026, 11, 13, 22, 59, tzinfo=timezone.utc)
					),
				)
			self.assertIn("signed before", str(raised.exception))

	def test_invalid_transitive_evidence_is_rejected_before_sealing(self):
		with tempfile.TemporaryDirectory() as temporary:
			record, record_path, signature_path = self.fixture(temporary)
			claims = Path(temporary) / record["claimsAudit"]["path"]
			claims.write_text("tampered\n", encoding="utf-8")
			with self.assertRaises(VERIFIER.RecordSealPolicyError) as raised:
				self.verify(temporary, record_path, signature_path)
			self.assertIn("did not pass final verification", str(raised.exception))

	def test_gpgv_status_records_subkey_primary_and_time(self):
		status = (
			f"[GNUPG:] VALIDSIG {SIGNING} 2026-11-13 {int(SIGNED_AT.timestamp())} "
			f"0 4 0 1 10 00 {PRIMARY}\n"
		)
		details = VERIFIER.parse_gpgv_status(status)
		self.assertEqual(details["signingFingerprint"], SIGNING)
		self.assertEqual(details["primaryFingerprint"], PRIMARY)
		self.assertEqual(details["signedAt"], SIGNED_AT)

	def test_seal_receipt_is_create_new(self):
		with tempfile.TemporaryDirectory() as temporary:
			_record, record_path, signature_path = self.fixture(temporary)
			result = self.verify(temporary, record_path, signature_path)
			output = Path(temporary) / "release-record-seal.json"
			VERIFIER.write_receipt(output, result)
			self.assertEqual(json.loads(output.read_text())["result"], "PASS")
			with self.assertRaises(VERIFIER.RecordSealPolicyError):
				VERIFIER.write_receipt(output, result)


if __name__ == "__main__":
	unittest.main()
