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

"""Seeded-violation tests for verify-release-signing-key.py."""

from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parent / "verify-release-signing-key.py"
SPEC = importlib.util.spec_from_file_location("verify_release_signing_key", SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)
PRIMARY = "A" * 40
SUBKEY = "B" * 40
NOW = datetime(2026, 11, 13, 22, 0, tzinfo=timezone.utc)


def key_listing(primary=PRIMARY, primary_validity="-", primary_expires="1893456000"):
	return "\n".join((
		f"pub:{primary_validity}:3072:1:AAAAAAAAAAAAAAAA:1700000000:{primary_expires}:::::c::::::23::0:",
		f"fpr:::::::::{primary}:",
		"uid:-::::1700000000::HASH::Revetsec Release <release@revetsec.com>::::::::::0:",
		"sub:-:3072:1:BBBBBBBBBBBBBBBB:1700000000:1893456000:::::s::::::23:",
		f"fpr:::::::::{SUBKEY}:",
	)) + "\n"


class SigningKeyTests(unittest.TestCase):
	def fetcher(self, url, maximum_bytes, timeout_seconds):
		self.assertEqual(url, VERIFIER.CANONICAL_KEY_URL)
		self.assertEqual(maximum_bytes, VERIFIER.MAX_KEY_BYTES)
		self.assertEqual(timeout_seconds, 9)
		return b"-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n"

	def runner(self, arguments, timeout_seconds):
		self.assertEqual(timeout_seconds, 9)
		if arguments[1:] == ["--version"]:
			return "gpg (GnuPG) 2.5.21\n"
		self.assertIn("show-only", arguments)
		return key_listing()

	def verify(self, **changes):
		arguments = {
			"url": VERIFIER.CANONICAL_KEY_URL,
			"expected_fingerprint": PRIMARY,
			"gpg": "/test/gpg",
			"timeout_seconds": 9,
			"fetcher": self.fetcher,
			"command_runner": self.runner,
			"now": NOW,
		}
		arguments.update(changes)
		return VERIFIER.verify_signing_key(**arguments)

	def test_canonical_published_key_passes(self):
		result = self.verify()
		self.assertEqual(result["schema"], VERIFIER.SCHEMA)
		self.assertEqual(result["primaryKey"]["fingerprint"], PRIMARY)
		self.assertEqual(result["signingKeys"][0]["fingerprint"], SUBKEY)
		self.assertEqual(result["publicKey"]["sizeBytes"], 42)
		self.assertEqual(result["result"], "PASS")

	def test_noncanonical_key_url_is_rejected_before_fetch(self):
		with self.assertRaises(VERIFIER.SigningKeyPolicyError) as raised:
			self.verify(url="https://www.revetsec.com/security/release-key.asc")
		self.assertIn("must be", str(raised.exception))

	def test_wrong_primary_fingerprint_is_rejected(self):
		with self.assertRaises(VERIFIER.SigningKeyPolicyError) as raised:
			self.verify(expected_fingerprint="C" * 40)
		self.assertIn("published primary fingerprint", str(raised.exception))

	def test_expired_primary_key_is_rejected(self):
		def expired_runner(arguments, timeout_seconds):
			if arguments[1:] == ["--version"]:
				return "gpg (GnuPG) 2.5.21\n"
			return key_listing(primary_validity="e", primary_expires="1700000001")
		with self.assertRaises(VERIFIER.SigningKeyPolicyError) as raised:
			self.verify(command_runner=expired_runner)
		self.assertIn("primary key is disabled, expired or revoked", str(raised.exception))

	def test_listing_without_usable_signing_key_is_rejected(self):
		def encryption_runner(arguments, timeout_seconds):
			if arguments[1:] == ["--version"]:
				return "gpg (GnuPG) 2.5.21\n"
			return key_listing().replace(":::::s::::::23:", ":::::e::::::23:")
		with self.assertRaises(VERIFIER.SigningKeyPolicyError) as raised:
			self.verify(command_runner=encryption_runner)
		self.assertIn("no usable signing key", str(raised.exception))

	def test_receipt_is_create_new(self):
		with tempfile.TemporaryDirectory() as temporary:
			path = Path(temporary) / "signing-key.json"
			result = self.verify()
			VERIFIER.write_receipt(path, result)
			self.assertEqual(json.loads(path.read_text())["result"], "PASS")
			with self.assertRaises(VERIFIER.SigningKeyPolicyError):
				VERIFIER.write_receipt(path, result)


if __name__ == "__main__":
	unittest.main()
