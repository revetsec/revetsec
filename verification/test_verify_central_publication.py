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

"""Local HTTP tests for verify-central-publication.py."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import urllib.parse
import zipfile


DIRECTORY = Path(__file__).resolve().parent
SCRIPT = DIRECTORY / "verify-central-publication.py"
SPEC = importlib.util.spec_from_file_location("verify_central_publication", SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)

FIXTURES_PATH = DIRECTORY / "test_verify_central_bundle.py"
FIXTURES_SPEC = importlib.util.spec_from_file_location("central_bundle_fixtures", FIXTURES_PATH)
FIXTURES = importlib.util.module_from_spec(FIXTURES_SPEC)
FIXTURES_SPEC.loader.exec_module(FIXTURES)
EXPECTED = ("com.revetsec", "revetsec", "1.0.0")


class CentralPublicationTests(unittest.TestCase):
	def setUp(self):
		self.temporary = tempfile.TemporaryDirectory()
		self.addCleanup(self.temporary.cleanup)
		self.root = Path(self.temporary.name)
		self.bundle = self.root / "central-bundle.zip"
		self.remote = self.root / "repository" / "maven2" / "com" / "revetsec" / "revetsec" / "1.0.0"
		self.remote.mkdir(parents=True)
		self.payloads = self.make_payloads()
		self.write_bundle()
		self.write_publication()
		self.repository = "http://127.0.0.1/maven2"

	def make_payloads(self):
		prefix = "revetsec-1.0.0"
		return {
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

	def write_bundle(self):
		files = dict(self.payloads)
		for name, data in self.payloads.items():
			files[f"{name}.asc"] = f"signature for {name}".encode()
			for algorithm in VERIFIER.BUNDLE_VERIFIER.CHECKSUMS:
				files[f"{name}.{algorithm}"] = hashlib.new(algorithm, data).hexdigest().encode()
		root = "com/revetsec/revetsec/1.0.0/"
		with zipfile.ZipFile(self.bundle, "w") as archive:
			for name, data in files.items():
				archive.writestr(root + name, data)

	def write_publication(self):
		for name, data in self.payloads.items():
			(self.remote / name).write_bytes(data)
			(self.remote / f"{name}.asc").write_bytes(f"signature for {name}".encode())

	def verify(self):
		return VERIFIER.verify_publication(
			self.bundle,
			EXPECTED,
			repository=self.repository,
			skip_signature_verification=True,
			allow_loopback_http=True,
			fetcher=self.fetch,
		)

	def fetch(self, url, maximum_bytes, timeout_seconds):
		self.assertGreaterEqual(timeout_seconds, 1)
		name = Path(urllib.parse.urlsplit(url).path).name
		path = self.remote / name
		if not path.is_file():
			raise VERIFIER.PublicationPolicyError(f"cannot download {url}: not found")
		data = path.read_bytes()
		if len(data) > maximum_bytes:
			raise VERIFIER.PublicationPolicyError(f"repository file exceeds the size limit: {url}")
		return data

	def test_exact_publication_passes(self):
		result = self.verify()
		self.assertEqual(result["coordinates"], "com.revetsec:revetsec:1.0.0")
		self.assertTrue(result["exactBundleContent"])
		self.assertFalse(result["signaturesVerified"])
		self.assertIsNone(result["signingFingerprint"])
		self.assertEqual(len(result["files"]), 10)

	def test_changed_payload_is_rejected(self):
		(self.remote / "revetsec-1.0.0.jar").write_bytes(b"changed")
		with self.assertRaises(VERIFIER.PublicationPolicyError) as raised:
			self.verify()
		self.assertIn("payload differs", str(raised.exception))

	def test_changed_signature_is_rejected(self):
		(self.remote / "revetsec-1.0.0.jar.asc").write_bytes(b"changed")
		with self.assertRaises(VERIFIER.PublicationPolicyError) as raised:
			self.verify()
		self.assertIn("signature differs", str(raised.exception))

	def test_missing_file_is_rejected(self):
		(self.remote / "revetsec-1.0.0-sources.jar").unlink()
		with self.assertRaises(VERIFIER.PublicationPolicyError) as raised:
			self.verify()
		self.assertIn("cannot download", str(raised.exception))

	def test_noncanonical_live_repository_is_rejected(self):
		with self.assertRaises(VERIFIER.PublicationPolicyError) as raised:
			VERIFIER.validate_repository("https://example.com/maven2")
		self.assertIn("canonical Maven Central", str(raised.exception))

	def test_canonical_host_with_wrong_port_is_rejected(self):
		with self.assertRaises(VERIFIER.PublicationPolicyError):
			VERIFIER.validate_repository("https://repo.maven.apache.org:444/maven2")

	def test_canonical_host_with_wrong_path_is_rejected(self):
		with self.assertRaises(VERIFIER.PublicationPolicyError):
			VERIFIER.validate_repository("https://repo.maven.apache.org/not-central")

	def test_both_canonical_repository_bases_are_accepted(self):
		for repository in VERIFIER.CANONICAL_REPOSITORIES:
			with self.subTest(repository=repository):
				self.assertEqual(VERIFIER.validate_repository(repository + "/"), repository)

	def test_insecure_nonloopback_test_repository_is_rejected(self):
		with self.assertRaises(VERIFIER.PublicationPolicyError) as raised:
			VERIFIER.validate_repository("http://example.com/maven2", allow_loopback_http=True)
		self.assertIn("loopback HTTP", str(raised.exception))

	def test_receipt_is_create_new(self):
		result = self.verify()
		receipt = self.root / "receipt.json"
		VERIFIER.write_receipt(receipt, result)
		self.assertEqual(json.loads(receipt.read_text())["exactBundleContent"], True)
		with self.assertRaises(VERIFIER.PublicationPolicyError) as raised:
			VERIFIER.write_receipt(receipt, result)
		self.assertIn("already exists", str(raised.exception))


if __name__ == "__main__":
	unittest.main()
