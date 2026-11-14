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

"""Policy tests for verify-release-documentation.py."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile


DIRECTORY = Path(__file__).resolve().parent
SCRIPT = DIRECTORY / "verify-release-documentation.py"
SPEC = importlib.util.spec_from_file_location("verify_release_documentation", SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)
VERSION = "1.0.0"
COMMIT = "a" * 40


class ReleaseDocumentationTests(unittest.TestCase):
	def fixture(self, root):
		root = Path(root)
		claims = root / "SECURITY_CLAIMS_AUDIT.md"
		claims.write_text("# Accepted security claims\n", encoding="utf-8")
		site = root / "dist"
		(site / "docs").mkdir(parents=True)
		(site / "_next" / "static").mkdir(parents=True)
		(site / "index.html").write_bytes(b"<html>Revetsec 1.0.0</html>\n")
		(site / "docs" / "getting-started.html").write_bytes(
			b"<html>Install Revetsec 1.0.0</html>\n"
		)
		(site / "docs" / "security.html").write_bytes(b"<html>Security</html>\n")
		(site / "404.html").write_bytes(b"<html>Not found</html>\n")
		(site / "_next" / "static" / "app.js").write_bytes(b"release();\n")

		mapping = {
			VERIFIER.website_url(path.relative_to(site).as_posix()): path.read_bytes()
			for path in site.rglob("*") if path.is_file()
		}
		receipts = []
		for artifact_id, specification in VERIFIER.COMPONENTS.items():
			buffer = io.BytesIO()
			with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
				archive.writestr(
					specification["representative"],
					f"<html>{artifact_id} representative</html>\n".encode(),
				)
				archive.writestr(
					f"{specification['package']}package-summary.html",
					f"<html>{artifact_id} package</html>\n".encode(),
				)
			jar = buffer.getvalue()
			name = f"{artifact_id}-{VERSION}-javadoc.jar"
			base = (
				"https://repo.maven.apache.org/maven2/com/revetsec/"
				f"{artifact_id}/{VERSION}"
			)
			url = f"{base}/{name}"
			prefix = f"{artifact_id}-{VERSION}"
			payload_names = {
				f"{prefix}.pom",
				f"{prefix}.jar",
				f"{prefix}-sources.jar",
				f"{prefix}-javadoc.jar",
				f"{prefix}-cyclonedx.json",
			}
			files = {}
			for published_name in payload_names:
				files[published_name] = {
					"url": f"{base}/{published_name}",
					"sha256": hashlib.sha256(jar).hexdigest()
						if published_name == name else "d" * 64,
				}
				files[f"{published_name}.asc"] = {
					"url": f"{base}/{published_name}.asc",
					"sha256": "e" * 64,
				}
			receipt = {
				"schema": VERIFIER.CENTRAL_SCHEMA,
				"verifiedAt": "2026-11-13T22:30:00Z",
				"coordinates": f"com.revetsec:{artifact_id}:{VERSION}",
				"repository": "https://repo.maven.apache.org/maven2",
				"approvedBundle": {"path": "/release/bundle.zip", "sha256": "b" * 64},
				"files": files,
				"signaturesVerified": True,
				"signingFingerprint": "A" * 40,
				"exactBundleContent": True,
			}
			path = root / f"{artifact_id}-central.json"
			path.write_text(json.dumps(receipt) + "\n", encoding="utf-8")
			receipts.append(path)
			mapping[url] = jar
			with zipfile.ZipFile(io.BytesIO(jar)) as archive:
				for page in archive.namelist():
					mapping[f"{VERIFIER.API_BASE_URL}/{page}"] = archive.read(page)
		return claims, site, receipts, mapping

	def verify(self, root, mutate=None):
		claims, site, receipts, mapping = self.fixture(root)
		if mutate:
			mutate(claims, site, receipts, mapping)
		def fetcher(url, maximum, timeout):
			self.assertGreaterEqual(maximum, len(mapping[url]))
			self.assertEqual(timeout, 7)
			return mapping[url]
		return VERIFIER.verify_documentation(
			VERSION, claims, receipts, site, COMMIT, timeout_seconds=7, fetcher=fetcher,
		)

	def test_exact_api_and_website_deployments_pass(self):
		with tempfile.TemporaryDirectory() as temporary:
			result = self.verify(temporary)
		self.assertEqual(result["schema"], VERIFIER.SCHEMA)
		self.assertEqual(result["result"], "PASS")
		self.assertEqual(result["api"]["result"], "PASS")
		self.assertEqual(len(result["api"]["components"]), 4)
		self.assertTrue(result["website"]["allFilesMatchExport"])
		self.assertEqual(
			result["website"]["export"]["manifestSha256"],
			result["website"]["deployed"]["manifestSha256"],
		)

	def test_deployed_javadoc_must_equal_signed_jar_page(self):
		def mutate(claims, site, receipts, mapping):
			mapping[f"{VERIFIER.API_BASE_URL}/com/revetsec/StateSealer.html"] = b"changed"
		with tempfile.TemporaryDirectory() as temporary:
			with self.assertRaises(VERIFIER.DocumentationPolicyError) as raised:
				self.verify(temporary, mutate)
		self.assertIn("differs from the signed JAR", str(raised.exception))

	def test_javadoc_jar_must_equal_central_receipt_hash(self):
		def mutate(claims, site, receipts, mapping):
			receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
			name = f"revetsec-{VERSION}-javadoc.jar"
			receipt["files"][name]["sha256"] = "9" * 64
			receipts[0].write_text(json.dumps(receipt) + "\n", encoding="utf-8")
		with tempfile.TemporaryDirectory() as temporary:
			with self.assertRaises(VERIFIER.DocumentationPolicyError) as raised:
				self.verify(temporary, mutate)
		self.assertIn("published Javadoc JAR differs", str(raised.exception))

	def test_deployed_website_must_equal_local_export(self):
		def mutate(claims, site, receipts, mapping):
			mapping[VERIFIER.WEBSITE_BASE_URL + "/docs/security"] = b"changed"
		with tempfile.TemporaryDirectory() as temporary:
			with self.assertRaises(VERIFIER.DocumentationPolicyError) as raised:
				self.verify(temporary, mutate)
		self.assertIn("differs from the verified export", str(raised.exception))

	def test_release_pages_must_name_version(self):
		def mutate(claims, site, receipts, mapping):
			path = site / "index.html"
			path.write_bytes(b"<html>Revetsec</html>\n")
			mapping[VERIFIER.WEBSITE_BASE_URL + "/"] = path.read_bytes()
		with tempfile.TemporaryDirectory() as temporary:
			with self.assertRaises(VERIFIER.DocumentationPolicyError) as raised:
				self.verify(temporary, mutate)
		self.assertIn("does not name 1.0.0", str(raised.exception))

	def test_all_four_component_receipts_are_required(self):
		def mutate(claims, site, receipts, mapping):
			receipts.pop()
		with tempfile.TemporaryDirectory() as temporary:
			with self.assertRaises(VERIFIER.DocumentationPolicyError) as raised:
				self.verify(temporary, mutate)
		self.assertIn("exactly four", str(raised.exception))

	def test_noncanonical_central_receipt_is_rejected(self):
		def mutate(claims, site, receipts, mapping):
			receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
			receipt["repository"] = "https://packages.example.test/maven2"
			receipts[0].write_text(json.dumps(receipt) + "\n", encoding="utf-8")
		with tempfile.TemporaryDirectory() as temporary:
			with self.assertRaises(VERIFIER.DocumentationPolicyError) as raised:
				self.verify(temporary, mutate)
		self.assertIn("noncanonical", str(raised.exception))

	def test_claims_audit_name_is_fixed(self):
		with tempfile.TemporaryDirectory() as temporary:
			claims, site, receipts, mapping = self.fixture(temporary)
			wrong = claims.with_name("claims.md")
			claims.rename(wrong)
			with self.assertRaises(VERIFIER.DocumentationPolicyError) as raised:
				VERIFIER.verify_documentation(
					VERSION, wrong, receipts, site, COMMIT, fetcher=lambda url, maximum, timeout: mapping[url],
				)
		self.assertIn("SECURITY_CLAIMS_AUDIT.md", str(raised.exception))

	def test_website_symlink_is_rejected(self):
		def mutate(claims, site, receipts, mapping):
			(site / "alias.js").symlink_to(site / "_next" / "static" / "app.js")
		with tempfile.TemporaryDirectory() as temporary:
			with self.assertRaises(VERIFIER.DocumentationPolicyError) as raised:
				self.verify(temporary, mutate)
		self.assertIn("symlink", str(raised.exception))

	def test_receipt_write_is_create_new(self):
		with tempfile.TemporaryDirectory() as temporary:
			result = self.verify(temporary)
			output = Path(temporary) / "documentation.json"
			VERIFIER.write_receipt(output, result)
			self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["result"], "PASS")
			with self.assertRaises(VERIFIER.DocumentationPolicyError):
				VERIFIER.write_receipt(output, result)


if __name__ == "__main__":
	unittest.main()
