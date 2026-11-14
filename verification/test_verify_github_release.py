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

"""Policy tests for verify-github-release.py."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


DIRECTORY = Path(__file__).resolve().parent
SCRIPT = DIRECTORY / "verify-github-release.py"
SPEC = importlib.util.spec_from_file_location("verify_github_release", SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)
REPOSITORY = "revetsec"
VERSION = "1.0.0"
COMMIT = "a" * 40
TAG_OBJECT = "b" * 40
CI_URL = "https://github.com/revetsec/revetsec/actions/runs/101"
EVIDENCE_URL = "https://github.com/revetsec/revetsec/actions/runs/102"


class GitHubReleaseTests(unittest.TestCase):
	def responses(self):
		base = "https://api.github.com/repos/revetsec/revetsec"
		def run(run_id, url, path):
			created, completed = (
				("2026-11-13T20:00:00Z", "2026-11-13T20:30:00Z")
				if run_id == 101 else
				("2026-11-13T20:40:00Z", "2026-11-13T21:30:00Z")
			)
			return {
				"id": run_id,
				"html_url": url,
				"status": "completed",
				"conclusion": "success",
				"head_sha": COMMIT,
				"event": "push",
				"path": path,
				"repository": {"full_name": "revetsec/revetsec"},
				"created_at": created,
				"updated_at": completed,
			}
		return {
			f"{base}/git/ref/tags/v1.0.0": {
				"ref": "refs/tags/v1.0.0",
				"object": {"type": "tag", "sha": TAG_OBJECT},
			},
			f"{base}/git/tags/{TAG_OBJECT}": {
				"sha": TAG_OBJECT,
				"tag": "v1.0.0",
				"object": {"type": "commit", "sha": COMMIT},
				"verification": {"verified": True, "reason": "valid"},
				"tagger": {"date": "2026-11-13T20:35:00Z"},
			},
			f"{base}/actions/runs/101": run(101, CI_URL, ".github/workflows/ci.yml"),
			f"{base}/actions/runs/102": run(
				102, EVIDENCE_URL, ".github/workflows/release-evidence.yml"
			),
			f"{base}/releases/tags/v1.0.0": {
				"id": 103,
				"tag_name": "v1.0.0",
				"draft": False,
				"prerelease": False,
				"html_url": "https://github.com/revetsec/revetsec/releases/tag/v1.0.0",
				"published_at": "2026-11-13T22:00:00Z",
			},
		}

	def verify(self, mutate=None):
		responses = self.responses()
		if mutate:
			mutate(responses)
		return VERIFIER.verify_github_release(
			REPOSITORY,
			VERSION,
			COMMIT,
			CI_URL,
			EVIDENCE_URL,
			fetcher=lambda url: responses[url],
		)

	def test_exact_signed_tag_runs_and_release_pass(self):
		result = self.verify()
		self.assertEqual(result["schema"], VERIFIER.SCHEMA)
		self.assertEqual(result["result"], "PASS")
		self.assertTrue(result["signedTag"]["signatureVerified"])
		self.assertEqual(result["ciRun"]["headSha"], COMMIT)
		self.assertEqual(result["releaseEvidenceRun"]["workflowPath"], ".github/workflows/release-evidence.yml")
		self.assertFalse(result["release"]["prerelease"])

	def test_lightweight_tag_is_rejected(self):
		def mutate(responses):
			responses[next(url for url in responses if "/git/ref/" in url)]["object"]["type"] = "commit"
		with self.assertRaises(VERIFIER.GitHubReleasePolicyError) as raised:
			self.verify(mutate)
		self.assertIn("does not equal 'tag'", str(raised.exception))

	def test_wrong_tag_target_is_rejected(self):
		def mutate(responses):
			responses[next(url for url in responses if "/git/tags/" in url)]["object"]["sha"] = "c" * 40
		with self.assertRaises(VERIFIER.GitHubReleasePolicyError) as raised:
			self.verify(mutate)
		self.assertIn("annotated tag target", str(raised.exception))

	def test_unverified_tag_is_rejected(self):
		def mutate(responses):
			responses[next(url for url in responses if "/git/tags/" in url)]["verification"]["verified"] = False
		with self.assertRaises(VERIFIER.GitHubReleasePolicyError) as raised:
			self.verify(mutate)
		self.assertIn("verification verified", str(raised.exception))

	def test_failed_ci_run_is_rejected(self):
		def mutate(responses):
			responses[next(url for url in responses if url.endswith("/actions/runs/101"))]["conclusion"] = "failure"
		with self.assertRaises(VERIFIER.GitHubReleasePolicyError) as raised:
			self.verify(mutate)
		self.assertIn("CI run conclusion", str(raised.exception))

	def test_wrong_release_evidence_workflow_is_rejected(self):
		def mutate(responses):
			responses[next(url for url in responses if url.endswith("/actions/runs/102"))]["path"] = ".github/workflows/ci.yml"
		with self.assertRaises(VERIFIER.GitHubReleasePolicyError) as raised:
			self.verify(mutate)
		self.assertIn("release-evidence run path", str(raised.exception))

	def test_draft_or_prerelease_is_rejected(self):
		for field in ("draft", "prerelease"):
			with self.subTest(field=field):
				def mutate(responses, field=field):
					responses[next(url for url in responses if "/releases/tags/" in url)][field] = True
				with self.assertRaises(VERIFIER.GitHubReleasePolicyError) as raised:
					self.verify(mutate)
				self.assertIn(f"GitHub Release {field}", str(raised.exception))

	def test_release_evidence_must_follow_ci_and_signed_tag(self):
		for field, value, message in (
			("created_at", "2026-11-13T20:20:00Z", "CI did not complete"),
			("created_at", "2026-11-13T20:34:59Z", "annotated tag existed"),
		):
			with self.subTest(value=value):
				def mutate(responses, field=field, value=value):
					responses[next(
						url for url in responses if url.endswith("/actions/runs/102")
					)][field] = value
				with self.assertRaises(VERIFIER.GitHubReleasePolicyError) as raised:
					self.verify(mutate)
				self.assertIn(message, str(raised.exception))

	def test_release_must_follow_completed_release_evidence(self):
		def mutate(responses):
			responses[next(url for url in responses if "/releases/tags/" in url)][
				"published_at"
			] = "2026-11-13T21:29:59Z"
		with self.assertRaises(VERIFIER.GitHubReleasePolicyError) as raised:
			self.verify(mutate)
		self.assertIn("predates completed release evidence", str(raised.exception))

	def test_run_url_for_wrong_repository_is_rejected(self):
		with self.assertRaises(VERIFIER.GitHubReleasePolicyError) as raised:
			VERIFIER.verify_github_release(
				REPOSITORY,
				VERSION,
				COMMIT,
				"https://github.com/revetsec/other/actions/runs/101",
				EVIDENCE_URL,
				fetcher=lambda url: {},
			)
		self.assertIn("expected GitHub Actions run", str(raised.exception))

	def test_receipt_write_is_create_new(self):
		result = self.verify()
		with tempfile.TemporaryDirectory() as temporary:
			output = Path(temporary) / "github.json"
			VERIFIER.write_receipt(output, result)
			self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["result"], "PASS")
			with self.assertRaises(VERIFIER.GitHubReleasePolicyError):
				VERIFIER.write_receipt(output, result)


if __name__ == "__main__":
	unittest.main()
