#!/usr/bin/env python3
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

"""Verify a Revetsec repository's signed tag, hosted runs and GitHub Release."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


SCHEMA = "revetsec.github-release-verification.v1"
OWNER = "revetsec"
API_BASE_URL = "https://api.github.com"
REPOSITORIES = {
	"revetsec",
	"revetsec-soklet",
	"revetsec-servlet-jakarta",
	"revetsec-servlet-javax",
}
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?")
COMMIT = re.compile(r"[0-9a-f]{40}")
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class GitHubReleasePolicyError(ValueError):
	"""GitHub does not expose the exact successful release state required."""


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
	"""Refuse redirects so GitHub API verification remains on the requested endpoint."""

	def redirect_request(self, request, file_pointer, code, message, headers, new_url):
		return None


def parse_timestamp(value, label):
	try:
		parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
	except (AttributeError, ValueError) as exception:
		raise GitHubReleasePolicyError(f"{label} is not an ISO-8601 timestamp") from exception
	if parsed.tzinfo is None:
		raise GitHubReleasePolicyError(f"{label} lacks a timezone")
	return parsed


def validate_run_url(value, repository, label):
	if not isinstance(value, str):
		raise GitHubReleasePolicyError(f"{label} must be a string")
	parsed = urllib.parse.urlsplit(value)
	prefix = f"/{OWNER}/{repository}/actions/runs/"
	if (
		parsed.scheme != "https" or parsed.netloc != "github.com"
		or parsed.query or parsed.fragment or not parsed.path.startswith(prefix)
	):
		raise GitHubReleasePolicyError(f"{label} must name the expected GitHub Actions run")
	run_id = parsed.path.removeprefix(prefix)
	if not run_id.isdigit() or int(run_id) < 1:
		raise GitHubReleasePolicyError(f"{label} has an invalid run ID")
	return int(run_id)


def fetch_json(opener, url, timeout_seconds, token=None):
	if not url.startswith(f"{API_BASE_URL}/repos/{OWNER}/"):
		raise GitHubReleasePolicyError("GitHub API URL is outside the fixed organization origin")
	headers = {
		"Accept": "application/vnd.github+json",
		"Accept-Encoding": "identity",
		"User-Agent": "revetsec-github-release-verifier/1",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if token:
		headers["Authorization"] = f"Bearer {token}"
	request = urllib.request.Request(url, headers=headers)
	try:
		with opener.open(request, timeout=timeout_seconds) as response:
			if response.status != 200:
				raise GitHubReleasePolicyError(f"GitHub returned HTTP {response.status} for {url}")
			length = response.headers.get("Content-Length")
			if length is not None and int(length) > MAX_RESPONSE_BYTES:
				raise GitHubReleasePolicyError(f"GitHub response exceeds the size limit: {url}")
			data = response.read(MAX_RESPONSE_BYTES + 1)
	except (urllib.error.URLError, OSError, ValueError) as exception:
		raise GitHubReleasePolicyError(f"cannot download {url}: {exception}") from exception
	if len(data) > MAX_RESPONSE_BYTES:
		raise GitHubReleasePolicyError(f"GitHub response exceeds the size limit: {url}")
	try:
		result = json.loads(data.decode("utf-8"))
	except (UnicodeError, json.JSONDecodeError) as exception:
		raise GitHubReleasePolicyError(f"GitHub returned invalid JSON for {url}") from exception
	if not isinstance(result, dict):
		raise GitHubReleasePolicyError(f"GitHub returned a non-object for {url}")
	return result


def require_value(document, key, expected, label):
	if document.get(key) != expected:
		raise GitHubReleasePolicyError(f"{label} {key} does not equal {expected!r}")


def verify_run(document, repository, commit, url, run_id, workflow_path, label):
	require_value(document, "id", run_id, label)
	require_value(document, "html_url", url, label)
	require_value(document, "status", "completed", label)
	require_value(document, "conclusion", "success", label)
	require_value(document, "head_sha", commit, label)
	require_value(document, "event", "push", label)
	require_value(document, "path", workflow_path, label)
	repository_document = document.get("repository")
	if not isinstance(repository_document, dict):
		raise GitHubReleasePolicyError(f"{label} has no repository identity")
	require_value(repository_document, "full_name", f"{OWNER}/{repository}", label)
	created_at = document.get("created_at")
	updated_at = document.get("updated_at")
	parse_timestamp(created_at, f"{label} created_at")
	parse_timestamp(updated_at, f"{label} updated_at")
	return {
		"url": url,
		"id": run_id,
		"workflowPath": workflow_path,
		"event": "push",
		"headSha": commit,
		"createdAt": created_at,
		"completedAt": updated_at,
		"conclusion": "success",
	}


def verify_github_release(
	repository,
	version,
	commit,
	ci_run_url,
	release_evidence_run_url,
	timeout_seconds=30,
	token=None,
	fetcher=None,
):
	if repository not in REPOSITORIES:
		raise GitHubReleasePolicyError(f"unexpected Revetsec repository: {repository!r}")
	if not isinstance(version, str) or not VERSION.fullmatch(version) or version.endswith("-SNAPSHOT"):
		raise GitHubReleasePolicyError("version must be a literal semantic release version")
	if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
		raise GitHubReleasePolicyError("commit must be a full lowercase SHA")
	ci_run_id = validate_run_url(ci_run_url, repository, "CI run")
	release_run_id = validate_run_url(release_evidence_run_url, repository, "release-evidence run")
	if ci_run_id == release_run_id:
		raise GitHubReleasePolicyError("CI and release-evidence runs must be distinct")
	if fetcher is None:
		opener = urllib.request.build_opener(NoRedirectHandler())
		fetcher = lambda url: fetch_json(opener, url, timeout_seconds, token=token)

	tag = f"v{version}"
	api_repository = f"{API_BASE_URL}/repos/{OWNER}/{repository}"
	ref = fetcher(f"{api_repository}/git/ref/tags/{urllib.parse.quote(tag, safe='')}")
	require_value(ref, "ref", f"refs/tags/{tag}", "tag reference")
	tag_object = ref.get("object")
	if not isinstance(tag_object, dict):
		raise GitHubReleasePolicyError("tag reference has no object")
	require_value(tag_object, "type", "tag", "tag reference")
	tag_object_sha = tag_object.get("sha")
	if not isinstance(tag_object_sha, str) or not COMMIT.fullmatch(tag_object_sha):
		raise GitHubReleasePolicyError("annotated tag object SHA is invalid")

	annotated = fetcher(f"{api_repository}/git/tags/{tag_object_sha}")
	require_value(annotated, "sha", tag_object_sha, "annotated tag")
	require_value(annotated, "tag", tag, "annotated tag")
	target = annotated.get("object")
	if not isinstance(target, dict):
		raise GitHubReleasePolicyError("annotated tag has no target object")
	require_value(target, "type", "commit", "annotated tag target")
	require_value(target, "sha", commit, "annotated tag target")
	verification = annotated.get("verification")
	if not isinstance(verification, dict):
		raise GitHubReleasePolicyError("annotated tag has no GitHub verification result")
	require_value(verification, "verified", True, "annotated tag verification")
	require_value(verification, "reason", "valid", "annotated tag verification")
	tagger = annotated.get("tagger")
	if not isinstance(tagger, dict):
		raise GitHubReleasePolicyError("annotated tag has no tagger")
	tagged_at = tagger.get("date")
	tagged_time = parse_timestamp(tagged_at, "annotated tag date")

	ci_run = fetcher(f"{api_repository}/actions/runs/{ci_run_id}")
	ci_result = verify_run(
		ci_run, repository, commit, ci_run_url, ci_run_id, ".github/workflows/ci.yml", "CI run"
	)
	release_run = fetcher(f"{api_repository}/actions/runs/{release_run_id}")
	release_run_result = verify_run(
		release_run,
		repository,
		commit,
		release_evidence_run_url,
		release_run_id,
		".github/workflows/release-evidence.yml",
		"release-evidence run",
	)

	release = fetcher(f"{api_repository}/releases/tags/{urllib.parse.quote(tag, safe='')}")
	require_value(release, "tag_name", tag, "GitHub Release")
	require_value(release, "draft", False, "GitHub Release")
	require_value(release, "prerelease", False, "GitHub Release")
	expected_release_url = f"https://github.com/{OWNER}/{repository}/releases/tag/{tag}"
	require_value(release, "html_url", expected_release_url, "GitHub Release")
	release_id = release.get("id")
	if isinstance(release_id, bool) or not isinstance(release_id, int) or release_id < 1:
		raise GitHubReleasePolicyError("GitHub Release ID is invalid")
	published_at = release.get("published_at")
	published_time = parse_timestamp(published_at, "GitHub Release published_at")
	ci_completed = parse_timestamp(ci_result["completedAt"], "CI run completed_at")
	evidence_created = parse_timestamp(
		release_run_result["createdAt"], "release-evidence run created_at"
	)
	evidence_completed = parse_timestamp(
		release_run_result["completedAt"], "release-evidence run completed_at"
	)
	verified_at = datetime.now(timezone.utc)
	if ci_completed > evidence_created:
		raise GitHubReleasePolicyError("CI did not complete before release evidence started")
	if tagged_time > evidence_created:
		raise GitHubReleasePolicyError("release evidence started before the annotated tag existed")
	if evidence_completed > published_time:
		raise GitHubReleasePolicyError("GitHub Release predates completed release evidence")
	if published_time > verified_at:
		raise GitHubReleasePolicyError("GitHub Release publication time is in the future")

	return {
		"schema": SCHEMA,
		"verifiedAt": verified_at.isoformat().replace("+00:00", "Z"),
		"repository": repository,
		"commit": commit,
		"tag": tag,
		"signedTag": {
			"objectSha": tag_object_sha,
			"targetSha": commit,
			"taggedAt": tagged_at,
			"signatureVerified": True,
			"verificationReason": "valid",
		},
		"ciRun": ci_result,
		"releaseEvidenceRun": release_run_result,
		"release": {
			"url": expected_release_url,
			"id": release_id,
			"publishedAt": published_at,
			"draft": False,
			"prerelease": False,
		},
		"result": "PASS",
	}


def write_receipt(path, result):
	if path.exists() or path.is_symlink():
		raise GitHubReleasePolicyError(f"receipt path already exists: {path}")
	if not path.parent.is_dir():
		raise GitHubReleasePolicyError(f"receipt parent directory does not exist: {path.parent}")
	path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv=None):
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("--repository", required=True, choices=sorted(REPOSITORIES))
	parser.add_argument("--version", required=True)
	parser.add_argument("--commit", required=True)
	parser.add_argument("--ci-run", required=True)
	parser.add_argument("--release-evidence-run", required=True)
	parser.add_argument("--timeout", type=int, default=30, help="per-request timeout in seconds")
	parser.add_argument(
		"--token-environment", default="GITHUB_TOKEN",
		help="environment variable containing an optional read-only GitHub token",
	)
	parser.add_argument("--output", required=True, type=Path, help="create-new JSON receipt path")
	arguments = parser.parse_args(argv)
	if arguments.timeout < 1 or arguments.timeout > 300:
		parser.error("--timeout must be between 1 and 300 seconds")
	try:
		result = verify_github_release(
			arguments.repository,
			arguments.version,
			arguments.commit,
			arguments.ci_run,
			arguments.release_evidence_run,
			timeout_seconds=arguments.timeout,
			token=os.environ.get(arguments.token_environment),
		)
		write_receipt(arguments.output, result)
	except (GitHubReleasePolicyError, OSError) as exception:
		print(f"GitHub release verification failed: {exception}", file=sys.stderr)
		return 1
	print(json.dumps(result, indent=2, sort_keys=True))
	return 0


if __name__ == "__main__":
	sys.exit(main())
