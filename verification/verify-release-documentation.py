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

"""Verify deployed API and website documentation for a Revetsec release."""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile


SCHEMA = "revetsec.release-documentation-verification.v1"
CENTRAL_SCHEMA = "revetsec.central-publication-verification.v1"
CENTRAL_REPOSITORIES = {
	"https://repo.maven.apache.org/maven2",
	"https://repo1.maven.org/maven2",
}
API_BASE_URL = "https://javadoc.revetsec.com"
WEBSITE_BASE_URL = "https://revetsec.com"
WEBSITE_REPOSITORY = "https://github.com/revetsec/revetsec.com"
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?")
COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_RECEIPT_BYTES = 1024 * 1024
MAX_JAVADOC_JAR_BYTES = 64 * 1024 * 1024
MAX_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_JAVADOC_PAGE_BYTES = 512 * 1024 * 1024
MAX_JAVADOC_ENTRIES = 20_000
MAX_WEBSITE_FILES = 20_000
MAX_WEBSITE_BYTES = 1024 * 1024 * 1024

COMPONENTS = {
	"revetsec": {
		"package": "com/revetsec/",
		"representative": "com/revetsec/StateSealer.html",
	},
	"revetsec-soklet": {
		"package": "com/revetsec/soklet/",
		"representative": "com/revetsec/soklet/SokletOAuth.html",
	},
	"revetsec-servlet-jakarta": {
		"package": "com/revetsec/servlet/jakarta/",
		"representative": "com/revetsec/servlet/jakarta/ServletOAuth.html",
	},
	"revetsec-servlet-javax": {
		"package": "com/revetsec/servlet/javax/",
		"representative": "com/revetsec/servlet/javax/ServletOAuth.html",
	},
}
VERSIONED_WEBSITE_FILES = {
	"index.html",
	"docs/getting-started.html",
}


class DocumentationPolicyError(ValueError):
	"""The deployed documentation is incomplete or differs from release inputs."""


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
	"""Refuse redirects so a verification request cannot change origins or paths."""

	def redirect_request(self, request, file_pointer, code, message, headers, new_url):
		return None


def sha256(data):
	return hashlib.sha256(data).hexdigest()


def require_sha256(value, label):
	if not isinstance(value, str) or not SHA256.fullmatch(value):
		raise DocumentationPolicyError(f"{label} must be a lowercase SHA-256")


def read_bounded(path, maximum, label):
	try:
		if path.is_symlink() or not path.is_file():
			raise DocumentationPolicyError(f"{label} must be a regular file")
		if path.stat().st_size > maximum:
			raise DocumentationPolicyError(f"{label} exceeds the size limit")
		return path.read_bytes()
	except OSError as exception:
		raise DocumentationPolicyError(f"cannot read {label}: {exception}") from exception


def fetch(opener, url, maximum_bytes, timeout_seconds):
	request = urllib.request.Request(
		url,
		headers={
			"Accept-Encoding": "identity",
			"User-Agent": "revetsec-release-documentation-verifier/1",
		},
	)
	try:
		with opener.open(request, timeout=timeout_seconds) as response:
			if response.status != 200:
				raise DocumentationPolicyError(f"documentation returned HTTP {response.status} for {url}")
			length = response.headers.get("Content-Length")
			if length is not None and int(length) > maximum_bytes:
				raise DocumentationPolicyError(f"documentation exceeds the size limit: {url}")
			data = response.read(maximum_bytes + 1)
	except (urllib.error.URLError, OSError, ValueError) as exception:
		raise DocumentationPolicyError(f"cannot download {url}: {exception}") from exception
	if len(data) > maximum_bytes:
		raise DocumentationPolicyError(f"documentation exceeds the size limit: {url}")
	return data


def manifest_sha256(files):
	encoded = json.dumps(files, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
	return sha256(encoded)


def load_central_receipt(path, version):
	data = read_bounded(path, MAX_RECEIPT_BYTES, f"Central receipt {path}")
	try:
		receipt = json.loads(data.decode("utf-8"))
	except (UnicodeError, json.JSONDecodeError) as exception:
		raise DocumentationPolicyError(f"Central receipt is not valid UTF-8 JSON: {path}") from exception
	if not isinstance(receipt, dict) or set(receipt) != {
		"schema", "verifiedAt", "coordinates", "repository", "approvedBundle",
		"files", "signaturesVerified", "signingFingerprint", "exactBundleContent",
	}:
		raise DocumentationPolicyError(f"Central receipt has an unexpected shape: {path}")
	if receipt["schema"] != CENTRAL_SCHEMA:
		raise DocumentationPolicyError(f"Central receipt has the wrong schema: {path}")
	try:
		verified_at = datetime.fromisoformat(receipt["verifiedAt"].replace("Z", "+00:00"))
	except (AttributeError, ValueError) as exception:
		raise DocumentationPolicyError(f"Central receipt has an invalid timestamp: {path}") from exception
	if verified_at.tzinfo is None:
		raise DocumentationPolicyError(f"Central receipt timestamp lacks a timezone: {path}")
	if receipt["repository"] not in CENTRAL_REPOSITORIES:
		raise DocumentationPolicyError(f"Central receipt uses a noncanonical repository: {path}")
	if receipt["signaturesVerified"] is not True or receipt["exactBundleContent"] is not True:
		raise DocumentationPolicyError(f"Central receipt does not verify exact signed content: {path}")
	if not isinstance(receipt["signingFingerprint"], str) or not re.fullmatch(
		r"(?:[0-9A-F]{40}|[0-9A-F]{64})", receipt["signingFingerprint"]
	):
		raise DocumentationPolicyError(f"Central receipt has an invalid signing fingerprint: {path}")
	try:
		group_id, artifact_id, receipt_version = receipt["coordinates"].split(":")
	except (AttributeError, ValueError) as exception:
		raise DocumentationPolicyError(f"Central receipt coordinates are invalid: {path}") from exception
	if group_id != "com.revetsec" or artifact_id not in COMPONENTS or receipt_version != version:
		raise DocumentationPolicyError(f"Central receipt coordinates are not an expected {version} component: {path}")
	bundle = receipt["approvedBundle"]
	if not isinstance(bundle, dict) or set(bundle) != {"path", "sha256"}:
		raise DocumentationPolicyError(f"Central receipt approved bundle has an unexpected shape: {path}")
	if not isinstance(bundle["path"], str) or not bundle["path"]:
		raise DocumentationPolicyError(f"Central receipt approved bundle path is empty: {path}")
	require_sha256(bundle["sha256"], "Central receipt approved bundle")
	files = receipt["files"]
	if not isinstance(files, dict):
		raise DocumentationPolicyError(f"Central receipt files must be an object: {path}")
	prefix = f"{artifact_id}-{version}"
	payload_names = {
		f"{prefix}.pom",
		f"{prefix}.jar",
		f"{prefix}-sources.jar",
		f"{prefix}-javadoc.jar",
		f"{prefix}-cyclonedx.json",
	}
	expected_names = payload_names.union(f"{name}.asc" for name in payload_names)
	if set(files) != expected_names:
		raise DocumentationPolicyError(f"Central receipt file set is incomplete for {artifact_id}")
	base = f"{receipt['repository']}/{group_id.replace('.', '/')}/{artifact_id}/{version}"
	for published_name, published_entry in files.items():
		if not isinstance(published_entry, dict) or set(published_entry) != {"url", "sha256"}:
			raise DocumentationPolicyError(f"Central receipt entry is malformed: {published_name}")
		require_sha256(published_entry["sha256"], f"Central receipt {published_name}")
		if published_entry["url"] != f"{base}/{published_name}":
			raise DocumentationPolicyError(f"Central receipt URL differs for {published_name}")
	name = f"{artifact_id}-{version}-javadoc.jar"
	entry = files.get(name)
	return artifact_id, receipt, sha256(data), entry


def safe_javadoc_pages(jar_data, artifact_id):
	specification = COMPONENTS[artifact_id]
	try:
		archive = zipfile.ZipFile(io.BytesIO(jar_data))
	except zipfile.BadZipFile as exception:
		raise DocumentationPolicyError(f"{artifact_id} Javadoc JAR is not a ZIP archive") from exception
	with archive:
		entries = archive.infolist()
		if len(entries) > MAX_JAVADOC_ENTRIES:
			raise DocumentationPolicyError(f"{artifact_id} Javadoc JAR has too many entries")
		names = [entry.filename for entry in entries]
		if len(names) != len(set(names)):
			raise DocumentationPolicyError(f"{artifact_id} Javadoc JAR has duplicate entries")
		pages = {}
		total_page_bytes = 0
		for entry in entries:
			path = PurePosixPath(entry.filename)
			if entry.filename.startswith("/") or ".." in path.parts or "\\" in entry.filename:
				raise DocumentationPolicyError(f"{artifact_id} Javadoc JAR has an unsafe entry")
			if entry.is_dir() or not entry.filename.startswith(specification["package"]):
				continue
			if not entry.filename.endswith(".html"):
				continue
			if entry.file_size > MAX_DOCUMENT_BYTES:
				raise DocumentationPolicyError(f"Javadoc page exceeds the size limit: {entry.filename}")
			total_page_bytes += entry.file_size
			if total_page_bytes > MAX_JAVADOC_PAGE_BYTES:
				raise DocumentationPolicyError(f"{artifact_id} Javadoc pages exceed the total size limit")
			pages[entry.filename] = archive.read(entry)
	if specification["representative"] not in pages:
		raise DocumentationPolicyError(
			f"{artifact_id} Javadoc JAR lacks {specification['representative']}"
		)
	return pages


def website_url(relative_path):
	if relative_path == "index.html":
		path = "/"
	elif relative_path == "404.html":
		path = "/404.html"
	elif relative_path.endswith("/index.html"):
		path = f"/{relative_path.removesuffix('index.html')}"
	elif relative_path.endswith(".html"):
		path = f"/{relative_path.removesuffix('.html')}"
	else:
		path = f"/{relative_path}"
	return f"{WEBSITE_BASE_URL}{urllib.parse.quote(path, safe='/._~-')}"


def load_website_export(site_directory, version):
	if site_directory.is_symlink() or not site_directory.is_dir():
		raise DocumentationPolicyError("website export must be a directory, not a symlink")
	files = {}
	total = 0
	for path in sorted(site_directory.rglob("*")):
		if path.is_symlink():
			raise DocumentationPolicyError(f"website export contains a symlink: {path}")
		if path.is_dir():
			continue
		if not path.is_file():
			raise DocumentationPolicyError(f"website export contains a non-regular file: {path}")
		relative = path.relative_to(site_directory).as_posix()
		if not relative or relative.startswith("/") or ".." in PurePosixPath(relative).parts:
			raise DocumentationPolicyError(f"website export contains an unsafe path: {path}")
		data = read_bounded(path, MAX_DOCUMENT_BYTES, f"website export file {relative}")
		total += len(data)
		if total > MAX_WEBSITE_BYTES:
			raise DocumentationPolicyError("website export exceeds the total size limit")
		files[relative] = data
		if len(files) > MAX_WEBSITE_FILES:
			raise DocumentationPolicyError("website export has too many files")
	missing = VERSIONED_WEBSITE_FILES.difference(files)
	if missing:
		raise DocumentationPolicyError(f"website export lacks release pages: {sorted(missing)}")
	for relative in VERSIONED_WEBSITE_FILES:
		try:
			text = files[relative].decode("utf-8")
		except UnicodeError as exception:
			raise DocumentationPolicyError(f"website release page is not UTF-8: {relative}") from exception
		if version not in text:
			raise DocumentationPolicyError(f"website release page does not name {version}: {relative}")
	return files


def git_commit(repository):
	try:
		commit_result = subprocess.run(
			["git", "-C", str(repository), "rev-parse", "HEAD"],
			check=True, capture_output=True, text=True,
		)
		status_result = subprocess.run(
			["git", "-C", str(repository), "status", "--porcelain", "--untracked-files=all"],
			check=True, capture_output=True, text=True,
		)
	except (OSError, subprocess.CalledProcessError) as exception:
		raise DocumentationPolicyError(f"cannot inspect website repository: {exception}") from exception
	commit = commit_result.stdout.strip()
	if not COMMIT.fullmatch(commit):
		raise DocumentationPolicyError("website repository HEAD is not a full lowercase commit SHA")
	if status_result.stdout:
		raise DocumentationPolicyError("website repository must be clean before deployment verification")
	return commit


def verify_documentation(
	version,
	claims_audit,
	central_receipts,
	site_directory,
	website_commit,
	timeout_seconds=30,
	fetcher=None,
):
	if not isinstance(version, str) or not VERSION.fullmatch(version) or version.endswith("-SNAPSHOT"):
		raise DocumentationPolicyError("version must be a literal semantic release version")
	if not COMMIT.fullmatch(website_commit):
		raise DocumentationPolicyError("website commit must be a full lowercase commit SHA")
	claims_data = read_bounded(claims_audit, MAX_DOCUMENT_BYTES, "claims audit")
	if claims_audit.name != "SECURITY_CLAIMS_AUDIT.md":
		raise DocumentationPolicyError("claims audit must be named SECURITY_CLAIMS_AUDIT.md")
	if len(central_receipts) != len(COMPONENTS):
		raise DocumentationPolicyError("exactly four Central receipts are required")
	if fetcher is None:
		opener = urllib.request.build_opener(NoRedirectHandler())
		fetcher = lambda url, maximum, timeout: fetch(opener, url, maximum, timeout)

	receipts = {}
	for receipt_path in central_receipts:
		artifact_id, receipt, receipt_sha, javadoc_entry = load_central_receipt(receipt_path, version)
		if artifact_id in receipts:
			raise DocumentationPolicyError(f"duplicate Central receipt for {artifact_id}")
		receipts[artifact_id] = (receipt_path, receipt, receipt_sha, javadoc_entry)
	if set(receipts) != set(COMPONENTS):
		raise DocumentationPolicyError("Central receipts do not name all four release components")

	api_components = []
	for artifact_id in COMPONENTS:
		receipt_path, receipt, receipt_sha, javadoc_entry = receipts[artifact_id]
		jar_data = fetcher(javadoc_entry["url"], MAX_JAVADOC_JAR_BYTES, timeout_seconds)
		if sha256(jar_data) != javadoc_entry["sha256"]:
			raise DocumentationPolicyError(f"published Javadoc JAR differs for {artifact_id}")
		pages = safe_javadoc_pages(jar_data, artifact_id)
		page_hashes = {}
		for path, expected in sorted(pages.items()):
			url = f"{API_BASE_URL}/{urllib.parse.quote(path, safe='/._~-')}"
			deployed = fetcher(url, MAX_DOCUMENT_BYTES, timeout_seconds)
			if deployed != expected:
				raise DocumentationPolicyError(f"deployed Javadoc differs from the signed JAR: {url}")
			page_hashes[path] = sha256(deployed)
		api_components.append({
			"coordinates": receipt["coordinates"],
			"centralReceipt": {"path": str(receipt_path), "sha256": receipt_sha},
			"javadocJar": {"url": javadoc_entry["url"], "sha256": javadoc_entry["sha256"]},
			"pages": {
				"count": len(page_hashes),
				"manifestSha256": manifest_sha256(page_hashes),
				"allMatchSignedJar": True,
			},
		})

	website_files = load_website_export(site_directory, version)
	local_hashes = {path: sha256(data) for path, data in sorted(website_files.items())}
	deployed_hashes = {}
	urls = set()
	for path, expected in sorted(website_files.items()):
		url = website_url(path)
		if url in urls:
			raise DocumentationPolicyError(f"website export paths map to the same URL: {url}")
		urls.add(url)
		deployed = fetcher(url, MAX_DOCUMENT_BYTES, timeout_seconds)
		if deployed != expected:
			raise DocumentationPolicyError(f"deployed website differs from the verified export: {url}")
		deployed_hashes[path] = sha256(deployed)
	local_manifest = manifest_sha256(local_hashes)
	deployed_manifest = manifest_sha256(deployed_hashes)
	if deployed_manifest != local_manifest:
		raise DocumentationPolicyError("deployed website manifest differs from the verified export")

	return {
		"schema": SCHEMA,
		"verifiedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
		"version": version,
		"claimsAudit": {"path": str(claims_audit), "sha256": sha256(claims_data)},
		"api": {
			"baseUrl": API_BASE_URL,
			"components": api_components,
			"result": "PASS",
		},
		"website": {
			"baseUrl": WEBSITE_BASE_URL,
			"repository": WEBSITE_REPOSITORY,
			"sourceCommit": website_commit,
			"export": {
				"path": str(site_directory),
				"fileCount": len(local_hashes),
				"manifestSha256": local_manifest,
			},
			"deployed": {
				"fileCount": len(deployed_hashes),
				"manifestSha256": deployed_manifest,
			},
			"releaseVersionVerified": True,
			"allFilesMatchExport": True,
			"result": "PASS",
		},
		"result": "PASS",
	}


def write_receipt(path, result):
	if path.exists() or path.is_symlink():
		raise DocumentationPolicyError(f"receipt path already exists: {path}")
	if not path.parent.is_dir():
		raise DocumentationPolicyError(f"receipt parent directory does not exist: {path.parent}")
	path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv=None):
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("--version", required=True, help="literal release version")
	parser.add_argument("--claims-audit", required=True, type=Path)
	parser.add_argument(
		"--central-receipt", action="append", required=True, type=Path,
		help="Central verification receipt; provide once for each of the four components",
	)
	parser.add_argument("--website-repository", required=True, type=Path)
	parser.add_argument("--site-directory", required=True, type=Path, help="verified static website export")
	parser.add_argument("--timeout", type=int, default=30, help="per-file network timeout in seconds")
	parser.add_argument("--output", required=True, type=Path, help="create-new documentation receipt")
	arguments = parser.parse_args(argv)
	if arguments.timeout < 1 or arguments.timeout > 300:
		parser.error("--timeout must be between 1 and 300 seconds")
	try:
		if arguments.website_repository.is_symlink() or arguments.site_directory.is_symlink():
			raise DocumentationPolicyError("website repository and site directory must not be symlinks")
		website_repository = arguments.website_repository.resolve()
		site_directory = arguments.site_directory.resolve()
		if not site_directory.is_relative_to(website_repository):
			raise DocumentationPolicyError("site directory must be inside the website repository")
		result = verify_documentation(
			arguments.version,
			arguments.claims_audit,
			arguments.central_receipt,
			site_directory,
			git_commit(website_repository),
			timeout_seconds=arguments.timeout,
		)
		write_receipt(arguments.output, result)
	except (DocumentationPolicyError, OSError) as exception:
		print(f"Release documentation verification failed: {exception}", file=sys.stderr)
		return 1
	print(json.dumps(result, indent=2, sort_keys=True))
	return 0


if __name__ == "__main__":
	sys.exit(main())
