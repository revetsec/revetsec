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

"""Verify that Maven Central serves the exact payloads from an approved bundle."""

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request


BUNDLE_VERIFIER_PATH = Path(__file__).resolve().parent / "verify-central-bundle.py"
SPEC = importlib.util.spec_from_file_location("verify_central_bundle", BUNDLE_VERIFIER_PATH)
BUNDLE_VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUNDLE_VERIFIER)

DEFAULT_REPOSITORY = "https://repo.maven.apache.org/maven2"
CANONICAL_REPOSITORIES = {
	DEFAULT_REPOSITORY,
	"https://repo1.maven.org/maven2",
}
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_SIGNATURE_BYTES = 256 * 1024


class PublicationPolicyError(ValueError):
	"""The public repository content is missing, unsafe or not the approved release."""


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
	"""Refuse redirects so the verified host cannot change under the client."""

	def redirect_request(self, request, file_pointer, code, message, headers, new_url):
		return None


def validate_repository(value, allow_loopback_http=False):
	normalized = value.rstrip("/")
	parsed = urllib.parse.urlsplit(normalized)
	if parsed.username or parsed.password or parsed.query or parsed.fragment:
		raise PublicationPolicyError("repository URL must not contain credentials, query or fragment")
	if allow_loopback_http:
		if parsed.scheme != "http" or parsed.hostname not in LOOPBACK_HOSTS:
			raise PublicationPolicyError("test repository must be loopback HTTP")
	elif normalized not in CANONICAL_REPOSITORIES:
		raise PublicationPolicyError("repository must be a canonical Maven Central HTTPS base URL")
	if not parsed.path or parsed.path == "/":
		raise PublicationPolicyError("repository URL must include the Maven repository path")
	return urllib.parse.urlunsplit(parsed).rstrip("/")


def fetch(opener, url, maximum_bytes, timeout_seconds):
	request = urllib.request.Request(url, headers={"User-Agent": "revetsec-release-verifier/1"})
	try:
		with opener.open(request, timeout=timeout_seconds) as response:
			if response.status != 200:
				raise PublicationPolicyError(f"repository returned HTTP {response.status} for {url}")
			length = response.headers.get("Content-Length")
			if length is not None and int(length) > maximum_bytes:
				raise PublicationPolicyError(f"repository file exceeds the size limit: {url}")
			data = response.read(maximum_bytes + 1)
	except (urllib.error.URLError, OSError, ValueError) as exception:
		raise PublicationPolicyError(f"cannot download {url}: {exception}") from exception
	if len(data) > maximum_bytes:
		raise PublicationPolicyError(f"repository file exceeds the size limit: {url}")
	return data


def verify_publication(
	bundle,
	expected,
	keyring=None,
	expected_fingerprint=None,
	repository=DEFAULT_REPOSITORY,
	timeout_seconds=30,
	skip_signature_verification=False,
	allow_loopback_http=False,
	fetcher=None,
):
	repository = validate_repository(repository, allow_loopback_http=allow_loopback_http)
	local = BUNDLE_VERIFIER.verify_bundle(
		bundle,
		expected,
		keyring=keyring,
		expected_fingerprint=expected_fingerprint,
		skip_signature_verification=skip_signature_verification,
	)
	group_id, artifact_id, version = expected
	repository_path = "/".join((group_id.replace(".", "/"), artifact_id, version))
	payload_names = BUNDLE_VERIFIER.expected_files(artifact_id, version)
	if fetcher is None:
		opener = urllib.request.build_opener(NoRedirectHandler())
		fetcher = lambda url, maximum, timeout: fetch(opener, url, maximum, timeout)
	urls = {}
	remote_files = {}
	for name in payload_names:
		for published_name, maximum in ((name, MAX_PAYLOAD_BYTES), (f"{name}.asc", MAX_SIGNATURE_BYTES)):
			url = f"{repository}/{repository_path}/{published_name}"
			urls[published_name] = url
			remote_files[published_name] = fetcher(url, maximum, timeout_seconds)

	for name in payload_names:
		digest = hashlib.sha256(remote_files[name]).hexdigest()
		if digest != local["payloads"][name]:
			raise PublicationPolicyError(f"published payload differs from approved bundle: {name}")
		signature_name = f"{name}.asc"
		signature_digest = hashlib.sha256(remote_files[signature_name]).hexdigest()
		if signature_digest != local["signatures"][signature_name]:
			raise PublicationPolicyError(f"published signature differs from approved bundle: {signature_name}")

	with tempfile.TemporaryDirectory(prefix="revetsec-central-publication-") as temporary:
		directory = Path(temporary)
		for name, data in remote_files.items():
			(directory / name).write_bytes(data)
		pom_name = f"{artifact_id}-{version}.pom"
		try:
			BUNDLE_VERIFIER.POM_VERIFIER.verify_pom(directory / pom_name, expected)
		except BUNDLE_VERIFIER.POM_VERIFIER.PomPolicyError as exception:
			raise PublicationPolicyError(str(exception)) from exception
		BUNDLE_VERIFIER.verify_release_pom_metadata(
			directory / pom_name, group_id, artifact_id, version
		)
		BUNDLE_VERIFIER.verify_jars(directory, artifact_id, version)
		BUNDLE_VERIFIER.verify_sbom(
			directory / f"{artifact_id}-{version}-cyclonedx.json",
			group_id,
			artifact_id,
			version,
		)
		if not skip_signature_verification:
			published_fingerprint = BUNDLE_VERIFIER.verify_signatures(
				directory, payload_names, keyring, expected_fingerprint
			)
			if published_fingerprint != local["signingFingerprint"]:
				raise PublicationPolicyError("published signatures use a different primary key")

	return {
		"schema": "revetsec.central-publication-verification.v1",
		"verifiedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
		"coordinates": ":".join(expected),
		"repository": repository,
		"approvedBundle": {
			"path": str(bundle),
			"sha256": local["sha256"],
		},
		"files": {
			name: {
				"url": urls[name],
				"sha256": hashlib.sha256(data).hexdigest(),
			}
			for name, data in remote_files.items()
		},
		"signaturesVerified": not skip_signature_verification,
		"signingFingerprint": local["signingFingerprint"],
		"exactBundleContent": True,
	}


def write_receipt(path, result):
	if path.exists() or path.is_symlink():
		raise PublicationPolicyError(f"receipt path already exists: {path}")
	if not path.parent.is_dir():
		raise PublicationPolicyError(f"receipt parent directory does not exist: {path.parent}")
	path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv=None):
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("bundle", type=Path, help="the already verified local Central bundle")
	parser.add_argument("--expect", type=BUNDLE_VERIFIER.parse_coordinates, required=True, metavar="GROUP:ARTIFACT:VERSION")
	parser.add_argument("--keyring", type=Path, help="trusted OpenPGP keyring for gpgv")
	parser.add_argument(
		"--expect-fingerprint",
		help="full uppercase fingerprint of the trusted primary release-signing key",
	)
	parser.add_argument("--repository", default=DEFAULT_REPOSITORY, help="canonical Maven Central repository base")
	parser.add_argument("--timeout", type=int, default=30, help="per-file network timeout in seconds")
	parser.add_argument("--output", type=Path, help="create-new JSON receipt path")
	parser.add_argument(
		"--skip-signature-verification",
		action="store_true",
		help="compare signature bytes without cryptographic verification; intended only for self-tests",
	)
	parser.add_argument(
		"--allow-loopback-http",
		action="store_true",
		help="allow a loopback HTTP repository; intended only for self-tests",
	)
	arguments = parser.parse_args(argv)
	if arguments.timeout < 1 or arguments.timeout > 300:
		parser.error("--timeout must be between 1 and 300 seconds")
	try:
		result = verify_publication(
			arguments.bundle,
			arguments.expect,
			keyring=arguments.keyring,
			expected_fingerprint=arguments.expect_fingerprint,
			repository=arguments.repository,
			timeout_seconds=arguments.timeout,
			skip_signature_verification=arguments.skip_signature_verification,
			allow_loopback_http=arguments.allow_loopback_http,
		)
		if arguments.output:
			write_receipt(arguments.output, result)
	except (BUNDLE_VERIFIER.BundlePolicyError, PublicationPolicyError, OSError) as exception:
		print(f"Central publication verification failed: {exception}", file=sys.stderr)
		return 1
	print(json.dumps(result, indent=2, sort_keys=True))
	return 0


if __name__ == "__main__":
	sys.exit(main())
