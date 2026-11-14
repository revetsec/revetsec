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

"""Verify the canonical public release-signing key and create an identity receipt."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request


SCHEMA = "revetsec.release-signing-key-verification.v1"
CANONICAL_KEY_URL = "https://revetsec.com/security/release-key.asc"
FINGERPRINT = re.compile(r"(?:[0-9A-F]{40}|[0-9A-F]{64})")
MAX_KEY_BYTES = 1024 * 1024


class SigningKeyPolicyError(ValueError):
	"""The published release key is missing, unsafe or has the wrong identity."""


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
	"""Refuse redirects so the canonical key origin cannot change under the client."""

	def redirect_request(self, request, file_pointer, code, message, headers, new_url):
		return None


def fetch_key(url, timeout_seconds):
	opener = urllib.request.build_opener(NoRedirectHandler())
	request = urllib.request.Request(url, headers={"User-Agent": "revetsec-release-verifier/1"})
	try:
		with opener.open(request, timeout=timeout_seconds) as response:
			if response.status != 200:
				raise SigningKeyPolicyError(f"key origin returned HTTP {response.status}")
			length = response.headers.get("Content-Length")
			if length is not None and int(length) > MAX_KEY_BYTES:
				raise SigningKeyPolicyError("published key exceeds the size limit")
			data = response.read(MAX_KEY_BYTES + 1)
	except (urllib.error.URLError, OSError, ValueError) as exception:
		raise SigningKeyPolicyError(f"cannot download the published release key: {exception}") from exception
	if len(data) > MAX_KEY_BYTES:
		raise SigningKeyPolicyError("published key exceeds the size limit")
	return data


def invoke_gpg(arguments, timeout_seconds, command_runner=None):
	if command_runner is not None:
		output = command_runner(arguments, timeout_seconds)
		if not isinstance(output, str):
			raise SigningKeyPolicyError("test GPG runner returned a non-string")
		return output
	try:
		result = subprocess.run(
			arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
			check=False, timeout=timeout_seconds,
		)
	except (OSError, subprocess.TimeoutExpired) as exception:
		raise SigningKeyPolicyError(f"cannot inspect the published release key: {exception}") from exception
	if result.returncode != 0:
		detail = result.stderr.strip() or result.stdout.strip() or "GPG returned no diagnostic"
		raise SigningKeyPolicyError(f"GPG rejected the published release key: {detail}")
	return result.stdout


def parse_timestamp(value, label):
	try:
		seconds = int(value)
	except (TypeError, ValueError) as exception:
		raise SigningKeyPolicyError(f"published key has an invalid {label} timestamp") from exception
	if seconds < 1:
		raise SigningKeyPolicyError(f"published key has an invalid {label} timestamp")
	return seconds


def parse_key_listing(listing, expected_fingerprint, verified_at):
	keys = []
	current = None
	for line in listing.splitlines():
		fields = line.split(":")
		record_type = fields[0] if fields else ""
		if record_type in {"sec", "ssb"}:
			raise SigningKeyPolicyError("published key material contains a secret key")
		if record_type in {"pub", "sub"}:
			if len(fields) < 12:
				raise SigningKeyPolicyError("GPG returned a malformed public-key record")
			expires = None if fields[6] == "" else parse_timestamp(fields[6], "expiration")
			current = {
				"type": "primary" if record_type == "pub" else "subkey",
				"fingerprint": None,
				"validity": fields[1],
				"algorithm": fields[3],
				"created": parse_timestamp(fields[5], "creation"),
				"expires": expires,
				"capabilities": fields[11],
			}
			keys.append(current)
		elif record_type == "fpr" and current is not None and current["fingerprint"] is None:
			if len(fields) < 10 or not FINGERPRINT.fullmatch(fields[9]):
				raise SigningKeyPolicyError("GPG returned a malformed key fingerprint")
			current["fingerprint"] = fields[9]

	primary_keys = [key for key in keys if key["type"] == "primary"]
	if len(primary_keys) != 1:
		raise SigningKeyPolicyError("published key file must contain exactly one primary public key")
	if any(key["fingerprint"] is None for key in keys):
		raise SigningKeyPolicyError("published key listing omitted a key fingerprint")
	primary = primary_keys[0]
	if primary["fingerprint"] != expected_fingerprint:
		raise SigningKeyPolicyError(
			f"published primary fingerprint is {primary['fingerprint']}, expected {expected_fingerprint}"
		)
	verified_seconds = int(verified_at.timestamp())
	for key in keys:
		if key["created"] > verified_seconds:
			raise SigningKeyPolicyError(f"published {key['type']} was created in the future")
	if (
		primary["validity"] in {"d", "e", "r"}
		or primary["expires"] is not None and primary["expires"] <= verified_seconds
	):
		raise SigningKeyPolicyError("published primary key is disabled, expired or revoked")
	signing_keys = [
		key for key in keys
		if "s" in key["capabilities"].lower()
		and key["validity"] not in {"d", "e", "r"}
		and (key["expires"] is None or key["expires"] > verified_seconds)
	]
	if not signing_keys:
		raise SigningKeyPolicyError("published key has no usable signing key")
	return primary, signing_keys


def verify_signing_key(
	url, expected_fingerprint, gpg="gpg", timeout_seconds=30, fetcher=None,
	command_runner=None, now=None,
):
	if url != CANONICAL_KEY_URL:
		raise SigningKeyPolicyError(f"public key URL must be {CANONICAL_KEY_URL}")
	if not isinstance(expected_fingerprint, str) or not FINGERPRINT.fullmatch(expected_fingerprint):
		raise SigningKeyPolicyError("expected fingerprint must be 40 or 64 uppercase hexadecimal characters")
	verified_at = now or datetime.now(timezone.utc)
	if verified_at.tzinfo is None:
		raise SigningKeyPolicyError("verification time must include a timezone")
	key_data = fetch_key(url, timeout_seconds) if fetcher is None else fetcher(
		url, MAX_KEY_BYTES, timeout_seconds
	)
	if not isinstance(key_data, bytes) or not key_data:
		raise SigningKeyPolicyError("published release key is empty or not bytes")
	if len(key_data) > MAX_KEY_BYTES:
		raise SigningKeyPolicyError("published key exceeds the size limit")
	with tempfile.TemporaryDirectory(prefix="revetsec-release-key-") as temporary:
		home = Path(temporary) / "gnupg"
		home.mkdir(mode=0o700)
		key_path = Path(temporary) / "release-key.asc"
		key_path.write_bytes(key_data)
		base = [str(gpg), "--batch", "--no-options", "--homedir", str(home)]
		version_lines = invoke_gpg([str(gpg), "--version"], timeout_seconds, command_runner).splitlines()
		if not version_lines or not version_lines[0].strip():
			raise SigningKeyPolicyError("GPG did not report its version")
		listing = invoke_gpg(
			base + ["--with-colons", "--import-options", "show-only", "--import", str(key_path)],
			timeout_seconds,
			command_runner,
		)
	primary, signing_keys = parse_key_listing(listing, expected_fingerprint, verified_at)
	def key_receipt(key):
		return {
			"fingerprint": key["fingerprint"],
			"type": key["type"],
			"algorithm": key["algorithm"],
			"created": key["created"],
			"expires": key["expires"],
			"capabilities": key["capabilities"],
		}
	return {
		"schema": SCHEMA,
		"verifiedAt": verified_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
		"url": url,
		"publicKey": {
			"sha256": hashlib.sha256(key_data).hexdigest(),
			"sizeBytes": len(key_data),
		},
		"primaryKey": key_receipt(primary),
		"signingKeys": [key_receipt(key) for key in signing_keys],
		"gpgVersion": version_lines[0].strip(),
		"result": "PASS",
	}


def write_receipt(path, result):
	if path.exists() or path.is_symlink():
		raise SigningKeyPolicyError(f"receipt path already exists: {path}")
	if not path.parent.is_dir():
		raise SigningKeyPolicyError(f"receipt parent directory does not exist: {path.parent}")
	path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv=None):
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("--url", default=CANONICAL_KEY_URL, help="canonical public release-key URL")
	parser.add_argument("--expect-fingerprint", required=True, help="full uppercase primary fingerprint")
	parser.add_argument("--gpg", default="gpg", help="GPG executable")
	parser.add_argument("--timeout", type=int, default=30, help="network and GPG timeout in seconds")
	parser.add_argument("--output", type=Path, required=True, help="create-new JSON receipt path")
	arguments = parser.parse_args(argv)
	if arguments.timeout < 1 or arguments.timeout > 300:
		parser.error("--timeout must be between 1 and 300 seconds")
	try:
		result = verify_signing_key(
			arguments.url, arguments.expect_fingerprint, gpg=arguments.gpg,
			timeout_seconds=arguments.timeout,
		)
		write_receipt(arguments.output, result)
	except (SigningKeyPolicyError, OSError) as exception:
		print(f"Release signing-key verification failed: {exception}", file=sys.stderr)
		return 1
	print(json.dumps(result, indent=2, sort_keys=True))
	return 0


if __name__ == "__main__":
	sys.exit(main())
