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

"""Verify and seal a complete release record with its detached OpenPGP signature."""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile


DIRECTORY = Path(__file__).resolve().parent
RECORD_PATH = DIRECTORY / "verify-release-record.py"
RECORD_SPEC = importlib.util.spec_from_file_location("verify_release_record", RECORD_PATH)
RECORD_VERIFIER = importlib.util.module_from_spec(RECORD_SPEC)
RECORD_SPEC.loader.exec_module(RECORD_VERIFIER)

SCHEMA = "revetsec.release-record-seal.v1"
FINGERPRINT = re.compile(r"(?:[0-9A-F]{40}|[0-9A-F]{64})")
MAX_RECORD_BYTES = 4 * 1024 * 1024
MAX_SIGNATURE_BYTES = 256 * 1024


class RecordSealPolicyError(ValueError):
	"""The final release record or its detached signature is invalid."""


def read_regular(path, maximum_bytes, label):
	try:
		if path.is_symlink() or not path.is_file():
			raise RecordSealPolicyError(f"{label} must be a regular file")
		if path.stat().st_size > maximum_bytes:
			raise RecordSealPolicyError(f"{label} exceeds the size limit")
		data = path.read_bytes()
	except OSError as exception:
		raise RecordSealPolicyError(f"cannot read {label}: {exception}") from exception
	if not data:
		raise RecordSealPolicyError(f"{label} is empty")
	return data


def parse_gpgv_status(status):
	prefix = "[GNUPG:] VALIDSIG "
	valid = [line[len(prefix):].split() for line in status.splitlines() if line.startswith(prefix)]
	if len(valid) != 1 or len(valid[0]) < 9:
		raise RecordSealPolicyError("gpgv did not report exactly one valid record signature")
	fields = valid[0]
	signing_fingerprint = fields[0]
	primary_fingerprint = fields[9] if len(fields) > 9 else signing_fingerprint
	if not FINGERPRINT.fullmatch(signing_fingerprint) or not FINGERPRINT.fullmatch(
		primary_fingerprint
	):
		raise RecordSealPolicyError("gpgv reported a malformed record-signing fingerprint")
	try:
		signed_seconds = int(fields[2])
	except (IndexError, ValueError) as exception:
		raise RecordSealPolicyError("gpgv reported an invalid record-signature time") from exception
	if signed_seconds < 1:
		raise RecordSealPolicyError("gpgv reported an invalid record-signature time")
	return {
		"signingFingerprint": signing_fingerprint,
		"primaryFingerprint": primary_fingerprint,
		"signedAt": datetime.fromtimestamp(signed_seconds, timezone.utc),
	}


def verify_detached_signature(
	record_path, signature_path, keyring, expected_fingerprint, gpgv="gpgv", timeout_seconds=30
):
	keyring = Path(keyring)
	if keyring.is_symlink() or not keyring.is_file():
		raise RecordSealPolicyError("trusted OpenPGP keyring must be a regular file")
	with tempfile.TemporaryDirectory(prefix="revetsec-record-seal-") as temporary:
		command = [
			str(gpgv), "--status-fd=1", "--homedir", temporary,
			"--keyring", str(keyring.resolve()), str(signature_path), str(record_path),
		]
		try:
			result = subprocess.run(
				command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
				check=False, timeout=timeout_seconds,
			)
		except (OSError, subprocess.TimeoutExpired) as exception:
			raise RecordSealPolicyError(f"cannot verify the release-record signature: {exception}") from exception
		if result.returncode != 0:
			detail = result.stderr.strip() or result.stdout.strip() or "gpgv returned no diagnostic"
			raise RecordSealPolicyError(f"release-record signature verification failed: {detail}")
		details = parse_gpgv_status(result.stdout)
	if details["primaryFingerprint"] != expected_fingerprint:
		raise RecordSealPolicyError(
			"release-record signature does not chain to the recorded primary fingerprint"
		)
	return details


def verify_seal(
	record_path,
	signature_path,
	evidence_root,
	keyring,
	gpgv="gpgv",
	timeout_seconds=30,
	signature_checker=None,
	now=None,
):
	record_data = read_regular(record_path, MAX_RECORD_BYTES, "release record")
	signature_data = read_regular(signature_path, MAX_SIGNATURE_BYTES, "release-record signature")
	try:
		record = json.loads(record_data.decode("utf-8"))
	except (UnicodeError, json.JSONDecodeError) as exception:
		raise RecordSealPolicyError("release record is not valid UTF-8 JSON") from exception
	try:
		RECORD_VERIFIER.verify_record(record, final=True)
		RECORD_VERIFIER.verify_evidence(record, evidence_root)
	except RECORD_VERIFIER.ReleaseRecordError as exception:
		raise RecordSealPolicyError(f"release record did not pass final verification: {exception}") from exception
	expected_fingerprint = record["signing"]["fingerprint"]
	checker = signature_checker or (
		lambda: verify_detached_signature(
			record_path, signature_path, keyring, expected_fingerprint,
			gpgv=gpgv, timeout_seconds=timeout_seconds,
		)
	)
	details = checker()
	if not isinstance(details, dict) or set(details) != {
		"signingFingerprint", "primaryFingerprint", "signedAt"
	}:
		raise RecordSealPolicyError("signature checker returned an invalid result")
	if not all(
		isinstance(details[name], str) and FINGERPRINT.fullmatch(details[name])
		for name in ("signingFingerprint", "primaryFingerprint")
	):
		raise RecordSealPolicyError("signature checker returned an invalid fingerprint")
	if details["primaryFingerprint"] != expected_fingerprint:
		raise RecordSealPolicyError(
			"release-record signature does not match the recorded primary fingerprint"
		)
	if not isinstance(details["signedAt"], datetime) or details["signedAt"].tzinfo is None:
		raise RecordSealPolicyError("release-record signature time is invalid")
	released_at = RECORD_VERIFIER.parse_evidence_timestamp(record["releasedAt"], "releasedAt")
	verified_at = now or datetime.now(timezone.utc)
	if verified_at.tzinfo is None:
		raise RecordSealPolicyError("verification time must include a timezone")
	if details["signedAt"] < released_at:
		raise RecordSealPolicyError("release record was signed before its recorded release time")
	if details["signedAt"] > verified_at + timedelta(minutes=5):
		raise RecordSealPolicyError("release-record signature time is in the future")
	return {
		"schema": SCHEMA,
		"verifiedAt": verified_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
		"version": record["version"],
		"releasedAt": record["releasedAt"],
		"record": {
			"path": str(record_path),
			"sha256": hashlib.sha256(record_data).hexdigest(),
		},
		"signature": {
			"path": str(signature_path),
			"sha256": hashlib.sha256(signature_data).hexdigest(),
			"signedAt": details["signedAt"].astimezone(timezone.utc).isoformat().replace(
				"+00:00", "Z"
			),
			"signingFingerprint": details["signingFingerprint"],
			"primaryFingerprint": details["primaryFingerprint"],
		},
		"repositories": [
			{
				"name": repository["name"],
				"commit": repository["commit"],
				"tag": repository["tag"],
			}
			for repository in record["repositories"]
		],
		"evidenceGraphVerified": True,
		"result": "PASS",
	}


def write_receipt(path, result):
	if path.exists() or path.is_symlink():
		raise RecordSealPolicyError(f"receipt path already exists: {path}")
	if not path.parent.is_dir():
		raise RecordSealPolicyError(f"receipt parent directory does not exist: {path.parent}")
	path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv=None):
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("record", type=Path, help="completed RELEASE_RECORD.json")
	parser.add_argument("--signature", type=Path, required=True, help="detached OpenPGP signature")
	parser.add_argument("--evidence-root", type=Path, required=True)
	parser.add_argument("--keyring", type=Path, required=True, help="trusted public release-key keyring")
	parser.add_argument("--gpgv", default="gpgv", help="gpgv executable")
	parser.add_argument("--timeout", type=int, default=30, help="gpgv timeout in seconds")
	parser.add_argument("--output", type=Path, required=True, help="create-new seal receipt path")
	arguments = parser.parse_args(argv)
	if arguments.timeout < 1 or arguments.timeout > 300:
		parser.error("--timeout must be between 1 and 300 seconds")
	try:
		result = verify_seal(
			arguments.record,
			arguments.signature,
			arguments.evidence_root,
			arguments.keyring,
			gpgv=arguments.gpgv,
			timeout_seconds=arguments.timeout,
		)
		write_receipt(arguments.output, result)
	except (OSError, RecordSealPolicyError) as exception:
		print(f"Release-record seal verification failed: {exception}", file=sys.stderr)
		return 1
	print(json.dumps(result, indent=2, sort_keys=True))
	return 0


if __name__ == "__main__":
	sys.exit(main())
