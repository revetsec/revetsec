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

"""Join downloaded GitHub release evidence to an approved signed Central bundle."""

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
import zipfile


BUNDLE_VERIFIER_PATH = Path(__file__).resolve().parent / "verify-central-bundle.py"
SPEC = importlib.util.spec_from_file_location("verify_central_bundle", BUNDLE_VERIFIER_PATH)
BUNDLE_VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUNDLE_VERIFIER)

MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 4096
MAX_ATTESTATION_MANIFEST_BYTES = 16 * 1024
MANIFEST_NAME = "SHA256SUMS"
ATTESTATION_MANIFEST_NAME = "ATTESTATIONS.json"
WORKFLOW_DIRECTORY = "release-evidence"
SHA256_LINE = re.compile(r"([0-9a-f]{64})  release-evidence/([^/]+)")
COMMIT = re.compile(r"[0-9a-f]{40}")


class EvidencePolicyError(ValueError):
	"""The hosted evidence set is unsafe, incomplete or differs from the bundle."""


def required_names(artifact_id, version):
	return (
		*BUNDLE_VERIFIER.expected_files(artifact_id, version),
		MANIFEST_NAME,
		ATTESTATION_MANIFEST_NAME,
	)


def maximum_bytes(name):
	if name == MANIFEST_NAME:
		return MAX_MANIFEST_BYTES
	if name == ATTESTATION_MANIFEST_NAME:
		return MAX_ATTESTATION_MANIFEST_BYTES
	return MAX_PAYLOAD_BYTES


def read_bounded_file(path, maximum):
	if path.is_symlink() or not path.is_file():
		raise EvidencePolicyError(f"evidence entry is not a regular file: {path.name}")
	try:
		if path.stat().st_size > maximum:
			raise EvidencePolicyError(f"evidence entry exceeds its size limit: {path.name}")
		data = path.read_bytes()
	except OSError as exception:
		raise EvidencePolicyError(f"cannot read evidence entry {path.name}: {exception}") from exception
	if len(data) > maximum:
		raise EvidencePolicyError(f"evidence entry exceeds its size limit: {path.name}")
	return data


def read_directory(directory, expected_names):
	try:
		entries = list(directory.iterdir())
	except OSError as exception:
		raise EvidencePolicyError(f"cannot list evidence directory {directory}: {exception}") from exception
	actual = {entry.name for entry in entries}
	if len(actual) != len(entries):
		raise EvidencePolicyError("evidence directory contains duplicate names")
	missing = sorted(set(expected_names).difference(actual))
	unexpected = sorted(actual.difference(expected_names))
	if missing or unexpected:
		raise EvidencePolicyError(
			f"evidence file set differs; missing={missing}, unexpected={unexpected}"
		)
	return {
		name: read_bounded_file(directory / name, maximum_bytes(name))
		for name in expected_names
	}


def normalized_zip_names(archive):
	members = archive.infolist()
	all_names = [member.filename for member in members]
	if len(all_names) != len(set(all_names)):
		raise EvidencePolicyError("evidence ZIP contains duplicate names")
	files = []
	for member in members:
		candidate = member.filename[:-1] if member.is_dir() else member.filename
		path = PurePosixPath(candidate)
		if not candidate or candidate.startswith("/") or "\\" in candidate or ".." in path.parts:
			raise EvidencePolicyError(f"evidence ZIP contains unsafe path {member.filename!r}")
		mode = member.external_attr >> 16
		if stat.S_ISLNK(mode):
			raise EvidencePolicyError(f"evidence ZIP contains a symbolic link: {member.filename}")
		if member.flag_bits & 1:
			raise EvidencePolicyError(f"evidence ZIP contains an encrypted entry: {member.filename}")
		if not member.is_dir():
			files.append(member)
	file_names = [member.filename for member in files]
	if all("/" not in name for name in file_names):
		return {member.filename: member for member in files}
	prefix = f"{WORKFLOW_DIRECTORY}/"
	if all(name.startswith(prefix) and "/" not in name[len(prefix):] for name in file_names):
		return {member.filename[len(prefix):]: member for member in files}
	raise EvidencePolicyError("evidence ZIP files must be at its root or under release-evidence/")


def read_zip(path, expected_names):
	if path.is_symlink() or not path.is_file():
		raise EvidencePolicyError(f"evidence ZIP is not a regular file: {path}")
	try:
		with zipfile.ZipFile(path) as archive:
			members = normalized_zip_names(archive)
			missing = sorted(set(expected_names).difference(members))
			unexpected = sorted(set(members).difference(expected_names))
			if missing or unexpected:
				raise EvidencePolicyError(
					f"evidence file set differs; missing={missing}, unexpected={unexpected}"
				)
			files = {}
			for name in expected_names:
				member = members[name]
				maximum = maximum_bytes(name)
				if member.file_size > maximum:
					raise EvidencePolicyError(f"evidence entry exceeds its size limit: {name}")
				with archive.open(member) as source:
					data = source.read(maximum + 1)
				if len(data) > maximum:
					raise EvidencePolicyError(f"evidence entry exceeds its size limit: {name}")
				files[name] = data
			return files
	except (OSError, RuntimeError, zipfile.BadZipFile) as exception:
		raise EvidencePolicyError(f"cannot read evidence ZIP {path}: {exception}") from exception


def read_evidence(path, artifact_id, version):
	expected_names = required_names(artifact_id, version)
	if path.is_dir():
		return read_directory(path, expected_names)
	return read_zip(path, expected_names)


def verify_manifest(files, payload_names):
	try:
		text = files[MANIFEST_NAME].decode("ascii")
	except UnicodeDecodeError as exception:
		raise EvidencePolicyError("SHA256SUMS is not ASCII") from exception
	lines = text.splitlines()
	if text != "\n".join(lines) + "\n" or len(lines) != len(payload_names):
		raise EvidencePolicyError("SHA256SUMS must contain exactly five newline-terminated entries")
	for line, expected_name in zip(lines, payload_names):
		match = SHA256_LINE.fullmatch(line)
		if not match:
			raise EvidencePolicyError(f"malformed SHA256SUMS entry: {line!r}")
		digest, name = match.groups()
		if name != expected_name:
			raise EvidencePolicyError(
				f"SHA256SUMS entry is out of order or names the wrong file: {name!r}"
			)
		if hashlib.sha256(files[name]).hexdigest() != digest:
			raise EvidencePolicyError(f"incorrect hosted SHA-256 for {name}")


def verify_attestation_manifest(files, expected, commit):
	group_id, artifact_id, version = expected
	if group_id != "com.revetsec" or not COMMIT.fullmatch(commit):
		raise EvidencePolicyError("attestation manifest requires an expected full release commit")
	try:
		document = json.loads(files[ATTESTATION_MANIFEST_NAME].decode("utf-8"))
	except (UnicodeError, json.JSONDecodeError) as exception:
		raise EvidencePolicyError("ATTESTATIONS.json is not valid UTF-8 JSON") from exception
	if not isinstance(document, dict) or set(document) != {
		"schema", "repository", "run", "source", "attestations",
	}:
		raise EvidencePolicyError("ATTESTATIONS.json has an unexpected shape")
	if document["schema"] != "revetsec.release-attestations.v1":
		raise EvidencePolicyError("ATTESTATIONS.json has the wrong schema")
	expected_repository = f"revetsec/{artifact_id}"
	if document["repository"] != expected_repository:
		raise EvidencePolicyError("ATTESTATIONS.json repository differs from the component")
	run = document["run"]
	if not isinstance(run, dict) or set(run) != {"id", "attempt", "url"}:
		raise EvidencePolicyError("ATTESTATIONS.json run has an unexpected shape")
	for field in ("id", "attempt"):
		if isinstance(run[field], bool) or not isinstance(run[field], int) or run[field] < 1:
			raise EvidencePolicyError(f"ATTESTATIONS.json run {field} is invalid")
	expected_run_url = f"https://github.com/{expected_repository}/actions/runs/{run['id']}"
	if run["url"] != expected_run_url:
		raise EvidencePolicyError("ATTESTATIONS.json run URL differs from its identity")
	source = document["source"]
	if not isinstance(source, dict) or set(source) != {"ref", "sha"}:
		raise EvidencePolicyError("ATTESTATIONS.json source has an unexpected shape")
	if source != {"ref": f"refs/tags/v{version}", "sha": commit}:
		raise EvidencePolicyError("ATTESTATIONS.json source differs from the release tag and commit")
	attestations = document["attestations"]
	if not isinstance(attestations, dict) or set(attestations) != {"provenance", "sbom"}:
		raise EvidencePolicyError("ATTESTATIONS.json must name provenance and SBOM attestations")
	identifiers = set()
	for name in ("provenance", "sbom"):
		attestation = attestations[name]
		if not isinstance(attestation, dict) or set(attestation) != {"id", "url"}:
			raise EvidencePolicyError(f"ATTESTATIONS.json {name} entry has an unexpected shape")
		identifier = attestation["id"]
		if isinstance(identifier, bool) or not isinstance(identifier, int) or identifier < 1:
			raise EvidencePolicyError(f"ATTESTATIONS.json {name} ID is invalid")
		if identifier in identifiers:
			raise EvidencePolicyError("ATTESTATIONS.json attestation IDs must be distinct")
		identifiers.add(identifier)
		expected_url = f"https://github.com/{expected_repository}/attestations/{identifier}"
		if attestation["url"] != expected_url:
			raise EvidencePolicyError(f"ATTESTATIONS.json {name} URL differs from its identity")
	return document


def validate_payloads(files, expected):
	group_id, artifact_id, version = expected
	payload_names = BUNDLE_VERIFIER.expected_files(artifact_id, version)
	verify_manifest(files, payload_names)
	with tempfile.TemporaryDirectory(prefix="revetsec-release-evidence-") as temporary:
		directory = Path(temporary)
		for name in payload_names:
			(directory / name).write_bytes(files[name])
		pom_name = f"{artifact_id}-{version}.pom"
		try:
			BUNDLE_VERIFIER.POM_VERIFIER.verify_pom(directory / pom_name, expected)
		except BUNDLE_VERIFIER.POM_VERIFIER.PomPolicyError as exception:
			raise EvidencePolicyError(str(exception)) from exception
		try:
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
		except BUNDLE_VERIFIER.BundlePolicyError as exception:
			raise EvidencePolicyError(str(exception)) from exception
	return {name: hashlib.sha256(files[name]).hexdigest() for name in payload_names}


def verify_evidence(
	evidence, bundle, expected, commit, keyring=None, expected_fingerprint=None,
	skip_signature_verification=False
):
	group_id, artifact_id, version = expected
	files = read_evidence(evidence, artifact_id, version)
	payloads = validate_payloads(files, expected)
	attestation_manifest = verify_attestation_manifest(files, expected, commit)
	bundle_result = BUNDLE_VERIFIER.verify_bundle(
		bundle,
		expected,
		keyring=keyring,
		expected_fingerprint=expected_fingerprint,
		skip_signature_verification=skip_signature_verification,
	)
	mismatches = sorted(
		name for name, digest in payloads.items() if bundle_result["payloads"].get(name) != digest
	)
	if mismatches:
		raise EvidencePolicyError(
			"hosted evidence differs from the approved signed bundle: " + ", ".join(mismatches)
		)
	return {
		"schema": "revetsec.release-evidence-join.v1",
		"verifiedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
		"coordinates": f"{group_id}:{artifact_id}:{version}",
		"evidence": str(evidence),
		"approvedBundle": {"path": str(bundle), "sha256": bundle_result["sha256"]},
		"payloads": payloads,
		"run": attestation_manifest["run"],
		"source": attestation_manifest["source"],
		"attestations": attestation_manifest["attestations"],
		"signaturesVerified": bundle_result["signaturesVerified"],
		"signingFingerprint": bundle_result["signingFingerprint"],
		"exactBundleContent": True,
	}


def write_receipt(path, result):
	if path.exists() or path.is_symlink():
		raise EvidencePolicyError(f"receipt path already exists: {path}")
	if not path.parent.is_dir():
		raise EvidencePolicyError(f"receipt parent directory does not exist: {path.parent}")
	path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv=None):
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("evidence", type=Path, help="downloaded release-evidence directory or ZIP")
	parser.add_argument("--bundle", type=Path, required=True, help="approved signed Central bundle")
	parser.add_argument(
		"--expect", type=BUNDLE_VERIFIER.parse_coordinates, required=True,
		metavar="GROUP:ARTIFACT:VERSION",
	)
	parser.add_argument("--keyring", type=Path, help="trusted OpenPGP keyring for gpgv")
	parser.add_argument(
		"--expect-fingerprint",
		help="full uppercase fingerprint of the trusted primary release-signing key",
	)
	parser.add_argument("--commit", required=True, help="full release commit expected in hosted evidence")
	parser.add_argument("--output", type=Path, help="create-new JSON join receipt path")
	parser.add_argument(
		"--skip-signature-verification", action="store_true",
		help="compare to an unsigned test bundle; intended only for verifier self-tests",
	)
	arguments = parser.parse_args(argv)
	if not COMMIT.fullmatch(arguments.commit):
		parser.error("--commit must be a full lowercase commit SHA")
	try:
		result = verify_evidence(
			arguments.evidence, arguments.bundle, arguments.expect, arguments.commit,
			keyring=arguments.keyring,
			expected_fingerprint=arguments.expect_fingerprint,
			skip_signature_verification=arguments.skip_signature_verification,
		)
		if arguments.output:
			write_receipt(arguments.output, result)
	except (BUNDLE_VERIFIER.BundlePolicyError, EvidencePolicyError, OSError) as exception:
		print(f"Release evidence verification failed: {exception}", file=sys.stderr)
		return 1
	print(json.dumps(result, indent=2, sort_keys=True))
	return 0


if __name__ == "__main__":
	sys.exit(main())
