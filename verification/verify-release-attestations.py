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

"""Cryptographically verify release provenance and CycloneDX attestations."""

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile


BUNDLE_VERIFIER_PATH = Path(__file__).resolve().parent / "verify-central-bundle.py"
SPEC = importlib.util.spec_from_file_location("verify_central_bundle", BUNDLE_VERIFIER_PATH)
BUNDLE_VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUNDLE_VERIFIER)

SCHEMA = "revetsec.release-attestation-verification.v1"
PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1"
CYCLONEDX_PREDICATE = "https://cyclonedx.org/bom"
COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
GH_VERSION = re.compile(r"gh version ([0-9]+)\.([0-9]+)\.([0-9]+)(?:\s|$)")
MINIMUM_GH_VERSION = (2, 102, 0)
MAX_HOSTED_RECEIPT_BYTES = 1024 * 1024
MAX_GH_OUTPUT_BYTES = 32 * 1024 * 1024


class AttestationPolicyError(ValueError):
	"""The release attestations do not prove the required artifact identities."""


def require_safe_gh_version(value):
	if not isinstance(value, str):
		raise AttestationPolicyError("GitHub CLI did not report a parseable version")
	match = GH_VERSION.match(value.strip())
	if match is None:
		raise AttestationPolicyError("GitHub CLI did not report a parseable version")
	version = tuple(int(part) for part in match.groups())
	if version < MINIMUM_GH_VERSION:
		raise AttestationPolicyError("GitHub CLI 2.102.0 or newer is required")
	return value.strip()


def sha256(data):
	return hashlib.sha256(data).hexdigest()


def read_hosted_receipt(path, expected, commit):
	try:
		if path.is_symlink() or not path.is_file():
			raise AttestationPolicyError("hosted-evidence receipt must be a regular file")
		if path.stat().st_size > MAX_HOSTED_RECEIPT_BYTES:
			raise AttestationPolicyError("hosted-evidence receipt exceeds the size limit")
		data = path.read_bytes()
	except OSError as exception:
		raise AttestationPolicyError(f"cannot read hosted-evidence receipt: {exception}") from exception
	try:
		receipt = json.loads(data.decode("utf-8"))
	except (UnicodeError, json.JSONDecodeError) as exception:
		raise AttestationPolicyError("hosted-evidence receipt is not valid UTF-8 JSON") from exception
	if not isinstance(receipt, dict) or set(receipt) != {
		"schema", "verifiedAt", "coordinates", "evidence", "approvedBundle", "payloads",
		"run", "source", "attestations", "signaturesVerified", "signingFingerprint",
		"exactBundleContent",
	}:
		raise AttestationPolicyError("hosted-evidence receipt has an unexpected shape")
	coordinates = ":".join(expected)
	if receipt["schema"] != "revetsec.release-evidence-join.v1" or receipt["coordinates"] != coordinates:
		raise AttestationPolicyError("hosted-evidence receipt identity differs")
	if receipt["signaturesVerified"] is not True or receipt["exactBundleContent"] is not True:
		raise AttestationPolicyError("hosted evidence is not joined to exact signed content")
	group_id, artifact_id, version = expected
	expected_source = {"ref": f"refs/tags/v{version}", "sha": commit}
	if receipt["source"] != expected_source:
		raise AttestationPolicyError("hosted-evidence source differs from the release tag and commit")
	attestations = receipt["attestations"]
	if not isinstance(attestations, dict) or set(attestations) != {"provenance", "sbom"}:
		raise AttestationPolicyError("hosted evidence lacks exact provenance and SBOM identities")
	expected_repository = f"revetsec/{artifact_id}"
	for name, entry in attestations.items():
		if not isinstance(entry, dict) or set(entry) != {"id", "url"}:
			raise AttestationPolicyError(f"hosted {name} attestation has an unexpected shape")
		identifier = entry["id"]
		if isinstance(identifier, bool) or not isinstance(identifier, int) or identifier < 1:
			raise AttestationPolicyError(f"hosted {name} attestation ID is invalid")
		if entry["url"] != f"https://github.com/{expected_repository}/attestations/{identifier}":
			raise AttestationPolicyError(f"hosted {name} attestation URL differs")
	return receipt, data


def extract_payloads(bundle, expected, directory):
	group_id, artifact_id, version = expected
	payload_names = BUNDLE_VERIFIER.expected_files(artifact_id, version)
	prefix = f"{group_id.replace('.', '/')}/{artifact_id}/{version}/"
	try:
		with zipfile.ZipFile(bundle) as archive:
			for name in payload_names:
				(directory / name).write_bytes(archive.read(f"{prefix}{name}"))
	except (OSError, KeyError, zipfile.BadZipFile) as exception:
		raise AttestationPolicyError(f"cannot extract verified bundle payloads: {exception}") from exception
	return payload_names


def invoke(command_runner, arguments, timeout_seconds):
	if command_runner is not None:
		output = command_runner(arguments, timeout_seconds)
		if not isinstance(output, str):
			raise AttestationPolicyError("test command runner returned a non-string")
		return output
	try:
		result = subprocess.run(
			arguments,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			text=True,
			check=False,
			timeout=timeout_seconds,
		)
	except (OSError, subprocess.TimeoutExpired) as exception:
		raise AttestationPolicyError(f"cannot run GitHub CLI: {exception}") from exception
	if result.returncode != 0:
		detail = result.stderr.strip() or result.stdout.strip() or "GitHub CLI returned no diagnostic"
		raise AttestationPolicyError(f"GitHub CLI attestation verification failed: {detail}")
	if len(result.stdout.encode("utf-8")) > MAX_GH_OUTPUT_BYTES:
		raise AttestationPolicyError("GitHub CLI output exceeds the size limit")
	return result.stdout


def parse_gh_results(output, predicate_type, artifact_name, artifact_sha256):
	try:
		results = json.loads(output)
	except json.JSONDecodeError as exception:
		raise AttestationPolicyError("GitHub CLI returned invalid verification JSON") from exception
	if not isinstance(results, list) or not results:
		raise AttestationPolicyError("GitHub CLI returned no verified attestations")
	matches = []
	allowed_subject_names = {artifact_name, f"release-evidence/{artifact_name}"}
	for result in results:
		if not isinstance(result, dict):
			continue
		verification = result.get("verificationResult")
		if not isinstance(verification, dict):
			continue
		statement = verification.get("statement")
		if not isinstance(statement, dict) or statement.get("predicateType") != predicate_type:
			continue
		subjects = statement.get("subject")
		if not isinstance(subjects, list):
			continue
		matched_subject = any(
			isinstance(subject, dict)
			and subject.get("name") in allowed_subject_names
			and isinstance(subject.get("digest"), dict)
			and subject["digest"].get("sha256") == artifact_sha256
			for subject in subjects
		)
		if not matched_subject:
			continue
		timestamps = verification.get("verifiedTimestamps")
		if not isinstance(timestamps, list) or not timestamps:
			continue
		matches.append((statement, len(timestamps)))
	if not matches:
		raise AttestationPolicyError(
			f"no timestamped {predicate_type} attestation matches {artifact_name}"
		)
	return matches


def gh_verify_arguments(gh, artifact, repository, signer_workflow, source_ref, commit, predicate):
	return [
		str(gh), "attestation", "verify", str(artifact),
		"--repo", repository,
		"--signer-workflow", signer_workflow,
		"--source-ref", source_ref,
		"--source-digest", commit,
		"--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
		"--deny-self-hosted-runners",
		"--predicate-type", predicate,
		"--limit", "30",
		"--format", "json",
	]


def verify_attestations(
	bundle,
	hosted_evidence,
	expected,
	commit,
	gh="gh",
	keyring=None,
	expected_fingerprint=None,
	timeout_seconds=120,
	skip_signature_verification=False,
	command_runner=None,
):
	if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
		raise AttestationPolicyError("commit must be a full lowercase SHA")
	bundle_result = BUNDLE_VERIFIER.verify_bundle(
		bundle,
		expected,
		keyring=keyring,
		expected_fingerprint=expected_fingerprint,
		skip_signature_verification=skip_signature_verification,
	)
	hosted, hosted_data = read_hosted_receipt(hosted_evidence, expected, commit)
	if hosted["approvedBundle"].get("sha256") != bundle_result["sha256"]:
		raise AttestationPolicyError("hosted evidence used a different approved bundle")
	if hosted["payloads"] != bundle_result["payloads"]:
		raise AttestationPolicyError("hosted evidence payloads differ from the approved bundle")
	if hosted["signingFingerprint"] != bundle_result["signingFingerprint"]:
		raise AttestationPolicyError("hosted evidence used a different release-signing key")
	group_id, artifact_id, version = expected
	repository = f"revetsec/{artifact_id}"
	signer_workflow = f"{repository}/.github/workflows/release-evidence.yml"
	source_ref = f"refs/tags/v{version}"
	gh_version = invoke(command_runner, [str(gh), "--version"], timeout_seconds).splitlines()
	if not gh_version or not gh_version[0].strip():
		raise AttestationPolicyError("GitHub CLI did not report its version")
	gh_identity = require_safe_gh_version(gh_version[0])

	with tempfile.TemporaryDirectory(prefix="revetsec-release-attestations-") as temporary:
		directory = Path(temporary)
		payload_names = extract_payloads(bundle, expected, directory)
		provenance_subjects = {}
		for name in payload_names:
			path = directory / name
			digest = sha256(path.read_bytes())
			output = invoke(
				command_runner,
				gh_verify_arguments(
					gh, path, repository, signer_workflow, source_ref, commit, PROVENANCE_PREDICATE
				),
				timeout_seconds,
			)
			matches = parse_gh_results(output, PROVENANCE_PREDICATE, name, digest)
			provenance_subjects[name] = {
				"sha256": digest,
				"verifiedAttestations": len(matches),
				"verifiedTimestamps": max(item[1] for item in matches),
			}

		jar_name = f"{artifact_id}-{version}.jar"
		sbom_name = f"{artifact_id}-{version}-cyclonedx.json"
		jar_path = directory / jar_name
		sbom_path = directory / sbom_name
		sbom_digest = sha256(sbom_path.read_bytes())
		try:
			expected_sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
		except (UnicodeError, json.JSONDecodeError) as exception:
			raise AttestationPolicyError("verified bundle SBOM is not valid JSON") from exception
		output = invoke(
			command_runner,
			gh_verify_arguments(
				gh, jar_path, repository, signer_workflow, source_ref, commit, CYCLONEDX_PREDICATE
			),
			timeout_seconds,
		)
		sbom_matches = parse_gh_results(output, CYCLONEDX_PREDICATE, jar_name, sha256(jar_path.read_bytes()))
		matching_predicates = [item for item in sbom_matches if item[0].get("predicate") == expected_sbom]
		if not matching_predicates:
			raise AttestationPolicyError("verified CycloneDX predicate differs from the exact release SBOM")

	return {
		"schema": SCHEMA,
		"verifiedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
		"coordinates": f"{group_id}:{artifact_id}:{version}",
		"repository": repository,
		"source": {"ref": source_ref, "sha": commit},
		"signerWorkflow": signer_workflow,
		"githubCli": gh_identity,
		"approvedBundle": {
			"path": str(bundle),
			"sha256": bundle_result["sha256"],
			"signaturesVerified": bundle_result["signaturesVerified"],
			"signingFingerprint": bundle_result["signingFingerprint"],
		},
		"hostedEvidence": {"path": str(hosted_evidence), "sha256": sha256(hosted_data)},
		"attestations": hosted["attestations"],
		"provenance": {
			"predicateType": PROVENANCE_PREDICATE,
			"subjects": provenance_subjects,
			"allSubjectsVerified": True,
		},
		"sbom": {
			"predicateType": CYCLONEDX_PREDICATE,
			"subject": {"name": jar_name, "sha256": bundle_result["payloads"][jar_name]},
			"sbomSha256": sbom_digest,
			"predicateMatchesSbom": True,
			"verifiedAttestations": len(matching_predicates),
			"verifiedTimestamps": max(item[1] for item in matching_predicates),
		},
		"result": "PASS",
	}


def write_receipt(path, result):
	if path.exists() or path.is_symlink():
		raise AttestationPolicyError(f"receipt path already exists: {path}")
	if not path.parent.is_dir():
		raise AttestationPolicyError(f"receipt parent directory does not exist: {path.parent}")
	path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv=None):
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("--bundle", required=True, type=Path, help="approved signed Central bundle")
	parser.add_argument("--hosted-evidence", required=True, type=Path, help="hosted-evidence join receipt")
	parser.add_argument(
		"--expect", required=True, type=BUNDLE_VERIFIER.parse_coordinates,
		metavar="GROUP:ARTIFACT:VERSION",
	)
	parser.add_argument("--commit", required=True, help="full release commit")
	parser.add_argument("--keyring", type=Path, help="trusted OpenPGP keyring for gpgv")
	parser.add_argument(
		"--expect-fingerprint",
		help="full uppercase fingerprint of the trusted primary release-signing key",
	)
	parser.add_argument("--gh", default="gh", help="GitHub CLI executable")
	parser.add_argument("--timeout", type=int, default=120, help="per-command timeout in seconds")
	parser.add_argument("--output", required=True, type=Path, help="create-new attestation receipt")
	parser.add_argument(
		"--skip-signature-verification", action="store_true",
		help="accept an unsigned test bundle; intended only for verifier self-tests",
	)
	arguments = parser.parse_args(argv)
	if arguments.timeout < 1 or arguments.timeout > 600:
		parser.error("--timeout must be between 1 and 600 seconds")
	try:
		result = verify_attestations(
			arguments.bundle,
			arguments.hosted_evidence,
			arguments.expect,
			arguments.commit,
			gh=arguments.gh,
			keyring=arguments.keyring,
			expected_fingerprint=arguments.expect_fingerprint,
			timeout_seconds=arguments.timeout,
			skip_signature_verification=arguments.skip_signature_verification,
		)
		write_receipt(arguments.output, result)
	except (BUNDLE_VERIFIER.BundlePolicyError, AttestationPolicyError, OSError) as exception:
		print(f"Release attestation verification failed: {exception}", file=sys.stderr)
		return 1
	print(json.dumps(result, indent=2, sort_keys=True))
	return 0


if __name__ == "__main__":
	sys.exit(main())
