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

"""Validate the structure and completeness of a Revetsec release record."""

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import urllib.parse


SCHEMA = "revetsec.release-record.v1"
REPOSITORIES = (
	"revetsec",
	"revetsec-soklet",
	"revetsec-servlet-jakarta",
	"revetsec-servlet-javax",
)
ARTIFACTS = {
	"revetsec": "revetsec",
	"revetsec-soklet": "revetsec-soklet",
	"revetsec-servlet-jakarta": "revetsec-servlet-jakarta",
	"revetsec-servlet-javax": "revetsec-servlet-javax",
}
ACCEPTANCE_KEYS = {
	"finalQ5",
	"compatibility",
	"externalQualification",
	"securityClaims",
	"release",
}
PAYLOAD_KEYS = {"pom", "jar", "sources", "javadoc", "sbom"}
SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?")
FINGERPRINT = re.compile(r"(?:[0-9A-F]{40}|[0-9A-F]{64})")
GRADLE_VERSION = "9.8.2"
GRADLE_DISTRIBUTION_SHA256 = "21bd5da2de49b642904077f38c0efdc7778e92b3ed0889392dca61b97e389607"
CANONICAL_SIGNING_KEY_URL = "https://revetsec.com/security/release-key.asc"
GH_VERSION = re.compile(r"gh version ([0-9]+)\.([0-9]+)\.([0-9]+)(?:\s|$)")
MINIMUM_GH_VERSION = (2, 102, 0)


class ReleaseRecordError(ValueError):
	"""The release record is malformed or incomplete."""


def require_mapping(value, label):
	if not isinstance(value, dict):
		raise ReleaseRecordError(f"{label} must be an object")
	return value


def require_exact_keys(value, expected, label):
	actual = set(value)
	if actual != set(expected):
		missing = sorted(set(expected).difference(actual))
		extra = sorted(actual.difference(expected))
		raise ReleaseRecordError(f"{label} keys differ; missing={missing}, extra={extra}")


def require_https(value, label, github_repository=None):
	if not isinstance(value, str):
		raise ReleaseRecordError(f"{label} must be a string")
	parsed = urllib.parse.urlsplit(value)
	if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
		raise ReleaseRecordError(f"{label} must be an HTTPS URL without credentials")
	if parsed.query or parsed.fragment:
		raise ReleaseRecordError(f"{label} must not contain a query or fragment")
	if github_repository:
		expected_prefix = f"/revetsec/{github_repository}/actions/runs/"
		if parsed.netloc != "github.com" or not parsed.path.startswith(expected_prefix):
			raise ReleaseRecordError(f"{label} must name the expected GitHub Actions run")
		if not parsed.path.removeprefix(expected_prefix).isdigit():
			raise ReleaseRecordError(f"{label} has an invalid GitHub Actions run ID")


def require_github_attestation(value, label, github_repository):
	require_https(value, label)
	parsed = urllib.parse.urlsplit(value)
	expected_prefix = f"/revetsec/{github_repository}/attestations/"
	if parsed.netloc != "github.com" or not parsed.path.startswith(expected_prefix):
		raise ReleaseRecordError(f"{label} must name an attestation for the expected GitHub repository")
	if not parsed.path.removeprefix(expected_prefix).isdigit():
		raise ReleaseRecordError(f"{label} has an invalid GitHub attestation ID")


def require_sha256(value, label, final):
	if not isinstance(value, str):
		raise ReleaseRecordError(f"{label} must be a string")
	if final and not SHA256.fullmatch(value):
		raise ReleaseRecordError(f"{label} must be a lowercase SHA-256")


def require_relative_path(value, label, final):
	if not isinstance(value, str):
		raise ReleaseRecordError(f"{label} must be a string")
	if not value and not final:
		return
	path = PurePosixPath(value)
	if not value or value.startswith("/") or "\\" in value or ".." in path.parts:
		raise ReleaseRecordError(f"{label} must be a safe relative path")


def verify_record(record, final=True):
	record = require_mapping(record, "record")
	require_exact_keys(
		record,
		{
			"schema", "version", "disposition", "ownerAcceptance", "repositories",
			"signing", "externalDependencies", "components", "claimsAudit", "documentation",
			"releasedAt", "notes",
		},
		"record",
	)
	if record["schema"] != SCHEMA:
		raise ReleaseRecordError(f"schema must be {SCHEMA}")
	version = record["version"]
	if not isinstance(version, str) or not VERSION.fullmatch(version):
		raise ReleaseRecordError("version must be a literal semantic release version")
	expected_disposition = "RELEASED" if final else "TEMPLATE"
	if record["disposition"] != expected_disposition:
		raise ReleaseRecordError(f"disposition must be {expected_disposition}")

	acceptance = require_mapping(record["ownerAcceptance"], "ownerAcceptance")
	require_exact_keys(acceptance, ACCEPTANCE_KEYS, "ownerAcceptance")
	for name, decision in acceptance.items():
		decision = require_mapping(decision, f"ownerAcceptance.{name}")
		require_exact_keys(decision, {"accepted", "evidence"}, f"ownerAcceptance.{name}")
		if not isinstance(decision["accepted"], bool):
			raise ReleaseRecordError(f"ownerAcceptance.{name}.accepted must be a boolean")
		evidence = require_mapping(decision["evidence"], f"ownerAcceptance.{name}.evidence")
		require_exact_keys(evidence, {"path", "sha256"}, f"ownerAcceptance.{name}.evidence")
		require_relative_path(evidence["path"], f"ownerAcceptance.{name}.evidence.path", final)
		require_sha256(evidence["sha256"], f"ownerAcceptance.{name}.evidence.sha256", final)
		if final and not decision["accepted"]:
			raise ReleaseRecordError(f"ownerAcceptance.{name} is not accepted with evidence")

	repositories = record["repositories"]
	if not isinstance(repositories, list) or len(repositories) != len(REPOSITORIES):
		raise ReleaseRecordError("repositories must contain the four release repositories")
	names = []
	for item in repositories:
		item = require_mapping(item, "repository")
		require_exact_keys(item, {"name", "commit", "tag", "ciRun", "githubReceipt"}, "repository")
		name = item["name"]
		names.append(name)
		if name not in REPOSITORIES:
			raise ReleaseRecordError(f"unexpected repository {name!r}")
		if item["tag"] != f"v{version}":
			raise ReleaseRecordError(f"{name} tag does not match the release version")
		if final:
			if not isinstance(item["commit"], str) or not COMMIT.fullmatch(item["commit"]):
				raise ReleaseRecordError(f"{name} commit must be a full lowercase SHA")
			require_https(item["ciRun"], f"{name} ciRun", github_repository=name)
		elif not isinstance(item["commit"], str) or not isinstance(item["ciRun"], str):
			raise ReleaseRecordError(f"{name} placeholder fields must be strings")
		github_receipt = require_mapping(item["githubReceipt"], f"{name} githubReceipt")
		require_exact_keys(github_receipt, {"path", "sha256"}, f"{name} githubReceipt")
		require_relative_path(github_receipt["path"], f"{name} githubReceipt.path", final)
		require_sha256(github_receipt["sha256"], f"{name} githubReceipt.sha256", final)
	if set(names) != set(REPOSITORIES) or len(names) != len(set(names)):
		raise ReleaseRecordError("repositories must name each release repository exactly once")

	signing = require_mapping(record["signing"], "signing")
	require_exact_keys(signing, {"fingerprint", "publicKeyUrl", "receipt"}, "signing")
	if not isinstance(signing["fingerprint"], str) or not isinstance(signing["publicKeyUrl"], str):
		raise ReleaseRecordError("signing fields must be strings")
	signing_receipt = require_mapping(signing["receipt"], "signing.receipt")
	require_exact_keys(signing_receipt, {"path", "sha256"}, "signing.receipt")
	require_relative_path(signing_receipt["path"], "signing.receipt.path", final)
	require_sha256(signing_receipt["sha256"], "signing.receipt.sha256", final)
	if final:
		if not FINGERPRINT.fullmatch(signing["fingerprint"]):
			raise ReleaseRecordError("signing fingerprint must be 40 or 64 uppercase hexadecimal characters")
		require_https(signing["publicKeyUrl"], "signing.publicKeyUrl")
		if signing["publicKeyUrl"] != CANONICAL_SIGNING_KEY_URL:
			raise ReleaseRecordError(
				f"signing.publicKeyUrl must be {CANONICAL_SIGNING_KEY_URL}"
			)

	external_dependencies = record["externalDependencies"]
	if not isinstance(external_dependencies, list) or len(external_dependencies) != 1:
		raise ReleaseRecordError("externalDependencies must contain the qualified Soklet release")
	external = require_mapping(external_dependencies[0], "external dependency")
	require_exact_keys(
		external, {"coordinates", "repository", "jarSha256", "pomSha256"},
		"external dependency",
	)
	if final:
		try:
			group_id, artifact_id, external_version = external["coordinates"].split(":")
		except (AttributeError, ValueError) as exception:
			raise ReleaseRecordError("external dependency coordinates are invalid") from exception
		if (
			(group_id, artifact_id) != ("com.soklet", "soklet")
			or not VERSION.fullmatch(external_version) or external_version.endswith("-SNAPSHOT")
		):
			raise ReleaseRecordError("external dependency must be a literal Soklet release")
		if external["repository"] != "https://repo.maven.apache.org/maven2":
			raise ReleaseRecordError("external dependency must resolve from canonical Central")
		require_sha256(external["jarSha256"], "external dependency jarSha256", True)
		require_sha256(external["pomSha256"], "external dependency pomSha256", True)
	else:
		for field in ("coordinates", "repository", "jarSha256", "pomSha256"):
			if not isinstance(external[field], str):
				raise ReleaseRecordError(f"external dependency {field} must be a string")

	components = record["components"]
	if not isinstance(components, list) or len(components) != len(REPOSITORIES):
		raise ReleaseRecordError("components must contain all four release artifacts")
	component_repositories = []
	for component in components:
		component = require_mapping(component, "component")
		require_exact_keys(
			component,
			{
				"coordinates", "repository", "localBundleSha256", "secondBundleSha256",
				"bundleEvidence", "reproducibilityReceipt", "payloadSha256", "centralReceipt", "hostedEvidence",
				"attestationReceipt", "provenanceRun", "provenanceAttestations", "consumerReceipt",
			},
			"component",
		)
		repository = component["repository"]
		component_repositories.append(repository)
		if repository not in ARTIFACTS:
			raise ReleaseRecordError(f"component has unexpected repository {repository!r}")
		expected_coordinates = f"com.revetsec:{ARTIFACTS[repository]}:{version}"
		if component["coordinates"] != expected_coordinates:
			raise ReleaseRecordError(f"{repository} coordinates must be {expected_coordinates}")
		require_sha256(component["localBundleSha256"], f"{repository} localBundleSha256", final)
		require_sha256(component["secondBundleSha256"], f"{repository} secondBundleSha256", final)
		bundle_evidence = require_mapping(component["bundleEvidence"], f"{repository} bundleEvidence")
		require_exact_keys(bundle_evidence, {"first", "second"}, f"{repository} bundleEvidence")
		for label in ("first", "second"):
			bundle_ref = require_mapping(
				bundle_evidence[label], f"{repository} bundleEvidence.{label}"
			)
			require_exact_keys(
				bundle_ref, {"path", "sha256"}, f"{repository} bundleEvidence.{label}"
			)
			require_relative_path(
				bundle_ref["path"], f"{repository} bundleEvidence.{label}.path", final
			)
			require_sha256(
				bundle_ref["sha256"], f"{repository} bundleEvidence.{label}.sha256", final
			)
		if final:
			if bundle_evidence["first"]["path"] == bundle_evidence["second"]["path"]:
				raise ReleaseRecordError(f"{repository} signed bundle evidence paths must be distinct")
			if bundle_evidence["first"]["sha256"] != component["localBundleSha256"]:
				raise ReleaseRecordError(f"{repository} first bundle evidence hash differs")
			if bundle_evidence["second"]["sha256"] != component["secondBundleSha256"]:
				raise ReleaseRecordError(f"{repository} second bundle evidence hash differs")
		reproducibility = require_mapping(
			component["reproducibilityReceipt"], f"{repository} reproducibilityReceipt"
		)
		require_exact_keys(
			reproducibility, {"path", "sha256"}, f"{repository} reproducibilityReceipt"
		)
		require_relative_path(
			reproducibility["path"], f"{repository} reproducibilityReceipt.path", final
		)
		require_sha256(
			reproducibility["sha256"], f"{repository} reproducibilityReceipt.sha256", final
		)
		payloads = require_mapping(component["payloadSha256"], f"{repository} payloadSha256")
		require_exact_keys(payloads, PAYLOAD_KEYS, f"{repository} payloadSha256")
		for name, digest in payloads.items():
			require_sha256(digest, f"{repository} payloadSha256.{name}", final)
		receipt = require_mapping(component["centralReceipt"], f"{repository} centralReceipt")
		require_exact_keys(receipt, {"path", "sha256"}, f"{repository} centralReceipt")
		require_relative_path(receipt["path"], f"{repository} centralReceipt.path", final)
		require_sha256(receipt["sha256"], f"{repository} centralReceipt.sha256", final)
		hosted = require_mapping(component["hostedEvidence"], f"{repository} hostedEvidence")
		require_exact_keys(hosted, {"path", "sha256"}, f"{repository} hostedEvidence")
		require_relative_path(hosted["path"], f"{repository} hostedEvidence.path", final)
		require_sha256(hosted["sha256"], f"{repository} hostedEvidence.sha256", final)
		attestation_receipt = require_mapping(
			component["attestationReceipt"], f"{repository} attestationReceipt"
		)
		require_exact_keys(
			attestation_receipt, {"path", "sha256"}, f"{repository} attestationReceipt"
		)
		require_relative_path(
			attestation_receipt["path"], f"{repository} attestationReceipt.path", final
		)
		require_sha256(
			attestation_receipt["sha256"], f"{repository} attestationReceipt.sha256", final
		)
		consumer = require_mapping(component["consumerReceipt"], f"{repository} consumerReceipt")
		require_exact_keys(consumer, {"path", "sha256"}, f"{repository} consumerReceipt")
		require_relative_path(consumer["path"], f"{repository} consumerReceipt.path", final)
		require_sha256(consumer["sha256"], f"{repository} consumerReceipt.sha256", final)
		if final:
			require_https(component["provenanceRun"], f"{repository} provenanceRun", github_repository=repository)
		elif not isinstance(component["provenanceRun"], str):
			raise ReleaseRecordError(f"{repository} provenanceRun must be a string")
		attestations = require_mapping(
			component["provenanceAttestations"], f"{repository} provenanceAttestations"
		)
		require_exact_keys(
			attestations, {"provenance", "sbom"}, f"{repository} provenanceAttestations"
		)
		if not all(isinstance(url, str) for url in attestations.values()):
			raise ReleaseRecordError(f"{repository} provenanceAttestations must be strings")
		if final and not all(attestations.values()):
			raise ReleaseRecordError(f"{repository} must record provenance and SBOM attestations")
		if final and len(set(attestations.values())) != len(attestations):
			raise ReleaseRecordError(f"{repository} provenanceAttestations must be distinct")
		for name, url in attestations.items():
			if final:
				require_github_attestation(
					url,
					f"{repository} provenanceAttestations.{name}",
					repository,
				)
	if set(component_repositories) != set(REPOSITORIES) or len(component_repositories) != len(set(component_repositories)):
		raise ReleaseRecordError("components must name each release repository exactly once")

	claims = require_mapping(record["claimsAudit"], "claimsAudit")
	require_exact_keys(claims, {"path", "sha256"}, "claimsAudit")
	require_relative_path(claims["path"], "claimsAudit.path", final)
	require_sha256(claims["sha256"], "claimsAudit.sha256", final)
	if claims["path"] != "release/SECURITY_CLAIMS_AUDIT.md":
		raise ReleaseRecordError("claimsAudit.path must name release/SECURITY_CLAIMS_AUDIT.md")

	documentation = require_mapping(record["documentation"], "documentation")
	require_exact_keys(documentation, {"receipt"}, "documentation")
	documentation_receipt = require_mapping(documentation["receipt"], "documentation.receipt")
	require_exact_keys(documentation_receipt, {"path", "sha256"}, "documentation.receipt")
	require_relative_path(documentation_receipt["path"], "documentation.receipt.path", final)
	require_sha256(documentation_receipt["sha256"], "documentation.receipt.sha256", final)

	if not isinstance(record["releasedAt"], str):
		raise ReleaseRecordError("releasedAt must be a string")
	if final:
		try:
			released_at = datetime.fromisoformat(record["releasedAt"].replace("Z", "+00:00"))
		except ValueError as exception:
			raise ReleaseRecordError("releasedAt must be an ISO-8601 timestamp") from exception
		if released_at.tzinfo is None:
			raise ReleaseRecordError("releasedAt must include a timezone")
	elif record["releasedAt"]:
		raise ReleaseRecordError("template releasedAt must be empty")
	if not isinstance(record["notes"], list) or not all(isinstance(note, str) for note in record["notes"]):
		raise ReleaseRecordError("notes must be an array of strings")
	return record


def read_evidence_file(root, value, expected_sha256, label):
	require_relative_path(value, label, True)
	root = root.resolve()
	path = (root / value).resolve()
	if not path.is_relative_to(root):
		raise ReleaseRecordError(f"{label} escapes the evidence root")
	try:
		data = path.read_bytes()
	except OSError as exception:
		raise ReleaseRecordError(f"cannot read {label}: {exception}") from exception
	actual = hashlib.sha256(data).hexdigest()
	if actual != expected_sha256:
		raise ReleaseRecordError(f"{label} SHA-256 does not match the release record")
	return path, data


def parse_evidence_timestamp(value, label):
	try:
		parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
	except (AttributeError, ValueError) as exception:
		raise ReleaseRecordError(f"{label} has an invalid timestamp") from exception
	if parsed.tzinfo is None:
		raise ReleaseRecordError(f"{label} timestamp lacks a timezone")
	return parsed


def require_safe_gh_version(value, label):
	if not isinstance(value, str):
		raise ReleaseRecordError(f"{label} is not a parseable GitHub CLI version")
	match = GH_VERSION.match(value.strip())
	if match is None or tuple(int(part) for part in match.groups()) < MINIMUM_GH_VERSION:
		raise ReleaseRecordError(f"{label} must be GitHub CLI 2.102.0 or newer")
	return value.strip()


def verify_signing_key_receipt(record, root, released_at):
	ref = record["signing"]["receipt"]
	path, data = read_evidence_file(root, ref["path"], ref["sha256"], "signing.receipt.path")
	try:
		receipt = json.loads(data.decode("utf-8"))
	except (UnicodeError, json.JSONDecodeError) as exception:
		raise ReleaseRecordError(f"signing-key receipt is not valid UTF-8 JSON: {path}") from exception
	receipt = require_mapping(receipt, "signing-key receipt")
	require_exact_keys(
		receipt,
		{
			"schema", "verifiedAt", "url", "publicKey", "primaryKey", "signingKeys",
			"gpgVersion", "result",
		},
		"signing-key receipt",
	)
	if receipt["schema"] != "revetsec.release-signing-key-verification.v1":
		raise ReleaseRecordError(f"signing-key receipt has the wrong schema: {path}")
	verified_at = parse_evidence_timestamp(receipt["verifiedAt"], "signing-key receipt verifiedAt")
	if verified_at > released_at:
		raise ReleaseRecordError(f"signing-key receipt was verified after releasedAt: {path}")
	if receipt["url"] != record["signing"]["publicKeyUrl"] or receipt["result"] != "PASS":
		raise ReleaseRecordError("signing-key receipt URL or result differs from the release record")
	if not isinstance(receipt["gpgVersion"], str) or not receipt["gpgVersion"].strip():
		raise ReleaseRecordError("signing-key receipt has no GPG identity")
	public_key = require_mapping(receipt["publicKey"], "signing-key receipt publicKey")
	require_exact_keys(public_key, {"sha256", "sizeBytes"}, "signing-key receipt publicKey")
	if (
		not isinstance(public_key["sha256"], str) or not SHA256.fullmatch(public_key["sha256"])
		or isinstance(public_key["sizeBytes"], bool) or not isinstance(public_key["sizeBytes"], int)
		or public_key["sizeBytes"] < 1 or public_key["sizeBytes"] > 1024 * 1024
	):
		raise ReleaseRecordError("signing-key receipt public-key identity is invalid")

	def validate_key(value, label, expected_type=None):
		key = require_mapping(value, label)
		require_exact_keys(
			key, {"fingerprint", "type", "algorithm", "created", "expires", "capabilities"},
			label,
		)
		if not isinstance(key["fingerprint"], str) or not FINGERPRINT.fullmatch(key["fingerprint"]):
			raise ReleaseRecordError(f"{label} fingerprint is invalid")
		if key["type"] not in {"primary", "subkey"} or expected_type and key["type"] != expected_type:
			raise ReleaseRecordError(f"{label} type is invalid")
		if not isinstance(key["algorithm"], str) or not key["algorithm"]:
			raise ReleaseRecordError(f"{label} algorithm is invalid")
		if not isinstance(key["capabilities"], str) or not key["capabilities"]:
			raise ReleaseRecordError(f"{label} capabilities are invalid")
		verified_seconds = int(verified_at.timestamp())
		if (
			isinstance(key["created"], bool) or not isinstance(key["created"], int)
			or key["created"] < 1 or key["created"] > verified_seconds
		):
			raise ReleaseRecordError(f"{label} creation time is invalid")
		if key["expires"] is not None and (
			isinstance(key["expires"], bool) or not isinstance(key["expires"], int)
			or key["expires"] <= verified_seconds
		):
			raise ReleaseRecordError(f"{label} expiration time is invalid")
		return key

	primary = validate_key(receipt["primaryKey"], "signing-key receipt primaryKey", "primary")
	if primary["fingerprint"] != record["signing"]["fingerprint"]:
		raise ReleaseRecordError("signing-key receipt primary fingerprint differs from the release record")
	if not isinstance(receipt["signingKeys"], list) or not receipt["signingKeys"]:
		raise ReleaseRecordError("signing-key receipt has no usable signing key")
	seen = set()
	for index, value in enumerate(receipt["signingKeys"]):
		key = validate_key(value, f"signing-key receipt signingKeys[{index}]")
		if "s" not in key["capabilities"].lower():
			raise ReleaseRecordError(f"signing-key receipt signingKeys[{index}] cannot sign")
		if key["fingerprint"] in seen:
			raise ReleaseRecordError("signing-key receipt contains a duplicate signing key")
		seen.add(key["fingerprint"])
	return receipt


def verify_owner_acceptance_receipts(record, root, released_at):
	expected_repositories = {
		repository["name"]: repository["commit"] for repository in record["repositories"]
	}
	accepted_times = {}
	for gate, decision in record["ownerAcceptance"].items():
		ref = decision["evidence"]
		path, data = read_evidence_file(
			root, ref["path"], ref["sha256"], f"ownerAcceptance.{gate}.evidence.path"
		)
		try:
			receipt = json.loads(data.decode("utf-8"))
		except (UnicodeError, json.JSONDecodeError) as exception:
			raise ReleaseRecordError(
				f"ownerAcceptance.{gate} receipt is not valid UTF-8 JSON: {path}"
			) from exception
		receipt = require_mapping(receipt, f"ownerAcceptance.{gate} receipt")
		require_exact_keys(
			receipt,
			{
				"schema", "version", "gate", "disposition", "acceptedAt", "acceptedBy",
				"repositories", "evidence", "notes",
			},
			f"ownerAcceptance.{gate} receipt",
		)
		if (
			receipt["schema"] != "revetsec.owner-acceptance.v1"
			or receipt["version"] != record["version"]
			or receipt["gate"] != gate
			or receipt["disposition"] != "ACCEPTED"
		):
			raise ReleaseRecordError(f"ownerAcceptance.{gate} receipt identity is invalid")
		accepted_at = parse_evidence_timestamp(
			receipt["acceptedAt"], f"ownerAcceptance.{gate} acceptedAt"
		)
		if accepted_at > released_at:
			raise ReleaseRecordError(f"ownerAcceptance.{gate} was accepted after releasedAt")
		accepted_times[gate] = accepted_at
		if not isinstance(receipt["acceptedBy"], str) or not receipt["acceptedBy"].strip():
			raise ReleaseRecordError(f"ownerAcceptance.{gate} has no accepting owner identity")
		repositories = receipt["repositories"]
		if not isinstance(repositories, list) or len(repositories) != len(REPOSITORIES):
			raise ReleaseRecordError(
				f"ownerAcceptance.{gate} must bind all four release repositories"
			)
		actual_repositories = {}
		for item in repositories:
			item = require_mapping(item, f"ownerAcceptance.{gate} repository")
			require_exact_keys(item, {"name", "commit"}, f"ownerAcceptance.{gate} repository")
			if item["name"] in actual_repositories:
				raise ReleaseRecordError(f"ownerAcceptance.{gate} repeats a repository")
			actual_repositories[item["name"]] = item["commit"]
		if actual_repositories != expected_repositories:
			raise ReleaseRecordError(
				f"ownerAcceptance.{gate} does not bind the exact release commits"
			)
		support = receipt["evidence"]
		if not isinstance(support, list) or not support:
			raise ReleaseRecordError(f"ownerAcceptance.{gate} has no supporting evidence")
		seen = set()
		for index, evidence_ref in enumerate(support):
			label = f"ownerAcceptance.{gate} receipt evidence[{index}]"
			evidence_ref = require_mapping(evidence_ref, label)
			require_exact_keys(evidence_ref, {"path", "sha256"}, label)
			if evidence_ref["path"] == ref["path"]:
				raise ReleaseRecordError(f"{label} cannot refer to its own receipt")
			if evidence_ref["path"] in seen:
				raise ReleaseRecordError(f"ownerAcceptance.{gate} repeats supporting evidence")
			seen.add(evidence_ref["path"])
			read_evidence_file(root, evidence_ref["path"], evidence_ref["sha256"], label)
		if not isinstance(receipt["notes"], list) or not all(
			isinstance(note, str) for note in receipt["notes"]
		):
			raise ReleaseRecordError(f"ownerAcceptance.{gate} notes must be strings")
	return accepted_times


def verify_github_run_receipt(run, label, expected_url, expected_commit, expected_workflow):
	run = require_mapping(run, label)
	require_exact_keys(
		run,
		{
			"url", "id", "workflowPath", "event", "headSha", "createdAt",
			"completedAt", "conclusion",
		},
		label,
	)
	if run["url"] != expected_url:
		raise ReleaseRecordError(f"{label} URL differs from the release record")
	parsed = urllib.parse.urlsplit(run["url"])
	try:
		expected_id = int(parsed.path.rsplit("/", 1)[-1])
	except (TypeError, ValueError) as exception:
		raise ReleaseRecordError(f"{label} URL has an invalid run ID") from exception
	if isinstance(run["id"], bool) or not isinstance(run["id"], int) or run["id"] != expected_id:
		raise ReleaseRecordError(f"{label} ID differs from its URL")
	if run["workflowPath"] != expected_workflow:
		raise ReleaseRecordError(f"{label} workflow path differs")
	if run["event"] != "push" or run["headSha"] != expected_commit or run["conclusion"] != "success":
		raise ReleaseRecordError(f"{label} did not successfully run for the recorded commit")
	created = parse_evidence_timestamp(run["createdAt"], f"{label} createdAt")
	completed = parse_evidence_timestamp(run["completedAt"], f"{label} completedAt")
	if completed < created:
		raise ReleaseRecordError(f"{label} completed before it was created")
	return created, completed


def verify_github_receipts(record, root, components_by_repository):
	released_at = parse_evidence_timestamp(record["releasedAt"], "releasedAt")
	receipt_paths = set()
	times = {}
	for repository in record["repositories"]:
		name = repository["name"]
		reference = repository["githubReceipt"]
		if reference["path"] in receipt_paths:
			raise ReleaseRecordError("GitHub receipt paths must be distinct")
		receipt_paths.add(reference["path"])
		path, data = read_evidence_file(
			root, reference["path"], reference["sha256"], f"{name} githubReceipt.path"
		)
		try:
			receipt = json.loads(data.decode("utf-8"))
		except (UnicodeError, json.JSONDecodeError) as exception:
			raise ReleaseRecordError(f"GitHub receipt is not valid UTF-8 JSON: {path}") from exception
		receipt = require_mapping(receipt, "GitHub receipt")
		require_exact_keys(
			receipt,
			{
				"schema", "verifiedAt", "repository", "commit", "tag", "signedTag",
				"ciRun", "releaseEvidenceRun", "release", "result",
			},
			"GitHub receipt",
		)
		if receipt["schema"] != "revetsec.github-release-verification.v1":
			raise ReleaseRecordError(f"GitHub receipt has the wrong schema: {path}")
		verified_at = parse_evidence_timestamp(receipt["verifiedAt"], "GitHub receipt verifiedAt")
		if verified_at > released_at:
			raise ReleaseRecordError(f"GitHub receipt for {name} was verified after releasedAt")
		if (
			receipt["repository"] != name or receipt["commit"] != repository["commit"]
			or receipt["tag"] != repository["tag"] or receipt["result"] != "PASS"
		):
			raise ReleaseRecordError(f"GitHub receipt identity or result differs for {name}")

		signed_tag = require_mapping(receipt["signedTag"], "GitHub receipt signedTag")
		require_exact_keys(
			signed_tag,
			{
				"objectSha", "targetSha", "taggedAt", "signatureVerified",
				"verificationReason",
			},
			"GitHub receipt signedTag",
		)
		if not isinstance(signed_tag["objectSha"], str) or not COMMIT.fullmatch(signed_tag["objectSha"]):
			raise ReleaseRecordError(f"GitHub receipt tag object SHA is invalid for {name}")
		if (
			signed_tag["targetSha"] != repository["commit"]
			or signed_tag["signatureVerified"] is not True
			or signed_tag["verificationReason"] != "valid"
		):
			raise ReleaseRecordError(f"GitHub receipt does not prove the signed tag target for {name}")
		tagged_at = parse_evidence_timestamp(signed_tag["taggedAt"], "GitHub receipt signedTag.taggedAt")

		ci_created, ci_completed = verify_github_run_receipt(
			receipt["ciRun"],
			"GitHub receipt ciRun",
			repository["ciRun"],
			repository["commit"],
			".github/workflows/ci.yml",
		)
		component = components_by_repository[name]
		evidence_created, evidence_completed = verify_github_run_receipt(
			receipt["releaseEvidenceRun"],
			"GitHub receipt releaseEvidenceRun",
			component["provenanceRun"],
			repository["commit"],
			".github/workflows/release-evidence.yml",
		)
		if ci_completed > evidence_created:
			raise ReleaseRecordError(
				f"GitHub receipt CI did not complete before release evidence started for {name}"
			)
		if tagged_at > evidence_created:
			raise ReleaseRecordError(
				f"GitHub receipt release evidence started before the signed tag existed for {name}"
			)

		release = require_mapping(receipt["release"], "GitHub receipt release")
		require_exact_keys(
			release, {"url", "id", "publishedAt", "draft", "prerelease"}, "GitHub receipt release"
		)
		expected_release_url = f"https://github.com/revetsec/{name}/releases/tag/{repository['tag']}"
		if release["url"] != expected_release_url:
			raise ReleaseRecordError(f"GitHub Release URL differs for {name}")
		if isinstance(release["id"], bool) or not isinstance(release["id"], int) or release["id"] < 1:
			raise ReleaseRecordError(f"GitHub Release ID is invalid for {name}")
		if release["draft"] is not False or release["prerelease"] is not False:
			raise ReleaseRecordError(f"GitHub Release is draft or prerelease for {name}")
		published_at = parse_evidence_timestamp(release["publishedAt"], "GitHub receipt release.publishedAt")
		if evidence_completed > published_at:
			raise ReleaseRecordError(f"GitHub Release predates release evidence for {name}")
		if published_at > verified_at or verified_at > released_at:
			raise ReleaseRecordError(f"GitHub receipt chronology is invalid for {name}")
		times[name] = {
			"evidenceCompleted": evidence_completed,
			"releasePublished": published_at,
			"verified": verified_at,
		}
	return times


def verify_evidence(record, evidence_root):
	root = Path(evidence_root)
	if not root.is_dir():
		raise ReleaseRecordError(f"evidence root is not a directory: {root}")
	released_at = parse_evidence_timestamp(record["releasedAt"], "releasedAt")
	signing_receipt = verify_signing_key_receipt(record, root, released_at)
	signing_at = parse_evidence_timestamp(
		signing_receipt["verifiedAt"], "signing-key receipt verifiedAt"
	)
	acceptance_times = verify_owner_acceptance_receipts(record, root, released_at)

	claims = record["claimsAudit"]
	read_evidence_file(root, claims["path"], claims["sha256"], "claimsAudit.path")
	components_by_coordinates = {
		component["coordinates"]: component for component in record["components"]
	}
	components_by_repository = {
		component["repository"]: component for component in record["components"]
	}
	repositories_by_name = {
		repository["name"]: repository for repository in record["repositories"]
	}
	central_by_coordinates = {}
	component_times = {}
	core_coordinates = f"com.revetsec:revetsec:{record['version']}"
	core_component = components_by_coordinates[core_coordinates]
	external_dependency = record["externalDependencies"][0]
	for component in record["components"]:
		coordinates = component["coordinates"]
		timing = {}
		component_times[component["repository"]] = timing
		group_id, artifact_id, version = coordinates.split(":")
		prefix = f"{artifact_id}-{version}"
		payload_names = {
			"pom": f"{prefix}.pom",
			"jar": f"{prefix}.jar",
			"sources": f"{prefix}-sources.jar",
			"javadoc": f"{prefix}-javadoc.jar",
			"sbom": f"{prefix}-cyclonedx.json",
		}
		for label, expected_sha256 in (
			("first", component["localBundleSha256"]),
			("second", component["secondBundleSha256"]),
		):
			bundle_ref = component["bundleEvidence"][label]
			read_evidence_file(
				root,
				bundle_ref["path"],
				expected_sha256,
				f"{component['repository']} bundleEvidence.{label}.path",
			)
		reproducibility_ref = component["reproducibilityReceipt"]
		reproducibility_path, reproducibility_data = read_evidence_file(
			root,
			reproducibility_ref["path"],
			reproducibility_ref["sha256"],
			f"{component['repository']} reproducibilityReceipt.path",
		)
		try:
			reproducibility = json.loads(reproducibility_data.decode("utf-8"))
		except (UnicodeError, json.JSONDecodeError) as exception:
			raise ReleaseRecordError(
				f"reproducibility receipt is not valid UTF-8 JSON: {reproducibility_path}"
			) from exception
		reproducibility = require_mapping(reproducibility, "reproducibility receipt")
		require_exact_keys(
			reproducibility,
			{
				"schema", "verifiedAt", "coordinates", "firstBundle", "secondBundle",
				"payloads", "payloadsMatch",
			},
			"reproducibility receipt",
		)
		if reproducibility["schema"] != "revetsec.central-bundle-reproducibility.v1":
			raise ReleaseRecordError(
				f"reproducibility receipt has the wrong schema: {reproducibility_path}"
			)
		reproducibility_at = parse_evidence_timestamp(
			reproducibility["verifiedAt"], "reproducibility receipt verifiedAt"
		)
		if reproducibility_at > released_at:
			raise ReleaseRecordError(
				f"reproducibility receipt was verified after releasedAt: {reproducibility_path}"
			)
		if signing_at > reproducibility_at:
			raise ReleaseRecordError(
				f"reproducibility verification predates signing-key verification for {coordinates}"
			)
		timing["reproducibility"] = reproducibility_at
		if reproducibility["coordinates"] != coordinates:
			raise ReleaseRecordError(f"reproducibility coordinates differ for {coordinates}")
		for label, expected_sha256 in (
			("firstBundle", component["localBundleSha256"]),
			("secondBundle", component["secondBundleSha256"]),
		):
			bundle = require_mapping(reproducibility[label], f"reproducibility receipt {label}")
			require_exact_keys(
				bundle, {"path", "sha256", "signaturesVerified", "signingFingerprint"},
				f"reproducibility receipt {label}",
			)
			if not isinstance(bundle["path"], str) or not bundle["path"]:
				raise ReleaseRecordError(f"reproducibility receipt {label} path is empty")
			if bundle["sha256"] != expected_sha256:
				raise ReleaseRecordError(
					f"reproducibility receipt {label} differs from the recorded bundle"
				)
			if bundle["signaturesVerified"] is not True:
				raise ReleaseRecordError(
					f"reproducibility receipt {label} signatures were not verified"
				)
			if bundle["signingFingerprint"] != record["signing"]["fingerprint"]:
				raise ReleaseRecordError(
					f"reproducibility receipt {label} used a different release-signing key"
				)
		reproducible_payloads = require_mapping(
			reproducibility["payloads"], "reproducibility receipt payloads"
		)
		if set(reproducible_payloads) != set(payload_names.values()):
			raise ReleaseRecordError(f"reproducibility payload set is incomplete for {coordinates}")
		for logical_name, published_name in payload_names.items():
			if reproducible_payloads[published_name] != component["payloadSha256"][logical_name]:
				raise ReleaseRecordError(
					f"reproducibility payload hash differs for {published_name}"
				)
		if reproducibility["payloadsMatch"] is not True:
			raise ReleaseRecordError(f"release payloads were not reproducible for {coordinates}")

		hosted_ref = component["hostedEvidence"]
		hosted_path, hosted_data = read_evidence_file(
			root,
			hosted_ref["path"],
			hosted_ref["sha256"],
			f"{component['repository']} hostedEvidence.path",
		)
		try:
			hosted = json.loads(hosted_data.decode("utf-8"))
		except (UnicodeError, json.JSONDecodeError) as exception:
			raise ReleaseRecordError(f"hosted evidence receipt is not valid UTF-8 JSON: {hosted_path}") from exception
		hosted = require_mapping(hosted, "hosted evidence receipt")
		require_exact_keys(
			hosted,
			{
				"schema", "verifiedAt", "coordinates", "evidence", "approvedBundle",
				"payloads", "run", "source", "attestations", "signaturesVerified",
				"signingFingerprint", "exactBundleContent",
			},
			"hosted evidence receipt",
		)
		if hosted["schema"] != "revetsec.release-evidence-join.v1":
			raise ReleaseRecordError(f"hosted evidence receipt has the wrong schema: {hosted_path}")
		hosted_at = parse_evidence_timestamp(
			hosted["verifiedAt"], "hosted evidence receipt verifiedAt"
		)
		if hosted_at > released_at:
			raise ReleaseRecordError(f"hosted evidence was verified after releasedAt: {hosted_path}")
		if signing_at > hosted_at:
			raise ReleaseRecordError(
				f"hosted evidence verification predates signing-key verification for {coordinates}"
			)
		timing["hosted"] = hosted_at
		if hosted["coordinates"] != coordinates:
			raise ReleaseRecordError(f"hosted evidence coordinates do not match {coordinates}")
		if not isinstance(hosted["evidence"], str) or not hosted["evidence"]:
			raise ReleaseRecordError(f"hosted evidence receipt has no evidence source: {hosted_path}")
		if hosted["signaturesVerified"] is not True or hosted["exactBundleContent"] is not True:
			raise ReleaseRecordError(f"hosted evidence is not joined to exact signed content: {hosted_path}")
		if hosted["signingFingerprint"] != record["signing"]["fingerprint"]:
			raise ReleaseRecordError(f"hosted evidence used a different release-signing key: {hosted_path}")
		hosted_bundle = require_mapping(hosted["approvedBundle"], "hosted evidence approvedBundle")
		require_exact_keys(hosted_bundle, {"path", "sha256"}, "hosted evidence approvedBundle")
		if not isinstance(hosted_bundle["path"], str) or not hosted_bundle["path"]:
			raise ReleaseRecordError(f"hosted evidence approved bundle path is invalid: {hosted_path}")
		if hosted_bundle["sha256"] != component["localBundleSha256"]:
			raise ReleaseRecordError(f"hosted evidence approved bundle does not match {coordinates}")
		hosted_payloads = require_mapping(hosted["payloads"], "hosted evidence payloads")
		if set(hosted_payloads) != set(payload_names.values()):
			raise ReleaseRecordError(f"hosted evidence payload set is incomplete for {coordinates}")
		for logical_name, published_name in payload_names.items():
			if hosted_payloads[published_name] != component["payloadSha256"][logical_name]:
				raise ReleaseRecordError(f"hosted evidence payload hash differs for {published_name}")
		repository_record = repositories_by_name[component["repository"]]
		hosted_run = require_mapping(hosted["run"], "hosted evidence run")
		require_exact_keys(hosted_run, {"id", "attempt", "url"}, "hosted evidence run")
		for field in ("id", "attempt"):
			if (
				isinstance(hosted_run[field], bool) or not isinstance(hosted_run[field], int)
				or hosted_run[field] < 1
			):
				raise ReleaseRecordError(f"hosted evidence run {field} is invalid")
		if hosted_run["url"] != component["provenanceRun"]:
			raise ReleaseRecordError(f"hosted evidence run differs for {coordinates}")
		if not hosted_run["url"].endswith(f"/actions/runs/{hosted_run['id']}"):
			raise ReleaseRecordError(f"hosted evidence run ID differs from its URL for {coordinates}")
		hosted_source = require_mapping(hosted["source"], "hosted evidence source")
		require_exact_keys(hosted_source, {"ref", "sha"}, "hosted evidence source")
		if hosted_source != {
			"ref": f"refs/tags/{repository_record['tag']}",
			"sha": repository_record["commit"],
		}:
			raise ReleaseRecordError(f"hosted evidence source differs for {coordinates}")
		hosted_attestations = require_mapping(hosted["attestations"], "hosted evidence attestations")
		require_exact_keys(
			hosted_attestations, {"provenance", "sbom"}, "hosted evidence attestations"
		)
		attestation_ids = set()
		for name, expected_url in component["provenanceAttestations"].items():
			attestation = require_mapping(
				hosted_attestations[name], f"hosted evidence {name} attestation"
			)
			require_exact_keys(
				attestation, {"id", "url"}, f"hosted evidence {name} attestation"
			)
			identifier = attestation["id"]
			if isinstance(identifier, bool) or not isinstance(identifier, int) or identifier < 1:
				raise ReleaseRecordError(f"hosted evidence {name} attestation ID is invalid")
			if identifier in attestation_ids:
				raise ReleaseRecordError("hosted evidence attestation IDs must be distinct")
			attestation_ids.add(identifier)
			if attestation["url"] != expected_url or not expected_url.endswith(
				f"/attestations/{identifier}"
			):
				raise ReleaseRecordError(
					f"hosted evidence {name} attestation differs for {coordinates}"
				)

		attestation_ref = component["attestationReceipt"]
		attestation_path, attestation_data = read_evidence_file(
			root,
			attestation_ref["path"],
			attestation_ref["sha256"],
			f"{component['repository']} attestationReceipt.path",
		)
		try:
			attestation_receipt = json.loads(attestation_data.decode("utf-8"))
		except (UnicodeError, json.JSONDecodeError) as exception:
			raise ReleaseRecordError(
				f"attestation receipt is not valid UTF-8 JSON: {attestation_path}"
			) from exception
		attestation_receipt = require_mapping(attestation_receipt, "attestation receipt")
		require_exact_keys(
			attestation_receipt,
			{
				"schema", "verifiedAt", "coordinates", "repository", "source",
				"signerWorkflow", "githubCli", "approvedBundle", "hostedEvidence",
				"attestations", "provenance", "sbom", "result",
			},
			"attestation receipt",
		)
		if attestation_receipt["schema"] != "revetsec.release-attestation-verification.v1":
			raise ReleaseRecordError(f"attestation receipt has the wrong schema: {attestation_path}")
		attestation_at = parse_evidence_timestamp(
			attestation_receipt["verifiedAt"], "attestation receipt verifiedAt"
		)
		if attestation_at > released_at:
			raise ReleaseRecordError(f"attestation receipt was verified after releasedAt: {attestation_path}")
		if attestation_at < hosted_at:
			raise ReleaseRecordError(
				f"attestation verification predates its hosted-evidence join for {coordinates}"
			)
		timing["attestation"] = attestation_at
		expected_repository = f"revetsec/{artifact_id}"
		expected_source = {
			"ref": f"refs/tags/{repository_record['tag']}",
			"sha": repository_record["commit"],
		}
		if (
			attestation_receipt["coordinates"] != coordinates
			or attestation_receipt["repository"] != expected_repository
			or attestation_receipt["source"] != expected_source
			or attestation_receipt["signerWorkflow"]
			!= f"{expected_repository}/.github/workflows/release-evidence.yml"
			or attestation_receipt["result"] != "PASS"
		):
			raise ReleaseRecordError(f"attestation receipt identity or result differs for {coordinates}")
		require_safe_gh_version(
			attestation_receipt["githubCli"], "attestation receipt githubCli"
		)
		attested_bundle = require_mapping(
			attestation_receipt["approvedBundle"], "attestation receipt approvedBundle"
		)
		require_exact_keys(
			attested_bundle,
			{"path", "sha256", "signaturesVerified", "signingFingerprint"},
			"attestation receipt approvedBundle",
		)
		if (
			not isinstance(attested_bundle["path"], str) or not attested_bundle["path"]
			or attested_bundle["sha256"] != component["localBundleSha256"]
			or attested_bundle["signaturesVerified"] is not True
			or attested_bundle["signingFingerprint"] != record["signing"]["fingerprint"]
		):
			raise ReleaseRecordError(f"attestation receipt approved bundle differs for {coordinates}")
		attested_hosted = require_mapping(
			attestation_receipt["hostedEvidence"], "attestation receipt hostedEvidence"
		)
		require_exact_keys(
			attested_hosted, {"path", "sha256"}, "attestation receipt hostedEvidence"
		)
		if (
			not isinstance(attested_hosted["path"], str) or not attested_hosted["path"]
			or attested_hosted["sha256"] != hosted_ref["sha256"]
		):
			raise ReleaseRecordError(f"attestation receipt used different hosted evidence for {coordinates}")
		if attestation_receipt["attestations"] != hosted_attestations:
			raise ReleaseRecordError(f"attestation receipt identities differ from hosted evidence for {coordinates}")

		provenance = require_mapping(attestation_receipt["provenance"], "attestation receipt provenance")
		require_exact_keys(
			provenance, {"predicateType", "subjects", "allSubjectsVerified"},
			"attestation receipt provenance",
		)
		if (
			provenance["predicateType"] != "https://slsa.dev/provenance/v1"
			or provenance["allSubjectsVerified"] is not True
		):
			raise ReleaseRecordError(f"provenance attestation verification is incomplete for {coordinates}")
		provenance_subjects = require_mapping(
			provenance["subjects"], "attestation receipt provenance subjects"
		)
		if set(provenance_subjects) != set(payload_names.values()):
			raise ReleaseRecordError(f"provenance subject set is incomplete for {coordinates}")
		for logical_name, published_name in payload_names.items():
			subject = require_mapping(
				provenance_subjects[published_name], f"provenance subject {published_name}"
			)
			require_exact_keys(
				subject, {"sha256", "verifiedAttestations", "verifiedTimestamps"},
				f"provenance subject {published_name}",
			)
			if subject["sha256"] != component["payloadSha256"][logical_name]:
				raise ReleaseRecordError(f"provenance subject hash differs for {published_name}")
			for field in ("verifiedAttestations", "verifiedTimestamps"):
				if isinstance(subject[field], bool) or not isinstance(subject[field], int) or subject[field] < 1:
					raise ReleaseRecordError(
						f"provenance subject {published_name} has no verified {field}"
					)

		sbom_attestation = require_mapping(attestation_receipt["sbom"], "attestation receipt sbom")
		require_exact_keys(
			sbom_attestation,
			{
				"predicateType", "subject", "sbomSha256", "predicateMatchesSbom",
				"verifiedAttestations", "verifiedTimestamps",
			},
			"attestation receipt sbom",
		)
		jar_name = payload_names["jar"]
		if (
			sbom_attestation["predicateType"] != "https://cyclonedx.org/bom"
			or sbom_attestation["subject"]
			!= {"name": jar_name, "sha256": component["payloadSha256"]["jar"]}
			or sbom_attestation["sbomSha256"] != component["payloadSha256"]["sbom"]
			or sbom_attestation["predicateMatchesSbom"] is not True
		):
			raise ReleaseRecordError(f"SBOM attestation differs from release payloads for {coordinates}")
		for field in ("verifiedAttestations", "verifiedTimestamps"):
			if (
				isinstance(sbom_attestation[field], bool)
				or not isinstance(sbom_attestation[field], int)
				or sbom_attestation[field] < 1
			):
				raise ReleaseRecordError(f"SBOM attestation has no verified {field} for {coordinates}")

		receipt_ref = component["centralReceipt"]
		path, data = read_evidence_file(
			root,
			receipt_ref["path"],
			receipt_ref["sha256"],
			f"{component['repository']} centralReceipt.path",
		)
		try:
			receipt = json.loads(data.decode("utf-8"))
		except (UnicodeError, json.JSONDecodeError) as exception:
			raise ReleaseRecordError(f"Central receipt is not valid UTF-8 JSON: {path}") from exception
		receipt = require_mapping(receipt, "Central receipt")
		require_exact_keys(
			receipt,
			{
				"schema", "verifiedAt", "coordinates", "repository", "approvedBundle",
				"files", "signaturesVerified", "signingFingerprint", "exactBundleContent",
			},
			"Central receipt",
		)
		if receipt["schema"] != "revetsec.central-publication-verification.v1":
			raise ReleaseRecordError(f"Central receipt has the wrong schema: {path}")
		verified_at = parse_evidence_timestamp(receipt["verifiedAt"], "Central receipt verifiedAt")
		if verified_at > released_at:
			raise ReleaseRecordError(f"Central receipt was verified after releasedAt: {path}")
		if verified_at < max(reproducibility_at, hosted_at, attestation_at):
			raise ReleaseRecordError(
				f"Central publication verification predates prepublication evidence for {coordinates}"
			)
		timing["central"] = verified_at
		if receipt["coordinates"] != coordinates:
			raise ReleaseRecordError(f"Central receipt coordinates do not match {coordinates}")
		if receipt["signaturesVerified"] is not True or receipt["exactBundleContent"] is not True:
			raise ReleaseRecordError(f"Central receipt does not verify exact signed content: {path}")
		if receipt["signingFingerprint"] != record["signing"]["fingerprint"]:
			raise ReleaseRecordError(f"Central receipt used a different release-signing key: {path}")
		repository = receipt["repository"]
		if repository not in (
			"https://repo.maven.apache.org/maven2",
			"https://repo1.maven.org/maven2",
		):
			raise ReleaseRecordError(f"Central receipt uses a noncanonical repository: {path}")
		bundle = require_mapping(receipt["approvedBundle"], "Central receipt approvedBundle")
		require_exact_keys(bundle, {"path", "sha256"}, "Central receipt approvedBundle")
		if not isinstance(bundle["path"], str) or not bundle["path"]:
			raise ReleaseRecordError(f"Central receipt approved bundle path is invalid: {path}")
		if bundle["sha256"] != component["localBundleSha256"]:
			raise ReleaseRecordError(f"Central receipt approved bundle does not match {coordinates}")
		files = require_mapping(receipt["files"], "Central receipt files")
		expected_names = set(payload_names.values())
		expected_names.update(f"{name}.asc" for name in payload_names.values())
		if set(files) != expected_names:
			raise ReleaseRecordError(f"Central receipt file set is incomplete for {coordinates}")
		base = f"{repository}/{group_id.replace('.', '/')}/{artifact_id}/{version}"
		for logical_name, published_name in payload_names.items():
			entry = require_mapping(files[published_name], f"Central receipt {published_name}")
			require_exact_keys(entry, {"url", "sha256"}, f"Central receipt {published_name}")
			if entry["sha256"] != component["payloadSha256"][logical_name]:
				raise ReleaseRecordError(f"Central receipt payload hash differs for {published_name}")
			if entry["url"] != f"{base}/{published_name}":
				raise ReleaseRecordError(f"Central receipt URL differs for {published_name}")
			signature_name = f"{published_name}.asc"
			signature = require_mapping(files[signature_name], f"Central receipt {signature_name}")
			require_exact_keys(signature, {"url", "sha256"}, f"Central receipt {signature_name}")
			if not isinstance(signature["sha256"], str) or not SHA256.fullmatch(signature["sha256"]):
				raise ReleaseRecordError(f"Central receipt signature hash is invalid for {signature_name}")
			if signature["url"] != f"{base}/{signature_name}":
				raise ReleaseRecordError(f"Central receipt URL differs for {signature_name}")
		central_by_coordinates[coordinates] = {
			"receiptSha256": receipt_ref["sha256"],
			"javadocUrl": files[payload_names["javadoc"]]["url"],
			"javadocSha256": files[payload_names["javadoc"]]["sha256"],
		}

		consumer_ref = component["consumerReceipt"]
		consumer_path, consumer_data = read_evidence_file(
			root,
			consumer_ref["path"],
			consumer_ref["sha256"],
			f"{component['repository']} consumerReceipt.path",
		)
		try:
			consumer = json.loads(consumer_data.decode("utf-8"))
		except (UnicodeError, json.JSONDecodeError) as exception:
			raise ReleaseRecordError(f"consumer receipt is not valid UTF-8 JSON: {consumer_path}") from exception
		consumer = require_mapping(consumer, "consumer receipt")
		require_exact_keys(
			consumer,
			{
				"schema", "verifiedAt", "coordinates", "repository", "javaHome",
				"centralReceipt", "componentDependencies", "artifacts", "maven", "gradle",
				"result",
			},
			"consumer receipt",
		)
		if consumer["schema"] != "revetsec.central-consumer-verification.v1":
			raise ReleaseRecordError(f"consumer receipt has the wrong schema: {consumer_path}")
		consumer_at = parse_evidence_timestamp(consumer["verifiedAt"], "consumer receipt verifiedAt")
		if consumer_at > released_at:
			raise ReleaseRecordError(f"consumer receipt was verified after releasedAt: {consumer_path}")
		if consumer_at < verified_at:
			raise ReleaseRecordError(
				f"consumer verification predates Central publication verification for {coordinates}"
			)
		timing["consumer"] = consumer_at
		if consumer["coordinates"] != coordinates:
			raise ReleaseRecordError(f"consumer receipt coordinates do not match {coordinates}")
		if consumer["repository"] != "https://repo.maven.apache.org/maven2":
			raise ReleaseRecordError(f"consumer receipt did not resolve from canonical Central: {consumer_path}")
		if not isinstance(consumer["javaHome"], str) or not consumer["javaHome"]:
			raise ReleaseRecordError(f"consumer receipt has no Java home: {consumer_path}")
		if consumer["result"] != "PASS":
			raise ReleaseRecordError(f"consumer receipt did not pass: {consumer_path}")
		consumer_central = require_mapping(consumer["centralReceipt"], "consumer receipt centralReceipt")
		require_exact_keys(consumer_central, {"path", "sha256"}, "consumer receipt centralReceipt")
		if not isinstance(consumer_central["path"], str) or not consumer_central["path"]:
			raise ReleaseRecordError(f"consumer receipt has no Central receipt path: {consumer_path}")
		if consumer_central["sha256"] != receipt_ref["sha256"]:
			raise ReleaseRecordError(f"consumer receipt used a different Central receipt for {coordinates}")
		component_dependencies = require_mapping(
			consumer["componentDependencies"], "consumer receipt componentDependencies"
		)
		expected_component_dependencies = {}
		if component["repository"] != "revetsec":
			expected_component_dependencies["com.revetsec:revetsec"] = {
				"version": record["version"], "scope": "provided",
			}
		if component["repository"] == "revetsec-soklet":
			external_group, external_artifact, external_version = external_dependency[
				"coordinates"
			].split(":")
			expected_component_dependencies[f"{external_group}:{external_artifact}"] = {
				"version": external_version, "scope": "provided",
			}
		elif component["repository"] == "revetsec-servlet-jakarta":
			expected_component_dependencies["jakarta.servlet:jakarta.servlet-api"] = {
				"version": "6.1.0", "scope": "provided",
			}
		elif component["repository"] == "revetsec-servlet-javax":
			expected_component_dependencies["javax.servlet:javax.servlet-api"] = {
				"version": "4.0.1", "scope": "provided",
			}
		if component_dependencies != expected_component_dependencies:
			raise ReleaseRecordError(
				f"published component POM dependencies differ for {coordinates}"
			)

		artifacts = require_mapping(consumer["artifacts"], "consumer receipt artifacts")
		expected_artifacts = {coordinates}
		if component["repository"] != "revetsec":
			expected_artifacts.add(core_coordinates)
		if component["repository"] == "revetsec-soklet":
			expected_artifacts.add(external_dependency["coordinates"])
		elif component["repository"] == "revetsec-servlet-jakarta":
			expected_artifacts.add("jakarta.servlet:jakarta.servlet-api:6.1.0")
		elif component["repository"] == "revetsec-servlet-javax":
			expected_artifacts.add("javax.servlet:javax.servlet-api:4.0.1")
		if set(artifacts) != expected_artifacts:
			raise ReleaseRecordError(f"consumer artifact set differs for {coordinates}")
		for artifact_coordinates, hashes in artifacts.items():
			hashes = require_mapping(hashes, f"consumer artifact {artifact_coordinates}")
			require_exact_keys(hashes, {"jarSha256", "pomSha256"}, f"consumer artifact {artifact_coordinates}")
			require_sha256(hashes["jarSha256"], f"consumer artifact {artifact_coordinates} jarSha256", True)
			require_sha256(hashes["pomSha256"], f"consumer artifact {artifact_coordinates} pomSha256", True)
		if artifacts[coordinates]["jarSha256"] != component["payloadSha256"]["jar"]:
			raise ReleaseRecordError(f"consumer JAR differs from the recorded release payload for {coordinates}")
		if artifacts[coordinates]["pomSha256"] != component["payloadSha256"]["pom"]:
			raise ReleaseRecordError(f"consumer POM differs from the recorded release payload for {coordinates}")
		if component["repository"] != "revetsec":
			if artifacts[core_coordinates]["jarSha256"] != core_component["payloadSha256"]["jar"]:
				raise ReleaseRecordError(f"consumer core JAR differs for {coordinates}")
			if artifacts[core_coordinates]["pomSha256"] != core_component["payloadSha256"]["pom"]:
				raise ReleaseRecordError(f"consumer core POM differs for {coordinates}")
		if component["repository"] == "revetsec-soklet":
			external_hashes = artifacts[external_dependency["coordinates"]]
			if (
				external_hashes["jarSha256"] != external_dependency["jarSha256"]
				or external_hashes["pomSha256"] != external_dependency["pomSha256"]
			):
				raise ReleaseRecordError("Soklet consumer artifacts differ from externalDependencies")

		maven = require_mapping(consumer["maven"], "consumer receipt maven")
		require_exact_keys(maven, {"result", "classpath", "output"}, "consumer receipt maven")
		gradle = require_mapping(consumer["gradle"], "consumer receipt gradle")
		require_exact_keys(
			gradle,
			{"result", "version", "distributionSha256", "classpath", "output"},
			"consumer receipt gradle",
		)
		for name, result in (("maven", maven), ("gradle", gradle)):
			classpath = result["classpath"]
			if (
				result["result"] != "PASS" or not isinstance(classpath, list)
				or not all(isinstance(item, str) for item in classpath)
				or len(classpath) != len(set(classpath)) or set(classpath) != expected_artifacts
				or not isinstance(result["output"], str) or not result["output"].startswith("linked=")
			):
				raise ReleaseRecordError(f"consumer receipt {name} result is incomplete for {coordinates}")
		if gradle["version"] != GRADLE_VERSION or gradle["distributionSha256"] != GRADLE_DISTRIBUTION_SHA256:
			raise ReleaseRecordError(f"consumer receipt Gradle identity differs for {coordinates}")
		if maven["output"] != gradle["output"]:
			raise ReleaseRecordError(f"Maven and Gradle consumer linkage differs for {coordinates}")

	github_times = verify_github_receipts(record, root, components_by_repository)
	for repository, timing in component_times.items():
		if timing["hosted"] < github_times[repository]["evidenceCompleted"]:
			raise ReleaseRecordError(
				f"hosted evidence join predates its completed workflow run for {repository}"
			)

	documentation_ref = record["documentation"]["receipt"]
	documentation_path, documentation_data = read_evidence_file(
		root,
		documentation_ref["path"],
		documentation_ref["sha256"],
		"documentation.receipt.path",
	)
	try:
		documentation = json.loads(documentation_data.decode("utf-8"))
	except (UnicodeError, json.JSONDecodeError) as exception:
		raise ReleaseRecordError(
			f"documentation receipt is not valid UTF-8 JSON: {documentation_path}"
		) from exception
	documentation = require_mapping(documentation, "documentation receipt")
	require_exact_keys(
		documentation,
		{"schema", "verifiedAt", "version", "claimsAudit", "api", "website", "result"},
		"documentation receipt",
	)
	if documentation["schema"] != "revetsec.release-documentation-verification.v1":
		raise ReleaseRecordError(f"documentation receipt has the wrong schema: {documentation_path}")
	documentation_at = parse_evidence_timestamp(
		documentation["verifiedAt"], "documentation receipt verifiedAt"
	)
	if documentation_at > released_at:
		raise ReleaseRecordError("documentation receipt was verified after the recorded release timestamp")
	if documentation_at < max(timing["consumer"] for timing in component_times.values()):
		raise ReleaseRecordError(
			"documentation verification predates completed Central consumer verification"
		)
	if documentation["version"] != record["version"]:
		raise ReleaseRecordError("documentation receipt version differs from the release record")
	if documentation["result"] != "PASS":
		raise ReleaseRecordError(f"documentation receipt did not pass: {documentation_path}")
	documentation_claims = require_mapping(documentation["claimsAudit"], "documentation claimsAudit")
	require_exact_keys(documentation_claims, {"path", "sha256"}, "documentation claimsAudit")
	if not isinstance(documentation_claims["path"], str) or not documentation_claims["path"]:
		raise ReleaseRecordError("documentation receipt has no claims-audit path")
	if documentation_claims["sha256"] != claims["sha256"]:
		raise ReleaseRecordError("documentation receipt uses a different claims audit")

	api = require_mapping(documentation["api"], "documentation api")
	require_exact_keys(api, {"baseUrl", "components", "result"}, "documentation api")
	if api["baseUrl"] != "https://javadoc.revetsec.com" or api["result"] != "PASS":
		raise ReleaseRecordError("documentation API verification is incomplete")
	api_components = api["components"]
	if not isinstance(api_components, list) or len(api_components) != len(components_by_coordinates):
		raise ReleaseRecordError("documentation receipt must contain all four API components")
	seen_api_components = set()
	for api_component in api_components:
		api_component = require_mapping(api_component, "documentation API component")
		require_exact_keys(
			api_component,
			{"coordinates", "centralReceipt", "javadocJar", "pages"},
			"documentation API component",
		)
		coordinates = api_component["coordinates"]
		if coordinates not in central_by_coordinates or coordinates in seen_api_components:
			raise ReleaseRecordError(f"documentation API component is unexpected or duplicated: {coordinates!r}")
		seen_api_components.add(coordinates)
		central_reference = require_mapping(
			api_component["centralReceipt"], "documentation API centralReceipt"
		)
		require_exact_keys(
			central_reference, {"path", "sha256"}, "documentation API centralReceipt"
		)
		if not isinstance(central_reference["path"], str) or not central_reference["path"]:
			raise ReleaseRecordError(f"documentation receipt has no Central receipt path for {coordinates}")
		if central_reference["sha256"] != central_by_coordinates[coordinates]["receiptSha256"]:
			raise ReleaseRecordError(f"documentation receipt used a different Central receipt for {coordinates}")
		javadoc_jar = require_mapping(api_component["javadocJar"], "documentation API javadocJar")
		require_exact_keys(javadoc_jar, {"url", "sha256"}, "documentation API javadocJar")
		if (
			javadoc_jar["url"] != central_by_coordinates[coordinates]["javadocUrl"]
			or javadoc_jar["sha256"] != central_by_coordinates[coordinates]["javadocSha256"]
		):
			raise ReleaseRecordError(f"documentation Javadoc JAR differs from Central for {coordinates}")
		pages = require_mapping(api_component["pages"], "documentation API pages")
		require_exact_keys(
			pages, {"count", "manifestSha256", "allMatchSignedJar"}, "documentation API pages"
		)
		if isinstance(pages["count"], bool) or not isinstance(pages["count"], int) or pages["count"] < 1:
			raise ReleaseRecordError(f"documentation receipt has no API pages for {coordinates}")
		require_sha256(pages["manifestSha256"], "documentation API pages manifestSha256", True)
		if pages["allMatchSignedJar"] is not True:
			raise ReleaseRecordError(f"deployed API pages do not match the signed Javadoc JAR for {coordinates}")
	if seen_api_components != set(components_by_coordinates):
		raise ReleaseRecordError("documentation receipt API component set is incomplete")

	website = require_mapping(documentation["website"], "documentation website")
	require_exact_keys(
		website,
		{
			"baseUrl", "repository", "sourceCommit", "export", "deployed",
			"releaseVersionVerified", "allFilesMatchExport", "result",
		},
		"documentation website",
	)
	if website["baseUrl"] != "https://revetsec.com":
		raise ReleaseRecordError("documentation website uses an unexpected canonical base URL")
	if website["repository"] != "https://github.com/revetsec/revetsec.com":
		raise ReleaseRecordError("documentation website uses an unexpected source repository")
	if not isinstance(website["sourceCommit"], str) or not COMMIT.fullmatch(website["sourceCommit"]):
		raise ReleaseRecordError("documentation website sourceCommit must be a full lowercase SHA")
	website_export = require_mapping(website["export"], "documentation website export")
	require_exact_keys(
		website_export, {"path", "fileCount", "manifestSha256"}, "documentation website export"
	)
	deployed = require_mapping(website["deployed"], "documentation website deployed")
	require_exact_keys(deployed, {"fileCount", "manifestSha256"}, "documentation website deployed")
	if not isinstance(website_export["path"], str) or not website_export["path"]:
		raise ReleaseRecordError("documentation website export path is empty")
	for label, value in (
		("export", website_export["fileCount"]), ("deployed", deployed["fileCount"])
	):
		if isinstance(value, bool) or not isinstance(value, int) or value < 1:
			raise ReleaseRecordError(f"documentation website {label} file count is invalid")
	require_sha256(
		website_export["manifestSha256"], "documentation website export manifestSha256", True
	)
	require_sha256(deployed["manifestSha256"], "documentation website deployed manifestSha256", True)
	if (
		website_export["fileCount"] != deployed["fileCount"]
		or website_export["manifestSha256"] != deployed["manifestSha256"]
		or website["releaseVersionVerified"] is not True
		or website["allFilesMatchExport"] is not True
		or website["result"] != "PASS"
	):
		raise ReleaseRecordError("documentation website verification is incomplete")
	for repository, timing in github_times.items():
		if timing["releasePublished"] < documentation_at:
			raise ReleaseRecordError(
				f"GitHub Release predates completed documentation verification for {repository}"
			)
	final_evidence_at = max(
		documentation_at,
		*(timing["verified"] for timing in github_times.values()),
	)
	if acceptance_times["release"] < final_evidence_at:
		raise ReleaseRecordError(
			"ownerAcceptance.release predates completed documentation or GitHub verification"
		)
	return record


def main(argv=None):
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("record", type=Path)
	parser.add_argument("--template", action="store_true", help="validate the unfilled template shape")
	parser.add_argument("--evidence-root", type=Path, help="root for final record receipts and evidence paths")
	arguments = parser.parse_args(argv)
	if not arguments.template and arguments.evidence_root is None:
		parser.error("final record verification requires --evidence-root")
	try:
		document = json.loads(arguments.record.read_text(encoding="utf-8"))
		verify_record(document, final=not arguments.template)
		if not arguments.template:
			verify_evidence(document, arguments.evidence_root)
	except (OSError, UnicodeError, json.JSONDecodeError, ReleaseRecordError) as exception:
		print(f"Release record verification failed: {exception}", file=sys.stderr)
		return 1
	print(f"Release record verified: {arguments.record}")
	return 0


if __name__ == "__main__":
	sys.exit(main())
