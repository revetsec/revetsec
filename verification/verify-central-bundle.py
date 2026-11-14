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

"""Verify a local Maven Central release bundle without uploading it.

The bundle must contain one non-SNAPSHOT com.revetsec component: its POM,
binary, source and Javadoc JARs, reproducible CycloneDX JSON SBOM, detached
signatures and all four checksums. Signature verification is mandatory unless
the caller explicitly selects --skip-signature-verification (for tests only).
"""

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import zipfile


CHECKSUMS = ("md5", "sha1", "sha256", "sha512")
HEX_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
FINGERPRINT = re.compile(r"(?:[0-9A-F]{40}|[0-9A-F]{64})")
VERIFIER_PATH = Path(__file__).resolve().parent / "verify-published-pom.py"
SPEC = importlib.util.spec_from_file_location("verify_published_pom", VERIFIER_PATH)
POM_VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POM_VERIFIER)


class BundlePolicyError(ValueError):
	"""The release bundle is unsafe, incomplete or inconsistent."""


def parse_coordinates(value):
	parts = tuple(part.strip() for part in value.split(":"))
	if len(parts) != 3 or not all(parts):
		raise argparse.ArgumentTypeError("expected groupId:artifactId:version")
	if parts[0] != "com.revetsec":
		raise argparse.ArgumentTypeError("the release groupId must be com.revetsec")
	for label, part in (("artifactId", parts[1]), ("version", parts[2])):
		if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", part):
			raise argparse.ArgumentTypeError(f"the release {label} contains unsafe characters")
	if parts[2].endswith("-SNAPSHOT"):
		raise argparse.ArgumentTypeError("a Central release version cannot end in -SNAPSHOT")
	return parts


def safe_members(archive):
	members = archive.infolist()
	names = [member.filename for member in members if not member.is_dir()]
	if len(names) != len(set(names)):
		raise BundlePolicyError("bundle contains duplicate file names")
	for name in names:
		path = PurePosixPath(name)
		if not name or name.startswith("/") or "\\" in name or ".." in path.parts:
			raise BundlePolicyError(f"bundle contains unsafe path {name!r}")
	return names


def expected_files(artifact_id, version):
	prefix = f"{artifact_id}-{version}"
	return (
		f"{prefix}.pom",
		f"{prefix}.jar",
		f"{prefix}-sources.jar",
		f"{prefix}-javadoc.jar",
		f"{prefix}-cyclonedx.json",
	)


def checksum_value(data, algorithm):
	return hashlib.new(algorithm, data).hexdigest()


def verify_checksums(files, payload_names):
	for payload_name in payload_names:
		payload = files[payload_name]
		for algorithm in CHECKSUMS:
			checksum_name = f"{payload_name}.{algorithm}"
			if checksum_name not in files:
				raise BundlePolicyError(f"missing {algorithm} checksum for {payload_name}")
			value = files[checksum_name].decode("ascii", errors="strict").strip().split()[0].lower()
			if not re.fullmatch(rf"[0-9a-f]{{{HEX_LENGTHS[algorithm]}}}", value):
				raise BundlePolicyError(f"malformed {algorithm} checksum for {payload_name}")
			expected = checksum_value(payload, algorithm)
			if value != expected:
				raise BundlePolicyError(f"incorrect {algorithm} checksum for {payload_name}")


def jar_entries(path, description):
	try:
		with zipfile.ZipFile(path) as archive:
			return set(safe_members(archive))
	except zipfile.BadZipFile as exception:
		raise BundlePolicyError(f"{description} is not a valid ZIP/JAR") from exception


def verify_jars(directory, artifact_id, version):
	prefix = f"{artifact_id}-{version}"
	main_entries = jar_entries(directory / f"{prefix}.jar", "main JAR")
	for required in ("META-INF/MANIFEST.MF", "META-INF/LICENSE", "META-INF/NOTICE"):
		if required not in main_entries:
			raise BundlePolicyError(f"main JAR is missing {required}")
	if not any(name.endswith(".class") for name in main_entries):
		raise BundlePolicyError("main JAR contains no class files")

	source_entries = jar_entries(directory / f"{prefix}-sources.jar", "source JAR")
	if not any(name.endswith(".java") for name in source_entries):
		raise BundlePolicyError("source JAR contains no Java sources")

	javadoc_entries = jar_entries(directory / f"{prefix}-javadoc.jar", "Javadoc JAR")
	for required in ("index.html", "element-list"):
		if required not in javadoc_entries:
			raise BundlePolicyError(f"Javadoc JAR is missing {required}")


def verify_release_pom_metadata(path, group_id, artifact_id, version):
	project = POM_VERIFIER.load_pom(path)
	required = (
		("m:name", "a project name"),
		("m:description", "a project description"),
		("m:url", "a project URL"),
		("m:licenses/m:license/m:name", "a license name"),
		("m:licenses/m:license/m:url", "a license URL"),
		("m:developers/m:developer/m:name", "a developer name"),
		("m:developers/m:developer/m:email", "a developer email"),
		("m:developers/m:developer/m:organization", "a developer organization"),
		("m:developers/m:developer/m:organizationUrl", "a developer organization URL"),
		("m:scm/m:connection", "an SCM connection"),
		("m:scm/m:developerConnection", "an SCM developer connection"),
		("m:scm/m:url", "an SCM URL"),
		("m:scm/m:tag", "an SCM tag"),
	)
	try:
		values = {path_expression: POM_VERIFIER.literal_text(project, path_expression, label) for path_expression, label in required}
	except POM_VERIFIER.PomPolicyError as exception:
		raise BundlePolicyError(f"release POM metadata: {exception}") from exception
	expected_scm = f"https://github.com/revetsec/{artifact_id}"
	if values["m:scm/m:url"] != expected_scm:
		raise BundlePolicyError(f"release POM SCM URL is {values['m:scm/m:url']!r}, expected {expected_scm!r}")
	expected_tag = f"v{version}"
	if values["m:scm/m:tag"] != expected_tag:
		raise BundlePolicyError(f"release POM SCM tag is {values['m:scm/m:tag']!r}, expected {expected_tag!r}")
	if group_id != "com.revetsec":
		raise BundlePolicyError("release POM groupId must be com.revetsec")


def verify_sbom(path, group_id, artifact_id, version):
	try:
		document = json.loads(path.read_text(encoding="utf-8"))
	except (OSError, UnicodeError, json.JSONDecodeError) as exception:
		raise BundlePolicyError("CycloneDX SBOM is not valid UTF-8 JSON") from exception
	if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.6":
		raise BundlePolicyError("SBOM must be CycloneDX 1.6")
	if "serialNumber" in document:
		raise BundlePolicyError("reproducible SBOM must not contain a serial number")
	metadata = document.get("metadata")
	if not isinstance(metadata, dict) or "timestamp" in metadata:
		raise BundlePolicyError("reproducible SBOM must have metadata and no timestamp")
	component = metadata.get("component")
	if not isinstance(component, dict):
		raise BundlePolicyError("SBOM metadata is missing the root component")
	actual = (component.get("group"), component.get("name"), component.get("version"))
	if actual != (group_id, artifact_id, version):
		raise BundlePolicyError(f"SBOM root component is {actual!r}, expected {(group_id, artifact_id, version)!r}")
	if document.get("components", []) != []:
		raise BundlePolicyError("runtime-focused SBOM must contain no dependency components")
	purl = component.get("purl")
	dependencies = document.get("dependencies")
	if dependencies != [{"ref": purl, "dependsOn": []}]:
		raise BundlePolicyError("SBOM dependency graph must contain only the dependency-free root component")
	properties = {item.get("name"): item.get("value") for item in metadata.get("properties", [])}
	if properties.get("cdx:reproducible") != "enabled" or properties.get("maven.scopes") != "":
		raise BundlePolicyError("SBOM does not declare reproducible, empty-scope generation")


def parse_valid_signature(status, payload_name):
	"""Return the signing and primary fingerprints from one gpgv status stream."""
	prefix = "[GNUPG:] VALIDSIG "
	valid = [line[len(prefix):].split() for line in status.splitlines() if line.startswith(prefix)]
	if len(valid) != 1 or len(valid[0]) < 9:
		raise BundlePolicyError(f"gpgv did not report exactly one valid signature for {payload_name}")
	fields = valid[0]
	signing_fingerprint = fields[0]
	primary_fingerprint = fields[9] if len(fields) > 9 else signing_fingerprint
	if not FINGERPRINT.fullmatch(signing_fingerprint) or not FINGERPRINT.fullmatch(primary_fingerprint):
		raise BundlePolicyError(f"gpgv reported a malformed signing fingerprint for {payload_name}")
	return signing_fingerprint, primary_fingerprint


def verify_signatures(directory, payload_names, keyring, expected_fingerprint=None):
	keyring = Path(keyring)
	if keyring.is_symlink() or not keyring.is_file():
		raise BundlePolicyError("trusted OpenPGP keyring must be a regular file")
	keyring = keyring.resolve()
	primary_fingerprints = set()
	for payload_name in payload_names:
		command = [
			"gpgv", "--status-fd=1", "--homedir", str(directory), "--keyring", str(keyring),
			str(directory / f"{payload_name}.asc"), str(directory / payload_name),
		]
		result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
		if result.returncode != 0:
			detail = result.stderr.strip() or result.stdout.strip() or "gpgv returned no diagnostic"
			raise BundlePolicyError(f"signature verification failed for {payload_name}: {detail}")
		_signing_fingerprint, primary_fingerprint = parse_valid_signature(result.stdout, payload_name)
		primary_fingerprints.add(primary_fingerprint)
	if len(primary_fingerprints) != 1:
		raise BundlePolicyError("release payloads were not all signed by the same primary key")
	primary_fingerprint = primary_fingerprints.pop()
	if expected_fingerprint is not None and primary_fingerprint != expected_fingerprint:
		raise BundlePolicyError(
			f"release signing fingerprint is {primary_fingerprint}, expected {expected_fingerprint}"
		)
	return primary_fingerprint


def verify_bundle(
	bundle, expected, keyring=None, expected_fingerprint=None, skip_signature_verification=False
):
	group_id, artifact_id, version = expected
	if version.endswith("-SNAPSHOT"):
		raise BundlePolicyError("a Central release bundle cannot contain a SNAPSHOT version")
	if not skip_signature_verification and keyring is None:
		raise BundlePolicyError("signature verification requires --keyring")
	if not skip_signature_verification and not FINGERPRINT.fullmatch(expected_fingerprint or ""):
		raise BundlePolicyError("signature verification requires --expect-fingerprint")

	try:
		with zipfile.ZipFile(bundle) as archive:
			names = safe_members(archive)
			expected_directory = f"{group_id.replace('.', '/')}/{artifact_id}/{version}/"
			if any(not name.startswith(expected_directory) for name in names):
				raise BundlePolicyError(f"every bundle file must be under {expected_directory}")
			leaf_names = [name[len(expected_directory):] for name in names]
			if any("/" in name or not name for name in leaf_names):
				raise BundlePolicyError("bundle component directory contains a nested or blank file name")
			files = {leaf: archive.read(full) for leaf, full in zip(leaf_names, names)}
	except (OSError, zipfile.BadZipFile) as exception:
		raise BundlePolicyError(f"cannot read Central bundle {bundle}: {exception}") from exception

	payload_names = expected_files(artifact_id, version)
	required = set(payload_names)
	required.update(f"{name}.asc" for name in payload_names)
	required.update(f"{name}.{algorithm}" for name in payload_names for algorithm in CHECKSUMS)
	missing = sorted(required.difference(files))
	if missing:
		raise BundlePolicyError("bundle is missing required files: " + ", ".join(missing))
	allowed = set(required)
	allowed.update(f"{name}.asc.{algorithm}" for name in payload_names for algorithm in CHECKSUMS)
	unexpected = sorted(set(files).difference(allowed))
	if unexpected:
		raise BundlePolicyError("bundle contains unexpected files: " + ", ".join(unexpected))
	verify_checksums(files, payload_names)

	with tempfile.TemporaryDirectory(prefix="revetsec-central-bundle-") as temporary:
		directory = Path(temporary)
		for name, data in files.items():
			(directory / name).write_bytes(data)
		pom_name = f"{artifact_id}-{version}.pom"
		try:
			POM_VERIFIER.verify_pom(directory / pom_name, expected)
		except POM_VERIFIER.PomPolicyError as exception:
			raise BundlePolicyError(str(exception)) from exception
		verify_release_pom_metadata(directory / pom_name, group_id, artifact_id, version)
		verify_jars(directory, artifact_id, version)
		verify_sbom(directory / f"{artifact_id}-{version}-cyclonedx.json", group_id, artifact_id, version)
		signing_fingerprint = None
		if not skip_signature_verification:
			signing_fingerprint = verify_signatures(
				directory, payload_names, keyring, expected_fingerprint
			)

	return {
		"bundle": str(bundle),
		"coordinates": ":".join(expected),
		"sha256": hashlib.sha256(Path(bundle).read_bytes()).hexdigest(),
		"payloads": {name: hashlib.sha256(files[name]).hexdigest() for name in payload_names},
		"signatures": {
			f"{name}.asc": hashlib.sha256(files[f"{name}.asc"]).hexdigest()
			for name in payload_names
		},
		"signaturesVerified": not skip_signature_verification,
		"signingFingerprint": signing_fingerprint,
	}


def compare_payloads(first, second):
	"""Require two already-verified bundles to contain byte-identical payloads."""
	if first["coordinates"] != second["coordinates"]:
		raise BundlePolicyError("reproducibility comparison coordinates do not match")
	mismatches = [
		name
		for name, digest in first["payloads"].items()
		if second["payloads"].get(name) != digest
	]
	unexpected = sorted(set(second["payloads"]).difference(first["payloads"]))
	mismatches.extend(unexpected)
	if mismatches:
		raise BundlePolicyError(
			"release payloads are not reproducible: " + ", ".join(sorted(set(mismatches)))
		)
	return {
		"bundle": second["bundle"],
		"sha256": second["sha256"],
		"payloadsMatch": True,
		"signaturesVerified": second["signaturesVerified"],
		"signingFingerprint": second["signingFingerprint"],
	}


def reproducibility_receipt(first, second):
	comparison = compare_payloads(first, second)
	return {
		"schema": "revetsec.central-bundle-reproducibility.v1",
		"verifiedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
		"coordinates": first["coordinates"],
		"firstBundle": {
			"path": first["bundle"],
			"sha256": first["sha256"],
			"signaturesVerified": first["signaturesVerified"],
			"signingFingerprint": first["signingFingerprint"],
		},
		"secondBundle": {
			"path": second["bundle"],
			"sha256": second["sha256"],
			"signaturesVerified": second["signaturesVerified"],
			"signingFingerprint": second["signingFingerprint"],
		},
		"payloads": dict(first["payloads"]),
		"payloadsMatch": comparison["payloadsMatch"],
	}


def write_receipt(path, result):
	if path.exists() or path.is_symlink():
		raise BundlePolicyError(f"receipt path already exists: {path}")
	if not path.parent.is_dir():
		raise BundlePolicyError(f"receipt parent directory does not exist: {path.parent}")
	path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv=None):
	parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument("bundle", type=Path, help="central-bundle.zip created with central.skipUpload=true")
	parser.add_argument(
		"--compare-to",
		type=Path,
		help="second independently built bundle whose five payloads must be byte-identical",
	)
	parser.add_argument(
		"--output",
		type=Path,
		help="create-new reproducibility receipt; requires --compare-to",
	)
	parser.add_argument("--expect", type=parse_coordinates, required=True, metavar="GROUP:ARTIFACT:VERSION")
	parser.add_argument("--keyring", type=Path, help="trusted OpenPGP keyring for gpgv")
	parser.add_argument(
		"--expect-fingerprint",
		help="full uppercase fingerprint of the trusted primary release-signing key",
	)
	parser.add_argument(
		"--skip-signature-verification",
		action="store_true",
		help="check signature presence but not cryptographic validity; intended only for verifier self-tests",
	)
	arguments = parser.parse_args(argv)
	if arguments.output and not arguments.compare_to:
		parser.error("--output requires --compare-to")
	try:
		result = verify_bundle(
			arguments.bundle,
			arguments.expect,
			keyring=arguments.keyring,
			expected_fingerprint=arguments.expect_fingerprint,
			skip_signature_verification=arguments.skip_signature_verification,
		)
		if arguments.compare_to:
			comparison = verify_bundle(
				arguments.compare_to,
				arguments.expect,
				keyring=arguments.keyring,
				expected_fingerprint=arguments.expect_fingerprint,
				skip_signature_verification=arguments.skip_signature_verification,
			)
			result["comparison"] = compare_payloads(result, comparison)
			if arguments.output:
				write_receipt(arguments.output, reproducibility_receipt(result, comparison))
	except (BundlePolicyError, OSError) as exception:
		print(f"Central bundle verification failed: {exception}", file=sys.stderr)
		return 1
	print(json.dumps(result, indent=2, sort_keys=True))
	return 0


if __name__ == "__main__":
	sys.exit(main())
