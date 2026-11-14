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

"""Seeded-incompleteness tests for verify-release-record.py."""

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


DIRECTORY = Path(__file__).resolve().parent
SCRIPT = DIRECTORY / "verify-release-record.py"
SPEC = importlib.util.spec_from_file_location("verify_release_record", SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)
TEMPLATE = DIRECTORY.parent / "release" / "RELEASE_RECORD.template.json"


class ReleaseRecordTests(unittest.TestCase):
	def template(self):
		return json.loads(TEMPLATE.read_text(encoding="utf-8"))

	def complete_record(self):
		record = deepcopy(self.template())
		record["disposition"] = "RELEASED"
		for name, decision in record["ownerAcceptance"].items():
			decision["accepted"] = True
			decision["evidence"] = {
				"path": f"release/acceptance/{name}.json",
				"sha256": "e" * 64,
			}
		for repository in record["repositories"]:
			name = repository["name"]
			repository["commit"] = "a" * 40
			repository["ciRun"] = f"https://github.com/revetsec/{name}/actions/runs/123"
			repository["githubReceipt"] = {
				"path": f"release/records/{name}-github.json",
				"sha256": "e" * 64,
			}
		record["signing"] = {
			"fingerprint": "A" * 40,
			"publicKeyUrl": "https://revetsec.com/security/release-key.asc",
			"receipt": {
				"path": "release/records/signing-key.json",
				"sha256": "e" * 64,
			},
		}
		record["externalDependencies"][0]["jarSha256"] = "4" * 64
		record["externalDependencies"][0]["pomSha256"] = "5" * 64
		for component in record["components"]:
			name = component["repository"]
			component["localBundleSha256"] = "b" * 64
			component["secondBundleSha256"] = "c" * 64
			component["bundleEvidence"] = {
				"first": {
					"path": f"release/bundles/{name}-first.zip",
					"sha256": component["localBundleSha256"],
				},
				"second": {
					"path": f"release/bundles/{name}-second.zip",
					"sha256": component["secondBundleSha256"],
				},
			}
			component["reproducibilityReceipt"] = {
				"path": f"release/records/{name}-reproducibility.json",
				"sha256": "e" * 64,
			}
			component["payloadSha256"] = {key: "d" * 64 for key in VERIFIER.PAYLOAD_KEYS}
			component["centralReceipt"] = {
				"path": f"release/records/{name}-central.json",
				"sha256": "e" * 64,
			}
			component["hostedEvidence"] = {
				"path": f"release/records/{name}-hosted-evidence.json",
				"sha256": "e" * 64,
			}
			component["attestationReceipt"] = {
				"path": f"release/records/{name}-attestations.json",
				"sha256": "e" * 64,
			}
			component["consumerReceipt"] = {
				"path": f"release/records/{name}-consumers.json",
				"sha256": "e" * 64,
			}
			component["provenanceRun"] = f"https://github.com/revetsec/{name}/actions/runs/124"
			component["provenanceAttestations"] = {
				"provenance": f"https://github.com/revetsec/{name}/attestations/1",
				"sbom": f"https://github.com/revetsec/{name}/attestations/2",
			}
		record["claimsAudit"]["sha256"] = "f" * 64
		record["documentation"] = {
			"receipt": {
				"path": "release/records/documentation.json",
				"sha256": "e" * 64,
			}
		}
		record["releasedAt"] = "2026-11-13T23:00:00Z"
		return record

	def materialize_evidence(self, root, record):
		root = Path(root)
		for gate, decision in record["ownerAcceptance"].items():
			support_path = root / f"release/acceptance/support/{gate}.md"
			support_path.parent.mkdir(parents=True, exist_ok=True)
			support_path.write_text(f"# Supporting evidence for {gate}\n", encoding="utf-8")
			receipt = {
				"schema": "revetsec.owner-acceptance.v1",
				"version": record["version"],
				"gate": gate,
				"disposition": "ACCEPTED",
				"acceptedAt": (
					"2026-11-13T22:58:00Z" if gate == "release" else "2026-11-13T21:00:00Z"
				),
				"acceptedBy": "project-owner",
				"repositories": [
					{"name": repository["name"], "commit": repository["commit"]}
					for repository in record["repositories"]
				],
				"evidence": [{
					"path": f"release/acceptance/support/{gate}.md",
					"sha256": hashlib.sha256(support_path.read_bytes()).hexdigest(),
				}],
				"notes": [],
			}
			path = root / decision["evidence"]["path"]
			path.parent.mkdir(parents=True, exist_ok=True)
			path.write_text(
				json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
			)
			decision["evidence"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

		signing_receipt = {
			"schema": "revetsec.release-signing-key-verification.v1",
			"verifiedAt": "2026-11-13T22:00:00Z",
			"url": record["signing"]["publicKeyUrl"],
			"publicKey": {"sha256": "9" * 64, "sizeBytes": 4096},
			"primaryKey": {
				"fingerprint": record["signing"]["fingerprint"],
				"type": "primary",
				"algorithm": "1",
				"created": 1700000000,
				"expires": 1893456000,
				"capabilities": "c",
			},
			"signingKeys": [{
				"fingerprint": "B" * 40,
				"type": "subkey",
				"algorithm": "1",
				"created": 1700000000,
				"expires": 1893456000,
				"capabilities": "s",
			}],
			"gpgVersion": "gpg (GnuPG) 2.5.21",
			"result": "PASS",
		}
		signing_path = root / record["signing"]["receipt"]["path"]
		signing_path.parent.mkdir(parents=True, exist_ok=True)
		signing_path.write_text(
			json.dumps(signing_receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
		)
		record["signing"]["receipt"]["sha256"] = hashlib.sha256(
			signing_path.read_bytes()
		).hexdigest()

		claims_path = root / record["claimsAudit"]["path"]
		claims_path.parent.mkdir(parents=True, exist_ok=True)
		claims_path.write_text("# Accepted security claims\n", encoding="utf-8")
		record["claimsAudit"]["sha256"] = hashlib.sha256(claims_path.read_bytes()).hexdigest()

		core = next(item for item in record["components"] if item["repository"] == "revetsec")
		repositories = {item["name"]: item for item in record["repositories"]}
		for component in record["components"]:
			group_id, artifact_id, version = component["coordinates"].split(":")
			prefix = f"{artifact_id}-{version}"
			first_bundle = root / component["bundleEvidence"]["first"]["path"]
			second_bundle = root / component["bundleEvidence"]["second"]["path"]
			first_bundle.parent.mkdir(parents=True, exist_ok=True)
			first_bundle.write_bytes(f"{component['repository']} first signed bundle\n".encode())
			second_bundle.write_bytes(f"{component['repository']} second signed bundle\n".encode())
			component["localBundleSha256"] = hashlib.sha256(first_bundle.read_bytes()).hexdigest()
			component["secondBundleSha256"] = hashlib.sha256(second_bundle.read_bytes()).hexdigest()
			component["bundleEvidence"]["first"]["sha256"] = component["localBundleSha256"]
			component["bundleEvidence"]["second"]["sha256"] = component["secondBundleSha256"]
			payload_names = {
				"pom": f"{prefix}.pom",
				"jar": f"{prefix}.jar",
				"sources": f"{prefix}-sources.jar",
				"javadoc": f"{prefix}-javadoc.jar",
				"sbom": f"{prefix}-cyclonedx.json",
			}
			reproducibility = {
				"schema": "revetsec.central-bundle-reproducibility.v1",
				"verifiedAt": "2026-11-13T22:10:00Z",
				"coordinates": component["coordinates"],
				"firstBundle": {
					"path": "/release-host/first/central-bundle.zip",
					"sha256": component["localBundleSha256"],
					"signaturesVerified": True,
					"signingFingerprint": record["signing"]["fingerprint"],
				},
				"secondBundle": {
					"path": "/release-host/second/central-bundle.zip",
					"sha256": component["secondBundleSha256"],
					"signaturesVerified": True,
					"signingFingerprint": record["signing"]["fingerprint"],
				},
				"payloads": {
					published_name: component["payloadSha256"][logical_name]
					for logical_name, published_name in payload_names.items()
				},
				"payloadsMatch": True,
			}
			reproducibility_path = root / component["reproducibilityReceipt"]["path"]
			reproducibility_path.parent.mkdir(parents=True, exist_ok=True)
			reproducibility_path.write_text(
				json.dumps(reproducibility, indent=2, sort_keys=True) + "\n",
				encoding="utf-8",
			)
			component["reproducibilityReceipt"]["sha256"] = hashlib.sha256(
				reproducibility_path.read_bytes()
			).hexdigest()
			repository = "https://repo.maven.apache.org/maven2"
			base = f"{repository}/{group_id.replace('.', '/')}/{artifact_id}/{version}"
			files = {}
			for logical_name, published_name in payload_names.items():
				files[published_name] = {
					"sha256": component["payloadSha256"][logical_name],
					"url": f"{base}/{published_name}",
				}
				files[f"{published_name}.asc"] = {
					"sha256": "1" * 64,
					"url": f"{base}/{published_name}.asc",
				}
			hosted = {
				"schema": "revetsec.release-evidence-join.v1",
				"verifiedAt": "2026-11-13T22:15:00Z",
				"coordinates": component["coordinates"],
				"evidence": f"release-evidence-{artifact_id}-{version}.zip",
				"approvedBundle": {
					"path": "/release-host/central-bundle.zip",
					"sha256": component["localBundleSha256"],
				},
				"payloads": {
					published_name: component["payloadSha256"][logical_name]
					for logical_name, published_name in payload_names.items()
				},
				"run": {
					"id": 124,
					"attempt": 1,
					"url": component["provenanceRun"],
				},
				"source": {
					"ref": f"refs/tags/{repositories[component['repository']]['tag']}",
					"sha": repositories[component["repository"]]["commit"],
				},
				"attestations": {
					"provenance": {
						"id": 1,
						"url": component["provenanceAttestations"]["provenance"],
					},
					"sbom": {
						"id": 2,
						"url": component["provenanceAttestations"]["sbom"],
					},
				},
				"signaturesVerified": True,
				"signingFingerprint": record["signing"]["fingerprint"],
				"exactBundleContent": True,
			}
			hosted_path = root / component["hostedEvidence"]["path"]
			hosted_path.parent.mkdir(parents=True, exist_ok=True)
			hosted_path.write_text(
				json.dumps(hosted, indent=2, sort_keys=True) + "\n",
				encoding="utf-8",
			)
			component["hostedEvidence"]["sha256"] = hashlib.sha256(
				hosted_path.read_bytes()
			).hexdigest()
			attestation = {
				"schema": "revetsec.release-attestation-verification.v1",
				"verifiedAt": "2026-11-13T22:20:00Z",
				"coordinates": component["coordinates"],
				"repository": f"revetsec/{component['repository']}",
				"source": hosted["source"],
				"signerWorkflow": (
					f"revetsec/{component['repository']}/.github/workflows/release-evidence.yml"
				),
				"githubCli": "gh version 2.102.0",
				"approvedBundle": {
					"path": "/release-host/central-bundle.zip",
					"sha256": component["localBundleSha256"],
					"signaturesVerified": True,
					"signingFingerprint": record["signing"]["fingerprint"],
				},
				"hostedEvidence": {
					"path": str(hosted_path),
					"sha256": component["hostedEvidence"]["sha256"],
				},
				"attestations": hosted["attestations"],
				"provenance": {
					"predicateType": "https://slsa.dev/provenance/v1",
					"subjects": {
						published_name: {
							"sha256": component["payloadSha256"][logical_name],
							"verifiedAttestations": 1,
							"verifiedTimestamps": 1,
						}
						for logical_name, published_name in payload_names.items()
					},
					"allSubjectsVerified": True,
				},
				"sbom": {
					"predicateType": "https://cyclonedx.org/bom",
					"subject": {
						"name": payload_names["jar"],
						"sha256": component["payloadSha256"]["jar"],
					},
					"sbomSha256": component["payloadSha256"]["sbom"],
					"predicateMatchesSbom": True,
					"verifiedAttestations": 1,
					"verifiedTimestamps": 1,
				},
				"result": "PASS",
			}
			attestation_path = root / component["attestationReceipt"]["path"]
			attestation_path.parent.mkdir(parents=True, exist_ok=True)
			attestation_path.write_text(
				json.dumps(attestation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
			)
			component["attestationReceipt"]["sha256"] = hashlib.sha256(
				attestation_path.read_bytes()
			).hexdigest()
			receipt = {
				"schema": "revetsec.central-publication-verification.v1",
				"verifiedAt": "2026-11-13T22:30:00Z",
				"coordinates": component["coordinates"],
				"repository": repository,
				"approvedBundle": {
					"path": "/release-host/central-bundle.zip",
					"sha256": component["localBundleSha256"],
				},
				"files": files,
				"signaturesVerified": True,
				"signingFingerprint": record["signing"]["fingerprint"],
				"exactBundleContent": True,
			}
			receipt_path = root / component["centralReceipt"]["path"]
			receipt_path.parent.mkdir(parents=True, exist_ok=True)
			receipt_path.write_text(
				json.dumps(receipt, indent=2, sort_keys=True) + "\n",
				encoding="utf-8",
			)
			component["centralReceipt"]["sha256"] = hashlib.sha256(
				receipt_path.read_bytes()
			).hexdigest()

			artifacts = {
				component["coordinates"]: {
					"jarSha256": component["payloadSha256"]["jar"],
					"pomSha256": component["payloadSha256"]["pom"],
				}
			}
			if component["repository"] != "revetsec":
				artifacts[core["coordinates"]] = {
					"jarSha256": core["payloadSha256"]["jar"],
					"pomSha256": core["payloadSha256"]["pom"],
				}
			if component["repository"] == "revetsec-soklet":
				artifacts["com.soklet:soklet:4.0.0"] = {
					"jarSha256": "4" * 64, "pomSha256": "5" * 64,
				}
			elif component["repository"] == "revetsec-servlet-jakarta":
				artifacts["jakarta.servlet:jakarta.servlet-api:6.1.0"] = {
					"jarSha256": "4" * 64, "pomSha256": "5" * 64,
				}
			elif component["repository"] == "revetsec-servlet-javax":
				artifacts["javax.servlet:javax.servlet-api:4.0.1"] = {
					"jarSha256": "4" * 64, "pomSha256": "5" * 64,
				}
			classpath = list(artifacts)
			consumer = {
				"schema": "revetsec.central-consumer-verification.v1",
				"verifiedAt": "2026-11-13T22:45:00Z",
				"coordinates": component["coordinates"],
				"repository": "https://repo.maven.apache.org/maven2",
				"javaHome": "/release-host/jdk",
				"centralReceipt": {
					"path": str(receipt_path),
					"sha256": component["centralReceipt"]["sha256"],
				},
				"componentDependencies": {},
				"artifacts": artifacts,
				"maven": {
					"result": "PASS", "classpath": classpath, "output": "linked=example.Types",
				},
				"gradle": {
					"result": "PASS",
					"version": VERIFIER.GRADLE_VERSION,
					"distributionSha256": VERIFIER.GRADLE_DISTRIBUTION_SHA256,
					"classpath": classpath,
					"output": "linked=example.Types",
				},
				"result": "PASS",
			}
			if component["repository"] != "revetsec":
				consumer["componentDependencies"]["com.revetsec:revetsec"] = {
					"version": record["version"], "scope": "provided",
				}
			if component["repository"] == "revetsec-soklet":
				consumer["componentDependencies"]["com.soklet:soklet"] = {
					"version": "4.0.0", "scope": "provided",
				}
			elif component["repository"] == "revetsec-servlet-jakarta":
				consumer["componentDependencies"]["jakarta.servlet:jakarta.servlet-api"] = {
					"version": "6.1.0", "scope": "provided",
				}
			elif component["repository"] == "revetsec-servlet-javax":
				consumer["componentDependencies"]["javax.servlet:javax.servlet-api"] = {
					"version": "4.0.1", "scope": "provided",
				}
			consumer_path = root / component["consumerReceipt"]["path"]
			consumer_path.parent.mkdir(parents=True, exist_ok=True)
			consumer_path.write_text(
				json.dumps(consumer, indent=2, sort_keys=True) + "\n",
				encoding="utf-8",
			)
			component["consumerReceipt"]["sha256"] = hashlib.sha256(
				consumer_path.read_bytes()
			).hexdigest()

		components_by_repository = {
			component["repository"]: component for component in record["components"]
		}
		for repository in record["repositories"]:
			name = repository["name"]
			component = components_by_repository[name]
			def run(url, run_id, workflow, created, completed):
				return {
					"url": url,
					"id": run_id,
					"workflowPath": workflow,
					"event": "push",
					"headSha": repository["commit"],
					"createdAt": created,
					"completedAt": completed,
					"conclusion": "success",
				}
			github = {
				"schema": "revetsec.github-release-verification.v1",
				"verifiedAt": "2026-11-13T22:57:00Z",
				"repository": name,
				"commit": repository["commit"],
				"tag": repository["tag"],
				"signedTag": {
					"objectSha": "1" * 40,
					"targetSha": repository["commit"],
					"taggedAt": "2026-11-13T20:35:00Z",
					"signatureVerified": True,
					"verificationReason": "valid",
				},
				"ciRun": run(
					repository["ciRun"], 123, ".github/workflows/ci.yml",
					"2026-11-13T20:00:00Z", "2026-11-13T20:30:00Z",
				),
				"releaseEvidenceRun": run(
					component["provenanceRun"], 124, ".github/workflows/release-evidence.yml",
					"2026-11-13T20:40:00Z", "2026-11-13T21:30:00Z",
				),
				"release": {
					"url": f"https://github.com/revetsec/{name}/releases/tag/{repository['tag']}",
					"id": 125,
					"publishedAt": "2026-11-13T22:56:00Z",
					"draft": False,
					"prerelease": False,
				},
				"result": "PASS",
			}
			github_path = root / repository["githubReceipt"]["path"]
			github_path.parent.mkdir(parents=True, exist_ok=True)
			github_path.write_text(
				json.dumps(github, indent=2, sort_keys=True) + "\n", encoding="utf-8"
			)
			repository["githubReceipt"]["sha256"] = hashlib.sha256(
				github_path.read_bytes()
			).hexdigest()

		api_components = []
		for component in record["components"]:
			central_path = root / component["centralReceipt"]["path"]
			central = json.loads(central_path.read_text(encoding="utf-8"))
			artifact_id = component["coordinates"].split(":")[1]
			javadoc_name = f"{artifact_id}-{record['version']}-javadoc.jar"
			api_components.append({
				"coordinates": component["coordinates"],
				"centralReceipt": {
					"path": str(central_path),
					"sha256": component["centralReceipt"]["sha256"],
				},
				"javadocJar": central["files"][javadoc_name],
				"pages": {
					"count": 1,
					"manifestSha256": "6" * 64,
					"allMatchSignedJar": True,
				},
			})
		documentation = {
			"schema": "revetsec.release-documentation-verification.v1",
			"verifiedAt": "2026-11-13T22:55:00Z",
			"version": record["version"],
			"claimsAudit": {
				"path": str(claims_path),
				"sha256": record["claimsAudit"]["sha256"],
			},
			"api": {
				"baseUrl": "https://javadoc.revetsec.com",
				"components": api_components,
				"result": "PASS",
			},
			"website": {
				"baseUrl": "https://revetsec.com",
				"repository": "https://github.com/revetsec/revetsec.com",
				"sourceCommit": "7" * 40,
				"export": {
					"path": "/release-host/revetsec.com/dist",
					"fileCount": 100,
					"manifestSha256": "8" * 64,
				},
				"deployed": {"fileCount": 100, "manifestSha256": "8" * 64},
				"releaseVersionVerified": True,
				"allFilesMatchExport": True,
				"result": "PASS",
			},
			"result": "PASS",
		}
		documentation_path = root / record["documentation"]["receipt"]["path"]
		documentation_path.parent.mkdir(parents=True, exist_ok=True)
		documentation_path.write_text(
			json.dumps(documentation, indent=2, sort_keys=True) + "\n",
			encoding="utf-8",
		)
		record["documentation"]["receipt"]["sha256"] = hashlib.sha256(
			documentation_path.read_bytes()
		).hexdigest()

	def rewrite_receipt(self, root, reference, mutate):
		path = Path(root) / reference["path"]
		receipt = json.loads(path.read_text(encoding="utf-8"))
		mutate(receipt)
		path.write_text(
			json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
		)
		reference["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
		return receipt

	def test_repository_template_has_valid_shape_but_is_not_a_release(self):
		record = self.template()
		self.assertIs(VERIFIER.verify_record(record, final=False), record)
		with self.assertRaises(VERIFIER.ReleaseRecordError):
			VERIFIER.verify_record(record, final=True)

	def test_complete_record_passes(self):
		record = self.complete_record()
		self.assertIs(VERIFIER.verify_record(record), record)

	def test_bundle_evidence_hash_must_match_recorded_bundle(self):
		record = self.complete_record()
		record["components"][0]["bundleEvidence"]["first"]["sha256"] = "9" * 64
		with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
			VERIFIER.verify_record(record)
		self.assertIn("first bundle evidence hash differs", str(raised.exception))

	def test_unaccepted_owner_gate_is_rejected(self):
		record = self.complete_record()
		record["ownerAcceptance"]["finalQ5"]["accepted"] = False
		with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
			VERIFIER.verify_record(record)
		self.assertIn("finalQ5", str(raised.exception))

	def test_unsafe_owner_acceptance_receipt_path_is_rejected(self):
		record = self.complete_record()
		record["ownerAcceptance"]["finalQ5"]["evidence"]["path"] = "../acceptance.json"
		with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
			VERIFIER.verify_record(record)
		self.assertIn("safe relative path", str(raised.exception))

	def test_duplicate_repository_is_rejected(self):
		record = self.complete_record()
		record["repositories"][1]["name"] = "revetsec"
		with self.assertRaises(VERIFIER.ReleaseRecordError):
			VERIFIER.verify_record(record)

	def test_unsafe_receipt_path_is_rejected(self):
		record = self.complete_record()
		record["components"][0]["centralReceipt"]["path"] = "../receipt.json"
		with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
			VERIFIER.verify_record(record)
		self.assertIn("safe relative path", str(raised.exception))

	def test_wrong_repository_ci_run_is_rejected(self):
		record = self.complete_record()
		record["repositories"][0]["ciRun"] = "https://github.com/revetsec/other/actions/runs/123"
		with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
			VERIFIER.verify_record(record)
		self.assertIn("expected GitHub Actions run", str(raised.exception))

	def test_noncanonical_public_signing_key_url_is_rejected(self):
		record = self.complete_record()
		record["signing"]["publicKeyUrl"] = "https://www.revetsec.com/security/release-key.asc"
		with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
			VERIFIER.verify_record(record)
		self.assertIn("signing.publicKeyUrl must be", str(raised.exception))

	def test_nonliteral_external_dependency_is_rejected(self):
		record = self.complete_record()
		record["externalDependencies"][0]["coordinates"] = "com.soklet:soklet:4.0.0-SNAPSHOT"
		with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
			VERIFIER.verify_record(record)
		self.assertIn("literal Soklet release", str(raised.exception))

	def test_missing_attestation_is_rejected(self):
		record = self.complete_record()
		record["components"][0]["provenanceAttestations"]["sbom"] = ""
		with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
			VERIFIER.verify_record(record)
		self.assertIn("provenance and SBOM", str(raised.exception))

	def test_attestation_for_wrong_repository_is_rejected(self):
		record = self.complete_record()
		record["components"][0]["provenanceAttestations"]["provenance"] = (
			"https://github.com/revetsec/other/attestations/1"
		)
		with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
			VERIFIER.verify_record(record)
		self.assertIn("expected GitHub repository", str(raised.exception))

	def test_duplicate_attestation_is_rejected(self):
		record = self.complete_record()
		attestations = record["components"][0]["provenanceAttestations"]
		attestations["sbom"] = attestations["provenance"]
		with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
			VERIFIER.verify_record(record)
		self.assertIn("must be distinct", str(raised.exception))

	def test_complete_evidence_set_passes(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			self.assertIs(VERIFIER.verify_evidence(record, temporary), record)

	def test_missing_preserved_signed_bundle_is_rejected(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			bundle = Path(temporary) / record["components"][0]["bundleEvidence"]["first"]["path"]
			bundle.unlink()
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("cannot read", str(raised.exception))

	def test_tampered_preserved_signed_bundle_is_rejected(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			bundle = Path(temporary) / record["components"][0]["bundleEvidence"]["second"]["path"]
			bundle.write_bytes(bundle.read_bytes() + b"tampered")
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("SHA-256 does not match", str(raised.exception))

	def test_hosted_join_must_follow_completed_workflow(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			repository = record["repositories"][0]
			self.rewrite_receipt(
				temporary, repository["githubReceipt"],
				lambda receipt: receipt["releaseEvidenceRun"].__setitem__(
					"completedAt", "2026-11-13T22:16:00Z"
				),
			)
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("hosted evidence join predates", str(raised.exception))

	def test_central_verification_must_follow_prepublication_evidence(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			component = record["components"][0]
			self.rewrite_receipt(
				temporary, component["centralReceipt"],
				lambda receipt: receipt.__setitem__("verifiedAt", "2026-11-13T22:19:00Z"),
			)
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("predates prepublication evidence", str(raised.exception))

	def test_consumer_verification_must_follow_central(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			component = record["components"][0]
			self.rewrite_receipt(
				temporary, component["consumerReceipt"],
				lambda receipt: receipt.__setitem__("verifiedAt", "2026-11-13T22:29:00Z"),
			)
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("predates Central publication", str(raised.exception))

	def test_documentation_must_follow_all_consumers(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			self.rewrite_receipt(
				temporary, record["documentation"]["receipt"],
				lambda receipt: receipt.__setitem__("verifiedAt", "2026-11-13T22:44:00Z"),
			)
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("predates completed Central consumer", str(raised.exception))

	def test_github_releases_must_follow_documentation(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			repository = record["repositories"][0]
			self.rewrite_receipt(
				temporary, repository["githubReceipt"],
				lambda receipt: receipt["release"].__setitem__(
					"publishedAt", "2026-11-13T22:54:00Z"
				),
			)
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("predates completed documentation", str(raised.exception))

	def test_final_owner_release_acceptance_must_follow_publication_evidence(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			decision = record["ownerAcceptance"]["release"]
			self.rewrite_receipt(
				temporary, decision["evidence"],
				lambda receipt: receipt.__setitem__("acceptedAt", "2026-11-13T22:56:00Z"),
			)
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("predates completed documentation or GitHub", str(raised.exception))

	def test_tampered_claims_audit_is_rejected(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			claims = Path(temporary) / record["claimsAudit"]["path"]
			claims.write_text("changed\n", encoding="utf-8")
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("claimsAudit.path SHA-256", str(raised.exception))

	def test_signing_key_receipt_with_rehashed_wrong_primary_is_rejected(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			path = Path(temporary) / record["signing"]["receipt"]["path"]
			receipt = json.loads(path.read_text(encoding="utf-8"))
			receipt["primaryKey"]["fingerprint"] = "C" * 40
			path.write_text(
				json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
			)
			record["signing"]["receipt"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("primary fingerprint differs", str(raised.exception))

	def test_owner_acceptance_with_rehashed_wrong_commit_is_rejected(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			decision = record["ownerAcceptance"]["compatibility"]
			path = Path(temporary) / decision["evidence"]["path"]
			receipt = json.loads(path.read_text(encoding="utf-8"))
			receipt["repositories"][0]["commit"] = "9" * 40
			path.write_text(
				json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
			)
			decision["evidence"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("exact release commits", str(raised.exception))

	def test_owner_acceptance_with_tampered_support_is_rejected(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			path = Path(temporary) / "release/acceptance/support/securityClaims.md"
			path.write_text("changed\n", encoding="utf-8")
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("receipt evidence", str(raised.exception))
			self.assertIn("SHA-256", str(raised.exception))

	def test_central_receipt_with_rehashed_wrong_signing_key_is_rejected(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			component = record["components"][0]
			path = Path(temporary) / component["centralReceipt"]["path"]
			receipt = json.loads(path.read_text(encoding="utf-8"))
			receipt["signingFingerprint"] = "C" * 40
			path.write_text(
				json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
			)
			component["centralReceipt"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("different release-signing key", str(raised.exception))

	def test_receipt_with_rehashed_wrong_payload_is_rejected(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			component = record["components"][0]
			receipt_path = Path(temporary) / component["centralReceipt"]["path"]
			receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
			payload_name = f"revetsec-{record['version']}.jar"
			receipt["files"][payload_name]["sha256"] = "9" * 64
			receipt_path.write_text(
				json.dumps(receipt, indent=2, sort_keys=True) + "\n",
				encoding="utf-8",
			)
			component["centralReceipt"]["sha256"] = hashlib.sha256(
				receipt_path.read_bytes()
			).hexdigest()
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("payload hash differs", str(raised.exception))

	def test_hosted_evidence_with_rehashed_wrong_bundle_is_rejected(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			component = record["components"][0]
			receipt_path = Path(temporary) / component["hostedEvidence"]["path"]
			receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
			receipt["approvedBundle"]["sha256"] = "9" * 64
			receipt_path.write_text(
				json.dumps(receipt, indent=2, sort_keys=True) + "\n",
				encoding="utf-8",
			)
			component["hostedEvidence"]["sha256"] = hashlib.sha256(
				receipt_path.read_bytes()
			).hexdigest()
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("hosted evidence approved bundle", str(raised.exception))

	def test_hosted_evidence_with_rehashed_wrong_attestation_is_rejected(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			component = record["components"][0]
			receipt_path = Path(temporary) / component["hostedEvidence"]["path"]
			receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
			receipt["attestations"]["provenance"]["id"] = 99
			receipt["attestations"]["provenance"]["url"] = (
				"https://github.com/revetsec/revetsec/attestations/99"
			)
			receipt_path.write_text(
				json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
			)
			component["hostedEvidence"]["sha256"] = hashlib.sha256(
				receipt_path.read_bytes()
			).hexdigest()
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("provenance attestation differs", str(raised.exception))

	def test_reproducibility_receipt_with_rehashed_wrong_second_bundle_is_rejected(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			component = record["components"][0]
			receipt_path = Path(temporary) / component["reproducibilityReceipt"]["path"]
			receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
			receipt["secondBundle"]["sha256"] = "9" * 64
			receipt_path.write_text(
				json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
			)
			component["reproducibilityReceipt"]["sha256"] = hashlib.sha256(
				receipt_path.read_bytes()
			).hexdigest()
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("secondBundle differs", str(raised.exception))

	def test_attestation_receipt_with_rehashed_wrong_subject_is_rejected(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			component = record["components"][0]
			receipt_path = Path(temporary) / component["attestationReceipt"]["path"]
			receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
			name = f"revetsec-{record['version']}.jar"
			receipt["provenance"]["subjects"][name]["sha256"] = "9" * 64
			receipt_path.write_text(
				json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
			)
			component["attestationReceipt"]["sha256"] = hashlib.sha256(
				receipt_path.read_bytes()
			).hexdigest()
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("provenance subject hash differs", str(raised.exception))

	def test_attestation_receipt_from_vulnerable_github_cli_is_rejected(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			component = record["components"][0]
			self.rewrite_receipt(
				temporary, component["attestationReceipt"],
				lambda receipt: receipt.__setitem__("githubCli", "gh version 2.101.0"),
			)
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("2.102.0 or newer", str(raised.exception))

	def test_consumer_receipt_with_rehashed_wrong_core_is_rejected(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			component = next(
				item for item in record["components"]
				if item["repository"] == "revetsec-servlet-jakarta"
			)
			receipt_path = Path(temporary) / component["consumerReceipt"]["path"]
			receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
			receipt["artifacts"]["com.revetsec:revetsec:1.0.0"]["jarSha256"] = "9" * 64
			receipt_path.write_text(
				json.dumps(receipt, indent=2, sort_keys=True) + "\n",
				encoding="utf-8",
			)
			component["consumerReceipt"]["sha256"] = hashlib.sha256(
				receipt_path.read_bytes()
			).hexdigest()
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("consumer core JAR differs", str(raised.exception))

	def test_consumer_receipt_with_rehashed_wrong_published_dependency_is_rejected(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			component = next(
				item for item in record["components"]
				if item["repository"] == "revetsec-soklet"
			)
			self.rewrite_receipt(
				temporary, component["consumerReceipt"],
				lambda receipt: receipt["componentDependencies"]["com.soklet:soklet"].__setitem__(
					"version", "3.5.1"
				),
			)
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("published component POM dependencies differ", str(raised.exception))

	def test_external_dependency_hashes_must_match_resolved_consumer_artifacts(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			record["externalDependencies"][0]["jarSha256"] = "9" * 64
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("differ from externalDependencies", str(raised.exception))

	def test_documentation_receipt_with_rehashed_wrong_javadoc_is_rejected(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			receipt_path = Path(temporary) / record["documentation"]["receipt"]["path"]
			receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
			receipt["api"]["components"][0]["javadocJar"]["sha256"] = "9" * 64
			receipt_path.write_text(
				json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
			)
			record["documentation"]["receipt"]["sha256"] = hashlib.sha256(
				receipt_path.read_bytes()
			).hexdigest()
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("Javadoc JAR differs from Central", str(raised.exception))

	def test_documentation_receipt_with_rehashed_wrong_website_is_rejected(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			receipt_path = Path(temporary) / record["documentation"]["receipt"]["path"]
			receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
			receipt["website"]["deployed"]["manifestSha256"] = "9" * 64
			receipt_path.write_text(
				json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
			)
			record["documentation"]["receipt"]["sha256"] = hashlib.sha256(
				receipt_path.read_bytes()
			).hexdigest()
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("website verification is incomplete", str(raised.exception))

	def test_github_receipt_with_rehashed_wrong_tag_target_is_rejected(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			repository = record["repositories"][0]
			receipt_path = Path(temporary) / repository["githubReceipt"]["path"]
			receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
			receipt["signedTag"]["targetSha"] = "9" * 40
			receipt_path.write_text(
				json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
			)
			repository["githubReceipt"]["sha256"] = hashlib.sha256(
				receipt_path.read_bytes()
			).hexdigest()
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("signed tag target", str(raised.exception))

	def test_missing_local_owner_evidence_is_rejected(self):
		record = self.complete_record()
		with tempfile.TemporaryDirectory() as temporary:
			self.materialize_evidence(temporary, record)
			path = (
				Path(temporary) / record["ownerAcceptance"]["release"]["evidence"]["path"]
			)
			path.unlink()
			with self.assertRaises(VERIFIER.ReleaseRecordError) as raised:
				VERIFIER.verify_evidence(record, temporary)
			self.assertIn("ownerAcceptance.release.evidence", str(raised.exception))


if __name__ == "__main__":
	unittest.main()
