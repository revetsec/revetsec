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

"""Seeded policy tests for verify-central-consumers.py."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


DIRECTORY = Path(__file__).resolve().parent
SCRIPT = DIRECTORY / "verify-central-consumers.py"
SPEC = importlib.util.spec_from_file_location("verify_central_consumers", SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class CentralConsumerTests(unittest.TestCase):
	def setUp(self):
		self.temporary = tempfile.TemporaryDirectory()
		self.addCleanup(self.temporary.cleanup)
		self.root = Path(self.temporary.name)

	def test_every_release_component_has_an_exact_consumer_spec(self):
		for component in VERIFIER.COMPONENTS:
			with self.subTest(component=component):
				spec = VERIFIER.component_spec(component, "1.0.0", "4.0.0")
				self.assertEqual(spec["coordinates"], f"com.revetsec:{component}:1.0.0")
				self.assertEqual(spec["dependencies"][0], spec["coordinates"])
				self.assertGreaterEqual(len(spec["classes"]), 3)

	def test_soklet_adapter_requires_a_literal_qualified_version(self):
		for value in (None, "4.0.0-SNAPSHOT", "${soklet.version}"):
			with self.subTest(value=value), self.assertRaises(VERIFIER.ConsumerPolicyError):
				VERIFIER.component_spec("revetsec-soklet", "1.0.0", value)

	def test_snapshot_component_version_is_rejected(self):
		with self.assertRaises(VERIFIER.ConsumerPolicyError):
			VERIFIER.component_spec("revetsec", "1.0.0-SNAPSHOT")

	def test_maven_path_separator_classpath_is_exact(self):
		first = self.root / "a.jar"
		second = self.root / "b.jar"
		first.write_bytes(b"a")
		second.write_bytes(b"b")
		classpath = self.root / "classpath.txt"
		classpath.write_text(f"{first}{os.pathsep}{second}", encoding="utf-8")
		result = VERIFIER.require_exact_classpath(
			classpath, {"a:one:1": first, "b:two:2": second}, "Maven runtime",
			separator=os.pathsep,
		)
		self.assertEqual(result, ["a:one:1", "b:two:2"])

	def test_extra_classpath_artifact_is_rejected(self):
		first = self.root / "a.jar"
		extra = self.root / "extra.jar"
		first.write_bytes(b"a")
		extra.write_bytes(b"extra")
		classpath = self.root / "classpath.txt"
		classpath.write_text(f"{first}\n{extra}\n", encoding="utf-8")
		with self.assertRaises(VERIFIER.ConsumerPolicyError) as raised:
			VERIFIER.require_exact_classpath(classpath, {"a:one:1": first}, "Gradle runtime")
		self.assertIn("classpath differs", str(raised.exception))

	def test_component_pom_must_bind_exact_provided_dependencies(self):
		spec = VERIFIER.component_spec("revetsec-servlet-jakarta", "1.0.0")
		pom = self.root / "component.pom"
		pom.write_text("""<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.revetsec</groupId><artifactId>revetsec-servlet-jakarta</artifactId><version>1.0.0</version>
  <properties><revetsec.version>1.0.0</revetsec.version><jakarta.servlet.version>6.1.0</jakarta.servlet.version></properties>
  <dependencies>
    <dependency><groupId>com.revetsec</groupId><artifactId>revetsec</artifactId><version>${revetsec.version}</version><scope>provided</scope></dependency>
    <dependency><groupId>jakarta.servlet</groupId><artifactId>jakarta.servlet-api</artifactId><version>${jakarta.servlet.version}</version><scope>provided</scope></dependency>
  </dependencies>
</project>""", encoding="utf-8")
		self.assertEqual(len(VERIFIER.verify_component_pom(pom, spec)), 2)
		pom.write_text(
			pom.read_text(encoding="utf-8").replace(
				"<jakarta.servlet.version>6.1.0</jakarta.servlet.version>",
				"<jakarta.servlet.version>6.0.0</jakarta.servlet.version>",
			),
			encoding="utf-8",
		)
		with self.assertRaises(VERIFIER.ConsumerPolicyError) as raised:
			VERIFIER.verify_component_pom(pom, spec)
		self.assertIn("functional dependencies differ", str(raised.exception))

	def make_receipt(self):
		spec = VERIFIER.component_spec("revetsec", "1.0.0")
		repository = self.root / "repository"
		paths = VERIFIER.artifact_paths(repository, spec["coordinates"])
		paths["jar"].parent.mkdir(parents=True)
		paths["jar"].write_bytes(b"jar")
		paths["pom"].write_bytes(b"pom")
		group_id, artifact_id, version = spec["coordinates"].split(":")
		prefix = f"{artifact_id}-{version}"
		payloads = {
			f"{prefix}.pom", f"{prefix}.jar", f"{prefix}-sources.jar",
			f"{prefix}-javadoc.jar", f"{prefix}-cyclonedx.json",
		}
		base = f"{VERIFIER.CANONICAL_REPOSITORY}/{group_id.replace('.', '/')}/{artifact_id}/{version}"
		files = {
			name: {
				"url": f"{base}/{name}",
				"sha256": (
					VERIFIER.sha256(paths["jar"]) if name == f"{prefix}.jar"
					else VERIFIER.sha256(paths["pom"]) if name == f"{prefix}.pom"
					else "1" * 64
				),
			}
			for name in payloads | {f"{name}.asc" for name in payloads}
		}
		receipt = {
			"schema": "revetsec.central-publication-verification.v1",
			"verifiedAt": "2026-11-13T23:00:00Z",
			"coordinates": spec["coordinates"],
			"repository": VERIFIER.CANONICAL_REPOSITORY,
			"approvedBundle": {"path": "/release/central-bundle.zip", "sha256": "2" * 64},
			"files": files,
			"signaturesVerified": True,
			"signingFingerprint": "A" * 40,
			"exactBundleContent": True,
		}
		path = self.root / "central.json"
		path.write_text(json.dumps(receipt), encoding="utf-8")
		return path, spec, paths, receipt

	def test_central_receipt_binds_resolved_component_bytes(self):
		path, spec, paths, _ = self.make_receipt()
		self.assertEqual(
			VERIFIER.validate_central_receipt(path, spec, paths),
			hashlib.sha256(path.read_bytes()).hexdigest(),
		)

	def test_rehashed_wrong_component_is_rejected(self):
		path, spec, paths, receipt = self.make_receipt()
		name = "revetsec-1.0.0.jar"
		receipt["files"][name]["sha256"] = "9" * 64
		path.write_text(json.dumps(receipt), encoding="utf-8")
		with self.assertRaises(VERIFIER.ConsumerPolicyError) as raised:
			VERIFIER.validate_central_receipt(path, spec, paths)
		self.assertIn("differs from the signed Central receipt", str(raised.exception))

	def test_incomplete_central_receipt_is_rejected(self):
		path, spec, paths, receipt = self.make_receipt()
		receipt["files"].pop("revetsec-1.0.0.jar.asc")
		path.write_text(json.dumps(receipt), encoding="utf-8")
		with self.assertRaises(VERIFIER.ConsumerPolicyError) as raised:
			VERIFIER.validate_central_receipt(path, spec, paths)
		self.assertIn("exact payload and signature set", str(raised.exception))

	def test_generated_consumers_use_only_canonical_repository_input(self):
		spec = VERIFIER.component_spec("revetsec-servlet-jakarta", "1.0.0")
		consumer = self.root / "consumer"
		consumer.mkdir()
		VERIFIER.write_consumer_sources(consumer, spec)
		settings = (consumer / "settings.xml").read_text(encoding="utf-8")
		self.assertIn(VERIFIER.CANONICAL_REPOSITORY, settings)
		self.assertIn("<mirrorOf>*</mirrorOf>", settings)
		self.assertNotIn("password", settings.lower())
		java = (consumer / "src/main/java/example/ReleasedConsumer.java").read_text(encoding="utf-8")
		for class_name in spec["classes"]:
			self.assertIn(f"{class_name}.class", java)

	def test_consumer_receipt_is_create_new(self):
		path = self.root / "consumer.json"
		VERIFIER.write_receipt(path, {"result": "PASS"})
		with self.assertRaises(VERIFIER.ConsumerPolicyError) as raised:
			VERIFIER.write_receipt(path, {"result": "PASS"})
		self.assertIn("already exists", str(raised.exception))


if __name__ == "__main__":
	unittest.main()
