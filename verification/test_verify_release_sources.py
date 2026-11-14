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

"""Four-repository source-set tests for verify-release-sources.py."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


DIRECTORY = Path(__file__).resolve().parent
SCRIPT = DIRECTORY / "verify-release-sources.py"
SPEC = importlib.util.spec_from_file_location("verify_release_sources", SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class ReleaseSourcesTests(unittest.TestCase):
	def setUp(self):
		self.temporary = tempfile.TemporaryDirectory()
		self.addCleanup(self.temporary.cleanup)
		self.workspace = Path(self.temporary.name)

	def pom(self, repository, artifact_id, phase, core_version=None, soklet_version=None):
		version = "1.0.0" if phase == "release" else "1.0.0-SNAPSHOT"
		tag = "<tag>v1.0.0</tag>" if phase == "release" else ""
		properties = []
		dependencies = []
		if core_version is not None:
			properties.append(f"<revetsec.version>{core_version}</revetsec.version>")
			dependencies.append("""
    <dependency><groupId>com.revetsec</groupId><artifactId>revetsec</artifactId>
      <version>${revetsec.version}</version><scope>provided</scope></dependency>""")
		if soklet_version is not None:
			properties.append(f"<soklet.version>{soklet_version}</soklet.version>")
			dependencies.append("""
    <dependency><groupId>com.soklet</groupId><artifactId>soklet</artifactId>
      <version>${soklet.version}</version><scope>provided</scope></dependency>""")
		if repository == "revetsec-servlet-jakarta":
			properties.append("<jakarta.servlet.version>6.1.0</jakarta.servlet.version>")
			dependencies.append("""
    <dependency><groupId>jakarta.servlet</groupId><artifactId>jakarta.servlet-api</artifactId>
      <version>${jakarta.servlet.version}</version><scope>provided</scope></dependency>""")
		if repository == "revetsec-servlet-javax":
			properties.append("<javax.servlet.version>4.0.1</javax.servlet.version>")
			dependencies.append("""
    <dependency><groupId>javax.servlet</groupId><artifactId>javax.servlet-api</artifactId>
      <version>${javax.servlet.version}</version><scope>provided</scope></dependency>""")
		return f"""<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion><groupId>com.revetsec</groupId>
  <artifactId>{artifact_id}</artifactId><version>{version}</version>
  <properties>{''.join(properties)}</properties>
  <dependencies>{''.join(dependencies)}</dependencies>
  <scm><url>https://github.com/revetsec/{repository}</url>{tag}</scm>
</project>
"""

	def write_workspace(self, phase):
		project_version = "1.0.0" if phase == "release" else "1.0.0-SNAPSHOT"
		for repository, artifact_id in VERIFIER.REPOSITORIES.items():
			path = self.workspace / repository
			path.mkdir()
			core_version = None if repository == "revetsec" else project_version
			soklet_version = "4.0.0" if repository == "revetsec-soklet" else None
			(path / "pom.xml").write_text(
				self.pom(repository, artifact_id, phase, core_version, soklet_version),
				encoding="utf-8",
			)
			if phase == "release":
				changelog = "# Changelog\n\n## 1.0.0 (2026-11-13)\n\nRelease.\n"
			else:
				changelog = "# Changelog\n\n## Unreleased\n\nThe version is `1.0.0-SNAPSHOT`.\n"
			(path / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
			if repository != "revetsec":
				workflow = path / ".github" / "workflows"
				workflow.mkdir(parents=True)
				(workflow / "ci.yml").write_text(
					"env:\n  REVETSEC_CORE_SHA: '" + "a" * 40 + "'\n", encoding="utf-8"
				)
		release = self.workspace / "revetsec" / "release"
		release.mkdir()
		template = {
			"version": "1.0.0",
			"disposition": "TEMPLATE",
			"repositories": [
				{"name": name, "tag": "v1.0.0"} for name in VERIFIER.REPOSITORIES
			],
			"components": [
				{
					"repository": name,
					"coordinates": f"com.revetsec:{artifact_id}:1.0.0",
				}
				for name, artifact_id in VERIFIER.REPOSITORIES.items()
			],
			"externalDependencies": [{
				"coordinates": "com.soklet:soklet:4.0.0",
			}],
		}
		(release / "RELEASE_RECORD.template.json").write_text(
			json.dumps(template), encoding="utf-8"
		)
		if phase == "release":
			(release / "SECURITY_CLAIMS_AUDIT.md").write_text(
				"# Security claims audit\n\n## Approved\n\nA.\n\n## Narrowed\n\nN.\n\n## Rejected\n\nR.\n",
				encoding="utf-8",
			)

	def verify(self, phase, **options):
		with mock.patch.object(VERIFIER, "require_git_state", return_value="a" * 40):
			return VERIFIER.verify_source_set(self.workspace, "1.0.0", phase, **options)

	def test_coherent_snapshot_source_set_passes(self):
		self.write_workspace("snapshot")
		result = self.verify("snapshot")
		self.assertTrue(result["sourceSetCoherent"])
		self.assertEqual(
			result["externalDependencies"][0]["coordinates"],
			"com.soklet:soklet:4.0.0",
		)

	def test_coherent_release_source_set_passes(self):
		self.write_workspace("release")
		result = self.verify("release", require_clean=True, require_tag=True)
		self.assertEqual(result["phase"], "release")
		self.assertEqual(len(result["repositories"]), 4)

	def test_adapter_snapshot_core_in_release_is_rejected(self):
		self.write_workspace("release")
		path = self.workspace / "revetsec-servlet-jakarta" / "pom.xml"
		path.write_text(
			path.read_text(encoding="utf-8").replace(
				"<revetsec.version>1.0.0</revetsec.version>",
				"<revetsec.version>1.0.0-SNAPSHOT</revetsec.version>",
			),
			encoding="utf-8",
		)
		with self.assertRaises(VERIFIER.SourcePolicyError) as raised:
			self.verify("release")
		self.assertIn("exact core source-set version", str(raised.exception))

	def test_release_without_security_claims_audit_is_rejected(self):
		self.write_workspace("release")
		(self.workspace / "revetsec" / "release" / "SECURITY_CLAIMS_AUDIT.md").unlink()
		with self.assertRaises(VERIFIER.SourcePolicyError) as raised:
			self.verify("release")
		self.assertIn("security claims audit is missing", str(raised.exception))

	def test_servlet_platform_version_drift_is_rejected(self):
		self.write_workspace("snapshot")
		path = self.workspace / "revetsec-servlet-jakarta" / "pom.xml"
		path.write_text(
			path.read_text(encoding="utf-8").replace(
				"<jakarta.servlet.version>6.1.0</jakarta.servlet.version>",
				"<jakarta.servlet.version>6.0.0</jakarta.servlet.version>",
			),
			encoding="utf-8",
		)
		with self.assertRaises(VERIFIER.SourcePolicyError) as raised:
			self.verify("snapshot")
		self.assertIn("jakarta.servlet-api:6.1.0", str(raised.exception))

	def test_release_changelog_still_marked_snapshot_is_rejected(self):
		self.write_workspace("release")
		path = self.workspace / "revetsec-soklet" / "CHANGELOG.md"
		path.write_text(
			path.read_text(encoding="utf-8") + "The version is `1.0.0-SNAPSHOT`.\n",
			encoding="utf-8",
		)
		with self.assertRaises(VERIFIER.SourcePolicyError) as raised:
			self.verify("release")
		self.assertIn("still describes 1.0.0-SNAPSHOT", str(raised.exception))

	def test_active_release_input_still_marked_snapshot_is_rejected(self):
		self.write_workspace("release")
		path = self.workspace / "revetsec-soklet" / "README.md"
		path.write_text("Use com.revetsec:revetsec:1.0.0-SNAPSHOT.\n", encoding="utf-8")
		with self.assertRaises(VERIFIER.SourcePolicyError) as raised:
			self.verify("release")
		self.assertIn("active release input still names 1.0.0-SNAPSHOT", str(raised.exception))

	def test_release_record_template_coordinate_drift_is_rejected(self):
		self.write_workspace("snapshot")
		path = self.workspace / "revetsec" / "release" / "RELEASE_RECORD.template.json"
		template = json.loads(path.read_text(encoding="utf-8"))
		template["components"][0]["coordinates"] = "com.revetsec:revetsec:1.0.1"
		path.write_text(json.dumps(template), encoding="utf-8")
		with self.assertRaises(VERIFIER.SourcePolicyError) as raised:
			self.verify("snapshot")
		self.assertIn("template coordinates", str(raised.exception))

	def test_clean_release_requires_adapter_pins_at_core_head(self):
		self.write_workspace("release")
		path = self.workspace / "revetsec-soklet" / ".github" / "workflows" / "ci.yml"
		path.write_text("env:\n  REVETSEC_CORE_SHA: '" + "b" * 40 + "'\n", encoding="utf-8")
		with self.assertRaises(VERIFIER.SourcePolicyError) as raised:
			self.verify("release", require_clean=True)
		self.assertIn("does not match release core HEAD", str(raised.exception))

	def test_release_record_template_external_dependency_drift_is_rejected(self):
		self.write_workspace("snapshot")
		path = self.workspace / "revetsec" / "release" / "RELEASE_RECORD.template.json"
		template = json.loads(path.read_text(encoding="utf-8"))
		template["externalDependencies"][0]["coordinates"] = "com.soklet:soklet:3.5.1"
		path.write_text(json.dumps(template), encoding="utf-8")
		with self.assertRaises(VERIFIER.SourcePolicyError) as raised:
			self.verify("snapshot")
		self.assertIn("external dependencies differ", str(raised.exception))

	def test_snapshot_phase_cannot_require_release_tag(self):
		self.write_workspace("snapshot")
		with self.assertRaises(VERIFIER.SourcePolicyError) as raised:
			self.verify("snapshot", require_tag=True)
		self.assertIn("valid only in the release phase", str(raised.exception))


if __name__ == "__main__":
	unittest.main()
