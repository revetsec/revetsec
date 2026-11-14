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

"""Verify that the four Revetsec source repositories form one coherent release unit."""

import argparse
from datetime import date
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


NAMESPACE = "http://maven.apache.org/POM/4.0.0"
NS = {"m": NAMESPACE}
REPOSITORIES = {
	"revetsec": "revetsec",
	"revetsec-soklet": "revetsec-soklet",
	"revetsec-servlet-jakarta": "revetsec-servlet-jakarta",
	"revetsec-servlet-javax": "revetsec-servlet-javax",
}
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
ACTIVE_TEXT_SUFFIXES = {
	".groovy", ".html", ".java", ".js", ".json", ".md", ".mjs", ".properties",
	".py", ".sh", ".txt", ".xml", ".yaml", ".yml",
}
ACTIVE_RELEASE_ROOTS = (
	".github", "src/main", "docs", "examples", "conformance", "differential", "fuzz",
	"interop", "verification", "scripts",
)
ACTIVE_RELEASE_FILES = (
	"pom.xml", "README.md", "CONTRIBUTING.md", "CHANGELOG.md", "COMPATIBILITY.md", "SECURITY.md",
)


class SourcePolicyError(ValueError):
	"""The four source repositories do not form the requested release phase."""


def text(element, path):
	value = element.findtext(path, namespaces=NS)
	return value.strip() if value else ""


def load_pom(path):
	if path.is_symlink() or not path.is_file():
		raise SourcePolicyError(f"POM is not a regular file: {path}")
	try:
		data = path.read_bytes()
	except OSError as exception:
		raise SourcePolicyError(f"cannot read POM {path}: {exception}") from exception
	if b"<!DOCTYPE" in data.upper():
		raise SourcePolicyError(f"POM must not contain a DOCTYPE: {path}")
	try:
		return ET.fromstring(data)
	except ET.ParseError as exception:
		raise SourcePolicyError(f"POM is not well-formed XML: {path}: {exception}") from exception


def require_release_changelog(path, version):
	try:
		contents = path.read_text(encoding="utf-8")
	except (OSError, UnicodeError) as exception:
		raise SourcePolicyError(f"cannot read release changelog {path}: {exception}") from exception
	match = re.search(rf"^## {re.escape(version)} \(([0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})\)$", contents, re.MULTILINE)
	if not match:
		raise SourcePolicyError(f"{path} has no dated {version} release heading")
	try:
		date.fromisoformat(match.group(1))
	except ValueError as exception:
		raise SourcePolicyError(f"{path} has an invalid release date") from exception
	if f"The version is `{version}-SNAPSHOT`" in contents:
		raise SourcePolicyError(f"{path} still describes {version}-SNAPSHOT as unreleased")


def require_claims_audit(path):
	if path.is_symlink() or not path.is_file():
		raise SourcePolicyError(f"security claims audit is missing: {path}")
	try:
		contents = path.read_text(encoding="utf-8")
	except (OSError, UnicodeError) as exception:
		raise SourcePolicyError(f"cannot read security claims audit {path}: {exception}") from exception
	for heading in ("Approved", "Narrowed", "Rejected"):
		if not re.search(rf"^## {heading}\s*$", contents, re.MULTILINE):
			raise SourcePolicyError(f"security claims audit is missing the {heading} section")


def require_no_active_snapshot(repository, version):
	"""Reject the release version's snapshot coordinate in active inputs.

	Seeded negative tests, historical review records, and the frozen shared-clock
	migration harness deliberately retain snapshot text and are not release inputs.
	"""
	needle = f"{version}-SNAPSHOT"
	candidates = [repository / name for name in ACTIVE_RELEASE_FILES]
	for root_name in ACTIVE_RELEASE_ROOTS:
		root = repository / root_name
		if root.is_dir() and not root.is_symlink():
			candidates.extend(path for path in root.rglob("*") if path.is_file())
	for path in candidates:
		if path.is_symlink() or not path.is_file() or path.suffix not in ACTIVE_TEXT_SUFFIXES:
			continue
		relative = path.relative_to(repository)
		parts = relative.parts
		is_test_source = any(parts[index:index + 2] == ("src", "test") for index in range(len(parts) - 1))
		if (
			is_test_source
			or parts[:2] == ("docs", "reviews")
			or parts[:2] == ("verification", "shared-clock-migration")
			or "target" in parts
			or path.name.startswith("test_")
		):
			continue
		try:
			contents = path.read_text(encoding="utf-8")
		except (OSError, UnicodeError) as exception:
			raise SourcePolicyError(f"cannot inspect active release input {path}: {exception}") from exception
		if needle in contents:
			raise SourcePolicyError(f"active release input still names {needle}: {relative}")


def require_git_state(repository, version, require_clean, require_tag):
	def git(*arguments):
		result = subprocess.run(
			["git", *arguments], cwd=repository, text=True,
			stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
		)
		if result.returncode != 0:
			detail = result.stderr.strip() or result.stdout.strip()
			raise SourcePolicyError(f"git {' '.join(arguments)} failed in {repository}: {detail}")
		return result.stdout.strip()

	head = git("rev-parse", "HEAD")
	if require_clean and git("status", "--porcelain", "--untracked-files=normal"):
		raise SourcePolicyError(f"release repository is not clean: {repository}")
	if require_tag:
		ref = f"refs/tags/v{version}"
		if git("cat-file", "-t", ref) != "tag":
			raise SourcePolicyError(f"release tag is not annotated: {repository.name} v{version}")
		if git("rev-parse", f"{ref}^{{commit}}") != head:
			raise SourcePolicyError(f"release tag does not point to HEAD: {repository.name} v{version}")
	return head


def require_adapter_core_pins(workspace, expected_core_head):
	for repository_name in REPOSITORIES:
		if repository_name == "revetsec":
			continue
		path = workspace / repository_name / ".github" / "workflows" / "ci.yml"
		if path.is_symlink() or not path.is_file():
			raise SourcePolicyError(f"adapter CI workflow is missing or symbolic: {path}")
		try:
			contents = path.read_text(encoding="utf-8")
		except (OSError, UnicodeError) as exception:
			raise SourcePolicyError(f"cannot read adapter CI workflow {path}: {exception}") from exception
		pins = re.findall(r"^\s*REVETSEC_CORE_SHA:\s*'([0-9a-f]{40})'\s*$", contents, re.MULTILINE)
		if len(pins) != 1:
			raise SourcePolicyError(f"{repository_name} CI must declare exactly one literal REVETSEC_CORE_SHA")
		if pins[0] != expected_core_head:
			raise SourcePolicyError(
				f"{repository_name} CI core pin {pins[0]} does not match release core HEAD {expected_core_head}"
			)


def verify_template(core_repository, version, external_dependencies):
	path = core_repository / "release" / "RELEASE_RECORD.template.json"
	try:
		record = json.loads(path.read_text(encoding="utf-8"))
	except (OSError, UnicodeError, json.JSONDecodeError) as exception:
		raise SourcePolicyError(f"cannot read release-record template {path}: {exception}") from exception
	if record.get("version") != version or record.get("disposition") != "TEMPLATE":
		raise SourcePolicyError("release-record template version or disposition differs from the source set")
	repositories = record.get("repositories")
	if not isinstance(repositories, list):
		raise SourcePolicyError("release-record template repositories are missing")
	actual_repositories = {
		item.get("name"): item.get("tag") for item in repositories if isinstance(item, dict)
	}
	expected_repositories = {name: f"v{version}" for name in REPOSITORIES}
	if actual_repositories != expected_repositories:
		raise SourcePolicyError("release-record template repository tags differ from the source set")
	components = record.get("components")
	if not isinstance(components, list):
		raise SourcePolicyError("release-record template components are missing")
	actual_components = {
		item.get("repository"): item.get("coordinates") for item in components if isinstance(item, dict)
	}
	expected_components = {
		name: f"com.revetsec:{artifact_id}:{version}"
		for name, artifact_id in REPOSITORIES.items()
	}
	if actual_components != expected_components:
		raise SourcePolicyError("release-record template coordinates differ from the source set")
	external = record.get("externalDependencies")
	if not isinstance(external, list):
		raise SourcePolicyError("release-record template external dependencies are missing")
	actual_external = [
		item.get("coordinates") for item in external if isinstance(item, dict)
	]
	expected_external = [item["coordinates"] for item in external_dependencies]
	if actual_external != expected_external:
		raise SourcePolicyError("release-record template external dependencies differ from the source set")


def verify_source_set(workspace, version, phase, require_clean=False, require_tag=False):
	if not VERSION.fullmatch(version):
		raise SourcePolicyError("version must be a literal X.Y.Z release version")
	workspace = Path(workspace).resolve()
	if not workspace.is_dir():
		raise SourcePolicyError(f"workspace is not a directory: {workspace}")
	if require_tag and phase != "release":
		raise SourcePolicyError("--require-tag is valid only in the release phase")
	expected_project_version = version if phase == "release" else f"{version}-SNAPSHOT"
	report = {
		"schema": "revetsec.release-sources.v1",
		"phase": phase,
		"version": version,
		"repositories": {},
		"externalDependencies": [],
		"sourceSetCoherent": True,
	}
	for repository_name, artifact_id in REPOSITORIES.items():
		repository = workspace / repository_name
		if repository.is_symlink() or not repository.is_dir():
			raise SourcePolicyError(f"release repository is missing or symbolic: {repository}")
		project = load_pom(repository / "pom.xml")
		actual = {
			"groupId": text(project, "m:groupId"),
			"artifactId": text(project, "m:artifactId"),
			"version": text(project, "m:version"),
			"scmUrl": text(project, "m:scm/m:url"),
			"scmTag": text(project, "m:scm/m:tag"),
			"coreVersion": text(project, "m:properties/m:revetsec.version"),
		}
		if (actual["groupId"], actual["artifactId"], actual["version"]) != (
			"com.revetsec", artifact_id, expected_project_version,
		):
			raise SourcePolicyError(f"{repository_name} coordinates do not match the {phase} source set")
		if actual["scmUrl"] != f"https://github.com/revetsec/{repository_name}":
			raise SourcePolicyError(f"{repository_name} has the wrong SCM URL")
		if phase == "release" and actual["scmTag"] != f"v{version}":
			raise SourcePolicyError(f"{repository_name} has the wrong release SCM tag")
		if repository_name == "revetsec":
			if actual["coreVersion"]:
				raise SourcePolicyError("core must not declare revetsec.version")
		else:
			if actual["coreVersion"] != expected_project_version:
				raise SourcePolicyError(f"{repository_name} does not select the exact core source-set version")
			core_dependencies = [
				dependency for dependency in project.findall("m:dependencies/m:dependency", NS)
				if text(dependency, "m:groupId") == "com.revetsec"
				and text(dependency, "m:artifactId") == "revetsec"
			]
			if len(core_dependencies) != 1:
				raise SourcePolicyError(f"{repository_name} must have exactly one direct core dependency")
			core_dependency = core_dependencies[0]
			if text(core_dependency, "m:version") != "${revetsec.version}" or text(core_dependency, "m:scope") != "provided":
				raise SourcePolicyError(f"{repository_name} core dependency must use the provided source-set property")
		if repository_name == "revetsec-soklet":
			soklet_version = text(project, "m:properties/m:soklet.version")
			soklet_dependencies = [
				dependency for dependency in project.findall("m:dependencies/m:dependency", NS)
				if text(dependency, "m:groupId") == "com.soklet"
				and text(dependency, "m:artifactId") == "soklet"
			]
			if len(soklet_dependencies) != 1 or not VERSION.fullmatch(soklet_version):
				raise SourcePolicyError("Soklet adapter must select one literal X.Y.Z Soklet dependency")
			soklet_dependency = soklet_dependencies[0]
			if text(soklet_dependency, "m:version") != "${soklet.version}" or text(soklet_dependency, "m:scope") != "provided":
				raise SourcePolicyError("Soklet dependency must use the provided soklet.version property")
			report["externalDependencies"].append({
				"coordinates": f"com.soklet:soklet:{soklet_version}",
				"releaseGate": "published Central artifacts plus owner externalQualification acceptance",
			})
		elif repository_name in ("revetsec-servlet-jakarta", "revetsec-servlet-javax"):
			if repository_name == "revetsec-servlet-jakarta":
				property_name = "jakarta.servlet.version"
				platform_group = "jakarta.servlet"
				platform_artifact = "jakarta.servlet-api"
				expected_platform_version = "6.1.0"
			else:
				property_name = "javax.servlet.version"
				platform_group = "javax.servlet"
				platform_artifact = "javax.servlet-api"
				expected_platform_version = "4.0.1"
			platform_version = text(project, f"m:properties/m:{property_name}")
			platform_dependencies = [
				dependency for dependency in project.findall("m:dependencies/m:dependency", NS)
				if text(dependency, "m:groupId") == platform_group
				and text(dependency, "m:artifactId") == platform_artifact
			]
			if platform_version != expected_platform_version or len(platform_dependencies) != 1:
				raise SourcePolicyError(
					f"{repository_name} must select {platform_group}:{platform_artifact}:{expected_platform_version}"
				)
			platform_dependency = platform_dependencies[0]
			if (
				text(platform_dependency, "m:version") != f"${{{property_name}}}"
				or text(platform_dependency, "m:scope") != "provided"
			):
				raise SourcePolicyError(
					f"{repository_name} platform dependency must use its provided version property"
				)
		if phase == "release":
			require_release_changelog(repository / "CHANGELOG.md", version)
			require_no_active_snapshot(repository, version)
		head = require_git_state(repository, version, require_clean, require_tag)
		report["repositories"][repository_name] = {
			"coordinates": f"com.revetsec:{artifact_id}:{expected_project_version}",
			"head": head,
			"scmTag": actual["scmTag"],
		}
	verify_template(workspace / "revetsec", version, report["externalDependencies"])
	if phase == "release":
		require_claims_audit(workspace / "revetsec" / "release" / "SECURITY_CLAIMS_AUDIT.md")
		if require_clean:
			require_adapter_core_pins(workspace, report["repositories"]["revetsec"]["head"])
	return report


def main(argv=None):
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("workspace", type=Path, help="directory containing all four repositories")
	parser.add_argument("--version", required=True, help="literal release version, for example 1.0.0")
	parser.add_argument("--phase", choices=("snapshot", "release"), required=True)
	parser.add_argument("--require-clean", action="store_true", help="require every repository worktree to be clean")
	parser.add_argument("--require-tag", action="store_true", help="require annotated vVERSION tags at each HEAD")
	arguments = parser.parse_args(argv)
	try:
		result = verify_source_set(
			arguments.workspace, arguments.version, arguments.phase,
			require_clean=arguments.require_clean, require_tag=arguments.require_tag,
		)
	except (OSError, SourcePolicyError) as exception:
		print(f"Release source verification failed: {exception}", file=sys.stderr)
		return 1
	print(json.dumps(result, indent=2, sort_keys=True))
	return 0


if __name__ == "__main__":
	sys.exit(main())
