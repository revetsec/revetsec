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

"""Resolve, compile and run Maven and Gradle consumers against a Central release."""

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import zipfile
import xml.etree.ElementTree as ET


DIRECTORY = Path(__file__).resolve().parent
PACKAGED_PATH = DIRECTORY / "packaged-consumer" / "verify-packaged-consumer.py"
PACKAGED_SPEC = importlib.util.spec_from_file_location("verify_packaged_consumer", PACKAGED_PATH)
PACKAGED = importlib.util.module_from_spec(PACKAGED_SPEC)
PACKAGED_SPEC.loader.exec_module(PACKAGED)

CANONICAL_REPOSITORY = "https://repo.maven.apache.org/maven2"
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
COMPONENTS = (
	"revetsec",
	"revetsec-soklet",
	"revetsec-servlet-jakarta",
	"revetsec-servlet-javax",
)
MAVEN_NAMESPACE = "http://maven.apache.org/POM/4.0.0"
MAVEN_NS = {"m": MAVEN_NAMESPACE}


class ConsumerPolicyError(ValueError):
	"""The released component failed exact Maven/Gradle consumer verification."""


def sha256(path):
	digest = hashlib.sha256()
	with path.open("rb") as source:
		for chunk in iter(lambda: source.read(1 << 16), b""):
			digest.update(chunk)
	return digest.hexdigest()


def literal_version(value, label):
	if not isinstance(value, str) or not VERSION.fullmatch(value):
		raise ConsumerPolicyError(f"{label} must be a literal X.Y.Z release version")
	return value


def component_spec(component, version, soklet_version=None):
	literal_version(version, "version")
	core = f"com.revetsec:revetsec:{version}"
	if component == "revetsec":
		return {
			"coordinates": core,
			"dependencies": [core],
			"classes": [
				"com.revetsec.StateSealer",
				"com.revetsec.oauth.OAuthClient",
				"com.revetsec.scim.ScimResource",
			],
		}
	if component == "revetsec-soklet":
		literal_version(soklet_version, "soklet-version")
		coordinates = f"com.revetsec:revetsec-soklet:{version}"
		return {
			"coordinates": coordinates,
			"dependencies": [coordinates, core, f"com.soklet:soklet:{soklet_version}"],
			"classes": [
				"com.revetsec.soklet.SokletOAuth",
				"com.revetsec.soklet.SokletSaml",
				"com.revetsec.soklet.SokletScim",
			],
		}
	if component == "revetsec-servlet-jakarta":
		coordinates = f"com.revetsec:revetsec-servlet-jakarta:{version}"
		return {
			"coordinates": coordinates,
			"dependencies": [coordinates, core, "jakarta.servlet:jakarta.servlet-api:6.1.0"],
			"classes": [
				"com.revetsec.servlet.jakarta.ServletOAuth",
				"com.revetsec.servlet.jakarta.ServletSaml",
				"com.revetsec.servlet.jakarta.ServletScim",
			],
		}
	if component == "revetsec-servlet-javax":
		coordinates = f"com.revetsec:revetsec-servlet-javax:{version}"
		return {
			"coordinates": coordinates,
			"dependencies": [coordinates, core, "javax.servlet:javax.servlet-api:4.0.1"],
			"classes": [
				"com.revetsec.servlet.javax.ServletOAuth",
				"com.revetsec.servlet.javax.ServletSaml",
				"com.revetsec.servlet.javax.ServletScim",
			],
		}
	raise ConsumerPolicyError(f"unsupported release component: {component!r}")


def artifact_paths(repository, coordinates):
	group_id, artifact_id, version = coordinates.split(":")
	directory = repository.joinpath(*group_id.split("."), artifact_id, version)
	return {
		"jar": directory / f"{artifact_id}-{version}.jar",
		"pom": directory / f"{artifact_id}-{version}.pom",
	}


def pom_text(element, path):
	value = element.findtext(path, namespaces=MAVEN_NS)
	return value.strip() if value else ""


def verify_component_pom(path, spec):
	try:
		data = path.read_bytes()
	except OSError as exception:
		raise ConsumerPolicyError(f"cannot read resolved component POM {path}: {exception}") from exception
	if b"<!DOCTYPE" in data.upper():
		raise ConsumerPolicyError("resolved component POM must not contain a DOCTYPE")
	try:
		project = ET.fromstring(data)
	except ET.ParseError as exception:
		raise ConsumerPolicyError(f"resolved component POM is malformed: {exception}") from exception
	coordinates = ":".join((
		pom_text(project, "m:groupId"), pom_text(project, "m:artifactId"), pom_text(project, "m:version"),
	))
	if coordinates != spec["coordinates"]:
		raise ConsumerPolicyError(
			f"resolved component POM coordinates are {coordinates}, expected {spec['coordinates']}"
		)
	properties = {
		child.tag.rsplit("}", 1)[-1]: (child.text or "").strip()
		for child in project.findall("m:properties/*", MAVEN_NS)
	}
	def resolve(value):
		match = re.fullmatch(r"\$\{([^}]+)\}", value)
		return properties.get(match.group(1), "") if match else value

	functional_groups = {"com.revetsec", "com.soklet", "jakarta.servlet", "javax.servlet"}
	actual = {}
	for dependency in project.findall("m:dependencies/m:dependency", MAVEN_NS):
		group_id = pom_text(dependency, "m:groupId")
		if group_id not in functional_groups:
			continue
		artifact_id = pom_text(dependency, "m:artifactId")
		actual[f"{group_id}:{artifact_id}"] = {
			"version": resolve(pom_text(dependency, "m:version")),
			"scope": pom_text(dependency, "m:scope") or "compile",
		}
	expected = {}
	for dependency_coordinates in spec["dependencies"][1:]:
		group_id, artifact_id, version = dependency_coordinates.split(":")
		expected[f"{group_id}:{artifact_id}"] = {"version": version, "scope": "provided"}
	if actual != expected:
		raise ConsumerPolicyError(
			f"resolved component POM functional dependencies differ; expected={expected}, actual={actual}"
		)
	return actual


def require_exact_classpath(path, expected_paths, label, separator=None):
	try:
		contents = path.read_text(encoding="utf-8").strip()
	except (OSError, UnicodeError) as exception:
		raise ConsumerPolicyError(f"cannot read {label} classpath: {exception}") from exception
	values = contents.split(separator) if separator is not None else contents.splitlines()
	entries = [Path(value).resolve() for value in values if value]
	expected = {candidate.resolve(): coordinates for coordinates, candidate in expected_paths.items()}
	if len(entries) != len(set(entries)) or set(entries) != set(expected):
		raise ConsumerPolicyError(
			f"{label} classpath differs; expected={sorted(str(item) for item in expected)}, "
			f"actual={sorted(str(item) for item in entries)}"
		)
	return [expected[entry] for entry in entries]


def java_source(classes):
	literals = ",\n\t\t\t".join(f"{name}.class" for name in classes)
	expected = ",".join(classes)
	return f"""package example;

public final class ReleasedConsumer {{
\tprivate ReleasedConsumer() {{}}

\tpublic static void main(String[] arguments) {{
\t\tClass<?>[] linked = {{
\t\t\t{literals}
\t\t}};
\t\tString actual = java.util.Arrays.stream(linked)
\t\t\t\t.map(Class::getName).collect(java.util.stream.Collectors.joining(","));
\t\tif (!actual.equals("{expected}"))
\t\t\tthrow new AssertionError(actual);
\t\tSystem.out.println("linked=" + actual);
\t}}
}}
"""


def dependency_xml(coordinates):
	items = []
	for value in coordinates:
		group_id, artifact_id, version = value.split(":")
		items.append(
			f"<dependency><groupId>{group_id}</groupId><artifactId>{artifact_id}</artifactId>"
			f"<version>{version}</version></dependency>"
		)
	return "\n".join(items)


def write_consumer_sources(root, spec):
	source = root / "src" / "main" / "java" / "example" / "ReleasedConsumer.java"
	source.parent.mkdir(parents=True)
	source.write_text(java_source(spec["classes"]), encoding="utf-8")
	(root / "pom.xml").write_text(f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.revetsec.verification</groupId><artifactId>released-consumer</artifactId><version>1</version>
  <properties><maven.compiler.release>17</maven.compiler.release><project.build.sourceEncoding>UTF-8</project.build.sourceEncoding></properties>
  <dependencies>{dependency_xml(spec['dependencies'])}</dependencies>
  <build><plugins>
    <plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-clean-plugin</artifactId><version>3.5.0</version></plugin>
    <plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-compiler-plugin</artifactId><version>3.16.0</version>
      <configuration><release>17</release><showWarnings>true</showWarnings><failOnWarning>true</failOnWarning><compilerArgs><arg>-Xlint:all</arg></compilerArgs></configuration></plugin>
    <plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-dependency-plugin</artifactId><version>3.11.0</version>
      <executions><execution><id>classpath</id><phase>compile</phase><goals><goal>build-classpath</goal></goals>
        <configuration><includeScope>runtime</includeScope><outputFile>${{project.build.directory}}/runtime-classpath.txt</outputFile></configuration>
      </execution></executions></plugin>
  </plugins></build>
</project>
""", encoding="utf-8")
	gradle_dependencies = "\n".join(
		f'\timplementation "{coordinates}"' for coordinates in spec["dependencies"]
	)
	(root / "build.gradle").write_text(f"""plugins {{ id 'java' }}

String releaseRepository = providers.gradleProperty('release.repository').get()
repositories {{ maven {{ url = uri(releaseRepository) }} }}
dependencies {{
{gradle_dependencies}
}}
tasks.withType(JavaCompile).configureEach {{
\toptions.release = 17
\toptions.encoding = 'UTF-8'
\toptions.compilerArgs += ['-Xlint:all', '-Werror']
}}
tasks.register('writeClasspaths') {{
\tdef outputDirectory = layout.buildDirectory.dir('release-consumer')
\toutputs.dir(outputDirectory)
\tdoLast {{
\t\tFile directory = outputDirectory.get().asFile
\t\tdirectory.mkdirs()
\t\t['runtimeClasspath', 'compileClasspath'].each {{ name ->
\t\t\tFile target = new File(directory, name + '.txt')
\t\t\ttarget.setText(configurations.getByName(name).files.collect {{ it.canonicalPath }}.sort().join('\\n') + '\\n', 'UTF-8')
\t\t}}
\t}}
}}
""", encoding="utf-8")
	(root / "settings.gradle").write_text("rootProject.name = 'released-consumer'\n", encoding="utf-8")
	(root / "settings.xml").write_text(f"""<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">
  <mirrors><mirror><id>canonical-central-only</id><name>Canonical Central only</name>
    <url>{CANONICAL_REPOSITORY}</url><mirrorOf>*</mirrorOf></mirror></mirrors>
</settings>
""", encoding="utf-8")


def validate_central_receipt(path, spec, component_paths):
	try:
		data = path.read_bytes()
		receipt = json.loads(data.decode("utf-8"))
	except (OSError, UnicodeError, json.JSONDecodeError) as exception:
		raise ConsumerPolicyError(f"cannot read Central receipt {path}: {exception}") from exception
	required = {
		"schema", "verifiedAt", "coordinates", "repository", "approvedBundle",
		"files", "signaturesVerified", "signingFingerprint", "exactBundleContent",
	}
	if not isinstance(receipt, dict) or set(receipt) != required:
		raise ConsumerPolicyError("Central receipt has an unexpected schema shape")
	if receipt["schema"] != "revetsec.central-publication-verification.v1":
		raise ConsumerPolicyError("Central receipt has the wrong schema")
	try:
		verified_at = datetime.fromisoformat(receipt["verifiedAt"].replace("Z", "+00:00"))
	except (AttributeError, ValueError) as exception:
		raise ConsumerPolicyError("Central receipt has an invalid verification timestamp") from exception
	if verified_at.tzinfo is None:
		raise ConsumerPolicyError("Central receipt verification timestamp lacks a timezone")
	if receipt["coordinates"] != spec["coordinates"] or receipt["repository"] != CANONICAL_REPOSITORY:
		raise ConsumerPolicyError("Central receipt does not identify the selected canonical release")
	if receipt["signaturesVerified"] is not True or receipt["exactBundleContent"] is not True:
		raise ConsumerPolicyError("Central receipt does not verify exact signed content")
	if not isinstance(receipt["signingFingerprint"], str) or not re.fullmatch(
		r"(?:[0-9A-F]{40}|[0-9A-F]{64})", receipt["signingFingerprint"]
	):
		raise ConsumerPolicyError("Central receipt has an invalid release-signing fingerprint")
	bundle = receipt["approvedBundle"]
	if (
		not isinstance(bundle, dict) or set(bundle) != {"path", "sha256"}
		or not isinstance(bundle["path"], str) or not bundle["path"]
		or not isinstance(bundle["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", bundle["sha256"])
	):
		raise ConsumerPolicyError("Central receipt approved bundle is invalid")
	if not isinstance(receipt["files"], dict):
		raise ConsumerPolicyError("Central receipt files must be an object")
	group_id, artifact_id, version = spec["coordinates"].split(":")
	base = f"{CANONICAL_REPOSITORY}/{group_id.replace('.', '/')}/{artifact_id}/{version}"
	prefix = f"{artifact_id}-{version}"
	payload_names = {
		f"{prefix}.pom", f"{prefix}.jar", f"{prefix}-sources.jar",
		f"{prefix}-javadoc.jar", f"{prefix}-cyclonedx.json",
	}
	expected_names = payload_names | {f"{name}.asc" for name in payload_names}
	if set(receipt["files"]) != expected_names:
		raise ConsumerPolicyError("Central receipt does not contain the exact payload and signature set")
	for name, entry in receipt["files"].items():
		if (
			not isinstance(entry, dict) or set(entry) != {"url", "sha256"}
			or entry["url"] != f"{base}/{name}"
			or not isinstance(entry["sha256"], str)
			or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
		):
			raise ConsumerPolicyError(f"Central receipt entry is invalid for {name}")
	for extension in ("jar", "pom"):
		name = f"{artifact_id}-{version}.{extension}"
		entry = receipt["files"].get(name)
		if not component_paths[extension].is_file() or sha256(component_paths[extension]) != entry["sha256"]:
			raise ConsumerPolicyError(f"resolved {name} differs from the signed Central receipt")
	return hashlib.sha256(data).hexdigest()


def run_java(java, classes, jars, expected_classes, java_home, description):
	output = PACKAGED.run(
		[str(java), "-cp", os.pathsep.join([str(classes), *(str(path) for path in jars)]), "example.ReleasedConsumer"],
		env=PACKAGED.java_environment(java_home), description=description,
	).strip()
	expected = "linked=" + ",".join(expected_classes)
	if output != expected:
		raise ConsumerPolicyError(f"{description} produced {output!r}, expected {expected!r}")
	return output


def verify_consumers(arguments):
	spec = component_spec(arguments.component, arguments.version, arguments.soklet_version)
	java_home = arguments.java_home.resolve()
	java = java_home / "bin" / "java"
	if not java.is_file():
		raise ConsumerPolicyError(f"Java launcher not found: {java}")
	if not arguments.gradle_distribution.is_file():
		raise ConsumerPolicyError(f"Gradle distribution not found: {arguments.gradle_distribution}")
	PACKAGED.check_gradle_distribution_digest(arguments.gradle_distribution)

	if arguments.work_directory is None:
		temporary = tempfile.TemporaryDirectory(prefix="revetsec-central-consumers-")
		work = Path(temporary.name)
	else:
		temporary = None
		work = arguments.work_directory.resolve()
		if work.exists() and any(work.iterdir()):
			raise ConsumerPolicyError(f"work directory must be empty: {work}")
		work.mkdir(parents=True, exist_ok=True)
	try:
		consumer = work / "consumer"
		consumer.mkdir()
		write_consumer_sources(consumer, spec)
		repository = work / "maven-repository"
		repository.mkdir()
		PACKAGED.run(
			[
				arguments.maven, "-B", "-ntp", "-nsu", "--strict-checksums",
				"-s", str(consumer / "settings.xml"), f"-Dmaven.repo.local={repository}",
				"-f", str(consumer / "pom.xml"), "clean", "compile",
			],
			env=PACKAGED.java_environment(java_home), description="Maven Central consumer build",
		)
		paths = {coordinates: artifact_paths(repository, coordinates) for coordinates in spec["dependencies"]}
		for coordinates, artifact in paths.items():
			for kind, path in artifact.items():
				if not path.is_file():
					raise ConsumerPolicyError(f"Maven did not resolve {kind} for {coordinates}: {path}")
		component_dependencies = verify_component_pom(paths[spec["coordinates"]]["pom"], spec)
		expected_jars = {coordinates: artifact["jar"] for coordinates, artifact in paths.items()}
		maven_coordinates = require_exact_classpath(
			consumer / "target" / "runtime-classpath.txt", expected_jars, "Maven runtime",
			separator=os.pathsep,
		)
		maven_output = run_java(
			java, consumer / "target" / "classes",
			[expected_jars[coordinates] for coordinates in maven_coordinates],
			spec["classes"], java_home, "Maven Central consumer",
		)

		gradle = PACKAGED.unpack_gradle_distribution(
			arguments.gradle_distribution, work / "gradle-distribution"
		)
		PACKAGED.run(
			[
				str(gradle), "--offline", "--no-daemon", "--no-build-cache", "--no-configuration-cache",
				"--console=plain", "--warning-mode=fail", "--stacktrace",
				"--project-dir", str(consumer), f"-Prelease.repository={repository}",
				"clean", "classes", "writeClasspaths",
			],
			env=PACKAGED.gradle_environment(java_home, work / "gradle-user-home"),
			description="Gradle Central consumer build",
		)
		gradle_runtime = require_exact_classpath(
			consumer / "build" / "release-consumer" / "runtimeClasspath.txt",
			expected_jars, "Gradle runtime",
		)
		require_exact_classpath(
			consumer / "build" / "release-consumer" / "compileClasspath.txt",
			expected_jars, "Gradle compile",
		)
		gradle_output = run_java(
			java, consumer / "build" / "classes" / "java" / "main",
			[expected_jars[coordinates] for coordinates in gradle_runtime],
			spec["classes"], java_home, "Gradle Central consumer",
		)

		component_paths = paths[spec["coordinates"]]
		central_receipt_sha256 = validate_central_receipt(
			arguments.central_receipt, spec, component_paths
		)
		artifacts = {
			coordinates: {
				"jarSha256": sha256(artifact["jar"]),
				"pomSha256": sha256(artifact["pom"]),
			}
			for coordinates, artifact in paths.items()
		}
		return {
			"schema": "revetsec.central-consumer-verification.v1",
			"verifiedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
			"coordinates": spec["coordinates"],
			"repository": CANONICAL_REPOSITORY,
			"javaHome": str(java_home),
			"centralReceipt": {
				"path": str(arguments.central_receipt),
				"sha256": central_receipt_sha256,
			},
			"componentDependencies": component_dependencies,
			"artifacts": artifacts,
			"maven": {"result": "PASS", "classpath": maven_coordinates, "output": maven_output},
			"gradle": {
				"result": "PASS", "version": PACKAGED.GRADLE_VERSION,
				"distributionSha256": PACKAGED.GRADLE_DISTRIBUTION_SHA256,
				"classpath": gradle_runtime, "output": gradle_output,
			},
			"result": "PASS",
		}
	finally:
		if temporary is not None:
			temporary.cleanup()


def write_receipt(path, result):
	if path.exists() or path.is_symlink():
		raise ConsumerPolicyError(f"receipt path already exists: {path}")
	if not path.parent.is_dir():
		raise ConsumerPolicyError(f"receipt parent directory does not exist: {path.parent}")
	path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv=None):
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("--component", choices=COMPONENTS, required=True)
	parser.add_argument("--version", required=True)
	parser.add_argument("--soklet-version", help="qualified Soklet release; required for revetsec-soklet")
	parser.add_argument("--central-receipt", type=Path, required=True)
	parser.add_argument("--java-home", type=Path, default=os.environ.get("JAVA_HOME"))
	parser.add_argument("--maven", default=shutil.which("mvn"))
	parser.add_argument("--gradle-distribution", type=Path, required=True)
	parser.add_argument("--work-directory", type=Path)
	parser.add_argument("--output", type=Path, required=True, help="create-new JSON receipt path")
	arguments = parser.parse_args(argv)
	if arguments.java_home is None:
		parser.error("--java-home is required when JAVA_HOME is not set")
	if not arguments.maven:
		parser.error("--maven is required when mvn is not on PATH")
	try:
		result = verify_consumers(arguments)
		write_receipt(arguments.output, result)
	except (ConsumerPolicyError, PACKAGED.VerificationError, OSError, zipfile.BadZipFile) as exception:
		print(f"Central consumer verification failed: {exception}", file=sys.stderr)
		return 1
	print(json.dumps(result, indent=2, sort_keys=True))
	return 0


if __name__ == "__main__":
	sys.exit(main())
