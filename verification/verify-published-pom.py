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

"""Fail unless a Revetsec POM gives consumers zero compile, runtime or system dependencies.

Run it on the POM exactly as a consumer receives it: the file `mvn install` wrote
into a local repository, or the file downloaded from Central. It checks INV-L1 and
plan section 10.2 statically, and fails closed on anything it cannot decide:

- the document is a Maven 4.0.0 POM with no DOCTYPE or entity declarations;
- groupId, artifactId and version are literal, and match --expect when given;
- packaging is jar;
- there is no <parent>, which could contribute dependencies this file does not show;
- there are no <repositories>, so consumers are never pointed at another repository;
- every <dependency> in <dependencies>, and in every <profile>'s <dependencies>
  (dependency POM profiles can activate during consumer resolution), has scope
  provided or test. A missing scope means compile. A scope written as a property
  cannot be verified statically, so it fails.

<dependencyManagement> and plugin dependencies never reach a consumer's class path,
so they are not checked.
"""

import argparse
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


POM_NAMESPACE = "http://maven.apache.org/POM/4.0.0"
NAMESPACES = {"m": POM_NAMESPACE}
ALLOWED_SCOPES = ("provided", "test")


class PomPolicyError(ValueError):
    """The POM breaks the zero-dependency policy, or could not be checked."""


class DeclaredDependency:
    def __init__(self, location, coordinates, scope):
        self.location = location
        self.coordinates = coordinates
        self.scope = scope

    def as_dict(self):
        return {"location": self.location, "coordinates": self.coordinates, "scope": self.scope}


class VerifiedPom:
    def __init__(self, group_id, artifact_id, version, dependencies):
        self.group_id = group_id
        self.artifact_id = artifact_id
        self.version = version
        self.dependencies = dependencies

    @property
    def coordinates(self):
        return f"{self.group_id}:{self.artifact_id}:{self.version}"

    def as_dict(self):
        return {
            "coordinates": self.coordinates,
            "dependencies": [dependency.as_dict() for dependency in self.dependencies],
        }


def load_pom(path):
    data = Path(path).read_bytes()
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise PomPolicyError(f"{path}: a DOCTYPE or entity declaration is not allowed in a published POM")
    try:
        project = ET.fromstring(data)
    except ET.ParseError as exception:
        raise PomPolicyError(f"{path}: not well-formed XML: {exception}") from exception
    if project.tag != f"{{{POM_NAMESPACE}}}project":
        raise PomPolicyError(f"{path}: root element must be <project> in namespace {POM_NAMESPACE}")
    return project


def literal_text(element, path, description):
    value = element.findtext(path, namespaces=NAMESPACES)
    if value is None or not value.strip():
        raise PomPolicyError(f"POM must declare {description}")
    value = value.strip()
    if "${" in value:
        raise PomPolicyError(f"POM must declare {description} as a literal, found {value!r}")
    return value


def optional_text(element, path, default):
    value = element.findtext(path, namespaces=NAMESPACES)
    if value is None or not value.strip():
        return default
    return value.strip()


def dependency_containers(project):
    yield "dependencies", project.find("m:dependencies", NAMESPACES)
    for profile in project.findall("m:profiles/m:profile", NAMESPACES):
        profile_id = optional_text(profile, "m:id", "<no id>")
        yield f"profile {profile_id} dependencies", profile.find("m:dependencies", NAMESPACES)


def repository_containers(project):
    yield "repositories", project.find("m:repositories", NAMESPACES)
    for profile in project.findall("m:profiles/m:profile", NAMESPACES):
        profile_id = optional_text(profile, "m:id", "<no id>")
        yield f"profile {profile_id} repositories", profile.find("m:repositories", NAMESPACES)


def dependency_coordinates(dependency):
    group_id = optional_text(dependency, "m:groupId", "?")
    artifact_id = optional_text(dependency, "m:artifactId", "?")
    version = optional_text(dependency, "m:version", "?")
    packaging = optional_text(dependency, "m:type", "jar")
    classifier = optional_text(dependency, "m:classifier", "")
    coordinates = f"{group_id}:{artifact_id}:{packaging}"
    if classifier:
        coordinates += f":{classifier}"
    return f"{coordinates}:{version}"


def parse_expected_coordinates(value):
    parts = value.split(":")
    if len(parts) != 3 or not all(part.strip() for part in parts):
        raise argparse.ArgumentTypeError("expected groupId:artifactId:version")
    return tuple(part.strip() for part in parts)


def verify_pom(path, expected_coordinates=None):
    """Return a VerifiedPom, or raise PomPolicyError listing every violation."""
    project = load_pom(path)
    violations = []

    try:
        group_id = literal_text(project, "m:groupId", "a groupId")
        artifact_id = literal_text(project, "m:artifactId", "an artifactId")
        version = literal_text(project, "m:version", "a version")
    except PomPolicyError as exception:
        raise PomPolicyError(f"{path}: {exception}") from exception

    if expected_coordinates is not None and (group_id, artifact_id, version) != tuple(expected_coordinates):
        violations.append(
            f"coordinates are {group_id}:{artifact_id}:{version}, expected {':'.join(expected_coordinates)}"
        )

    packaging = optional_text(project, "m:packaging", "jar")
    if packaging != "jar":
        violations.append(f"packaging is {packaging!r}, expected 'jar'")

    if project.find("m:parent", NAMESPACES) is not None:
        violations.append("declares a <parent>, which could contribute dependencies this file does not show")

    for location, container in repository_containers(project):
        if container is not None and len(container.findall("m:repository", NAMESPACES)) > 0:
            violations.append(f"{location}: declares a <repository>; consumers must resolve from Central only")

    dependencies = []
    for location, container in dependency_containers(project):
        if container is None:
            continue
        for dependency in container.findall("m:dependency", NAMESPACES):
            coordinates = dependency_coordinates(dependency)
            scope = optional_text(dependency, "m:scope", "compile")
            dependencies.append(DeclaredDependency(location, coordinates, scope))
            if "${" in scope:
                violations.append(f"{location}: {coordinates} has scope {scope!r}, which cannot be verified statically")
            elif scope not in ALLOWED_SCOPES:
                violations.append(
                    f"{location}: {coordinates} has scope {scope!r}; only {' and '.join(ALLOWED_SCOPES)} are allowed"
                )

    if violations:
        raise PomPolicyError(f"{path}:\n" + "\n".join(f"  - {violation}" for violation in violations))

    return VerifiedPom(group_id, artifact_id, version, dependencies)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("pom", type=Path, help="the installed or published POM to check")
    parser.add_argument(
        "--expect",
        type=parse_expected_coordinates,
        metavar="GROUP:ARTIFACT:VERSION",
        help="fail unless the POM declares exactly these coordinates",
    )
    arguments = parser.parse_args(argv)
    try:
        verified = verify_pom(arguments.pom, arguments.expect)
    except (PomPolicyError, OSError) as exception:
        print(f"Published POM verification failed: {exception}", file=sys.stderr)
        return 1
    print(f"Verified POM: {arguments.pom}")
    print(f"Coordinates: {verified.coordinates}")
    if verified.dependencies:
        for dependency in verified.dependencies:
            print(f"  {dependency.scope:<8} {dependency.coordinates} ({dependency.location})")
    else:
        print("  (no dependencies declared)")
    print("Consumers inherit zero compile, runtime and system dependencies.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
