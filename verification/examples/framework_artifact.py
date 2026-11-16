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

"""Identify a supplied Soklet artifact by the Maven coordinates it carries.

Soklet 4.0.0 is a published Maven Central release, so the examples pin its coordinates rather
than a checksum. Maven checks downloads against Central's own published checksums.
"""

import zipfile
import xml.etree.ElementTree as ET

POM_NAMESPACE = {"m": "http://maven.apache.org/POM/4.0.0"}


def jar_coordinates(jar):
    """Return the groupId:artifactId:version that Maven embedded in a JAR, or None."""
    try:
        with zipfile.ZipFile(jar) as archive:
            names = [name for name in archive.namelist()
                     if name.startswith("META-INF/maven/") and name.endswith("/pom.properties")]
            if len(names) != 1:
                return None
            text = archive.read(names[0]).decode("utf-8")
    except (OSError, zipfile.BadZipFile, UnicodeDecodeError):
        return None
    values = dict(line.split("=", 1) for line in text.splitlines()
                  if "=" in line and not line.startswith("#"))
    return ":".join(values.get(key, "").strip() for key in ("groupId", "artifactId", "version"))


def pom_coordinates(pom):
    """Return the groupId:artifactId:version declared by a POM file, or None."""
    try:
        root = ET.parse(pom).getroot()
    except (OSError, ET.ParseError):
        return None
    return ":".join((root.findtext("m:" + key, default="", namespaces=POM_NAMESPACE) or "").strip()
                    for key in ("groupId", "artifactId", "version"))
