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

"""Keep the container runtime aligned with the actual Soklet application."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
NAMESPACES = {"m": "http://maven.apache.org/POM/4.0.0"}
runner_spec = importlib.util.spec_from_file_location("scim_runtime_runner", HERE / "run.py")
runner = importlib.util.module_from_spec(runner_spec)
runner_spec.loader.exec_module(runner)


def compiler_release(pom):
    root = ET.parse(pom).getroot()
    for plugin in root.findall("m:build/m:plugins/m:plugin", NAMESPACES):
        if plugin.findtext("m:artifactId", namespaces=NAMESPACES) == "maven-compiler-plugin":
            return int(plugin.findtext("m:configuration/m:release", namespaces=NAMESPACES))
    raise AssertionError("POM has no explicit compiler release")


class RuntimeBaselineTests(unittest.TestCase):
    def test_pinned_java_matches_the_playground_compiler_release(self):
        release = compiler_release(ROOT / "examples/playground/pom.xml")
        self.assertEqual(release, 21)
        self.assertEqual(runner.PINS["java"].get("requiredMajor"), release)
        self.assertRegex(runner.PINS["java"]["image"],
                         rf"^amazoncorretto:{release}-[^@]+@sha256:[0-9a-f]{{64}}$")

    def test_application_image_uses_the_digest_pinned_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            classes = directory / "input-classes"
            classes.mkdir()
            (classes / "application.class").write_bytes(b"synthetic application bytes")
            dependency = directory / "dependency.jar"
            dependency.write_bytes(b"synthetic dependency bytes")
            build = directory / "build"
            build.mkdir()
            runner.prepare_application(build, classes, os.pathsep.join((str(classes), str(dependency))))
            dockerfile = (build / "Dockerfile").read_text()
            self.assertEqual(dockerfile.splitlines()[0], "FROM " + runner.PINS["java"]["image"])
            self.assertIn('"example.playground.ScimPlayground"', dockerfile)
            self.assertEqual((build / "application/classes/application.class").read_bytes(),
                             b"synthetic application bytes")
            self.assertEqual((build / "application/libraries/1-dependency.jar").read_bytes(),
                             b"synthetic dependency bytes")

    def test_core_retains_java_17(self):
        self.assertEqual(compiler_release(ROOT / "pom.xml"), 17)


if __name__ == "__main__":
    unittest.main()
