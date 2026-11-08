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

"""Read-only source and complete-test guards for the pinned Soklet adapter."""
import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "examples/compatibility/soklet-shared-clock/manifest.json"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def tree_hashes(source, paths):
    result = {}
    for relative in paths:
        path = source / relative
        files = sorted(path.rglob("*")) if path.is_dir() else [path]
        for item in files:
            if item.is_file():
                result[item.relative_to(source).as_posix()] = digest(item.read_bytes())
    return result


def pinned_hashes(source, revision, paths):
    names = subprocess.check_output(["git", "-C", str(source), "ls-tree", "-r", "--name-only",
                                     revision, "--", *paths], text=True).splitlines()
    return {name: digest(subprocess.check_output(
        ["git", "-C", str(source), "show", revision + ":" + name])) for name in names}


def require(condition, message):
    if not condition:
        raise RuntimeError("Adapter test compatibility: " + message)


def prepare_adapter(core, adapter, revision, root=ROOT):
    """Verify unchanged pinned library and test inputs; never patch the private copy."""
    manifest_path = root / MANIFEST
    manifest = json.loads(manifest_path.read_text())
    require(manifest["schemaVersion"] == 2 and manifest["mode"] == "pinned-upstream-tests",
            "unknown manifest schema or mode")
    require(revision == manifest["adapterRevision"], "adapter revision differs from guarded pin")
    before = tree_hashes(adapter, ("pom.xml", "src/main"))
    require(before == pinned_hashes(adapter, revision, ("pom.xml", "src/main")),
            "library/POM differs from pin")
    tests = tree_hashes(adapter, ("src/test",))
    require(tests == pinned_hashes(adapter, revision, ("src/test",)), "upstream tests differ from pin")
    info = {"mode": "pinned-upstream-tests", "manifestSha256": digest(manifest_path.read_bytes()),
            "adapterRevision": revision, "coreSourceRoot": str(core),
            "pinnedLibraryInputsBefore": before, "selectedTestInputs": tests,
            "expectedTests": manifest["expectedTests"]}
    assert_adapter_unchanged(adapter, info)
    return info


def assert_adapter_unchanged(adapter, info):
    after = tree_hashes(adapter, ("pom.xml", "src/main"))
    require(after == info["pinnedLibraryInputsBefore"], "library/POM changed during build")
    require(tree_hashes(adapter, ("src/test",)) == info["selectedTestInputs"],
            "selected test sources changed during build")
    info["pinnedLibraryInputsAfter"] = after


def record_test_results(adapter, info):
    reports = sorted((adapter / "target/surefire-reports").glob("TEST-*.xml"))
    require(bool(reports), "adapter test reports missing")
    totals = {name: 0 for name in ("tests", "failures", "errors", "skipped")}
    for path in reports:
        report = ET.parse(path).getroot()
        for name in totals:
            totals[name] += int(report.get(name, 0))
    require(totals["tests"] > 0 and not any(totals[name] for name in ("failures", "errors", "skipped")),
            "adapter suite did not run completely and successfully")
    if "expectedTests" in info:
        require(totals["tests"] == info["expectedTests"], "shared-clock adapter test count changed")
    info["testResults"] = totals
    assert_adapter_unchanged(adapter, info)
