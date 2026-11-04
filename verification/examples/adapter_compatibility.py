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

"""Explicit, hash-guarded test compatibility for the pinned Soklet adapter."""
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
    """Modify only the private copy's two declared test paths, or fail closed."""
    manifest_path = root / MANIFEST
    manifest = json.loads(manifest_path.read_text())
    require(manifest["schemaVersion"] == 1, "unknown manifest schema")
    require(revision == manifest["adapterRevision"], "adapter revision differs from guarded base")
    library_paths = ("pom.xml", "src/main")
    before = tree_hashes(adapter, library_paths)
    require(before == pinned_hashes(adapter, revision, library_paths), "library/POM differs from pin")
    carriers = {path: digest((core / path).read_bytes()) if (core / path).is_file() else None
                for path in manifest["sharedClockCarriers"]}
    present = sum(value is not None for value in carriers.values())
    require(present in (0, len(carriers)), "partial shared-clock SPI")
    shared_clock = present != 0
    if shared_clock:
        require(carriers == manifest["sharedClockCarriers"], "unknown shared-clock carrier source")
    fixture = manifest["issuerFixture"]
    helper = manifest["supportHelper"]
    base_tests = pinned_hashes(adapter, revision, ("src/test",))
    require(base_tests.get(fixture["adapterPath"]) == fixture["baseSha256"],
            "pinned issuer fixture hash differs from guarded base")
    tests_before = tree_hashes(adapter, ("src/test",))
    info = {"mode": "shared-clock-test-overlay" if shared_clock else "legacy-upstream-tests",
            "manifestSha256": digest(manifest_path.read_bytes()), "adapterRevision": revision,
            "coreCarriers": carriers, "pinnedLibraryInputsBefore": before,
            "issuerFixtureBaseSha256": fixture["baseSha256"],
            "issuerFixtureInputSha256": tests_before.get(fixture["adapterPath"])}
    if shared_clock:
        excluded = {fixture["adapterPath"], helper["adapterPath"]}
        require({k: v for k, v in tests_before.items() if k not in excluded} ==
                {k: v for k, v in base_tests.items() if k not in excluded},
                "other upstream tests differ from pin")
        require(info["issuerFixtureInputSha256"] in (fixture["baseSha256"], fixture["overlaySha256"]),
                "unknown issuer fixture input")
        overlay_bytes = (root / fixture["overlayPath"]).read_bytes()
        helper_bytes = (root / helper["corePath"]).read_bytes()
        require(digest(overlay_bytes) == fixture["overlaySha256"], "overlay fixture hash mismatch")
        require(digest(helper_bytes) == helper["sha256"], "canonical support helper hash mismatch")
        helper_before = tests_before.get(helper["adapterPath"])
        require(helper_before in (None, helper["sha256"], *helper["acceptedExistingSha256"]),
                "unknown existing support helper")
        for destination, data in ((fixture["adapterPath"], overlay_bytes),
                                  (helper["adapterPath"], helper_bytes)):
            path = adapter / destination
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        info.update({"issuerFixtureOverlay": {"path": fixture["overlayPath"],
                                               "sha256": fixture["overlaySha256"]},
                     "supportHelper": {"corePath": helper["corePath"], "sha256": helper["sha256"],
                                       "inputSha256": helper_before},
                     "expectedTests": manifest["expectedSharedClockTests"]})
    else:
        require(tests_before == base_tests, "legacy core requires unchanged pinned adapter tests")
    info["selectedTestInputs"] = tree_hashes(adapter, ("src/test",))
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
