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

"""Exercise the pinned adapter test bridge without Maven or Git mutations."""
import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from unittest import mock

from verification.examples import adapter_compatibility as bridge


class AdapterCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="revetsec-adapter-compatibility-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.root = self.work / "authoring"
        self.core = self.work / "core"
        self.adapter = self.work / "adapter"
        self.manifest = json.loads((bridge.ROOT / bridge.MANIFEST).read_text())
        self.fixture = self.manifest["issuerFixture"]
        self.helper = self.manifest["supportHelper"]
        self.revision = self.manifest["adapterRevision"]
        for relative in (*self.manifest["sharedClockCarriers"], self.helper["corePath"],
                         self.fixture["overlayPath"]):
            self.write(self.root / relative, (bridge.ROOT / relative).read_bytes())
        for relative in self.manifest["sharedClockCarriers"]:
            self.write(self.core / relative, (bridge.ROOT / relative).read_bytes())
        # The immutable Git boundary is supplied as hashes. No synthetic commits are needed.
        self.write(self.adapter / "pom.xml", b"pinned POM")
        self.write(self.adapter / "src/main/java/Adapter.java", b"pinned production source")
        self.write(self.adapter / "src/test/java/OtherTests.java", b"other pinned tests")
        self.write(self.adapter / self.fixture["adapterPath"], b"pinned legacy issuer fixture")
        self.fixture["baseSha256"] = bridge.digest(b"pinned legacy issuer fixture")
        self.pinned_library = bridge.tree_hashes(self.adapter, ("pom.xml", "src/main"))
        self.pinned_tests = bridge.tree_hashes(self.adapter, ("src/test",))
        self.save_manifest()
        patch = mock.patch.object(bridge, "pinned_hashes", side_effect=self.git_hashes)
        patch.start()
        self.addCleanup(patch.stop)

    @staticmethod
    def write(path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def save_manifest(self):
        self.write(self.root / bridge.MANIFEST, (json.dumps(self.manifest) + "\n").encode())

    def git_hashes(self, source, revision, paths):
        self.assertEqual(source, self.adapter)
        self.assertEqual(revision, self.revision)
        return copy.deepcopy(self.pinned_tests if paths == ("src/test",) else self.pinned_library)

    def prepare(self):
        return bridge.prepare_adapter(self.core, self.adapter, self.revision, self.root)

    def test_checked_in_manifest_guards_the_exact_fixture_helper_and_carriers(self):
        manifest = json.loads((bridge.ROOT / bridge.MANIFEST).read_text())
        self.assertEqual(manifest["adapterRevision"], json.loads(
            (bridge.ROOT / "examples/pins.json").read_text())["adapter"]["revision"])
        for relative, expected in manifest["sharedClockCarriers"].items():
            self.assertEqual(expected, bridge.digest((bridge.ROOT / relative).read_bytes()))
        for item, path_key, hash_key in ((manifest["issuerFixture"], "overlayPath", "overlaySha256"),
                                         (manifest["supportHelper"], "corePath", "sha256")):
            self.assertEqual(item[hash_key], bridge.digest((bridge.ROOT / item[path_key]).read_bytes()))

    def test_shared_clock_changes_only_declared_tests_and_records_separate_hashes(self):
        before = bridge.tree_hashes(self.adapter, ("pom.xml", "src/main", "src/test"))
        info = self.prepare()
        self.assertEqual("shared-clock-test-overlay", info["mode"])
        after = bridge.tree_hashes(self.adapter, ("pom.xml", "src/main", "src/test"))
        changed = {key for key in before.keys() | after.keys() if before.get(key) != after.get(key)}
        self.assertEqual({self.fixture["adapterPath"], self.helper["adapterPath"]}, changed)
        self.assertEqual(info["pinnedLibraryInputsBefore"], info["pinnedLibraryInputsAfter"])
        self.assertNotEqual(info["issuerFixtureBaseSha256"], info["issuerFixtureOverlay"]["sha256"])
        self.assertEqual(self.helper["sha256"], info["supportHelper"]["sha256"])
        # Re-running on the explicitly selected overlay remains honest and deterministic.
        repeated = self.prepare()
        self.assertEqual(self.fixture["overlaySha256"], repeated["issuerFixtureInputSha256"])

    def test_legacy_core_preserves_all_upstream_tests_and_does_not_need_helper(self):
        shutil.rmtree(self.core)
        self.core.mkdir()
        (self.root / self.helper["corePath"]).unlink()
        (self.root / self.fixture["overlayPath"]).unlink()
        before = bridge.tree_hashes(self.adapter, ("pom.xml", "src/main", "src/test"))
        self.assertEqual("legacy-upstream-tests", self.prepare()["mode"])
        self.assertEqual(before, bridge.tree_hashes(self.adapter, ("pom.xml", "src/main", "src/test")))

    def test_wrong_base_fixture_hash_is_rejected_before_mutation(self):
        self.pinned_tests[self.fixture["adapterPath"]] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "pinned issuer fixture hash"):
            self.prepare()
        self.assertFalse((self.adapter / self.helper["adapterPath"]).exists())

    def test_wrong_overlay_hash_is_rejected_before_mutation(self):
        self.write(self.root / self.fixture["overlayPath"], b"changed overlay")
        before = bridge.tree_hashes(self.adapter, ("src/test",))
        with self.assertRaisesRegex(RuntimeError, "overlay fixture hash mismatch"):
            self.prepare()
        self.assertEqual(before, bridge.tree_hashes(self.adapter, ("src/test",)))

    def test_unknown_revision_carrier_and_partial_spi_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "adapter revision"):
            bridge.prepare_adapter(self.core, self.adapter, "0" * 40, self.root)
        carrier = next(iter(self.manifest["sharedClockCarriers"]))
        original = (self.core / carrier).read_bytes()
        (self.core / carrier).unlink()
        with self.assertRaisesRegex(RuntimeError, "partial shared-clock SPI"):
            self.prepare()
        self.write(self.core / carrier, original + b"\n")
        with self.assertRaisesRegex(RuntimeError, "unknown shared-clock carrier"):
            self.prepare()

    def test_unknown_dirty_tests_or_helper_are_rejected(self):
        for path in ("src/test/java/OtherTests.java", self.fixture["adapterPath"], self.helper["adapterPath"]):
            with self.subTest(path=path):
                target = self.adapter / path
                original = target.read_bytes() if target.exists() else None
                self.write(target, b"unreviewed test change")
                with self.assertRaisesRegex(RuntimeError, "other upstream tests|unknown issuer|unknown existing support"):
                    self.prepare()
                if original is None:
                    target.unlink()
                else:
                    target.write_bytes(original)

    def test_canonical_helper_and_production_drift_are_rejected(self):
        helper = self.root / self.helper["corePath"]
        original = helper.read_bytes()
        helper.write_bytes(original + b"\n")
        with self.assertRaisesRegex(RuntimeError, "canonical support helper hash mismatch"):
            self.prepare()
        helper.write_bytes(original)
        (self.adapter / "pom.xml").write_bytes(b"changed POM")
        with self.assertRaisesRegex(RuntimeError, "library/POM differs from pin"):
            self.prepare()

    def test_build_postcondition_rejects_changes_to_production_or_selected_tests(self):
        info = self.prepare()
        for relative, reason in (("pom.xml", "library/POM changed"),
                                 (self.fixture["adapterPath"], "selected test sources changed")):
            with self.subTest(relative=relative):
                path = self.adapter / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with self.assertRaisesRegex(RuntimeError, reason):
                    bridge.assert_adapter_unchanged(self.adapter, info)
                path.write_bytes(original)

    def test_full_suite_count_and_no_skips_are_required(self):
        info = self.prepare()
        report = self.adapter / "target/surefire-reports/TEST-fixture.xml"
        for tests, skipped, accepted in ((169, 0, True), (168, 0, False), (169, 1, False)):
            with self.subTest(tests=tests, skipped=skipped):
                self.write(report, ('<testsuite tests="%d" failures="0" errors="0" skipped="%d"/>' %
                                    (tests, skipped)).encode())
                if accepted:
                    bridge.record_test_results(self.adapter, info)
                    self.assertEqual(169, info["testResults"]["tests"])
                else:
                    with self.assertRaises(RuntimeError):
                        bridge.record_test_results(self.adapter, info)

    def test_scim_workflow_runs_full_adapter_suite_and_records_success_and_failure(self):
        workflow = (bridge.ROOT / ".github/workflows/scim-interop.yml").read_text()
        step = workflow.split("      - name: Build current SCIM core and pinned adapter\n", 1)[1]
        step = step.split("      - name:", 1)[0]
        match = re.search(r"          python3 - <<'PY'\n(.*?)^          PY$", step, re.M | re.S)
        self.assertIsNotNone(match, "SCIM adapter install must use the checked compatibility bridge")
        script = compile(textwrap.dedent(match.group(1)), "scim-interop-adapter-step", "exec")
        adapter = bridge.ROOT / ".scim-inputs/adapter"
        revision = json.loads((bridge.ROOT / "examples/pins.json").read_text())["adapter"]["revision"]
        for failed in (False, True):
            with self.subTest(adapter_install_failed=failed):
                receipt = self.work / "ADAPTER-COMPATIBILITY.json"
                receipt.unlink(missing_ok=True)
                info = {"mode": "shared-clock-test-overlay"}
                calls = []

                def prepare(core, selected_adapter, selected_revision):
                    self.assertEqual((bridge.ROOT, adapter, revision),
                                     (core, selected_adapter, selected_revision))
                    calls.append("prepare")
                    return info

                def install(command, *, check):
                    calls.append("install")
                    self.assertTrue(check)
                    self.assertEqual(["clean", "install"], command[-2:])
                    self.assertEqual(str(adapter / "pom.xml"), command[command.index("-f") + 1])
                    self.assertFalse(any("skipTests" in arg or "maven.test.skip" in arg for arg in command))
                    self.assertEqual(info, json.loads(receipt.read_text()))
                    if failed:
                        raise subprocess.CalledProcessError(1, command)

                def postcondition(selected_adapter, selected_info):
                    self.assertEqual((adapter, info), (selected_adapter, selected_info))
                    calls.append("postcondition")
                    info["postcondition"] = "checked"

                def results(selected_adapter, selected_info):
                    self.assertEqual((adapter, info), (selected_adapter, selected_info))
                    calls.append("results")
                    info["testResults"] = {"tests": 169, "failures": 0, "errors": 0, "skipped": 0}

                with mock.patch.object(bridge, "prepare_adapter", side_effect=prepare), \
                     mock.patch.object(bridge, "assert_adapter_unchanged", side_effect=postcondition), \
                     mock.patch.object(bridge, "record_test_results", side_effect=results), \
                     mock.patch("subprocess.run", side_effect=install), \
                     mock.patch.object(Path, "cwd", return_value=bridge.ROOT), \
                     mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.work)}):
                    if failed:
                        with self.assertRaises(subprocess.CalledProcessError):
                            exec(script, {})
                    else:
                        exec(script, {})
                self.assertEqual(["prepare", "install", "postcondition"] + ([] if failed else ["results"]), calls)
                self.assertEqual(info, json.loads(receipt.read_text()))
                self.assertEqual(not failed, "testResults" in info)


if __name__ == "__main__":
    unittest.main()
