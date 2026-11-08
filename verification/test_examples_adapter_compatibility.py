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

"""Exercise the pinned adapter guards without Maven or Git mutations."""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest
from unittest import mock
from verification.examples import adapter_compatibility as bridge

class AdapterCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="revetsec-adapter-pin-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.root, self.core, self.adapter = (self.work / name for name in ["authoring", "core", "adapter"])
        self.manifest = json.loads((bridge.ROOT / bridge.MANIFEST).read_text())
        self.revision = self.manifest["adapterRevision"]
        self.write(self.root / bridge.MANIFEST, json.dumps(self.manifest).encode())
        self.write(self.adapter / "pom.xml", b"pinned POM")
        self.write(self.adapter / "src/main/java/Adapter.java", b"pinned library")
        self.write(self.adapter / "src/test/java/AdapterTests.java", b"pinned tests")
        self.library = bridge.tree_hashes(self.adapter, ("pom.xml", "src/main"))
        self.tests = bridge.tree_hashes(self.adapter, ("src/test",))
        patch = mock.patch.object(bridge, "pinned_hashes", side_effect=self.git_hashes)
        patch.start()
        self.addCleanup(patch.stop)

    @staticmethod
    def write(path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def git_hashes(self, source, revision, paths):
        self.assertEqual((self.adapter, self.revision), (source, revision))
        return copy.deepcopy(self.tests if paths == ("src/test",) else self.library)

    def prepare(self):
        return bridge.prepare_adapter(self.core, self.adapter, self.revision, self.root)

    def test_manifest_and_workflows_select_the_published_adapter(self):
        manifest = json.loads((bridge.ROOT / bridge.MANIFEST).read_text())
        self.assertEqual(2, manifest["schemaVersion"])
        self.assertEqual("pinned-upstream-tests", manifest["mode"])
        self.assertEqual(manifest["adapterRevision"], json.loads((bridge.ROOT / "examples/pins.json").read_text())["adapter"]["revision"])
        self.assertEqual(196, manifest["expectedTests"])
        self.assertFalse((bridge.ROOT / "examples/compatibility/soklet-shared-clock/SokletOAuthAuthorizationServerTests.java").exists())

    def test_complete_pinned_sources_pass_without_any_replacement(self):
        before = bridge.tree_hashes(self.adapter, ("pom.xml", "src/main", "src/test"))
        info = self.prepare()
        self.assertEqual("pinned-upstream-tests", info["mode"])
        self.assertEqual(before, bridge.tree_hashes(self.adapter, ("pom.xml", "src/main", "src/test")))
        self.assertEqual(self.tests, info["selectedTestInputs"])

    def test_wrong_revision_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "adapter revision"):
            bridge.prepare_adapter(self.core, self.adapter, "0" * 40, self.root)

    def test_library_pom_and_test_drift_are_rejected(self):
        for relative in ["pom.xml", "src/main/java/Adapter.java", "src/test/java/AdapterTests.java", "src/test/java/Unknown.java"]:
            path = self.adapter / relative
            original = path.read_bytes() if path.exists() else None
            self.write(path, b"unreviewed change")
            with self.assertRaisesRegex(RuntimeError, "library/POM|upstream tests"):
                self.prepare()
            if original is None:
                path.unlink()
            else:
                path.write_bytes(original)

    def test_build_postcondition_rejects_source_drift(self):
        info = self.prepare()
        for relative in ["pom.xml", "src/test/java/AdapterTests.java"]:
            path = self.adapter / relative
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            with self.assertRaisesRegex(RuntimeError, "library/POM changed|selected test sources changed"):
                bridge.assert_adapter_unchanged(self.adapter, info)
            path.write_bytes(original)

    def test_exact_suite_count_and_no_skips_are_required(self):
        info = self.prepare()
        report = self.adapter / "target/surefire-reports/TEST-fixture.xml"
        for count, skipped, failures, valid in [(196, 0, 0, True), (195, 0, 0, False), (196, 1, 0, False), (196, 0, 1, False)]:
            self.write(report, ('<testsuite tests="%d" failures="%d" errors="0" skipped="%d"/>' % (count, failures, skipped)).encode())
            if valid:
                bridge.record_test_results(self.adapter, info)
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
                info = {"mode": "pinned-upstream-tests"}
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
                    info["testResults"] = {"tests": 196, "failures": 0, "errors": 0, "skipped": 0}

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
