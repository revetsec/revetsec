# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Real CLI input refusals occur before output/resource creation; build the normal Maven module first."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


class SelectedArtifactTests(unittest.TestCase):
    def setUp(self):
        self.examples = Path(os.environ.get("PROVIDER_SOKLET_EXAMPLES_ROOT", ROOT / "examples")).resolve()
        self.java = Path(os.environ["PROVIDER_SOKLET_JAVA_HOME"])
        self.common = self.examples / "provider-backend-tokens/target/revetsec-provider-backend-tokens-1.0.0.jar"
        self.carrier = self.examples / "provider-backend-tokens-soklet/target/provider-backend-tokens-soklet-1.0.0.jar"
        self.core = self.common.parent / "lib/revetsec-1.0.0.jar"
        self.framework = self.carrier.parent / "lib/soklet-4.0.0.jar"
        self.core_hash = hashlib.sha256(self.core.read_bytes()).hexdigest()
        self.framework_hash = hashlib.sha256(self.framework.read_bytes()).hexdigest()

    def invoke(self, root, output, core_hash, framework_hash):
        return subprocess.run(["python3", str(HERE / "run.py"), "--examples-root", str(root),
                               "--java-home", str(self.java), "--core-sha256", core_hash,
                               "--framework-sha256", framework_hash, "--output", str(output)],
                              capture_output=True, text=True, timeout=15)

    def test_runtime_mismatch_refuses_before_output(self):
        with tempfile.TemporaryDirectory(prefix="revetsec-soklet-pins-") as work:
            for name, core, framework in [("core", "0" * 64, self.framework_hash),
                                          ("framework", self.core_hash, "0" * 64)]:
                with self.subTest(name=name):
                    output = Path(work) / name
                    result = self.invoke(self.examples, output, core, framework)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("Selected runtime artifact digest mismatch", result.stderr)
                    self.assertFalse(output.exists())

    def test_manifest_cannot_add_an_unselected_runtime(self):
        with tempfile.TemporaryDirectory(prefix="revetsec-soklet-manifest-") as work:
            tree = Path(work) / "examples"
            common = tree / self.common.relative_to(self.examples)
            common.parent.mkdir(parents=True)
            with zipfile.ZipFile(self.common) as before, zipfile.ZipFile(common, "w") as after:
                for item in before.infolist():
                    data = before.read(item.filename)
                    if item.filename == "META-INF/MANIFEST.MF":
                        data = b"Manifest-Version: 1.0\r\nClass-Path: lib/unselected.jar\r\n\r\n"
                    after.writestr(item.filename, data)
            for original in [self.core, self.carrier, self.framework]:
                selected = tree / original.relative_to(self.examples)
                selected.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(original, selected)
            fixtures = tree / "provider-backend-tokens-soklet/target/test-classes/example/provider/soklet"
            fixtures.mkdir(parents=True)
            (fixtures / "ProviderSokletSocketFixture.class").write_bytes(b"not executed")
            output = Path(work) / "refused"
            result = self.invoke(tree, output, self.core_hash, self.framework_hash)
            self.assertEqual(result.returncode, 2)
            self.assertIn("Unselected manifest runtime dependency", result.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
