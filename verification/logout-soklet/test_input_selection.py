# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
"""Pure runner-input rejection controls; no Java process or socket is started."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
import zipfile
import run

class SelectedInputTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        common=self.root/'rp-initiated-logout/target';carrier=self.root/'rp-initiated-logout-soklet/target'
        self.paths={'common':common/'revetsec-rp-initiated-logout-1.0.0-SNAPSHOT.jar','fixture':common/'revetsec-rp-initiated-logout-1.0.0-SNAPSHOT-tests.jar','core':common/'lib/revetsec-1.0.0-SNAPSHOT.jar','carrier':carrier/'rp-initiated-logout-soklet-1.0.0-SNAPSHOT.jar','framework':carrier/'lib/soklet-4.0.0.jar'}
        for path in self.paths.values():
            path.parent.mkdir(parents=True,exist_ok=True)
            with zipfile.ZipFile(path,'w')as jar:jar.writestr('META-INF/MANIFEST.MF','Manifest-Version: 1.0\n\n')
        self.classes=carrier/'test-classes';self.fixture=self.classes/'example/logout/soklet/SokletLogoutSocketFixture.class';self.fixture.parent.mkdir(parents=True);self.fixture.write_bytes(b'not-executed')
        java=self.root/'java/bin/java';java.parent.mkdir(parents=True);java.write_bytes(b'not-executed')
        self.args=SimpleNamespace(examples_root=self.root,java_home=self.root/'java',**{n+'_sha256':run.digest(p)for n,p in self.paths.items()})
    def test_exact_five_inputs_are_selected_without_io(self):
        java,selected,classes,watched=run.inputs(self.args);self.assertEqual(selected,self.paths);self.assertEqual(classes,self.classes);self.assertEqual(len(selected),5)
    def test_each_wrong_digest_is_rejected_before_process(self):
        for name in self.paths:
            with self.subTest(name=name):
                original=getattr(self.args,name+'_sha256');setattr(self.args,name+'_sha256','0'*64)
                with self.assertRaises(ValueError):run.inputs(self.args)
                setattr(self.args,name+'_sha256',original)
    def test_missing_fixture_is_rejected(self):
        self.fixture.unlink()
        with self.assertRaises(ValueError):run.inputs(self.args)
    def test_missing_java_is_rejected(self):
        (self.root/'java/bin/java').unlink()
        with self.assertRaises(ValueError):run.inputs(self.args)
    def test_core_shadow_is_rejected(self):
        path=self.classes/'com/revetsec/StateSealer.class';path.parent.mkdir(parents=True);path.write_bytes(b'shadow')
        with self.assertRaises(ValueError):run.inputs(self.args)
    def test_common_shadow_is_rejected(self):
        path=self.classes/'example/logout/LocalFirstLogout.class';path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'shadow')
        with self.assertRaises(ValueError):run.inputs(self.args)
    def test_unselected_manifest_dependency_is_rejected(self):
        path=self.paths['carrier']
        with zipfile.ZipFile(path,'w')as jar:jar.writestr('META-INF/MANIFEST.MF','Manifest-Version: 1.0\nClass-Path: surprise.jar\n\n')
        self.args.carrier_sha256=run.digest(path)
        with self.assertRaises(ValueError):run.inputs(self.args)
    def test_over_cap_artifact_is_rejected_before_zip_parse(self):
        path=self.paths['core']
        with path.open('wb')as stream:stream.truncate(16_777_217)
        self.args.core_sha256=run.digest(path)
        with self.assertRaises(ValueError):run.inputs(self.args)

if __name__=='__main__':unittest.main()
