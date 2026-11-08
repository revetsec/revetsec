# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
"""Invalid artifact selection refuses before output, javac or disposable PostgreSQL creation."""
from pathlib import Path
import hashlib
import subprocess
import sys
import tempfile
import unittest

RUNNER=Path(__file__).resolve().parents[2]/'examples/postgresql-pending-store/run_issuer_cleanup.py'
class SelectedInputTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.output=self.root/'output';java=self.root/'java/bin';java.mkdir(parents=True);(java/'java').write_bytes(b'not-executed');(java/'javac').write_bytes(b'not-executed');self.paths={}
        for name in ['core','pyranid','driver','jspecify','jsr305','errorprone']:
            path=self.root/(name+'.jar');path.write_bytes(name.encode());self.paths[name]=path
    def command(self):
        result=[sys.executable,str(RUNNER),'--java-home',str(self.root/'java'),'--output',str(self.output)]
        for name,path in self.paths.items():result.extend(['--'+name+'-jar',str(path),'--'+name+'-sha256',hashlib.sha256(path.read_bytes()).hexdigest()])
        return result
    def refused(self,command):
        result=subprocess.run(command,capture_output=True,text=True,timeout=10);self.assertEqual(2,result.returncode);self.assertFalse(self.output.exists());self.assertNotIn('Traceback',result.stderr)
    def test_each_wrong_digest_refuses_before_output_or_process(self):
        for name in self.paths:
            with self.subTest(name=name):
                command=self.command();command[command.index('--'+name+'-sha256')+1]='0'*64;self.refused(command)
    def test_missing_jdk_refuses_before_output(self):
        (self.root/'java/bin/javac').unlink();self.refused(self.command())
    def test_oversize_artifact_refuses_before_parsing_or_output(self):
        with self.paths['driver'].open('wb')as file:file.truncate(16_777_217)
        self.refused(self.command())
    def test_relative_output_refuses(self):
        command=self.command();command[command.index('--output')+1]='relative';self.refused(command)
    def test_baseline_requires_preserved_old_store(self):self.refused([*self.command(),'--baseline-only'])
    def test_baseline_override_without_baseline_mode_refuses(self):
        file=self.root/'old.java';file.write_bytes(b'preserved');self.refused([*self.command(),'--baseline-store',str(file),'--baseline-store-sha256',hashlib.sha256(file.read_bytes()).hexdigest()])
    def test_wrong_preserved_store_digest_refuses(self):
        file=self.root/'old.java';file.write_bytes(b'preserved');self.refused([*self.command(),'--baseline-only','--baseline-store',str(file),'--baseline-store-sha256','0'*64])
    def test_legacy_fixture_requires_baseline_mode(self):
        file=self.root/'IssuerStoreProbe.java';file.write_bytes(b'preserved');self.refused([*self.command(),'--legacy-issuer-fixture',str(file),'--legacy-issuer-fixture-sha256',hashlib.sha256(file.read_bytes()).hexdigest()])
    def test_legacy_digest_requires_explicit_fixture(self):self.refused([*self.command(),'--legacy-issuer-fixture-sha256','0'*64])
    def test_invalid_genuine_offset_refuses(self):self.refused([*self.command(),'--genuine-offset-nanos','2'])

if __name__=='__main__':unittest.main()
