# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""The optional workload flags must not break the shared probe's compile closure."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(os.environ.get('REVETSEC_WORKSPACE_ROOT',Path(__file__).resolve().parents[3]))
HERE=ROOT/'revetsec/verification/shared-clock-migration'

class AdapterSourceSelectionTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  sys.path.insert(0,str(HERE))
  selected=Path(os.environ.get('ADAPTER_JOIN_SELECTION_SOURCE',HERE/'run_adapter_join.py'))
  namespace={'__name__':'adapter_source_selection_control','__file__':str(HERE/'run_adapter_join.py')}
  exec(compile(selected.read_text(),str(selected),'exec'),namespace)
  cls.selected=staticmethod(namespace['current_sources'])
  cls.java=Path(os.environ.get('SCP10_JAVA_HOME','/Users/agents/Java/amazon-corretto-21.jdk/Contents/Home'))/'bin/javac'
  cls.core=Path(os.environ.get('SCP10_CORE_JAR',namespace['DEFAULT_CORE']))
  expected=os.environ.get('SCP10_CORE_SHA256',namespace['DEFAULT_CORE_SHA256'])
  if hashlib.sha256(cls.core.read_bytes()).hexdigest()!=expected:raise AssertionError('Explicit current artifact mismatch')
  manifest=json.loads((ROOT/'planning/records/security/shared-clock-scp01-2026-10-29/ARTIFACT-PRESERVATION.json').read_text())
  cls.dependencies=[]
  for name in ['com.pyranid:pyranid:4.7.0','org.postgresql:postgresql:42.7.14','org.jspecify:jspecify:1.0.1','com.google.code.findbugs:jsr305:3.0.2','com.google.errorprone:error_prone_annotations:2.50.0']:
   row=next(r for r in manifest['artifacts'] if r.get('coordinate')==name);path=ROOT/row['frozen_path']
   if hashlib.sha256(path.read_bytes()).hexdigest()!=row['sha256']:raise AssertionError('Pinned dependency mismatch')
   cls.dependencies.append(path)
 def compile(self,quota):
  sources=self.selected(ROOT/'revetsec/examples/postgresql-pending-store/src/main/java/example/pending',quota_allocation=quota)
  with tempfile.TemporaryDirectory(prefix='revetsec-adapter-closure-') as directory:
   result=subprocess.run([str(self.java),'--release','17','-proc:none','-Xlint:all','-Werror','-cp',os.pathsep.join(map(str,[self.core,*self.dependencies])),'-d',directory,*map(str,sources)],capture_output=True,text=True,timeout=45)
  self.assertEqual(result.returncode,0,result.stdout+result.stderr)
 def test_default_shared_probe_has_complete_compile_dependencies(self):self.compile(False)
 def test_quota_shared_probe_has_complete_compile_dependencies(self):self.compile(True)
 def test_core_without_hash_is_rejected_before_output_creation(self):
  with tempfile.TemporaryDirectory(prefix='revetsec-adapter-arguments-') as directory:
   output=Path(directory)/'output'
   result=subprocess.run([sys.executable,str(HERE/'run_adapter_join.py'),'--output',str(output),'--java-home',str(self.java.parent.parent),'--core-jar',str(self.core)],capture_output=True,text=True,timeout=15)
   self.assertEqual(result.returncode,2,result.stdout+result.stderr)
   self.assertIn('--core-jar requires its explicit --core-sha256',result.stderr)
   self.assertFalse(output.exists())
 def test_hash_without_core_is_rejected_before_output_creation(self):
  with tempfile.TemporaryDirectory(prefix='revetsec-adapter-arguments-') as directory:
   output=Path(directory)/'output'
   result=subprocess.run([sys.executable,str(HERE/'run_adapter_join.py'),'--output',str(output),'--java-home',str(self.java.parent.parent),'--core-sha256','0'*64],capture_output=True,text=True,timeout=15)
   self.assertEqual(result.returncode,2,result.stdout+result.stderr)
   self.assertIn('--core-sha256 requires --core-jar',result.stderr)
   self.assertFalse(output.exists())

if __name__=='__main__':unittest.main()
