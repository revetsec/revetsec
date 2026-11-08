#!/usr/bin/env python3
# Copyright 2026 Revetware LLC.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Artifact identity failures must precede output and owned-resource creation."""
import hashlib,subprocess,sys,tempfile,unittest,zipfile
from pathlib import Path

class InputSelectionTests(unittest.TestCase):
 def invoke(self,root,kind,value):
  examples=root/'examples';module=examples/'playground';libs=module/'target/lib';libs.mkdir(parents=True)
  paths={'application':module/'target/playground-1.0.0-SNAPSHOT.jar','core':libs/'revetsec-1.0.0-SNAPSHOT.jar','adapter':libs/'revetsec-soklet-1.0.0-SNAPSHOT.jar','framework':libs/'soklet-4.0.0.jar'}
  for name,p in paths.items():p.write_bytes(('private-placeholder-'+name).encode())
  command=[sys.executable,'-B',str(Path(__file__).with_name('run.py')),'--examples-root',str(examples),'--java-home',str(root),'--repository',str(root),'--output',str(root/'evidence')]
  for name,p in paths.items():command+=['--'+name+'-sha256',value if name==kind else hashlib.sha256(p.read_bytes()).hexdigest()]
  result=subprocess.run(command,capture_output=True,text=True,timeout=5)
  self.assertEqual(2,result.returncode);self.assertIn('Selected '+kind.upper()+' artifact mismatch before resources',result.stderr);self.assertFalse((root/'evidence').exists())
 def test_core(self):self.variants('core')
 def test_adapter(self):self.variants('adapter')
 def test_framework(self):self.variants('framework')
 def test_application(self):self.variants('application')
 def variants(self,kind):
  for value in ['0'*64,'A'*64,'invalid']:
   with self.subTest(kind=kind,value=value),tempfile.TemporaryDirectory(prefix='slo-selection-')as directory:self.invoke(Path(directory),kind,value)
if __name__=='__main__':unittest.main()
