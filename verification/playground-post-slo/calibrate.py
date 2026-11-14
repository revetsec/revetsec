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
"""Private exact source plants: actual socket and cross-auth session-cancellation oracles."""
import argparse,hashlib,json,os,shutil,subprocess,sys,xml.etree.ElementTree as ET
from pathlib import Path

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 parser=argparse.ArgumentParser(description=__doc__)
 if not __debug__:parser.error('Python optimization disables assertions')
 parser.add_argument('--examples-root',type=Path,required=True);parser.add_argument('--repository',type=Path,required=True);parser.add_argument('--java-home',type=Path,required=True);parser.add_argument('--maven',type=Path,required=True);parser.add_argument('--core-sha256',required=True);parser.add_argument('--adapter-sha256',required=True);parser.add_argument('--framework-sha256',required=True);parser.add_argument('--output',type=Path,required=True)
 args=parser.parse_args();fixture=Path(__file__).resolve().parent;module=args.examples_root/'playground';main=module/'src/main/java/example/playground';sources={p.name:p.read_text()for p in [main/'BrowserSessions.java',main/'PlaygroundSaml.java']}
 definitions=[('ignore-trusted-post-mode','PlaygroundSaml.java',[('boolean postLogout = logoutBinding.equals("post");','boolean postLogout = false;')],'socket','post-form-delivered'),('ignore-final-cancellation','BrowserSessions.java',[('if (old.authenticationGeneration != generation) throw new IllegalStateException("Browser session changed.");','if (false) throw new IllegalStateException("Browser session changed.");'),(' || old.authenticationClosed || old.authenticationGeneration == Long.MAX_VALUE','')],'socket','post-validation-cancellation-final-rotation-denied'),('ignore-session-index','BrowserSessions.java', [('if (!request.getSessionIndexes().isEmpty()\n                    && reference.getSessionIndex().filter(request.getSessionIndexes()::contains).isEmpty()) continue;','')],'socket','full-signed-session-index-keeps-unmatched-session'),('ignore-other-auth-closed-object','BrowserSessions.java',[(' || old.authenticationClosed || old.authenticationGeneration == Long.MAX_VALUE','')],'unit','localCloseCancelsOtherAuthPendingAndHeldObjectCannotRotateButFreshBootstrapCan')]
 for name,path,changes,mode,expected in definitions:
  for old,new in changes:
   if sources[path].count(old)!=1:parser.error('Private exact plant anchor changed: '+name)
 if args.output.exists():parser.error('Fresh output required')
 args.output.mkdir(parents=True);env=dict(os.environ);env['JAVA_HOME']=str(args.java_home);env['PATH']=str(args.java_home/'bin')+os.pathsep+env['PATH'];env.pop('JAVA_TOOL_OPTIONS',None);env.pop('JDK_JAVA_OPTIONS',None)
 watched={str(p):sha(p)for p in [*main.glob('*.java'),fixture/'run.py',Path(__file__)]};receipt={'success':False,'sourceInputs':watched,'plants':[],'scope':'Private application-source defects only; no core defect or full mutation/profile score. Exact socket and genuine-signed-SSO/app-session unit oracles; live sources stay unchanged.'}
 def native(examples,out):
  built=examples/'playground/target';jar=built/'playground-1.0.0.jar';cmd=[sys.executable,'-B',str(fixture/'run.py'),'--examples-root',str(examples),'--java-home',str(args.java_home),'--repository',str(args.repository),'--core-sha256',args.core_sha256,'--adapter-sha256',args.adapter_sha256,'--framework-sha256',args.framework_sha256,'--application-sha256',sha(jar),'--output',str(out)];r=subprocess.run(cmd,capture_output=True,text=True,timeout=90);(args.output/(out.parent.name+'-'+out.name+'-process.log')).write_text(r.stdout+r.stderr);return r.returncode,json.loads((out/'RESULT.json').read_text())
 try:
  code,control=native(args.examples_root,args.output/'control');assert code==0 and control['success'] and control['sourceStable'] and control['ownedProcessStopped'] and control['ownedInstanceRemoved'],'green-socket-control-required';receipt['control']=str(args.output/'control/RESULT.json')
  for name,path,changes,mode,expected in definitions:
   root=args.output/name;examples=root/'examples';examples.mkdir(parents=True);shutil.copyfile(args.examples_root/'pom.xml',examples/'pom.xml');shutil.copytree(module,examples/'playground',ignore=shutil.ignore_patterns('target','.git','__pycache__'));planted=examples/'playground/src/main/java/example/playground'/path;candidate=sources[path]
   for old,new in changes:candidate=candidate.replace(old,new)
   planted.write_text(candidate);cmd=[str(args.maven),'-o','-B','-ntp','-Dmaven.repo.local='+str(args.repository),'-f',str(examples/'playground/pom.xml')]
   if mode=='socket':cmd+=['-DskipTests','package']
   else:cmd+=['-Dtest=PlaygroundSamlTests#'+expected,'test']
   completed=subprocess.run(cmd,capture_output=True,text=True,env=env,timeout=120);(root/'maven.log').write_text(completed.stdout+completed.stderr)
   if mode=='socket':
    assert completed.returncode==0,'private-plant-build-required-'+name;code,result=native(examples,root/'socket');failure=result.get('failure',{});detected=code==1 and failure.get('type')=='AssertionError' and failure.get('message')==expected and result['sourceStable'] and result['ownedProcessStopped'] and result['ownedInstanceRemoved'];detail={'failure':failure,'lastCheck':result['checks'][-1]if result['checks']else None}
   else:
    reports=list((examples/'playground/target/surefire-reports').glob('TEST-*.xml'));assert len(reports)==1,'one-selected-unit-suite';suite=ET.parse(reports[0]).getroot();cases=suite.findall('testcase');failures=suite.findall('testcase/failure');detected=completed.returncode==1 and len(cases)==1 and cases[0].get('name')==expected and len(failures)==1 and suite.get('errors')=='0' and suite.get('skipped')=='0' and 'IllegalStateException' in failures[0].get('message','');detail={'testcase':cases[0].get('name'),'failureType':failures[0].get('type')if failures else None,'message':failures[0].get('message')if failures else None}
   receipt['plants'].append({'name':name,'sourceSha256':sha(planted),'mode':mode,'expectedAssertion':expected,'detected':detected,'detail':detail});assert detected,'named-plant-detection-required-'+name
  assert all(sha(Path(p))==v for p,v in watched.items()),'live-source-changed';receipt['success']=True
 except Exception as failure:receipt['failure']={'type':type(failure).__name__,'message':str(failure)[:200]}
 (args.output/'CALIBRATION.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({'success':receipt['success'],'detected':sum(p['detected']for p in receipt['plants']),'failure':receipt.get('failure')}));return 0 if receipt['success']else 1
if __name__=='__main__':raise SystemExit(main())
