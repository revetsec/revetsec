#!/usr/bin/env python3
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

from pathlib import Path
import hashlib,json,os,subprocess,shutil
import argparse,re
parser=argparse.ArgumentParser(description="Public-only packaged WebAuthn reauthentication consumer and exhaustive-result calibration")
parser.add_argument('--core-jar',required=True,type=Path)
parser.add_argument('--core-sha256',required=True)
parser.add_argument('--java-home',required=True,type=Path,action='append')
parser.add_argument('--work',required=True,type=Path)
args=parser.parse_args()
root=Path(__file__).resolve().parent;jar=args.core_jar.resolve();sha=hashlib.sha256(jar.read_bytes()).hexdigest()
if sha!=args.core_sha256:parser.error('Selected core SHA differs')
output=args.work.resolve()
if not args.work.is_absolute() or output.exists() or root==output or root in output.parents:parser.error('--work must be a new absolute directory outside fixture sources')
output.mkdir(parents=True,mode=0o700);results=[]
versions={}
for home in args.java_home:
 check=subprocess.run([str(home/'bin/javac'),'-version'],capture_output=True,text=True,timeout=10)
 match=re.search(r'javac (17|21|27)(?:[. ]|$)',check.stdout+check.stderr)
 if check.returncode or not match:parser.error('Expected JDK17,21or27')
 version=int(match.group(1))
 if version in versions:parser.error('Duplicate JDK version')
 versions[version]=home/'bin'

def run(name,command,expect=0,contains=None):
 result=subprocess.run(command,capture_output=True,text=True,timeout=40);log=output/(name+'.log');log.write_text(result.stdout+result.stderr);passed=result.returncode==expect and(contains is None or contains in result.stderr);results.append({'name':name,'command':command,'returncode':result.returncode,'expected':expect,'expectedDiagnostic':contains,'passed':passed,'log':str(log)});assert passed,name
for version,java in sorted(versions.items()):
 out=output/('classes'+str(version));out.mkdir();sources=list((root/'src').rglob('*.java'))
 run(str(version)+'-compile',[str(java/'javac'),'--release','17','-Xlint:all','-Werror','-cp',str(jar),'-d',str(out),*map(str,sources)])
 cp=os.pathsep.join(map(str,[out,jar]))
 for label,command in [('CP',[str(java/'java'),'-cp',cp]),('MP',[str(java/'java'),'--module-path',str(jar),'--add-modules','com.revetsec','-cp',str(out)])]:run(str(version)+'-'+label,[*command,'consumer.PublicProofCases',str(jar),sha])
 if version>=21:
  switch=root/'java21/consumer/ExhaustiveProofResults.java';run(str(version)+'-switch-compile',[str(java/'javac'),'--release','21','-Xlint:all','-Werror','-cp',cp,'-d',str(out),str(switch)])
  for label,command in [('CP',[str(java/'java'),'-cp',cp]),('MP',[str(java/'java'),'--module-path',str(jar),'--add-modules','com.revetsec','-cp',str(out)])]:run(str(version)+'-'+label+'-switch',[*command,'consumer.PublicProofCases',str(jar),sha,'exhaustive'])
  for variant in ['Succeeded','Rejected','Unavailable','Indeterminate','ReconciliationRequired']:
   plant=output/('missing-'+variant+'-'+str(version));plant.mkdir();source=plant/'ExhaustiveProofResults.java';text=switch.read_text();line='   case WebAuthnReauthenticationResult.'+variant+' value -> "'+variant+'";\n';assert text.count(line)==1;source.write_text(text.replace(line,''));run(str(version)+'-missing-'+variant,[str(java/'javac'),'--release','21','-Xlint:all','-Werror','-cp',str(jar),'-d',str(plant),str(source)],1,'the switch expression does not cover all possible input values')
 for name,code,diagnostic in [
  ('OrdinaryProof','package consumer;import com.revetsec.webauthn.WebAuthnAuthentication;final class OrdinaryProof{static void misuse(WebAuthnAuthentication ordinary){PublicProofCases.consumeSelectedAction(ordinary);}}','WebAuthnAuthentication cannot be converted to WebAuthnReauthentication'),
  ('GenericSuccess','package consumer;import com.revetsec.webauthn.WebAuthnAuthenticationResult;final class GenericSuccess{static void misuse(WebAuthnAuthenticationResult.Succeeded ordinary){PublicProofCases.consumeSelectedAction(ordinary.getAuthentication());}}','WebAuthnAuthentication cannot be converted to WebAuthnReauthentication'),
  ('PublicConstruction','package consumer;import com.revetsec.webauthn.WebAuthnReauthentication;final class PublicConstruction{static Object misuse(){return new WebAuthnReauthentication("n","rp",new byte[]{1},new byte[]{2},"p","id");}}','cannot be accessed from outside package')]:
  dest=output/(name+str(version));dest.mkdir();source=dest/(name+'.java');source.write_text(code);run(str(version)+'-negative-'+name,[str(java/'javac'),'--release','17','-Xlint:all','-Werror','-cp',cp,'-d',str(dest),str(source)],1,diagnostic)
(output/'RESULT.json').write_text(json.dumps({'coreSha256':sha,'sourceHashes':{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()for p in root.rglob('*.java')if not any(part.startswith(('jdk','qualified'))for part in p.relative_to(root).parts)},'commands':results,'success':all(r['passed']for r in results),'missingVariantPlants':5*sum(version>=21 for version in versions),'negativePublicTypeCases':3*len(versions),'privateConstructorBypass':False,'runtimeProductionClasspath':'exact core JAR only, plus external consumer classfiles; no annotations/JUnit/coretest/internalclassshadow'},indent=2)+'\n')
