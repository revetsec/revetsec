#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Private exact-JAR administrative codec subprocesses, not a runtime store API."""
from pathlib import Path
import base64, hashlib, json, os, subprocess

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
FAMILIES={
 'TOTP':('com.revetsec.totp.FrozenTotpWriter','com.revetsec.totp.ClosedTotpCodec','NAMESPACE_STATE'),
 'WEBAUTHN':('com.revetsec.internal.webauthn.FrozenWebAuthnWriter','com.revetsec.internal.webauthn.ClosedWebAuthnCodec','NAMESPACE_CLOCK'),
 'ISSUER':('com.revetsec.oauth.server.FrozenIssuerWriter','com.revetsec.oauth.server.ClosedIssuerCodec','ISSUER_STATE')}
ANNOTATIONS=('org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar','com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar','com/google/errorprone/error_prone_annotations/2.50.0/error_prone_annotations-2.50.0.jar')
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def identifier(value):return base64.urlsafe_b64encode(bytes([value])+bytes(31)).rstrip(b'=').decode()
def synthetic_config():
 return {'migrationId':identifier(11),'authorityId':identifier(12),'recoveryGeneration':identifier(13),'activeKeyId':'k','keys':{'k':base64.b64encode(bytes(range(1,33))).decode()},'maximumRecordBytes':16384,'legacyMaximumRecordBytes':16384,'issuer':'https://issuer.example','minimumSeconds':1700000000,'minimumNanos':999999999,'totpScope':identifier(31),'webauthnScope':identifier(32),'issuerScope':identifier(33)}
def root_rows(rows):return [r for r in rows if ':'+FAMILIES[r['family']][2]+':' in r['key']]
def protected_write(path,value):
 data=json.dumps(value,separators=(',',':')).encode();fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
 try:os.fchmod(fd,0o600);os.write(fd,data)
 finally:os.close(fd)

class CodecClient:
 def __init__(self,work,java_home,core_jar,old_jar,repository='/private/tmp/revetsec-refresh-m2'):
  self.work=Path(work);self.work.mkdir(parents=True,exist_ok=True);os.chmod(self.work,0o700)
  self.java=Path(java_home)/'bin/java';self.javac=Path(java_home)/'bin/javac';self.core=Path(core_jar).resolve();self.old=Path(old_jar).resolve();self.annotations=[Path(repository)/x for x in ANNOTATIONS];self.commands=[];self.counter=0
  if digest(self.core)!='b23109a3434703a40ce5a9795ae18b46265c9f07b73901c3b3c4c54dcbbe3b38' or digest(self.old)!='03c9bbc0ff0ec7ea1038d1549a198a49c8ec3e287fb3a8fd4ed0de0508e86497':raise ValueError('Unexpected source artifact')
  for label,jar,sources in [('current',self.core,sorted((HERE/'java').rglob('*.java'))),('legacy',self.old,[HERE/'java/example/migration/CodecSupport.java',*sorted((HERE/'old-writer').rglob('*.java'))])]:
   classes=self.work/(label+'-classes');classes.mkdir(exist_ok=True);cp=os.pathsep.join(map(str,[jar,*self.annotations]));command=[str(self.javac),'--release','17','-proc:none','-Xlint:all','-Werror','-cp',cp,'-d',str(classes),*map(str,sources)];r=subprocess.run(command,capture_output=True,text=True);(self.work/(label+'-compile.log')).write_text(r.stdout+r.stderr);self.commands.append({'kind':'compile','artifact':digest(jar),'exit':r.returncode,'sources':{str(p.relative_to(ROOT)):digest(p) for p in sources}})
   if r.returncode:raise RuntimeError('Private codec compilation failed; inspect owned log')
  self.provenance={'core_jar_sha256':digest(self.core),'old_jar_sha256':digest(self.old),'java_home':str(java_home),'sources':{str(p.relative_to(ROOT)):digest(p) for directory in ['java','old-writer'] for p in sorted((HERE/directory).rglob('*.java'))},'strict_release':17,'runtime_jar_origins_asserted':True}
 def _run(self,family,config,legacy=False):
  self.counter+=1;stem=self.work/('protected-%04d'%self.counter);inp=stem.with_suffix('.input.json');out=stem.with_suffix('.output.json');config=dict(config);config['expectedCoreSha256']=digest(self.old if legacy else self.core);protected_write(inp,config)
  jar=self.old if legacy else self.core;cp=os.pathsep.join(map(str,[self.work/('legacy-classes' if legacy else 'current-classes'),jar,*self.annotations]));command=[str(self.java),'-Xmx256m','-cp',cp,FAMILIES[family][0 if legacy else 1],str(inp),str(out)];r=subprocess.run(command,capture_output=True,text=True);self.commands.append({'kind':'fixture' if legacy else config['operation'],'family':family,'artifact':digest(jar),'exit':r.returncode,'stdout':r.stdout.strip(),'rows':len(config.get('rows',[]))})
  if r.returncode:
   protected_write(stem.with_suffix('.diagnostic.json'),{'stdout':r.stdout,'stderr':r.stderr});raise RuntimeError('Private codec subprocess failed')
  data=json.loads(out.read_text());assert data['coreOriginSha256']==digest(jar)
  if out.stat().st_mode&0o077:raise RuntimeError('Private output permissions changed')
  return data['rows' if legacy else 'decisions']
 def fixtures(self,config):
  result=[]
  for family in FAMILIES:result.extend(self._run(family,config,True))
  return result
 def process(self,family,config,rows,roots,operation='prepare'):
  return self._run(family,{**config,'operation':operation,'rows':rows,'roots':roots})
 def prepare(self,config,rows):
  result=[];roots=root_rows(rows)
  for family in FAMILIES:
   selected=[r for r in rows if r['family']==family]
   if selected:result.extend(self.process(family,config,selected,[r for r in roots if r['family']==family]))
  by_identity={(d["source"]["family"],d["source"]["scope"],d["source"]["handle"]):d for d in result}
  return [by_identity[(r["family"],r["scope"],r["handle"])] for r in rows]
 def verify(self,config,rows):
  result=[];roots=root_rows(rows)
  for family in FAMILIES:
   selected=[r for r in rows if r['family']==family]
   if selected:result.extend(self.process(family,config,selected,[r for r in roots if r['family']==family],'verify'))
  by_identity={(d["source"]["family"],d["source"]["scope"],d["source"]["handle"]):d for d in result}
  return [by_identity[(r["family"],r["scope"],r["handle"])] for r in rows]

 def inspect_legacy_webauthn(self,config,rows,roots=None):
  """Authenticate exact legacy expiry metadata without preparing replacement bytes.

  Native timestamp projections are deliberately not an authority for retention.
  The caller retains raw native projection values in its protected CAS binding.
  """
  if any(row['family']!='WEBAUTHN' for row in rows):raise ValueError('Legacy WebAuthn inspection requires its exact family')
  return self.process('WEBAUTHN',config,rows,root_rows(rows) if roots is None else roots,'inspect-legacy')
