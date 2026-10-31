#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Bounded structural all-family current-adapter contention on owned disposable PostgreSQL.

No arbitrary target/deployment option. Fixed authority is deliberately scripted;
these measurements cannot certify service/protocol, real UTC or full lane C.
"""
import argparse
import base64
import hashlib
import json
import math
import os
import re
from pathlib import Path
import secrets
import select
import shutil
import socket
import subprocess
import tempfile
import time

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
CURRENT=ROOT/'revetsec/examples/postgresql-pending-store'
OLD=ROOT/'planning/records/security/shared-clock-scp01-2026-10-29'
CORE=ROOT/'planning/records/security/shared-clock-scp09-2026-10-30/candidate/core/revetsec-1.0.0-SNAPSHOT.jar'
IMAGE='sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a'
LABEL='com.revetsec.scp11.native=true'
FAMILIES=('TOTP','WEBAUTHN','ISSUER')
ACTOR_JVM_OPTIONS=['-Xms16m','-Xmx64m','-XX:ActiveProcessorCount=2','-XX:CICompilerCount=2']

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def nonce(value):return base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()).decode().rstrip('=')
def encode(value):return base64.urlsafe_b64encode(value).decode().rstrip('=')
def quote(value):return "'"+str(value).replace("'","''")+"'"
def run(command,*,data=None,env=None,timeout=60):return subprocess.run(command,input=data,capture_output=True,text=True,env=env,timeout=timeout)
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--java-home',type=Path,required=True);args=parser.parse_args()
 out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
 runtime=Path(tempfile.mkdtemp(prefix='revetsec-scp11-native-',dir=Path(tempfile.gettempdir()).resolve()));runtime.chmod(0o700)
 result={'status':'RUNNING','checks':[],'workloads':[],'blocking':[],'qualified':False,'qualification':{'approvedUtcQualified':False,'witnessOwnerDeploymentQualified':False,'platformDurabilityQualified':False,'service120msPreparationQualified':False,'completeLaneCQualified':False,'actualDeploymentMigration':False},'profile':{'scope':'structural store carriers only; opaque synthetic records not opened by engines','families':list(FAMILIES),'actors':[8,16],'authorityDelayMillis':1,'authorityTime':'fixed-scripted-1800000000','normalServiceOperations':False,'realUTC':False},'actorJvmOptions':ACTOR_JVM_OPTIONS,'scriptedCarrierConstructedBeforeCallbacks':True,'image':IMAGE,'coreJarSha256':sha(CORE),'java_home':str(args.java_home),'cleanup':{}}
 resource='revetsec-scp11-native-'+secrets.token_hex(6);volume=resource+'-data';network=resource+'-network';password=secrets.token_urlsafe(32);created=[];children=[]
 def save():(out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
 def check(label,condition):
  assert label not in {x['id'] for x in result['checks']},'Duplicate assertion label'
  result['checks'].append({'id':label,'passed':bool(condition)});save()
  if not condition:raise AssertionError(label)
 def docker(*parts,data=None,timeout=60):
  p=run(['docker',*parts],data=data,timeout=timeout)
  if p.returncode:raise RuntimeError('Owned Docker '+parts[0]+' failed')
  return p.stdout.strip()
 def sql(text):return docker('exec','-i',resource,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','qualification',data=text)
 def java(command,env=None,timeout=60):
  return run([str(args.java_home/'bin/java'),*ACTOR_JVM_OPTIONS,'-cp',classpath,'example.pending.NativeContentionActor',*command],env=env,timeout=timeout)
 def readline(child,timeout=20):
  ready,_,_=select.select([child.stdout],[],[],timeout)
  if not ready:raise RuntimeError('Owned actor protocol deadline')
  return child.stdout.readline().strip()
 def environment(family,namespace,actor,root,key='',bucket=0):
  return dict(os.environ,DB_URL=f'jdbc:postgresql://127.0.0.1:{port}/qualification',DB_USER='postgres',DB_PASSWORD=password,FAMILY=family,NAMESPACE=namespace,PHYSICAL=nonce(family+'/'+namespace),ACTOR_ID=actor,ROOT_KEY=root,TARGET_KEY=key,BUCKET=str(bucket),AUTHORITY=nonce('authority'),RECOVERY=nonce('recovery'),CLOCK=nonce('clock'))
 def spawn(env,mode=None):
  p=subprocess.Popen([str(args.java_home/'bin/java'),*ACTOR_JVM_OPTIONS,'-cp',classpath,'example.pending.NativeContentionActor',*([mode] if mode else [])],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1);children.append(p)
  return p
 def finish(child):
  stdout,stderr=child.communicate(timeout=30)
  if child.returncode or stderr:raise RuntimeError('Owned structural actor failed')
  parts=stdout.strip().split();assert len(parts)==5 and parts[0]=='RESULT', 'Owned actor result protocol'
  return {'status':parts[1],'elapsedNanos':int(parts[2]),'authoritySamples':int(parts[3]),'maximumAuthorityNanos':int(parts[4])}
 def ready_actor(child):
  line=readline(child)
  if line=='READY':return True
  if child.poll() is None:
   child.kill()
  stdout,stderr=child.communicate(timeout=5)
  match=re.search(r'STRUCTURAL_ACTOR_FAILED ([A-Z_]+) ([A-Za-z0-9]+) ([A-Za-z0-9]+) ([0-9]+)',stderr)
  result.setdefault('readinessDiagnostics',[]).append({'exit':child.returncode,'protocol':'empty' if not line else 'unexpected','phase':match.group(1) if match else 'UNKNOWN','exception':match.group(2) if match else 'UNKNOWN','envelope':match.group(3) if match else 'UNKNOWN','nativeThreadFailure':'unable to create native thread' in stderr.lower(),'heapFailure':'java heap space' in stderr.lower(),'maximumAuthorityNanos':int(match.group(4)) if match else None});save()
  return False
 def prep(family,namespace):
  p=java(['keys',family,namespace]);assert p.returncode==0 and not p.stderr,'Structural key preparation'
  rows=[line.split('\t') for line in p.stdout.splitlines()];root=rows[0][1]
  keys={'distinct':[(int(r[1]),r[2]) for r in rows if r[0]=='DISTINCT'],'collision':[(int(r[1]),r[2]) for r in rows if r[0]=='COLLISION']}
  physical=nonce(family+'/'+namespace);common=','.join(map(quote,[nonce('authority'),nonce('recovery'),nonce('clock')]))
  cap=65536 if family=='TOTP' else 1000000;prefix=family.lower()
  if family=='TOTP':
   sql('INSERT INTO totp_store_namespace VALUES('+','.join(map(quote,[namespace,physical,'epoch','ACTIVATED']))+','+common+',0,'+quote(nonce('allocation'))+',3,65536,268435456);INSERT INTO totp_store_epoch VALUES('+quote(namespace)+",'epoch',true);")
   raw=bytearray(55);raw[0]=1;raw[1]=1;raw[2]=ord('k');wire=encode(raw).encode();form=encode(wire);size=len(wire);reserved=(118*4+2)//3
   sql('INSERT INTO totp_store_entry VALUES('+','.join(map(quote,[namespace,'epoch',root,'NAMESPACE_STATE',nonce('root'),form]))+','+str(size)+','+str(reserved)+');')
  else:
   sql('INSERT INTO '+prefix+'_store_namespace VALUES('+','.join(map(quote,[namespace,physical]))+','+common+',0,'+quote(nonce('allocation'))+',2,1000000,true);')
   if family=='WEBAUTHN':sql('INSERT INTO webauthn_store_entry VALUES('+','.join(map(quote,[namespace,root,'NAMESPACE_CLOCK']))+",nextval('webauthn_store_version_seq'),"+quote(encode(bytes([1,2,3,4])))+',4,NULL,NULL);')
   else:sql('INSERT INTO issuer_store_entry VALUES('+','.join(map(quote,[namespace,root,'ISSUER_STATE',nonce('root')]))+",31556889864403199,0,'structural-fixture');")
   sql('INSERT INTO '+prefix+'_store_root VALUES('+quote(namespace)+','+quote(root)+');');reserved=0
  root_bucket=hashlib.sha256(root.encode()).digest()[0]
  values=[]
  for bucket in range(256):
   limit=cap//256+(bucket<cap%256);used=int(bucket==root_bucket);byte_limit=1048576 if family=='TOTP' else 0;used_bytes=reserved*used
   values.append('('+','.join([quote(family),quote(physical),str(bucket),quote(nonce('allocation')),str(limit),str(used),str(byte_limit),str(used_bytes)])+')')
  sql('INSERT INTO '+prefix+'_store_escrow VALUES'+','.join(values)+';')
  return root,keys
 def invariant(family,namespace,root):
  prefix=family.lower()
  return sql("SELECT json_build_object('namespace',(SELECT to_jsonb(n) FROM "+prefix+'_store_namespace n WHERE namespace='+quote(namespace)+"),'root',(SELECT to_jsonb(e) FROM "+prefix+'_store_entry e WHERE namespace='+quote(namespace)+' AND storage_key='+quote(root)+"),'usage',(SELECT sum(used_entries) FROM "+prefix+'_store_escrow WHERE namespace='+quote(nonce(family+'/'+namespace))+"),'count',(SELECT count(*) FROM "+prefix+'_store_entry WHERE namespace='+quote(namespace)+"),'bytes',(SELECT sum(used_bytes) FROM "+prefix+'_store_escrow WHERE namespace='+quote(nonce(family+'/'+namespace))+'));')
 def audit(family,namespace,root,targets):
  prefix=family.lower();physical=nonce(family+'/'+namespace)
  rows=json.loads(sql("SELECT coalesce(json_agg(json_build_object('actor',actor,'table',table_name,'operation',operation,'keyDigest',key_digest,'bucket',bucket) ORDER BY actor,table_name,key_digest),'[]'::json) FROM scp11_trace WHERE logical_namespace IN ("+quote(namespace)+','+quote(physical)+');'))
  actual={row['keyDigest'] for row in rows if row['table']==prefix+'_store_entry'}
  expected={hashlib.sha256(k.encode()).hexdigest() for k in targets}
  check(namespace+'/exact-entry-write-set',actual==expected and all(row['operation']=='INSERT' for row in rows if row['table']==prefix+'_store_entry'))
  check(namespace+'/no-namespace-or-root-write',all(row['table'] not in [prefix+'_store_namespace',prefix+'_store_root', 'totp_store_epoch'] for row in rows) and hashlib.sha256(root.encode()).hexdigest() not in actual)
  check(namespace+'/only-target-escrow-buckets',all(row['bucket'] in {hashlib.sha256(k.encode()).digest()[0] for k in targets} for row in rows if row['table']==prefix+'_store_escrow'))
  return rows
 try:
  check('exact-cached-image-no-pull',docker('image','inspect',IMAGE,'--format','{{.Id}}')==IMAGE)
  deps=[];manifest=json.loads((OLD/'ARTIFACT-PRESERVATION.json').read_text())
  for coordinate in ['com.pyranid:pyranid:4.7.0','org.postgresql:postgresql:42.7.14','org.jspecify:jspecify:1.0.1','com.google.code.findbugs:jsr305:3.0.2','com.google.errorprone:error_prone_annotations:2.50.0']:
   item=next(x for x in manifest['artifacts'] if x.get('coordinate')==coordinate);path=ROOT/item['frozen_path'];check('pinned-'+coordinate,sha(path)==item['sha256']);deps.append(path)
  current=CURRENT/'src/main/java/example/pending';sources=[*sorted(current.glob('*Pg*.java')),*[current/n for n in ['PostgresqlTotpStore.java','PostgresqlWebAuthnStore.java','PostgresqlIssuerStore.java','PostgresqlPyranidDataSource.java']],*sorted((HERE/'native').rglob('*.java'))];auditor=ROOT/'revetsec/verification/examples/NullabilityAudit.java'
  inputs={str(p.relative_to(ROOT)):sha(p) for p in [Path(__file__),*sources,auditor,*[CURRENT/(family.lower()+'-schema.sql') for family in FAMILIES]]};result['sourceInputsSha256']=inputs
  for name in inputs:
   target=out/'SOURCE'/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,target)
  result['artifactInputsSha256']={str(p.relative_to(ROOT)):sha(p) for p in [CORE,*deps]};classes=runtime/'classes';classes.mkdir();classpath=os.pathsep.join(map(str,[classes,CORE,*deps]));result['javaVersion']=run([str(args.java_home/'bin/java'),'-version']).stderr.strip()
  p=run([str(args.java_home/'bin/javac'),'--release','17','-proc:none','-Xlint:all','-Werror','-cp',classpath,'-d',str(classes),*map(str,sources),str(auditor)]);(out/'compile.log').write_text(p.stdout+p.stderr);check('strict-current-java17-compile',p.returncode==0)
  source_list=runtime/'audit.sources';source_list.write_text('\n'.join(map(str,sources))+'\n');cp_file=runtime/'audit.classpath';cp_file.write_text(classpath)
  p=run([str(args.java_home/'bin/java'),'-cp',classpath,'NullabilityAudit',str(source_list),str(cp_file),str(out/'NULLABILITY.json')]);audit_result=json.loads((out/'NULLABILITY.json').read_text());result['nullability']=audit_result;check('all-compiled-source-nullability',p.returncode==0 and not audit_result['missing'] and not audit_result['attribution_errors'])
  envfile=runtime/'postgres.env';envfile.write_text('POSTGRES_PASSWORD='+password+'\nPOSTGRES_DB=qualification\n');envfile.chmod(0o600)
  bound=socket.socket();bound.bind(('127.0.0.1',0));port=bound.getsockname()[1]
  docker('network','create','--label',LABEL,network);created.append('network');docker('volume','create','--label',LABEL,volume);created.append('volume');bound.close();created.append('container')
  docker('run','-d','--pull=never','--name',resource,'--network',network,'--label',LABEL,'--publish',f'127.0.0.1:{port}:5432','--env-file',str(envfile),'--mount',f'type=volume,source={volume},target=/var/lib/postgresql',IMAGE)
  for attempt in range(150):
   p=run(['docker','exec',resource,'psql','-X','-qAt','-U','postgres','-d','qualification','-c','SELECT 1'],timeout=3)
   if p.returncode==0 and p.stdout.strip()=='1':break
   time.sleep(.1)
  else:raise RuntimeError('Owned primary startup failed')
  for family in FAMILIES:sql((CURRENT/(family.lower()+'-schema.sql')).read_text())
  sql('''CREATE TABLE scp11_trace(actor text,table_name text,operation text,logical_namespace text,key_digest text,bucket integer);
CREATE FUNCTION scp11_trace_write() RETURNS trigger LANGUAGE plpgsql AS $audit$
DECLARE value jsonb;key text;
BEGIN value=CASE WHEN TG_OP='DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;key=value->>'storage_key';
INSERT INTO scp11_trace VALUES(current_setting('application_name'),TG_TABLE_NAME,TG_OP,value->>'namespace',CASE WHEN key IS NULL THEN NULL ELSE encode(sha256(convert_to(key,'UTF8')),'hex') END,(value->>'bucket')::integer);
RETURN NEW;END $audit$;''')
  for family in FAMILIES:
   for suffix in ['namespace','entry','escrow']+(['epoch'] if family=='TOTP' else ['root']):sql('CREATE TRIGGER scp11_trace AFTER INSERT OR UPDATE OR DELETE ON '+family.lower()+'_store_'+suffix+' FOR EACH ROW EXECUTE FUNCTION scp11_trace_write();')
  result['traceCalibrations']=[]
  for family in FAMILIES:
   ns='q_observe_'+family.lower();root,keys=prep(family,ns);sql('DELETE FROM scp11_trace;');before=invariant(family,ns,root);prefix=family.lower();physical=nonce(family+'/'+ns)
   statements=['BEGIN']
   if family=='TOTP':statements.append('UPDATE totp_store_epoch SET activated=false WHERE namespace='+quote(ns))
   statements += ['DELETE FROM '+prefix+'_store_escrow WHERE namespace='+quote(physical),'DELETE FROM '+prefix+'_store_entry WHERE namespace='+quote(ns)]
   statements.append('DELETE FROM '+prefix+'_store_'+('epoch' if family=='TOTP' else 'root')+' WHERE namespace='+quote(ns))
   statements.append('DELETE FROM '+prefix+'_store_namespace WHERE namespace='+quote(ns))
   statements.append("SELECT coalesce(json_agg(json_build_object('table',table_name,'operation',operation,'namespace',logical_namespace,'keyDigest',key_digest,'bucket',bucket)),'[]'::json) FROM scp11_trace WHERE logical_namespace IN ("+quote(ns)+','+quote(physical)+')')
   statements.append('ROLLBACK');traces=json.loads(sql(';'.join(statements)+';'))
   expected={prefix+'_store_namespace':1,prefix+'_store_entry':1,prefix+'_store_escrow':256,prefix+'_store_'+('epoch' if family=='TOTP' else 'root'):1}
   actual={table:sum(row['table']==table and row['operation']=='DELETE' for row in traces) for table in expected}
   check('trace-calibration/'+family+'/delete-OLD-values-visible',actual==expected and any(row['table']==prefix+'_store_entry' and row['keyDigest']==hashlib.sha256(root.encode()).hexdigest() for row in traces))
   if family=='TOTP':check('trace-calibration/TOTP/epoch-update-and-delete-visible',sum(row['table']=='totp_store_epoch' and row['operation'] in ['UPDATE','DELETE'] for row in traces)==2)
   check('trace-calibration/'+family+'/rollback-restores-auth-and-audit',invariant(family,ns,root)==before and sql('SELECT count(*) FROM scp11_trace;')=='0')
   result['traceCalibrations'].append({'family':family,'deleteCounts':actual,'epochUpdates':sum(row['table']=='totp_store_epoch' and row['operation']=='UPDATE' for row in traces),'rolledBack':True});save()
  for family in FAMILIES:
   for count in [8,16]:
    for shape in ['distinct','collision','same-entity']:
     ns='q_'+family.lower()+'_'+str(count)+'_'+shape.replace('-','_');root,keys=prep(family,ns);sql('DELETE FROM scp11_trace;');before=json.loads(invariant(family,ns,root))
     selected=keys['distinct' if shape!='collision' else 'collision'][:count];targets=[selected[0][1]]*count if shape=='same-entity' else [key for _,key in selected]
     actors=[spawn(environment(family,ns,ns+'_'+str(i),root,key)) for i,key in enumerate(targets)]
     check(ns+'/all-independent-jvms-snapshot-ready',all(ready_actor(child) for child in actors));started=time.monotonic_ns()
     for child in actors:child.stdin.write('GO\n');child.stdin.flush()
     reports=[finish(child) for child in actors];elapsed=time.monotonic_ns()-started;statuses=[row['status'] for row in reports]
     expected=1 if shape=='same-entity' else count
     check(ns+'/exact-commit-conflict-outcomes',statuses.count('COMMITTED')==expected and statuses.count('CONFLICT')==count-expected)
     after=json.loads(invariant(family,ns,root));check(ns+'/stable-root-and-namespace',before['namespace']==after['namespace'] and before['root']==after['root'])
     check(ns+'/durable-exact-count-and-quota',after['count']==before['count']+expected and after['usage']==before['usage']+expected and after['bytes']==before['bytes']+(158*expected if family=='TOTP' else 0))
     trace=audit(family,ns,root,set(targets));times=sorted(row['elapsedNanos'] for row in reports)
     result['workloads'].append({'family':family,'actors':count,'shape':shape,'committed':expected,'conflicted':count-expected,'wallNanos':elapsed,'throughputPerSecond':count*1e9/elapsed,'p50Nanos':times[math.ceil(count*.5)-1],'p95Nanos':times[math.ceil(count*.95)-1],'p99Nanos':times[-1],'latenciesNanos':times,'authoritySamples':[row['authoritySamples'] for row in reports],'maximumAuthorityNanos':max(row['maximumAuthorityNanos'] for row in reports),'changedEntryDigests':sorted({hashlib.sha256(k.encode()).hexdigest() for k in targets}),'assignedBuckets':[hashlib.sha256(k.encode()).digest()[0] for k in targets],'writeTrace':trace,'namespaceFingerprint':hashlib.sha256(json.dumps(after['namespace'],sort_keys=True).encode()).hexdigest(),'rootFingerprint':hashlib.sha256(json.dumps(after['root'],sort_keys=True).encode()).hexdigest()});save()
   for lock_kind in ['bucket','entity']:
    ns='q_'+family.lower()+'_held_'+lock_kind;root,keys=prep(family,ns);sql('DELETE FROM scp11_trace;');held_key=keys['collision'][0][1];other_key=next(key for bucket,key in keys['distinct'] if bucket!=0)
    held=spawn(environment(family,ns,ns+'_blocked',root,held_key));other=spawn(environment(family,ns,ns+'_other',root,other_key));check(ns+'/both-snapshot-ready',ready_actor(held) and ready_actor(other))
    holder=spawn(environment(family,ns,ns+'_holder',root,held_key,0),'hold-'+lock_kind);check(ns+'/actual-holder-ready',readline(holder)=='HELD')
    for child in [held,other]:child.stdin.write('GO\n');child.stdin.flush()
    end=time.monotonic()+5;observed=False;edges=[]
    while time.monotonic()<end:
     edges=json.loads(sql("SELECT coalesce(json_agg(json_build_object('actor',application_name,'blockingActors',(SELECT coalesce(json_agg(b.application_name),'[]'::json) FROM pg_stat_activity b WHERE b.pid=ANY(pg_blocking_pids(a.pid))))),'[]'::json) FROM pg_stat_activity a WHERE application_name IN ("+quote(ns+'_blocked')+','+quote(ns+'_other')+');'))
     if any(row['actor']==ns+'_blocked' and ns+'_holder' in row['blockingActors'] for row in edges):observed=True;break
     time.sleep(.01)
    check(ns+'/real-database-blocking-edge',observed);other_report=finish(other);check(ns+'/unrelated-completes-while-held',other_report['status']=='COMMITTED' and held.poll() is None)
    holder.stdin.write('RELEASE\n');holder.stdin.flush();holder_out,holder_err=holder.communicate(timeout=10);check(ns+'/holder-released',holder.returncode==0 and not holder_err and holder_out.strip()=='RELEASED');held_report=finish(held);check(ns+'/blocked-operation-resumes',held_report['status']=='COMMITTED')
    trace=audit(family,ns,root,{held_key,other_key});result['blocking'].append({'family':family,'kind':lock_kind,'edges':edges,'unrelated':other_report,'held':held_report,'writeTrace':trace});save()
  result['status']='PASS'
 except Exception as failure:
  result['status']='FAIL';result['failure']={'type':type(failure).__name__,'fixedLabel':str(failure) if isinstance(failure,AssertionError) else 'Owned bounded qualification failed'}
 finally:
  for child in children:
   if child.poll() is None:child.kill()
   try:child.communicate(timeout=5)
   except Exception:pass
  result['cleanup']['children']=all(child.poll() is not None for child in children)
  for kind in ['container','volume','network']:
   if kind not in created:result['cleanup'][kind]=True;continue
   parts={'container':['rm','-f','-v',resource],'volume':['volume','rm','-f',volume],'network':['network','rm',network]}[kind]
   p=run(['docker',*parts]);result['cleanup'][kind]=p.returncode==0
  shutil.rmtree(runtime,ignore_errors=True);result['cleanup']['protectedRuntime']=not runtime.exists()
  result['sourceStable']=all((ROOT/name).exists() and sha(ROOT/name)==digest for name,digest in result.get('sourceInputsSha256',{}).items());save()
  print('SCP11_NATIVE_'+result['status']+' checks='+str(len(result['checks'])))
 return 0 if result['status']=='PASS' and all(result['cleanup'].values()) and result['sourceStable'] else 1
if __name__=='__main__':raise SystemExit(main())
