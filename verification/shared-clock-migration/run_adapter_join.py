#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Owned frozen-old -> exact current PostgreSQL adapters; scripted/unqualified only."""
import argparse
import base64
import copy
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import traceback

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
sys.path[:0]=[str(HERE.parent/'shared-clock-postgresql'),str(HERE.parent/'shared-clock')]
from fault_proxy import CommitLossProxy
from codec import CodecClient,synthetic_config,root_rows,protected_write
from migration import ProtectedJournal,Migration,MigrationClosed,DirectoryOwner,identity,commitment,FORMATS
from postgres_backend import TABLES,decode,quote,kind
from adapter_schema import AdapterPgBackend,SchemaInstaller,control_sql,_catalog_query
from witness import Witness
from witness_capture import CheckedCapture
from witness_storage import DirectoryOwner as WitnessOwner,ManifestStore,PROFILE

IMAGE='sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a'
OLD=ROOT/'planning/records/security/shared-clock-scp01-2026-10-29'
CORE=ROOT/'planning/records/security/shared-clock-scp09-2026-10-30/candidate/core/revetsec-1.0.0-SNAPSHOT.jar'
CURRENT=ROOT/'revetsec/examples/postgresql-pending-store'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def execute(command,*,data=None,env=None,timeout=60):return subprocess.run(command,input=data,capture_output=True,text=True,env=env,timeout=timeout)
def deadline():return time.monotonic_ns()+90_000_000_000
def schema_config(config):return {key:config[key] for key in ['clockGeneration','allocationGeneration','maximumUtcErrorNanos','authorityId','recoveryGeneration']}

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--java-home',type=Path,required=True);args=parser.parse_args()
 out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
 result={'status':'RUNNING','checks':[],'image':IMAGE,'java_home':str(args.java_home),'coreJarSha256':sha(CORE),'oldCoreJarSha256':sha(OLD/'baseline/built-core/revetsec-1.0.0-SNAPSHOT.jar'),'qualified':False,'qualification':{'approvedUtcQualified':False,'witnessOwnerDeploymentQualified':False,'platformDurabilityQualified':False,'actualDeploymentMigration':False,'qualifiedSharedProfile':False},'cleanup':{}}
 def save():(out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
 def check(name,condition):
  if any(row['id']==name for row in result['checks']):raise AssertionError('duplicate assertion identity')
  result['checks'].append({'id':name,'passed':bool(condition)});save()
  if not condition:raise AssertionError(name)
 inputs={str(p.relative_to(ROOT)):sha(p) for p in HERE.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
 resource='revetsec-scp10-adapter-'+secrets.token_hex(6);volume=resource+'-data';network=resource+'-bridge';password=secrets.token_urlsafe(32);created=[];processes=[];owners=[];proxies=[];server=None;server_thread=None;stop=threading.Event()
 runtime=Path(tempfile.mkdtemp(prefix='revetsec-scp10-adapter-',dir=Path(tempfile.gettempdir()).resolve()));runtime.chmod(0o700)
 bound=socket.socket();bound.bind(('127.0.0.1',0));port=bound.getsockname()[1]
 result['ownedResources']={'container':resource,'volume':volume,'network':network,'loopbackPort':port}
 def docker(*parts,data=None,timeout=60):
  p=execute(['docker',*parts],data=data,timeout=timeout)
  if p.returncode:raise RuntimeError('Owned Docker operation failed: '+parts[0])
  return p.stdout.strip()
 def sql(text):return docker('exec','-i',resource,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','migration_fixture',data=text)
 fault=[None];observations=[]
 def transaction(statements,end):
  selected=fault[0];proxy=None
  if isinstance(selected,dict):
   if any(selected['marker'] in statement for statement in statements):selected=selected['mode'];fault[0]=None
   else:selected=None
  elif selected:fault[0]=None
  if selected:proxy=CommitLossProxy(port,selected);proxies.append(proxy)
  diagnostic=runtime/('transaction-'+secrets.token_hex(4)+'.diagnostic');diagnostic.touch(mode=0o600)
  environment=dict(os.environ,DIAGNOSTIC_FILE=str(diagnostic),DB_URL=f'jdbc:postgresql://127.0.0.1:{proxy.local_port if proxy else port}/migration_fixture',DB_USER='postgres',DB_PASSWORD=password)
  data=''.join(base64.b64encode(s.encode()).decode()+'\n' for s in statements)
  p=execute([str(args.java_home/'bin/java'),'-cp',native_cp,'verification.migration.AdapterPgBatch'],data=data,env=environment,timeout=max(1,min(30,(end-time.monotonic_ns())/1e9)))
  if proxy:proxy.close()
  answer=p.stdout.strip() if p.returncode==0 and not p.stderr else 'UNKNOWN'
  observation={'status':answer,'statements':len(statements),'loss':selected,'drops':proxy.drops if proxy else 0,'committedReady':proxy.committed_ready if proxy else 0,'proxyErrors':proxy.errors if proxy else []}
  if diagnostic.stat().st_size:
   index,state=diagnostic.read_text().split('|');index=int(index);observation.update(failureStatement=index,sqlState=state,statementSha256=hashlib.sha256(statements[index-1].encode()).hexdigest() if 0<index<=len(statements) else None)
   if 0<index<=len(statements) and statements[index-1].startswith(('ALTER TABLE ','ALTER SEQUENCE ','DROP INDEX ','CREATE TABLE ')):
    tokens=statements[index-1].split()[:6]
    if all(re.fullmatch('[A-Za-z_"]+',token) for token in tokens):observation['failureDdlLabel']=' '.join(tokens)
   if selected and index<len(statements):observation['failureBeforeSelectedCommit']=True
  observations.append(observation)
  return answer if answer in ['COMMITTED','NO_EFFECT','UNKNOWN'] else 'UNKNOWN'
 try:
  check('exact-cached-image-no-pull',docker('image','inspect',IMAGE,'--format','{{.Id}}')==IMAGE)
  manifest=json.loads((OLD/'ARTIFACT-PRESERVATION.json').read_text());dependencies=[]
  for coordinate in ['com.pyranid:pyranid:4.7.0','org.postgresql:postgresql:42.7.14','org.jspecify:jspecify:1.0.1','com.google.code.findbugs:jsr305:3.0.2','com.google.errorprone:error_prone_annotations:2.50.0']:
   row=next(x for x in manifest['artifacts'] if x.get('coordinate')==coordinate);p=ROOT/row['frozen_path'];check('pinned-'+coordinate,sha(p)==row['sha256']);dependencies.append(p)
  oldjar=OLD/'baseline/built-core/revetsec-1.0.0-SNAPSHOT.jar';frozen=OLD/'baseline/source/revetsec/examples/postgresql-pending-store';frozen_java=frozen/'src/main/java/example/pending';current_java=CURRENT/'src/main/java/example/pending'
  oldclasses=runtime/'old-classes';classes=runtime/'current-classes';oldclasses.mkdir();classes.mkdir()
  oldsources=[frozen_java/'PostgresqlWebAuthnStore.java',frozen_java/'PostgresqlPyranidDataSource.java',HERE/'java/example/migration/CodecSupport.java',HERE/'native/com/revetsec/webauthn/AdapterLegacyWriter.java',HERE/'native/com/revetsec/webauthn/AdapterLegacySeed.java']
  sources=[*sorted(current_java.glob('*Pg*.java')),*[current_java/name for name in ['PostgresqlTotpStore.java','PostgresqlWebAuthnStore.java','PostgresqlIssuerStore.java','PostgresqlPyranidDataSource.java']],HERE/'java/example/migration/CodecSupport.java',HERE/'native/example/pending/AdapterJoinProbe.java',HERE/'native/com/revetsec/webauthn/AdapterJoinWorker.java',HERE/'native/verification/migration/AdapterPgBatch.java']
  auditor=ROOT/'revetsec/verification/examples/NullabilityAudit.java'
  for source in [*sources,*oldsources,auditor,frozen/'schema.sql',frozen/'totp-schema.sql',*[CURRENT/name for name in ['totp-schema.sql','webauthn-schema.sql','issuer-schema.sql']],*sorted((HERE.parent/'shared-clock').glob('*.py')),HERE.parent/'shared-clock-postgresql/fault_proxy.py']:
   inputs[str(source.relative_to(ROOT))]=sha(source)
  for name in inputs:
   target=out/'SOURCE'/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,target)
  result['artifactInputsSha256']={str(path.relative_to(ROOT)):sha(path) for path in [CORE,oldjar,*dependencies]}
  result['javaVersion']=execute([str(args.java_home/'bin/java'),'-version']).stderr.strip()
  for label,selected,jar,dest in [('legacy',oldsources,oldjar,oldclasses),('current',sources,CORE,classes)]:
   p=execute([str(args.java_home/'bin/javac'),'--release','17','-proc:none','-Xlint:all','-Werror','-cp',os.pathsep.join(map(str,[jar,*dependencies])),'-d',str(dest),*map(str,selected)])
   (out/(label+'-compile.log')).write_text(p.stdout+p.stderr);check(label+'-strict-compile',p.returncode==0)
  oldcp=os.pathsep.join(map(str,[oldclasses,oldjar,*dependencies]));currentcp=os.pathsep.join(map(str,[classes,CORE,*dependencies]));native_cp=currentcp
  p=execute([str(args.java_home/'bin/javac'),'--release','17','-proc:none','-Xlint:all','-Werror','-cp',os.pathsep.join(map(str,dependencies)),'-d',str(classes),str(auditor)]);(out/'audit-compile.log').write_text(p.stdout+p.stderr);check('signature-auditor-strict-compile',p.returncode==0)
  for label,selected,classpath in [('legacy',oldsources,oldcp),('current',sources,currentcp)]:
   source_file=runtime/(label+'-audit.sources');source_file.write_text('\n'.join(map(str,selected))+'\n');classpath_file=runtime/(label+'-audit.classpath');classpath_file.write_text(classpath);audit_output=out/(label+'-nullability.json')
   p=execute([str(args.java_home/'bin/java'),'-cp',currentcp,'NullabilityAudit',str(source_file),str(classpath_file),str(audit_output)]);audit=json.loads(audit_output.read_text()) if audit_output.exists() else {};check(label+'-all-compiled-source-signature-nullability',p.returncode==0 and not audit.get('missing',[1]) and not audit.get('attribution_errors',[1]));result[label+'Nullability']=audit
  client=CodecClient(runtime/'codec',args.java_home,CORE,oldjar);config=synthetic_config();config.update(minimumSeconds=int(time.time())+3600,minimumNanos=123456001,ceremonyExpiresNanos=123456001,clockGeneration=commitment('adapter/clock'),allocationGeneration=commitment('adapter/allocation'),maximumUtcErrorNanos=250000000)
  source_rows=client.fixtures(config);check('frozen-old-complete-31-retained-rows',len(source_rows)==31)
  scopes={f:config[k] for f,k in [('TOTP','totpScope'),('WEBAUTHN','webauthnScope'),('ISSUER','issuerScope')]};namespaces={f:'migration' for f in FORMATS};required_roots=[(r['family'],r['key']) for r in root_rows(source_rows)]
  envfile=runtime/'postgres.env';envfile.write_text('POSTGRES_PASSWORD='+password+'\nPOSTGRES_DB=migration_fixture\n');envfile.chmod(0o600)
  docker('network','create','--label','com.revetsec.scp10.adapter=true',network);created.append('network');docker('volume','create','--label','com.revetsec.scp10.adapter=true',volume);created.append('volume');bound.close();created.append('container')
  docker('run','-d','--pull=never','--name',resource,'--network',network,'--label','com.revetsec.scp10.adapter=true','--publish',f'127.0.0.1:{port}:5432','--env-file',str(envfile),'--mount',f'type=volume,source={volume},target=/var/lib/postgresql',IMAGE)
  for _ in range(150):
   ready=execute(['docker','exec',resource,'psql','-X','-qAt','-U','postgres','-d','migration_fixture','-c','SELECT 1'],timeout=3);primary=execute(['docker','exec',resource,'cat','/proc/1/comm'],timeout=3)
   if ready.returncode==0 and ready.stdout.strip()=='1' and primary.stdout.strip()=='postgres':break
   time.sleep(.1)
  else:raise RuntimeError('Owned primary unavailable')
  check('primary-fsync-fullpage',sql("SELECT NOT pg_is_in_recovery() AND current_setting('fsync')='on' AND current_setting('full_page_writes')='on';")=='t')
  old_role='scp10_old_'+secrets.token_hex(4);runtime_role='scp10_current_'+secrets.token_hex(4);old_password=secrets.token_urlsafe(32);runtime_password=secrets.token_urlsafe(32)
  sql('CREATE ROLE '+old_role+' LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '+quote(old_password)+';CREATE ROLE '+runtime_role+' NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '+quote(runtime_password)+';')
  def environment(user='postgres',pw=password):return dict(os.environ,DB_URL=f'jdbc:postgresql://127.0.0.1:{port}/migration_fixture?sslmode=disable&gssEncMode=disable',DB_USER=user,DB_PASSWORD=pw,OLD_CORE_JAR=str(oldjar))
  seed_config=runtime/'seed.json';protected_write(seed_config,{'rows':source_rows})
  def seed(label):
   sql('DROP SCHEMA public CASCADE;CREATE SCHEMA public;'+(frozen/'schema.sql').read_text()+'\n'+(frozen/'totp-schema.sql').read_text())
   sql("INSERT INTO totp_store_namespace VALUES('migration','old-one','ACTIVATED');INSERT INTO totp_store_epoch VALUES('migration','old-one'),('migration','old-two');INSERT INTO webauthn_store_namespace VALUES('migration');INSERT INTO issuer_store_namespace VALUES('migration');")
   statements=[]
   for row in source_rows:
    family=row['family']
    if family=='WEBAUTHN':continue
    common=[quote('migration'),quote(row['key']),quote(kind(row)),quote(row['version']),quote(decode(row['ciphertext']).decode('ascii')) if family=='ISSUER' else quote(row['ciphertext'])]
    if family=='TOTP':
     epoch=decode(row['key'].split(':')[2]).decode('ascii');statements.append('INSERT INTO totp_store_entry(namespace,storage_key,kind,version,sealed_form,recovery_epoch,sealed_size) VALUES('+','.join([*common,quote(epoch),str(len(decode(row['ciphertext'])))])+')')
    else:statements.append('INSERT INTO issuer_store_entry(namespace,storage_key,kind,version,sealed_form,retain_seconds,retain_nanos) VALUES('+','.join([*common,str(row['retention']['epochSecond']),str(row['retention']['nano'])])+')')
   sql(';'.join(statements)+';')
   p=execute([str(args.java_home/'bin/java'),'-cp',oldcp,'com.revetsec.webauthn.AdapterLegacySeed',str(seed_config)],env=environment(),timeout=30);check(label+'/genuine-old-adapter-jdbc-seed',p.returncode==0 and p.stdout.strip()=='PASS genuine-old-adapter-jdbc-seed')
   check(label+'/untouched-legacy-wa-timestamptz-only',sql("SELECT string_agg(column_name,',' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='public' AND table_name='webauthn_store_entry';")=='namespace,storage_key,kind,version,sealed_form,expires_at')
   check(label+'/old-jdbc-rounded-expiry-differs-authenticated-nanoseconds',sql("SELECT ((extract(epoch FROM expires_at)*1000000)::bigint%1000000) FROM webauthn_store_entry WHERE kind='CEREMONY';")=='123457')
   sql(control_sql())
  seed('initial-source')
  sql('GRANT USAGE ON SCHEMA public TO '+old_role+';GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO '+old_role+';GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO '+old_role+';')
  writer_env=dict(environment(old_role,old_password),SEAL_KEY=config['keys']['k'],SEAL_KEY_ID='k',OLD_WORKER_SECONDS=str(config['minimumSeconds']+100))
  writers=[]
  for mode in ['direct','pooled']:
   p=subprocess.Popen([str(args.java_home/'bin/java'),'-cp',oldcp,'com.revetsec.webauthn.AdapterLegacyWriter',mode,'migration'],env=writer_env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);processes.append(p);writers.append(p);check('genuine-old-'+mode+'-held-session',p.stdout.readline().strip()=='READY '+mode)
  check('two-actual-old-sql-sessions',sql('SELECT count(*) FROM pg_stat_activity WHERE usename='+quote(old_role)+';')=='2')
  sql('ALTER ROLE '+old_role+' NOLOGIN PASSWORD NULL;REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM '+old_role+';REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM '+old_role+';REVOKE ALL PRIVILEGES ON SCHEMA public FROM '+old_role+';SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='+quote(old_role)+';')
  for mode,p in zip(['direct','pooled'],writers):
   stdout,stderr=p.communicate('CONTINUE\n',timeout=20);check('actual-old-'+mode+'-commit-and-login-fenced',p.returncode==0 and not stderr and stdout.count('PASS ')==2)
  def case(name,exhausted=False,bad_expiry=False):
   if bad_expiry:sql("UPDATE webauthn_store_entry SET expires_at=expires_at+interval '1 microsecond' WHERE kind='CEREMONY';")
   sql('ALTER SEQUENCE webauthn_store_version_seq RESTART WITH '+str(9223372036854775807 if exhausted else 9223372036854774783)+';'+("SELECT nextval('webauthn_store_version_seq');" if exhausted else ''))
   cfg={**config,'migrationId':commitment(name+'/migration'),'recoveryGeneration':commitment(name+'/recovery')}
   intent={'migrationId':cfg['migrationId'],'sourceRecoveryGeneration':commitment(name+'/old'),'targetAdmission':{k:cfg[k] for k in ['authorityId','recoveryGeneration']},'writerFence':commitment(name+'/fence'),'targetFormats':dict(FORMATS),'authorityWitness':commitment(name+'/scripted-witness')}
   sql('INSERT INTO scp10_control(migration_id,writer_fence,source_recovery,target_authority,target_recovery,mode) VALUES('+','.join(map(quote,[intent['migrationId'],intent['writerFence'],intent['sourceRecoveryGeneration'],cfg['authorityId'],cfg['recoveryGeneration'],'CLOSED']))+');')
   directory=runtime/name;directory.mkdir(mode=0o700);owner=DirectoryOwner(directory);owners.append(owner);journal=ProtectedJournal(owner)
   backend=AdapterPgBackend(sql,transaction,scopes,[old_role],namespaces=namespaces,required_roots=required_roots,journal=journal,confirmed_new_intent=True,codec_client=client,codec_config=cfg);machine=Migration(journal,backend);installer=SchemaInstaller(backend)
   machine.close(intent,deadline());backend.confirmed_new_intent=False
   if bad_expiry:
    before=backend._raw_source()
    try:backend.stage_legacy(Migration.context(journal.read(),deadline()));refused=False
    except MigrationClosed as failure:refused=failure.label=='CORRUPT'
    check(name+'/native-timestamp-not-authenticated-expiry-authority',refused and before==backend._raw_source() and journal.read()['phase']=='CLOSED')
    return None
   backend.stage_legacy(Migration.context(journal.read(),deadline()));machine.inventory(deadline())
   rows=journal.get_blob(journal.read()['inventoryBlob']);check(name+'/source-metadata-authenticated-exact-all31',rows==sorted(source_rows,key=identity))
   decisions=sorted(client.prepare(cfg,rows),key=lambda d:identity(d['source']));caps=[{'family':f,'scope':scopes[f],'entryCap':65536 if f=='TOTP' else 1000000,'hardEntryCap':65536 if f=='TOTP' else 1000000,'byteCap':268435456 if f=='TOTP' else None,'hardByteCap':268435456 if f=='TOTP' else None} for f in sorted(FORMATS)]
   machine.prepare(decisions,caps,deadline())
   if exhausted:
    try:installer.preflight_current(Migration.context(journal.read(),deadline()),schema_config(cfg));refused=False
    except MigrationClosed as failure:refused=failure.label=='UNSUPPORTED'
    check(name+'/exhausted-native-sequence-refuses-before-rewrite',refused and journal.read()['cursor']==0 and backend._all()==rows)
    return None
   installer.preflight_current(Migration.context(journal.read(),deadline()),schema_config(cfg));check(name+'/current-schema-capacity-preflight',True)
   check(name+'/exact-256-bucket-quotas',backend.install_quotas(Migration.context(journal.read(),deadline()),journal.get_blob(journal.read()['quotaBlob']))=='COMMITTED')
   while journal.read()['cursor']<31:machine.rewrite_next(deadline())
   actual=backend._all();verified=sorted(client.verify(cfg,actual),key=lambda d:identity(d['source']));machine.verify(verified,deadline());state=journal.read();machine.activate({k:state[k] for k in ['authorityWitness','writerFence','targetAdmission','activationCommitment']},deadline())
   check(name+'/current-codec-independently-opens-all31',len(verified)==31 and all(d['classification']=='FIT' for d in verified));return cfg,journal,backend,machine,installer
  case('wrong-old-timestamp',bad_expiry=True)
  seed('exhaustion-source')
  case('exhausted-sequence',exhausted=True)
  seed('main-source')
  cfg,journal,backend,machine,installer=case('main')
  archive='/tmp/scp10-adapter-auth.dump';docker('exec',resource,'pg_dump','-Fc','-U','postgres','-d','migration_fixture','-f',archive)
  # The dump is owned, container-private and predates schema activation/runtime mutations.
  token=secrets.token_urlsafe(32);runtime_lock=runtime/'runtime.lock';runtime_lock.touch(mode=0o600);rpc_lock=threading.RLock();witness_box=[None];static_query=[None];witness_expected={};rpc_counts={'allowed':0,'denied':0}
  pipe=subprocess.Popen(['docker','exec','-i',resource,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','migration_fixture'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);processes.append(pipe)
  def fast_sql(query):
   pipe.stdin.write(query+'\n\\echo SCP10_END\n');pipe.stdin.flush();lines=[]
   while True:
    line=pipe.stdout.readline()
    if not line:raise RuntimeError('Owned authority SQL channel unavailable')
    if line.strip()=='SCP10_END':return '\n'.join(lines).strip()
    lines.append(line.rstrip('\n'))
  def admitted(family,scope):
   state=journal.read();schema=installer.state.read()
   if state['phase']!='ACTIVE' or state['invalidated'] or state['progress'] is not None or schema['migrationId']!=state['migrationId'] or schema['phase']!='CURRENT_VERIFIED' or schema['status']!='COMMITTED' or scope!=scopes[family] or witness_box[0] is None or static_query[0] is None:raise MigrationClosed('CLOSED')
   plan=journal.get_blob(schema['planBlob'])
   expected_context={key:state[key] for key in ['migrationId','writerFence','sourceRecoveryGeneration','targetAdmission']}
   if plan['context']!=expected_context or any(sha(ROOT/path)!=digest for path,digest in plan['ddlHashes'].items()) or fast_sql(static_query[0])!='t':raise MigrationClosed('CLOSED')
   witness=witness_box[0];elapsed=witness.elapsed()[1]
   if witness.renewal_due(elapsed+100000000):witness.renew(witness.store.read()['activeDatabaseAdmission'],witness.elapsed()[1]+100000000)
   return witness.sample(witness_expected[family],witness.elapsed()[1]+100000000)
  class Handler(socketserver.StreamRequestHandler):
   def handle(self):
    try:
     self.request.settimeout(1);parts=self.rfile.readline(2048).decode('ascii').strip().split('\t')
     if len(parts)!=5 or parts[0]!=token or parts[1] not in ['ADMIT','OBSERVE'] or parts[2] not in scopes:raise ValueError()
     with rpc_lock:
      point=admitted(parts[2],parts[3]);rpc_counts['allowed']+=1
     seconds,nano=divmod(point.authority_ns,1000000000);reply='\t'.join(map(str,['OK',point.authority_id,point.recovery_generation,point.clock_generation,seconds,nano,point.maximum_utc_error_ns,commitment('scripted-qualified-false')]))+'\n'
    except Exception:
     rpc_counts['denied']+=1;reply='CLOSED\n'
    try:self.wfile.write(reply.encode('ascii'));self.wfile.flush()
    except OSError:pass
  class Server(socketserver.ThreadingTCPServer):allow_reuse_address=False;daemon_threads=True
  server=Server(('127.0.0.1',0),Handler);server_thread=threading.Thread(target=server.serve_forever,daemon=True);server_thread.start()
  # Worker time is an independent advancing channel. Authority capture never reads it.
  worker_origin=time.monotonic_ns();worker_base=(config['minimumSeconds']+100)*1000000000
  probe_base={**cfg,'expectedCoreSha256':base64.urlsafe_b64encode(bytes.fromhex(sha(CORE))).decode().rstrip('='),'authorityPort':server.server_address[1],'authorityToken':token,'runtimeLock':str(runtime_lock),'rows':backend._all()}
  def probe_config(skew=0):
   now=worker_base+2*(time.monotonic_ns()-worker_origin)+skew;sec,nano=divmod(now,1000000000);value={**probe_base,'workerNow':{'epochSecond':sec,'nano':nano},'activeKeyId':'runtime-rotate','keys':{**cfg['keys'],'runtime-rotate':base64.b64encode(bytes(range(32,64))).decode()}};path=runtime/('probe-'+secrets.token_hex(4)+'.json');protected_write(path,value);return path
  def probe(command,label=None,skew=0):
   p=execute([str(args.java_home/'bin/java'),'-cp',currentcp,'example.pending.AdapterJoinProbe',str(probe_config(skew)),command],env=environment(runtime_role,runtime_password),timeout=45)
   name=label or command;(out/(name+'.stdout')).write_text(p.stdout);(out/(name+'.stderr')).write_text(p.stderr);check('actual-current-adapters/'+name,p.returncode==0 and not p.stderr and 'PASS ' in p.stdout);return p
  probe('closed','before-schema-verification')
  # Both real COMMIT loss outcomes retain closed external admission until settlement.
  fault[0]={'mode':'before','marker':'ALTER TABLE'}
  try:installer.install_current(Migration.context(journal.read(),deadline()),schema_config(cfg));unknown=False
  except MigrationClosed as failure:unknown=failure.label=='UNKNOWN';result.setdefault('schemaLossDiagnostics',[]).append({'label':failure.label,'schemaPhase':installer.state.read()['phase'],'schemaStatus':installer.state.read()['status'],'lastTransaction':observations[-1]})
  check('schema/real-precommit-response-loss-remains-pending',unknown and installer.state.read()['status']=='PENDING' and observations[-1]['drops']==1)
  probe('closed','schema-precommit-unknown-denies-all-services')
  sql('ALTER TABLE issuer_store_namespace ADD COLUMN unauthorized_shape integer;')
  try:installer.settle(Migration.context(journal.read(),deadline()));refused=False
  except MigrationClosed as failure:refused=failure.label=='THIRD_STATE'
  check('schema/third-catalog-state-refuses-settlement',refused and installer.state.read()['status']=='PENDING')
  probe('closed','schema-third-state-denies-all-services')
  sql('ALTER TABLE issuer_store_namespace DROP COLUMN unauthorized_shape;')
  installer.settle(Migration.context(journal.read(),deadline()));check('schema/whole-source-no-effect-settlement',installer.state.read()['status']=='NO_EFFECT' and not installer.verified())
  fault[0]={'mode':'after','marker':'ALTER TABLE'}
  try:installer.install_current(Migration.context(journal.read(),deadline()),schema_config(cfg));unknown=False
  except MigrationClosed as failure:unknown=failure.label=='UNKNOWN';result.setdefault('schemaLossDiagnostics',[]).append({'label':failure.label,'schemaPhase':installer.state.read()['phase'],'schemaStatus':installer.state.read()['status'],'lastTransaction':observations[-1]})
  check('schema/real-commit-response-loss-remains-pending',unknown and installer.state.read()['status']=='PENDING' and observations[-1]['drops']==1)
  probe('closed','schema-unknown-denies-all-services')
  installer.settle(Migration.context(journal.read(),deadline()));check('schema/whole-exact-target-settlement',installer.verified())
  installer.verify_current(Migration.context(journal.read(),deadline()));check('schema/exact-current-reference-catalog-and-data',True)
  plan=journal.get_blob(installer.state.read()['planBlob']);result['activation']={'schemaPlanCommitment':commitment(plan),'rows':len(plan['rows']),'targetCatalogCommitment':commitment(plan['targetCatalog']),'targetSequence':plan['targetSequence'],'ddlHashes':plan['ddlHashes']}
  # Runtime identity pins all immutable catalog/namespace/root/epoch/quota-limit fields.
  catalog_raw=json.loads(sql(_catalog_query()+';'));predicates=[]
  predicates.append('('+_catalog_query()+')::jsonb='+quote(json.dumps(catalog_raw))+'::jsonb')
  for table in plan['targetMetadata']:
   select='to_jsonb(n)'
   if table.endswith('_escrow'):select="to_jsonb(n)-'used_entries'-'used_bytes'"
   body="SELECT coalesce(jsonb_agg(v ORDER BY v::text),'[]'::jsonb) FROM (SELECT "+select+' v FROM '+table+' n) x'
   pinned=sql(body+';');predicates.append('('+body+')='+quote(pinned)+'::jsonb')
  predicates.append("EXISTS(SELECT 1 FROM pg_roles WHERE rolname="+quote(old_role)+" AND NOT rolcanlogin)")
  control=sql("SELECT coalesce(jsonb_agg(to_jsonb(n) ORDER BY migration_id),'[]'::jsonb) FROM scp10_control n;")
  predicates.append("(SELECT coalesce(jsonb_agg(to_jsonb(n) ORDER BY migration_id),'[]'::jsonb) FROM scp10_control n)="+quote(control)+'::jsonb')
  sequence_query="SELECT jsonb_build_object('start',seqstart,'increment',seqincrement,'min',seqmin,'max',seqmax,'cache',seqcache,'cycle',seqcycle) FROM pg_sequence WHERE seqrelid='webauthn_store_version_seq'::regclass"
  predicates.append('('+sequence_query+')='+quote(json.dumps(plan['sequenceConfig']))+'::jsonb')
  predicates.append('(SELECT last_value>='+str(plan['targetSequence']['lastValue'])+' AND last_value<=9223372036854775807 FROM webauthn_store_version_seq)')
  static_query[0]='SELECT '+' AND '.join('('+p+')' for p in predicates)+';'
  check('runtime/static-sql-admission-binding-current',fast_sql(static_query[0])=='t')
  # Provision an explicitly new scripted witness directory after exact SQL settlement.
  witness_dir=runtime/'witness';witness_dir.mkdir(mode=0o700);wowner=WitnessOwner(witness_dir);owners.append(wowner);store=ManifestStore(wowner);source_origin=time.monotonic_ns();source_base=(config['minimumSeconds']+100)*1000000000+2*(source_origin-worker_origin);boot='scripted-owned-adapter-boot';owner_id=commitment('adapter/witness-owner')
  elapsed=lambda:(boot,2*(time.monotonic_ns()-source_origin))
  def capture(end):
   sample=elapsed()[1];return CheckedCapture(source_base+sample,sample,50000000,boot,commitment('scripted-adapter-capture'))
  mirrors=[{'family':f,'namespace':scopes[f],'metadataCommitment':commitment(plan['targetMetadata'][TABLES[f].replace('_entry','_namespace')]),'schemaCommitment':commitment(plan['targetCatalog']),'writerRoleIdentity':commitment(runtime_role)} for f in sorted(FORMATS)]
  initial={'format':1,'controlSequence':0,'mode':'UTC_CLOSED','ownerIncarnation':owner_id,'authorityId':cfg['authorityId'],'recoveryGeneration':cfg['recoveryGeneration'],'clockGeneration':cfg['clockGeneration'],'profile':dict(PROFILE),'reservationUpper':{'epochSecond':0,'nano':0},'brokerBootIdentity':boot,'admissionScopes':[{'family':m['family'],'namespace':m['namespace']} for m in mirrors],'activeDatabaseAdmission':mirrors,'pendingTransition':None,'utcCaptureEvidence':commitment('scripted-adapter-capture'),'migrationIntent':None}
  store.provision_genesis(initial,confirmed_never_used=True);witness=Witness(wowner,store,elapsed,capture,owner_incarnation=owner_id,previous_clock_generation=None,continuity=lambda:True);witness.start(mirrors,elapsed()[1]+100000000);witness_box[0]=witness
  for f in FORMATS:witness_expected[f]={**{k:initial[k] for k in ['authorityId','recoveryGeneration','clockGeneration','profile']},'scope':next(m for m in mirrors if m['family']==f)}
  sql('ALTER ROLE '+runtime_role+' LOGIN;GRANT USAGE ON SCHEMA public TO '+runtime_role+';GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO '+runtime_role+';GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO '+runtime_role+';')
  check('runtime/installer-immutable-guard-initial',installer.runtime_guard(Migration.context(journal.read(),deadline())))
  sql('ALTER SEQUENCE webauthn_store_version_seq CYCLE;');probe('closed','altered-sequence-configuration-denied');sql('ALTER SEQUENCE webauthn_store_version_seq NO CYCLE;')
  old_fence=journal.read()['writerFence'];sql('UPDATE scp10_control SET writer_fence='+quote(commitment('wrong-runtime-fence'))+';');probe('closed','altered-native-writer-fence-denied');sql('UPDATE scp10_control SET writer_fence='+quote(old_fence)+';')
  probe('raw');probe('query');probe('skew','independent-worker-skew-refuses',20_000_000_000);probe('mutate')
  check('runtime/installer-immutable-guard-after-mutations',installer.runtime_guard(Migration.context(journal.read(),deadline())))
  check('runtime/genuine-mutations-do-not-invalidate-static-admission',fast_sql(static_query[0])=='t' and backend.sequence()['lastValue']>=plan['targetSequence']['lastValue'])
  held=subprocess.Popen([str(args.java_home/'bin/java'),'-cp',currentcp,'example.pending.AdapterJoinProbe',str(probe_config()),'hold-status'],env=environment(runtime_role,runtime_password),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);processes.append(held);check('restore/public-service-permit-held',held.stdout.readline().strip()=='READY HELD_PUBLIC_STATUS')
  with runtime_lock.open('r+b') as barrier:
   try:fcntl.lockf(barrier,fcntl.LOCK_EX|fcntl.LOCK_NB);drained=False;fcntl.lockf(barrier,fcntl.LOCK_UN)
   except BlockingIOError:drained=True
   check('restore/exclusive-barrier-waits-for-public-operation',drained)
   stdout,stderr=held.communicate('CONTINUE\n',timeout=20);check('restore/inflight-finishes-before-close',held.returncode==0 and not stderr and 'PASS ' in stdout)
   fcntl.lockf(barrier,fcntl.LOCK_EX)
   machine.restore_closed(commitment('restore/new-recovery'),commitment('restore/container-private-auth-dump'),deadline());sql('ALTER ROLE '+runtime_role+' NOLOGIN;SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='+quote(runtime_role)+';')
   # The newer schema has root tables absent from the older archive. Clear the
   # entirely owned fixture schema while closed before restoring authentic SQL.
   sql('DROP SCHEMA public CASCADE;CREATE SCHEMA public;')
   docker('exec',resource,'pg_restore','--clean','--if-exists','--single-transaction','--exit-on-error','-U','postgres','-d','migration_fixture',archive)
   check('restore/external-intent-stays-newer-and-invalidated',journal.read()['invalidated'] and store.read()['recoveryGeneration']==cfg['recoveryGeneration'])
   fcntl.lockf(barrier,fcntl.LOCK_UN)
  probe('closed','restored-old-sql-mirrors-denied')
  p=execute([str(args.java_home/'bin/java'),'-cp',oldcp,'com.revetsec.webauthn.AdapterLegacyWriter','direct','migration'],env=writer_env,timeout=15);check('restore/fresh-old-binary-cannot-login',p.returncode==1 and p.stderr.strip()=='LEGACY_WRITER_FAILED')
  check('runtime/authority-channel-used-and-denied',rpc_counts['allowed']>0 and rpc_counts['denied']>0)
  result['rpcCounts']=rpc_counts;result['transactions']=observations;result['codecProvenance']=client.provenance;result['status']='PASS'
 except Exception as failure:
  result['failureTrace']=[{'file':str(Path(frame.filename).relative_to(ROOT)) if Path(frame.filename).is_relative_to(ROOT) else Path(frame.filename).name,'line':frame.lineno,'function':frame.name} for frame in traceback.extract_tb(failure.__traceback__)]
  result['status']='FAIL';result['failure']={'type':type(failure).__name__,'label':str(failure) if isinstance(failure,(AssertionError,MigrationClosed)) else 'Owned adapter rehearsal failed'}
 finally:
  if server:server.shutdown();server.server_close()
  for p in processes:
   if p.poll() is None:
    p.terminate()
    try:p.communicate(timeout=3)
    except subprocess.TimeoutExpired:p.kill();p.communicate(timeout=3)
  for proxy in proxies:proxy.close()
  for owner in reversed(owners):
   try:owner.close()
   except Exception:pass
  for label,command in [('container',['docker','rm','-f',resource]),('volume',['docker','volume','rm',volume]),('network',['docker','network','rm',network])]:
   if label in created:result['cleanup'][label]=execute(command).returncode==0
  try:bound.close();shutil.rmtree(runtime);result['cleanup']['protectedRuntime']=not runtime.exists()
  except Exception:result['cleanup']['protectedRuntime']=False
  result['transactions']=observations
  result['sourceInputsSha256']=inputs;result['sourceStable']=all((ROOT/name).is_file() and sha(ROOT/name)==digest for name,digest in inputs.items());save()
  print('ADAPTER_JOIN_'+result['status']+' checks='+str(len(result['checks'])))
 return 0 if result['status']=='PASS' and all(result['cleanup'].values()) and result['sourceStable'] else 1
if __name__=='__main__':raise SystemExit(main())
