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
from codec import CodecClient,synthetic_config,root_rows,protected_write,identifier
from migration import ProtectedJournal,Migration,MigrationClosed,DirectoryOwner,identity,commitment,FORMATS
from postgres_backend import TABLES,decode,quote,kind
from adapter_schema import AdapterPgBackend,SchemaInstaller,control_sql,_catalog_query
from witness import Witness, WitnessUnavailable
from fence_admission import fence_admission
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

def current_sources(current_java, *, quota_allocation=False):
 # The shared probe has typed CAP09 references even when that workload is disabled.
 # Workload flags select execution; required compile dependencies remain unconditional.
 sources=[*sorted(current_java.glob('*Pg*.java')),*[current_java/name for name in ['PostgresqlTotpStore.java','PostgresqlWebAuthnStore.java','PostgresqlIssuerStore.java','PostgresqlPyranidDataSource.java']],HERE/'java/example/migration/CodecSupport.java',HERE/'native/example/pending/AdapterJoinProbe.java',HERE/'native/com/revetsec/webauthn/AdapterJoinWorker.java',HERE/'native/verification/migration/AdapterPgBatch.java',HERE/'native/example/pending/Cap09ContentionChecks.java']
 if quota_allocation:sources.append(HERE/'native/example/pending/Cap08CapacityChecks.java')
 return sources

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--java-home',type=Path,required=True);parser.add_argument('--core-jar',type=Path);parser.add_argument('--core-sha256');parser.add_argument('--repository',type=Path,default=Path('/private/tmp/revetsec-refresh-m2'));parser.add_argument('--rotation-key-id-length',type=int,choices=[14,64],default=14);parser.add_argument('--inventory-preflight',action='store_true');parser.add_argument('--crash-restart',action='store_true');parser.add_argument('--unknown-reconciliation',action='store_true');parser.add_argument('--restore-fencing',action='store_true');parser.add_argument('--retention-maintenance',action='store_true');parser.add_argument('--fence-only',action='store_true');parser.add_argument('--floor-timing',action='store_true');parser.add_argument('--bootstrap-recovery',action='store_true');parser.add_argument('--totp-capacity',action='store_true');parser.add_argument('--webauthn-capacity',action='store_true');parser.add_argument('--quota-allocation',action='store_true');parser.add_argument('--capacity-contention',action='store_true');args=parser.parse_args()
 global CORE
 if args.core_jar is not None:
  if args.core_sha256 is None:parser.error('--core-jar requires its explicit --core-sha256')
  CORE=args.core_jar.resolve()
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
  if selected:proxy=CommitLossProxy(port,selected,maximum_packet_bytes=2097152 if args.webauthn_capacity else 131072);proxies.append(proxy)
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
  sources=current_sources(current_java,quota_allocation=args.quota_allocation)
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
  client=CodecClient(runtime/'codec',args.java_home,CORE,oldjar,args.repository,expected_core_sha256=args.core_sha256);config=synthetic_config();config.update(minimumSeconds=int(time.time())+3600,minimumNanos=123456001,ceremonyExpiresNanos=123456001,clockGeneration=commitment('adapter/clock'),allocationGeneration=commitment('adapter/allocation'),maximumUtcErrorNanos=250000000)
  if args.retention_maintenance:config['retainedCodeBaseSeconds']=config['minimumSeconds']-10
  if args.totp_capacity:config['totpCapacityCorpus']=1
  if args.webauthn_capacity:config.update(webauthnCapacityCorpus=1,webauthnMaximumSealedLength=3800)
  if args.quota_allocation or args.capacity_contention:config['quotaCorpus']=1
  if args.capacity_contention:config.update(cap09EntryCap=513,cap09TotpByteCap=512003)
  source_count=31+(8 if args.totp_capacity else 0)+(11 if args.webauthn_capacity else 0)+(8 if args.quota_allocation or args.capacity_contention else 0)
  source_rows=client.fixtures(config);check('frozen-old-complete-'+str(source_count)+'-retained-rows',len(source_rows)==source_count)
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
   check(label+'/old-jdbc-rounded-expiry-differs-authenticated-nanoseconds',sql("SELECT bool_and(((extract(epoch FROM expires_at)*1000000)::bigint%1000000)=123457) FROM webauthn_store_entry WHERE kind='CEREMONY';")=='t')
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
  restore_snapshots={}
  def snapshot_facts():
   return [sql("SELECT md5(coalesce(jsonb_agg(to_jsonb(e) ORDER BY storage_key)::text,'')) FROM "+table+' e;') for table in TABLES.values()]+[sql('SELECT md5(row_to_json(c)::text) FROM scp10_control c;')]
  def case(name,exhausted=False,bad_expiry=False,crash_stage=None,stage_only=False,activate=True):
   if bad_expiry:sql("UPDATE webauthn_store_entry SET expires_at=expires_at+interval '1 microsecond' WHERE kind='CEREMONY';")
   sql('ALTER SEQUENCE webauthn_store_version_seq RESTART WITH '+str(9223372036854775807 if exhausted else 9223372036854774783)+';'+("SELECT nextval('webauthn_store_version_seq');" if exhausted else ''))
   cfg={**config,'migrationId':commitment(name+'/migration'),'recoveryGeneration':commitment(name+'/recovery')}
   intent={'migrationId':cfg['migrationId'],'sourceRecoveryGeneration':commitment(name+'/old'),'targetAdmission':{k:cfg[k] for k in ['authorityId','recoveryGeneration']},'writerFence':commitment(name+'/fence'),'targetFormats':dict(FORMATS),'authorityWitness':commitment(name+'/scripted-witness')}
   sql('INSERT INTO scp10_control(migration_id,writer_fence,source_recovery,target_authority,target_recovery,mode) VALUES('+','.join(map(quote,[intent['migrationId'],intent['writerFence'],intent['sourceRecoveryGeneration'],cfg['authorityId'],cfg['recoveryGeneration'],'CLOSED']))+');')
   if args.restore_fencing and name in ['MIG10-before','main']:
    archive='/tmp/mig10-adapter-'+name+'.dump';docker('exec',resource,'pg_dump','--schema=public','-Fc','-U','postgres','-d','migration_fixture','-f',archive)
    restore_snapshots[name]={'archive':archive,'facts':snapshot_facts()}
   directory=runtime/name;directory.mkdir(mode=0o700);owner=DirectoryOwner(directory);owners.append(owner);journal=ProtectedJournal(owner)
   backend=AdapterPgBackend(sql,transaction,scopes,[old_role],namespaces=namespaces,required_roots=required_roots,journal=journal,confirmed_new_intent=True,codec_client=client,codec_config=cfg);machine=Migration(journal,backend);installer=SchemaInstaller(backend)
   machine.close(intent,deadline());backend.confirmed_new_intent=False
   if args.inventory_preflight and name=='main':
    original=backend.sql;before=journal.read();transactions=len(observations)
    baseline=backend._raw_source()
    for family,table in sorted(TABLES.items()):
     for defect in ['omitted','duplicate']:
      def faulty(query,table=table,defect=defect):
       answer=original(query)
       if 'FROM '+table+' ' in query and 'LIMIT 32' in query:
        page=json.loads(answer)
        return json.dumps([] if defect=='omitted' else page+[copy.deepcopy(page[0])])
       return answer
      backend.sql=faulty
      try:backend._raw_source();refused=False
      except MigrationClosed:refused=True
      finally:backend.sql=original
      check('MIG07/legacy-'+family+'-'+defect,refused and journal.read()==before and len(observations)==transactions and backend._raw_source()==baseline)
    declared=backend.required_roots;backend.required_roots=[r for r in declared if r[0]!='ISSUER']
    try:backend._raw_source();refused=False
    except MigrationClosed:refused=True
    finally:backend.required_roots=declared
    check('MIG07/legacy-complete-root-declaration',refused and journal.read()==before and len(observations)==transactions and backend._raw_source()==baseline)
   if bad_expiry:
    before=backend._raw_source()
    try:backend.stage_legacy(Migration.context(journal.read(),deadline()));refused=False
    except MigrationClosed as failure:refused=failure.label=='CORRUPT'
    check(name+'/native-timestamp-not-authenticated-expiry-authority',refused and before==backend._raw_source() and journal.read()['phase']=='CLOSED')
    return None
   if crash_stage is not None:
    proposed=[None];original=installer.state.write;hit=[False]
    def write(expected,value):proposed[0]=value;return original(expected,value)
    installer.state.write=write
    def lost(point):
     if point=='after_rename' and proposed[0]['phase']==crash_stage and not hit[0]:hit[0]=True;raise OSError('MIG08_SCHEMA_ACK_LOST')
    installer.state.fault=lost
    try:installer.stage_legacy(Migration.context(journal.read(),deadline()));uncertain=False
    except MigrationClosed as failure:uncertain=failure.label=='DURABILITY_UNCERTAIN'
    check('MIG08/schema-'+crash_stage+'/metadata-ack-loss-closes',uncertain and hit[0] and journal.owner._adapter_schema_uncertain)
    installer=SchemaInstaller(backend)
    settled=installer.settle(Migration.context(journal.read(),deadline()))
    check('MIG08/schema-'+crash_stage+'/exact-native-settlement',not journal.owner._adapter_schema_uncertain and settled['status'] in ['NO_EFFECT','COMMITTED'])
    installer.stage_legacy(Migration.context(journal.read(),deadline()))
   else:backend.stage_legacy(Migration.context(journal.read(),deadline()))
   if stage_only:
    actual=backend._all();opened=client.prepare(cfg,actual)
    check('MIG08/schema-'+crash_stage+'/all-permanent-facts-preserved',actual==sorted(source_rows,key=identity) and all(v['classification']=='FIT' for v in opened) and journal.read()['phase']=='CLOSED' and journal.read()['timedAdmission']=='CLOSED')
    return None
   machine.inventory(deadline())
   rows=journal.get_blob(journal.read()['inventoryBlob']);check(name+'/source-metadata-authenticated-exact-all'+str(source_count),rows==sorted(source_rows,key=identity))
   decisions=sorted(client.prepare(cfg,rows),key=lambda d:identity(d['source']));caps=[{'family':f,'scope':scopes[f],'entryCap':65536 if f=='TOTP' else 1000000,'hardEntryCap':65536 if f=='TOTP' else 1000000,'byteCap':268435456 if f=='TOTP' else None,'hardByteCap':268435456 if f=='TOTP' else None} for f in sorted(FORMATS)]
   if args.capacity_contention:
    for c in caps:
     c['entryCap']=cfg['cap09EntryCap']
     if c['family']=='TOTP':c['byteCap']=cfg['cap09TotpByteCap']
   if args.totp_capacity and name=='main':
    preserved=journal.read();native_before=backend._all();writes=len(observations);reserved=sum(d['reservationBytes'] for d in decisions if d['source']['family']=='TOTP');old_size=sum(len(decode(r['ciphertext'])) for r in rows if r['family']=='TOTP');small=copy.deepcopy(caps)
    for c in small:
     if c['family']=='TOTP':c['byteCap']=reserved-1
    check('CAP06/adapter/legacy-bytes-fit-but-reserved-target-does-not',old_size<reserved-1)
    try:machine.prepare(decisions,small,deadline());refused=False
    except MigrationClosed as failure:refused=failure.label=='UNSUPPORTED'
    check('CAP06/adapter/aggregate-refusal-before-native-write-preserves-complete-history',refused and journal.read()==preserved and backend._all()==native_before and len(observations)==writes)
   if args.quota_allocation and name=='main':
    preserved=journal.read();native_before=backend._all();writes=len(observations)
    for dimension in ['TOTP-entry','WEBAUTHN-entry','ISSUER-entry','TOTP-byte']:
     small=copy.deepcopy(caps);family=dimension.split('-')[0];selected=next(c for c in small if c['family']==family)
     if dimension.endswith('entry'):selected['entryCap']=sum(d['source']['family']==family for d in decisions)-1
     else:selected['byteCap']=sum(d['reservationBytes'] for d in decisions if d['source']['family']==family)-1
     try:machine.prepare(decisions,small,deadline());refused=False
     except MigrationClosed as failure:refused=failure.label=='UNSUPPORTED'
     check('CAP08/adapter/'+dimension+'-under-retained-usage-refuses-before-any-write',refused and journal.read()==preserved and backend._all()==native_before and len(observations)==writes)
   machine.prepare(decisions,caps,deadline())
   if exhausted:
    try:installer.preflight_current(Migration.context(journal.read(),deadline()),schema_config(cfg));refused=False
    except MigrationClosed as failure:refused=failure.label=='UNSUPPORTED'
    check(name+'/exhausted-native-sequence-refuses-before-rewrite',refused and journal.read()['cursor']==0 and backend._all()==rows)
    return None
   installer.preflight_current(Migration.context(journal.read(),deadline()),schema_config(cfg));check(name+'/current-schema-capacity-preflight',True)
   check(name+'/exact-256-bucket-quotas',backend.install_quotas(Migration.context(journal.read(),deadline()),journal.get_blob(journal.read()['quotaBlob']))=='COMMITTED')
   if args.unknown_reconciliation and name=='main':
    result['unknownBatches']=[]
    while journal.read()['cursor']<source_count:
     cursor=journal.read()['cursor'];before_transactions=len(observations);fault[0]='before'
     try:machine.rewrite_next(deadline());unknown=False
     except MigrationClosed as failure:unknown=failure.label=='UNKNOWN'
     pending=journal.read();pinned=pending['progress']['batchBlob'];batch=journal.get_blob(pinned)
     check('MIG09/adapter/'+str(cursor)+'/precommit-loss-keeps-exact-intent',unknown and pending['cursor']==cursor and pending['timedAdmission']=='CLOSED' and not installer.runtime_guard(Migration.context(journal.read(),deadline())))
     machine.settle(deadline());settled=journal.read()
     check('MIG09/adapter/'+str(cursor)+'/all-old-staged-legacy-is-no-effect',settled['cursor']==cursor and settled['progress']['status']=='NO_EFFECT' and settled['progress']['batchBlob']==pinned and len(observations)==before_transactions+1)
     fault[0]='after'
     try:machine.rewrite_next(deadline());unknown=False
     except MigrationClosed as failure:unknown=failure.label=='UNKNOWN'
     check('MIG09/adapter/'+str(cursor)+'/explicit-retry-reuses-original-bytes',unknown and journal.read()['progress']['batchBlob']==pinned and journal.get_blob(pinned)==batch and len(observations)==before_transactions+2)
     try:machine.rewrite_next(deadline());unknown=False
     except MigrationClosed as failure:unknown=failure.label=='UNKNOWN'
     check('MIG09/adapter/'+str(cursor)+'/pending-is-never-blind-replayed',unknown and len(observations)==before_transactions+2)
     machine.settle(deadline())
     check('MIG09/adapter/'+str(cursor)+'/all-new-advances-once-still-closed',journal.read()['cursor']==cursor+len(batch['replacements']) and journal.read()['progress'] is None and journal.read()['timedAdmission']=='CLOSED' and not installer.runtime_guard(Migration.context(journal.read(),deadline())) and len(observations)==before_transactions+2)
     result['unknownBatches'].append({'cursor':cursor,'mutations':len(batch['replacements']),'allOld':'NO_EFFECT','allNew':'COMMITTED','exactPlanReused':True})
   while journal.read()['cursor']<source_count:machine.rewrite_next(deadline())
   actual=backend._all();verified=sorted(client.verify(cfg,actual),key=lambda d:identity(d['source']));machine.verify(verified,deadline());state=journal.read()
   if activate:machine.activate({k:state[k] for k in ['authorityWitness','writerFence','targetAdmission','activationCommitment']},deadline())
   check(name+'/current-codec-independently-opens-all'+str(source_count),len(verified)==source_count and all(d['classification']=='FIT' for d in verified));return cfg,journal,backend,machine,installer
  if args.crash_restart:
   for target in ['SOURCE_PREPARED','STAGING','STAGED']:
    seed('crash-'+target);case('crash-'+target,crash_stage=target,stage_only=True)
   seed('crash-current')
   cfg,journal,backend,machine,installer=case('crash-current')
   for target in ['CURRENT_PREPARED','CURRENT_APPLYING','CURRENT_VERIFIED']:
    proposed=[None];original=installer.state.write;hit=[False]
    def write(expected,value,original=original):proposed[0]=value;return original(expected,value)
    installer.state.write=write
    def lost(point):
     if point=='after_rename' and proposed[0]['phase']==target and not hit[0]:hit[0]=True;raise OSError('MIG08_SCHEMA_ACK_LOST')
    installer.state.fault=lost
    try:installer.install_current(Migration.context(journal.read(),deadline()),schema_config(cfg));uncertain=False
    except MigrationClosed as failure:uncertain=failure.label=='DURABILITY_UNCERTAIN'
    check('MIG08/schema-'+target+'/metadata-ack-loss-closes',uncertain and hit[0] and not installer.verified() and not installer.runtime_guard(Migration.context(journal.read(),deadline())))
    installer=SchemaInstaller(backend)
    settled=installer.settle(Migration.context(journal.read(),deadline()))
    check('MIG08/schema-'+target+'/exact-native-settlement',not journal.owner._adapter_schema_uncertain and settled['status'] in ['NO_EFFECT','COMMITTED'] and journal.read()['timedAdmission']=='CLOSED')
   installer.verify_current(Migration.context(journal.read(),deadline()))
   values=client.verify(cfg,backend._all())
   check('MIG08/schema-current/all-authenticated-targets-preserved',len(values)==source_count and all(v['classification']=='FIT' for v in values))
   seed('timestamp-source')
  case('wrong-old-timestamp',bad_expiry=True)
  seed('exhaustion-source')
  case('exhausted-sequence',exhausted=True)
  if args.restore_fencing:
   seed('MIG10-before-source');cfg,journal,backend,machine,installer=case('MIG10-before',activate=False)
   before=journal.read();machine.restore_closed(commitment('MIG10/adapter-before/fresh'),commitment('MIG10/adapter-before/snapshot'),deadline());saved=journal.read()
   sql('DROP SCHEMA public CASCADE;CREATE SCHEMA public;')
   docker('exec',resource,'pg_restore','--clean','--if-exists','--single-transaction','--exit-on-error','-U','postgres','-d','migration_fixture',restore_snapshots['MIG10-before']['archive'])
   check('MIG10/adapter/before/actual-legacy-rows-and-old-marker-restored',snapshot_facts()==restore_snapshots['MIG10-before']['facts'])
   check('MIG10/adapter/before/external-invalidation-and-runtime-closure',saved['invalidated'] and saved['phase']==before['phase']=='VERIFIED' and journal.read()==saved and not installer.runtime_guard(Migration.context(saved,deadline())))
   try:machine.inventory(deadline());refused=False
   except MigrationClosed as failure:refused=failure.label=='RECOVERY_REQUIRED'
   check('MIG10/adapter/before/old-marker-cannot-reauthorize',refused)
   for mode in ['direct','pooled']:
    p=execute([str(args.java_home/'bin/java'),'-cp',oldcp,'com.revetsec.webauthn.AdapterLegacyWriter',mode,'migration'],env=writer_env,timeout=15)
    check('MIG10/adapter/before/old-'+mode+'-binary-cannot-login',p.returncode==1 and p.stderr.strip()=='LEGACY_WRITER_FAILED')
  seed('main-source')
  cfg,journal,backend,machine,installer=case('main')
  archive=restore_snapshots['main']['archive'] if args.restore_fencing else '/tmp/scp10-adapter-auth.dump'
  if not args.restore_fencing:docker('exec',resource,'pg_dump','-Fc','-U','postgres','-d','migration_fixture','-f',archive)
  # The dump is owned, container-private and predates schema activation/runtime mutations.
  token=secrets.token_urlsafe(32);runtime_lock=runtime/'runtime.lock';runtime_lock.touch(mode=0o600);rpc_lock=threading.RLock();witness_box=[None];static_query=[None];witness_expected={};rpc_counts={'allowed':0,'denied':0,'maxHandlerNanos':0,'handlersOver80Millis':0,'failureTypes':{}}
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
   # Independent current recovery admission; no elapsed, worker or UTC read here.
   wowner.check()
   return fence_admission(store.read(),owner_id,cfg,mirrors,family,scope)
  def observed(family,scope):
   expected=admitted(family,scope);witness=witness_box[0]
   try:
    elapsed=witness.elapsed()[1]
    if witness.renewal_due(elapsed+100000000):witness.renew(witness.store.read()['activeDatabaseAdmission'],witness.elapsed()[1]+100000000)
    return witness.sample(witness_expected[family],witness.elapsed()[1]+100000000)
   except WitnessUnavailable:
    # Recheck independent admission after time failure. Missing/uncertain external
    # state is CLOSED; only a still-current recovery tuple can report UTC outage.
    if admitted(family,scope)!=expected:raise MigrationClosed('CLOSED')
    return None
  class Handler(socketserver.StreamRequestHandler):
   def handle(self):
    handler_started=time.monotonic_ns()
    try:
     self.request.settimeout(1);parts=self.rfile.readline(2048).decode('ascii').strip().split('\t')
     if len(parts)!=5 or parts[0]!=token or parts[1] not in ['ADMIT','OBSERVE'] or parts[2] not in scopes:raise ValueError()
     with rpc_lock:
      authority,recovery=admitted(parts[2],parts[3])
      point=observed(parts[2],parts[3]) if parts[1]=='OBSERVE' else None
      status='OK' if point is not None else 'UTC_UNAVAILABLE' if parts[1]=='OBSERVE' else 'ADMITTED'
      rpc_counts['allowed']+=1;rpc_counts[status]=rpc_counts.get(status,0)+1
      if point is None:reply='\t'.join([status,authority,recovery,'','','','',''])+'\n'
      else:
       seconds,nano=divmod(point.authority_ns,1000000000);reply='\t'.join(map(str,['OK',point.authority_id,point.recovery_generation,point.clock_generation,seconds,nano,point.maximum_utc_error_ns,commitment('scripted-qualified-false')]))+'\n'
    except Exception as failure:
     rpc_counts['denied']+=1;kind=type(failure).__name__;rpc_counts['failureTypes'][kind]=rpc_counts['failureTypes'].get(kind,0)+1;reply='CLOSED\n'
    elapsed_handler=time.monotonic_ns()-handler_started;rpc_counts['maxHandlerNanos']=max(rpc_counts['maxHandlerNanos'],elapsed_handler)
    if elapsed_handler>80000000:rpc_counts['handlersOver80Millis']+=1
    try:self.wfile.write(reply.encode('ascii'));self.wfile.flush()
    except OSError:pass
  class Server(socketserver.ThreadingTCPServer):allow_reuse_address=False;daemon_threads=True
  server=Server(('127.0.0.1',0),Handler);server_thread=threading.Thread(target=server.serve_forever,daemon=True);server_thread.start()
  # Worker time is an independent advancing channel. Authority capture never reads it.
  worker_origin=time.monotonic_ns();worker_base=(config['minimumSeconds']+100)*1000000000
  probe_base={**cfg,'expectedCoreSha256':base64.urlsafe_b64encode(bytes.fromhex(sha(CORE))).decode().rstrip('='),'authorityPort':server.server_address[1],'authorityToken':token,'runtimeLock':str(runtime_lock),'rows':backend._all(),'expectedTotpActiveRecords':13 if args.totp_capacity else 5,'expectedWebauthnRecords':8+(11 if args.webauthn_capacity else 0)+(8 if args.quota_allocation or args.capacity_contention else 0)}
  runtime_key_id='r'*64 if args.rotation_key_id_length==64 else 'runtime-rotate'
  result['runtimeRotationKeyIdLength']=len(runtime_key_id)
  def probe_config(skew=0):
   now=worker_base+2*(time.monotonic_ns()-worker_origin)+skew;sec,nano=divmod(now,1000000000);value={**probe_base,'workerNow':{'epochSecond':sec,'nano':nano},'activeKeyId':runtime_key_id,'keys':{**cfg['keys'],runtime_key_id:base64.b64encode(bytes(range(32,64))).decode()}};path=runtime/('probe-'+secrets.token_hex(4)+'.json');protected_write(path,value);return path
  def probe(command,label=None,skew=0):
   p=execute([str(args.java_home/'bin/java'),'-cp',currentcp,'example.pending.AdapterJoinProbe',str(probe_config(skew)),command],env=environment(runtime_role,runtime_password),timeout=120 if command=='capacity-contention' else 45)
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
  if args.quota_allocation:
   prepared=journal.get_blob(journal.read()['decisionsBlob']);quotas=journal.get_blob(journal.read()['quotaBlob'])
   for q in quotas:
    family=q['family'];selected=[d for d in prepared if d['source']['family']==family];used=[0]*256;byte_used=[0]*256
    for d in selected:
     bucket=int(hashlib.sha256(d['source']['key'].encode('ascii')).hexdigest()[:2],16);used[bucket]+=1;byte_used[bucket]+=d['reservationBytes'] if family=='TOTP' else 0
    entry=[*used];left=q['entryCap']-sum(used);rounds,left=divmod(left,256);entry=[n+rounds for n in entry]
    for i in range(left):entry[i]+=1
    byte_limit=[0]*256
    if family=='TOTP':
     byte_limit=[*byte_used];rounds,left=divmod(q['byteCap']-sum(byte_used),256);byte_limit=[n+rounds for n in byte_limit]
     for i in range(left):byte_limit[i]+=1
    expected=[{'bucket':i,'entryLimit':entry[i],'usedEntries':used[i],'byteLimit':byte_limit[i],'usedBytes':byte_used[i]} for i in range(256)]
    table=family.lower()+'_store_escrow';physical=json.loads(sql("SELECT jsonb_agg(jsonb_build_object('bucket',bucket,'entryLimit',entry_limit,'usedEntries',used_entries,'byteLimit',byte_limit,'usedBytes',used_bytes) ORDER BY bucket) FROM "+table+';'))
    check('CAP08/adapter/'+family+'-all-256-persisted-quotas-match-independent-retained-histogram',physical==expected and sum(r['entryLimit'] for r in physical)==q['entryCap'] and sum(r['byteLimit'] for r in physical)==(q['byteCap'] or 0))
   check('CAP08/adapter/complete-old-epochs-and-RP-scopes-remain-counted',len({r['key'].split(':')[2] for r in backend._all() if r['family']=='TOTP'})==2 and len({r['key'].split(':')[2] for r in backend._all() if r['family']=='WEBAUTHN'})==2 and len(backend._all())==source_count)
   public_before=backend._all();quota_before=[sql("SELECT jsonb_agg(to_jsonb(e) ORDER BY bucket)::text FROM "+f.lower()+'_store_escrow e;') for f in sorted(FORMATS)]
   protected=runtime/'cap08-native-input.json';output=runtime/'cap08-native-output.json';protected_write(protected,{**cfg,'operation':'native','prepared':prepared,'expectedCoreSha256':sha(CORE)})
   ran=execute([str(args.java_home/'bin/java'),'-cp',currentcp,'example.pending.Cap08CapacityChecks',str(protected),str(output)],env=environment(),timeout=45)
   cells=json.loads(output.read_text())['decisions'] if ran.returncode==0 and output.exists() else []
   (out/'CAP08-native-cells.json').write_text(json.dumps({'cells':cells,'exit':ran.returncode,'stderr':ran.stderr},indent=2)+'\n')
   check('CAP08/adapter/fresh-root-temporary-SQL-components-pass',ran.returncode==0 and len(cells)==13 and all(c['passed'] for c in cells))
   check('CAP08/adapter/fresh-component-session-preserves-all-real-retained-rows-and-quotas',backend._all()==public_before and quota_before==[sql("SELECT jsonb_agg(to_jsonb(e) ORDER BY bucket)::text FROM "+f.lower()+'_store_escrow e;') for f in sorted(FORMATS)])
   result['quotaAllocation']={'sourceRows':source_count,'totpRows':9,'totpEpochs':2,'webauthnRows':16,'webauthnRps':2,'issuerRows':14,'bucketsPerFamily':256,'newOuterChecks':10,'nativeTemporarySqlCells':13,'freshScope':'Temporary escrow tables cloned from actual schema; genuine prepared-root charge and actual helper SQL. No fresh runtime bootstrap/deployment activation claim.','qualified':False}
  # Runtime identity pins all immutable catalog/namespace/root/epoch/quota-limit fields.
  catalog_raw=json.loads(sql(_catalog_query()+';'));predicates=[]
  predicates.append('('+_catalog_query()+')::jsonb='+quote(json.dumps(catalog_raw))+'::jsonb')
  for table in plan['targetMetadata']:
   select='to_jsonb(n)'
   if table.endswith('_escrow'):select="to_jsonb(n)-'used_entries'-'used_bytes'"
   body="SELECT coalesce(jsonb_agg(v ORDER BY v::text),'[]'::jsonb) FROM (SELECT "+select+' v FROM '+table+' n) x'
   pinned=sql(body+';');predicates.append('('+body+')='+quote(pinned)+'::jsonb')
  predicates.append('('+backend._writer_predicate()+')')
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
  capture_available=[True]
  def capture(end):
   if not capture_available[0]:raise RuntimeError('Scripted UTC capture outage')
   sample=elapsed()[1];return CheckedCapture(source_base+sample,sample,50000000,boot,commitment('scripted-adapter-capture'))
  mirrors=[{'family':f,'namespace':scopes[f],'metadataCommitment':commitment(plan['targetMetadata'][TABLES[f].replace('_entry','_namespace')]),'schemaCommitment':commitment(plan['targetCatalog']),'writerRoleIdentity':commitment(runtime_role)} for f in sorted(FORMATS)]
  initial={'format':1,'controlSequence':0,'mode':'UTC_CLOSED','ownerIncarnation':owner_id,'authorityId':cfg['authorityId'],'recoveryGeneration':cfg['recoveryGeneration'],'clockGeneration':cfg['clockGeneration'],'profile':dict(PROFILE),'reservationUpper':{'epochSecond':0,'nano':0},'brokerBootIdentity':boot,'admissionScopes':[{'family':m['family'],'namespace':m['namespace']} for m in mirrors],'activeDatabaseAdmission':mirrors,'pendingTransition':None,'utcCaptureEvidence':commitment('scripted-adapter-capture'),'migrationIntent':None}
  store.provision_genesis(initial,confirmed_never_used=True);witness=Witness(wowner,store,elapsed,capture,owner_incarnation=owner_id,previous_clock_generation=None,continuity=lambda:True);witness.start(mirrors,elapsed()[1]+100000000);witness_box[0]=witness
  for f in FORMATS:witness_expected[f]={**{k:initial[k] for k in ['authorityId','recoveryGeneration','clockGeneration','profile']},'scope':next(m for m in mirrors if m['family']==f)}
  sql('ALTER ROLE '+runtime_role+' LOGIN;GRANT USAGE ON SCHEMA public TO '+runtime_role+';GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO '+runtime_role+';GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO '+runtime_role+';')
  check('runtime/installer-immutable-guard-initial',installer.runtime_guard(Migration.context(journal.read(),deadline())))
  sql('ALTER SEQUENCE webauthn_store_version_seq CYCLE;');probe('closed','altered-sequence-configuration-denied');sql('ALTER SEQUENCE webauthn_store_version_seq NO CYCLE;')
  old_fence=journal.read()['writerFence'];sql('UPDATE scp10_control SET writer_fence='+quote(commitment('wrong-runtime-fence'))+';');probe('closed','altered-native-writer-fence-denied');sql('UPDATE scp10_control SET writer_fence='+quote(old_fence)+';')
  if args.restore_fencing:
   sql('GRANT UPDATE(sealed_form) ON issuer_store_entry TO '+old_role+';');probe('closed','MIG10-column-grant-denies-all-services');sql('REVOKE UPDATE(sealed_form) ON issuer_store_entry FROM '+old_role+';')
   check('MIG10/adapter/fence-restored-positive-control',fast_sql(static_query[0])=='t')
  probe('raw');probe('query');probe('skew','independent-worker-skew-refuses',20_000_000_000)
  def closed_audit(selected,facts=False):
   with runtime_lock.open('r+b') as barrier:
    fcntl.lockf(barrier,fcntl.LOCK_EX);previous=witness_box[0];witness_box[0]=None
    sql('ALTER ROLE '+runtime_role+' NOLOGIN;SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='+quote(runtime_role)+';')
    try:
     if sql('SELECT count(*) FROM pg_stat_activity WHERE usename='+quote(runtime_role)+';')!='0':raise MigrationClosed('CLOSED')
     rows=backend._all()
     if facts:
      selected_rows=[r for r in rows if r['family']=='ISSUER' and any(':'+k+':' in r['key'] for k in ['ISSUER_STATE','SUBJECT_STATE'])]
      return client.process('ISSUER',selected,selected_rows,root_rows(selected_rows),'fence-facts')
     return client.verify(selected,rows)
    finally:
     sql('ALTER ROLE '+runtime_role+' LOGIN;');witness_box[0]=previous;fcntl.lockf(barrier,fcntl.LOCK_UN)
  if args.retention_maintenance:
   maintenance=next(r for r in source_rows if r['family']=='ISSUER' and ':CODE:' in r['key'] and r['key'].endswith(':'+identifier(23)))
   probe_base.update(maintenanceKey=maintenance['key'],maintenanceExpiresSeconds=config['minimumSeconds']+90)
   before=closed_audit(cfg);probe('retained-issuer','MIG12-retained-issuer')
   runtime_keys={**cfg['keys'],runtime_key_id:base64.b64encode(bytes(range(32,64))).decode()}
   after=closed_audit({**cfg,'keys':runtime_keys,'activeKeyId':runtime_key_id})
   check('MIG12/adapter/retained-maintenance-preserves-complete-payload-floors-and-retention',all(d['classification']=='FIT' for d in after) and [(d['sourceSemanticCommitment'],d['floor'],d['retention']) for d in before]==[(d['sourceSemanticCommitment'],d['floor'],d['retention']) for d in after])
   unchanged=commitment(backend._all());old_witness=witness_box[0];witness_box[0]=None
   try:probe('closed','MIG12-unhealthy-ttl-denies-services',3_155_760_000_000_000_000)
   finally:witness_box[0]=old_witness
   check('MIG12/adapter/raw-future-worker-cannot-expire-or-evict-any-auth-state',commitment(backend._all())==unchanged)
   result['retentionMaintenance']={'genuineOldUsedCode':True,'credentialExpiredAtAdmittedAuthority':True,'beforeOuterRetention':True,'completeSemanticsPreserved':True,'ttlPausedDuringAuthorityClosure':True,'rawWorkerAdvanceYears':100}
  if args.fence_only:
   runtime_keys={**cfg['keys'],runtime_key_id:base64.b64encode(bytes(range(32,64))).decode()};selected={**cfg,'keys':runtime_keys,'activeKeyId':runtime_key_id}
   before=closed_audit(selected,True);rows_before=backend._all()
   capture_available[0]=False
   try:witness.renew(mirrors,witness.elapsed()[1]+100000000);renewed=True
   except WitnessUnavailable:renewed=False
   check('MIG13/adapter/failed-capture-closes-UTC-with-known-recovery',not renewed and store.read()['mode']=='UTC_CLOSED' and store.read()['pendingTransition'] is None)
   probe('fence-outage','MIG13-UTC-outage',20_000_000_000)
   after=closed_audit(selected,True);rows_after=backend._all()
   check('MIG13/adapter/exact-F-L-authority-incarnation-permanent-retention',len(before)==len(after)==2 and all(a['floor']==b['floor'] and a['retention']==b['retention'] and a['unchangedPayloadCommitment']==b['unchangedPayloadCommitment'] and b['epoch']==a['epoch']+1 and a['source']['version']!=b['source']['version'] for a,b in zip(before,after)))
   permanent_keys={r['source']['key'] for r in before}
   check('MIG13/adapter/only-existing-two-fence-rows-changed',len(rows_before)==len(rows_after)==len(source_rows) and [r for r in rows_before if r['key'] not in permanent_keys]==[r for r in rows_after if r['key'] not in permanent_keys])
   # Known recovery closure, unknown external owner and authenticated-root faults
   # each refuse both public fence operations with exact row preservation.
   stable=commitment(backend._all());old_witness=witness_box[0];witness_box[0]=None
   try:probe('fence-denied','MIG13-unknown-external-owner')
   finally:witness_box[0]=old_witness
   check('MIG13/adapter/unknown-external-owner-zero-effects',commitment(backend._all())==stable)
   with rpc_lock:
    closed=store.read();closed['controlSequence']+=1;closed['mode']='RECOVERY_CLOSED';witness._persist(store.read(),closed)
   probe('fence-denied','MIG13-closed-recovery')
   check('MIG13/adapter/closed-recovery-zero-effects',commitment(backend._all())==stable)
   with rpc_lock:
    reopened=store.read();reopened['controlSequence']+=1;reopened['mode']='UTC_CLOSED';witness._persist(store.read(),reopened)
   def raw_snapshot():
    # Complete raw native facts remain observable even when the protected inventory
    # correctly refuses a missing established root. Never reinterpret refusal as absence.
    tables=sorted(TABLES.values())+['issuer_store_root','issuer_store_escrow']
    return commitment([sql("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text)::text,'[]') FROM "+table+' t;') for table in tables])
   root=next(r for r in rows_after if r['family']=='ISSUER' and ':ISSUER_STATE:' in r['key'])
   for label,mutation in [('corrupt-root',"UPDATE issuer_store_entry SET sealed_form='corrupt' WHERE namespace='migration' AND storage_key="+quote(root['key'])+';'),('missing-root',"DELETE FROM issuer_store_entry WHERE namespace='migration' AND storage_key="+quote(root['key'])+';')]:
    sql(mutation);damaged=raw_snapshot();probe('fence-denied','MIG13-'+label)
    check('MIG13/adapter/'+label+'-zero-effects',raw_snapshot()==damaged)
    sql("DELETE FROM issuer_store_entry WHERE namespace='migration' AND storage_key="+quote(root['key'])+';')
    values=[quote('migration'),quote(root['key']),quote('ISSUER_STATE'),quote(root['version']),str(root['retention']['epochSecond']),str(root['retention']['nano']),quote(decode(root['ciphertext']).decode('ascii'))]
    sql('INSERT INTO issuer_store_entry(namespace,storage_key,kind,version,retain_seconds,retain_nanos,sealed_form) VALUES('+','.join(values)+');')
   # The test-only direct SQL perturbations are confined to this owned database.
   # Close/resume the live witness through its own control path after external mode probes.
   capture_available[0]=True;witness.renew(mirrors,witness.elapsed()[1]+100000000,resume=True)
   check('MIG13/adapter/explicit-continuity-resume',store.read()['mode']=='ACTIVE' and commitment(backend._all())==stable)
   result['fenceOnly']={'utcOutage':'Failed checked-capture renewal persists UTC_CLOSED','workerSkewSeconds':20,'rootAndSubjectEpochAdvance':True,'exactPreparedFloorAndMinimum':True,'unchangedPayloadExceptEpoch':True,'permanentRetention':True,'closedAndUnknownRecoveryRefuse':True,'corruptAndMissingRootRefuse':True,'timedPurposesRefuse':['warmup','initialization','new subject','reseal'],'otherFamiliesRefuse':True,'qualified':False}
  if args.floor_timing:
   roots_before=root_rows(backend._all());runtime_keys={**cfg['keys'],runtime_key_id:base64.b64encode(bytes(range(32,64))).decode()}
   run=probe('floor-timing','MIG14-floor-timing');prepared=[]
   for line in run.stdout.splitlines():
    if not line.startswith('MIG14_FLOOR\t'):continue
    _,family,address,seconds,nano,vseconds,vnano=line.split('\t');prepared.append({'family':family,'key':decode(address).decode(),'floor':{'epochSecond':int(seconds),'nano':int(nano)},'validated':{'epochSecond':int(vseconds),'nano':int(vnano)}})
   verified=closed_audit({**cfg,'keys':runtime_keys,'activeKeyId':runtime_key_id});by_key={d['source']['key']:d for d in verified}
   check('MIG14/adapter/all-family-prepared-floor-is-authenticated-stored-floor',set(v['family'] for v in prepared)==set(FORMATS) and all(by_key[v['key']]['classification']=='FIT' and by_key[v['key']]['floor']==v['floor'] for v in prepared))
   check('MIG14/adapter/normal-transitions-never-refresh-existing-roots',root_rows(backend._all())==roots_before)
   def pure_query_facts():
    tables=sorted(TABLES.values())+['totp_store_escrow','webauthn_store_escrow','issuer_store_escrow']
    return commitment([sql("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text)::text,'[]') FROM "+table+' t;') for table in tables])
   pure=pure_query_facts();probe('query','MIG14-status-list-pure')
   check('MIG14/adapter/status-list-preserve-all-native-rows-and-escrows',pure_query_facts()==pure)
   result['floorTiming']={'families':sorted(FORMATS),'preparedFrames':len(prepared),'floorComparisons':prepared,'exactInputFramesPreserved':True,'backendValidationStrictlyLater':True,'completedTime':'Absent in actual adapter receipts; supplied later completion separately covered in source tests','statusListNoWrites':True,'qualified':False}
  if args.bootstrap_recovery:
   def native_facts():
    tables=sorted(TABLES.values())+['totp_store_namespace','webauthn_store_namespace','issuer_store_namespace','totp_store_epoch','webauthn_store_root','issuer_store_root','totp_store_escrow','webauthn_store_escrow','issuer_store_escrow']
    return commitment([sql("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text)::text,'[]') FROM "+table+' t;') for table in tables])
   for family in sorted(FORMATS,reverse=True):
    probe_base['bootstrapFamily']=family;root=next(r for r in backend._all() if r['family']==family and r in root_rows(backend._all()) and (family!='TOTP' or ':b2xkLW9uZQ:' in r['key']))
    table=TABLES[family]
    # Capture one exact native row, then perturb only its presence in this owned
    # database. Persistent activation/root markers and external admission remain.
    columns=sql("SELECT string_agg(quote_ident(column_name),',' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='public' AND table_name="+quote(table)+';')
    original=sql('SELECT row_to_json(t)::text FROM '+table+" t WHERE namespace='migration' AND storage_key="+quote(root['key'])+';')
    sql('DELETE FROM '+table+" WHERE namespace='migration' AND storage_key="+quote(root['key'])+';');damaged=native_facts();probe('bootstrap-denied','MIG15-'+family+'-root-loss')
    check('MIG15/adapter/'+family+'/established-root-loss-never-bootstraps-or-repairs',native_facts()==damaged)
    sql('INSERT INTO '+table+'('+columns+') SELECT '+columns+' FROM json_populate_record(NULL::'+table+','+quote(original)+'::json);')
   stable=native_facts();previous=witness_box[0];witness_box[0]=None
   try:
    for family in sorted(FORMATS):probe_base['bootstrapFamily']=family;probe('bootstrap-denied','MIG15-'+family+'-unknown-authorization')
   finally:witness_box[0]=previous
   check('MIG15/adapter/unknown-authorization-zero-native-effects',native_facts()==stable)
   # An externally owned pending transition is a real closed witness state; no
   # SQL row or worker time can turn it into clean-bootstrap authorization.
   with rpc_lock:
    current=store.read();pending=copy.deepcopy(current);pending['controlSequence']+=1;pending['mode']='UTC_CLOSED';pending['pendingTransition']={key:commitment('MIG15/'+key) for key in ['transitionId','expectedOldCommitment','targetCommitment']};witness._persist(current,pending)
   for family in sorted(FORMATS):probe_base['bootstrapFamily']=family;probe('bootstrap-denied','MIG15-'+family+'-interrupted-control')
   check('MIG15/adapter/interrupted-control-zero-native-effects',native_facts()==stable)
   with rpc_lock:
    current=store.read();settled=copy.deepcopy(current);settled['controlSequence']+=1;settled['pendingTransition']=None;witness._persist(current,settled);witness.renew(mirrors,witness.elapsed()[1]+100000000,resume=True)
   # No migration plan or authority identity is edited to repair credentials.
   old_authority=cfg['authorityId'];cfg['authorityId']=commitment('MIG15/wrong-authority')
   try:
    for family in sorted(FORMATS):probe_base['bootstrapFamily']=family;probe('bootstrap-denied','MIG15-'+family+'-changed-authority')
   finally:cfg['authorityId']=old_authority
   check('MIG15/adapter/changed-authority-zero-native-effects',native_facts()==stable)
   probe('query','MIG15-explicit-control-settlement-restores-original-services')
   result['bootstrapRecovery']={'missingRoots':sorted(FORMATS),'unknownExternalAuthorization':True,'durablePendingExternalTransition':True,'explicitControlSettlement':True,'changedAuthorityRefuses':True,'credentialsNotRepairedOrReinitialized':True,'clockGenerationPositive':'Source/volatile all-family original-credential controls; full joined C re-admission remains open','qualified':False}
  if args.totp_capacity:
   physical=json.loads(sql("SELECT jsonb_agg(jsonb_build_object('key',storage_key,'actual',sealed_size,'reserved',reserved_size,'sql',length(sealed_form)) ORDER BY storage_key) FROM totp_store_entry WHERE namespace='migration';"))
   planned=closed_audit(cfg);totp={d['source']['key']:d for d in planned if d['source']['family']=='TOTP'}
   check('CAP06/adapter/every-TOTP-row-has-truthful-wire-SQL-and-K64-reservation',len(physical)==len(totp)==17 and all(r['actual']==totp[r['key']]['actualBytes'] and r['reserved']==totp[r['key']]['reservationBytes'] and r['sql']==totp[r['key']]['sqlBytes'] and r['actual']<=r['reserved']<=65536 and r['sql']<=87382 for r in physical))
  if args.webauthn_capacity:
   planned=closed_audit(cfg);wa={d['source']['key']:d for d in planned if d['source']['family']=='WEBAUTHN'}
   physical=json.loads(sql("SELECT jsonb_agg(jsonb_build_object('key',storage_key,'actual',sealed_size,'sql',length(sealed_form)) ORDER BY storage_key) FROM webauthn_store_entry WHERE namespace='migration';"))
   check('CAP07/adapter/every-WAR2-row-has-truthful-frame-and-SQL-metadata',len(physical)==len(wa)==19 and all(r['actual']==wa[r['key']]['actualBytes'] and r['sql']==wa[r['key']]['sqlBytes'] and r['sql']==(4*r['actual']+2)//3 and r['actual']<=262144 and r['sql']<=350000 for r in physical))
   check('CAP07/adapter/selected-recipe-chunks-and-maximum-index',all(int.from_bytes(decode(d['target']['ciphertext'])[6:8],'big')==2029 for d in wa.values()) and max(d['actualBytes'] for d in wa.values())>110000)
  probe('mutate')
  if args.totp_capacity:
   selected={**cfg,'keys':{**cfg['keys'],runtime_key_id:base64.b64encode(bytes(range(32,64))).decode()},'activeKeyId':runtime_key_id}
   before=closed_audit(selected);quota_before=sql("SELECT jsonb_agg(to_jsonb(e) ORDER BY bucket)::text FROM totp_store_escrow e;")
   probe('totp-capacity','CAP06-all-active-TOTP-K64-maintenance');after=closed_audit(selected)
   check('CAP06/adapter/K64-maintenance-preserves-all-authenticated-semantics-floors-retention',[(d['sourceSemanticCommitment'],d['floor'],d['retention']) for d in before]==[(d['sourceSemanticCommitment'],d['floor'],d['retention']) for d in after])
   check('CAP06/adapter/K64-maintenance-consumes-no-extra-reservation-or-escrow',sql("SELECT jsonb_agg(to_jsonb(e) ORDER BY bucket)::text FROM totp_store_escrow e;")==quota_before)
   result['totpCapacity']={'sourceRows':39,'totpRows':17,'newCapacityCorpusRows':8,'activeEpochRows':13,'otherRetainedEpochRows':4,'individualBounds':True,'sqlDoubleEncoding':True,'reservedKeyLength':64,'aggregateRefusalPreservesAllSources':True,'activePublicMaintenancePreservesCompleteSemantics':True,'inactiveEpochMaintenance':'Still fenced; no public bypass','qualified':False}
  if args.webauthn_capacity:
   selected={**cfg,'keys':{**cfg['keys'],runtime_key_id:base64.b64encode(bytes(range(32,64))).decode()},'activeKeyId':runtime_key_id}
   before=closed_audit(selected);quota_before=sql("SELECT jsonb_agg(to_jsonb(e) ORDER BY bucket)::text FROM webauthn_store_escrow e;")
   probe('webauthn-capacity','CAP07-permanent-K64-maintenance-and-ceremony-refusal');after=closed_audit(selected)
   check('CAP07/adapter/K64-maintenance-preserves-all-authenticated-inner-facts-floors-retention',[(d['sourceSemanticCommitment'],d['floor'],d['retention']) for d in before]==[(d['sourceSemanticCommitment'],d['floor'],d['retention']) for d in after])
   check('CAP07/adapter/entry-escrow-stays-exact',sql("SELECT jsonb_agg(to_jsonb(e) ORDER BY bucket)::text FROM webauthn_store_escrow e;")==quota_before)
   result['webauthnCapacity']={'sourceRows':source_count,'webauthnRows':19,'newCapacityCorpusRows':11,'maximumIndexCredentials':64,'maximumCredentialIdBytes':1023,'selectedSealerCapacity':3800,'rawChunkSize':2029,'permanentRowsResealed':12,'ceremonyRowsStillMaintenanceIneligible':7,'sqlCaps':True,'qualified':False}
  if args.capacity_contention:
   selected={**cfg,'keys':{**cfg['keys'],runtime_key_id:base64.b64encode(bytes(range(32,64))).decode()},'activeKeyId':runtime_key_id}
   before=closed_audit(selected);originals={identity(d['source']):d for d in before};namespace_before=[sql("SELECT row_to_json(n)::text FROM "+family.lower()+"_store_namespace n;") for family in sorted(FORMATS)]
   ran=probe('capacity-contention','CAP09-current-adapter-bucket-contention');after=closed_audit(selected)
   check('CAP09/adapter/all-original-retained-facts-floors-retention-survive',all(d['sourceSemanticCommitment']==originals[identity(d['source'])]['sourceSemanticCommitment'] and d['floor']==originals[identity(d['source'])]['floor'] and d['retention']==originals[identity(d['source'])]['retention'] for d in after if identity(d['source']) in originals) and len([d for d in after if identity(d['source']) in originals])==len(originals))
   check('CAP09/adapter/all-new-genuine-account-records-independently-authenticate',len(after)>len(before) and all(d['classification']=='FIT' for d in after))
   check('CAP09/adapter/no-namespace-capacity-metadata-write',namespace_before==[sql("SELECT row_to_json(n)::text FROM "+family.lower()+"_store_namespace n;") for family in sorted(FORMATS)])
   for family in sorted(FORMATS):
    retained=[d for d in after if d['source']['family']==family];used=[0]*256;reserved=[0]*256
    for d in retained:
     b=int(hashlib.sha256(d['source']['key'].encode('ascii')).hexdigest()[:2],16);used[b]+=1;reserved[b]+=d['reservationBytes'] if family=='TOTP' else 0
    actual=json.loads(sql("SELECT jsonb_agg(jsonb_build_object('bucket',bucket,'entries',used_entries,'bytes',used_bytes) ORDER BY bucket) FROM "+family.lower()+'_store_escrow;'))
    check('CAP09/adapter/'+family+'-all-256-counters-match-authenticated-retained-inventory',actual==[{'bucket':i,'entries':used[i],'bytes':reserved[i]} for i in range(256)])
   result['capacityContention']={'sourceRows':source_count,'newOuterChecks':7,'nativeAssertions':sum(line.startswith('PASS CAP09/') for line in ran.stdout.splitlines()),'roundsPerFamily':2,'entryCap':513,'totpByteCap':512003,'allFamilyCollision':True,'totpByteStranding':True,'qualified':False,'scope':'Genuine public engine-generated transactions; explicit native bucket/namespace row holders, exact wait observation and before-release commits. Scripted witness; no latency SLO/full deployment profile.'}
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
  if args.restore_fencing:
   check('MIG10/adapter/after/actual-legacy-rows-and-old-marker-restored',snapshot_facts()==restore_snapshots['main']['facts'])
   check('MIG10/adapter/after/genuine-old-six-column-schema-restored',sql("SELECT string_agg(column_name,',' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='public' AND table_name='webauthn_store_entry';")=='namespace,storage_key,kind,version,sealed_form,expires_at')
   check('MIG10/adapter/after/runtime-intent-cannot-reopen',not installer.runtime_guard(Migration.context(journal.read(),deadline())) and journal.read()['invalidated'])
   for mode in ['direct','pooled']:
    p=execute([str(args.java_home/'bin/java'),'-cp',oldcp,'com.revetsec.webauthn.AdapterLegacyWriter',mode,'migration'],env=writer_env,timeout=15)
    check('MIG10/adapter/after/old-'+mode+'-binary-cannot-login',p.returncode==1 and p.stderr.strip()=='LEGACY_WRITER_FAILED')
   result['restoreFencing']={'stages':['VERIFIED before activation','ACTIVE after actual runtime mutations'],'oldSnapshot':'Before staging and first target write; all31 old rows, six-column old WA schema, sequence and old SQL marker','writerModes':['direct','pooled'],'columnPrivilegeAdmissionPlant':True}
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
  if 'rpc_counts' in locals():result['rpcCounts']=rpc_counts
  result['sourceInputsSha256']=inputs;result['sourceStable']=all((ROOT/name).is_file() and sha(ROOT/name)==digest for name,digest in inputs.items());save()
  print('ADAPTER_JOIN_'+result['status']+' checks='+str(len(result['checks'])))
 return 0 if result['status']=='PASS' and all(result['cleanup'].values()) and result['sourceStable'] else 1
if __name__=='__main__':raise SystemExit(main())
