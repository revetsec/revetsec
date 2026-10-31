#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Owned offline PostgreSQL migration/restore component rehearsal; not live qualification."""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
sys.path.insert(0,str(HERE.parent/'shared-clock-postgresql'))
from fault_proxy import CommitLossProxy
from codec import CodecClient, synthetic_config, root_rows
from migration import allocate_quotas, ProtectedJournal as Journal, Migration, MigrationClosed, DirectoryOwner, identity, commitment, FORMATS
from postgres_backend import NativePgBackend, TABLES, decode, encode, quote, kind, reservation

IMAGE='sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a'
OLD=ROOT/'planning/records/security/shared-clock-scp01-2026-10-29'
CORE=ROOT/'planning/records/security/shared-clock-scp09-2026-10-30/candidate/core/revetsec-1.0.0-SNAPSHOT.jar'
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def execute(command,*,data=None,env=None,timeout=60):return subprocess.run(command,input=data,capture_output=True,text=True,env=env,timeout=timeout)
def cid(label):return commitment(label)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--java-home',type=Path,required=True);args=parser.parse_args()
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    result={'status':'RUNNING','checks':[],'image':IMAGE,'java_home':str(args.java_home),'coreJarSha256':sha(CORE),'oldCoreJarSha256':sha(OLD/'baseline/built-core/revetsec-1.0.0-SNAPSHOT.jar'),'qualification':{'approvedUtcQualified':False,'witnessOwnerDeploymentQualified':False,'platformDurabilityQualified':False,'actualDeploymentMigration':False,'qualifiedSharedProfile':False},'ownedContainerRemoved':False,'ownedVolumeRemoved':False,'ownedNetworkRemoved':False,'protectedRuntimeRemoved':False}
    def save():(out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
    def check(name,condition):
        result['checks'].append({'id':name,'passed':bool(condition)});save()
        if not condition:raise AssertionError(name)
    inspected=execute(['docker','image','inspect',IMAGE,'--format','{{.Id}}']);check('exact-cached-image-no-pull',inspected.returncode==0 and inspected.stdout.strip()==IMAGE)
    inputs={str(p.relative_to(ROOT)):sha(p) for p in HERE.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
    for name in inputs:
        copy_path=out/'SOURCE'/name;copy_path.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,copy_path)
    resource='revetsec-scp10-'+secrets.token_hex(6);volume=resource+'-data';network=resource+'-bridge';password=secrets.token_urlsafe(32);created=[];processes=[];proxies=[];owners=[]
    runtime=Path(tempfile.mkdtemp(prefix='revetsec-scp10-native-',dir=Path(tempfile.gettempdir()).resolve()));os.chmod(runtime,0o700)
    bound=socket.socket();bound.bind(('127.0.0.1',0));port=bound.getsockname()[1]
    result['ownedResources']={'container':resource,'volume':volume,'network':network,'loopbackPort':port}
    def docker(*parts,data=None,timeout=60):
        p=execute(['docker',*parts],data=data,timeout=timeout)
        if p.returncode:
            if parts[0] in ['run','network','volume']:result['dockerFailure']={'operation':parts[0],'fixedDiagnostic':p.stderr.replace(password,'<redacted>')[:1000]};save()
            raise RuntimeError('Owned Docker operation failed: '+parts[0])
        return p.stdout.strip()
    def sql(text):return docker('exec','-i',resource,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','migration_fixture',data=text)
    fault=[None];transaction_observations=[]
    def transaction(statements,deadline):
        if time.monotonic_ns()>=deadline:return 'NO_EFFECT'
        proxy=None;selected=fault[0];fault[0]=None
        if selected:proxy=CommitLossProxy(port,selected);proxies.append(proxy)
        environment=dict(os.environ,DB_URL=f'jdbc:postgresql://127.0.0.1:{proxy.local_port if proxy else port}/migration_fixture',DB_USER='postgres',DB_PASSWORD=password)
        data=''.join(base64.b64encode(s.encode()).decode()+'\n' for s in statements)
        p=execute([str(args.java_home/'bin/java'),'-cp',native_cp,'verification.migration.PgBatch'],data=data,env=environment,timeout=max(1,min(20,(deadline-time.monotonic_ns())/1e9)))
        if proxy:proxy.close()
        answer=p.stdout.strip() if p.returncode==0 and not p.stderr else 'UNKNOWN'
        transaction_observations.append({'status':answer,'statements':len(statements),'loss':selected,'drops':proxy.drops if proxy else 0,'committedReady':proxy.committed_ready if proxy else 0,'proxyErrors':proxy.errors if proxy else []})
        if answer not in ['COMMITTED','NO_EFFECT','UNKNOWN']:raise RuntimeError('Invalid fixed native outcome')
        return answer
    try:
        manifest=json.loads((OLD/'ARTIFACT-PRESERVATION.json').read_text())
        wanted=['com.pyranid:pyranid:4.7.0','org.postgresql:postgresql:42.7.14','org.jspecify:jspecify:1.0.1','com.google.code.findbugs:jsr305:3.0.2','com.google.errorprone:error_prone_annotations:2.50.0']
        dependencies=[]
        for name in wanted:
            row=next(x for x in manifest['artifacts'] if x.get('coordinate')==name);p=ROOT/row['frozen_path'];check('pinned-'+name,sha(p)==row['sha256']);dependencies.append(p)
        classes=runtime/'native-classes';classes.mkdir();oldclasses=runtime/'old-classes';oldclasses.mkdir()
        oldjar=OLD/'baseline/built-core/revetsec-1.0.0-SNAPSHOT.jar';frozen=OLD/'baseline/source/revetsec/examples/postgresql-pending-store/src/main/java/example/pending'
        oldsources=[frozen/'PostgresqlWebAuthnStore.java',frozen/'PostgresqlPyranidDataSource.java',HERE/'native/com/revetsec/webauthn/LegacyWriter.java']
        for label,sources,classpath,dest in [('native',[HERE/'native/verification/migration/PgBatch.java'],os.pathsep.join(map(str,dependencies)),classes),('old',oldsources,os.pathsep.join(map(str,[oldjar,*dependencies])),oldclasses)]:
            p=execute([str(args.java_home/'bin/javac'),'--release','17','-proc:none','-Xlint:all','-Werror','-cp',classpath,'-d',str(dest),*map(str,sources)])
            (out/(label+'-compile.log')).write_text(p.stdout+p.stderr);check(label+'-strict-compile',p.returncode==0)
        native_cp=os.pathsep.join(map(str,[classes,*dependencies]));oldcp=os.pathsep.join(map(str,[oldclasses,oldjar,*dependencies]))
        client=CodecClient(runtime/'codec',args.java_home,CORE,oldjar);config=synthetic_config();source_rows=sorted(client.fixtures(config),key=identity);check('frozen-old-all-family-fixtures',len(source_rows)==31 and {r['family'] for r in source_rows}==set(FORMATS))
        scopes={f:config[k] for f,k in [('TOTP','totpScope'),('WEBAUTHN','webauthnScope'),('ISSUER','issuerScope')]};namespaces={f:'migration' for f in FORMATS};required_roots=[(r['family'],r['key']) for r in root_rows(source_rows)]
        envfile=runtime/'postgres.env';envfile.write_text('POSTGRES_PASSWORD='+password+'\nPOSTGRES_DB=migration_fixture\n');envfile.chmod(0o600)
        docker('network','create','--label','com.revetsec.scp10=true',network);created.append('network')
        docker('volume','create','--label','com.revetsec.scp10=true',volume);created.append('volume')
        bound.close();created.append('container')
        docker('run','-d','--pull=never','--name',resource,'--network',network,'--label','com.revetsec.scp10=true','--publish',f'127.0.0.1:{port}:5432','--env-file',str(envfile),'--mount',f'type=volume,source={volume},target=/var/lib/postgresql',IMAGE)
        for _ in range(150):
            ready=execute(['docker','exec',resource,'psql','-X','-qAt','-U','postgres','-d','migration_fixture','-c','SELECT 1'],timeout=3)
            final_server=execute(['docker','exec',resource,'cat','/proc/1/comm'],timeout=3)
            if ready.returncode==0 and ready.stdout.strip()=='1' and final_server.stdout.strip()=='postgres':break
            time.sleep(.1)
        else:raise RuntimeError('Owned primary unavailable')
        check('primary-fsync-fullpage',sql("SELECT NOT pg_is_in_recovery() AND current_setting('fsync')='on' AND current_setting('full_page_writes')='on';")=='t')
        old_role='scp10_old_'+secrets.token_hex(4);role_password=secrets.token_urlsafe(32)
        sql('CREATE ROLE '+old_role+' LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '+quote(role_password)+';')
        def seed(rows=None):
            rows=source_rows if rows is None else rows
            sql('DROP SCHEMA public CASCADE;CREATE SCHEMA public;'+(HERE/'migration-schema.sql').read_text())
            sql("INSERT INTO totp_store_namespace VALUES('migration','old-one','ACTIVATED');INSERT INTO totp_store_epoch VALUES('migration','old-one'),('migration','old-two');INSERT INTO webauthn_store_namespace VALUES('migration'),('legacy_direct'),('legacy_pooled');INSERT INTO issuer_store_namespace VALUES('migration');")
            statements=[]
            for row in rows:
                family=row['family'];table=TABLES[family];version=str(int.from_bytes(decode(row['version']),'big')) if family=='WEBAUTHN' else quote(row['version']);form=quote(decode(row['ciphertext']).decode('ascii')) if family=='ISSUER' else quote(row['ciphertext']);common=[quote('migration'),quote(row['key']),quote(kind(row)),version,form]
                if family=='TOTP':
                    epoch=decode(row['key'].split(':')[2]).decode('ascii');statements.append('INSERT INTO '+table+'(namespace,storage_key,kind,version,sealed_form,recovery_epoch,sealed_size,reserved_size) VALUES('+','.join([*common,quote(epoch),str(len(decode(row['ciphertext']))),str(reservation(row))])+')')
                elif family=='WEBAUTHN':
                    finite=kind(row)=='CEREMONY';ret=row['retention'];statements.append('INSERT INTO '+table+'(namespace,storage_key,kind,version,sealed_form,sealed_size,expires_seconds,expires_nanos,expires_at) VALUES('+','.join([*common,str(len(decode(row['ciphertext']))),str(ret['epochSecond']) if finite else 'NULL',str(ret['nano']) if finite else 'NULL',"to_timestamp("+str(ret['epochSecond'])+")" if finite else 'NULL'])+')')
                else:statements.append('INSERT INTO '+table+'(namespace,storage_key,kind,version,sealed_form,retain_seconds,retain_nanos) VALUES('+','.join([*common,str(row['retention']['epochSecond']),str(row['retention']['nano'])])+')')
            sql(';'.join(statements)+';')
        seed()
        sql('GRANT USAGE ON SCHEMA public TO '+old_role+';GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO '+old_role+';GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO '+old_role+';')
        writer_env=dict(os.environ,DB_URL=f'jdbc:postgresql://127.0.0.1:{port}/migration_fixture?sslmode=disable&gssEncMode=disable',DB_USER=old_role,DB_PASSWORD=role_password,SEAL_KEY=base64.b64encode(bytes(range(1,33))).decode(),OLD_CORE_JAR=str(oldjar))
        for mode in ['direct','pooled']:
            p=subprocess.Popen([str(args.java_home/'bin/java'),'-cp',oldcp,'com.revetsec.webauthn.LegacyWriter',mode,'legacy_'+mode],env=writer_env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);processes.append(p)
            check('genuine-old-'+mode+'-session-ready',p.stdout.readline().strip()=='READY '+mode)
        check('two-actual-old-sql-sessions-held',sql('SELECT count(*) FROM pg_stat_activity WHERE usename='+quote(old_role)+';')=='2')
        sql('ALTER ROLE '+old_role+' NOLOGIN PASSWORD NULL;REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM '+old_role+';REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM '+old_role+';REVOKE ALL PRIVILEGES ON SCHEMA public FROM '+old_role+';SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='+quote(old_role)+';')
        check('old-role-sessions-actually-terminated',sql('SELECT count(*) FROM pg_stat_activity WHERE usename='+quote(old_role)+';')=='0')
        for mode,p in zip(['direct','pooled'],processes):
            stdout,stderr=p.communicate('CONTINUE\n',timeout=15);check('old-engine-'+mode+'-refused-with-no-login',p.returncode==0 and not stderr and len([s for s in stdout.splitlines() if s.startswith('PASS ')])==2)
        def deadline():return time.monotonic_ns()+60_000_000_000
        def case(name,*,prepare=True,fixture_rows=None):
            fixture_rows=source_rows if fixture_rows is None else fixture_rows
            seed(fixture_rows);cfg={**config,'migrationId':cid(name+'/migration'),'recoveryGeneration':cid(name+'/target')}
            intent={'migrationId':cfg['migrationId'],'sourceRecoveryGeneration':cid(name+'/old'),'targetAdmission':{'authorityId':cfg['authorityId'],'recoveryGeneration':cfg['recoveryGeneration']},'writerFence':cid(name+'/fence'),'targetFormats':dict(FORMATS),'authorityWitness':cid(name+'/scripted-witness')}
            sql('INSERT INTO scp10_control(migration_id,writer_fence,source_recovery,target_authority,target_recovery,mode) VALUES('+','.join(map(quote,[intent['migrationId'],intent['writerFence'],intent['sourceRecoveryGeneration'],cfg['authorityId'],cfg['recoveryGeneration'],'CLOSED']))+');')
            directory=runtime/name;directory.mkdir(mode=0o700);owner=DirectoryOwner(directory);owners.append(owner);journal=Journal(owner);backend=NativePgBackend(sql,transaction,scopes,[old_role],namespaces=namespaces,required_roots=required_roots,journal=journal);machine=Migration(journal,backend)
            backend.confirmed_new_intent=True
            machine.close(intent,deadline());backend.confirmed_new_intent=False;machine.inventory(deadline());rows=journal.get_blob(journal.read()['inventoryBlob']);check(name+'/complete-native-inventory',rows==sorted(fixture_rows,key=identity))
            decisions=sorted(client.prepare(cfg,rows),key=lambda d:identity(d['source']));caps=[{'family':f,'scope':scopes[f],'entryCap':65536 if f=='TOTP' else 1000000,'hardEntryCap':65536 if f=='TOTP' else 1000000,'byteCap':268435456 if f=='TOTP' else None,'hardByteCap':268435456 if f=='TOTP' else None} for f in sorted(FORMATS)]
            if prepare:
                prepared=machine.prepare(decisions,caps,deadline());plan=journal.get_blob(prepared['quotaBlob']);check(name+'/closed-native-256-quota-assignment',backend.install_quotas(Migration.context(prepared,deadline()),plan)=='COMMITTED')
            return cfg,journal,backend,machine,decisions
        def rewrite(machine,journal):
            while journal.read()['cursor']<journal.read()['inventoryCount']:machine.rewrite_next(deadline())
        def verified(cfg,journal,backend,machine):
            actual=backend._all();decisions=sorted(client.verify(cfg,actual),key=lambda d:identity(d['source']));machine.verify(decisions,deadline());return decisions
        def evidence(journal):
            state=journal.read();return {k:state[k] for k in ['authorityWitness','writerFence','targetAdmission','activationCommitment']}
        cfg,journal,backend,machine,decisions=case('main')
        archive='/tmp/scp10-old-auth.dump';docker('exec',resource,'pg_dump','-Fc','-U','postgres','-d','migration_fixture','-f',archive,*[part for table in [*TABLES.values(),'totp_store_epoch','totp_store_namespace','webauthn_store_namespace','issuer_store_namespace','scp10_control','scp10_quota_plan',*[t.replace('_entry','_escrow') for t in TABLES.values()]] for part in ['-t','public.'+table]])
        source_commitment=commitment(backend._all());rewrite(machine,journal);verifications=verified(cfg,journal,backend,machine);check('main/current-core-independently-opens-all-targets',len(verifications)==len(source_rows) and all(d['classification']=='FIT' for d in verifications))
        check('main/fresh-backend-can-reverify-without-counter-reinstall',NativePgBackend(sql,transaction,scopes,[old_role],namespaces=namespaces,required_roots=required_roots,journal=journal).verify(Migration.context(journal.read(),deadline()),backend._all(),commitment(journal.get_blob(journal.read()['quotaBlob']))))
        before=copy.deepcopy(journal.read());machine.activate(evidence(journal),deadline());check('main/structural-active-timed-still-closed',journal.read()['phase']=='ACTIVE' and journal.read()['timedAdmission']=='CLOSED')
        fresh=cid('restore/fresh');machine.restore_closed(fresh,cid('restore/authentic-dump'),deadline())
        # Only the protected external journal/witness stay outside; SQL control and namespace/epoch markers are restored.
        docker('exec',resource,'pg_restore','--clean','--if-exists','--single-transaction','--exit-on-error','-U','postgres','-d','migration_fixture',archive)
        check('restore/authentic-old-auth-exactly-restored',commitment(backend._all())==source_commitment)
        check('restore/external-intent-remains-invalidated',journal.read()['invalidated'] and journal.read()['phase']=='ACTIVE' and journal.read()['timedAdmission']=='CLOSED')
        check('restore/stale-native-context-refused',not backend.assert_closed(Migration.context(before,deadline())))
        try:machine.inventory(deadline());refused=False
        except MigrationClosed as e:refused=e.label=='RECOVERY_REQUIRED'
        check('restore/old-journal-operation-cannot-reopen',refused)
        journal.owner.close()
        probe_code = """import base64,json,os,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,os.environ['MIGRATION_SOURCE'])
from migration import ProtectedJournal,Migration,DirectoryOwner
from postgres_backend import NativePgBackend
owner=DirectoryOwner(Path(os.environ['MIGRATION_STATE']))
journal=ProtectedJournal(owner);state=journal.read();deadline=time.monotonic_ns()+30000000000

def sql(text):
 p=subprocess.run(['docker','exec','-i',os.environ['MIGRATION_CONTAINER'],'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','migration_fixture'],input=text,capture_output=True,text=True,timeout=10)
 if p.returncode:raise RuntimeError('Owned native read failed')
 return p.stdout.strip()
def transaction(statements,deadline):
 data=''.join(base64.b64encode(x.encode()).decode()+'\\n' for x in statements)
 p=subprocess.run([os.environ['MIGRATION_JAVA'],'-cp',os.environ['MIGRATION_CP'],'verification.migration.PgBatch'],input=data,capture_output=True,text=True,timeout=15)
 return p.stdout.strip() if p.returncode==0 else 'UNKNOWN'
backend=NativePgBackend(sql,transaction,json.loads(os.environ['MIGRATION_SCOPES']),[os.environ['MIGRATION_OLD_ROLE']],namespaces=json.loads(os.environ['MIGRATION_NAMESPACES']),required_roots=json.loads(os.environ['MIGRATION_ROOTS']),journal=journal)
decisions=journal.get_blob(state['decisionsBlob'])[:8]
batch={'batchId':state['migrationId'],'predicates':[d['source'] for d in decisions],'replacements':[d['target'] for d in decisions],'deletions':[]}
assert state['invalidated']
assert backend.apply(Migration.context(state,deadline),batch)=='NO_EFFECT'
print('PASS fresh-process-external-restore-fence')
owner.close()
"""
        probe_path=out/'restore-new-process.py';probe_path.write_text(probe_code)
        environment=dict(os.environ,MIGRATION_SOURCE=str(HERE),MIGRATION_STATE=str(runtime/'main'),MIGRATION_CONTAINER=resource,MIGRATION_JAVA=str(args.java_home/'bin/java'),MIGRATION_CP=native_cp,MIGRATION_SCOPES=json.dumps(scopes),MIGRATION_NAMESPACES=json.dumps(namespaces),MIGRATION_ROOTS=json.dumps(required_roots),MIGRATION_OLD_ROLE=old_role,DB_USER='postgres',DB_PASSWORD=password,DB_URL=f'jdbc:postgresql://127.0.0.1:{port}/migration_fixture')
        p=execute([sys.executable,str(probe_path)],env=environment,timeout=30)
        (out/'restore-new-process.stdout').write_text(p.stdout);(out/'restore-new-process.stderr').write_text(p.stderr)
        check('restore/fresh-process-restored-old-mirror-cannot-mutate',p.returncode==0 and p.stdout.strip()=='PASS fresh-process-external-restore-fence' and commitment(backend._all())==source_commitment)
        p=execute([str(args.java_home/'bin/java'),'-cp',oldcp,'com.revetsec.webauthn.LegacyWriter','direct','legacy_direct'],env=writer_env,timeout=20)
        check('restore/fresh-old-binary-jvm-still-cannot-login',p.returncode==1 and p.stderr.strip()=='LEGACY_WRITER_FAILED' and sql('SELECT NOT rolcanlogin FROM pg_roles WHERE rolname='+quote(old_role)+';')=='t' and commitment(backend._all())==source_commitment)
        for loss in ['before','after']:
            cfg,journal,backend,machine,decisions=case('unknown-'+loss);fault[0]=loss
            try:machine.rewrite_next(deadline());unknown=False
            except MigrationClosed as e:unknown=e.label=='UNKNOWN'
            check('unknown-'+loss+'/actual-commit-loss-pending',unknown and journal.read()['progress']['status']=='PENDING')
            batch=journal.get_blob(journal.read()['progress']['batchBlob']);observed=backend.read_batch(Migration.context(journal.read(),deadline()),batch)
            check('unknown-'+loss+'/complete-eight-row-settled',observed['settled'] and len(observed['rows'])==8)
            machine.settle(deadline());check('unknown-'+loss+'/whole-batch-factual-settlement',journal.read()['cursor']==(0 if loss=='before' else 8))
            rewrite(machine,journal);verified(cfg,journal,backend,machine);check('unknown-'+loss+'/no-blind-or-random-rewrite',journal.read()['phase']=='VERIFIED')
        for loss in ['before','after']:
            cfg,journal,backend,machine,_=case('activation-'+loss);rewrite(machine,journal);verified(cfg,journal,backend,machine);fault[0]=loss
            try:machine.activate(evidence(journal),deadline());unknown=False
            except MigrationClosed as e:unknown=e.label=='UNKNOWN'
            check('activation-'+loss+'/actual-loss-remains-pending',unknown and journal.read()['progress']['kind']=='ACTIVATION')
            fresh_backend=NativePgBackend(sql,transaction,scopes,[old_role],namespaces=namespaces,required_roots=required_roots,journal=journal);fresh_machine=Migration(journal,fresh_backend);fresh_machine.settle_activation(deadline())
            check('activation-'+loss+'/fresh-process-equivalent-definitive-settlement',journal.read()['phase']==('ACTIVE' if loss=='after' else 'VERIFIED'))
        cfg,journal,backend,machine,_=case('activation-tamper');rewrite(machine,journal);verified(cfg,journal,backend,machine);one=backend._all()[0];sql('UPDATE '+TABLES[one['family']]+' SET version='+quote(cid('tampered-version'))+' WHERE '+backend._where(one)+';')
        check('activation/current-full-data-rechecked-under-lock',backend.activate(Migration.context(journal.read(),deadline()),journal.read()['activationCommitment'])=='NO_EFFECT')
        check('activation/tamper-did-not-open-native-gate',sql('SELECT mode FROM scp10_control;')=='CLOSED')
        for mode in ['mixed','third-state','unresolved']:
            cfg,journal,backend,machine,_=case('settle-'+mode);fault[0]='after' if mode=='mixed' else 'before'
            try:machine.rewrite_next(deadline())
            except MigrationClosed:pass
            batch=journal.get_blob(journal.read()['progress']['batchBlob'])
            if mode=='mixed':
                old=batch['predicates'][0];sql('UPDATE '+TABLES[old['family']]+' SET version='+backend._version(old)+',sealed_form='+backend._form(old)+' WHERE '+backend._where(old)+';')
            elif mode=='third-state':
                old=batch['predicates'][0];sql('UPDATE '+TABLES[old['family']]+' SET version='+quote(cid('third-state-version'))+' WHERE '+backend._where(old)+';')
            else:
                sleeping=subprocess.Popen(['docker','exec','-i',resource,'psql','-X','-qAt','-U','postgres','-d','migration_fixture'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);processes.append(sleeping);sleeping.stdin.write("SET application_name='scp10-batch';BEGIN;SELECT pg_sleep(30);\n");sleeping.stdin.flush()
                for _ in range(100):
                    if sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='scp10-batch' AND xact_start IS NOT NULL;")=='1':break
                    time.sleep(.01)
            try:machine.settle(deadline());refused=None
            except MigrationClosed as e:refused=e.label
            check('settle-'+mode+'/no-single-row-or-plaintext-shortcut',refused=={'mixed':'MIXED','third-state':'THIRD_STATE','unresolved':'UNRESOLVED'}[mode] and journal.read()['progress']['status']=='PENDING')
            if mode=='unresolved':
                sql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='scp10-batch';");sleeping.stdin.close();sleeping.stdin=None;sleeping.communicate(timeout=5)
        for mode in ['all-old-epoch-lost','native-epoch-mismatch','configured-issuer-root-lost']:
            cfg,journal,backend,machine,_=case('inventory-'+mode,prepare=False)
            if mode=='all-old-epoch-lost':sql("DELETE FROM totp_store_entry WHERE namespace='migration' AND recovery_epoch='old-two';")
            elif mode=='native-epoch-mismatch':sql("UPDATE totp_store_entry SET recovery_epoch='old-two' WHERE namespace='migration' AND recovery_epoch='old-one';")
            else:sql("DELETE FROM issuer_store_entry WHERE namespace='migration';")
            try:backend.inventory(Migration.context(journal.read(),deadline()),None,16);refused=False
            except (MigrationClosed,ValueError):refused=True
            check('inventory-'+mode+'/complete-permanent-registry-refusal',refused and journal.read()['phase']=='INVENTORIED')
        cfg,journal,backend,machine,_=case('wa-projection-tamper');rewrite(machine,journal);verified(cfg,journal,backend,machine)
        sql("UPDATE webauthn_store_entry SET expires_nanos=(expires_nanos+1)%1000000000 WHERE namespace='migration' AND kind='CEREMONY';")
        check('activation/exact-wa-expiry-projection-rechecked',backend.activate(Migration.context(journal.read(),deadline()),journal.read()['activationCommitment'])=='NO_EFFECT')
        for mode in ['epoch-registry','physical-kind']:
            cfg,journal,backend,machine,_=case('activation-'+mode);rewrite(machine,journal);verified(cfg,journal,backend,machine)
            if mode=='epoch-registry':sql("INSERT INTO totp_store_epoch VALUES('migration','unlisted-retained-epoch');")
            else:sql("UPDATE issuer_store_entry SET kind='CODE' WHERE namespace='migration' AND kind='SUBJECT_STATE';")
            check('activation-'+mode+'/protected-metadata-tamper-refuses',backend.activate(Migration.context(journal.read(),deadline()),journal.read()['activationCommitment'])=='NO_EFFECT')
        for mode in ['BLOCKED_DEPENDENCY','UNSUPPORTED','CORRUPT']:
            selected=copy.deepcopy(source_rows)
            if mode=='CORRUPT':
                row=next(r for r in selected if r['family']=='ISSUER' and kind(r)=='CODE');raw=bytearray(decode(row['ciphertext']));raw[-1]=ord('A') if raw[-1]!=ord('A') else ord('B');row['ciphertext']=encode(bytes(raw))
            cfg,journal,backend,machine,decisions=case('label-'+mode,prepare=False,fixture_rows=selected)
            if mode=='BLOCKED_DEPENDENCY':
                missing={**cfg,'activeKeyId':'new','keys':{'new':base64.b64encode(bytes(range(33,65))).decode()}};decisions=sorted(client.prepare(missing,backend._all()),key=lambda d:identity(d['source']))
            caps=[{'family':f,'scope':scopes[f],'entryCap':0 if mode=='UNSUPPORTED' and f=='TOTP' else 65536 if f=='TOTP' else 1000000,'hardEntryCap':65536 if f=='TOTP' else 1000000,'byteCap':268435456 if f=='TOTP' else None,'hardByteCap':268435456 if f=='TOTP' else None} for f in sorted(FORMATS)];before=commitment(backend._all())
            try:machine.prepare(decisions,caps,deadline());refused=None
            except MigrationClosed as e:refused=e.label
            check('label-'+mode+'/exact-disposition-before-data-write',refused==mode and journal.read()['phase']=='INVENTORIED' and commitment(backend._all())==before)
        cfg,journal,backend,machine,_=case('query-only-continuity');rewrite(machine,journal);verified(cfg,journal,backend,machine)
        from witness import Witness, WitnessUnavailable
        from witness_storage import ManifestStore
        from test_witness import manifest, ScriptedClock
        targets=backend._all();finite=next(r for r in targets if r['family']=='WEBAUTHN' and kind(r)=='CEREMONY');expiry=finite['retention']['epochSecond']*1000000000+finite['retention']['nano'];unchanged=commitment(targets)
        query_archive='/tmp/scp10-query-only-auth.dump'
        docker('exec',resource,'pg_dump','-Fc','-U','postgres','-d','migration_fixture','-f',query_archive,*[part for table in [*TABLES.values(),'totp_store_epoch','totp_store_namespace','webauthn_store_namespace','issuer_store_namespace','scp10_control','scp10_quota_plan',*[t.replace('_entry','_escrow') for t in TABLES.values()]] for part in ['-t','public.'+table]])
        directory=runtime/'witness-query';directory.mkdir(mode=0o700);owner=DirectoryOwner(directory);owners.append(owner);store=ManifestStore(owner);clock=ScriptedClock();clock.base=expiry-28*1000000000
        initial=manifest('UTC_CLOSED');initial.update(authorityId=cfg['authorityId'],recoveryGeneration=cfg['recoveryGeneration']);initial['admissionScopes']=[{'family':f,'namespace':scopes[f]} for f in sorted(FORMATS)];initial['activeDatabaseAdmission']=[dict(x,metadataCommitment=cid(['query-metadata',x]),schemaCommitment=cid(['query-schema',x]),writerRoleIdentity=cid('query-retired-writer')) for x in initial['admissionScopes']]
        store.provision_genesis(initial,confirmed_never_used=True);g1=Witness(owner,store,clock.elapsed,clock.capture,owner_incarnation=initial['ownerIncarnation'],previous_clock_generation=None,continuity=lambda:clock.continuous);g1.start(initial['activeDatabaseAdmission'],clock.ns+100000000)
        def expected(value):return {**{k:copy.deepcopy(value[k]) for k in ['authorityId','recoveryGeneration','clockGeneration','profile']},'scope':next(copy.deepcopy(x) for x in value['activeDatabaseAdmission'] if x['family']=='WEBAUTHN')}
        g1_value=store.read();clock.ns=29*1000000000;point=g1.sample(expected(g1_value),clock.ns+100000000)
        check('query-only/g1-expiry-observed-with-zero-entity-write',point.authority_ns>expiry and commitment(backend._all())==unchanged)
        old=store.read();upper=copy.deepcopy(old['reservationUpper']);closed=copy.deepcopy(old)
        closed.update(controlSequence=old['controlSequence']+1,mode='UTC_CLOSED',pendingTransition={'transitionId':cid('query-transition'),'expectedOldCommitment':cid('query-old-commitment'),'targetCommitment':cid('query-target-commitment')});store.compare_and_set(old,closed)
        changing=copy.deepcopy(closed);changing.update(controlSequence=closed['controlSequence']+1,ownerIncarnation=cid('query-g2-owner'),clockGeneration=cid('query-g2-clock'));store.compare_and_set(closed,changing)
        prepared=copy.deepcopy(changing);prepared.update(controlSequence=changing['controlSequence']+1,pendingTransition=None);store.compare_and_set(changing,prepared);owner.close()
        docker('exec',resource,'pg_restore','--clean','--if-exists','--single-transaction','--exit-on-error','-U','postgres','-d','migration_fixture',query_archive)
        owner2=DirectoryOwner(directory);owners.append(owner2);store2=ManifestStore(owner2);check('query-only/authentic-restore-keeps-newer-external-reservation',commitment(backend._all())==unchanged and store2.read()['reservationUpper']==upper and store2.read()['clockGeneration']==prepared['clockGeneration'])
        try:g1.sample(expected(g1_value),clock.ns+100000000);refused=False
        except WitnessUnavailable:refused=True
        check('query-only/prior-owner-cannot-serve-after-restore',refused)
        g2=Witness(owner2,store2,clock.elapsed,clock.capture,owner_incarnation=prepared['ownerIncarnation'],previous_clock_generation=old['clockGeneration'],continuity=lambda:clock.continuous);clock.ns=30*1000000000
        try:g2.start(prepared['activeDatabaseAdmission'],clock.ns+100000000);refused=False
        except WitnessUnavailable:refused=True
        check('query-only/g2-center-at-old-u-still-refuses-lower-endpoint',refused)
        clock.ns+=clock.uncertainty;g2.start(prepared['activeDatabaseAdmission'],clock.ns+100000000);point=g2.sample(expected(store2.read()),clock.ns+100000000)
        check('query-only/g2-catchup-cannot-revive-expired-entity',point.authority_ns>expiry and commitment(backend._all())==unchanged and store2.read()['authorityId']==old['authorityId'] and store2.read()['recoveryGeneration']==old['recoveryGeneration'])
        oversized=sorted(client.fixtures({**config,'oversizedInteraction':True}),key=identity)
        for mode in ['unhealthy','equality-unknown']:
            cfg,journal,backend,machine,decisions=case('retention-'+mode,prepare=False,fixture_rows=oversized)
            waiting=[d for d in decisions if d['classification']=='WAIT_RETENTION']
            check('retention-'+mode+'/authenticated-oversize-classified',len(waiting)==1 and all(d['classification']=='FIT' for d in decisions if d not in waiting))
            initial=[]
            for d in decisions:
                value=copy.deepcopy(d);value.update(classification='FIT',reservationBytes=reservation(d['source']) if d['source']['family']=='TOTP' else len(decode(d['source']['ciphertext'])));initial.append(value)
            caps=[{'family':f,'scope':scopes[f],'entryCap':65536 if f=='TOTP' else 1000000,'hardEntryCap':65536 if f=='TOTP' else 1000000,'byteCap':268435456 if f=='TOTP' else None,'hardByteCap':268435456 if f=='TOTP' else None} for f in sorted(FORMATS)]
            check('retention-'+mode+'/truthful-preexisting-native-quota-usage',backend.install_quotas(Migration.context(journal.read(),deadline()),allocate_quotas(initial,caps))=='COMMITTED')
            from witness import Witness, WitnessUnavailable
            from witness_storage import ManifestStore
            from test_witness import manifest, ScriptedClock
            directory=runtime/('witness-'+mode);directory.mkdir(mode=0o700);owner=DirectoryOwner(directory);owners.append(owner);store=ManifestStore(owner);clock=ScriptedClock();retention=waiting[0]['retention'];clock.base=retention['epochSecond']*1000000000+retention['nano']-1
            initial_manifest=manifest('MIGRATING');initial_manifest.update(migrationIntent=cfg['migrationId'],authorityId=cfg['authorityId'],recoveryGeneration=cfg['recoveryGeneration'])
            initial_manifest['admissionScopes']=[{'family':f,'namespace':scopes[f]} for f in sorted(FORMATS)]
            initial_manifest['activeDatabaseAdmission']=[dict(x,metadataCommitment=cid(['metadata',x]),schemaCommitment=cid(['schema',x]),writerRoleIdentity=cid('retired-writer')) for x in initial_manifest['admissionScopes']]
            store.provision_genesis(initial_manifest,confirmed_never_used=True);witness=Witness(owner,store,clock.elapsed,clock.capture,owner_incarnation=initial_manifest['ownerIncarnation'],previous_clock_generation=None,continuity=lambda:clock.continuous)
            witness.start(initial_manifest['activeDatabaseAdmission'],clock.ns+100000000,administrative=True);admission=store.read()['activeDatabaseAdmission'];before=commitment(backend._all())
            if mode=='unhealthy':
                clock.boot='different-boot'
                try:machine.cleanup_waiting(waiting,witness,admission,deadline());refused=False
                except WitnessUnavailable:refused=True
                check('retention/unhealthy-component-time-cannot-delete',refused and commitment(backend._all())==before)
                continue
            permanent=copy.deepcopy(waiting[0]);permanent['permanent']=True
            try:machine.cleanup_waiting([permanent],witness,admission,deadline());refused=False
            except MigrationClosed as e:refused=e.label=='CLOSED'
            check('retention/permanent-state-not-reclaimed',refused and commitment(backend._all())==before)
            try:machine.cleanup_waiting(waiting,witness,admission,deadline());refused=False
            except MigrationClosed as e:refused=e.label=='WAIT_RETENTION'
            check('retention/one-nanosecond-before-full-retention-refuses',refused and commitment(backend._all())==before)
            clock.ns=1;fault[0]='after'
            try:machine.cleanup_waiting(waiting,witness,admission,deadline());unknown=False
            except MigrationClosed as e:unknown=e.label=='UNKNOWN'
            check('retention/equality-real-unknown-delete-keeps-intent',unknown and journal.read()['progress']['status']=='PENDING' and not journal.read()['reinventoryRequired'])
            machine.settle(deadline());check('retention/whole-delete-settlement-requires-reinventory',journal.read()['reinventoryRequired'] and journal.read()['inventoryCommitment'] is None)
            machine.inventory(deadline());rows=journal.get_blob(journal.read()['inventoryBlob']);decisions=sorted(client.prepare(cfg,rows),key=lambda d:identity(d['source']));prepared=machine.prepare(decisions,caps,deadline());check('retention/independent-full-fit-and-quota-recomputed',len(rows)==31 and all(d['classification']=='FIT' for d in decisions) and backend.install_quotas(Migration.context(prepared,deadline()),journal.get_blob(prepared['quotaBlob']))=='COMMITTED')
        result['sourceInputsUnchanged']=all(sha(ROOT/name)==digest for name,digest in inputs.items())
        check('current-selected-runtime-input-bytes-unchanged',result['sourceInputsUnchanged'])
        result['status']='PASS';result['codecProvenance']=client.provenance;result['codecCommands']=client.commands;result['nativeTransactions']=transaction_observations;result['oldWriterSourceInputs']={str(p.relative_to(ROOT)):sha(p) for p in oldsources};result['sourceInputs']=inputs;result['retainedMigrationRows']=len(source_rows);result['nativeScopeProfile']={'maximumRows':128,'maximumSqlSealedBytes':6291456,'pageRows':32,'batchMutations':8,'batchPredicates':16};result['limits']=['Scripted authority component only; actual approved UTC/witness/backend/profile prerequisites remain open.','Actual family entry storage and transformed bytes verified against exact current core. Full selected current-adapter schema/probe activation remains separate.','No production, retained customer data or unowned database was addressed.']
    except Exception as failure:
        result['status']='FAIL';result['failureType']=type(failure).__name__;result['failureMessage']=str(failure) if isinstance(failure,AssertionError) else 'Owned rehearsal failed; private diagnostics retained'
        raise
    finally:
        bound.close()
        for p in processes:
            if p.poll() is None:p.kill();p.communicate(timeout=5)
        for proxy in proxies:
            try:proxy.close()
            except Exception:result['proxyCleanupFailure']=True
        for owner in owners:owner.close()
        for name,parts in [('container',['rm','-f',resource]),('volume',['volume','rm',volume]),('network',['network','rm',network])]:
            if name in created:
                p=execute(['docker',*parts]);absent=execute(['docker','inspect',resource] if name=='container' else ['docker',name,'inspect',volume if name=='volume' else network]);result['owned'+name.title()+('Removed')]=p.returncode==0 or absent.returncode!=0
        for label in ['current','legacy']:
            log=runtime/'codec'/(label+'-compile.log')
            if log.exists():shutil.copy2(log,out/('codec-'+label+'-compile.log'))
        if 'client' in locals():result['codecCommands']=client.commands
        shutil.rmtree(runtime);result['protectedRuntimeRemoved']=not runtime.exists();save()
    return 0 if result['status']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
