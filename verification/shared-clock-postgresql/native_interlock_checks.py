# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Owned native interlock scenarios, with scripted UTC explicitly unqualified.

The parent owns the one fresh PostgreSQL cluster, loopback transport and source
binding. This module owns only its uniquely named databases/roles/processes and
short-lived witness directories. No raw rows, SQL or credentials enter evidence.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import subprocess
import tempfile
import time

from fault_proxy import CommitLossProxy
from postgres_interlock import Controller, NativeAdapter, InterlockClosed, ROW_FIELDS, commitment, role_identity
from witness import Witness, WitnessUnavailable
from witness_capture import CheckedCapture
from witness_storage import DirectoryOwner, ManifestStore, PROFILE

HERE=Path(__file__).resolve().parent
SECOND=1_000_000_000
BASE=1_800_000_000*SECOND


def _identity(text):
    return base64.urlsafe_b64encode(hashlib.sha256(text.encode()).digest()).decode().rstrip('=')


def _quoted(value):
    # Only fixture-generated identifiers/IDs and token_urlsafe passwords reach
    # this bound SQL literal helper; the SQL text is never logged or retained.
    return "'"+value.replace("'","''")+"'"


def _row_lines(rows):
    return '\n'.join('\t'.join(str(row[name]) for name in ROW_FIELDS) for row in rows)


def _manifest_and_rows(tag,old_role,new_role):
    scopes=[{'family':family,'namespace':_identity(tag+'/'+family)} for family in ('ISSUER','TOTP','WEBAUTHN')]
    old={'format':1,'controlSequence':0,'mode':'UTC_CLOSED','ownerIncarnation':_identity(tag+'/old-owner'),
         'authorityId':_identity(tag+'/authority'),'recoveryGeneration':_identity(tag+'/recovery'),
         'clockGeneration':_identity(tag+'/old-clock'),'profile':dict(PROFILE),
         'reservationUpper':{'epochSecond':1_800_000_020,'nano':99},
         'brokerBootIdentity':'scripted-boot','admissionScopes':scopes,
         'activeDatabaseAdmission':[dict(scope,metadataCommitment=_identity(tag+'/'+scope['family']+'/old-metadata'),
              schemaCommitment=_identity(tag+'/'+scope['family']+'/schema'),writerRoleIdentity=role_identity(old_role)) for scope in scopes],
         'pendingTransition':None,'utcCaptureEvidence':_identity(tag+'/old-capture'),'migrationIntent':None}
    target=copy.deepcopy(old)
    target.update(ownerIncarnation=_identity(tag+'/new-owner'),clockGeneration=_identity(tag+'/new-clock'))
    for mirror in target['activeDatabaseAdmission']:
        mirror['metadataCommitment']=_identity(tag+'/'+mirror['family']+'/new-metadata')
        mirror['writerRoleIdentity']=_identity(new_role)
    def rows(manifest):
        return [dict(mirror,**{name:manifest[name] for name in ('authorityId','recoveryGeneration','clockGeneration')},
                     profileCommitment=commitment(manifest['profile']),allocationGeneration=_identity(tag+'/'+mirror['family']+'/allocation'),
                     formatVersion=3 if mirror['family']=='TOTP' else 2,mode='ACTIVE') for mirror in manifest['activeDatabaseAdmission']]
    return old,target,rows(old),rows(target)


def _seed(sql,database,rows):
    columns='family,namespace,authority_id,recovery_generation,clock_generation,profile_commitment,schema_commitment,metadata_commitment,writer_role_identity,allocation_generation,format_version,mode'
    values=[]
    for row in rows:
        values.append('('+','.join(str(row[name]) if name=='formatVersion' else _quoted(row[name]) for name in ROW_FIELDS)+')')
    sql(database,'INSERT INTO scp05_admission('+columns+') VALUES '+','.join(values)+';')


def _actual_rows(sql,database):
    columns='family,namespace,authority_id,recovery_generation,clock_generation,profile_commitment,schema_commitment,metadata_commitment,writer_role_identity,allocation_generation,format_version,mode'
    return sql(database,"SELECT concat_ws(E'\\t',"+columns+") FROM scp05_admission ORDER BY family,namespace;")


def _ready(process):
    end=time.monotonic()+10
    while time.monotonic()<end:
        if process.poll() is not None:raise AssertionError('native old writer failed before rendezvous')
        readable,_,_=select.select([process.stdout],[],[],min(.1,end-time.monotonic()))
        if readable:
            value=process.stdout.readline()
            if value=='READY stale-writer\n':return value
            raise AssertionError('native old writer rendezvous differed')
    raise AssertionError('native old writer rendezvous timed out')


class _SplitAdapter:
    """Fence on the direct route; inject only the actual metadata COMMIT route."""
    def __init__(self,direct,transition):
        self.direct=direct;self.target=transition
        self.fence_calls=0;self.transition_calls=0;self.verify_calls=0
    def fence(self,roles,deadline):
        self.fence_calls+=1
        return self.direct.fence(roles,deadline)
    def transition(self,old,target,roles,deadline):
        self.transition_calls+=1
        return self.target.transition(old,target,roles,deadline)
    def verify(self,target,roles,deadline):
        self.verify_calls+=1
        return self.direct.verify(target,roles,deadline)


def exercise(lane,classes,classpath,number,sql,environment,run_java,check,out):
    """Run four independent fixture cases in an already-owned fresh cluster."""
    for name in ('success','before','after','mismatch'):
        tag='j'+str(number)+'_'+name
        database='scp05_interlock_'+tag
        old_role='scp05_old_'+tag;new_role='scp05_new_'+tag
        old_password=secrets.token_urlsafe(32);new_password=secrets.token_urlsafe(32)
        folder=out/lane.parent.parent.name/('interlock-'+name);folder.mkdir(parents=True,exist_ok=True)
        prefix=lane.parent.parent.name+'/interlock-'+name
        record={'case':name,'passed':False,'scripted_utc':True,'actual_utc_qualified':False,
                'old_engine_binary_claim':False,'target':'owned fresh per-case database only',
                'old_actor':'native uncooperative JDBC session, not an engine transaction',
                'application_route_processes_started':0,'application_request_programs_started':0,
                'activation':'none until explicit scripted witness checks in success case',
                'private_state_removed':False,'database_removed':False,'roles_removed':False}
        created_database=False;created_roles=[];process=None;proxy=None;temporary=None;owner=None
        admin_env=old_env=new_env=None
        try:
            sql('scp05_admin','CREATE DATABASE '+database+';');created_database=True
            sql(database,(HERE/'schema.sql').read_text())
            sql(database,'CREATE TABLE scp05_legacy_probe(id integer PRIMARY KEY);')
            for role,password in ((old_role,old_password),(new_role,new_password)):
                sql('scp05_admin','CREATE ROLE '+role+' LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '+_quoted(password)+';')
                created_roles.append(role)
                sql(database,'GRANT USAGE ON SCHEMA public TO '+role+'; GRANT SELECT,INSERT,UPDATE,DELETE ON scp05_entries,scp05_escrow,scp05_admission,scp05_legacy_probe TO '+role+';')
            old,target,old_rows,target_rows=_manifest_and_rows(tag,old_role,new_role)
            _seed(sql,database,old_rows)
            expected_old=_row_lines(old_rows);expected_target=_row_lines(target_rows)
            check(prefix+'/three-exact-old-mirrors-seeded',_actual_rows(sql,database)==expected_old)
            admin_env=environment(database)
            old_env=environment(database,user=old_role,secret=old_password)
            new_env=environment(database,user=new_role,secret=new_password)
            cp=str(classes)+os.pathsep+classpath
            direct=NativeAdapter(lane/'bin/java',cp,admin_env)
            if name in ('before','after'):
                # DB_URL contains no credential; only the owned target port is
                # extracted so the protocol fault proxy can reach that primary.
                port=int(admin_env['DB_URL'].split('://127.0.0.1:',1)[1].split('/',1)[0])
                proxy=CommitLossProxy(port,name)
                through_proxy=NativeAdapter(lane/'bin/java',cp,environment(database,proxy_port=proxy.local_port))
            else:through_proxy=direct
            adapter=_SplitAdapter(direct,through_proxy)
            temporary=tempfile.TemporaryDirectory(prefix='revetsec-scp05-interlock-',dir=Path(tempfile.gettempdir()).resolve())
            owner=DirectoryOwner(temporary.name);store=ManifestStore(owner)
            store.provision_genesis(old,confirmed_never_used=True)
            if name=='success':
                command=[str(lane/'bin/java'),'-ea','-cp',cp,'verification.sharedclock.PgLegacyWriterChecks','hold']
                process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                         text=True,bufsize=1,env=old_env)
                ready=_ready(process)
                check(prefix+'/already-open-native-writer-has-uncommitted-write',sql(database,"SELECT count(*) FROM pg_stat_activity WHERE usename="+_quoted(old_role)+" AND state='idle in transaction';")=='1')
            if name=='mismatch':
                sql(database,"UPDATE scp05_admission SET metadata_commitment="+_quoted(_identity(tag+'/third-state'))+" WHERE family='TOTP';")
            route_callbacks=[]
            def stop_routes(deadline):
                # This fixture started no application server or application
                # request program. Its one intentionally uncooperative native
                # session is the SQL fence target, not a claimed route drain.
                value=store.read()
                facts=(record['application_route_processes_started']==0 and record['application_request_programs_started']==0)
                route_callbacks.append(facts)
                check(prefix+'/external-pending-before-fixture-boundary-check',facts and value['mode']=='UTC_CLOSED' and value['pendingTransition'] is not None)
                return facts
            controller=Controller(owner,store,adapter,stop_routes)
            completion=None;prepared=None
            try:
                prepared=controller.prepare(old,target,old_rows,target_rows,[old_role],_identity(tag+'/transition'),time.monotonic_ns()+25*SECOND)
            except InterlockClosed as refusal:
                completion=refusal.sql_completion
                if name=='success':raise AssertionError('native successful interlock did not prepare closed target') from None
            actual=_actual_rows(sql,database)
            current=store.read()
            check(prefix+'/one-fence-and-one-transition-no-retry',adapter.fence_calls==1 and adapter.transition_calls==1)
            check(prefix+'/old-role-no-login-no-memberships',sql(database,"SELECT NOT rolcanlogin AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid OR roleid=r.oid) FROM pg_roles r WHERE rolname="+_quoted(old_role)+';')=='t')
            check(prefix+'/old-role-no-auth-table-or-probe-privileges',sql(database,"SELECT NOT (has_table_privilege("+_quoted(old_role)+",'public.scp05_entries','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_table_privilege("+_quoted(old_role)+",'public.scp05_escrow','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_table_privilege("+_quoted(old_role)+",'public.scp05_admission','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_table_privilege("+_quoted(old_role)+",'public.scp05_legacy_probe','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'));")=='t')
            check(prefix+'/old-session-absent-before-control-completes',sql(database,'SELECT count(*) FROM pg_stat_activity WHERE usename='+_quoted(old_role)+';')=='0')
            if name=='success':
                check(prefix+'/all-three-target-mirrors-known-committed',actual==expected_target and adapter.verify_calls==1)
                check(prefix+'/external-target-prepared-closed',prepared==current and current['mode']=='UTC_CLOSED' and current['pendingTransition'] is None and current['clockGeneration']==target['clockGeneration'])
                check(prefix+'/old-held-transaction-aborted',sql(database,'SELECT count(*) FROM scp05_legacy_probe WHERE id=1;')=='0')
                remainder,stderr=process.communicate('CONTINUE\n',timeout=10)
                labels=[line[5:] for line in remainder.splitlines() if line.startswith('PASS ')]
                check(prefix+'/legacy-writer-process-finished',process.returncode==0 and not stderr and len(labels)==2 and set(labels)=={'stale-native-session-cannot-commit','stale-native-credential-cannot-login'})
                for label in labels:check(prefix+'/'+label,True)
                (folder/'legacy.stdout.log').write_text(ready+remainder);(folder/'legacy.stderr.log').write_text(stderr)
                class ScriptedClock:
                    def __init__(self):self.center=BASE;self.elapsed_ns=0
                    def elapsed(self):return 'scripted-boot',self.elapsed_ns
                    def capture(self,deadline):return CheckedCapture(self.center,self.elapsed_ns,50_000_000,'scripted-boot',_identity(tag+'/scripted-capture'))
                clock=ScriptedClock()
                witness=Witness(owner,store,clock.elapsed,clock.capture,owner_incarnation=current['ownerIncarnation'],
                                previous_clock_generation=old['clockGeneration'],continuity=lambda:True)
                expected={**{field:copy.deepcopy(current[field]) for field in ('authorityId','recoveryGeneration','clockGeneration','profile')},'scope':copy.deepcopy(current['activeDatabaseAdmission'][0])}
                refused=False
                try:witness.sample(expected,100_000_000)
                except WitnessUnavailable:refused=True
                check(prefix+'/new-witness-refuses-before-explicit-activation',refused)
                refused=False
                try:witness.start(current['activeDatabaseAdmission'],100_000_000)
                except WitnessUnavailable:refused=True
                check(prefix+'/prepared-sql-does-not-bypass-durable-upper-catchup',refused and store.read()['mode']=='UTC_CLOSED')
                clock.center=current['reservationUpper']['epochSecond']*SECOND+current['reservationUpper']['nano']+50_000_000
                witness.start(current['activeDatabaseAdmission'],100_000_000)
                point=witness.sample(expected,100_000_000)
                check(prefix+'/scripted-checked-catchup-then-observation',point.clock_generation==target['clockGeneration'] and point.recovery_generation==old['recoveryGeneration'] and point.authority_ns==clock.center and store.read()['mode']=='ACTIVE')
                run_java(lane,classes,classpath,'PgLegacyWriterChecks',new_env,'new')
                check(prefix+'/new-role-write-ground-truth',sql(database,'SELECT array_agg(id ORDER BY id)::text FROM scp05_legacy_probe;')=='{2}')
                record.update(sql_completion='COMMITTED',sql_ground_truth='ALL_TARGET',external='PREPARED_CLOSED_THEN_SCRIPTED_ACTIVE',stale_native_assertions=labels,scripted_catchup_verified=True)
            elif name in ('before','after'):
                wanted=expected_old if name=='before' else expected_target
                check(prefix+'/lost-ack-is-unknown-not-no-effect',completion=='UNKNOWN' and prepared is None and adapter.verify_calls==0)
                check(prefix+'/lost-ack-complete-ground-truth',actual==wanted)
                check(prefix+'/lost-ack-pending-closed-with-old-external-tuple',current['mode']=='UTC_CLOSED' and current['pendingTransition'] is not None and current['clockGeneration']==old['clockGeneration'])
                check(prefix+'/lost-ack-one-writing-commit',proxy.drops==1 and proxy.committed_ready==(1 if name=='after' else 0) and not proxy.errors)
                record.update(sql_completion=completion,sql_ground_truth='ALL_OLD' if name=='before' else 'ALL_TARGET',external='OLD_TUPLE_PENDING_CLOSED',proxy_drops=proxy.drops,proxy_confirmed_commit=proxy.committed_ready)
            else:
                check(prefix+'/third-state-refuses-exact-transaction',completion=='NO_EFFECT' and prepared is None and adapter.verify_calls==0)
                check(prefix+'/third-state-does-not-advance-any-generation',sql(database,'SELECT count(*) FROM scp05_admission WHERE clock_generation='+_quoted(old['clockGeneration'])+';')=='3')
                check(prefix+'/third-state-stays-pending-closed',current['mode']=='UTC_CLOSED' and current['pendingTransition'] is not None and current['clockGeneration']==old['clockGeneration'])
                record.update(sql_completion=completion,sql_ground_truth='EXPLICIT_THIRD_METADATA_STATE_NO_TARGET_WRITES',external='OLD_TUPLE_PENDING_CLOSED')
            check(prefix+'/fixture-boundary-callback-once',route_callbacks==[True])
            record.update(passed=True,scope_count=3,fence_calls=adapter.fence_calls,transition_calls=adapter.transition_calls,verify_calls=adapter.verify_calls)
        finally:
            if process is not None and process.poll() is None:
                process.kill();process.communicate(timeout=5)
            if proxy is not None:proxy.close()
            if owner is not None:owner.close()
            if temporary is not None:
                private=Path(temporary.name);temporary.cleanup();record['private_state_removed']=not private.exists()
            if created_database:
                sql('scp05_admin','DROP DATABASE '+database+' WITH (FORCE);');record['database_removed']=True
            for role in reversed(created_roles):sql('scp05_admin','DROP ROLE '+role+';')
            record['roles_removed']=len(created_roles)==2
            if admin_env is not None:admin_env.clear()
            if old_env is not None:old_env.clear()
            if new_env is not None:new_env.clear()
            (folder/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n')
        check(prefix+'/private-state-database-and-roles-removed',record['private_state_removed'] and record['database_removed'] and record['roles_removed'])
