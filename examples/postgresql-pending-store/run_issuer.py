#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Bounded SCP08 issuer checks on an owned disposable one-primary fixture. No downloads."""
import argparse,base64,hashlib,json,os,re,secrets,socket,subprocess,tempfile,time
from datetime import datetime,timezone
from pathlib import Path
from run import IMAGE,ROOT


def identity(value):return base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()).decode().rstrip('=')

def provision(names,capacity=4096):
 lines=[]
 for namespace in names:
  physical=identity('issuer-physical/'+namespace);allocation=identity('issuer-allocation/'+namespace)
  values=[namespace,physical,identity('issuer-authority/'+namespace),identity('issuer-recovery/'+namespace),identity('issuer-clock/'+namespace)]
  lines.append("INSERT INTO issuer_store_namespace VALUES ("+','.join("'"+s+"'" for s in values)+",0,'"+allocation+"',2,"+str(capacity)+",true);")
  limits=[capacity//256+(i<capacity%256) for i in range(256)]
  lines.append("INSERT INTO issuer_store_escrow VALUES "+','.join("('ISSUER','"+physical+"',"+str(i)+",'"+allocation+"',"+str(limit)+",0,0,0)" for i,limit in enumerate(limits))+";")
 return '\n'.join(lines)+'\n'

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ['java-home','core-jar','pyranid-jar','driver-jar','jspecify-jar','jsr305-jar','output']:p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 receipt={'success':False,'checks':[],'profile':{'familyAllowlist':['ISSUER'],'independentScriptedAuthority':True,'workerTimeChannelSeparate':True,'approvedUtcQualified':False,'witnessOwnerJoined':False,'platformDurabilityQualified':False,'oldWriterQuarantine':False,'deploymentActivation':False,'sameAuthorityCombinedFamilyJoin':False},'postgresImage':IMAGE}
 def save():(a.output/'RESULT.json').write_text(json.dumps(receipt,indent=2)+'\n')
 def check(ok,label):
  if not ok:raise AssertionError(label)
  receipt['checks'].append(label);print('PASS '+label,flush=True);save()
 def docker(*args,input_text=None):
  r=subprocess.run(['docker',*args],input=input_text,capture_output=True,text=True,timeout=60)
  if r.returncode:
   errors=[re.sub(r"'[^']*'","'<redacted>'",line) for line in r.stderr.splitlines() if line.startswith(('ERROR:','FATAL:','psql:'))]
   raise RuntimeError('Owned Docker operation failed: '+' '.join(args[:2])+' '+' | '.join(errors)[-1500:])
  return r.stdout.strip()
 jars=[a.core_jar,a.pyranid_jar,a.driver_jar,a.jspecify_jar,a.jsr305_jar]
 receipt['artifacts']={str(q):hashlib.sha256(q.read_bytes()).hexdigest() for q in jars}
 sources=[ROOT/'src/main/java/example/pending/PostgresqlIssuerStore.java',*(ROOT/('src/main/java/example/pending/IssuerPg'+n+'.java') for n in ['Scope','Locks','Capacity','Transactions']),ROOT/'src/main/java/example/pending/PostgresqlPyranidDataSource.java',ROOT/'src/main/java/example/pending/PostgresqlPendingAuthorizationStore.java',ROOT/'src/test/java/example/pending/PendingStoreProbe.java',ROOT/'src/test/java/example/pending/RsaFixtureSigner.java',ROOT/'src/test/java/example/pending/IssuerFixtureAuthority.java',ROOT/'src/test/java/example/pending/IssuerStoreProbe.java',ROOT/'src/test/java/example/pending/IssuerTemporalStoreProbe.java']
 receipt['sourceInputs']={str(q.relative_to(ROOT.parent.parent)):hashlib.sha256(q.read_bytes()).hexdigest() for q in [*sources,ROOT/'issuer-schema.sql',Path(__file__).resolve(),ROOT/'run.py']}
 receipt['javaHome']=str(a.java_home);receipt['javaVersion']=subprocess.run([str(a.java_home/'bin/java'),'-version'],capture_output=True,text=True,check=True).stderr
 created=[]
 with tempfile.TemporaryDirectory(prefix='revetsec-issuer-scp08-') as t:
  work=Path(t);classes=work/'classes';classes.mkdir();cp=os.pathsep.join([str(classes),*map(str,jars)])
  command=[str(a.java_home/'bin/javac'),'--release','17','-proc:none','-Xlint:all','-Werror','-cp',cp,'-d',str(classes),*map(str,sources)]
  r=subprocess.run(command,capture_output=True,text=True,timeout=90);receipt['compileCommand']=command
  (a.output/'compile.stdout').write_text(r.stdout);(a.output/'compile.stderr').write_text(r.stderr)
  if r.returncode:raise RuntimeError('Issuer strict compile failed: '+r.stderr[-6000:])
  check(True,'strict-issuer-source-closure-compile')
  audit_source=ROOT.parent.parent/'verification/examples/NullabilityAudit.java';auditclasses=work/'audit';auditclasses.mkdir()
  subprocess.run([str(a.java_home/'bin/javac'),'--release','17','-proc:none','-Xlint:all','-Werror','-cp',cp,'-d',str(auditclasses),str(audit_source)],capture_output=True,text=True,check=True,timeout=60)
  listing=work/'sources.txt';listing.write_text('\n'.join(map(str,sources))+'\n');cpf=work/'classpath.txt';cpf.write_text(cp+'\n');auditfile=work/'audit.json'
  auditcmd=[str(a.java_home/'bin/java'),'-cp',os.pathsep.join([str(auditclasses),cp]),'NullabilityAudit',str(listing),str(cpf),str(auditfile),'17']
  audited=subprocess.run(auditcmd,capture_output=True,text=True,timeout=90);receipt['nullability']=json.loads(auditfile.read_text());receipt['auditCommand']=auditcmd;(a.output/'nullability.json').write_bytes(auditfile.read_bytes());save()
  (a.output/'audit.stdout').write_text(audited.stdout);(a.output/'audit.stderr').write_text(audited.stderr)
  receipt['sourceInputs'][str(audit_source.relative_to(ROOT.parent.parent))]=hashlib.sha256(audit_source.read_bytes()).hexdigest()
  check(audited.returncode==0,'source-nullability-audit')
  name='revetsec-issuer-'+secrets.token_hex(5);volume=name+'-data';password=secrets.token_urlsafe(24);rolepassword=secrets.token_urlsafe(24)
  with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
  envfile=work/'postgres.env';envfile.write_text('POSTGRES_PASSWORD='+password+'\nPOSTGRES_DB=issuer_fixture\n');envfile.chmod(0o600)
  try:
   docker('volume','create','--label','com.revetsec.owned-fixture=true',volume);created.append('volume')
   docker('run','-d','--pull=never','--name',name,'--label','com.revetsec.owned-fixture=true','-p','127.0.0.1:'+str(port)+':5432','--env-file',str(envfile),'--mount','type=volume,source='+volume+',target=/var/lib/postgresql',IMAGE);created.append('container')
   for _ in range(80):
    ready=subprocess.run(['docker','exec',name,'pg_isready','-h','127.0.0.1','-U','postgres','-d','issuer_fixture'],capture_output=True,timeout=5)
    if ready.returncode==0:break
    time.sleep(.25)
   else:raise RuntimeError('Owned primary readiness expired')
   def sql(query):return docker('exec','-i',name,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','issuer_fixture',input_text=query)
   namespaces=['fixture_issuer','fixture_issuer_unknown','fixture_issuer_fence','fixture_issuer_temporal','fixture_issuer_capacity','fixture_issuer_final']
   sql((ROOT/'issuer-schema.sql').read_text()+provision(namespaces))
   sql("CREATE ROLE issuer_runtime LOGIN PASSWORD '"+rolepassword+"'; GRANT CONNECT ON DATABASE issuer_fixture TO issuer_runtime; GRANT USAGE ON SCHEMA public TO issuer_runtime; GRANT SELECT ON issuer_store_namespace,issuer_store_root TO issuer_runtime; GRANT INSERT ON issuer_store_root TO issuer_runtime; GRANT SELECT,INSERT,DELETE ON issuer_store_entry TO issuer_runtime; GRANT UPDATE(version,retain_seconds,retain_nanos,sealed_form) ON issuer_store_entry TO issuer_runtime; GRANT SELECT ON issuer_store_escrow TO issuer_runtime; GRANT UPDATE(used_entries,used_bytes) ON issuer_store_escrow TO issuer_runtime; ALTER TABLE issuer_store_entry ENABLE ROW LEVEL SECURITY; CREATE POLICY issuer_select ON issuer_store_entry FOR SELECT TO issuer_runtime USING(true); CREATE POLICY issuer_insert ON issuer_store_entry FOR INSERT TO issuer_runtime WITH CHECK(true); CREATE POLICY issuer_update ON issuer_store_entry FOR UPDATE TO issuer_runtime USING(true) WITH CHECK(true); CREATE POLICY issuer_delete ON issuer_store_entry FOR DELETE TO issuer_runtime USING(kind NOT IN ('ISSUER_STATE','SUBJECT_STATE'));")
   check(sql("SELECT rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls FROM pg_roles WHERE rolname='issuer_runtime';")=='f|f|f|f|f','runtime-role-no-privileged-flags')
   check(sql("SELECT NOT has_table_privilege('issuer_runtime','issuer_store_entry','TRUNCATE') AND NOT has_table_privilege('issuer_runtime','issuer_store_root','DELETE') AND NOT has_table_privilege('issuer_runtime','issuer_store_namespace','UPDATE');")=='t','runtime-role-cannot-change-admission-or-delete-root-registry')
   check(sql("SELECT NOT has_column_privilege('issuer_runtime','issuer_store_entry','kind','UPDATE') AND NOT has_column_privilege('issuer_runtime','issuer_store_escrow','entry_limit','UPDATE') AND NOT has_column_privilege('issuer_runtime','issuer_store_escrow','allocation_generation','UPDATE');")=='t','runtime-role-cannot-relabel-permanent-kind-or-reallocate-capacity')
   secretsdir=work/'secrets';secretsdir.mkdir(mode=0o700)
   env=dict(os.environ,REVETSEC_TEST_DB_URL='jdbc:postgresql://127.0.0.1:'+str(port)+'/issuer_fixture?sslmode=disable&gssEncMode=disable',REVETSEC_TEST_DB_USER='issuer_runtime',REVETSEC_TEST_DB_PASSWORD=rolepassword,REVETSEC_TEST_ISSUER_TIME='1791288000',REVETSEC_TEST_ISSUER_AUTHORITY_NOW='2026-10-06T12:00:00Z',REVETSEC_TEST_ISSUER_SECRET_DIR=str(secretsdir))
   base=[str(a.java_home/'bin/java'),'-cp',cp]
   def run(mode,*args,overrides=None):
    r=subprocess.run([*base,'example.pending.IssuerStoreProbe',mode,*args],env=dict(env,**(overrides or {})),capture_output=True,text=True,timeout=45)
    if r.returncode:raise RuntimeError('Issuer probe '+mode+' failed: '+r.stderr[-3500:])
    return r.stdout.strip()
   def state():return hashlib.sha256(sql("SELECT namespace,storage_key,kind,version,retain_seconds,retain_nanos,sealed_form FROM issuer_store_entry ORDER BY namespace,storage_key; SELECT namespace,bucket,used_entries,used_bytes FROM issuer_store_escrow ORDER BY namespace,bucket;").encode()).hexdigest()
   check(run('keygen')=='KEYS_READY','ephemeral-owned-keys-ready')
   digest=identity('https://issuer.example');rootkey='revetsec:as:1:'+digest+':ISSUER_STATE:'+digest
   bucket=hashlib.sha256(rootkey.encode()).digest()[0]
   sql("UPDATE issuer_store_escrow SET entry_limit=CASE WHEN bucket="+str(bucket)+" THEN 1 ELSE 0 END WHERE namespace='"+identity('issuer-physical/fixture_issuer_capacity')+"';")
   check(run('capacity-root')=='CAPACITY_REFUSED','assigned-entry-escrow-refuses-without-eviction')
   check(sql("SELECT count(*) FROM issuer_store_entry WHERE namespace='fixture_issuer_capacity';")=='1','capacity-refusal-retains-permanent-root-only')

   check(run('known-final-refusal')=='KNOWN_COMMITTED_NO_OUTPUT','known-public-transition-final-read-refusal-reconciles')
   check(sql("SELECT count(*) FROM issuer_store_entry WHERE namespace='fixture_issuer_final' AND kind='INTERACTION';")=='1','final-read-refusal-preserves-committed-interaction')
   check(run('init')=='INITIALIZED','genuine-root-subject-initialization')
   root=sql("SELECT version FROM issuer_store_entry WHERE namespace='fixture_issuer' AND kind='ISSUER_STATE';")
   code=run('issue');check(bool(re.fullmatch('[A-Za-z0-9_-]+',code)),'genuine-interaction-and-code-commit')
   pair=run('redeem-pair',code);check(pair.startswith('PAIR:'),'genuine-code-redemption-credentials')
   access,refresh=pair[5:].split('\t');check(run('active',access)=='ACTIVE','genuine-authoritative-token-status')
   check(sql("SELECT version FROM issuer_store_entry WHERE namespace='fixture_issuer' AND kind='ISSUER_STATE';")==root,'normal-work-does-not-rewrite-stable-root')
   before=state();check(run('active',access)=='ACTIVE' and state()==before,'status-barrier-and-final-read-zero-data-quota-writes')
   before=state();fast=dict(REVETSEC_TEST_ISSUER_TIME='1791289000');check(run('active-refused',access,overrides=fast)=='STORE_UNAVAILABLE','fast-worker-cannot-advance-authority-floors')
   check(state()==before,'worker-health-refusal-zero-writes')
   rotated=run('refresh',refresh);check(rotated.startswith('PAIR:'),'genuine-refresh-rotation')
   nextaccess,nextrefresh=rotated[5:].split('\t')
   check(run('refresh',refresh)=='REJECTED','refresh-replay-rejects')
   check(run('active',nextaccess).startswith('INACTIVE'),'refresh-replay-invalidates-complete-family')
   check(run('reseal-root')=='RAW_RESEALED','raw-permanent-reseal-contextual-timed-receipt')
   check(run('unknown-reseal-root')=='RAW_UNKNOWN','applied-unknown-raw-reseal-preserves-fact')
   stored=sql("SELECT storage_key,retain_seconds,version FROM issuer_store_entry WHERE namespace='fixture_issuer' AND kind='CODE' ORDER BY storage_key LIMIT 1;").split('|')
   retained_key,retained_until,oldversion=stored;retained_until=int(retained_until);after_credential=min(1791288000+86400,retained_until-1)
   check(after_credential>1791288000+600,'used-code-retention-outlives-original-credential')
   overrides=dict(REVETSEC_TEST_ISSUER_AUTHORITY_NOW=datetime.fromtimestamp(after_credential,timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),REVETSEC_TEST_ISSUER_TIME=str(after_credential))
   check(run('reseal-entry',retained_key,overrides=overrides)=='COMMITTED','retained-credential-expired-code-reseal-before-full-retention')
   check(sql("SELECT retain_seconds::text||'|'||version FROM issuer_store_entry WHERE namespace='fixture_issuer' AND storage_key='"+retained_key+"';").split('|')[0]==str(retained_until),'finite-reseal-preserves-original-full-retention')
   before=state();overrides=dict(REVETSEC_TEST_ISSUER_AUTHORITY_NOW=datetime.fromtimestamp(retained_until,timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),REVETSEC_TEST_ISSUER_TIME=str(retained_until))
   check(run('reseal-entry',retained_key,overrides=overrides)=='CONFLICT' and state()==before,'finite-reseal-retention-equality-refuses-zero-effect')

   check(run('unknown-init')=='UNKNOWN','raw-init-applied-unknown-no-safe-retry')
   check(run('reconcile-unknown')=='CONFLICT','unknown-init-authoritative-reconciliation-only')
   check(run('fence-init')=='INITIALIZED','separate-fence-scope-initialized')
   no_utc=dict(REVETSEC_TEST_ISSUER_AUTHORITY_MODE='unavailable')
   check(run('subject-revoke',overrides=no_utc)=='SUBJECT_REVOKED','existing-subject-fence-no-utc-acknowledgement')
   check(run('revoke',overrides=no_utc)=='REVOKED','existing-issuer-fence-no-utc-acknowledgement')
   before=state();check(run('active-refused',access,overrides=no_utc)=='STORE_UNAVAILABLE','ordinary-credential-use-does-not-enter-no-utc-mode');check(state()==before,'utc-outage-query-no-hidden-mutation')
   r=subprocess.run([*base,'example.pending.IssuerTemporalStoreProbe'],env=env,capture_output=True,text=True,timeout=60)
   (a.output/'temporal.stdout').write_text(r.stdout);(a.output/'temporal.stderr').write_text(r.stderr)
   if r.returncode:raise RuntimeError('Temporal native probe failed: '+r.stderr[-3500:])
   for line in r.stdout.splitlines():
    if line.startswith('PASS '):check(True,line[5:])
   sql("DELETE FROM issuer_store_entry WHERE namespace='fixture_issuer' AND kind='ISSUER_STATE';")
   before=state();r=subprocess.run([*base,'example.pending.IssuerStoreProbe','init'],env=env,capture_output=True,text=True,timeout=30)
   check(r.returncode!=0 and state()==before,'missing-established-root-cannot-reinitialize')
   receipt['runtimeRole']={'superuser':False,'bypassRls':False,'entryDelete':'EPHEMERAL_ONLY','deleteRootRegistry':False,'changeAdmission':False,'changeKind':False,'changeEntryQuota':False,'changeAllocationGeneration':False}
   receipt['success']=True
  finally:
   if 'container' in created:docker('rm','-f',name);receipt['ownedContainerRemoved']=True
   if 'volume' in created:docker('volume','rm',volume);receipt['ownedVolumeRemoved']=True
   save()
if __name__=='__main__':main()
