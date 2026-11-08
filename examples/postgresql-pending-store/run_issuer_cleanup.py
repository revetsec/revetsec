#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
"""Explicit trusted-metadata ordinary issuer GC on disposable PostgreSQL only; no downloads."""
from pathlib import Path
import argparse,hashlib,json,os,re,secrets,socket,subprocess,tempfile,time
from run_issuer import provision
from run import IMAGE,ROOT

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--java-home',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--baseline-store',type=Path);p.add_argument('--baseline-store-sha256');p.add_argument('--legacy-issuer-fixture',type=Path);p.add_argument('--legacy-issuer-fixture-sha256');p.add_argument('--baseline-only',action='store_true');p.add_argument('--compile-only',action='store_true');p.add_argument('--genuine-offset-nanos',type=int,choices=[0,1],default=0)
 for name in ['core','pyranid','driver','jspecify','jsr305','errorprone']:p.add_argument('--'+name+'-jar',type=Path,required=True);p.add_argument('--'+name+'-sha256',required=True)
 a=p.parse_args();jars=[getattr(a,n+'_jar').resolve()for n in ['core','pyranid','driver','jspecify','jsr305','errorprone']]
 try:
  if not a.output.is_absolute()or a.output.exists():raise ValueError('New absolute output required')
  for name,path in zip(['core','pyranid','driver','jspecify','jsr305','errorprone'],jars):
   if not path.is_file()or path.stat().st_size>16_777_216 or digest(path)!=getattr(a,name+'_sha256'):raise ValueError('Selected artifact mismatch')
  if a.baseline_store and(not a.baseline_only or digest(a.baseline_store)!=a.baseline_store_sha256):raise ValueError('Explicit exact baseline store required')
  if a.baseline_only and not a.baseline_store:raise ValueError('Baseline requires preserved old store')
  if a.legacy_issuer_fixture and(not a.baseline_only or a.legacy_issuer_fixture.name!='IssuerStoreProbe.java' or a.legacy_issuer_fixture.stat().st_size>1_048_576 or digest(a.legacy_issuer_fixture)!=a.legacy_issuer_fixture_sha256):raise ValueError('Explicit bounded legacy fixture is baseline-only')
  if a.legacy_issuer_fixture_sha256 and not a.legacy_issuer_fixture:raise ValueError('Legacy fixture path required')
  if not(a.java_home/'bin/java').is_file()or not(a.java_home/'bin/javac').is_file():raise ValueError('Selected JDK missing')
 except(OSError,ValueError)as failure:p.error(str(failure))
 a.output.mkdir(parents=True);classes=a.output/'classes';classes.mkdir();sources=[a.baseline_store if a.baseline_store else ROOT/'src/main/java/example/pending/PostgresqlIssuerStore.java',*(ROOT/('src/main/java/example/pending/IssuerPg'+n+'.java')for n in ['Scope','Locks','Capacity','Transactions']),*(ROOT/('src/main/java/example/pending/'+n+'.java')for n in ['PostgresqlPyranidDataSource','PostgresqlPendingAuthorizationStore']),*((a.legacy_issuer_fixture if a.legacy_issuer_fixture and n=='IssuerStoreProbe' else ROOT/('src/test/java/example/pending/'+n+'.java'))for n in ['PendingStoreProbe','RsaFixtureSigner','IssuerFixtureAuthority','IssuerStoreProbe','IssuerRetentionBaselineProbe'])]
 if not a.baseline_only:sources.append(ROOT/'src/test/java/example/pending/IssuerRetentionCleanupProbe.java')
 watched=[*sources,ROOT/'issuer-schema.sql',ROOT/'run.py',ROOT/'run_issuer.py',Path(__file__).resolve()];before={str(f):digest(f)for f in watched};cp=os.pathsep.join(map(str,[classes,*jars]));receipt={'success':False,'baselineOnly':a.baseline_only,'genuineOffsetNanos':a.genuine_offset_nanos,'compileOnly':a.compile_only,'legacyFixtureSelected':str(a.legacy_issuer_fixture)if a.legacy_issuer_fixture else None,'checks':[],'postgresImage':IMAGE,'artifacts':{str(f):digest(f)for f in jars},'sourceBefore':before,'trustScope':'Physical full-retention metadata is engine-written trustedSQL protected by integrity/ACLs; no expired ciphertextauthentication/closedMIG12 credit','externalProfile':{'approvedUTC':False,'witnessOwner':False,'platformDurability':False,'restoreAdmission':False,'deploymentQualified':False},'runtime':[]}
 def save():(a.output/'RESULT.json').write_text(json.dumps(receipt,indent=2)+'\n')
 def check(value,label):
  if not value:raise AssertionError(label)
  receipt['checks'].append(label);save()
 command=[str(a.java_home/'bin/javac'),'--release','17','-proc:none','-Xlint:all','-Werror','-cp',cp,'-d',str(classes),*map(str,sources)];r=subprocess.run(command,capture_output=True,text=True,timeout=90);receipt['compileCommand']=command;receipt['compileExit']=r.returncode;(a.output/'compile.log').write_text(r.stdout+r.stderr);save()
 if r.returncode:print('Source compilation failed; inspect private compile.log');return 2
 receipt['classfiles']={str(f.relative_to(classes)):digest(f)for f in classes.rglob('*.class')};check(True,'strict-selected-source-compile')
 if a.compile_only:receipt['compileSuccessful']=True;save();return 0
 created=[];process_clean=True
 with tempfile.TemporaryDirectory(prefix='revetsec-ordinary-issuer-gc-')as tmp:
  work=Path(tmp);name='revetsec-issuer-gc-'+secrets.token_hex(5);volume=name+'-data';password=secrets.token_urlsafe(24);runtimepassword=secrets.token_urlsafe(24)
  with socket.socket()as available:available.bind(('127.0.0.1',0));port=available.getsockname()[1]
  def docker(*arguments,input_text=None):
   result=subprocess.run(['docker',*arguments],input=input_text,capture_output=True,text=True,timeout=60)
   if result.returncode:raise RuntimeError('Owned disposable Docker operation failed')
   return result.stdout.strip()
  def sql(query):return docker('exec','-i',name,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','issuer_gc',input_text=query)
  try:
   envfile=work/'postgres.env';envfile.write_text('POSTGRES_PASSWORD='+password+'\nPOSTGRES_DB=issuer_gc\n');envfile.chmod(0o600);docker('volume','create','--label','com.revetsec.owned-fixture=true',volume);created.append('volume');docker('run','-d','--pull=never','--name',name,'--label','com.revetsec.owned-fixture=true','-p','127.0.0.1:'+str(port)+':5432','--env-file',str(envfile),'--mount','type=volume,source='+volume+',target=/var/lib/postgresql',IMAGE);created.append('container')
   for _ in range(80):
    ready=subprocess.run(['docker','exec',name,'pg_isready','-h','127.0.0.1','-U','postgres','-d','issuer_gc'],capture_output=True,timeout=5)
    if ready.returncode==0:break
    time.sleep(.25)
   else:raise RuntimeError('Owned primary readiness expired')
   namespaces=['fixture_issuer','gc_boundary','gc_after','gc_batch','gc_nanos','gc_race','gc_sample_back','gc_sample_same','gc_sample_forward',*['gc_fault_'+n for n in ['utc','authority','clock','error','null','throw','late']],*['gc_bad_'+n for n in ['kind','permanent','missing_bucket','stale_allocation','undercharged']],*['gc_wait_'+n for n in ['entity_backward','entity_unhealthy','entity_replacement','entity_nanos','entity_retain_same','entity_form_same','escrow_backward','escrow_unhealthy']],*['gc_outcome_'+n for n in ['late','unknown_applied','unknown_no_effect','second_delete']]]
   sql((ROOT/'issuer-schema.sql').read_text()+provision(namespaces));sql("CREATE ROLE issuer_runtime LOGIN PASSWORD '"+runtimepassword+"'; GRANT CONNECT ON DATABASE issuer_gc TO issuer_runtime; GRANT USAGE ON SCHEMA public TO issuer_runtime; GRANT SELECT ON issuer_store_namespace,issuer_store_root TO issuer_runtime; GRANT INSERT ON issuer_store_root TO issuer_runtime; GRANT SELECT,INSERT,DELETE ON issuer_store_entry TO issuer_runtime; GRANT UPDATE(version,retain_seconds,retain_nanos,sealed_form) ON issuer_store_entry TO issuer_runtime; GRANT SELECT ON issuer_store_escrow TO issuer_runtime; GRANT UPDATE(used_entries,used_bytes) ON issuer_store_escrow TO issuer_runtime; ALTER TABLE issuer_store_entry ENABLE ROW LEVEL SECURITY; CREATE POLICY issuer_select ON issuer_store_entry FOR SELECT TO issuer_runtime USING(true); CREATE POLICY issuer_insert ON issuer_store_entry FOR INSERT TO issuer_runtime WITH CHECK(true); CREATE POLICY issuer_update ON issuer_store_entry FOR UPDATE TO issuer_runtime USING(true) WITH CHECK(true); CREATE POLICY issuer_delete ON issuer_store_entry FOR DELETE TO issuer_runtime USING(kind NOT IN ('ISSUER_STATE','SUBJECT_STATE'));")
   check(sql("SELECT rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls FROM pg_roles WHERE rolname='issuer_runtime';")=='f|f|f|f|f','ordinary-runtime-role-unprivileged')
   check(sql("SELECT NOT has_table_privilege('issuer_runtime','issuer_store_entry','TRUNCATE') AND NOT has_table_privilege('issuer_runtime','issuer_store_root','DELETE') AND NOT has_column_privilege('issuer_runtime','issuer_store_entry','kind','UPDATE') AND NOT has_column_privilege('issuer_runtime','issuer_store_escrow','entry_limit','UPDATE');")=='t','ordinary-runtime-cannot-truncate-delete-registry-relabel-or-reallocate')
   secret=work/'secrets';secret.mkdir(mode=0o700);environment=dict(os.environ,REVETSEC_CLEANUP_CORE_JAR=str(jars[0]),REVETSEC_CLEANUP_CORE_SHA256=digest(jars[0]),REVETSEC_TEST_DB_URL='jdbc:postgresql://127.0.0.1:'+str(port)+'/issuer_gc?sslmode=disable&gssEncMode=disable',REVETSEC_TEST_DB_USER='issuer_runtime',REVETSEC_TEST_DB_PASSWORD=runtimepassword,REVETSEC_CLEANUP_ADMIN_PASSWORD=password,REVETSEC_TEST_ISSUER_TIME='1791288000',REVETSEC_TEST_ISSUER_AUTHORITY_NOW='2026-10-06T12:00:00Z',REVETSEC_TEST_ISSUER_SECRET_DIR=str(secret));environment.pop('JAVA_TOOL_OPTIONS',None);environment.pop('JDK_JAVA_OPTIONS',None)
   def run(classname,mode,label,overrides=None,expected_failure=False):
    result=subprocess.run([str(a.java_home/'bin/java'),'-cp',cp,'example.pending.'+classname,mode],env=dict(environment,**(overrides or {})),capture_output=True,text=True,timeout=90);lines=result.stdout.splitlines();safe=all(re.fullmatch(r'(PASS [A-Za-z0-9_-]+|OBSERVED [A-Z_]+|KEYS_READY)',line)for line in lines);record={'label':label,'exit':result.returncode,'stdoutSha256':hashlib.sha256(result.stdout.encode()).hexdigest(),'stderrSha256':hashlib.sha256(result.stderr.encode()).hexdigest(),'namedPasses':[line[5:]for line in lines if re.fullmatch(r'PASS [A-Za-z0-9_-]+',line)],'assertionFailures':re.findall(r'java\.lang\.AssertionError: ([A-Za-z0-9_-]+)(?:\r?\n|$)',result.stderr)};receipt['runtime'].append(record)
    if expected_failure:
     record['exactAssertionFailure']='java.lang.AssertionError: full-retention-capacity-needs-explicit-reclamation' in result.stderr;record['capacityObserved']='OBSERVED CAPACITY'in lines;check(safe and result.returncode!=0 and record['exactAssertionFailure']and record['capacityObserved'],'actual-runtime-before-capacity-assertion-not-missing-api');return
    check(safe and result.returncode==0,'runtime-'+label)
    for name in record['namedPasses']:check(True,name)
   run('IssuerStoreProbe','keygen','owned-fixture-keys');run('IssuerRetentionBaselineProbe','seed','genuine-seven-kind-seed')
   finite=int(sql("SELECT count(*) FROM issuer_store_entry WHERE namespace='fixture_issuer' AND kind NOT IN ('ISSUER_STATE','SUBJECT_STATE');"));check(finite==5,'genuine-five-finite-kind-inventory')
   horizon=sql("SELECT max(retain_seconds) FROM issuer_store_entry WHERE namespace='fixture_issuer' AND kind NOT IN ('ISSUER_STATE','SUBJECT_STATE');");sql("UPDATE issuer_store_escrow SET entry_limit=used_entries WHERE namespace='"+__import__('run_issuer').identity('issuer-physical/fixture_issuer')+"';")
   from datetime import datetime,timezone
   current=datetime.fromtimestamp(int(horizon),timezone.utc).isoformat().replace('+00:00','Z');current=current[:-1]+'.000000001Z'if a.genuine_offset_nanos else current;overrides={'REVETSEC_TEST_ISSUER_TIME':horizon,'REVETSEC_TEST_ISSUER_AUTHORITY_NOW':current}
   if a.baseline_only:run('IssuerRetentionBaselineProbe','before','before-capacity',overrides,True);receipt['baselineExpectedFailureObserved']=True
   else:run('IssuerRetentionCleanupProbe','genuine','genuine-explicit-cleanup',overrides);run('IssuerRetentionCleanupProbe','mechanical','bounded-mechanics')
   receipt['success']=not a.baseline_only
  except Exception as failure:receipt['failure']={'type':type(failure).__name__,'message':str(failure)[:200]};receipt['success']=False
  finally:
   if 'container'in created:
    try:docker('rm','-f',name)
    except Exception:process_clean=False
   if 'volume'in created:
    try:docker('volume','rm','-f',volume)
    except Exception:process_clean=False
   receipt['ownedResourcesRemoved']=process_clean;receipt['privateRuntimeRemoved']=False
 receipt['privateRuntimeRemoved']=not work.exists();receipt['sourceAfter']={str(f):digest(f)for f in watched};receipt['sourceStable']=receipt['sourceAfter']==before;receipt['success']=receipt['success']and receipt['ownedResourcesRemoved']and receipt['privateRuntimeRemoved']and receipt['sourceStable'];save();print(json.dumps({'success':receipt['success'],'baselineExpectedFailureObserved':receipt.get('baselineExpectedFailureObserved',False),'checks':len(receipt['checks']),'failure':receipt.get('failure'),'ownedResourcesRemoved':receipt['ownedResourcesRemoved'],'privateRuntimeRemoved':receipt['privateRuntimeRemoved']}));return 0 if receipt['success']or receipt.get('baselineExpectedFailureObserved')and process_clean and receipt['sourceStable']else 1
if __name__=='__main__':raise SystemExit(main())
