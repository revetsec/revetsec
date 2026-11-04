#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
"""CAP-01 source profiles and owned disposable PostgreSQL byte/configuration checks. Offline only."""
import argparse,base64,hashlib,json,os,secrets,socket,subprocess,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
IMAGE='sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def identity(s):return base64.urlsafe_b64encode(hashlib.sha256(s.encode()).digest()).decode().rstrip('=')
def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for n in ['java-home','core-jar','pyranid-jar','driver-jar','jspecify-jar','jsr305-jar','output']:parser.add_argument('--'+n,type=Path,required=True)
 parser.add_argument('--profiles-only',action='store_true');a=parser.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 jars=[a.core_jar,a.pyranid_jar,a.driver_jar,a.jspecify_jar,a.jsr305_jar]
 example=ROOT/'examples/postgresql-pending-store';verification=ROOT/'verification/issuer-store'
 sources=[*(example/('src/main/java/example/pending/'+s+'.java') for s in ['PostgresqlIssuerStore','IssuerPgScope','IssuerPgLocks','IssuerPgCapacity','IssuerPgTransactions','PostgresqlPyranidDataSource','PostgresqlPendingAuthorizationStore']),*(example/('src/test/java/example/pending/'+s+'.java') for s in ['PendingStoreProbe','RsaFixtureSigner','IssuerFixtureAuthority','IssuerStoreProbe','CapacityProfileProbe']),*sorted((verification/'src/main/java').rglob('*.java')),verification/'src/test/java/verification/store/CapacityProfileProbe.java',ROOT/'verification/capacity-profile/CapacityRowFixture.java']
 inputs=[*sources,example/'issuer-schema.sql',example/'schema.sql',verification/'schema.sql',Path(__file__).resolve(),ROOT/'src/test/resources/fixtures/oauth/cap-02.properties']
 receipt={'success':False,'checks':[],'profiles':[],'javaHome':str(a.java_home),'postgresImage':IMAGE,'sourceInputs':{str(p.relative_to(ROOT)):sha(p) for p in inputs},'artifacts':{str(p):sha(p) for p in jars},'scope':'A configuration and disposable PostgreSQL component only; approved UTC/witness/host durability and complete C qualification remain unproved.'}
 def save():(a.output/'RESULT.json').write_text(json.dumps(receipt,indent=2)+'\n')
 def check(value,label):
  if not value:raise AssertionError(label)
  receipt['checks'].append(label);print('PASS '+label,flush=True);save()
 def run(cmd,**kw):return subprocess.run(list(map(str,cmd)),capture_output=True,text=True,timeout=90,**kw)
 def docker(*args,data=None):
  result=run(['docker',*args],input=data)
  if result.returncode:raise RuntimeError('Owned Docker operation failed: '+args[0])
  return result.stdout.strip()
 def provision(ns):
  physical=identity('issuer-physical/'+ns);allocation=identity('issuer-allocation/'+ns);values=[ns,physical,identity('issuer-authority/'+ns),identity('issuer-recovery/'+ns),identity('issuer-clock/'+ns)]
  return "INSERT INTO issuer_store_namespace VALUES("+','.join("'"+x+"'" for x in values)+",0,'"+allocation+"',2,4096,true);\nINSERT INTO issuer_store_escrow VALUES"+','.join("('ISSUER','"+physical+"',"+str(i)+",'"+allocation+"',16,0,0,0)" for i in range(256))+';\n'
 classes=a.output/'classes';classes.mkdir();cp=os.pathsep.join([str(classes),*map(str,jars)]);command=[a.java_home/'bin/javac','--release','17','-parameters','-g','-proc:none','-Xlint:all,-serial','-Werror','-cp',cp,'-d',classes,*sources]
 compiled=run(command);(a.output/'compile.stdout').write_text(compiled.stdout);(a.output/'compile.stderr').write_text(compiled.stderr);receipt['compileCommand']=list(map(str,command));save();check(compiled.returncode==0,'strict-complete-selected-source-compile')
 receipt['classfiles']={str(p.relative_to(classes)):sha(p) for p in sorted(classes.rglob('*.class'))}
 with tempfile.TemporaryDirectory(prefix='revetsec-cap01-') as tmp:
  private=Path(tmp);secretsdir=private/'secrets';secretsdir.mkdir(mode=0o700);config=private/'empty.properties';config.write_text('')
  env=dict(os.environ,REVETSEC_TEST_ISSUER_SECRET_DIR=str(secretsdir),REVETSEC_TEST_ISSUER_TIME='1791288000')
  java=[a.java_home/'bin/java','-cp',cp];keys=run([*java,'verification.store.Worker','keys',config,secretsdir],env=env);check(keys.returncode==0,'owned-ephemeral-keys')
  failures=[]
  for component in ['example.pending','verification.store']:
   for part in ['issuer','sealer']:
    result=run([*java,component+'.CapacityProfileProbe','profiles',part],env=env)
    lines=[line[5:] for line in result.stdout.splitlines() if line.startswith('PASS ')]
    error=result.stderr.splitlines();assertions=[line.split('java.lang.AssertionError: ',1)[1] for line in error if line.startswith('Exception in thread "main" java.lang.AssertionError: ')]
    row={'component':component,'part':part,'exit':result.returncode,'checks':lines,'assertions':assertions};receipt['profiles'].append(row);save()
    if result.returncode:failures.append(row)
  receipt['profileFailures']=len(failures)
  if failures:raise AssertionError('selected-profile-settings')
  check(True,'both-fixture-issuer-and-sealer-explicit16384-all-sealing-modes')
  if a.profiles_only:receipt['success']=True;save();return
  owner=secrets.token_hex(10);name='revetsec-cap01-'+owner;volume=name+'-data';password=secrets.token_urlsafe(24);runtimepassword=secrets.token_urlsafe(24)
  receipt['owned']={'label':'com.revetsec.cap01='+owner,'container':name,'volume':volume}
  with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
  envfile=private/'postgres.env';envfile.write_text('POSTGRES_PASSWORD='+password+'\nPOSTGRES_DB=postgres\n');envfile.chmod(0o600)
  try:
   docker('image','inspect',IMAGE);docker('volume','create','--label','com.revetsec.cap01='+owner,volume)
   docker('run','-d','--pull=never','--name',name,'--label','com.revetsec.cap01='+owner,'-p','127.0.0.1:'+str(port)+':5432','--env-file',str(envfile),'--mount','type=volume,source='+volume+',target=/var/lib/postgresql',IMAGE)
   for _ in range(80):
    if run(['docker','exec',name,'pg_isready','-h','127.0.0.1','-U','postgres']).returncode==0:break
    time.sleep(.25)
   else:raise RuntimeError('Owned primary readiness expired')
   def sql(db,text):return run(['docker','exec','-i',name,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-v','VERBOSITY=sqlstate','-U','postgres','-d',db],input=text)
   check(sql('postgres',"SELECT current_setting('fsync')='on' AND current_setting('full_page_writes')='on' AND NOT pg_is_in_recovery();").stdout.strip()=='t','real-primary-local-settings')
   check(sql('postgres',"CREATE ROLE cap01_runtime LOGIN PASSWORD '"+runtimepassword+"';").returncode==0,'owned-runtime-role-created')
   rowfile=private/'native-row.properties';generated=run([*java,'com.revetsec.oauth.server.CapacityRowFixture',ROOT/'src/test/resources/fixtures/oauth/cap-02.properties',rowfile],env=env);check(generated.returncode==0,'native-typed-authenticated-exact16384-fixture');rowfile.chmod(0o600)
   props={line.split('=',1)[0]:line.split('=',1)[1] for line in rowfile.read_text().splitlines() if line and not line.startswith('#')}
   # Java Properties escapes ':' in values; undo only the defined fixture alphabet escapes.
   props={k:v.replace('\\:',':').replace('\\=', '=') for k,v in props.items()}
   receipt['nativeRow']={'sealedBytes':len(props['sealed']),'sealedSha256':hashlib.sha256(props['sealed'].encode()).hexdigest()}
   assert len(props['sealed'])==16384
   variants=[('standalone',example/'issuer-schema.sql','example.pending','cap01_example'),('combined',example/'schema.sql','example.pending','cap01_example'),('verification',verification/'schema.sql','verification.store','cap01_verification')]
   for variant,schema,component,ns in variants:
    db='cap01_'+variant;check(sql('postgres','CREATE DATABASE '+db+';').returncode==0,variant+'-owned-database')
    applied=sql(db,schema.read_text()+provision(ns));check(applied.returncode==0,variant+'-actual-schema-and-profile-provisioned')
    base="INSERT INTO issuer_store_entry(namespace,storage_key,kind,version,retain_seconds,retain_nanos,sealed_form) VALUES('"+ns+"','"+props['key']+"','GRANT','"+props['version']+"',"+props['retain']+",0,"
    for label,value,accept in [('ascii-one','A',True),('ascii-exact','A'*16384,True),('ascii-one-over','A'*16385,False),('utf8-exact','é'*8192,True),('utf8-over','é'*8193,False),('empty','',False)]:
     trial=sql(db,"BEGIN;"+base+"'"+value+"');ROLLBACK;")
     check(trial.returncode==0 if accept else trial.returncode!=0 and '23514' in trial.stderr,variant+'-sql-byte-boundary-'+label)
    physical=identity('issuer-physical/'+ns);bucket=hashlib.sha256(props['key'].encode()).digest()[0]
    native=sql(db,'BEGIN;'+base+"'"+props['sealed']+"');UPDATE issuer_store_escrow SET used_entries=used_entries+1 WHERE namespace='"+physical+"' AND bucket="+str(bucket)+';COMMIT;');check(native.returncode==0,variant+'-native-exact-row-installed-with-escrow')
    grants="GRANT CONNECT ON DATABASE "+db+" TO cap01_runtime;GRANT USAGE ON SCHEMA public TO cap01_runtime;GRANT SELECT ON issuer_store_namespace,issuer_store_root TO cap01_runtime;GRANT INSERT ON issuer_store_root TO cap01_runtime;GRANT SELECT,INSERT,DELETE ON issuer_store_entry TO cap01_runtime;GRANT UPDATE(version,retain_seconds,retain_nanos,sealed_form) ON issuer_store_entry TO cap01_runtime;GRANT SELECT ON issuer_store_escrow TO cap01_runtime;GRANT UPDATE(used_entries,used_bytes) ON issuer_store_escrow TO cap01_runtime;"
    check(sql(db,grants).returncode==0,variant+'-runtime-role-grants')
    check(sql(db,"SELECT NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls FROM pg_roles WHERE rolname='cap01_runtime';").stdout.strip()=='t',variant+'-nonprivileged-role')
    localenv=dict(env,REVETSEC_TEST_DB_URL='jdbc:postgresql://127.0.0.1:'+str(port)+'/'+db+'?sslmode=disable&gssEncMode=disable',REVETSEC_TEST_DB_USER='cap01_runtime',REVETSEC_TEST_DB_PASSWORD=runtimepassword)
    result=run([*java,component+'.CapacityProfileProbe','database',rowfile],env=localenv)
    labels=[line[5:] for line in result.stdout.splitlines() if line.startswith('PASS ')]
    receipt.setdefault('databaseRuns',[]).append({'variant':variant,'component':component,'exit':result.returncode,'checks':labels,'assertions':[line.split('java.lang.AssertionError: ',1)[1] for line in result.stderr.splitlines() if line.startswith('Exception in thread "main" java.lang.AssertionError: ')]});save()
    check(result.returncode==0,variant+'-compiled-backend-config-and-carrier-probe')
   receipt['success']=True
  finally:
   present=run(['docker','inspect','--format','{{index .Config.Labels "com.revetsec.cap01"}}',name])
   if present.returncode==0 and present.stdout.strip()==owner:docker('rm','-f',name)
   present=run(['docker','volume','inspect','--format','{{index .Labels "com.revetsec.cap01"}}',volume])
   if present.returncode==0 and present.stdout.strip()==owner:docker('volume','rm',volume)
   receipt['ownedContainerRemoved']=run(['docker','inspect',name]).returncode!=0;receipt['ownedVolumeRemoved']=run(['docker','volume','inspect',volume]).returncode!=0;save()
   if not receipt['ownedContainerRemoved'] or not receipt['ownedVolumeRemoved']:raise RuntimeError('Owned resource cleanup incomplete')
 save()
if __name__=='__main__':main()
