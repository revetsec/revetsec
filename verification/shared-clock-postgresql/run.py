#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Owned offline native component runner, never a production migration/activation.

Uses only exact cached artifacts/image, creates uniquely named disposable Docker
resources, publishes PostgreSQL only on loopback, and removes credentials/state.
No raw credentials, SQL, rows or protocol frames are written to the receipt.
"""
import argparse
import base64
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
import xml.etree.ElementTree as ET

from fault_proxy import CommitLossProxy

HERE=Path(__file__).resolve().parent
IMAGE='sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def identity(text):
    return base64.urlsafe_b64encode(hashlib.sha256(text.encode()).digest()).decode().rstrip('=')


def execute(command, *, env=None, data=None, timeout=60):
    return subprocess.run(command,input=data,text=True,capture_output=True,env=env,timeout=timeout)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--dependencies',type=Path,required=True)
    parser.add_argument('--skip-interlock',action='store_true',help='Diagnostic component-only run, never final acceptance')
    parser.add_argument('--java-home',type=Path,action='append',required=True)
    args=parser.parse_args()
    out=args.output.absolute();out.mkdir(parents=True,exist_ok=False)
    sources={str(p.relative_to(HERE)):digest(p) for p in sorted(HERE.rglob('*')) if p.is_file() and 'target' not in p.parts and '__pycache__' not in p.parts}
    deps=json.loads(args.dependencies.read_text())
    for row in deps:
        if digest(row['path'])!=row['sha256']:raise RuntimeError('Frozen dependency mismatch')
    inspect=execute(['docker','image','inspect',IMAGE,'--format','{{.Id}}'])
    if inspect.returncode or inspect.stdout.strip()!=IMAGE:raise RuntimeError('Exact cached image unavailable; no pull attempted')
    checks=[];processes=[];cleanup={};resource='revetsec-scp05-'+secrets.token_hex(6)
    network=resource+'-bridge';volume=resource+'-data';created=[]
    runtime=out/'runtime';runtime.mkdir(mode=0o700)
    password=secrets.token_urlsafe(32)
    envfile=runtime/'postgres.env';envfile.write_text('POSTGRES_PASSWORD='+password+'\nPOSTGRES_DB=scp05_admin\n');envfile.chmod(0o600)
    with socket.socket() as bound:
        bound.bind(('127.0.0.1',0));port=bound.getsockname()[1]
    def check(label,condition):
        checks.append({'id':label,'passed':bool(condition)})
        if not condition:raise AssertionError(label)
    def docker(*parts,data=None,timeout=60):
        p=execute(['docker',*parts],data=data,timeout=timeout)
        if p.returncode:raise RuntimeError('Owned Docker operation failed: '+parts[0])
        return p.stdout.strip()
    def sql(database,text):
        return docker('exec','-i',resource,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d',database,data=text)
    def environment(database,user='postgres',secret=None,proxy_port=None):
        return dict(os.environ,DB_URL=f'jdbc:postgresql://127.0.0.1:{proxy_port or port}/{database}',DB_USER=user,DB_PASSWORD=secret or password)
    def run_java(lane,classes,classpath,name,env,*arguments,case_label=None):
        command=[str(lane/'bin/java'),'-ea','-cp',str(classes)+os.pathsep+classpath,'verification.sharedclock.'+name,*arguments]
        p=execute(command,env=env,timeout=40)
        label=case_label or name+('-'+'-'.join(arguments) if arguments else '')
        folder=out/lane.parent.parent.name/label;folder.mkdir(parents=True,exist_ok=True)
        (folder/'stdout.log').write_text(p.stdout);(folder/'stderr.log').write_text(p.stderr)
        labels=[line[5:] for line in p.stdout.splitlines() if line.startswith('PASS ')]
        valid=p.returncode==0 and bool(labels) and not p.stderr and len(labels)==len(set(labels))
        check(lane.parent.parent.name+'/'+label,valid)
        processes.append({'java_home':str(lane),'case':label,'exit_code':p.returncode,'assertions':labels,'directory':str(folder.relative_to(out))})
        for assertion in labels:checks.append({'id':lane.parent.parent.name+'/'+label+'/'+assertion,'passed':True})
        return labels
    failure=None
    try:
        docker('network','create','--label','com.revetsec.scp05=true',network);created.append('network')
        docker('volume','create','--label','com.revetsec.scp05=true',volume);created.append('volume')
        docker('run','-d','--pull=never','--name',resource,'--label','com.revetsec.scp05=true','--network',network,
               '--publish',f'127.0.0.1:{port}:5432','--env-file',str(envfile),'--mount',f'type=volume,source={volume},target=/var/lib/postgresql',IMAGE)
        created.append('container')
        until=time.monotonic()+30
        while True:
            p=execute(['docker','exec',resource,'pg_isready','-h','127.0.0.1','-U','postgres','-d','scp05_admin'],timeout=3)
            if p.returncode==0:break
            if time.monotonic()>=until:raise RuntimeError('Owned primary not ready')
            time.sleep(.1)
        check('primary-postgresql18-fsync-fullpage',sql('scp05_admin',"SELECT current_setting('server_version_num')::int>=180000 AND NOT pg_is_in_recovery() AND current_setting('fsync')='on' AND current_setting('full_page_writes')='on';")=='t')
        for number,lane in enumerate(args.java_home):
            lane=lane.absolute();laneout=out/lane.parent.parent.name;laneout.mkdir(exist_ok=True)
            classes=laneout/'classes';classes.mkdir()
            cp=os.pathsep.join(x['path'] for x in deps)
            command=[str(lane/'bin/javac'),'--release','17','-proc:none','-Xlint:all,-serial','-Werror','-cp',cp,'-d',str(classes),*[str(p) for p in sorted((HERE/'src').rglob('*.java'))]]
            p=execute(command);(laneout/'compile.stdout').write_text(p.stdout);(laneout/'compile.stderr').write_text(p.stderr)
            check(lane.parent.parent.name+'/warning-fatal-compile',p.returncode==0 and not p.stderr)
            database='scp05_lane'+str(number);sql('scp05_admin','CREATE DATABASE '+database+';')
            sql(database,(HERE/'schema.sql').read_text())
            env=environment(database)
            run_java(lane,classes,cp,'PgCapacityChecks',env)
            run_java(lane,classes,cp,'PgTransactionChecks',env)
            run_java(lane,classes,cp,'PgQuotaControlChecks',env)
            run_java(lane,classes,cp,'PgNativeChecks',env)
            for when in ('before','after'):
                sql(database,'DELETE FROM scp05_transaction_probe WHERE id=9001;')
                proxy=CommitLossProxy(port,when)
                try:
                    run_java(lane,classes,cp,'PgTransactionChecks',environment(database,proxy_port=proxy.local_port),'ack-loss',case_label='PgTransactionChecks-ack-loss-'+when)
                    check(lane.parent.parent.name+'/ack-'+when+'-ground-truth',sql(database,'SELECT count(*) FROM scp05_transaction_probe WHERE id=9001;')==('1' if when=='after' else '0'))
                    check(lane.parent.parent.name+'/ack-'+when+'-one-attempt',proxy.drops==1 and proxy.committed_ready==(1 if when=='after' else 0) and not proxy.errors)
                finally:proxy.close()
                proxy=CommitLossProxy(port,when)
                key='lost-ack-'+when;bucket=hashlib.sha256(key.encode()).digest()[0]
                prior=int(sql(database,f"SELECT used_entries FROM scp05_escrow WHERE family='ISSUER' AND namespace='{identity('native-scope')}' AND bucket={bucket};"))
                try:
                    run_java(lane,classes,cp,'PgNativeChecks',environment(database,proxy_port=proxy.local_port),'ack-loss',when)
                    present=sql(database,f"SELECT count(*) FROM scp05_entries WHERE storage_key='{key}';")
                    used=int(sql(database,f"SELECT used_entries FROM scp05_escrow WHERE family='ISSUER' AND namespace='{identity('native-scope')}' AND bucket={bucket};"))
                    check(lane.parent.parent.name+'/data-quota-ack-'+when+'-atomic-ground-truth',present==('1' if when=='after' else '0') and used==prior+(1 if when=='after' else 0))
                    check(lane.parent.parent.name+'/data-quota-ack-'+when+'-one-attempt',proxy.drops==1 and not proxy.errors)
                finally:proxy.close()
            proxy=CommitLossProxy(port,'after',drop_read_commits=True)
            try:
                run_java(lane,classes,cp,'PgTransactionChecks',environment(database,proxy_port=proxy.local_port),'barrier-ack-loss')
                check(lane.parent.parent.name+'/barrier-ack-loss-withheld-no-business-write',proxy.drops==1 and proxy.committed_ready==1 and not proxy.errors)
            finally:proxy.close()
            if not args.skip_interlock:
                from native_interlock_checks import exercise
                exercise(lane,classes,cp,number,sql,environment,run_java,check,out)
    except Exception as exc:
        failure=type(exc).__name__+': '+str(exc)
    finally:
        for kind,command in [('container',['rm','-f',resource]),('volume',['volume','rm',volume]),('network',['network','rm',network])]:
            if kind in created:
                p=execute(['docker',*command]);cleanup[kind]=p.returncode==0
        envfile.unlink(missing_ok=True);shutil.rmtree(runtime,ignore_errors=True)
    current={str(p.relative_to(HERE)):digest(p) for p in sorted(HERE.rglob('*')) if p.is_file() and 'target' not in p.parts and '__pycache__' not in p.parts}
    if current!=sources:failure='Source changed during run'
    unique_ids=len({x['id'] for x in checks})==len(checks)
    if not unique_ids:failure='Duplicate assertion IDs in run evidence'
    passed=failure is None and bool(checks) and unique_ids and all(x['passed'] for x in checks) and all(cleanup.values()) and len(cleanup)==3
    result={'passed':passed,'failure':failure,'interlock_skipped':args.skip_interlock,'unique_assertion_ids':unique_ids,'checks':checks,'processes':processes,'source_hashes':sources,'dependencies':deps,'image':IMAGE,'resources':{'container':resource,'volume':volume,'network':network},'cleanup':cleanup,'ephemeral_credential_file_removed':not envfile.exists(),'network':'owned bridge; loopback-only published PostgreSQL; no external requests/image pull','profile':'native components with scripted UTC only; no whole engine/profile group qualification'}
    (out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
    xml=ET.Element('testsuite',name='native-component-assertions',tests=str(len(checks)),failures=str(sum(not x['passed'] for x in checks)),errors='0',skipped='0')
    for row in checks:
        case=ET.SubElement(xml,'testcase',classname='owned-native-components',name=row['id'])
        if not row['passed']:ET.SubElement(case,'failure',message='Observed assertion failed')
    ET.indent(xml);ET.ElementTree(xml).write(out/'TEST-native-assertions.xml',encoding='utf-8',xml_declaration=True)
    print(json.dumps({'passed':passed,'failure':failure,'assertion_cases':len(checks),'processes':len(processes),'cleanup':cleanup}))
    return 0 if passed else 1


if __name__=='__main__':
    sys.exit(main())
