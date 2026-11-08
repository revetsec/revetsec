#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
"""Run exact-artifact local-first logout observations through the selected real Soklet listener."""
from pathlib import Path
import argparse,hashlib,json,os,secrets,socket,subprocess,sys,zipfile
from matrix import exercise
ROOT=Path(__file__).resolve().parents[2]

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def inputs(args):
    root=args.examples_root.resolve();common=root/'rp-initiated-logout/target/revetsec-rp-initiated-logout-1.0.0-SNAPSHOT.jar';fixture=root/'rp-initiated-logout/target/revetsec-rp-initiated-logout-1.0.0-SNAPSHOT-tests.jar';carrier=root/'rp-initiated-logout-soklet/target/rp-initiated-logout-soklet-1.0.0-SNAPSHOT.jar';core=common.parent/'lib/revetsec-1.0.0-SNAPSHOT.jar';framework=carrier.parent/'lib/soklet-4.0.0.jar';classes=carrier.parent/'test-classes';java=args.java_home.resolve()/'bin/java';selected={'core':core,'common':common,'fixture':fixture,'carrier':carrier,'framework':framework}
    if not java.is_file()or not(classes/'example/logout/soklet/SokletLogoutSocketFixture.class').is_file():raise ValueError('Built selected input missing')
    for name,path in selected.items():
        if not path.is_file()or path.stat().st_size>16_777_216 or digest(path)!=getattr(args,name+'_sha256'):raise ValueError('Selected artifact digest mismatch')
    if any((classes/'com/revetsec').rglob('*.class'))or any((classes/'example/logout').glob('LocalFirstLogout*.class')):raise ValueError('Fixture classes must not shadow selected core/common')
    allowed={digest(path)for path in selected.values()}
    for jar in selected.values():
        with zipfile.ZipFile(jar)as z:manifest=z.read('META-INF/MANIFEST.MF').decode('utf-8').replace('\r\n ','')
        for line in manifest.splitlines():
            if line.startswith('Class-Path: '):
                for name in line[len('Class-Path: '):].split():
                    dependency=jar.parent/name
                    if ':'in name or name.startswith('/')or not dependency.is_file()or digest(dependency)not in allowed:raise ValueError('Unselected manifest runtime dependency')
    watched=list(selected.values())+[Path(__file__),Path(__file__).with_name('matrix.py')]
    for module in ['rp-initiated-logout','rp-initiated-logout-soklet']:watched+=sorted((root/module/'src').rglob('*.java'))
    watched+=sorted(classes.rglob('*.class'))
    return java,selected,classes,watched

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--examples-root',type=Path,default=ROOT/'examples');parser.add_argument('--java-home',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--delivery',choices=['form','get'],default='form');parser.add_argument('--padding',type=int,default=0);parser.add_argument('--metadata-fault',choices=['outage','unsupported'],default='outage');parser.add_argument('--fault-only',action='store_true');parser.add_argument('--framing-only',action='store_true')
    for name in ['core','common','fixture','carrier','framework']:parser.add_argument('--'+name+'-sha256',required=True)
    args=parser.parse_args()
    try:
        java,selected,classes,watched=inputs(args)
        if not args.output.is_absolute()or args.output.exists()or not 0<=args.padding<=20000:raise ValueError('New absolute output and bounded padding required')
    except(OSError,ValueError)as failure:parser.error(str(failure))
    before={str(path):digest(path)for path in watched};args.output.mkdir(parents=True)
    with socket.socket()as available:available.bind(('127.0.0.1',0));port=available.getsockname()[1]
    environment=dict(os.environ);environment.pop('JAVA_TOOL_OPTIONS',None);environment.pop('JDK_JAVA_OPTIONS',None);credential=secrets.token_urlsafe(32);environment['REVETSEC_LOGOUT_FIXTURE_CREDENTIAL']=credential;environment['REVETSEC_LOGOUT_PADDING']='x'*args.padding
    for name,path in selected.items():environment['REVETSEC_LOGOUT_'+name.upper()+'_JAR']=str(path.resolve());environment['REVETSEC_LOGOUT_'+name.upper()+'_SHA256']=digest(path)
    cp=[selected['common'],selected['fixture'],selected['carrier'],classes,selected['core'],selected['framework']];receipt={'success':False,'qualifiedProfile':False,'checks':[],'requests':[],'inputs':{name:{'path':str(path),'sha256':digest(path)}for name,path in selected.items()},'sourceHashesBefore':before,'classpath':list(map(str,cp)),'runtimeAnnotationsAndJUnitAbsent':True,'delivery':args.delivery,'padding':args.padding,'faultOnly':args.fault_only,'framingOnly':args.framing_only,'metadataFault':args.metadata_fault,'scope':'Actual owned synthetic OP/session/Soklet components only; authenticated TLS/query edge, browser/hostedprovider/durable/release gates remainopen.'};process=None
    try:
        with(args.output/'runtime.log').open('w')as log:
            process=subprocess.Popen([str(java),'-cp',os.pathsep.join(map(str,cp)),'example.logout.soklet.SokletLogoutSocketFixture',str(port),args.delivery],stdout=log,stderr=subprocess.STDOUT,env=environment)
            exercise(port,credential,process,receipt,args.delivery,args.padding,args.metadata_fault,args.fault_only,args.framing_only)
    except Exception as failure:receipt['success']=False;receipt['failure']={'type':type(failure).__name__,'message':str(failure)[:250],'checkpoint':receipt['checks'][-1]['name']if receipt['checks']else'startup'}
    finally:
        if process is not None and process.poll()is None:
            process.terminate()
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        receipt['ownedProcessStopped']=process is None or process.poll()is not None
        with socket.socket()as probe:probe.settimeout(1);receipt['ownedListenerClosed']=probe.connect_ex(('127.0.0.1',port))!=0
        receipt['sourceHashesAfter']={str(path):digest(path)if path.is_file()else'MISSING'for path in watched};receipt['sourceStable']=receipt['sourceHashesAfter']==before
        receipt['success']=receipt['success']and receipt['ownedProcessStopped']and receipt['ownedListenerClosed']and receipt['sourceStable'];(args.output/'RESULT.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'success':receipt['success'],'checks':len(receipt['checks']),'failure':receipt.get('failure'),'ownedProcessStopped':receipt['ownedProcessStopped'],'ownedListenerClosed':receipt['ownedListenerClosed']}));return 0 if receipt['success']else 1
if __name__=='__main__':sys.exit(main())
