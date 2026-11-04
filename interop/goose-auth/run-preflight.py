#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
"""Run the pinned Goose synthetic preflight without external networking or accounts."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import uuid
import xml.etree.ElementTree as ET


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(directory):
    return {str(p.relative_to(directory)):sha(p) for p in sorted(directory.rglob('*')) if p.is_file() and '__pycache__' not in p.parts}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client',type=Path,required=True,help='Directory containing only the verified released goose binary')
    parser.add_argument('--output',type=Path,required=True,help='New private receipt directory')
    args=parser.parse_args();client=args.client.resolve();out=args.output.resolve();suite=Path(__file__).resolve().parent;pins=json.loads((suite/'pins.json').read_text())
    if out.exists() or any(',' in str(p) or ':' in str(p) for p in [client,out,suite]):parser.error('Use a new output and paths without Docker mount separators')
    if {p.name for p in client.iterdir()}!={'goose'} or not (client/'goose').is_file() or (client/'goose').is_symlink() or sha(client/'goose')!=pins['client']['binarySha256']:raise RuntimeError('PINNED_CLIENT_DRIFT')
    if sha(suite/'goose-client-metadata.json')!=pins['clientMetadataSha256']:raise RuntimeError('PINNED_DOCUMENT_DRIFT')
    inspected=subprocess.run(['docker','image','inspect',pins['runtimeImage'],'--format','{{.Id}} {{.Architecture}} {{.Os}}'],capture_output=True,text=True,timeout=20)
    if inspected.returncode or inspected.stdout.strip()!=pins['runtimeImage']+' arm64 linux':raise RuntimeError('PINNED_RUNTIME_DRIFT')
    spec=importlib.util.spec_from_file_location('goose_preflight',suite/'preflight.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    before=inventory(suite);out.mkdir(mode=0o700,parents=True);evidence=out/'evidence';evidence.mkdir(mode=0o777);evidence.chmod(0o777)
    name='revetsec-goose-preflight-'+uuid.uuid4().hex[:12]
    command=['docker','run','--rm','--init','--pull','never','--name',name,'--network','none','--cap-drop','ALL','--security-opt','no-new-privileges','--user','1001:1001','--pids-limit','128','--memory','2g','--mount','type=bind,src='+str(client)+',dst=/client,readonly','--mount','type=bind,src='+str(suite)+',dst=/suite,readonly','--mount','type=bind,src='+str(evidence)+',dst=/evidence','--tmpfs','/tmp:rw,mode=1777',pins['runtimeImage'],'python3','/suite/preflight.py']
    receipt=dict(status='FAIL',pins=pins,harness=before,command=command,rawLogsArchived=False,fullClientWorkflowQualified=False,releaseQualification='OPEN',realIssuerExercised=False,modelAccountUsed=False)
    checks=[]
    try:
        result=subprocess.run(command,capture_output=True,timeout=180);receipt['exit']=result.returncode
        # Child stdout/stderr may include synthetic codes and authorization URLs. Never persist them.
        report=json.loads((evidence/'RESULT.json').read_text());checks=module.validate_report(report)
        checks.append(dict(name='exact-child-proof',status='PASS' if report.get('checks')==checks.copy() else 'FAIL'))
        checks.append(dict(name='client-and-harness-unchanged',status='PASS' if sha(client/'goose')==pins['client']['binarySha256'] and inventory(suite)==before else 'FAIL'))
        receipt['status']='PASS' if result.returncode==0 and report.get('status')=='PASS' and all(c['status']=='PASS' for c in checks) else 'FAIL'
    except (subprocess.TimeoutExpired,OSError,ValueError,KeyError,TypeError,RuntimeError):
        receipt['failure']='BOUNDED_PREFLIGHT_OR_RECEIPT_FAILURE';checks=[dict(name='preflight-completed',status='FAIL')]
    finally:
        subprocess.run(['docker','rm','-f',name],capture_output=True,timeout=20)
        state=subprocess.run(['docker','ps','-aq','--filter','name=^/'+name+'$'],capture_output=True,timeout=20)
        receipt['ownedContainerRemoved']=state.returncode==0 and not state.stdout.strip();checks.append(dict(name='owned-container-removed',status='PASS' if receipt['ownedContainerRemoved'] else 'FAIL'))
        if not receipt['ownedContainerRemoved']:receipt['status']='FAIL'
        receipt['checks']=checks;(out/'RUN.json').write_text(json.dumps(receipt,indent=2)+'\n')
        junit=ET.Element('testsuite',name='GooseSyntheticClientPreflight',tests=str(len(checks)),failures=str(sum(c['status']!='PASS' for c in checks)),errors='0',skipped='0')
        for check in checks:
            case=ET.SubElement(junit,'testcase',name=check['name'])
            if check['status']!='PASS':ET.SubElement(case,'failure',message='Synthetic preflight requirement failed')
        ET.ElementTree(junit).write(out/'junit.xml',encoding='utf-8',xml_declaration=True)
    print(json.dumps(dict(status=receipt['status'],checks=len(checks),fullClientWorkflowQualified=False)))
    return 0 if receipt['status']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
