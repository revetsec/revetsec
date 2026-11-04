#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Apache-2.0.
import argparse,hashlib,json,subprocess,tempfile,uuid
from pathlib import Path
import xml.etree.ElementTree as ET
NAMES={'revetsec-soklet-1.0.0-SNAPSHOT.jar', 'self-issued-1.0.0-SNAPSHOT.jar', 'revetsec-1.0.0-SNAPSHOT.jar', 'soklet-4.0.0.jar'}
REQUIRED_CHILDREN={'after-expiry', 'edge', 'initial', 'wire', 'browser', 'application'}
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def tree(directory):
    rows=[]
    for path in sorted(directory.rglob('*')):
        if path.is_symlink(): rows.append([str(path.relative_to(directory)),'link',str(path.readlink())])
        elif path.is_file(): rows.append([str(path.relative_to(directory)),'file',sha(path)])
    return hashlib.sha256(json.dumps(rows,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()

def invoke(command):
    result=subprocess.run(command,capture_output=True,text=True,timeout=30)
    if result.returncode: raise RuntimeError('LOCAL_PREPARATION_FAILED')
    return result.stdout

def tls(directory):
    config=directory/'openssl.cnf'
    config.write_text('''[req]
distinguished_name=dn
prompt=no
[dn]
CN=Revetsec disposable fixture
[ca]
basicConstraints=critical,CA:true,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
[leaf]
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:goose-docs.ai
''')
    invoke(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-config',str(config),'-extensions','ca','-keyout',str(directory/'ca.key'),'-out',str(directory/'ca.pem')])
    invoke(['openssl','req','-new','-newkey','rsa:2048','-nodes','-config',str(config),'-keyout',str(directory/'key.pem'),'-out',str(directory/'leaf.csr')])
    invoke(['openssl','x509','-req','-in',str(directory/'leaf.csr'),'-CA',str(directory/'ca.pem'),'-CAkey',str(directory/'ca.key'),'-set_serial',str(uuid.uuid4().int),'-days','1','-extfile',str(config),'-extensions','leaf','-out',str(directory/'cert.pem')])
    for p in directory.iterdir(): p.chmod(0o600)
    return {name:(directory/(filename+'.pem')).read_text() for name,filename in [('ca','ca'),('cert','cert'),('key','key')]}

from validation import validate

def junit(path,checks):
    suite=ET.Element('testsuite',name='GooseReleasedClientWorkflow',tests=str(len(checks)),failures=str(sum(c['status']!='PASS' for c in checks)),errors='0',skipped='0')
    for check in checks:
        case=ET.SubElement(suite,'testcase',name=check['name'])
        if check['status']!='PASS': ET.SubElement(case,'failure',message='Structural qualification requirement failed')
    ET.ElementTree(suite).write(path,encoding='utf-8',xml_declaration=True)

def main():
    parser=argparse.ArgumentParser(description='Qualify the pinned Goose released-command profile against the real packaged self-issued example.')
    for name in ['source','runtime','client','app','app-manifest','output']: parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--port',type=int,required=True);parser.add_argument('--metadata-delay-ms',type=int,choices=[0,1000],default=0)
    args=parser.parse_args();paths={name:Path(getattr(args,name.replace('-','_'))).resolve() for name in ['source','runtime','client','app','app-manifest','output']};module=Path(__file__).resolve().parent;pins=json.loads((module/'workflow-pins.json').read_text())
    if any(',' in str(p) or ':' in str(p) for p in [*paths.values(),module]) or paths['output'].exists() or not 10000<=args.port<=60000: parser.error('Use new private output, unused issuer port and paths without mount separators')
    rows=json.loads(paths['app-manifest'].read_text());
    if len(rows)!=4 or {r['name'] for r in rows}!=NAMES or any(sha(paths['app']/r['name'])!=r['sha256'] for r in rows): raise RuntimeError('PACKAGED_APP_DRIFT')
    if sha(paths['client']/'goose')!=pins['client']['binarySha256'] or tree(paths['runtime']/'java')!=pins['javaTreeSha256'] or sha(paths['runtime']/'caddy')!=pins['caddySha256'] or sha(paths['runtime']/'seccomp.json')!=pins['seccompSha256'] or sha(module/'goose-client-metadata.json')!=pins['metadataDocumentSha256'] or sha(paths['runtime']/'system-ca.crt')!=pins['systemCaSha256']: raise RuntimeError('PINNED_RUNTIME_DRIFT')
    support={str(p.relative_to(paths['source'])):sha(p) for p in [paths['source']/'interop/inspector-auth/support'/name for name in ['process.mjs','cdp.mjs','web.mjs']]}
    for image in [pins['browserImage'],pins['namespaceImage']]:
        if invoke(['docker','image','inspect',image,'--format','{{.Id}} {{.Architecture}} {{.Os}}']).strip()!=image+' arm64 linux': raise RuntimeError('IMAGE_PIN_DRIFT')
    paths['output'].mkdir(mode=0o700,parents=True);evidence=paths['output']/'evidence';evidence.mkdir(mode=0o777);evidence.chmod(0o777)
    container='revetsec-goose-' +uuid.uuid4().hex[:12];namespace=container+'-namespace';checks=[]
    hosts=paths['output']/'fixture-hosts.txt';hosts.write_text('::1 localhost\n127.0.0.1 ipv4-localhost\n');hosts.chmod(0o644)
    receipt={'status':'FAIL','issuer':'https://localhost:'+str(args.port),'metadataDelayMs':args.metadata_delay_ms,'pins':pins,'appArtifacts':rows,'harness':{str(p.relative_to(module)):sha(p) for p in sorted(module.rglob('*')) if p.is_file() and '__pycache__' not in p.parts},'support':support,'noRawLogsArchived':True,'fullClientWorkflowQualified':False,'qualificationScope':'Goose 1.57.0 mcp-probe November-2025 browser/step-up/expired stored-auth reconnect','releaseQualification':'OPEN','privateTlsInput':'bounded stdin only'}
    try:
        invoke(['docker','run','-d','--rm','--pull','never','--name',namespace,'--network','none','--cap-drop','ALL','--cap-add','NET_ADMIN','--security-opt','no-new-privileges',pins['namespaceImage'],'/bin/sh','-c','ip addr add 8.8.8.8/32 dev lo && ip -6 addr add fd00::1/128 dev lo && exec sleep 490'])
        command=['docker','run','--pull','never','--rm','--init','-i','--name',container,'--network','container:'+namespace,'--shm-size','1g','--user','pwuser','--cap-drop','ALL','--security-opt','no-new-privileges','--security-opt','seccomp='+str(paths['runtime']/'seccomp.json')]
        for source,target in [(paths['source'],'/source'),(paths['runtime'],'/runtime'),(paths['client'],'/client'),(paths['app'],'/app'),(module,'/suite')]: command+=['--mount','type=bind,src='+str(source)+',dst='+target+',readonly']
        command+=['--mount','type=bind,src='+str(hosts)+',dst=/etc/hosts,readonly','--mount','type=bind,src='+str(evidence)+',dst=/evidence',pins['browserImage'],'node','/suite/client.mjs']
        with tempfile.TemporaryDirectory(prefix='revetsec-goose-tls-') as temp:
            private=Path(temp);private.chmod(0o700);payload=tls(private);payload.update(port=args.port,metadataDelayMs=args.metadata_delay_ms)
            bundle=private/'system-ca.crt';bundle.write_bytes((paths['runtime']/'system-ca.crt').read_bytes()+payload['ca'].encode());bundle.chmod(0o644)
            index=command.index(pins['browserImage']);command[index:index]=['--mount','type=bind,src='+str(bundle)+',dst=/etc/ssl/certs/ca-certificates.crt,readonly']
            result=subprocess.run(command,input=json.dumps(payload),capture_output=True,text=True,timeout=460);receipt['exit']=result.returncode
            # Crash output may contain credentials; deliberately do not archive it.
        receipt['hostPrivateTlsRemoved']=not private.exists()
        report=json.loads((evidence/'RESULT.json').read_text());checks,latency=validate(report,args.metadata_delay_ms);receipt['latencySamples']=latency;receipt['failure']=report.get('failure')
        checks.append({'name':'packaged-artifacts-and-runtime-unchanged','status':'PASS' if sha(paths['client']/'goose')==pins['client']['binarySha256'] and tree(paths['runtime']/'java')==pins['javaTreeSha256'] and all(sha(paths['app']/r['name'])==r['sha256'] for r in rows) and all(sha(paths['source']/name)==value for name,value in support.items()) else 'FAIL'})
        checks.append({'name':'host-private-tls-removed','status':'PASS' if receipt['hostPrivateTlsRemoved'] else 'FAIL'})
        receipt['status']='PASS' if result.returncode==0 and all(c['status']=='PASS' for c in checks) else 'FAIL'
    except (subprocess.TimeoutExpired,OSError,ValueError,KeyError,RuntimeError):
        receipt['failure']='BOUNDED_RUN_OR_RECEIPT_FAILURE';checks=[{'name':'client-workflow-completed','status':'FAIL'}]
    finally:
        for owned in [container,namespace]: subprocess.run(['docker','rm','-f',owned],capture_output=True,timeout=20)
        state=subprocess.run(['docker','ps','-aq','--filter','name=^/'+container+'(-namespace)?$'],capture_output=True,text=True,timeout=20)
        receipt['ownedContainersRemoved']=state.returncode==0 and not state.stdout.strip();checks.append({'name':'owned-containers-removed','status':'PASS' if receipt['ownedContainersRemoved'] else 'FAIL'})
        if not receipt['ownedContainersRemoved']: receipt['status']='FAIL'
        receipt['fullClientWorkflowQualified']=receipt['status']=='PASS';receipt['checks']=checks;(paths['output']/'RUN.json').write_text(json.dumps(receipt,indent=2)+'\n');junit(paths['output']/'junit.xml',checks)
    print(json.dumps({'status':receipt['status'],'checks':len(checks),'failure':receipt.get('failure'),'latencySamples':receipt.get('latencySamples')}));return 0 if receipt['status']=='PASS' else 1

if __name__=='__main__': raise SystemExit(main())
