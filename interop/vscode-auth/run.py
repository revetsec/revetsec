#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Qualify a pinned unmodified VS Code release against disposable local issuer artifacts."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import uuid
import xml.etree.ElementTree as ET

NAMES={'self-issued-1.0.0.jar','revetsec-1.0.0.jar','revetsec-soklet-1.0.0.jar','soklet-4.0.0.jar'}
REQUIRED_CHILDREN={'application','wire','edge','browser','display','vscode'}

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
subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:vscode.dev
''')
    invoke(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-config',str(config),'-extensions','ca','-keyout',str(directory/'ca.key'),'-out',str(directory/'ca.pem')])
    invoke(['openssl','req','-new','-newkey','rsa:2048','-nodes','-config',str(config),'-keyout',str(directory/'key.pem'),'-out',str(directory/'leaf.csr')])
    invoke(['openssl','x509','-req','-in',str(directory/'leaf.csr'),'-CA',str(directory/'ca.pem'),'-CAkey',str(directory/'ca.key'),'-set_serial',str(uuid.uuid4().int),'-days','1','-extfile',str(config),'-extensions','leaf','-out',str(directory/'cert.pem')])
    for p in directory.iterdir(): p.chmod(0o600)
    return {name:(directory/(filename+'.pem')).read_text() for name,filename in [('ca','ca'),('cert','cert'),('key','key')]}

def validate(report,metadata_delay_ms=0):
    """Reproduce the exact transport blocker; never grant full-client qualification from partial OAuth work."""
    events=report.get('events',[]);checks=[]
    def add(name,value): checks.append({'name':name,'status':'PASS' if value else 'FAIL'})
    auth=[e for e in events if e.get('kind')=='AUTHORIZE']
    codes=[e for e in events if e.get('kind')=='TOKEN' and e.get('codeGrant') and e.get('status')==200]
    refresh=[e for e in events if e.get('kind')=='TOKEN' and e.get('refreshGrant') and e.get('status')==200 and 'completedElapsedMs' in e]
    cimd=[e for e in events if e.get('kind')=='CIMD']
    initialized=[e for e in events if e.get('kind')=='MCP' and e.get('mcpMethod')=='initialize' and e.get('status')==200]
    rejected=[e for e in events if e.get('kind')=='MCP' and e.get('mcpMethod')=='notifications/initialized' and e.get('status')==400]
    add('exact-client-transport-blocker-observed',report.get('status')=='FAILED' and report.get('failure')=='CLIENT_PROTOCOL_REJECTED')
    add('all-local-prerequisite-checks-passed',bool(report.get('checks')) and all(c.get('status')=='PASS' for c in report.get('checks',[])))
    add('bounded-ordered-monotonic-events',0<len(events)<=256 and all(e.get('ordinal')==i and type(e.get('elapsedMs')) is int and e['elapsedMs']>=0 and (i==0 or e['elapsedMs']>=events[i-1]['elapsedMs']) for i,e in enumerate(events)))
    unauthenticated=[e for e in events if e.get('kind')=='MCP' and e.get('status')==401]
    add('real-client-resource-and-issuer-discovery-after-401',bool(unauthenticated) and all(any(e.get('kind')=='METADATA' and e.get('status')==200 and e.get('metadataKind')==kind and e.get('ordinal',-1)>unauthenticated[0].get('ordinal',10**12) for e in events) for kind in ['AUTH_SERVER','PROTECTED_RESOURCE']))
    add('one-real-cimd-s256-resource-native-authorization',len(auth)==1 and all(auth[0].get(k) is True for k in ['cimdClient','exactResource','s256','exactCallback']))
    add('real-browser-login-consent-callback-without-referrer',report.get('realBrowserLogin') is True and report.get('realBrowserConsent') is True and report.get('callback',{}).get('count')==1 and all(report.get('callback',{}).get(k) is True for k in ['observed','noReferrer']))
    prepared=[e for e in events if e.get('kind')=='CONSENT' and e.get('method')=='POST' and e.get('status')==303]
    add('prepared-code-redirect-binds-issuer-and-actual-return',len(prepared)==1 and all(prepared[0].get(k) is True for k in ['codeInPreparedRedirect','issuerBoundResponse','redirectMatchesAuthorization']))
    add('one-bound-public-code-exchange',len(codes)==1 and all(codes[0].get(k) is True for k in ['cimdClient','exactResource','exactCallback','pkceBound','noAmbientCredentials','accessPresent','refreshPresent','bearer','noStore']))
    add('client-refreshes-current-value-and-rotates-both',bool(refresh) and all(all(e.get(k) is True for k in ['cimdClient','exactResource','noAmbientCredentials','usesCurrentRefresh','accessChanged','refreshChanged','accessPresent','refreshPresent','bearer','noStore']) for e in refresh))
    add('all-cimd-requests-are-anonymous-unconditional-no-store',len(cimd)>=3 and all(e.get('status')==200 and all(e.get(k) is True for k in ['get','hostMatches','sniMatches','anonymous','unconditional','noStore']) for e in cimd))
    add('configured-metadata-delay-observed',bool(cimd) and all(e.get('configuredDelayMs')==metadata_delay_ms and type(e.get('durationMs')) is int and e['durationMs']>=max(0,metadata_delay_ms-10) for e in cimd if 'completedElapsedMs' in e))
    samples=[]
    for row in [*codes,*refresh]:
        fetched=[e for e in cimd if e.get('ordinal',-1)>row.get('ordinal',10**12) and e.get('elapsedMs',-1)>=row.get('elapsedMs',0) and e.get('completedElapsedMs',10**12)<=row.get('completedElapsedMs',-1)]
        kind='code' if row.get('codeGrant') else 'refresh'
        samples.append({'phase':kind,'ordinal':row.get('ordinal'),'roundTripMs':row.get('durationMs'),'metadataMs':sum(e.get('durationMs',0) for e in fetched),'ownFreshMetadata':bool(fetched)})
    add('code-and-every-completed-refresh-fetch-their-own-fresh-metadata',bool(samples) and all(e['ownFreshMetadata'] for e in samples))
    add('measured-token-latencies-are-coherent',bool(samples) and all(type(e['roundTripMs']) is int and 0<=e['metadataMs']<=e['roundTripMs'] for e in samples))
    add('initialize-negotiates-november-2025-with-current-access',len(initialized)==1 and initialized[0].get('negotiatedProtocol')=='2025-11-25' and initialized[0].get('usesCurrentAccess') is True and initialized[0].get('responseSessionHeaderPresent') is False)
    add('next-notification-omits-version-and-is-rejected',len(rejected)==1 and rejected[0].get('protocolHeader')=='ABSENT_OR_OTHER' and rejected[0].get('sessionHeaderPresent') is False and rejected[0].get('acceptsJson') is True and rejected[0].get('acceptsSse') is True and rejected[0].get('usesCurrentAccess') is True)
    add('no-dcr-or-unsupported-token-grant',not any(e.get('kind')=='DCR' or e.get('kind')=='TOKEN' and not e.get('codeGrant') and not e.get('refreshGrant') for e in events))
    add('no-trust-or-sandbox-bypass-or-model-account',report.get('accountSignIn') is False and all(report.get(k) is False for k in ['certificateErrorBypass','browserSandboxDisabled','clientSandboxDisabled','globalTrustMutation','externalServices']))
    add('no-unexpected-browser-opening-or-policy-failure',not report.get('unexpectedExternalOpen') and not report.get('browserPolicyFailure') and not report.get('browserOpenFailure'))
    add('private-state-and-all-child-processes-removed',report.get('privateStateRemoved') is True and set(report.get('shutdown',{}))==REQUIRED_CHILDREN and set(report.get('shutdown',{}).values())=={'CLOSED'})
    return checks,sorted(samples,key=lambda row:row['ordinal'])

def junit(path,checks):
    suite=ET.Element('testsuite',name='VSCodeCimdTransportCheckpoint',tests=str(len(checks)),failures=str(sum(c['status']!='PASS' for c in checks)),errors='0',skipped='0')
    for check in checks:
        case=ET.SubElement(suite,'testcase',name=check['name'])
        if check['status']!='PASS': ET.SubElement(case,'failure',message='Structural qualification requirement failed')
    ET.ElementTree(suite).write(path,encoding='utf-8',xml_declaration=True)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['source','runtime','client','app','app-manifest','output']: parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--port',type=int,required=True);parser.add_argument('--metadata-delay-ms',type=int,choices=[0,1000],default=0)
    args=parser.parse_args();paths={name:Path(getattr(args,name.replace('-','_'))).resolve() for name in ['source','runtime','client','app','app-manifest','output']};module=Path(__file__).resolve().parent;pins=json.loads((module/'pins.json').read_text())
    if any(',' in str(p) or ':' in str(p) for p in [*paths.values(),module]) or paths['output'].exists() or not 10000<=args.port<=60000: parser.error('Use new private output, unused issuer port and paths without mount separators')
    rows=json.loads(paths['app-manifest'].read_text());
    if len(rows)!=4 or {r['name'] for r in rows}!=NAMES or any(sha(paths['app']/r['name'])!=r['sha256'] for r in rows): raise RuntimeError('PACKAGED_APP_DRIFT')
    if tree(paths['client'])!=pins['client']['treeSha256'] or tree(paths['runtime']/'java')!=pins['javaTreeSha256'] or sha(paths['runtime']/'caddy')!=pins['caddySha256'] or sha(paths['runtime']/'seccomp.json')!=pins['seccompSha256'] or sha(module/'vscode-client-metadata.json')!=pins['metadataDocumentSha256'] or sha(paths['runtime']/'system-ca.crt')!=pins['systemCaSha256']: raise RuntimeError('PINNED_RUNTIME_DRIFT')
    support={str(p.relative_to(paths['source'])):sha(p) for p in [paths['source']/'interop/inspector-auth/support'/name for name in ['process.mjs','cdp.mjs','web.mjs']]}
    for image in [pins['browserImage'],pins['namespaceImage']]:
        if invoke(['docker','image','inspect',image,'--format','{{.Id}} {{.Architecture}} {{.Os}}']).strip()!=image+' arm64 linux': raise RuntimeError('IMAGE_PIN_DRIFT')
    paths['output'].mkdir(mode=0o700,parents=True);evidence=paths['output']/'evidence';evidence.mkdir(mode=0o777);evidence.chmod(0o777)
    container='revetsec-vscode-'+uuid.uuid4().hex[:12];namespace=container+'-namespace';checks=[]
    hosts=paths['output']/'fixture-hosts.txt';hosts.write_text('::1 localhost\n127.0.0.1 ipv4-localhost\n');hosts.chmod(0o644)
    receipt={'status':'FAILED','issuer':'https://localhost:'+str(args.port),'metadataDelayMs':args.metadata_delay_ms,'pins':pins,'appArtifacts':rows,'harness':{str(p.relative_to(module)):sha(p) for p in sorted(module.rglob('*')) if p.is_file() and '__pycache__' not in p.parts},'support':support,'noRawLogsArchived':True,'fullClientWorkflowQualified':False,'releaseQualification':'OPEN','privateTlsInput':'bounded stdin only'}
    try:
        invoke(['docker','run','-d','--rm','--pull','never','--name',namespace,'--network','none','--cap-drop','ALL','--cap-add','NET_ADMIN','--security-opt','no-new-privileges',pins['namespaceImage'],'/bin/sh','-c','ip addr add 8.8.8.8/32 dev lo && ip -6 addr add fd00::1/128 dev lo && exec sleep 490'])
        command=['docker','run','--pull','never','--rm','--init','-i','--name',container,'--network','container:'+namespace,'--shm-size','1g','--user','pwuser','--cap-drop','ALL','--security-opt','no-new-privileges','--security-opt','seccomp='+str(paths['runtime']/'seccomp.json')]
        for source,target in [(paths['source'],'/source'),(paths['runtime'],'/runtime'),(paths['client'],'/vscode'),(paths['app'],'/app'),(module,'/suite')]: command+=['--mount','type=bind,src='+str(source)+',dst='+target+',readonly']
        command+=['--mount','type=bind,src='+str(hosts)+',dst=/etc/hosts,readonly','--mount','type=bind,src='+str(evidence)+',dst=/evidence',pins['browserImage'],'node','/suite/client.mjs']
        with tempfile.TemporaryDirectory(prefix='revetsec-vscode-tls-') as temp:
            private=Path(temp);private.chmod(0o700);payload=tls(private);payload.update(port=args.port,metadataDelayMs=args.metadata_delay_ms)
            bundle=private/'system-ca.crt';bundle.write_bytes((paths['runtime']/'system-ca.crt').read_bytes()+payload['ca'].encode());bundle.chmod(0o644)
            index=command.index(pins['browserImage']);command[index:index]=['--mount','type=bind,src='+str(bundle)+',dst=/etc/ssl/certs/ca-certificates.crt,readonly']
            result=subprocess.run(command,input=json.dumps(payload),capture_output=True,text=True,timeout=460);receipt['exit']=result.returncode
            # Crash output may contain credentials; deliberately do not archive it.
        receipt['hostPrivateTlsRemoved']=not private.exists()
        report=json.loads((evidence/'RESULT.json').read_text());checks,latency=validate(report,args.metadata_delay_ms);receipt['latencySamples']=latency;receipt['failure']=report.get('failure')
        checks.append({'name':'packaged-artifacts-and-runtime-unchanged','status':'PASS' if tree(paths['client'])==pins['client']['treeSha256'] and tree(paths['runtime']/'java')==pins['javaTreeSha256'] and all(sha(paths['app']/r['name'])==r['sha256'] for r in rows) and all(sha(paths['source']/name)==value for name,value in support.items()) else 'FAIL'})
        checks.append({'name':'host-private-tls-removed','status':'PASS' if receipt['hostPrivateTlsRemoved'] else 'FAIL'})
        receipt['status']='REPRODUCED' if result.returncode==1 and all(c['status']=='PASS' for c in checks) else 'FAILED'
    except (subprocess.TimeoutExpired,OSError,ValueError,KeyError,RuntimeError):
        receipt['failure']='BOUNDED_RUN_OR_RECEIPT_FAILURE';checks=[{'name':'client-workflow-completed','status':'FAIL'}]
    finally:
        for owned in [container,namespace]: subprocess.run(['docker','rm','-f',owned],capture_output=True,timeout=20)
        state=subprocess.run(['docker','ps','-aq','--filter','name=^/'+container+'(-namespace)?$'],capture_output=True,text=True,timeout=20)
        receipt['ownedContainersRemoved']=state.returncode==0 and not state.stdout.strip();checks.append({'name':'owned-containers-removed','status':'PASS' if receipt['ownedContainersRemoved'] else 'FAIL'})
        if not receipt['ownedContainersRemoved']: receipt['status']='FAILED'
        receipt['checks']=checks;(paths['output']/'RUN.json').write_text(json.dumps(receipt,indent=2)+'\n');junit(paths['output']/'junit.xml',checks)
    print(json.dumps({'status':receipt['status'],'checks':len(checks),'failure':receipt.get('failure'),'latencySamples':receipt.get('latencySamples')}));return 0 if receipt['status']=='REPRODUCED' else 1

if __name__=='__main__': raise SystemExit(main())
