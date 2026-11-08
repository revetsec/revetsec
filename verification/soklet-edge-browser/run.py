#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
"""Owned fixture TLS/raw-target/Chrome composition; selected artifacts only, no production listeners."""
from pathlib import Path
import argparse,hashlib,http.client,json,os,signal,socket,ssl,subprocess,tempfile,time,urllib.parse
import certificates,runtime
from edge import Edge,Connect

def check(receipt,name,condition,observed=None):
    receipt['checks'].append({'name':name,'passed':bool(condition),**({'observed':observed}if observed is not None else{})})
    if not condition:raise AssertionError(name)
def data(reply):return json.loads(reply[2])
def cookie(reply,name):
    matches=[value.split(';',1)[0]for key,value in reply[1]if key.lower()=='set-cookie'and value.startswith(name+'=')]
    if len(matches)!=1:raise AssertionError('One private fixture cookie')
    return matches[0]
def raw_request(context,port,wire,hostname='app.example',timeout=5):
    with socket.create_connection(('127.0.0.1',port),timeout=timeout)as raw:
        with context.wrap_socket(raw,server_hostname=hostname)as connection:
            connection.settimeout(timeout)
            try:
                connection.sendall(wire);response=http.client.HTTPResponse(connection);response.begin();body=response.read(131073)
                if len(body)>131072:raise AssertionError('Bounded raw response')
                return response.status,response.getheaders(),body
            except (OSError,http.client.HTTPException):return 'CONNECTION_CLOSED',[],b''
def wire(method,target,body=b'',headers=(),framing=True):
    fields=[('Host','app.example'),*headers]
    if framing:fields.append(('Content-Length',str(len(body))))
    return (method+' '+target+' HTTP/1.1\r\n'+''.join(k+': '+v+'\r\n'for k,v in fields)+'Connection: close\r\n\r\n').encode('ascii')+body

def normal_tls(receipt,client,edge):
    check(receipt,'normal-TLS-private-CA-hostname-valid',raw_request(client,edge.port,wire('GET','/__verification/index'))[0]==200)
    before=edge.snapshot()['dispatched']
    for name,context,hostname in [('untrusted-CA',ssl.create_default_context(),'app.example'),('wrong-SAN-hostname',client,'wrong.example')]:
        refused=False
        try:raw_request(context,edge.port,wire('GET','/__verification/index'),hostname)
        except ssl.SSLCertVerificationError:refused=True
        check(receipt,'normal-TLS-'+name+'-refused-before-dispatch',refused and edge.snapshot()['dispatched']==before)
    check(receipt,'normal-TLS-context-verification-enabled',client.verify_mode==ssl.CERT_REQUIRED and client.check_hostname)

def native_matrix(receipt,profile,client,edge,private):
    def state():return data(private('GET','/fixture/control/state'if profile=='logout'else'/fixture/state'))
    def facts():
        observed=state();return observed['shared']if profile=='logout'else observed
    def refuse(name,request,expected):
        before=edge.snapshot()['dispatched'];previous=facts();reply=raw_request(client,edge.port,request);after=facts()
        check(receipt,name,reply[0]in expected and edge.snapshot()['dispatched']==before and after==previous,reply[0])
    path='/logout'if profile=='logout'else'/google/begin';media=[('Origin','https://app.example'),('Content-Type','application/x-www-form-urlencoded')]
    for target in ([path+'?',path+'?x=1']if profile=='logout'else[route+'?'for route in ['/google/begin','/google/complete','/apple/begin','/apple/complete','/session','/native/session','/account/tenant/alice','/native/account/tenant/alice','/logout','/native/logout']]):
        method='GET'if target.startswith(('/session','/native/session','/account/','/native/account/'))else'POST'
        refuse('raw-query-refused-'+target.split('?')[0]+'-'+('bare'if target.endswith('?')else'nonempty'),wire(method,target),[400])
        check(receipt,'raw-target-hash-preserved-'+target.split('?')[0],edge.snapshot()['events'][-1]['targetSha256']==hashlib.sha256(target.encode()).hexdigest())
    attacks=[
      ('duplicate-content-length',wire('POST',path,headers=[('Content-Length','0')])),
      ('conflicting-content-length',wire('POST',path,headers=[('Content-Length','1')])),
      ('CL-plus-TE',wire('POST',path,headers=[('Transfer-Encoding','chunked')])),
      ('duplicate-cookie',wire('POST',path,headers=[('Cookie','a=b'),('Cookie','c=d')])),
      ('duplicate-authorization',wire('POST',path,headers=[('Authorization','Bearer a'),('Authorization','Bearer b')])),
      ('duplicate-content-type',wire('POST',path,headers=[('Content-Type','a'),('Content-Type','b')])),
      ('duplicate-csrf-header',wire('POST',path,headers=[('X-CSRF-Token','a'),('X-CSRF-Token','b')])),
      ('duplicate-host',wire('POST',path,headers=[('Host','app.example')])),
      ('duplicate-origin',wire('POST',path,headers=[('Origin','https://app.example'),('Origin','https://app.example')])),
      ('forwarded-spoof',wire('POST',path,headers=[('Forwarded','proto=https;host=app.example')])),
      ('x-forwarded-spoof',wire('POST',path,headers=[('X-Forwarded-Proto','https')])),
      ('private-fixture-spoof',wire('POST',path,headers=[('X-Fixture-Credential','untrusted')])),
      ('encoded-path',wire('POST',path.replace('/logout','/%6Cogout').replace('/google','/%67oogle'))),
      ('absolute-target',wire('POST','https://app.example'+path)),
      ('header-count',wire('POST',path,headers=[('X-Pad-'+str(i),'x')for i in range(33)])),
      ('header-value',wire('POST',path,headers=[('X-Pad','x'*4097)])),
      ('chunk-extension',wire('POST',path,b'0;ext=x\r\n\r\n',[('Transfer-Encoding','chunked')],False)),
      ('chunk-trailers',wire('POST',path,b'0\r\nX-Foo: x\r\n\r\n',[('Transfer-Encoding','chunked')],False)),
      ('truncated-body',wire('POST',path,b'x',[('Content-Length','2')],False)),
      ('truncated-chunk',wire('POST',path,b'2\r\nx',[('Transfer-Encoding','chunked')],False)),
    ]
    for name,request in attacks:refuse(name,request,[400,431,'CONNECTION_CLOSED'])
    cap=4096 if profile=='logout'else 32768
    refuse('declared-body-cap-plus-one',wire('POST',path,headers=[('Content-Length',str(cap+1))],framing=False),[413])
    refuse('chunked-body-cap-plus-one',wire('POST',path,(hex(cap+1)[2:]+'\r\n').encode(),[('Transfer-Encoding','chunked')],False),[413])
    if profile=='logout':
        value='A'*43
        for query in ['', 'state='+value+'&state='+value,'st%61te='+value,'state='+value+';x=1','state='+value+'B']:
            refuse('callback-raw-state-shape-'+str(len(query)),wire('GET','/logout/callback?'+query),[400])
        started=private('POST','/fixture/login');headers=[('Origin','https://app.example'),('Cookie',cookie(started,'__Host-app-session')),('X-CSRF-Token',data(started)['csrf']),('Transfer-Encoding','chunked')]
        prior=facts();reply=raw_request(client,edge.port,wire('POST','/logout',b'0\r\n\r\n',headers,False));after=facts()
        check(receipt,'raw-complete-chunked-empty-logout',reply[0]==200 and after['closes']==prior['closes']+1 and after['saves']==prior['saves']+1)
    else:
        prefix=b'begin=1'+b''.join(b'&pad'+str(i).encode()+b'='+b'a'*8192 for i in range(1,4))+b'&pad4=';prefix+=b'a'*(cap-len(prefix));assert len(prefix)==cap
        before=facts();reply=raw_request(client,edge.port,wire('POST',path,(hex(cap)[2:]+'\r\n').encode()+prefix+b'\r\n0\r\n\r\n',[*media,('Transfer-Encoding','chunked')],False))
        check(receipt,'raw-complete-chunked-exact-cap-valid',reply[0]==200 and facts()['attempts']==before['attempts']+1)
        refuse('raw-complete-cap-plus-one-never-prefix',wire('POST',path,(hex(cap+1)[2:]+'\r\n').encode()+prefix+b'&\r\n0\r\n\r\n',[*media,('Transfer-Encoding','chunked')],False),[413])
        # Real native flow uses ordinary CA/hostname verification, no ambient browser carrier.
        started=raw_request(client,edge.port,wire('POST','/apple/begin',b'begin=1',[('Content-Type','application/x-www-form-urlencoded')]));check(receipt,'apple-verified-TLS-native-begin',started[0]==200)
        token=private('GET','/fixture/token/apple/valid',headers=[('X-Fixture-Nonce',data(started)['nonce'])]);fields=data(started)
        body=urllib.parse.urlencode({'request_id':fields['request_id'],'request_binding':fields['request_binding'],'identity_token':data(token)['token']}).encode()
        headers=[('Content-Type','application/x-www-form-urlencoded')];before=facts()
        check(receipt,'apple-native-browser-Origin-denied',raw_request(client,edge.port,wire('POST','/apple/complete',body,[*headers,('Origin','https://app.example')]))[0]==403 and facts()['lookups']==before['lookups'])
        done=raw_request(client,edge.port,wire('POST','/apple/complete',body,headers));check(receipt,'apple-verified-TLS-real-validation-session',done[0]==200 and not any(k.lower()=='set-cookie'for k,v in done[1]))
        bearer=[('Authorization','Bearer '+data(done)['session_token'])]
        check(receipt,'apple-native-resource-authorized',raw_request(client,edge.port,wire('GET','/native/account/tenant/alice',headers=bearer))[0]==200)
        check(receipt,'apple-native-replay-refused',raw_request(client,edge.port,wire('POST','/apple/complete',body,headers))[0]==401)
        check(receipt,'apple-native-local-logout',raw_request(client,edge.port,wire('POST','/native/logout',headers=[*headers,*bearer]))[0]==200 and raw_request(client,edge.port,wire('GET','/native/account/tenant/alice',headers=bearer))[0]==401)

def baseline(receipt,profile,private):
    if profile=='logout':
        started=private('POST','/fixture/login');before=data(private('GET','/fixture/control/state'))['shared'];reply=private('POST','/logout?',headers=[('Origin','https://app.example'),('Cookie',cookie(started,'__Host-app-session')),('X-CSRF-Token',data(started)['csrf'])]);after=data(private('GET','/fixture/control/state'))['shared']
        check(receipt,'current-PIN56-direct-bare-query-loss-local-close',reply[0]==200 and after['closes']==before['closes']+1 and after['saves']==before['saves']+1)
    else:
        media=[('Content-Type','application/x-www-form-urlencoded')];started=private('POST','/google/begin',b'begin=1',[*media,('Origin','https://app.example')]);token=private('GET','/fixture/token/google/valid',headers=[('X-Fixture-Nonce',data(started)['nonce'])]);before=data(private('GET','/fixture/state'))
        body=urllib.parse.urlencode({'credential':data(token)['token'],'g_csrf_token':'TEST-ONLY-csrf'}).encode();reply=private('POST','/google/complete?',body,[*media,('Cookie',cookie(started,'__Host-provider-login')+'; g_csrf_token=TEST-ONLY-csrf')]);after=data(private('GET','/fixture/state'))
        check(receipt,'current-PIN56-direct-bare-query-loss-genuine-session',reply[0]==200 and after['lookups']==before['lookups']+1 and after['sessions']==before['sessions']+1)

def browser(receipt,selection,profile,work,output,backend,credential,edge,certificate):
    browser_event_start=len(edge.snapshot()['events']);connect=Connect(edge.port);connect.start();chrome=None;log=(output/'chrome.log').open('w');profile_dir=work/'chrome-profile'
    command=[selection['chrome'],'--headless=new','--user-data-dir='+str(profile_dir),'--remote-debugging-port=0','--remote-debugging-address=127.0.0.1','--proxy-server=http://127.0.0.1:'+str(connect.port),'--ignore-certificate-errors-spki-list='+certificate['leafSpkiSha256Base64'],'--disable-background-networking','--disable-component-update','--disable-default-apps','--no-first-run','--no-default-browser-check','--disable-quic','about:blank']
    before=edge.snapshot()['dispatched']
    with socket.create_connection(('127.0.0.1',connect.port),timeout=3)as refused:
        refused.sendall(b'CONNECT foreign.invalid:443 HTTP/1.1\r\nHost: foreign.invalid:443\r\n\r\n');response=http.client.HTTPResponse(refused);response.begin();response.read()
        check(receipt,'CONNECT-foreign-destination-refused',response.status==403 and edge.snapshot()['dispatched']==before)
    receipt['browserCommand']=command;receipt['browserVersion']=subprocess.check_output([selection['chrome'],'--version'],text=True,timeout=10).strip()
    try:
        chrome=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);end=time.monotonic()+20
        while not(profile_dir/'DevToolsActivePort').exists():
            if chrome.poll()is not None or time.monotonic()>end:raise RuntimeError('Owned Chrome readiness')
            time.sleep(.05)
        lines=(profile_dir/'DevToolsActivePort').read_text().splitlines();configuration={'websocket':'ws://127.0.0.1:'+lines[0]+lines[1],'backend':backend,'credential':credential,'profile':profile}
        environment=dict(os.environ);environment['REVETSEC_EDGE_BROWSER_INPUT']=json.dumps(configuration)
        result=subprocess.run(['node',str(Path(__file__).with_name('browser.mjs'))],env=environment,capture_output=True,text=True,timeout=120)
        # Browser driver emits fixed check names only; never preserve its transport input/protocol.
        observed=json.loads(result.stdout);(output/'BROWSER.json').write_text(json.dumps(observed,indent=2)+'\n');receipt['browser']=observed
        check(receipt,'actual-Chrome-composition',result.returncode==0 and observed['success'])
    finally:
        if chrome is not None:
            try:chrome.wait(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(chrome.pid,signal.SIGTERM)
                try:chrome.wait(timeout=5)
                except subprocess.TimeoutExpired:os.killpg(chrome.pid,signal.SIGKILL);chrome.wait(timeout=5)
            receipt['chromeParentExited']=chrome.poll()is not None
            def members():
                result=subprocess.run(['ps','-axo','pid=,pgid='],capture_output=True,text=True,timeout=5,check=True)
                return [int(parts[0])for line in result.stdout.splitlines()if len(parts:=line.split())==2 and int(parts[1])==chrome.pid]
            remaining=members()
            if remaining:
                try:os.killpg(chrome.pid,signal.SIGTERM)
                except ProcessLookupError:pass
                until=time.monotonic()+3
                while members()and time.monotonic()<until:time.sleep(.05)
                if members():
                    try:os.killpg(chrome.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    time.sleep(.1)
            receipt['chromeOwnedProcessGroupClean']=not members()
        log.close();chrome_log=output/'chrome.log';receipt['chromeLogSha256']=runtime.digest(chrome_log);receipt['chromeLogBytes']=chrome_log.stat().st_size;chrome_log.unlink();receipt['rawChromeLogRemoved']=True;receipt['connectClean']=connect.close();receipt['connectTargets']=list(connect.targets)
        bare=b'/logout?'if profile=='logout'else b'/google/begin?';stripped=bare[:-1];digests=[hashlib.sha256(value).hexdigest()for value in [bare,stripped]]
        candidates=[entry for entry in edge.snapshot()['events'][browser_event_start:]if entry['targetSha256']in digests]
        receipt['browserBareQueryTargetObservation']={'firstMatchingBrowserEvent':candidates[0]if candidates else None,'rawBareTargetObserved':bool(candidates)and candidates[0]['targetSha256']==digests[0],'scope':'browser-only event interval; first matching target is the no-authority GET probe; raw native lane independently proves selected POST guards'}
        check(receipt,'CONNECT-fixture-exact-host-443-only',all(value=='app.example:443'for value in connect.targets)and bool(connect.targets))

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--selected',required=True,type=Path);parser.add_argument('--output',required=True,type=Path);parser.add_argument('--profile',choices=['logout','provider'],required=True);parser.add_argument('--jdk',choices=['21','27'],required=True);args=parser.parse_args();args.output.mkdir(parents=True)
    receipt={'profile':args.profile,'jdk':args.jdk,'checks':[],'success':False,'selectedInputSha256':runtime.digest(args.selected),'productionSourceChanged':False};edge=None;process=None;log=None
    source=Path(__file__).parent;receipt['verificationSource']={path.name:runtime.digest(path)for path in source.iterdir()if path.is_file()and path.suffix in['.py','.mjs','.java']}
    try:
        selection=json.loads(args.selected.read_text())
        for item in selection['artifacts'].values():check(receipt,'selected-artifact-'+Path(item['path']).name,runtime.digest(Path(item['path']))==item['sha256'])
        for key in ['normalReactorResult','sourceManifest']:check(receipt,'selected-'+key,runtime.digest(Path(selection[key]['path']))==selection[key]['sha256'])
        with tempfile.TemporaryDirectory(prefix='revetsec-edge-owned-')as temporary:
            work=Path(temporary);java=Path('/Users/agents/Java/amazon-corretto-'+args.jdk+'.jdk/Contents/Home')
            process,log,port,credential,private,identities=runtime.prepare(args.selected,args.profile,work,java);receipt['runtime']=identities
            server,client,certificate=certificates.prepare(work/'keys',args.output/'certificates');receipt['certificate']=certificate
            edge=Edge(server,port,credential,args.profile);edge.start()
            try:
                baseline(receipt,args.profile,private);normal_tls(receipt,client,edge);native_matrix(receipt,args.profile,client,edge,private);browser(receipt,selection,args.profile,work,args.output,port,credential,edge,certificate)
                receipt['success']=True
            finally:
                receipt['edge']=edge.snapshot();receipt['edgeClean']=edge.close();edge=None
                process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                receipt['backendClean']=process.poll()is not None;log.close();process=None;log=None
                # Fixture logs may contain provider material only on unexpected failure: never archive them.
            receipt['privateRuntimeRemovedAfterContext']=True
        check(receipt,'owned-temporary-runtime-and-keys-removed',not work.exists())
    except BaseException as failure:
        receipt['failure']={'type':type(failure).__name__,'check':str(failure)if isinstance(failure,AssertionError)else'preparation-or-transport-failure'}
    finally:
        if edge is not None:receipt['edgeClean']=edge.close()
        if process is not None:
            process.terminate();process.wait(timeout=10);receipt['backendClean']=True
        if log is not None:log.close()
        receipt['finishedSources']={path.name:runtime.digest(path)for path in source.iterdir()if path.is_file()and path.suffix in['.py','.mjs','.java']}
        receipt['sourcesStable']=receipt['finishedSources']==receipt['verificationSource']
        (args.output/'RESULT.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return 0 if receipt['success']and receipt.get('sourcesStable')and receipt.get('edgeClean')and receipt.get('backendClean')and receipt.get('connectClean')and receipt.get('chromeOwnedProcessGroupClean')else 1
if __name__=='__main__':raise SystemExit(main())
