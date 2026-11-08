# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
"""Actual Soklet/raw HTTP component observations; profile gaps remain explicit."""
import concurrent.futures,hashlib,html.parser,http.client,json,socket,threading,time,urllib.parse
from types import SimpleNamespace

def exercise(port,credential,process,receipt,delivery='form',padding=0,metadata_fault='outage',fault_only=False,framing_only=False):
    args=SimpleNamespace(delivery=delivery,padding=padding,metadata_fault=metadata_fault,fixture_supplement=True,fault_only=fault_only)
    current='readiness'
    receipt['notApplicableServletStreamCells']=['Soklet supplies a complete Request body value, not a Servlet InputStream; stream IOException injection is not a legal carrier seam. Real truncated framing is checked separately.']
    request_lock = threading.Lock()
    def request(method, path, body=b"", headers=(), authenticated=True, chunked=False):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.putrequest(method, path if path.startswith("/fixture/") else "/logout"+path, skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", "app.example")
            if authenticated: connection.putheader("X-Fixture-Credential", credential)
            for name, value in headers: connection.putheader(name, value)
            if chunked: connection.putheader("Transfer-Encoding", "chunked")
            elif body: connection.putheader("Content-Length", str(len(body)))
            connection.endheaders()
            if chunked:
                connection.send((f"{len(body):x}\r\n").encode()+body+b"\r\n0\r\n\r\n")
            elif body: connection.send(body)
            response = connection.getresponse()
            payload = response.read(131073)
            assert len(payload) <= 131072, "bounded-response"
            fields = response.getheaders()
            with request_lock:
                receipt["requests"].append({"method":method,"path":path.partition("?")[0],"querySha256":hashlib.sha256(path.partition("?")[2].encode()).hexdigest(),"status":response.status,
                    "bodySha256":hashlib.sha256(payload).hexdigest(),
                    "cookieCount":sum(name.lower()=="set-cookie" for name,value in fields)})
            return response.status, fields, payload
        finally: connection.close()

    def check(name, condition, observed=None):
        nonlocal current
        current = name
        receipt["checks"].append({"name": name, "passed": bool(condition), "observed": observed})
        assert condition, name

    def data(reply): return json.loads(reply[2])
    def cookies(reply): return [v for k,v in reply[1] if k.lower()=="set-cookie"]
    def cookie(reply,name):
        found=[v.split(";",1)[0] for v in cookies(reply) if v.startswith(name+"=")]
        assert len(found)==1,"one-cookie-"+name
        return found[0]
    def header(reply,name):
        found=[v for k,v in reply[1] if k.lower()==name]
        assert len(found)==1,"one-header-"+name
        return found[0]
    def state():
        value=data(request('GET','/fixture/control/state'));value.update(value.pop('shared'));return value
    def control(command):return request('GET','/fixture/control/'+command)
    def bootstrap():
        reply=request('POST','/fixture/login',b'begin=1',[("Content-Type","application/x-www-form-urlencoded")]);assert reply[0]==200,'genuine-fixture-login'
        assert data(reply)['genuine_authentication'] is True,'actual-op-pkce-signature-before-session'
        return {'cookie':cookie(reply,'__Host-app-session'),'csrf':data(reply)['csrf']}
    def live(browser):return data(request('GET','/fixture/live',headers=[('Cookie',browser['cookie'])]))['live']
    def start(browser,path='',body=b'',extra=(),method='POST',headers_override=None,chunked=False):
        headers=headers_override if headers_override is not None else [('Cookie',browser['cookie']),('X-CSRF-Token',browser['csrf']),('Origin','https://app.example')]
        return request(method,path,body,[*headers,*extra],chunked=chunked)
    def clear_cookie(reply,name):return any(c.startswith(name+'=;') and 'Max-Age=0' in c for c in cookies(reply))
    def no_delivery(reply):return not any(k.lower()=='location' for k,v in reply[1]) and b'id_token_hint' not in reply[2] and not any(c.startswith('__Host-rp-logout=') and not c.startswith('__Host-rp-logout=;') for c in cookies(reply))
    class Form(html.parser.HTMLParser):
        def __init__(self):super().__init__();self.action=None;self.fields={}
        def handle_starttag(self,tag,attrs):
            values=dict(attrs)
            if tag=='form':self.action=values.get('action')
            if tag=='input' and 'name' in values:self.fields[values['name']]=values.get('value','')
    def prepared(reply):
        if args.delivery=='form':
            assert reply[0]==200,'form-delivered';parsed=Form();parsed.feed(reply[2].decode());action=parsed.action;fields=parsed.fields
        else:
            assert reply[0]==303,'trusted-get-delivered';uri=urllib.parse.urlsplit(header(reply,'location'));action=urllib.parse.urlunsplit((uri.scheme,uri.netloc,uri.path,'',''));fields=dict(urllib.parse.parse_qsl(uri.query,strict_parsing=True));assert len(header(reply,'location'))<=4096,'bounded-get-uri'
        uri=urllib.parse.urlsplit(action);assert uri.scheme=='http' and uri.hostname=='127.0.0.1' and uri.path=='/logout' and uri.port,'owned-synthetic-provider-only'
        assert fields['post_logout_redirect_uri']=='https://app.example/logout/callback' and len(fields['state'])==43 and len(fields['id_token_hint'])>100,'genuine-hint-and-fixed-correlation'
        return {'pending':cookie(reply,'__Host-rp-logout'),'state':fields['state'],'action':action,'fields':fields}
    def callback(tx,query=None,extra=(),newer=None):
        return request('GET','/callback?'+(query if query is not None else urllib.parse.urlencode({'state':tx['state']})),headers=[('Cookie',tx['pending']+(';' + newer['cookie'] if newer else '')),*extra])
    def redacted(reply):return all(value not in reply[2] for value in [b'TEST-ONLY-close-secret',b'TEST-ONLY-store-secret',b'id_token_hint'])
    deadline=time.monotonic()+12
    while True:
        try:
            if request('GET','/fixture/control/state')[0]==200:break
        except (OSError,http.client.HTTPException):pass
        if time.monotonic()>deadline:raise RuntimeError('Selected Soklet startup failed')
        time.sleep(.05)
    check('actual-selected-core-common-fixture-origins',state()['origin_verified'])
    check('fixture-controls-require-credential',request('GET','/fixture/control/state',authenticated=False)[0]==401)
    browser=bootstrap();before=state()
    check('genuine-oidc-login-before-fixture-session',live(browser) and before['token_posts']==1)
    if framing_only:
        def truncated(path,headers):
            target=('/logout'+path).encode('ascii');wire=(b'GET 'if path.startswith('/callback')else b'POST ')+target+b' HTTP/1.1\r\nHost: app.example\r\nConnection: close\r\nContent-Length: 1\r\nX-Fixture-Credential: '+credential.encode('ascii')+b'\r\n'
            for name,value in headers:wire+=name.encode('ascii')+b': '+value.encode('ascii')+b'\r\n'
            wire+=b'\r\n';response=b''
            with socket.create_connection(('127.0.0.1',port),timeout=5)as connection:
                connection.sendall(wire);connection.shutdown(socket.SHUT_WR)
                while True:
                    part=connection.recv(8192)
                    if not part:break
                    response+=part
                    assert len(response)<=131072,'bounded-truncated-response'
            receipt.setdefault('truncatedFramingObservations',[]).append({'path':path.partition('?')[0],'querySha256':hashlib.sha256(path.partition('?')[2].encode()).hexdigest(),'responseSha256':hashlib.sha256(response).hexdigest(),'responseBytes':len(response),'cookieClearingPromise':False})
            return response
        before=state();response=truncated('',[('Cookie',browser['cookie']),('X-CSRF-Token',browser['csrf']),('Origin','https://app.example')]);after=state()
        check('truncated-start-before-local-close',live(browser)and after['closes']==before['closes']and after['saves']==before['saves']and b'id_token_hint'not in response and b'Location:'not in response)
        tx=prepared(start(browser));newer=bootstrap();before=state();response=truncated('/callback?state='+tx['state'],[('Cookie',tx['pending']+';'+newer['cookie'])]);after=state()
        check('truncated-callback-not-valid-empty-body-prefix',live(newer)and after['consumes']==before['consumes']and b'id_token_hint'not in response and b'Location:'not in response)
        check('complete-callback-still-correlates-once',callback(tx,newer=newer)[0]==200 and callback(tx,newer=newer)[0]==400 and live(newer))
        receipt['finalState']=state();receipt['success']=True;return receipt
    if args.fault_only:
        control('metadata/'+args.metadata_fault);before=state();reply=start(browser);after=state()
        check('actual-metadata-'+args.metadata_fault+'-lookup-local-first',reply[0]==503 and not live(browser) and after['saves']==before['saves'] and after['discovery']==before['discovery']+1 and clear_cookie(reply,'__Host-app-session') and no_delivery(reply),{'status':reply[0],'beforeDiscovery':before['discovery'],'afterDiscovery':after['discovery']})
        receipt['finalState']=after;receipt['success']=True;return receipt

    if args.padding:
        reply=start(browser)
        if args.delivery=='get':check('get-hint-uri-overflow-local-first-no-save',reply[0]==503 and not live(browser) and state()['saves']==before['saves'] and clear_cookie(reply,'__Host-app-session') and no_delivery(reply))
        else:
            tx=prepared(reply);check('large-form-hint-remains-bounded-and-correlated',len(reply[2])>6000 and len(reply[2])<131072 and not live(browser) and callback(tx)[0]==200)
    else:
        gap=bootstrap();gap_reply=start(gap,'?')
        check('documented-bare-start-query-information-loss',gap_reply[0]==(200 if args.delivery=='form' else 303) and not live(gap),gap_reply[0])
        receipt['externalProfileGaps']=[{'id':'SOKLET-EMPTY-START-QUERY','qualified':False,'required':'Actual authenticated HTTPS edge rejects every raw query delimiter on POST/logout before Soklet parsing','observed':'Selected PIN56 drops barequestionmark; valid privatebackend request closes its local session without the requirededge'}]
        cases=[('get-method','',b'',(),'GET',None,405),('head-method','',b'',(),'HEAD',None,405),('query','?state=attacker',b'',(),'POST',None,400),('body','',b'x',(),'POST',None,400),('body-cap-plus-one','',b'x'*4097,(),'POST',None,413),('wrong-origin','',b'',(),'POST',[('Cookie',browser['cookie']),('X-CSRF-Token',browser['csrf']),('Origin','https://wrong.invalid')],403),('null-origin','',b'',(),'POST',[('Cookie',browser['cookie']),('X-CSRF-Token',browser['csrf']),('Origin','null')],403),('missing-origin','',b'',(),'POST',[('Cookie',browser['cookie']),('X-CSRF-Token',browser['csrf'])],403),('wrong-csrf','',b'',(),'POST',[('Cookie',browser['cookie']),('X-CSRF-Token','A'*43),('Origin','https://app.example')],403),('duplicate-csrf','',b'',(('X-CSRF-Token',browser['csrf']),),'POST',None,400),('duplicate-origin','',b'',(('Origin','https://app.example'),),'POST',None,403),('duplicate-cookie','',b'',(('Cookie',browser['cookie']),),'POST',None,400),('authorization','',b'',(('Authorization','Bearer invalid'),),'POST',None,400),('duplicate-media','',b'',(('Content-Type','application/x-www-form-urlencoded'),('Content-Type','application/x-www-form-urlencoded')),'POST',None,415),('bad-media','',b'',(('Content-Type','application/json'),),'POST',None,415),('insecure-connector','',b'',(('X-Fixture-Carrier','insecure'),),'POST',None,400),('header-individual-budget','',b'',(('X-Large','x'*4097),),'POST',None,400),('header-total-budget','',b'',tuple(('X-Large-'+str(i),'x'*3000) for i in range(3)),'POST',None,400),('header-occurrence-budget','',b'',tuple(('X-Duplicate','x') for _ in range(33)),'POST',None,400),('encoded-route','/%63allback',b'',(),'POST',None,400)]
        for name,path,body,extra,method,headers_override,status in cases:
            before=state();reply=start(browser,path,body,extra,method,headers_override)
            check('carrier-'+name+'-before-local-close',(reply[0]==status or name in ['header-total-budget','header-occurrence-budget','encoded-route'] and reply[0] in [400,404,405,413,414,431]) and live(browser) and state()['closes']==before['closes']+(1 if name=='wrong-csrf' else 0) and state()['saves']==before['saves'] and no_delivery(reply),reply[0])
            if method=='HEAD':check('head-suppresses-error-body',reply[2]==b'')
        before=state();reply=start(browser,body=b'x'*4097,chunked=True)
        check('chunked-overflow-not-valid-prefix',reply[0]==413 and live(browser) and state()['closes']==before['closes'] and no_delivery(reply))
        before=state();reply=start(browser,extra=[('Host','app.example')])
        check('container-physical-host-duplicate-refuses',reply[0]==400 and live(browser) and state()['closes']==before['closes'])
        before=state();reply=start(browser);tx=prepared(reply)
        check('local-first-delivery-after-genuine-session-close',not live(browser) and state()['closes']==before['closes']+1 and state()['saves']==before['saves']+1 and state()['logout_posts']==before['logout_posts'])
        check('separate-session-and-pending-cookie-fields',len(cookies(reply))==2 and clear_cookie(reply,'__Host-app-session') and all('Secure' in c and 'HttpOnly' in c and 'Path=/' in c and 'SameSite=Lax' in c for c in cookies(reply)))
        check('no-referrer-no-store-bounded-emission',header(reply,'cache-control')=='no-store' and header(reply,'referrer-policy')=='no-referrer' and int(header(reply,'content-length'))==len(reply[2]))
        if args.delivery=='form':check('fixed-origin-csp-escaped-form',b'<form method="post"' in reply[2] and 'form-action http://127.0.0.1:' in header(reply,'content-security-policy'))
        before=state();reply=start(browser)
        check('closed-session-no-retry-or-reattach',reply[0]==403 and not live(browser) and state()['saves']==before['saves'] and no_delivery(reply))
        newer=bootstrap();before=state();reply=callback(tx,newer=newer)
        check('state-only-return-is-correlation-not-session-proof',reply[0]==200 and b'provider-session termination is not confirmed' in reply[2] and clear_cookie(reply,'__Host-rp-logout') and not clear_cookie(reply,'__Host-app-session') and live(newer))
        check('pending-consumed-once-no-provider-call',state()['consumes']==before['consumes']+1 and state()['logout_posts']==before['logout_posts'])
        check('return-replay-refused-newer-session-survives',callback(tx,newer=newer)[0]==400 and live(newer))
        for name,query,body,extra,status in [('missing-state','',b'',(),400),('bare-query','',b'',(),400),('duplicate-state','state='+tx['state']+'&state='+tx['state'],b'',(),400),('encoded-duplicate-state','state='+tx['state']+'&%73tate='+tx['state'],b'',(),400),('extra-credential','state='+tx['state']+'&id_token=untrusted',b'',(),400),('body','state='+tx['state'],b'x',(),400),('overflow','state='+tx['state'],b'x'*4097,(),413),('header-budget','state='+tx['state'],b'',(('X-Large','x'*4097),),400)]:
            before=state();reply=request('GET','/callback?'+query,body,[('Cookie',tx['pending']+';'+newer['cookie']),*extra])
            if name=='overflow' and reply[0]==413 and not cookies(reply):
                check('parser-callback-overflow-before-Request-no-clearing-response',live(newer) and state()['consumes']==before['consumes'] and no_delivery(reply),{'status':413,'cookieCount':0})
                receipt.setdefault('parserBoundaryObservations',[]).append({'id':'SOKLET-PARSER-BODY-413','qualifiedClearingPromise':False,'observed':'PIN56 rejects body4097 before Request construction; no application cookie-clearing response can be delivered','handlerTooLargeControl':'Separate directRequest control clearspendingcookie'})
                continue
            check('callback-'+name+'-clears-only-pending',reply[0]==status and clear_cookie(reply,'__Host-rp-logout') and not clear_cookie(reply,'__Host-app-session') and live(newer) and no_delivery(reply),reply[0])
        # An invalid browser binding is not correlation and cannot establish provider termination.
        fresh=bootstrap();started=start(fresh);pending=prepared(started);before=state()
        wrong=dict(pending);wrong['pending']='__Host-rp-logout='+'B'*42+'A';reply=callback(wrong,newer=newer)
        check('wrong-browser-binding-no-provider-correlation',reply[0]==400 and live(newer) and no_delivery(reply))
        check('exact-browser-binding-can-correlate',callback(pending,newer=newer)[0]==200 and live(newer))
        for mode in ['throw-before','throw-after','unavailable-before','unavailable-after','late','interrupt']+(['checked-interrupt','checked-io-interrupt','checked-timeout'] if args.fixture_supplement else []):
            control('reset-modes');fresh=bootstrap();control('close/'+mode);before=state();reply=start(fresh);after=state()
            expected_live=mode in ['throw-before','unavailable-before']
            check('close-'+mode+'-no-provider-or-retry',reply[0]==503 and live(fresh)==expected_live and after['closes']==before['closes']+1 and after['saves']==before['saves'] and clear_cookie(reply,'__Host-app-session') and no_delivery(reply) and redacted(reply),reply[0])
            if mode.startswith('checked-'):check('checked-close-thread-state-'+mode,after['last_handler_interrupt_set']==(mode!='checked-timeout') and (mode=='checked-timeout' or after['handler_interrupt_left_set'] and after['handler_cancel_no_publication']))
        for mode in ['UNAVAILABLE','CAPACITY_REFUSED','ALREADY_PRESENT','INDETERMINATE','throw-before','throw-after','null','late','interrupt']:
            control('reset-modes');fresh=bootstrap();control('save/'+mode);before=state();reply=start(fresh);after=state()
            check('save-'+mode+'-local-ended-no-success',reply[0]==503 and not live(fresh) and after['closes']==before['closes']+1 and after['saves']==before['saves']+1 and clear_cookie(reply,'__Host-app-session') and clear_cookie(reply,'__Host-rp-logout') and no_delivery(reply) and redacted(reply),reply[0])
        for mode in ['throw-before','throw-after','null','late','interrupt']:
            control('reset-modes');fresh=bootstrap();pending=prepared(start(fresh));control('consume/'+mode);before=state();reply=callback(pending,newer=newer);after=state()
            check('consume-'+mode+'-no-success-or-session-revival',reply[0] in [400,503] and not live(fresh) and live(newer) and after['consumes']==before['consumes']+1 and clear_cookie(reply,'__Host-rp-logout') and not clear_cookie(reply,'__Host-app-session') and no_delivery(reply) and redacted(reply),reply[0])
        check('explicit-fixture-cancellation-observed-before-clear',state()['interrupt_observed'] and state()['handler_interrupt_left_set'] and state()['handler_cancel_no_publication'])
        if args.fixture_supplement:
            def wait_blocked(count):
                until=time.monotonic()+2
                while time.monotonic()<until:
                    value=state();receipt['lastBlockedState']=value
                    if value['blocked_entered']>=count:return
                    time.sleep(.01)
                raise AssertionError('bounded-fixture-latch-entered')
            control('reset-modes');browsers=[bootstrap() for _ in range(9)];before=state();control('block-save')
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
                held=[workers.submit(start,browser) for browser in browsers[:8]]
                try:
                    wait_blocked(8);busy=start(browsers[8]);during=state()
                    check('ninth-start-before-close-or-cookie-effect',busy[0]==503 and live(browsers[8]) and not cookies(busy) and during['closes']==before['closes']+8 and during['saves']==before['saves']+8 and during['block_peak']==8)
                finally:control('release')
                done=[future.result(timeout=5) for future in held]
            check('eight-admitted-saves-deliver-after-release',all(reply[0]==(200 if args.delivery=='form' else 303) for reply in done) and all(not live(browser) for browser in browsers[:8]) and state()['saves']==before['saves']+8)
            check('ninth-start-can-explicitly-run-after-permit-return',start(browsers[8])[0]==(200 if args.delivery=='form' else 303) and not live(browsers[8]) and state()['saves']==before['saves']+9)
            control('reset-modes');transactions=[prepared(start(bootstrap())) for _ in range(9)];fresh=bootstrap();before=state();control('block-consume')
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
                held=[workers.submit(callback,tx) for tx in transactions[:8]]
                try:
                    wait_blocked(8);busy=callback(transactions[8],newer=newer);during=state()
                    check('ninth-callback-before-consume-clears-only-pending',busy[0]==503 and during['consumes']==before['consumes']+8 and clear_cookie(busy,'__Host-rp-logout') and not clear_cookie(busy,'__Host-app-session') and live(newer))
                    refused=start(fresh);check('callbacks-share-admission-with-starts',refused[0]==503 and live(fresh) and not cookies(refused) and state()['closes']==before['closes'])
                finally:control('release')
                done=[future.result(timeout=5) for future in held]
            check('eight-admitted-returns-correlate-after-release',all(reply[0]==200 for reply in done) and state()['consumes']==before['consumes']+8)
            check('ninth-return-explicit-after-permit-return',callback(transactions[8],newer=newer)[0]==200 and live(newer) and state()['consumes']==before['consumes']+9)
            control('reset-modes');tx=prepared(start(bootstrap()));before=state();control('block-consume')
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
                held=[workers.submit(callback,tx) for _ in range(2)]
                try:wait_blocked(2)
                finally:control('release')
                done=[future.result(timeout=5) for future in held]
            check('duplicate-return-race-atomic-one-use',sorted(reply[0] for reply in done)==[200,400] and state()['consumes']==before['consumes']+2 and live(newer))
        control('reset-modes');fresh=bootstrap();pending=prepared(start(fresh));control('clock/expiry');reply=callback(pending,newer=newer)
        check('expired-return-no-termination-or-local-revival',reply[0]==400 and not live(fresh) and live(newer) and no_delivery(reply))
        control('reset-modes');fresh=bootstrap();control('metadata/'+args.metadata_fault);before=state();reply=start(fresh)
        check('late-metadata-refresh-withholds-after-local-close',reply[0]==503 and not live(fresh) and state()['saves']==before['saves'] and clear_cookie(reply,'__Host-app-session') and no_delivery(reply) and redacted(reply),reply[0])

    receipt['finalState']=state();receipt['success']=True;return receipt
