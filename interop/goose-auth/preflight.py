#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
"""Synthetic Goose contract preflight. Never qualifies a real issuer/client workflow."""
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import subprocess
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import urlopen

CLIENT_ID = 'https://goose-docs.ai/oauth/client-metadata.json'
VERSION = '2025-11-25'


def run_case(mode):
    facts = {'mode': mode, 'browserUsed': False, 'syntheticIssuer': True, 'events': []}
    state = {}
    sockets = []
    lock = threading.Lock()
    def event(**row):
        with lock:
            if len(facts['events']) >= 64:
                raise RuntimeError('EVENT_BOUND')
            facts['events'].append(row)
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *args):
            pass
        def reply(self, code, body=None, headers=None):
            data = json.dumps(body).encode() if body is not None else b''
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(data)
        def do_GET(self):
            url = urlsplit(self.path)
            if url.path == '/.well-known/oauth-protected-resource/mcp':
                event(kind='resource-metadata')
                return self.reply(200, dict(resource=resource, authorization_servers=[origin], scopes_supported=['mcp:discover']))
            if url.path == '/.well-known/oauth-authorization-server':
                event(kind='issuer-metadata')
                return self.reply(200, dict(issuer=origin, authorization_endpoint=origin+'/authorize', token_endpoint=origin+'/token', scopes_supported=['mcp:discover'], response_types_supported=['code'], grant_types_supported=['authorization_code','refresh_token'], token_endpoint_auth_methods_supported=['none'], code_challenge_methods_supported=['S256'], client_id_metadata_document_supported=True))
            if url.path == '/authorize':
                q = parse_qs(url.query)
                state.update(redirect=q['redirect_uri'][0], challenge=q['code_challenge'][0], code=os.urandom(24).hex())
                return self.reply(302, headers={'Location': state['redirect']+'?'+urlencode(dict(code=state['code'],state=q['state'][0],iss=origin))})
            return self.reply(405 if url.path == '/mcp' else 404)
        def do_POST(self):
            length = int(self.headers.get('Content-Length', '0'))
            if length > 65536:
                return self.reply(413)
            body = self.rfile.read(length)
            if self.path == '/token':
                q = parse_qs(body.decode()); grant = q.get('grant_type', [''])[0]
                row = dict(kind='token', grant=grant if grant in ['authorization_code','refresh_token'] else 'OTHER', clientMatches=q.get('client_id')==[CLIENT_ID], resourceMatches=q.get('resource')==[resource], noAmbientCredentials='Authorization' not in self.headers and 'Cookie' not in self.headers and 'client_secret' not in q)
                if grant == 'authorization_code':
                    verifier=q.get('code_verifier',[''])[0];challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
                    row.update(codeMatches=q.get('code')==[state.get('code')], redirectMatches=q.get('redirect_uri')==[state.get('redirect')], pkceMatches=challenge==state.get('challenge'))
                if grant == 'refresh_token':
                    row['refreshMatches']=q.get('refresh_token')==[state.get('refresh')]
                event(**row)
                if mode == 'code-timeout' or mode == 'refresh-timeout' and grant == 'refresh_token':
                    started=time.monotonic();sockets.append(self.connection)
                    while time.monotonic()-started < 40:
                        ready,_,_=select.select([self.connection],[],[],0.1)
                        if ready and self.connection.recv(1, socket.MSG_PEEK) == b'':
                            facts['oauthHttpDisconnectMs']=round((time.monotonic()-started)*1000)
                            return
                    return
                state['access']=os.urandom(24).hex();state['refresh']=os.urandom(24).hex()
                return self.reply(200, dict(access_token=state['access'],refresh_token=state['refresh'],token_type='Bearer',expires_in=1 if mode=='refresh-timeout' else 120,scope='mcp:discover'), {'Cache-Control':'no-store'})
            if self.path != '/mcp':
                return self.reply(404)
            data=json.loads(body);method=data.get('method');ident=data.get('id')
            event(kind='mcp',method=method if method in ['initialize','notifications/initialized','tools/list','tools/call','notifications/cancelled','logging/setLevel','resources/list','prompts/list'] else 'OTHER',protocolHeader=self.headers.get('MCP-Protocol-Version') if self.headers.get('MCP-Protocol-Version') in [VERSION] else 'ABSENT_OR_OTHER',authenticated=bool(state.get('access')) and self.headers.get('Authorization')=='Bearer '+state['access'])
            if mode != 'transport' and self.headers.get('Authorization')!='Bearer '+state.get('access','unissued'):
                return self.reply(401,headers={'WWW-Authenticate':'Bearer resource_metadata="'+origin+'/.well-known/oauth-protected-resource/mcp", scope="mcp:discover"'})
            if ident is None:
                return self.reply(202)
            if method == 'initialize':
                facts['requestedVersionMatches']=data.get('params',{}).get('protocolVersion')==VERSION
                result=dict(protocolVersion=VERSION,serverInfo=dict(name='Synthetic preflight',version='1'),capabilities=dict(tools={}))
            elif method == 'tools/list':
                result=dict(tools=[dict(name='preflight',description='Fixed synthetic control',inputSchema=dict(type='object',properties={}))])
            elif method == 'tools/call':
                result=dict(content=[dict(type='text',text='SYNTHETIC_PREFLIGHT_OK')],isError=False)
            elif method == 'resources/list':
                result=dict(resources=[])
            elif method == 'prompts/list':
                result=dict(prompts=[])
            else:
                result={}
            return self.reply(200,dict(jsonrpc='2.0',id=ident,result=result))
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True
    origin='http://127.0.0.1:'+str(server.server_port);resource=origin+'/mcp'
    serving=threading.Thread(target=server.serve_forever,daemon=True);serving.start()
    with tempfile.TemporaryDirectory(prefix='goose-preflight-') as directory:
        private=Path(directory);script=private/'script.json';script.write_text(json.dumps(dict(protocolVersion=VERSION,steps=[dict(action='listTools'),dict(action='callTool',name='preflight',arguments={})])))
        env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':str(private),'XDG_CONFIG_HOME':str(private/'config'),'XDG_DATA_HOME':str(private/'data'),'XDG_STATE_HOME':str(private/'state'),'XDG_CACHE_HOME':str(private/'cache'),'BROWSER':'/bin/true','GOOSE_DISABLE_TELEMETRY':'true','GOOSE_DISABLE_KEYRING':'1','GOOSE_PATH_ROOT':str(private),'GOOSE_OAUTH_CALLBACK_TIMEOUT_SECONDS':'2' if mode=='callback-timeout' else '300'}
        child=subprocess.Popen(['/client/goose','mcp-probe',resource,'--script',str(script)],cwd=private,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        def read_errors():
            seen=False
            for line in iter(child.stderr.readline,b''):
                # Raw URLs/logs remain in memory; keep only structural booleans.
                if seen or not line.strip().startswith((origin+'/authorize?').encode()):continue
                seen=True;url=line.decode().strip();q=parse_qs(urlsplit(url).query);redirect=urlsplit(q.get('redirect_uri',[''])[0])
                facts['authorization']={'clientMatches':q.get('client_id')==[CLIENT_ID],'resourceMatches':q.get('resource')==[resource],'s256':q.get('code_challenge_method')==['S256'] and bool(re.fullmatch(r'[A-Za-z0-9_-]{43}',q.get('code_challenge',[''])[0])),'nativeIpCallback':redirect.scheme=='http' and redirect.hostname=='127.0.0.1' and bool(redirect.port) and redirect.path=='/oauth_callback','hasState':bool(q.get('state'))}
                if not all(facts['authorization'].values()):return
                if mode!='callback-timeout':
                    try:
                        with urlopen(url,timeout=5) as response:
                            facts['syntheticNativeCallbackCompleted']=response.status==200
                    except Exception:
                        facts['callbackDriverFailure']=True
        reader=threading.Thread(target=read_errors,daemon=True);reader.start();started=time.monotonic()
        try:
            # stderr has its own reader; stdout is bounded by fixed synthetic results.
            child.wait(timeout=40);facts['exit']=child.returncode;facts['elapsedMs']=round((time.monotonic()-started)*1000);out=child.stdout.read(65537);facts['stdoutBounded']=len(out)<=65536
            facts['syntheticToolResult']=False
            if child.returncode==0:
                parsed=json.loads(out);facts['syntheticToolResult']=any(r.get('action')=='callTool' and r.get('result',{}).get('content')==[dict(type='text',text='SYNTHETIC_PREFLIGHT_OK')] for r in parsed.get('results',[]))
        except subprocess.TimeoutExpired:
            facts['harnessDeadlineExceeded']=True
        finally:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            child.wait(timeout=5);reader.join(timeout=6)
            facts['clientRemoved']=child.poll() is not None;facts['readerRemoved']=not reader.is_alive()
            for connection in sockets:
                try:connection.close()
                except OSError:pass
            server.shutdown();server.server_close();serving.join(timeout=2)
            facts['serverRemoved']=not serving.is_alive();state.clear()
    facts['privateStateRemoved']=not private.exists()
    return facts


def validate(cases):
    checks=[]
    def add(name,value):checks.append(dict(name=name,status='PASS' if value else 'FAIL'))
    modes=['transport','callback-timeout','code-timeout','refresh-timeout']
    add('exact-four-synthetic-cases',len(cases)==4 and [c.get('mode') for c in cases]==modes)
    for c in cases:
        mode=c.get('mode','OTHER');events=c.get('events',[])
        add(mode+'-bounded-cleanup',0<len(events)<=64 and c.get('clientRemoved') is True and c.get('serverRemoved') is True and c.get('privateStateRemoved') is True and c.get('readerRemoved') is True and c.get('stdoutBounded') is True and not c.get('harnessDeadlineExceeded') and not c.get('callbackDriverFailure'))
        add(mode+'-synthetic-only',c.get('syntheticIssuer') is True and c.get('browserUsed') is False)
        if mode=='transport':
            add('selected-version-and-tool-complete',c.get('exit')==0 and c.get('requestedVersionMatches') is True and c.get('syntheticToolResult') is True)
            post=[e for e in events if e.get('kind')=='mcp' and e.get('method') in ['notifications/initialized','tools/list','tools/call']]
            add('subsequent-requests-carry-negotiated-header',all(any(e.get('method')==method for e in post) for method in ['notifications/initialized','tools/list','tools/call']) and all(e.get('protocolHeader')==VERSION for e in post))
        else:
            add(mode+'-cimd-native-s256-resource',set(c.get('authorization',{}))=={'clientMatches','resourceMatches','s256','nativeIpCallback','hasState'} and all(value is True for value in c['authorization'].values()) and any(e.get('kind')=='issuer-metadata' for e in events) and any(e.get('kind')=='resource-metadata' for e in events))
            tokens=[e for e in events if e.get('kind')=='token']
            if mode=='callback-timeout':
                add('callback-two-second-deadline',c.get('exit')!=0 and not tokens and 1800<=c.get('elapsedMs',0)<=7000)
            else:
                codes=[e for e in tokens if e.get('grant')=='authorization_code'];refresh=[e for e in tokens if e.get('grant')=='refresh_token']
                add(mode+'-actual-synthetic-code-bindings',c.get('syntheticNativeCallbackCompleted') is True and len(codes)==1 and all(codes[0].get(k) is True for k in ['clientMatches','resourceMatches','noAmbientCredentials','codeMatches','redirectMatches','pkceMatches']))
                add(mode+'-oauth-thirty-second-deadline',c.get('exit')!=0 and 28500<=c.get('oauthHttpDisconnectMs',0)<=35000 and 28500<=c.get('elapsedMs',0)<=38000)
                add(mode+'-expected-grants',not refresh if mode=='code-timeout' else len(refresh)==1 and all(refresh[0].get(k) is True for k in ['clientMatches','resourceMatches','noAmbientCredentials','refreshMatches']))
    return checks


def validate_report(report):
    checks=validate(report.get('cases',[]));isolation=report.get('isolation',{})
    isolated=set(isolation)=={'uid','zeroEffectiveCapabilities','noIpv4Route','clientReadOnly','suiteReadOnly'} and isolation.get('uid')==1001 and all(v is True for k,v in isolation.items() if k!='uid')
    checks.append(dict(name='nonroot-network-none-capability-and-mount-controls',status='PASS' if isolated else 'FAIL'))
    scoped=report.get('fullClientWorkflowQualified') is False and report.get('releaseQualification')=='OPEN' and report.get('realIssuerExercised') is False and report.get('modelAccountUsed') is False
    checks.append(dict(name='synthetic-only-and-open-qualification',status='PASS' if scoped else 'FAIL'))
    return checks


if __name__=='__main__':
    cases=[run_case(mode) for mode in ['transport','callback-timeout','code-timeout','refresh-timeout']]
    isolation=dict(uid=os.getuid(),zeroEffectiveCapabilities=bool(re.search(r'^CapEff:\s+0+$',Path('/proc/self/status').read_text(),re.M)),noIpv4Route=len(Path('/proc/net/route').read_text().splitlines())==1,clientReadOnly=bool(os.statvfs('/client').f_flag & os.ST_RDONLY),suiteReadOnly=bool(os.statvfs('/suite').f_flag & os.ST_RDONLY))
    result=dict(isolation=isolation,cases=cases,fullClientWorkflowQualified=False,releaseQualification='OPEN',modelAccountUsed=False,realIssuerExercised=False)
    checks=validate_report(result);result.update(status='PASS' if all(c['status']=='PASS' for c in checks) else 'FAIL',checks=checks)
    Path('/evidence/RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(status=result['status'],checks=len(checks))))
    raise SystemExit(0 if result['status']=='PASS' else 1)
