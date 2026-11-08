# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
"""Verification-only bounded HTTP/1 TLS edge. Not a general deployment proxy or trust service."""
from dataclasses import dataclass
import base64
import hashlib
import http.client
import re
import socket
import socketserver
import ssl
import threading
import time
import urllib.parse

class Refused(Exception):
    def __init__(self,status,reason,target=b''):self.status=status;self.reason=reason;self.target=target

@dataclass(frozen=True)
class Request:
    method:str
    target:bytes
    headers:tuple
    body:bytes

HOP={'connection','proxy-connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade'}
SINGLE={'host','content-length','transfer-encoding','origin','authorization','content-type','cookie','x-csrf-token'}

def policy(method,target,profile):
    if target==b'/__verification/index' and method=='GET':return 0
    if not target.startswith(b'/')or target.startswith(b'//')or b'#'in target or b'\\'in target:raise Refused(400,'target-form',target)
    if len(target)>(8192 if profile=='logout'else 2048):raise Refused(414,'target-bound',target)
    path,delimiter,query=target.partition(b'?')
    if b'%'in path or any(value<33 or value>126 for value in target):raise Refused(400,'target-canonical',target)
    if profile=='logout':
        if path==b'/logout':
            if method!='POST':raise Refused(405,'method',target)
            if delimiter:raise Refused(400,'query-on-start',target)
        elif path==b'/logout/callback':
            if method!='GET':raise Refused(405,'method',target)
            if not delimiter or len(query)>4096:raise Refused(400,'callback-query',target)
            name,equals,value=query.partition(b'=')
            if name!=b'state'or not equals or b'&'in query or b';'in query:raise Refused(400,'callback-state-shape',target)
            decoded=urllib.parse.unquote_to_bytes(value)
            if not re.fullmatch(rb'[A-Za-z0-9_-]{43}',decoded):raise Refused(400,'callback-state-shape',target)
            if base64.urlsafe_b64encode(base64.b64decode(decoded+b'=',altchars=b'-_',validate=True)).rstrip(b'=')!=decoded:raise Refused(400,'callback-state-canonical',target)
        else:raise Refused(404,'route',target)
        return 4096
    if delimiter:raise Refused(400,'query-on-provider-route',target)
    post={b'/google/begin',b'/google/complete',b'/apple/begin',b'/apple/complete',b'/logout',b'/native/logout'}
    get={b'/session',b'/native/session'}
    account=re.fullmatch(rb'/(native/)?account/[^/]{1,128}/[^/]{1,128}',path)
    if path in post:
        if method!='POST':raise Refused(405,'method',target)
    elif path in get or account:
        if method!='GET':raise Refused(405,'method',target)
    else:raise Refused(404,'route',target)
    return 32768

def parse(stream,profile,check=lambda:None):
    target=b''
    def line(limit):
        check();value=stream.readline(limit+1)
        if not value.endswith(b'\r\n')or len(value)>limit:raise Refused(400,'line-framing-or-bound',target)
        return value
    raw=line(8448);parts=raw[:-2].split(b' ')
    if len(parts)!=3 or parts[2]!=b'HTTP/1.1'or not re.fullmatch(rb'[A-Z]{1,8}',parts[0]):raise Refused(400,'request-line',target)
    method=parts[0].decode('ascii');target=parts[1];cap=policy(method,target,profile);headers=[];seen={};total=0
    while True:
        value=line(8192);total+=len(value)
        if total>8192:raise Refused(431,'header-total-bound',target)
        if value==b'\r\n':break
        if len(headers)>=32 or value[:1]in [b' ',b'\t']:raise Refused(431,'header-count-or-fold',target)
        name,colon,content=value[:-2].partition(b':')
        if not colon or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}",name):raise Refused(400,'header-name',target)
        content=content.strip(b' \t')
        if len(content)>4096 or any(c<32 and c!=9 or c==127 for c in content):raise Refused(400,'header-value',target)
        key=name.decode('ascii').lower();seen[key]=seen.get(key,0)+1
        if key in SINGLE and seen[key]!=1:raise Refused(400,'duplicate-security-header',target)
        if key=='forwarded'or key.startswith('x-forwarded-')or key.startswith('x-fixture-'):raise Refused(400,'untrusted-transport-or-private-header',target)
        headers.append((name.decode('ascii'),content.decode('latin-1')))
    values={name.lower():value for name,value in headers}
    if values.get('host')!='app.example':raise Refused(400,'host',target)
    if 'transfer-encoding'in values and 'content-length'in values:raise Refused(400,'ambiguous-framing',target)
    def exact(count):
        check();value=stream.read(count)
        if len(value)!=count:raise Refused(400,'truncated-body',target)
        return value
    if 'transfer-encoding'in values:
        if values['transfer-encoding'].lower()!='chunked':raise Refused(400,'transfer-coding',target)
        body=bytearray()
        while True:
            size=line(128)[:-2]
            if not re.fullmatch(rb'[0-9A-Fa-f]{1,8}',size):raise Refused(400,'chunk-size',target)
            size=int(size,16)
            if size>cap-len(body):raise Refused(413,'body-bound',target)
            if size==0:
                if line(128)!=b'\r\n':raise Refused(400,'trailers-not-selected',target)
                break
            body+=exact(size)
            if exact(2)!=b'\r\n':raise Refused(400,'chunk-delimiter',target)
        body=bytes(body)
    elif 'content-length'in values:
        value=values['content-length']
        if not re.fullmatch(r'0|[1-9][0-9]{0,8}',value):raise Refused(400,'content-length',target)
        length=int(value)
        if length>cap:raise Refused(413,'body-bound',target)
        body=exact(length)
    else:body=b''
    check();return Request(method,target,tuple(headers),body)

class BoundedServer(socketserver.ThreadingMixIn,socketserver.TCPServer):
    allow_reuse_address=False;daemon_threads=True;block_on_close=False
    def __init__(self,address,handler):self.permits=threading.BoundedSemaphore(16);self.active=set();self.active_lock=threading.Lock();super().__init__(address,handler)
    def process_request(self,request,address):
        if not self.permits.acquire(False):request.close();return
        with self.active_lock:self.active.add(request)
        try:super().process_request(request,address)
        except BaseException:
            with self.active_lock:self.active.discard(request)
            self.permits.release();raise
    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:
            with self.active_lock:self.active.discard(request)
            self.permits.release()
    def handle_error(self,request,address):pass
    def close_owned(self):
        self.shutdown();self.server_close()
        with self.active_lock:opened=list(self.active)
        for connection in opened:
            try:connection.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            connection.close()
        until=time.monotonic()+5
        while time.monotonic()<until:
            with self.active_lock:
                if not self.active:return True
            time.sleep(.01)
        return False

class Edge:
    def __init__(self,context,backend,credential,profile):
        self.context=context;self.backend=backend;self.credential=credential;self.profile=profile;self.lock=threading.Lock();self.events=[];self.dispatched=0;outer=self
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):outer.handle(self.request)
        self.server=BoundedServer(('127.0.0.1',0),Handler);self.thread=threading.Thread(target=self.server.serve_forever,name='owned-tls-edge',daemon=True)
    @property
    def port(self):return self.server.server_address[1]
    def start(self):self.thread.start()
    def record(self,name,status,target=b''):
        with self.lock:
            if len(self.events)<10000:self.events.append({'name':name,'status':status,'targetSha256':hashlib.sha256(target).hexdigest()})
    def snapshot(self):
        with self.lock:return {'dispatched':self.dispatched,'events':list(self.events)}
    @staticmethod
    def write(connection,status,headers,body):
        fields=[(k,v)for k,v in headers if k.lower()not in HOP|{'content-length'}];fields += [('Content-Length',str(len(body))),('Connection','close')]
        connection.sendall(('HTTP/1.1 '+str(status)+' '+http.client.responses.get(status,'Response')+'\r\n'+''.join(k+': '+v+'\r\n'for k,v in fields)+'\r\n').encode('latin-1')+body)
    def handle(self,raw):
        raw.settimeout(2);connection=None;backend_socket=None;target=b'';deadline=time.monotonic()+8
        def check():
            if time.monotonic()>=deadline:raise Refused(408,'original-edge-budget',target)
        def expire_owned():
            self.record('original-edge-budget-expired',408,target)
            for peer in [connection if connection is not None else raw,backend_socket]:
                if peer is not None:
                    try:peer.shutdown(socket.SHUT_RDWR)
                    except OSError:pass
        watchdog=threading.Timer(max(0,deadline-time.monotonic()),expire_owned);watchdog.daemon=True;watchdog.start()
        try:
            connection=self.context.wrap_socket(raw,server_side=True);connection.settimeout(2)
            with self.server.active_lock:self.server.active.discard(raw);self.server.active.add(connection)
            with connection.makefile('rb')as stream:
                request_line=parse(stream,self.profile,check);target=request_line.target
                if target==b'/__verification/index':
                    if request_line.body:raise Refused(400,'verification-page-body',target)
                    self.write(connection,200,[('Content-Type','text/html; charset=UTF-8'),('Cache-Control','no-store'),('Referrer-Policy','no-referrer'),('Content-Security-Policy',"default-src 'none'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")],b'<!doctype html><title>Owned browser composition</title><p>Local verification page.</p>');self.record('verification-page',200,target);return
                backend=http.client.HTTPConnection('127.0.0.1',self.backend,timeout=max(.001,min(4,deadline-time.monotonic())))
                try:
                    with self.lock:self.dispatched+=1
                    backend.putrequest(request_line.method,target.decode('ascii'),skip_host=True,skip_accept_encoding=True)
                    for name,value in request_line.headers:
                        if name.lower()not in HOP|{'content-length'}:backend.putheader(name,value)
                    backend.putheader('X-Fixture-Credential',self.credential);backend.putheader('Content-Length',str(len(request_line.body)));backend.putheader('Connection','close');backend.endheaders(request_line.body);backend_socket=backend.sock
                    response=backend.getresponse();body=response.read(131073)
                    if len(body)>131072:raise Refused(502,'backend-response-bound',target)
                    check();self.write(connection,response.status,response.getheaders(),body);self.record('forwarded',response.status,target)
                finally:backend.close()
        except Refused as failure:
            target=failure.target or target
            self.record(failure.reason,failure.status,target)
            if connection is not None:
                try:self.write(connection,failure.status,[('Cache-Control','no-store'),('Referrer-Policy','no-referrer')],b'Request unavailable.')
                except OSError:pass
        except (OSError,http.client.HTTPException,ValueError):self.record('transport-unavailable',503,target)
        finally:
            watchdog.cancel();watchdog.join(2)
            if connection is not None:
                connection.close()
                with self.server.active_lock:self.server.active.discard(connection)
            else:raw.close()
    def close(self):
        clean=self.server.close_owned();self.thread.join(3);return clean and not self.thread.is_alive()

class Connect:
    """Fixture-only transport mapping; URL/Host/Origin remain https://app.example on browser default443."""
    def __init__(self,edge_port):
        self.edge_port=edge_port;self.targets=[];self.lock=threading.Lock();outer=self
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):outer.handle(self.request)
        self.server=BoundedServer(('127.0.0.1',0),Handler);self.thread=threading.Thread(target=self.server.serve_forever,name='owned-connect',daemon=True)
    @property
    def port(self):return self.server.server_address[1]
    def start(self):self.thread.start()
    def handle(self,client):
        import select
        client.settimeout(2);server=None
        try:
            data=b''
            while b'\r\n\r\n'not in data:
                part=client.recv(1)
                if not part or len(data)>=4096:return
                data+=part
            lines=data.split(b'\r\n');parts=lines[0].split(b' ')
            if len(parts)!=3 or parts[0]!=b'CONNECT'or parts[1]!=b'app.example:443'or parts[2]not in[b'HTTP/1.1',b'HTTP/1.0']:
                client.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');return
            with self.lock:self.targets.append('app.example:443')
            server=socket.create_connection(('127.0.0.1',self.edge_port),timeout=2);client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n');end=time.monotonic()+30
            while time.monotonic()<end:
                ready,_,_=select.select([client,server],[],[],1)
                for peer in ready:
                    payload=peer.recv(65536)
                    if not payload:return
                    (server if peer is client else client).sendall(payload)
        except OSError:pass
        finally:
            if server:server.close()
            client.close()
    def close(self):
        clean=self.server.close_owned();self.thread.join(3);return clean and not self.thread.is_alive()
