#!/usr/bin/env python3
# Copyright 2026 Revetware LLC.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Actual owned socket SAML application controls; no deployment/browser/TLS/profile qualification."""
import argparse,concurrent.futures,hashlib,html.parser,http.client,json,os,re,secrets,shutil,socket,subprocess,tempfile,threading,time,urllib.parse,zipfile
from pathlib import Path

def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 if not __debug__:parser.error('Python optimization disables assertions')
 parser.add_argument('--examples-root',type=Path,required=True);parser.add_argument('--java-home',type=Path,required=True)
 for name in ['core','adapter','framework','application']:parser.add_argument('--'+name+'-sha256',required=True)
 parser.add_argument('--repository',type=Path,default=Path.home()/'.m2/repository');parser.add_argument('--binding',choices=['post','redirect'],default='post');parser.add_argument('--output',type=Path,required=True)
 args=parser.parse_args();fixture=Path(__file__).resolve().parent;module=args.examples_root/'playground';jar=module/'target/playground-1.0.0-SNAPSHOT.jar';libs=module/'target/lib'
 inputs={'APPLICATION':jar,'CORE':libs/'revetsec-1.0.0-SNAPSHOT.jar','ADAPTER':libs/'revetsec-soklet-1.0.0-SNAPSHOT.jar','FRAMEWORK':libs/'soklet-4.0.0.jar'}
 annotations=[args.repository/'org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar',args.repository/'com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar']
 sources=[fixture/'PlaygroundPostSloFixture.java',Path(__file__),*sorted((module/'src').rglob('*.java')),*sorted((module/'src/test/resources/saml').glob('*.pem')),module/'pom.xml',args.examples_root/'pom.xml']
 for name,path in inputs.items():
  if not path.is_file() or not re.fullmatch('[0-9a-f]{64}',getattr(args,name.lower()+'_sha256')) or digest(path)!=getattr(args,name.lower()+'_sha256'):parser.error('Selected '+name+' artifact mismatch before resources')
 for p in [*annotations,*sources]:
  if not p.is_file():parser.error('Missing exact fixture/source input')
 if args.output.exists():parser.error('Fresh output required')
 with zipfile.ZipFile(jar) as archive:
  manifest=archive.read('META-INF/MANIFEST.MF').decode().replace('\r\n ','')
  for line in manifest.splitlines():
   if line.startswith('Class-Path: '):
    for name in line[len('Class-Path: '):].split():
     dependency=jar.parent/name
     if ':'in name or name.startswith('/') or not dependency.is_file() or digest(dependency) not in {digest(v) for v in inputs.values()}:parser.error('Unselected application manifest dependency')
 args.output.mkdir(parents=True);watched={str(p):digest(p) for p in [*inputs.values(),*sources]};receipt={'success':False,'binding':args.binding,'sourceInputs':watched,'selectedArtifacts':{k:{'path':str(v),'sha256':digest(v)}for k,v in inputs.items()},'checks':[],'requests':[],'scope':'Owned actual Soklet/JCA-signed IdP/public SAML and application-session socket components. Synthetic fixed clock/keys, no realTLS/browser/provider/UTC/durable/final package claim.','ownedProcessStopped':False,'ownedInstanceRemoved':False};process=None;instance=None;current='preparation'
 try:
  with tempfile.TemporaryDirectory(prefix='revetsec-playground-slo-') as tmp:
   instance=Path(tmp);classes=instance/'classes';classes.mkdir();keys=instance/'keys';keys.mkdir();work=instance/'work';work.mkdir()
   for name in ['idp-signing-rsa-2048-key.pem','idp-signing-rsa-2048-cert.pem','sp-signing-rsa-2048-key.pem','sp-signing-rsa-2048-cert.pem']:shutil.copyfile(module/'src/test/resources/saml'/name,keys/name)
   cp=os.pathsep.join(map(str,[*inputs.values(),*annotations]));compiled=subprocess.run([str(args.java_home/'bin/javac'),'--release','21','-proc:none','-Xlint:all','-Werror','-cp',cp,'-d',str(classes),str(fixture/'PlaygroundPostSloFixture.java')],capture_output=True,text=True);(args.output/'compile.log').write_text(compiled.stdout+compiled.stderr)
   if compiled.returncode:raise RuntimeError('Warning-fatal fixture compilation failed')
   with socket.socket() as reserved:reserved.bind(('127.0.0.1',0));port=reserved.getsockname()[1]
   environment=dict(os.environ);environment.pop('JAVA_TOOL_OPTIONS',None);environment.pop('JDK_JAVA_OPTIONS',None);credential=secrets.token_urlsafe(24);environment['REVETSEC_SLO_FIXTURE_CREDENTIAL']=credential;environment['REVETSEC_SLO_FIXTURE_KEYS']=str(keys);environment['REVETSEC_SLO_FIXTURE_WORK']=str(work)
   for kind,path in inputs.items():environment['REVETSEC_SLO_'+kind+'_JAR']=str(path.resolve());environment['REVETSEC_SLO_'+kind+'_SHA256']=digest(path)
   with (args.output/'server.log').open('w') as log:
    process=subprocess.Popen([str(args.java_home/'bin/java'),'-cp',os.pathsep.join(map(str,[classes,*inputs.values()])),'example.playground.PlaygroundPostSloFixture',str(port),args.binding,'https://localhost:8443','https://idp.example.test'],env=environment,stdout=log,stderr=subprocess.STDOUT)
    lock=threading.Lock()
    def request(method,path,body=b'',headers=(),authenticated=True,chunked=False):
     c=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
     try:
      c.putrequest(method,path,skip_host=True,skip_accept_encoding=True);c.putheader('Host','localhost:8443')
      if authenticated:c.putheader('X-Fixture-Credential',credential)
      for k,v in headers:c.putheader(k,v)
      if chunked:c.putheader('Transfer-Encoding','chunked')
      elif body:c.putheader('Content-Length',str(len(body)))
      c.endheaders()
      if chunked:c.send((f'{len(body):x}\r\n').encode()+body+b'\r\n0\r\n\r\n')
      elif body:c.send(body)
      r=c.getresponse();payload=r.read(65537);assert len(payload)<=65536,'bounded-response';fields=r.getheaders()
      with lock:receipt['requests'].append({'method':method,'path':path.partition('?')[0],'querySha256':hashlib.sha256(path.partition('?')[2].encode()).hexdigest(),'status':r.status,'bodySha256':hashlib.sha256(payload).hexdigest(),'cookieCount':sum(k.lower()=='set-cookie'for k,v in fields)})
      return r.status,fields,payload
     finally:c.close()
    def check(name,condition,observed=None):
     nonlocal current
     current=name;receipt['checks'].append({'name':name,'passed':bool(condition),'observed':observed});assert condition,name
    def data(r):return json.loads(r[2])
    def header(r,name):
     found=[v for k,v in r[1]if k.lower()==name];assert len(found)==1,'one-header-'+name;return found[0]
    def cookie(r,name):
     found=[v.split(';',1)[0]for k,v in r[1]if k.lower()=='set-cookie'and v.startswith(name+'=')];assert len(found)==1,'one-cookie-'+name;return found[0]
    def state():return data(request('GET','/fixture/state'))
    def control(name):return request('GET','/fixture/control/'+name)
    def form(values):return urllib.parse.urlencode(values).encode()
    media=[('Content-Type','application/x-www-form-urlencoded')];origin=[('Origin','https://localhost:8443')];provider=[('Origin','https://idp.example.test')]
    def command(path,values):
     r=request('POST','/fixture/'+path,form(values),media);assert r[0]==200,'genuine-independent-idp-'+path;return data(r)
    def bootstrap():
     r=request('POST','/api/session',b'begin=1',[*media,*origin]);assert r[0]==200,'browser-session-bootstrap';return {'cookie':cookie(r,'__Host-RevetsecPlayground'),'csrf':data(r)['csrf']}
    def start_login(browser):return request('POST','/saml/begin',form({'csrf':browser['csrf']}),[*media,*origin,('Cookie',browser['cookie'])])
    def authentication(browser):
     started=start_login(browser);assert started[0]==302,'actual-authn-request';fields=command('authn',{'redirect':header(started,'location')})['fields'];pending=cookie(started,'__Host-RevetsecSamlPending');return form(fields),[ *media,*provider,('Cookie',browser['cookie']+'; '+pending)]
    def login():
     browser=bootstrap();body,fields=authentication(browser);done=request('POST','/saml/acs',body,fields);assert done[0]==302,'actual-saml-authentication';sid=cookie(done,'__Host-RevetsecPlayground');status=request('GET','/api/session',headers=[('Cookie',sid)]);assert data(status)['authenticated'] is True,'signed-authenticated-session';return {'cookie':sid,'csrf':data(status)['csrf']}
    def protected(browser):return request('POST','/api/config',form({'secretReference':'none','probeSecretReference':'none'}),[*media,*origin,('Cookie',browser['cookie']),('X-CSRF-Token',browser['csrf'])])
    class HtmlForm(html.parser.HTMLParser):
     def __init__(self):super().__init__();self.action=None;self.fields={}
     def handle_starttag(self,tag,attrs):
      values=dict(attrs)
      if tag=='form':self.action=values.get('action')
      if tag=='input'and'name'in values:self.fields[values['name']]=values.get('value','')
    def prepared(r):
     if args.binding=='post':
      assert r[0]==200,'post-form-delivered';p=HtmlForm();p.feed(r[2].decode());assert p.action=='https://idp.example.test/slo-post','fixed-post-action';assert 'SAMLRequest'in p.fields,'signed-post-fields';assert "script-src 'nonce-"in header(r,'content-security-policy'),'nonce-csp';return command('logout-response',{'form':urllib.parse.urlencode(p.fields)})
     assert r[0]==302,'default-redirect';return command('logout-response',{'redirect':header(r,'location')})
    def start_logout(browser):return request('POST','/saml/logout',form({'csrf':browser['csrf']}),[*media,*origin,('Cookie',browser['cookie'])])
    def complete_logout(browser,start,response,extra=()):
     pending=cookie(start,'__Host-RevetsecSamlLogout')
     if args.binding=='post':return request('POST','/saml/slo',form(response['fields']),[*media,*provider,('Cookie',browser['cookie']+'; '+pending),*extra])
     return request('GET','/saml/slo?'+response['query'],headers=[('Cookie',browser['cookie']+'; '+pending),*extra])
    deadline=time.monotonic()+12
    while True:
     try:
      if state()['selected_origins']:break
     except (OSError,http.client.HTTPException):pass
     if process.poll()is not None or time.monotonic()>deadline:raise RuntimeError('Bounded fixture readiness failed')
     time.sleep(.05)
    check('selected-actual-origins-and-runtime',state()['selected_origins']);check('fixture-credential',request('GET','/fixture/state',authenticated=False)[0]==401)
    browser=login();check('genuine-authentication-protected-access',protected(browser)[0]==200)
    started=start_logout(browser);check('local-authority-ends-before-provider-return',protected(browser)[0]==403 and data(request('GET','/api/session',headers=[('Cookie',browser['cookie'])]))['authenticated'] is False,started[0]);response=prepared(started);done=complete_logout(browser,started,response);check('genuine-correlated-logout-return',done[0]==302 and protected(browser)[0]==403,done[0]);check('logout-return-replay-no-authority',complete_logout(browser,started,response)[0]==400)
    def idp_request(mode='normal'):
     r=request('GET','/fixture/idp-request/'+args.binding+'/'+mode);assert r[0]==200,'signed-idp-request-fixture';return data(r)
    def idp_close(payload,extra=()):
     if args.binding=='post':return request('POST','/saml/slo',form(payload['fields']),[*media,*provider,*extra])
     return request('GET','/saml/slo?'+payload['query'],headers=[*provider,*extra])
    def verify_idp_response(reply):
     if args.binding=='post':
      parsed=HtmlForm();parsed.feed(reply[2].decode());assert parsed.action=='https://idp.example.test/slo-post','fixed-post-answer-action';return command('check-logout-response',{'form':urllib.parse.urlencode(parsed.fields)})['verified'] is True
     return command('check-logout-response',{'redirect':header(reply,'location')})['verified'] is True
    def pending(browser):return data(request('GET','/fixture/current',headers=[('Cookie',browser['cookie'])]))['logout_pending']
    expected_idp=200 if args.binding=='post'else 302
    cancelled=login();late_body,late_headers=authentication(cancelled);start=start_logout(cancelled)
    check('local-close-cancels-genuine-pending-sso',request('POST','/saml/acs',late_body,late_headers)[0]==400 and protected(cancelled)[0]==403 and pending(cancelled))
    response=prepared(start);check('local-close-keeps-only-slo-return-marker',complete_logout(cancelled,start,response)[0]==302 and protected(cancelled)[0]==403)
    known=login();late_body,late_headers=authentication(known);message=idp_request();answer=idp_close(message)
    check('signed-idp-close-targets-known-session',answer[0]==expected_idp and protected(known)[0]==403,answer[0]);check('idp-response-independent-signature-and-correlation',verify_idp_response(answer))
    refused=request('POST','/saml/acs',late_body,late_headers);check('idp-close-blocks-previously-signed-sso-revival',refused[0]==400 and protected(known)[0]==403 and not any(k.lower()=='set-cookie'and v.startswith('__Host-RevetsecPlayground=')for k,v in refused[1]),refused[0])
    fresh=login();replayed=idp_close(message);check('idp-replay-cannot-close-genuine-fresh-session',replayed[0]==400 and protected(fresh)[0]==200,replayed[0])
    unmatched=idp_request('wrong-index');answer=idp_close(unmatched);check('full-signed-session-index-keeps-unmatched-session',answer[0]==expected_idp and protected(fresh)[0]==200 and verify_idp_response(answer),answer[0])
    if args.binding=='post':
     invalid=idp_request('wrong-signature');before=state();reply=idp_close(invalid);check('wrong-post-signature-no-session-close-or-replay-mark',reply[0]==400 and protected(fresh)[0]==200 and state()['marks']==before['marks'],reply[0])
    start=start_logout(fresh);response=prepared(start);before=state()
    if args.binding=='post':
     good=form(response['fields']);cookie_value=fresh['cookie']+'; '+cookie(start,'__Host-RevetsecSamlLogout');base=[*media,*provider,('Cookie',cookie_value)]
     for name,path,body,fields,status in [
       ('duplicate-origin','/saml/slo',good,[*base,('Origin','https://idp.example.test')],403),
       ('hostile-origin','/saml/slo',good,[*media,('Origin','https://wrong.invalid'),('Cookie',cookie_value)],403),
       ('missing-pending','/saml/slo',good,[*media,*provider,('Cookie',fresh['cookie'])],400),
       ('duplicate-cookie','/saml/slo',good,[*base,('Cookie',cookie_value)],400),
       ('duplicate-media','/saml/slo',good,[*base,*media],400),
       ('duplicate-field','/saml/slo',good+b'&%53AMLResponse=duplicate',base,400),
       ('query-body-confusion','/saml/slo?SAMLResponse=query',good,base,400),
       ('wrong-method','/saml/slo',good,base,405),
       ('actual-overlimit','/saml/slo',b'A'*16385,base,413)]:
      reply=request('PUT'if name=='wrong-method'else'POST',path,body,fields)
      check('post-raw-'+name,reply[0]==status and pending(fresh) and state()['marks']==before['marks'] and protected(fresh)[0]==403,reply[0])
     # Core SAML permits non-protocol query fields, unlike the provider/logout recipe's strict no-query profile.
     reply=request('POST','/saml/slo?route=static',good,base);check('saml-nonprotocol-query-does-not-select-authority',reply[0]==302 and not pending(fresh) and protected(fresh)[0]==403,reply[0])
    else:check('default-redirect-correlated-return-retained',complete_logout(fresh,start,response)[0]==302)
    # A real replay backend mark is held after signature validation, before app publication.
    blocked_browser=login();late_body,late_headers=authentication(blocked_browser);close_message=idp_request();before=state();control('block-next-mark')
    with concurrent.futures.ThreadPoolExecutor(max_workers=1)as pool:
     callback=pool.submit(request,'POST','/saml/acs',late_body,late_headers);deadline=time.monotonic()+1
     while True:
      held=state()
      if held['blocked']:break
      if time.monotonic()>deadline:raise AssertionError('actual-replay-mark-entered')
      time.sleep(.01)
     check('actual-validated-replay-effect-before-wait',held['marks']==before['marks']+1 and held['last_mark']=='MARKED' and held['blocked_remaining_ms']>250)
     answer=idp_close(close_message);check('idp-close-does-not-wait-for-session-monitor',answer[0]==expected_idp and protected(blocked_browser)[0]==403 and verify_idp_response(answer),answer[0]);control('release');refused=callback.result(timeout=3)
    escaped_authority=False
    if any(k.lower()=='set-cookie'and v.startswith('__Host-RevetsecPlayground=')for k,v in refused[1]):
     escaped_sid=cookie(refused,'__Host-RevetsecPlayground');escaped_view=data(request('GET','/api/session',headers=[('Cookie',escaped_sid)]))
     escaped_authority=escaped_view.get('authenticated')is True and protected({'cookie':escaped_sid,'csrf':escaped_view['csrf']})[0]==200
    check('post-validation-cancellation-final-rotation-denied',refused[0]==400 and not escaped_authority and protected(blocked_browser)[0]==403 and not any(k.lower()=='set-cookie'and v.startswith('__Host-RevetsecPlayground=')for k,v in refused[1]),{'status':refused[0],'released_authority':escaped_authority})
    # The other serial order sees the already-published new session and its reference together.
    old=login();late_body,late_headers=authentication(old);done=request('POST','/saml/acs',late_body,late_headers);assert done[0]==302,'repeat-genuine-login';sid=cookie(done,'__Host-RevetsecPlayground');view=data(request('GET','/api/session',headers=[('Cookie',sid)]));current_browser={'cookie':sid,'csrf':view['csrf']}
    check('rotation-order-publishes-new-reference-and-authority',protected(old)[0]==403 and protected(current_browser)[0]==200 and view['authenticated'] is True)
    answer=idp_close(idp_request());check('rotation-before-idp-close-new-session-denied',answer[0]==expected_idp and verify_idp_response(answer) and protected(current_browser)[0]==403)
    next_browser=login();check('new-bootstrap-after-closure-independent',protected(next_browser)[0]==200)
    receipt['finalState']=state();receipt['success']=True
 except Exception as failure:
  receipt['failure']={'checkpoint':current,'type':type(failure).__name__,'message':str(failure)[:200]};receipt['success']=False
 finally:
  if process is not None:
   if process.poll()is None:
    process.terminate()
    try:process.wait(timeout=5)
    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
   receipt['ownedProcessStopped']=process.poll()is not None
  else:receipt['ownedProcessStopped']=True
  receipt['ownedInstanceRemoved']=instance is None or not instance.exists();receipt['sourceStable']=all(digest(Path(p))==v for p,v in watched.items())
  if not receipt['ownedProcessStopped']or not receipt['ownedInstanceRemoved']or not receipt['sourceStable']:receipt['success']=False
  (args.output/'RESULT.json').write_text(json.dumps(receipt,indent=2)+'\n')
 print(json.dumps({'success':receipt['success'],'checks':len(receipt['checks']),'ownedProcessStopped':receipt['ownedProcessStopped'],'ownedInstanceRemoved':receipt['ownedInstanceRemoved']}));return 0 if receipt['success']else 1
if __name__=='__main__':raise SystemExit(main())
