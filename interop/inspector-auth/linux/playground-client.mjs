// Copyright 2026 Revetware LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
import {randomBytes} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {request as httpsRequest} from 'node:https';
import {existsSync,mkdirSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {startProcess} from '../support/process.mjs';
import {createEnvironment} from '../support/config.mjs';
import {connectCdp} from '../support/cdp.mjs';
import {chromeArguments,browserVersion} from '../support/web.mjs';
import {directoryIdentity,verifyDependencyPins} from '../support/identity.mjs';

const input=JSON.parse(readFileSync(0,'utf8'));
if(!['jwt','opaque'].includes(input.tokenFormat))throw new Error('CLIENT_INPUT');
const issuer=input.issuer??'https://127.0.0.1:9443';
if(!['https://localhost:9443','https://127.0.0.1:9443'].includes(issuer))throw new Error('CLIENT_ISSUER');
const connectionSelector='[aria-label=\'Connect or disconnect \"revetsec_playground\"\']';
const root='/tmp/revetsec-playground-client';mkdirSync(root,{mode:0o700});
const env=createEnvironment(root,'/runtime/java/bin/java');
for(const key of ['HOME','XDG_CONFIG_HOME','XDG_CACHE_HOME','TMPDIR','MCP_STORAGE_DIR'])mkdirSync(env[key],{recursive:true,mode:0o700});
for(const [name,value]of Object.entries({ca:input.ca,cert:input.cert,key:input.key}))writeFileSync(root+'/'+name+'.pem',value,{mode:0o600});
const report={status:'FAILED',stage:'SETUP',tokenFormat:input.tokenFormat,issuer,implementationVerification:true,
  independentReview:false,certificateErrorBypass:false,browserSandboxDisabled:false,globalTrustMutation:false,
  network:{sameOrigin:0,localProvider:0,localApplication:0,localCallback:0,blockedFont:0,unexpected:0},
  browserExceptions:0,toolCallSent:false,toolArgumentsLocalSelf:false,browserFlows:[],shutdown:{}};
const handles={},sessions=new Map(),requestPaths=new Map();let cdp,closing=false,inspectorSession;
report.http=[];report.mcpMethods=[];report.browserDiagnostics=[];
function pathLabel(value){const u=new URL(value);const p=u.pathname;if(p==='/auth')return 'AUTHORIZATION';if(p.startsWith('/interaction/'))return 'INTERACTION';if(p.startsWith('/auth/'))return 'AUTH_CONTINUATION';if(p==='/oauth/callback')return 'INSPECTOR_CALLBACK';if(p==='/api/mcp/connect')return 'INSPECTOR_CONNECT';if(p==='/api/mcp/send')return 'INSPECTOR_SEND';if(p==='/api/session')return 'APP_SESSION';if(p==='/app.js')return 'APP_SCRIPT';if(p==='/style.css')return 'APP_STYLE';if(p==='/oidc/begin')return 'APP_BEGIN';if(p==='/oidc/callback')return 'APP_CALLBACK';if(p==='/api/probe')return 'APP_PROBE';if(p==='/')return 'INDEX';return 'OTHER_LOCAL';}
const pause=()=>new Promise(resolve=>setTimeout(resolve,50));
const fail=code=>{throw new Error(code);};
function managed(name,command,args,extra={}) {
  const handle=startProcess(command,args,{cwd:root,env,timeoutMs:150000,maxOutputBytes:1048576,...extra});
  handles[name]=handle;void handle.completion.catch(()=>{});return handle;
}
function command(executable,args) {
  const result=spawnSync(executable,args,{env,encoding:'utf8',timeout:10000,maxBuffer:65536});
  if(result.status!==0)fail('CLIENT_SETUP_COMMAND');
}
async function tlsGet(url) {
  return new Promise((resolve,reject)=>{
    const request=httpsRequest(url,{ca:input.ca,rejectUnauthorized:true,timeout:2000},response=>{
      response.resume();response.once('end',()=>resolve(response.statusCode));});
    request.once('error',reject);request.once('timeout',()=>request.destroy());request.end();
  });
}
async function waitFor(probe,code,ms=10000) {
  const until=Date.now()+ms;
  while(Date.now()<until){try{if(await probe())return;}catch{}await pause();}
  fail(code);
}
async function evaluate(session,expression) {
  const result=await cdp.send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true},session);
  if(result.exceptionDetails)fail('CLIENT_DOM_EVALUATION');return result.result.value;
}
function clickText(text) {
  return `(() => {const nodes=[...document.querySelectorAll('button')].filter(n=>n.getClientRects().length&&!n.disabled&&n.textContent.trim()===${JSON.stringify(text)});if(nodes.length!==1)return false;nodes[0].click();return true;})()`;
}
function clickSelector(selector) {
  return `(() => {const nodes=[...document.querySelectorAll(${JSON.stringify(selector)})].filter(n=>n.getClientRects().length&&!n.disabled);if(nodes.length!==1)return false;nodes[0].click();return true;})()`;
}
async function attach(targetId) {
  const {sessionId}=await cdp.send('Target.attachToTarget',{targetId,flatten:true});
  await cdp.send('Page.enable',{},sessionId);await cdp.send('Runtime.enable',{},sessionId);
  await cdp.send('Network.enable',{},sessionId);
  await cdp.send('Fetch.enable',{patterns:[{urlPattern:'*',requestStage:'Request'}]},sessionId);
  await cdp.send('Log.enable',{},sessionId);sessions.set(targetId,sessionId);
  return sessionId;
}
const proofExpression=`(() => {function checked(v,depth=0){if(depth>5||v==null)return false;
  if(typeof v==='string'){try{return checked(JSON.parse(v),depth+1);}catch{return false;}}
  if(Array.isArray(v))return v.some(x=>checked(x,depth+1));
  if(typeof v==='object'){
    if(Object.keys(v).sort().join(',')==='issuer,scopes,subject,validation')return v.issuer===${JSON.stringify(issuer)}
      &&/^p1_[A-Za-z0-9_-]{43}$/.test(v.subject)&&Array.isArray(v.scopes)
      &&v.scopes.includes('mcp:whoami')&&v.scopes.every(x=>['mcp:discover','mcp:whoami'].includes(x))
      &&v.validation==='Completed configured issuer, audience and credential profile checks';
    return Object.values(v).some(x=>checked(x,depth+1));}return false;}
  return [...document.querySelectorAll('[data-testid=tools-screen] pre,[data-testid=tools-screen] code,[data-testid=tools-screen] .ace_text-layer')].some(n=>n.getClientRects().length&&n.textContent.length<16384&&checked(n.textContent));})()`;
try {
  const pins=JSON.parse(readFileSync('/source/interop/inspector-auth/client/pins.json'));
  verifyDependencyPins(readFileSync('/private/inspector-client/package.json'),readFileSync('/private/inspector-client/package-lock.json'),pins);
  report.clientTreeBefore=directoryIdentity('/private/inspector-client/node_modules');
  report.client={version:'2.9.0',commit:pins.commit,lockSha256:pins.lockSha256,runtime:process.version};
  const nss=env.HOME+'/.pki/nssdb';mkdirSync(nss,{recursive:true,mode:0o700});
  command('/usr/bin/certutil',['-N','--empty-password','-d','sql:'+nss]);
  command('/usr/bin/certutil',['-A','-n','Revetsec disposable test CA','-t','C,,','-i',root+'/ca.pem','-d','sql:'+nss]);
  command('/runtime/java/bin/keytool',['-importcert','-noprompt','-alias','revetsec-local-test-ca',
    '-file',root+'/ca.pem','-storetype','PKCS12','-keystore',root+'/trust.p12','-storepass','test-only-temporary-value']);
  const shared={...env,NODE_EXTRA_CA_CERTS:root+'/ca.pem'};
  managed('provider',process.execPath,['/provider/server.js'],{env:{...shared,PORT:'9443',ISSUER:issuer,
    TLS_CERT_FILE:root+'/cert.pem',TLS_KEY_FILE:root+'/key.pem',TEST_BIND_ADDRESS:'127.0.0.1',
    TEST_RESOURCE_MODE:'playground',TEST_PLAYGROUND_RESOURCE:'https://localhost:8443/mcp',
    TEST_PLAYGROUND_TOKEN_FORMAT:input.tokenFormat,TEST_CLIENT_REDIRECT_URIS:'https://localhost:8443/oidc/callback,https://localhost:8445/callback'}});
  await waitFor(async()=>await tlsGet(issuer+'/.well-known/openid-configuration')===200,'CLIENT_PROVIDER_READY');
  const classpath=['playground-1.0.0-SNAPSHOT.jar','revetsec-1.0.0-SNAPSHOT.jar','revetsec-soklet-1.0.0-SNAPSHOT.jar','soklet-4.0.0.jar'].map(name=>'/app/'+name).join(':');
  managed('application','/runtime/java/bin/java',['-Djavax.net.ssl.trustStore='+root+'/trust.p12',
    '-Djavax.net.ssl.trustStorePassword=test-only-temporary-value','-cp',classpath,'example.playground.Playground'],
    {env:{...shared,PLAYGROUND_ISSUER:issuer,PLAYGROUND_CLIENT_ID:'revetsec-test-client',
      PLAYGROUND_SECRET_REFERENCE:'env:PLAYGROUND_CLIENT_SECRET',PLAYGROUND_CLIENT_SECRET:'test-only-client-secret-not-a-real-secret',
      PLAYGROUND_PROBE_CLIENT_ID:'revetsec-test-client',PLAYGROUND_PROBE_SECRET_REFERENCE:'env:PLAYGROUND_CLIENT_SECRET',
      PLAYGROUND_VALIDATION:input.tokenFormat==='jwt'?'jwt':'introspection',PLAYGROUND_REPLAY_JOURNAL:'true'}});
  managed('edge','/runtime/caddy',['run','--config','/source/interop/local-https/Caddyfile','--adapter','caddyfile'],
    {env:{...shared,REVETSEC_TLS_CERT:root+'/cert.pem',REVETSEC_TLS_KEY:root+'/key.pem',XDG_DATA_HOME:root+'/caddy-data'}});
  await waitFor(async()=>await tlsGet('https://localhost:8443/.well-known/oauth-protected-resource/mcp')===200,'CLIENT_APPLICATION_READY');
  report.stage='INSPECTOR';
  const config={mcpServers:{revetsec_playground:{type:'http',url:'https://localhost:8443/mcp',protocolEra:'modern',
    advertisedExtensions:{'io.modelcontextprotocol/ui':false,'io.modelcontextprotocol/skills':false},
    oauth:{scopes:'mcp:discover mcp:whoami'}}}};
  writeFileSync(root+'/session.json',JSON.stringify(config),{mode:0o600});
  const hostToken=randomBytes(32).toString('hex'),origin='http://127.0.0.1:6274';
  managed('inspector',process.execPath,['/private/inspector-client/node_modules/@modelcontextprotocol/inspector/clients/launcher/build/index.js','--web','--config',root+'/session.json'],
    {env:{...shared,HOST:'127.0.0.1',CLIENT_PORT:'6274',ALLOWED_ORIGINS:origin+',http://localhost:6274',
      MCP_SANDBOX_PORT:'0',MCP_APP_ORIGIN_PORT:'0',MCP_INSPECTOR_API_TOKEN:hostToken}});
  const apiHeaders={Origin:origin,'x-mcp-remote-auth':'Bearer '+hostToken};
  await waitFor(async()=>{const r=await fetch(origin+'/api/config',{headers:apiHeaders,signal:AbortSignal.timeout(1500)});
    if(r.status!==200){await r.body.cancel();return false;}const cfg=await r.json();
    report.readOnlyMemoryStore=cfg.writable===false&&cfg.secretStorage?.kind==='memory'&&cfg.secretStorage?.durable===false;return report.readOnlyMemoryStore;},'CLIENT_INSPECTOR_READY');
  const profile=root+'/chrome-profile';mkdirSync(profile,{mode:0o700});
  managed('browser','/ms-playwright/chromium-1243/chrome-linux-arm64/chrome',chromeArguments(profile));
  await waitFor(()=>existsSync(profile+'/DevToolsActivePort'),'CLIENT_BROWSER_READY');
  const [port,path]=readFileSync(profile+'/DevToolsActivePort','utf8').trim().split('\n');cdp=await connectCdp('ws://127.0.0.1:'+port+path);
  report.browser=browserVersion(await cdp.send('Browser.getVersion'));
  cdp.on('Runtime.exceptionThrown',event=>{report.browserExceptions++;const name=event.exceptionDetails?.exception?.className;report.browserDiagnostics.push({exceptionClass:['TypeError','ReferenceError','SyntaxError'].includes(name)?name:'OTHER'});});
  cdp.on('Log.entryAdded',event=>{const entry=event.entry;if(entry.level==='error'&&report.browserDiagnostics.length<16)report.browserDiagnostics.push({source:['security','javascript','network'].includes(entry.source)?entry.source:'OTHER',csp:entry.text.includes('Content Security Policy'),mime:entry.text.includes('MIME type'),nosniff:entry.text.includes('nosniff')});});
  cdp.on('Fetch.requestPaused',async(event,session)=>{
    let allowed=false;const req=event.request;
    try {const url=new URL(req.url);
      if(url.origin===origin){allowed=true;report.network.sameOrigin++;
        if(url.pathname==='/api/mcp/send'&&req.method==='POST'&&typeof req.postData==='string'&&req.postData.length<32768){
          const message=JSON.parse(req.postData).message;
          if(['server/discover','tools/list','tools/call','subscriptions/listen'].includes(message?.method)&&!report.mcpMethods.includes(message.method))report.mcpMethods.push(message.method);
          if(message?.method==='tools/call'&&message.params?.name==='whoami'){
            report.toolCallSent=true;const args=message.params.arguments??{};
            report.toolArgumentsLocalSelf=(args.tenant??'local')==='local'&&(args.object??'self')==='self';}}}
      else if(url.origin==='http://localhost:6274'){allowed=true;report.network.localCallback++;}
      else if(url.origin===issuer){allowed=true;report.network.localProvider++;}
      else if(url.origin==='https://localhost:8443'){allowed=true;report.network.localApplication++;if(url.pathname==='/oidc/begin'){const headers=Object.fromEntries(Object.entries(req.headers).map(([k,v])=>[k.toLowerCase(),v]));report.browserBegin={origin:headers.origin==='https://localhost:8443'?'TRUSTED_APP':headers.origin==='null'?'OPAQUE_NULL':headers.origin==null?'ABSENT':'OTHER',formContentType:headers['content-type']?.startsWith('application/x-www-form-urlencoded')===true};}}
      else if(req.url==='https://fonts.googleapis.com/css2?family=Fredoka:wght@300..700&family=Roboto+Mono:ital,wght@0,100..700;1,100..700&display=swap')report.network.blockedFont++;
      else report.network.unexpected++;
    }catch{report.network.unexpected++;}
    if(!closing)await cdp.send(allowed?'Fetch.continueRequest':'Fetch.failRequest',{requestId:event.requestId,...(!allowed?{errorReason:'BlockedByClient'}:{})},session);
  });
  cdp.on('Network.requestWillBeSent',event=>{if(requestPaths.size<512)requestPaths.set(event.requestId,pathLabel(event.request.url));});
  cdp.on('Network.loadingFailed',event=>{if(report.browserDiagnostics.length<16)report.browserDiagnostics.push({path:requestPaths.get(event.requestId)??'OTHER_LOCAL',networkFailure:/^net::ERR_[A-Z_]+$/.test(event.errorText)?event.errorText:'OTHER',blockedReason:['csp','mixed-content','inspector','subresource-filter'].includes(event.blockedReason)?event.blockedReason:null});});
  cdp.on('Network.responseReceived',event=>{if(report.http.length<128)report.http.push({path:pathLabel(event.response.url),status:event.response.status});});
  cdp.on('Target.targetCreated',async event=>{if(closing)return;if(event.targetInfo.type==='page'&&!sessions.has(event.targetInfo.targetId)){try{await attach(event.targetInfo.targetId);}catch(error){if(!closing||error.message!=='CDP_CLOSED')throw error;}}});
  const {targetId}=await cdp.send('Target.createTarget',{url:'about:blank'});inspectorSession=await attach(targetId);
  await cdp.send('Target.setDiscoverTargets',{discover:true});await cdp.send('Page.navigate',{url:origin},inspectorSession);
  const connectionSelector='[aria-label=\'Connect or disconnect "revetsec_playground"\']';
  await waitFor(()=>evaluate(inspectorSession,clickSelector(connectionSelector)),'CLIENT_CONNECT_CONTROL');
  report.connectedViaDom=true;report.stage='OAUTH';
  await waitFor(async()=>{
    await evaluate(inspectorSession,clickText('Authorize'));
    return report.mcpMethods.includes('server/discover')&&report.mcpMethods.includes('tools/list')
      &&await evaluate(inspectorSession,`document.querySelector(${JSON.stringify(connectionSelector)})?.checked===true`);
  },'CLIENT_OAUTH_DISCOVERY',30000);
  await waitFor(()=>evaluate(inspectorSession,`(() => {const n=[...document.querySelectorAll('label')].find(n=>n.getClientRects().length&&n.textContent.trim()==='Tools');if(!n)return false;n.click();return true;})()`),'CLIENT_TOOL_NAVIGATION');
  await waitFor(()=>evaluate(inspectorSession,`document.querySelector('[data-testid=tools-screen]')?.getAttribute('data-tool-count')==='1'`),'CLIENT_TOOL_CATALOG');
  report.oauthDiscoveryCompleted=true;
  report.stage='TOOL_CALL';
  await waitFor(()=>evaluate(inspectorSession,`(() => {const n=[...document.querySelectorAll('button')].find(n=>n.getClientRects().length&&!n.disabled&&n.textContent.trim().includes('whoami'));if(!n)return false;n.click();return true;})()`),'CLIENT_TOOL_SELECT');
  await waitFor(async()=>{
    for(const label of ['Execute Tool'])if(await evaluate(inspectorSession,clickText(label)))return true;
    return false;},'CLIENT_TOOL_RUN_CONTROL');
  await waitFor(()=>evaluate(inspectorSession,proofExpression),'CLIENT_TOOL_RESULT',15000);
  report.checkedWhoamiProof=true;
  report.stage='PLAYGROUND_UI';report.frontendSessionTlsStatus=await tlsGet('https://localhost:8443/api/session');
  const {targetId:appTarget}=await cdp.send('Target.createTarget',{url:'about:blank'});
  await waitFor(()=>sessions.has(appTarget),'CLIENT_APP_ATTACH');const appSession=sessions.get(appTarget);
  await cdp.send('Page.navigate',{url:'https://localhost:8443/'},appSession);
  await waitFor(()=>evaluate(appSession,`document.querySelector('#login')?.elements.csrf.value.length>0`),'CLIENT_APP_CSRF');
  for(const [mode,responseMode]of [['atomic','query'],['sealed','form_post']]) {
    const before=await cdp.send('Network.getCookies',{urls:['https://localhost:8443/']},appSession);
    const oldCsrf=await evaluate(appSession,`document.querySelector('#login')?.elements.csrf.value`);
    const oldSession=before.cookies.find(c=>c.name==='__Host-RevetsecPlayground')?.value;
    report.browserAttempt={mode,responseMode,sessionCookiePresent:!!oldSession};
    await evaluate(appSession,`(() => {const f=document.querySelector('#login');f.elements.mode.value=${JSON.stringify(mode)};f.elements.responseMode.value=${JSON.stringify(responseMode)};f.requestSubmit();return true;})()`);
    await waitFor(async()=>{const current=await cdp.send('Network.getCookies',{urls:['https://localhost:8443/']},appSession);
      return current.cookies.some(c=>c.name==='__Host-RevetsecPlayground'&&c.value!==oldSession)
        &&await evaluate(appSession,`(() => {try {const v=JSON.parse(document.querySelector('#identity')?.textContent);return v.issuer===${JSON.stringify(issuer)}&&/^p1_[A-Za-z0-9_-]{43}$/.test(v.subject)&&v.validation==='Completed OIDC authentication profile';}catch{return false;}})()`);
    },'CLIENT_BROWSER_OIDC',15000);
    const after=await cdp.send('Network.getCookies',{urls:['https://localhost:8443/']},appSession);
    const sessionCookie=after.cookies.find(c=>c.name==='__Host-RevetsecPlayground');
    const newCsrf=await evaluate(appSession,`document.querySelector('#login')?.elements.csrf.value`);
    report.browserFlows.push({mode,responseMode,identityChecked:true,crossSite:new URL(issuer).hostname!=='localhost',csrfRotated:typeof oldCsrf==='string'&&typeof newCsrf==='string'&&oldCsrf.length>0&&newCsrf.length>0&&oldCsrf!==newCsrf,sessionRotated:!!oldSession&&!!sessionCookie&&oldSession!==sessionCookie.value,
      sameSiteNone:sessionCookie?.sameSite==='None',secure:sessionCookie?.secure===true,httpOnly:sessionCookie?.httpOnly===true,hostPrefix:sessionCookie?.name.startsWith('__Host-')===true});
  }
  await evaluate(appSession,clickSelector('#probe'));
  await waitFor(()=>evaluate(appSession,`(() => {try {const v=JSON.parse(document.querySelector('#result')?.textContent);return v.httpStatus===200&&typeof v.retriedOnce==='boolean'&&v.outcome==='MCP request completed';}catch{return false;}})()`),'CLIENT_UI_PROBE',15000);report.uiProbeChecked=true;
  report.disconnectedViaDom=await evaluate(inspectorSession,clickSelector('[aria-label="Disconnect from server"]'));
  report.clientTreeUnchanged=JSON.stringify(directoryIdentity('/private/inspector-client/node_modules'))===JSON.stringify(report.clientTreeBefore);
  report.status=report.toolCallSent&&report.toolArgumentsLocalSelf&&report.checkedWhoamiProof&&report.browserFlows.every(r=>r.identityChecked&&r.sessionRotated&&r.csrfRotated&&r.sameSiteNone&&r.crossSite&&r.secure&&r.httpOnly&&r.hostPrefix)
    &&report.uiProbeChecked&&report.network.unexpected===0&&report.browserExceptions===0&&report.clientTreeUnchanged?'PASS':'FAILED';
} catch(error) {if(cdp)try{report.uiFacts=[];for(const session of sessions.values())try{report.uiFacts.push(await evaluate(session,`({connected:document.querySelector(${JSON.stringify(connectionSelector)})?.checked===true,whoamiVisible:document.body.innerText.includes('whoami'),authorizeVisible:[...document.querySelectorAll('button')].some(n=>n.textContent.trim()==='Authorize'),knownErrorCodes:['invalid_scope','invalid_request','invalid_client','invalid_redirect_uri','access_denied','server_error'].filter(x=>document.body.innerText.includes(x)),appLoginPresent:document.querySelector('#login')!==null,appCsrfReady:(document.querySelector('#login')?.elements.csrf?.value?.length??0)>0,appUnavailable:document.querySelector('#result')?.textContent.includes('Local app unavailable')===true,callStatus:document.querySelector('[data-testid=tools-screen]')?.getAttribute('data-call-status')??null,jsonEditorVisible:[...document.querySelectorAll('[data-testid=tools-screen] .ace_text-layer')].some(n=>n.getClientRects().length>0),toolCount:document.querySelector('[data-testid=tools-screen]')?.getAttribute('data-tool-count')??null,toolNavigationVisible:[...document.querySelectorAll('label,a,button,[role=tab]')].some(n=>n.getClientRects().length&&n.textContent.trim()==='Tools'),runLabels:['Execute Tool'].filter(x=>[...document.querySelectorAll('button')].some(n=>n.textContent.trim()===x))})`));}catch{}}catch{}report.failure=/^(CLIENT|DEPENDENCY|INSTALLED|CDP)_[A-Z_]+$/.test(error.message)?error.message:'CLIENT_RUN_FAILED';}
finally {
  closing=true;
  try{if(cdp&&!cdp.failure())await cdp.send('Browser.close');await cdp?.close();}catch{report.cdpClosureFailure=true;}
  for(const name of ['browser','inspector','application','edge','provider']) {
    const handle=handles[name];if(!handle)continue;
    try{await handle.stop();report.shutdown[name]='CLOSED';}catch{report.shutdown[name]='FAILED';report.status='FAILED';}
  }
  rmSync(root,{recursive:true,force:true});report.privateStateRemoved=!existsSync(root);
  writeFileSync('/evidence/playground-'+input.tokenFormat+'.RESULT.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
}
if(report.status!=='PASS')process.exitCode=1;
