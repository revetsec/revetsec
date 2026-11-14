// Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
// Disposable real VS Code + Chromium client. Receipts contain structural facts only.
import {readFileSync,writeFileSync,existsSync,mkdirSync,rmSync,readdirSync,statSync} from 'node:fs';
import {randomBytes} from 'node:crypto';
import {dirname} from 'node:path';
import {createServer} from 'node:net';
import {networkInterfaces} from 'node:os';
import {lookup} from 'node:dns/promises';
import {fixedClientErrorCodes} from './diagnostics.mjs';
import {spawnSync} from 'node:child_process';
import {request as httpsRequest} from 'node:https';
import {startProcess} from '/source/interop/inspector-auth/support/process.mjs';
import {connectCdp} from '/source/interop/inspector-auth/support/cdp.mjs';
import {chromeArguments,browserVersion} from '/source/interop/inspector-auth/support/web.mjs';
const input=JSON.parse(readFileSync(0,'utf8'));
const root='/tmp/revetsec-vscode-client';mkdirSync(root,{mode:0o700});
const issuer='https://localhost:'+input.port,resource=issuer+'/mcp',clientId='https://vscode.dev/oauth/client-metadata.json';
const report={status:'FAILED',stage:'SETUP',checks:[],shutdown:{},uiActions:[],callback:{observed:false},browserRequests:{local:0,blocked:0},certificateErrorBypass:false,browserSandboxDisabled:false,clientSandboxDisabled:false,globalTrustMutation:false,externalServices:false,accountSignIn:false};
const env={PATH:[root+'/bin',dirname(process.execPath),'/runtime/java/bin','/usr/bin','/bin'].join(':'),HOME:root+'/home',XDG_CONFIG_HOME:root+'/config',XDG_CACHE_HOME:root+'/cache',XDG_DATA_HOME:root+'/data',TMPDIR:root+'/tmp',DISPLAY:':79',NO_COLOR:'1',REVETSEC_QUAL_ROOT:root,BROWSER:root+'/bin/xdg-open'};
for(const dir of [env.HOME,env.XDG_CONFIG_HOME,env.XDG_CACHE_HOME,env.XDG_DATA_HOME,env.TMPDIR,root+'/bin',root+'/workspace',root+'/user/User',root+'/extensions'])mkdirSync(dir,{recursive:true,mode:0o700});
for(const [name,value]of Object.entries({ca:input.ca,cert:input.cert,key:input.key}))writeFileSync(root+'/'+name+'.pem',value,{mode:0o600});
const keys={login:randomBytes(32).toString('base64url'),client:randomBytes(32).toString('base64url'),resource:randomBytes(32).toString('base64url')};
for(const [name,value]of Object.entries(keys))writeFileSync(root+'/'+name+'.key',value,{mode:0o600});
const shared={...env,NODE_EXTRA_CA_CERTS:root+'/ca.pem',NODE_OPTIONS:'--dns-result-order=ipv6first'};
const handles={},connections=[],sessions=new Map();let externalBrowser,closing=false,callbackOpened=false;
const started=performance.now();
function stage(value){report.stage=value;writeFileSync('/evidence/PROGRESS.json',JSON.stringify({stage:value,checks:report.checks.length,elapsedMs:Math.floor(performance.now()-started)}),{mode:0o600});}
function fail(code){throw new Error(code);}
function check(name,value){report.checks.push({name,status:value?'PASS':'FAIL'});if(!value)fail('ASSERTION');}
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function managed(name,command,args,extra={}){
 const handle=startProcess(command,args,{cwd:root,env:shared,timeoutMs:465000,maxOutputBytes:2097152,...extra});handles[name]=handle;
 // Do not copy raw stdout/stderr, URLs, cookies or exception messages into receipts.
 void handle.completion.then(result=>{report.childExits??={};report.childExits[name]={code:result.code,facts:['No usable sandbox','error while loading shared libraries','Local issuer configuration rejected','adapting config','Permission denied','Cannot find module'].filter(s=>result.stdout.includes(s)||result.stderr.includes(s))};}).catch(()=>{});
 return handle;
}
function command(executable,args){const r=spawnSync(executable,args,{env:shared,encoding:'utf8',timeout:15000,maxBuffer:65536});if(r.status!==0)fail('SETUP_COMMAND');}
async function until(probe,code,ms=25000){const end=performance.now()+ms;while(performance.now()<end){if(await probe())return;await pause(100);}fail(code);}
async function tlsReady(){return new Promise(resolve=>{const r=httpsRequest(issuer+'/.well-known/oauth-authorization-server',{ca:input.ca,rejectUnauthorized:true,family:6,timeout:1500},s=>{s.resume();s.on('end',()=>resolve(s.statusCode===200));});r.on('error',()=>resolve(false));r.on('timeout',()=>r.destroy());r.end();});}
async function evaluate(connection,session,expression){const result=await connection.send('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true},session);if(result.exceptionDetails)fail('DOM_EVALUATION');return result.result.value;}
async function attach(connection,target){const key=connections.indexOf(connection)+':'+target;if(sessions.has(key))return sessions.get(key);const {sessionId}=await connection.send('Target.attachToTarget',{targetId:target,flatten:true});sessions.set(key,sessionId);await connection.send('Runtime.enable',{},sessionId);return sessionId;}
function clickText(labels){return `(()=>{const labels=${JSON.stringify(labels)};const n=[...document.querySelectorAll('button,a,.monaco-button,[role="button"]')].find(n=>n.getClientRects().length&&!n.disabled&&labels.includes(n.textContent.trim()));if(!n)return null;const label=n.textContent.trim();n.click();return label;})()`;}
const knownButtons=['Yes, I trust the authors','Trust','Trust Folder & Enable All Features','Allow','Continue','Allow Once'];
let codeConnection,codeSession,browserConnection,browserSession;
try{
 const interfaces=Object.keys(networkInterfaces());const routes=readFileSync('/proc/net/route','utf8').trim().split('\n').slice(1);
 check('owned-network-none-loopback-only',interfaces.every(n=>n==='lo')&&routes.length===0);
 check('nonroot-zero-effective-capabilities',process.getuid()===1001&&/^CapEff:\s+0+$/m.test(readFileSync('/proc/self/status','utf8')));
 const localhost=await lookup('localhost',{all:true});check('fixture-localhost-resolves-only-to-ipv6-edge',localhost.length>0&&localhost.every(a=>a.address==='::1'&&a.family===6));
 const nss=env.HOME+'/.pki/nssdb';mkdirSync(nss,{recursive:true,mode:0o700});command('/usr/bin/certutil',['-N','--empty-password','-d','sql:'+nss]);command('/usr/bin/certutil',['-A','-n','Revetsec disposable CA','-t','C,,','-i',root+'/ca.pem','-d','sql:'+nss]);
 command('/runtime/java/bin/keytool',['-importcert','-noprompt','-alias','local-cimd-ca','-file',root+'/ca.pem','-keystore',root+'/trust.p12','-storetype','PKCS12','-storepass','public-test-ca']);
 const config={root,issuer,resource,clientId,port:input.port,metadataDelayMs:input.metadataDelayMs};writeFileSync(root+'/driver-input.json',JSON.stringify(config),{mode:0o600});
 const cp=['self-issued-1.0.0.jar','revetsec-1.0.0.jar','revetsec-soklet-1.0.0.jar','soklet-4.0.0.jar'].map(n=>'/app/'+n).join(':');
 managed('application','/runtime/java/bin/java',['-Djavax.net.ssl.trustStore='+root+'/trust.p12','-Djavax.net.ssl.trustStorePassword=public-test-ca','-cp',cp,'example.issuer.IssuerPlayground'],{env:{...shared,REVETSEC_ISSUER_FRESH_NAMESPACE:'true',REVETSEC_ISSUER_ORIGIN:issuer,REVETSEC_ISSUER_RESOURCE:resource,REVETSEC_ISSUER_REDIRECT:'https://unused.example.com/callback',REVETSEC_ISSUER_BROWSER_ORIGIN:issuer,REVETSEC_ISSUER_HTTP_PORT:'8089',REVETSEC_ISSUER_MCP_PORT:String(input.port),REVETSEC_ISSUER_CIMD_ORIGIN:'https://vscode.dev',REVETSEC_ISSUER_CIMD_ADDRESS:'8.8.8.8',REVETSEC_ISSUER_LOGIN_KEY_FILE:root+'/login.key',REVETSEC_ISSUER_CLIENT_KEY_FILE:root+'/client.key',REVETSEC_ISSUER_RESOURCE_KEY_FILE:root+'/resource.key'}});
 managed('wire',process.execPath,['/suite/wire.mjs',root+'/driver-input.json']);
 managed('edge','/runtime/caddy',['run','--config','/suite/Caddyfile','--adapter','caddyfile'],{env:{...shared,REVETSEC_ISSUER_ORIGIN:issuer,REVETSEC_TLS_CERT:root+'/cert.pem',REVETSEC_TLS_KEY:root+'/key.pem'}});
 await until(tlsReady,'ISSUER_READY');check('issuer-normal-ca-hostname-validation',true);
 const profile=root+'/browser';mkdirSync(profile,{mode:0o700});
 managed('browser','/ms-playwright/chromium-1243/chrome-linux-arm64/chrome',chromeArguments(profile).map(a=>a.startsWith('--host-resolver-rules=')?'--host-resolver-rules=MAP localhost [::1],MAP * ~NOTFOUND,EXCLUDE 127.0.0.1':a));
 await until(()=>existsSync(profile+'/DevToolsActivePort'),'BROWSER_READY');const [port,path]=readFileSync(profile+'/DevToolsActivePort','utf8').trim().split('\n');browserConnection=await connectCdp('ws://127.0.0.1:'+port+path);connections.push(browserConnection);report.browser=browserVersion(await browserConnection.send('Browser.getVersion'));
 const target=await browserConnection.send('Target.createTarget',{url:'about:blank'});browserSession=await attach(browserConnection,target.targetId);
 await browserConnection.send('Network.enable',{},browserSession);await browserConnection.send('Page.enable',{},browserSession);await browserConnection.send('Fetch.enable',{patterns:[{urlPattern:'*',requestStage:'Request'}]},browserSession);
 browserConnection.on('Fetch.requestPaused',async(event,session)=>{try{
  const u=new URL(event.request.url);const allowed=u.origin===issuer||u.origin==='http://127.0.0.1:33418';
  report.browserRequests[allowed?'local':'blocked']++;
  if(u.origin==='http://127.0.0.1:33418'&&u.pathname==='/'&&u.searchParams.has('code')){report.callback.observed=true;report.callback.count=(report.callback.count??0)+1;report.callback.noReferrer=(report.callback.noReferrer??true)&&!Object.keys(event.request.headers).some(k=>k.toLowerCase()==='referer');}
  if(!closing)await browserConnection.send(allowed?'Fetch.continueRequest':'Fetch.failRequest',{requestId:event.requestId,...(allowed?{}:{errorReason:'BlockedByClient'})},session);
 }catch{if(!closing)report.browserPolicyFailure=true;}});
 // This is the disposable container's ordinary external-browser integration. The original URL is
 // delivered only over a private Unix socket and opened unchanged; it never enters evidence files.
 externalBrowser=createServer(socket=>{let size=0,parts=[];socket.on('data',p=>{size+=p.length;if(size>16384){socket.destroy();return;}parts.push(p);});socket.on('end',async()=>{try{const url=Buffer.concat(parts).toString('utf8');const u=new URL(url);if(u.origin!==issuer||u.pathname!=='/authorize'){report.unexpectedExternalOpen=true;return;}callbackOpened=true;await browserConnection.send('Page.navigate',{url},browserSession);}catch{if(!closing)report.browserOpenFailure=true;}});});
 await new Promise(resolve=>externalBrowser.listen(root+'/browser.sock',resolve));
 writeFileSync(root+'/bin/xdg-open',`#!/usr/bin/env node\nconst net=require('node:net');const c=net.connect(process.env.REVETSEC_QUAL_ROOT+'/browser.sock');c.on('connect',()=>c.end(process.argv.at(-1)));c.on('error',()=>process.exitCode=1);\n`,{mode:0o700});
 writeFileSync(root+'/user/User/settings.json',JSON.stringify({'telemetry.telemetryLevel':'off','update.mode':'none','extensions.autoUpdate':false,'extensions.autoCheckUpdates':false,'window.dialogStyle':'custom','workbench.startupEditor':'none','workbench.externalBrowser':root+'/bin/xdg-open','chat.disableAIFeatures':false,'security.workspace.trust.startupPrompt':'always','http.systemCertificates':true,'http.systemCertificatesNode':true}),{mode:0o600});
 managed('display','/usr/bin/Xvfb',[':79','-screen','0','1440x1000x24']);
 managed('vscode','/vscode/code',['--user-data-dir',root+'/user','--extensions-dir',root+'/extensions','--extensionDevelopmentPath=/suite/extension','--use-inmemory-secretstorage','--password-store=basic','--skip-welcome','--skip-release-notes','--host-resolver-rules=MAP localhost [::1],MAP * ~NOTFOUND,EXCLUDE 127.0.0.1','--no-proxy-server','--remote-debugging-port=9223',root+'/workspace']);
 await until(async()=>{try{const version=await(await fetch('http://127.0.0.1:9223/json/version',{signal:AbortSignal.timeout(1000)})).json();codeConnection=await connectCdp(version.webSocketDebuggerUrl);connections.push(codeConnection);return true;}catch{return false;}},'VSCODE_READY');
 let page;await until(async()=>{const targets=await codeConnection.send('Target.getTargets');page=targets.targetInfos.find(t=>t.type==='page');return !!page;},'VSCODE_WINDOW');codeSession=await attach(codeConnection,page.targetId);
 await codeConnection.send('Page.bringToFront',{},codeSession);
 await until(async()=>{try{return await evaluate(codeConnection,codeSession,`typeof document!=='undefined'&&!!document.body&&!!document.querySelector('.monaco-workbench')`);}catch{return false;}},'VSCODE_WINDOW');
 command('/usr/bin/python3',['/suite/focus.py',String(handles.vscode.child.pid)]);
 check('owned-vscode-window-has-normal-focus',await evaluate(codeConnection,codeSession,`document.hasFocus()`));
 stage('BROWSER_AUTHORIZATION');let loginSubmitted=false,lastDriverStage;const approvedForms=new Set();report.consentApprovals=[];
 await until(async()=>{
  if(!await evaluate(codeConnection,codeSession,`document.hasFocus()`)){command('/usr/bin/python3',['/suite/focus.py',String(handles.vscode.child.pid)]);report.focusRestorations=(report.focusRestorations??0)+1;}
  const item=await evaluate(codeConnection,codeSession,`(()=>{for(const label of ['Revetsec disposable qualification','Start Server']){const n=[...document.querySelectorAll('.quick-input-widget .monaco-list-row')].find(n=>n.getClientRects().length&&[...n.querySelectorAll('.label-name')].some(l=>l.textContent.trim()===label));if(n){const r=n.getBoundingClientRect();return {label,x:r.x+Math.min(50,r.width/2),y:r.y+r.height/2};}}return null;})()`);
  if(item){for(const type of ['mousePressed','mouseReleased'])await codeConnection.send('Input.dispatchMouseEvent',{type,x:item.x,y:item.y,button:'left',clickCount:1},codeSession);for(const type of ['keyDown','keyUp'])await codeConnection.send('Input.dispatchKeyEvent',{type,key:'Enter',code:'Enter',windowsVirtualKeyCode:13},codeSession);if(!report.uiActions.includes(item.label))report.uiActions.push(item.label);}
  const authClicked=await evaluate(codeConnection,codeSession,`(()=>{const roots=[...document.querySelectorAll('.notification-toast,.monaco-dialog-box,.notifications-toasts,.notifications-center')].filter(n=>n.getClientRects().length&&(n.textContent.includes('Revetsec')||n.textContent.includes('revetsec-qualification')||n.textContent.includes(${JSON.stringify('localhost:')})));for(const root of roots){const n=[...root.querySelectorAll('button,a,.monaco-button,[role="button"]')].find(n=>n.getClientRects().length&&['Sign in','Sign In','Authenticate','Open Browser','Open','Allow Authentication'].includes(n.textContent.trim()));if(n){const label=n.textContent.trim();n.click();return label;}}return null;})()`);
  if(authClicked&&!report.uiActions.includes('auth:'+authClicked))report.uiActions.push('auth:'+authClicked);
  const clicked=await evaluate(codeConnection,codeSession,clickText(knownButtons));if(clicked&&!report.uiActions.includes(clicked))report.uiActions.push(clicked);
  // A normal new-profile Restricted Mode banner exposes Manage, then the trust editor's Trust button.
  if(!clicked)await evaluate(codeConnection,codeSession,`(()=>{if(!document.body.textContent.includes('Restricted Mode'))return false;const n=[...document.querySelectorAll('a,button,[role="button"]')].find(n=>n.getClientRects().length&&n.textContent.trim()==='Manage');if(n){n.click();return true;}return false;})()`);
  if(callbackOpened){
   const forms=await evaluate(browserConnection,browserSession,`({login:document.querySelector('form[action="/login"]')!==null,consent:document.querySelector('form[action="/consent"]')!==null})`);
   if(forms.login&&!loginSubmitted){await evaluate(browserConnection,browserSession,`(()=>{const f=document.querySelector('form[action="/login"]');f.elements.key.value=${JSON.stringify(keys.login)};f.requestSubmit();return true;})()`);loginSubmitted=true;}
   if(forms.consent){
    const nonce=await evaluate(browserConnection,browserSession,`document.querySelector('form[action="/consent"]').elements.flow.value`);
    if(!approvedForms.has(nonce)){
     const authorizations=JSON.parse(readFileSync(root+'/wire.json','utf8')).events.filter(e=>e.kind==='AUTHORIZE');const authorization=authorizations.at(-1);
     check('consent-shows-client-resource-scopes-callback-'+authorizations.length,await evaluate(browserConnection,browserSession,`document.body.textContent.includes('Visual Studio Code')&&document.body.textContent.includes(${JSON.stringify(resource)})&&(document.body.textContent.includes('mcp:discover')===${authorization.scopesDiscover})&&(document.body.textContent.includes('mcp:whoami')===${authorization.scopesWhoami})&&document.body.textContent.includes('http://127.0.0.1:33418/')`));
     approvedForms.add(nonce);report.consentApprovals.push({discover:authorization.scopesDiscover,whoami:authorization.scopesWhoami,exactResource:true,exactCallback:true});
     await evaluate(browserConnection,browserSession,`(()=>{document.querySelector('button[name="decision"][value="approve"]').click();return true;})()`);
    }
   }
  }
  if(existsSync(root+'/wire.json')){const events=JSON.parse(readFileSync(root+'/wire.json','utf8')).events;if(events.some(e=>e.kind==='MCP'&&e.mcpMethod==='notifications/initialized'&&e.status===400))fail('CLIENT_PROTOCOL_REJECTED');}
  if(existsSync(root+'/driver-facts.json')){
   const driver=JSON.parse(readFileSync(root+'/driver-facts.json','utf8'));report.driver=driver;
   if(driver.stage!==lastDriverStage){lastDriverStage=driver.stage;stage(driver.stage);}
   if(driver.stage==='FAILED')fail('DRIVER_FAILED');
   if(driver.stage==='TOOLS_AVAILABLE'){report.realBrowserLogin=loginSubmitted;report.realBrowserConsent=approvedForms.size>0;return true;}
  }
  return false;
 },'CLIENT_WORKFLOW_TIMEOUT',430000);
 const wire=JSON.parse(readFileSync(root+'/wire.json','utf8'));report.events=wire.events;
 check('real-browser-login-consent-callback',report.realBrowserLogin&&report.realBrowserConsent&&report.callback.observed&&report.callback.noReferrer);
 check('no-browser-policy-failure',!report.browserPolicyFailure&&!report.browserOpenFailure&&!report.unexpectedExternalOpen);
 report.status='ADVANCED';stage('HANDSHAKE_ADVANCED');
}catch(error){report.failure=['ASSERTION','SETUP_COMMAND','ISSUER_READY','BROWSER_READY','VSCODE_READY','VSCODE_WINDOW','DOM_EVALUATION','DRIVER_FAILED','CLIENT_PROTOCOL_REJECTED','CLIENT_WORKFLOW_TIMEOUT'].includes(error.message)?error.message:'FIXED_RUN_FAILURE';
 // Retain only fixed UI labels and known stage/error categories; no DOM text or process logs.
 if(codeConnection&&codeSession)try{report.uiFacts=await evaluate(codeConnection,codeSession,`({restricted:document.body.textContent.includes('Restricted Mode'),signIn:document.body.textContent.includes('Sign In'),buttons:[...document.querySelectorAll('button,a,.monaco-button,[role="button"]')].filter(n=>n.getClientRects().length).map(n=>n.textContent.trim()).filter(t=>${JSON.stringify([...knownButtons,'Manage','Trust','Start','Cancel','Sign In','Open','Open Browser','Enable','I trust the authors'])}.includes(t))})`);}catch{}
 if(existsSync(root+'/wire.json'))try{report.events=JSON.parse(readFileSync(root+'/wire.json','utf8')).events;}catch{}
}finally{
 report.realBrowserLogin??=report.events?.some(e=>e.kind==='LOGIN'&&e.method==='POST'&&e.status===303)??false;
 report.realBrowserConsent??=(report.consentApprovals?.length??0)>0;
 if(report.status!=='ADVANCED'){
  const facts=new Set();let bytes=0,files=0;
  const scan=dir=>{if(!existsSync(dir))return;for(const item of readdirSync(dir,{withFileTypes:true})){const path=dir+'/'+item.name;if(item.isDirectory()){if(files<128)scan(path);}else if(item.isFile()&&files++<128&&statSync(path).size<=1000000&&bytes<8000000){const text=readFileSync(path,'utf8');bytes+=text.length;for(const code of fixedClientErrorCodes(text))facts.add(code);}}};
  try{scan(root+'/user/logs');report.fixedClientErrorCodes=[...facts].slice(0,16);}catch{}
 }
 closing=true;externalBrowser?.close();for(const connection of connections)connection.close();
 for(const [name,handle]of Object.entries(handles).reverse()){try{await handle.stop();await handle.completion.catch(()=>{});report.shutdown[name]='CLOSED';}catch{report.shutdown[name]='FAILED';report.status='FAILED';}}
 rmSync(root,{recursive:true,force:true});report.privateStateRemoved=!existsSync(root);
 writeFileSync('/evidence/RESULT.json',JSON.stringify(report,null,2)+'\n',{mode:0o600});
}
process.exitCode=report.status==='PASS'?0:1;
