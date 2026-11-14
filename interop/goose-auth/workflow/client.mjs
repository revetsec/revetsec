// Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
// Unmodified released Goose, real Chromium and exact packaged issuer; structural receipts only.
import {readFileSync,writeFileSync,existsSync,mkdirSync,rmSync} from 'node:fs';
import {randomBytes} from 'node:crypto';
import {dirname} from 'node:path';
import {createServer} from 'node:net';
import {networkInterfaces} from 'node:os';
import {spawnSync} from 'node:child_process';
import {request as httpsRequest} from 'node:https';
import {startProcess} from '/source/interop/inspector-auth/support/process.mjs';
import {connectCdp} from '/source/interop/inspector-auth/support/cdp.mjs';
import {chromeArguments,browserVersion} from '/source/interop/inspector-auth/support/web.mjs';
const input=JSON.parse(readFileSync(0,'utf8')),root='/tmp/revetsec-goose-client';mkdirSync(root,{mode:0o700});
const issuer='https://localhost:'+input.port,resource=issuer+'/mcp',clientId='https://goose-docs.ai/oauth/client-metadata.json',callback='http://127.0.0.1:33419/oauth_callback';
const report={status:'FAIL',stage:'SETUP',checks:[],shutdown:{},callback:{count:0,noReferrer:true},consentApprovals:[],browserRequests:{local:0,blocked:0},certificateErrorBypass:false,browserSandboxDisabled:false,globalTrustMutation:false,externalServices:false,accountSignIn:false,expiryMode:'stored-auth-reconnect'};
const env={PATH:[root+'/bin',dirname(process.execPath),'/runtime/java/bin','/usr/bin','/bin'].join(':'),HOME:root+'/home',XDG_CONFIG_HOME:root+'/config',XDG_CACHE_HOME:root+'/cache',XDG_DATA_HOME:root+'/data',TMPDIR:root+'/tmp',NO_COLOR:'1',REVETSEC_QUAL_ROOT:root,BROWSER:root+'/bin/xdg-open',NODE_EXTRA_CA_CERTS:root+'/ca.pem',NODE_OPTIONS:'--dns-result-order=ipv6first'};
for(const d of [env.HOME,env.XDG_CONFIG_HOME,env.XDG_CACHE_HOME,env.XDG_DATA_HOME,env.TMPDIR,root+'/bin'])mkdirSync(d,{recursive:true,mode:0o700});
for(const [n,v]of Object.entries({ca:input.ca,cert:input.cert,key:input.key}))writeFileSync(root+'/'+n+'.pem',v,{mode:0o600});
const keys={login:randomBytes(32).toString('base64url'),client:randomBytes(32).toString('base64url'),resource:randomBytes(32).toString('base64url')};for(const[n,v]of Object.entries(keys))writeFileSync(root+'/'+n+'.key',v,{mode:0o600});
const handles={},connections=[],started=performance.now();let browserConnection,browserSession,externalBrowser,closing=false,loginSubmitted=false,bootstrapSubmitted=false;
const pause=ms=>new Promise(r=>setTimeout(r,ms));
function stage(value){report.stage=value;writeFileSync('/evidence/PROGRESS.json',JSON.stringify({stage:value,checks:report.checks.length,elapsedMs:Math.floor(performance.now()-started)}),{mode:0o600});}
function fail(code){throw new Error(code);}
function check(name,value){report.checks.push({name,status:value?'PASS':'FAIL'});if(!value)fail('ASSERTION');}
function managed(name,command,args,extra={}){const h=startProcess(command,args,{cwd:root,env,timeoutMs:440000,maxOutputBytes:2097152,...extra});handles[name]=h;void h.completion.then(r=>{report.childExits??={};report.childExits[name]={code:r.code,facts:['certificate verify failed','UnknownIssuer','invalid peer certificate','Local issuer configuration rejected','adapting config','Permission denied','Cannot find module','No usable sandbox','certificate','tls','error sending request','timed out','connection refused','Failed to save'].filter(s=>r.stdout.includes(s)||r.stderr.includes(s))};}).catch(()=>{});return h;}
function command(exe,args){const r=spawnSync(exe,args,{env,timeout:15000,maxBuffer:65536});if(r.status!==0)fail('SETUP_COMMAND');}
async function until(probe,code,ms=25000){const end=performance.now()+ms;while(performance.now()<end){if(await probe())return;await pause(100);}fail(code);}
async function evaluate(expression){const r=await browserConnection.send('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true},browserSession);if(r.exceptionDetails)fail('DOM_EVALUATION');return r.result.value;}
function wire(){return JSON.parse(readFileSync(root+'/wire.json','utf8'));}
const approved=new Set();
async function browserTick(){
 const bootstrapExpression=`(()=>{if(location.origin!==${JSON.stringify(issuer)})return false;const f=Array.from(document.forms).find(f=>{const u=new URL(f.action,location.href);return f.method==='post'&&u.origin===location.origin&&u.pathname==='/session'&&u.search!==''&&f.elements.begin?.value==='1';});return !!f;})()`;
 const forms=await evaluate(`({login:document.querySelector('form[action="/login"]')!==null,consent:document.querySelector('form[action="/consent"]')!==null})`);
 if(!bootstrapSubmitted&&await evaluate(bootstrapExpression)){
  const submitted=await evaluate(bootstrapExpression.replace('return !!f;',"if(!f)return false;f.requestSubmit();return true;"));
  if(submitted){bootstrapSubmitted=true;report.browserBootstrap={count:1,originalForm:true,sameOrigin:true,methodPost:true};}return;
 }
 if(forms.login&&!loginSubmitted){await evaluate(`(()=>{const f=document.querySelector('form[action="/login"]');f.elements.key.value=${JSON.stringify(keys.login)};f.requestSubmit();return true;})()`);loginSubmitted=true;}
 if(forms.consent){
  const nonce=await evaluate(`document.querySelector('form[action="/consent"]').elements.flow.value`);
  if(!approved.has(nonce)){
   const authorization=wire().events.filter(e=>e.kind==='AUTHORIZE').at(-1);
   check('consent-shows-checked-client-resource-scopes-return-'+(approved.size+1),await evaluate(`document.body.textContent.includes('goose')&&document.body.textContent.includes(${JSON.stringify(resource)})&&(document.body.textContent.includes('mcp:discover')===${authorization.scopesDiscover})&&(document.body.textContent.includes('mcp:whoami')===${authorization.scopesWhoami})&&document.body.textContent.includes(${JSON.stringify(callback)})`));
   approved.add(nonce);report.consentApprovals.push({discover:authorization.scopesDiscover,whoami:authorization.scopesWhoami,exactResource:true,exactCallback:true});await evaluate(`(()=>{document.querySelector('button[name="decision"][value="approve"]').click();return true;})()`);
  }
 }
}
async function probe(name){
 const path=root+'/'+name+'.json';writeFileSync(path,JSON.stringify({protocolVersion:'2025-11-25',steps:[{action:'listTools'},{action:'callTool',name:'whoami',arguments:{}},{action:'callTool',name:'whoami',arguments:{tenant:'other'}}]}),{mode:0o600});
 const h=managed(name,'/client/goose',['mcp-probe',resource,'--script',path],{env:{...env,GOOSE_DISABLE_KEYRING:'1',GOOSE_PATH_ROOT:root+'/goose',GOOSE_DISABLE_TELEMETRY:'true',GOOSE_OAUTH_CALLBACK_PORT:'33419',SSL_CERT_FILE:'/etc/ssl/certs/ca-certificates.crt'}});let complete,result;
 void h.completion.then(r=>{result=r;complete=true;}).catch(()=>{complete=true;});
 await until(async()=>{await browserTick();return complete;},'GOOSE_WORKFLOW_TIMEOUT',115000);
 if(!result||result.code!==0)fail('GOOSE_FAILED');
 let data;try{data=JSON.parse(result.stdout);}catch{fail('GOOSE_OUTPUT');}
 const rows=data.results??[],listed=rows.find(r=>r.action==='listTools'),calls=rows.filter(r=>r.action==='callTool');
 const facts={catalog:listed?.result?.some?.(t=>t.name==='whoami')??listed?.result?.tools?.some(t=>t.name==='whoami')??false,checkedIdentity:calls[0]?.result?.isError!==true&&calls[0]?.result?.content?.some(p=>p.type==='text'&&/^Checked identity partition: [A-Za-z0-9_-]{43}; permitted scopes:/.test(p.text)&&p.text.includes('mcp:whoami'))===true,applicationDenial:calls[1]?.result?.isError===true&&calls[1]?.result?.content?.some(p=>p.type==='text'&&p.text==='Operation not permitted')===true};
 report.probes??={};report.probes[name]=facts;check(name+'-catalog-checked-call-and-application-denial',Object.values(facts).every(v=>v===true));
}
try{
 check('owned-network-none-loopback-only',Object.keys(networkInterfaces()).every(n=>n==='lo')&&readFileSync('/proc/net/route','utf8').trim().split('\n').length===1);
 check('nonroot-zero-effective-capabilities',process.getuid()===1001&&/^CapEff:\s+0+$/m.test(readFileSync('/proc/self/status','utf8')));
 const nss=env.HOME+'/.pki/nssdb';mkdirSync(nss,{recursive:true,mode:0o700});command('/usr/bin/certutil',['-N','--empty-password','-d','sql:'+nss]);command('/usr/bin/certutil',['-A','-n','Revetsec disposable CA','-t','C,,','-i',root+'/ca.pem','-d','sql:'+nss]);command('/runtime/java/bin/keytool',['-importcert','-noprompt','-alias','local-cimd-ca','-file',root+'/ca.pem','-keystore',root+'/trust.p12','-storetype','PKCS12','-storepass','public-test-ca']);
 writeFileSync(root+'/driver-input.json',JSON.stringify({root,issuer,resource,clientId,port:input.port,metadataDelayMs:input.metadataDelayMs}),{mode:0o600});
 const cp=['self-issued-1.0.0.jar','revetsec-1.0.0.jar','revetsec-soklet-1.0.0.jar','soklet-4.0.0.jar'].map(n=>'/app/'+n).join(':');
 managed('application','/runtime/java/bin/java',['-Djavax.net.ssl.trustStore='+root+'/trust.p12','-Djavax.net.ssl.trustStorePassword=public-test-ca','-cp',cp,'example.issuer.IssuerPlayground'],{env:{...env,REVETSEC_ISSUER_FRESH_NAMESPACE:'true',REVETSEC_ISSUER_ORIGIN:issuer,REVETSEC_ISSUER_RESOURCE:resource,REVETSEC_ISSUER_REDIRECT:'https://unused.example.com/callback',REVETSEC_ISSUER_BROWSER_ORIGIN:issuer,REVETSEC_ISSUER_HTTP_PORT:'8089',REVETSEC_ISSUER_MCP_PORT:String(input.port),REVETSEC_ISSUER_CIMD_ORIGIN:'https://goose-docs.ai',REVETSEC_ISSUER_CIMD_ADDRESS:'8.8.8.8',REVETSEC_ISSUER_LOGIN_KEY_FILE:root+'/login.key',REVETSEC_ISSUER_CLIENT_KEY_FILE:root+'/client.key',REVETSEC_ISSUER_RESOURCE_KEY_FILE:root+'/resource.key'}});
 managed('wire',process.execPath,['/suite/wire.mjs',root+'/driver-input.json']);managed('edge','/runtime/caddy',['run','--config','/suite/Caddyfile','--adapter','caddyfile'],{env:{...env,REVETSEC_ISSUER_ORIGIN:issuer,REVETSEC_TLS_CERT:root+'/cert.pem',REVETSEC_TLS_KEY:root+'/key.pem'}});
 await until(()=>new Promise(resolve=>{const r=httpsRequest(issuer+'/.well-known/oauth-authorization-server',{ca:input.ca,rejectUnauthorized:true,family:6,timeout:1500},s=>{s.resume();s.on('end',()=>resolve(s.statusCode===200));});r.on('error',()=>resolve(false));r.on('timeout',()=>r.destroy());r.end();}),'ISSUER_READY');check('issuer-normal-ca-hostname-validation',true);
 const profile=root+'/browser';mkdirSync(profile,{mode:0o700});managed('browser','/ms-playwright/chromium-1243/chrome-linux-arm64/chrome',chromeArguments(profile).map(a=>a.startsWith('--host-resolver-rules=')?'--host-resolver-rules=MAP localhost [::1],MAP * ~NOTFOUND,EXCLUDE 127.0.0.1':a));
 await until(()=>existsSync(profile+'/DevToolsActivePort'),'BROWSER_READY');const [port,path]=readFileSync(profile+'/DevToolsActivePort','utf8').trim().split('\n');browserConnection=await connectCdp('ws://127.0.0.1:'+port+path);connections.push(browserConnection);report.browser=browserVersion(await browserConnection.send('Browser.getVersion'));const target=await browserConnection.send('Target.createTarget',{url:'about:blank'});browserSession=(await browserConnection.send('Target.attachToTarget',{targetId:target.targetId,flatten:true})).sessionId;await browserConnection.send('Runtime.enable',{},browserSession);await browserConnection.send('Network.enable',{},browserSession);await browserConnection.send('Page.enable',{},browserSession);await browserConnection.send('Fetch.enable',{patterns:[{urlPattern:'*',requestStage:'Request'}]},browserSession);
 browserConnection.on('Fetch.requestPaused',async(e,s)=>{try{const u=new URL(e.request.url),allowed=u.origin===issuer||u.origin==='http://127.0.0.1:33419';report.browserRequests[allowed?'local':'blocked']++;if(u.origin==='http://127.0.0.1:33419'&&u.pathname==='/oauth_callback'&&u.searchParams.has('code')){report.callback.count++;report.callback.noReferrer&&=!Object.keys(e.request.headers).some(k=>k.toLowerCase()==='referer');}if(!closing)await browserConnection.send(allowed?'Fetch.continueRequest':'Fetch.failRequest',{requestId:e.requestId,...(allowed?{}:{errorReason:'BlockedByClient'})},s);}catch{if(!closing)report.browserPolicyFailure=true;}});
 externalBrowser=createServer(socket=>{let size=0,parts=[];socket.on('data',p=>{size+=p.length;if(size>16384){socket.destroy();return;}parts.push(p);});socket.on('end',async()=>{try{const url=Buffer.concat(parts).toString('utf8'),u=new URL(url);if(u.origin!==issuer||u.pathname!=='/authorize'){report.unexpectedExternalOpen=true;return;}report.browserOpenCount=(report.browserOpenCount??0)+1;await browserConnection.send('Page.navigate',{url},browserSession);}catch{if(!closing)report.browserOpenFailure=true;}});});await new Promise(r=>externalBrowser.listen(root+'/browser.sock',r));writeFileSync(root+'/bin/xdg-open',`#!/usr/bin/env node\nconst net=require('node:net');const c=net.connect(process.env.REVETSEC_QUAL_ROOT+'/browser.sock');c.on('connect',()=>c.end(process.argv.at(-1)));c.on('error',()=>process.exitCode=1);\n`,{mode:0o700});
 stage('FIRST_BROWSER_CODE_TOOL');await probe('initial');
 const codes=wire().events.filter(e=>e.kind==='TOKEN'&&e.codeGrant&&e.status===200),last=codes.at(-1);check('ordinary-expiry-bounded-by-two-minute-policy',last?.expirySeconds>=119&&last?.expirySeconds<=120);
 stage('REAL_EXPIRY_WAIT');const waitStart=performance.now();await pause(121500);report.expiryWaitMs=Math.floor(performance.now()-waitStart);
 stage('STORED_AUTH_REFRESH_TOOL');await probe('after-expiry');report.realBrowserLogin=loginSubmitted;report.realBrowserConsent=approved.size>0;
 check('no-browser-policy-failure',!report.browserPolicyFailure&&!report.browserOpenFailure&&!report.unexpectedExternalOpen);report.status='PASS';stage('COMPLETE');
}catch(error){report.failure=['ASSERTION','SETUP_COMMAND','DOM_EVALUATION','ISSUER_READY','BROWSER_READY','GOOSE_WORKFLOW_TIMEOUT','GOOSE_FAILED','GOOSE_OUTPUT'].includes(error.message)?error.message:'FIXED_RUN_FAILURE';}
finally{
 if(existsSync(root+'/wire.json'))try{report.events=wire().events;}catch{}
 closing=true;externalBrowser?.close();for(const connection of connections)connection.close();
 for(const[name,h]of Object.entries(handles).reverse()){try{await h.stop();await h.completion.catch(()=>{});report.shutdown[name]='CLOSED';}catch{report.shutdown[name]='FAILED';report.status='FAIL';}}
 rmSync(root,{recursive:true,force:true});report.privateStateRemoved=!existsSync(root);writeFileSync('/evidence/RESULT.json',JSON.stringify(report,null,2)+'\n',{mode:0o600});
}
process.exitCode=report.status==='PASS'?0:1;
