// Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
// Owned isolated browser fixture. Never retain credentials, raw network payloads, browser profiles or TLS keys.
import {networkInterfaces} from 'node:os';
import {randomBytes} from 'node:crypto';
import {setDefaultResultOrder} from 'node:dns';
import {spawnSync} from 'node:child_process';
import {request as httpsRequest} from 'node:https';
import {existsSync,mkdirSync,readFileSync,writeFileSync,rmSync,readdirSync,readlinkSync} from 'node:fs';
import {startProcess} from '/source/interop/inspector-auth/support/process.mjs';
import {createEnvironment} from '/source/interop/inspector-auth/support/config.mjs';
import {connectCdp} from '/source/interop/inspector-auth/support/cdp.mjs';
import {chromeArguments,browserVersion} from '/source/interop/inspector-auth/support/web.mjs';
import {directoryIdentity,verifyDependencyPins} from '/source/interop/inspector-auth/support/identity.mjs';

setDefaultResultOrder('ipv6first');
const input=JSON.parse(readFileSync(0,'utf8'));
if(!['public','confidential','cimd'].includes(input.clientType)||!['legacy','modern'].includes(input.era)
  ||!Number.isSafeInteger(input.port)||input.port<10000||input.port>60000)throw new Error('CLIENT_INPUT');
input.secondResource??=false;if(typeof input.secondResource!=='boolean'||input.secondResource&&input.recovery&&input.recovery!=='none')throw new Error('CLIENT_INPUT');
input.returnMode??='exact-native';input.recovery??='none';
if(!['none','expiry','step-up'].includes(input.recovery))throw new Error('CLIENT_INPUT');
if(!['exact-native','native-port','https','native-ephemeral-ipv4','native-ephemeral-ipv6'].includes(input.returnMode))throw new Error('CLIENT_INPUT');
const native=input.returnMode.startsWith('native-ephemeral-'),nativeHost=input.returnMode==='native-ephemeral-ipv6'?'[::1]':'127.0.0.1';
input.nativeFollowupEra??=input.era;if(!['legacy','modern'].includes(input.nativeFollowupEra)||native&&(input.clientType==='cimd'||input.recovery!=='none'||input.secondResource))throw new Error('CLIENT_INPUT');
const root='/tmp/revetsec-self-issued-client';mkdirSync(root,{mode:0o700});
const env=createEnvironment(root,'/runtime/java/bin/java');
for(const key of ['HOME','XDG_CONFIG_HOME','XDG_CACHE_HOME','TMPDIR','MCP_STORAGE_DIR'])mkdirSync(env[key],{recursive:true,mode:0o700});
for(const [name,value]of Object.entries({ca:input.ca,cert:input.cert,key:input.key}))writeFileSync(root+'/'+name+'.pem',value,{mode:0o600});
const keys={login:randomBytes(32).toString('base64url'),client:randomBytes(32).toString('base64url'),resource:randomBytes(32).toString('base64url')};
for(const [name,value]of Object.entries(keys))writeFileSync(root+'/'+name+'.key',value,{mode:0o600});
const issuer='https://localhost:'+input.port,resource=issuer+'/mcp',origin=native?issuer:input.returnMode==='https'?'https://localhost:6276':'http://127.0.0.1:6274',untrustedOrigin='http://127.0.0.1:6275';
const cimd=input.clientType==='cimd',metadataUrl='https://cimd.example.com:6277/client.json';
const clientId=cimd?metadataUrl:'demo-'+input.clientType;let redirect=native?'http://'+nativeHost+':0/oauth/callback':origin+'/oauth/callback';
const registeredRedirect=native?'http://'+nativeHost+':6273/oauth/callback':input.returnMode==='native-port'?'http://127.0.0.1:6273/oauth/callback':redirect;
const report={status:'FAILED',stage:'SETUP',clientType:input.clientType,era:input.era,returnMode:input.returnMode,nativeFollowupEra:input.nativeFollowupEra,nativeExecutable:native,recovery:input.recovery,secondResource:input.secondResource,issuer,registeredRedirect,requestedRedirect:redirect,browserOrigin:origin,
  certificateErrorBypass:false,browserSandboxDisabled:false,globalTrustMutation:false,externalServices:false,
  checks:[],network:{local:0,blockedFont:0,unexpected:0},http:[],methods:[],browserExceptions:0,shutdown:{}};
const started=Date.now();
function stage(value){report.stage=value;writeFileSync('/evidence/PROGRESS.json',JSON.stringify({stage:value,recovery:input.recovery,checks:report.checks.length,elapsedMs:Date.now()-started}),{mode:0o600});}
const handles={},sessions=new Map(),requests=new Map(),requestKinds=new Map();let cdp,closing=false,inspectorSession;
const failure=code=>{throw new Error(code);};
function check(name,condition){report.checks.push({name,status:condition?'PASS':'FAIL'});if(!condition)failure('CLIENT_ASSERTION');}
const pause=()=>new Promise(resolve=>setTimeout(resolve,50));
async function waitFor(probe,code,ms=15000){const until=Date.now()+ms;while(Date.now()<until){try{if(await probe())return;}catch(error){if(['CLIENT_ASSERTION','CLIENT_LOGIN_REJECTED'].includes(error.message))throw error;}await pause();}failure(code);}
function managed(name,command,args,extra={}){const h=startProcess(command,args,{cwd:root,env,timeoutMs:input.recovery==='none'?210000:310000,maxOutputBytes:1048576,...extra});handles[name]=h;for(const stream of [h.child.stdout,h.child.stderr])stream.on('data',chunk=>{const value=chunk.toString('utf8');report.childErrorFacts??={};const facts=report.childErrorFacts[name]??=[];for(const category of ['no certificate available','no matching certificates','failed to get certificate','wrong version number','permission denied','cannot assign requested address','adapting config','error during handshake'])if(value.includes(category)&&!facts.includes(category))facts.push(category);report.childErrorFacts[name]=facts;});void h.completion.then(result=>{report.childExitFacts??={};report.childExitFacts[name]={code:result.code,signaled:result.signal!==null,fixedErrorCategories:['cannot assign requested address','address already in use','adapting config','unrecognized directive','permission denied','Local issuer configuration rejected','java.net.BindException','ExceptionInInitializerError','network is unreachable'].filter(text=>result.stdout.includes(text)||result.stderr.includes(text))};}).catch(()=>{});return h;}
function command(executable,args){const r=spawnSync(executable,args,{env,encoding:'utf8',timeout:10000,maxBuffer:65536});if(r.status!==0)failure('CLIENT_SETUP_COMMAND');}
async function tlsGet(url){return new Promise((resolve,reject)=>{const r=httpsRequest(url,{ca:input.ca,rejectUnauthorized:true,family:6,timeout:2000},s=>{s.resume();s.once('end',()=>{report.tlsReadinessStatus=s.statusCode;resolve(s.statusCode);});});r.once('error',e=>{report.tlsReadinessReason=['tlsv1 alert internal error','wrong version number','certificate verify failed','tlsv1 unrecognized name'].filter(n=>e.reason?.includes(n)||e.message?.includes(n));report.tlsReadinessError=typeof e.code==='string'&&/^[A-Z][A-Z0-9_]{1,63}$/.test(e.code)?e.code:'OTHER';reject(e);});r.once('timeout',()=>r.destroy());r.end();});}
async function evaluate(session,expression){const r=await cdp.send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true},session);if(r.exceptionDetails)failure('CLIENT_DOM_EVALUATION');return r.result.value;}
function clickText(text){return `(()=>{const n=[...document.querySelectorAll('button')].filter(n=>n.getClientRects().length&&!n.disabled&&n.textContent.trim()===${JSON.stringify(text)});if(n.length!==1)return false;n[0].click();return true;})()`;}
function clickSelector(selector){return `(()=>{const n=[...document.querySelectorAll(${JSON.stringify(selector)})].filter(n=>n.getClientRects().length&&!n.disabled);if(n.length!==1)return false;n[0].click();return true;})()`;}
async function attach(targetId){if(sessions.has(targetId))return sessions.get(targetId);const {sessionId}=await cdp.send('Target.attachToTarget',{targetId,flatten:true});sessions.set(targetId,sessionId);for(const domain of ['Page','Runtime','Network','Log'])await cdp.send(domain+'.enable',{},sessionId);await cdp.send('Fetch.enable',{patterns:[{urlPattern:'*',requestStage:'Request'}]},sessionId);return sessionId;}
function label(value){try{const u=new URL(value);if(u.pathname==='/authorize')return 'AUTHORIZE';if(u.pathname==='/login')return 'LOGIN';if(u.pathname==='/consent')return 'CONSENT';if(u.pathname==='/oauth/callback')return 'CALLBACK';if(u.pathname.includes('.well-known'))return 'METADATA';if(u.pathname==='/token')return 'TOKEN';if(u.pathname==='/api/mcp/send')return 'MCP_SEND';if(u.pathname==='/api/mcp/connect')return 'MCP_CONNECT';return 'OTHER_LOCAL';}catch{return 'INVALID';}}
const selector='[aria-label=\'Connect or disconnect "revetsec_self_issued"\']';
const proofExpression=`(()=>{const nodes=document.querySelectorAll('[data-testid=tools-screen] pre,[data-testid=tools-screen] code,[data-testid=tools-screen] .ace_text-layer');return [...nodes].some(n=>n.getClientRects().length&&n.textContent.length<16384&&/Checked identity partition: [A-Za-z0-9_-]{43}; permitted scopes:/.test(n.textContent)&&n.textContent.includes('mcp:whoami'));})()`;
const appForms=new Map();let loginObserved=false,consentObserved=false;
try{
 stage('SETUP');
 const pins=JSON.parse(readFileSync('/source/interop/inspector-auth/client/pins.json'));
 verifyDependencyPins(readFileSync('/private/inspector-client/package.json'),readFileSync('/private/inspector-client/package-lock.json'),pins);
 report.clientTreeBefore=directoryIdentity('/private/inspector-client/node_modules');
 report.client={version:'2.9.0',commit:pins.commit,lockSha256:pins.lockSha256,integrity:pins.integrity,node:process.version};
 const nss=env.HOME+'/.pki/nssdb';mkdirSync(nss,{recursive:true,mode:0o700});
 command('/usr/bin/certutil',['-N','--empty-password','-d','sql:'+nss]);
 command('/usr/bin/certutil',['-A','-n','Revetsec disposable test CA','-t','C,,','-i',root+'/ca.pem','-d','sql:'+nss]);
 const shared={...env,NODE_OPTIONS:'--dns-result-order=ipv6first',NODE_EXTRA_CA_CERTS:root+'/ca.pem'};
 if(cimd){
  const interfaces=Object.keys(networkInterfaces());
  const routes=readFileSync('/proc/net/route','utf8').trim().split('\n').slice(1).map(row=>row.trim().split(/\s+/));report.namespaceFacts={interfaceCount:interfaces.length,onlyLoopback:interfaces.every(n=>n==='lo'),routeCount:routes.length,onlyLoopbackRoutes:routes.every(row=>row[0]==='lo'&&row[1]!=='00000000'&&row[2]==='00000000')};
  check('cimd-public-form-peer-isolated-on-loopback-only',interfaces.length===1&&interfaces[0]==='lo'&&report.namespaceFacts.onlyLoopbackRoutes);
  check('cimd-browser-runtime-nonroot-zero-effective-capabilities',process.getuid()===1001&&/^CapEff:\s+0+$/m.test(readFileSync('/proc/self/status','utf8')));
  command('/runtime/java/bin/keytool',['-importcert','-noprompt','-alias','local-cimd-ca','-file',root+'/ca.pem','-keystore',root+'/cimd-trust.p12','-storetype','PKCS12','-storepass','public-test-ca']);
 }
 const javaTrust=cimd?['-Djavax.net.ssl.trustStore='+root+'/cimd-trust.p12','-Djavax.net.ssl.trustStorePassword=public-test-ca']:[];
 const cp=['self-issued-1.0.0-SNAPSHOT.jar','revetsec-1.0.0-SNAPSHOT.jar','revetsec-soklet-1.0.0-SNAPSHOT.jar','soklet-4.0.0.jar'].map(n=>'/app/'+n).join(':');
 managed('application','/runtime/java/bin/java',[...javaTrust,'-cp',cp,'example.issuer.IssuerPlayground'],{env:{...shared,
  ...(cimd?{REVETSEC_ISSUER_CIMD_ORIGIN:'https://cimd.example.com:6277',REVETSEC_ISSUER_CIMD_ADDRESS:'8.8.8.8'}:{}),REVETSEC_ISSUER_SECOND_RESOURCE:String(input.secondResource),REVETSEC_ISSUER_FRESH_NAMESPACE:'true',REVETSEC_ISSUER_ORIGIN:issuer,REVETSEC_ISSUER_RESOURCE:resource,
  REVETSEC_ISSUER_REDIRECT:registeredRedirect,REVETSEC_ISSUER_BROWSER_ORIGIN:origin,REVETSEC_ISSUER_HTTP_PORT:'8089',REVETSEC_ISSUER_MCP_PORT:String(input.port),
  REVETSEC_ISSUER_LOGIN_KEY_FILE:root+'/login.key',REVETSEC_ISSUER_CLIENT_KEY_FILE:root+'/client.key',REVETSEC_ISSUER_RESOURCE_KEY_FILE:root+'/resource.key'}});
 managed('wire',process.execPath,['/suite/wire-proxy.mjs',root+'/wire.json',String(input.port),issuer,redirect,String(input.secondResource),cimd?metadataUrl:'',native?'native':''],{env:shared});
 const edgeConfig=readFileSync('/suite/Caddyfile','utf8');writeFileSync(root+'/edge.Caddyfile',cimd?edgeConfig:edgeConfig.replace(/# BEGIN OPTIONAL CIMD[\s\S]*# END OPTIONAL CIMD\n?/,''),{mode:0o600});
 managed('edge','/runtime/caddy',['run','--config',root+'/edge.Caddyfile','--adapter','caddyfile'],{env:{...shared,
  REVETSEC_ISSUER_ORIGIN:issuer,REVETSEC_BROWSER_TLS_ORIGIN:'https://localhost:6276',REVETSEC_TLS_CERT:root+'/cert.pem',REVETSEC_TLS_KEY:root+'/key.pem',XDG_DATA_HOME:root+'/caddy-data'}});
 await waitFor(async()=>await tlsGet(issuer+'/.well-known/oauth-authorization-server')===200,'CLIENT_ISSUER_READY');
 check('ordinary-ca-and-hostname-validated-issuer',true);
 const config={mcpServers:{revetsec_self_issued:{type:'http',url:resource,protocolEra:input.era,
  advertisedExtensions:{'io.modelcontextprotocol/ui':false,'io.modelcontextprotocol/skills':false},
  oauth:{...(cimd?{}:{clientId}),scopes:input.recovery==='step-up'?'mcp:discover':'mcp:discover mcp:whoami',...(input.clientType==='confidential'?{clientSecret:keys.client}:{})}}}};
 if(input.secondResource)config.mcpServers.revetsec_second_resource={...config.mcpServers.revetsec_self_issued,url:issuer+'/mcp-second'};
 if(cimd)writeFileSync(env.MCP_CLIENT_CONFIG_PATH,JSON.stringify({cimd:{enabled:true,clientMetadataUrl:metadataUrl}}),{mode:0o600});
 writeFileSync(root+'/session.json',JSON.stringify(config),{mode:0o600});
 if(!native){
 const hostToken=randomBytes(32).toString('hex');
 managed('inspector',process.execPath,['/private/inspector-client/node_modules/@modelcontextprotocol/inspector/clients/launcher/build/index.js','--web','--config',root+'/session.json'],{env:{...shared,
  HOST:'127.0.0.1',CLIENT_PORT:'6274',ALLOWED_ORIGINS:origin+',http://localhost:6274',MCP_SANDBOX_PORT:'0',MCP_APP_ORIGIN_PORT:'0',MCP_INSPECTOR_API_TOKEN:hostToken}});
 await waitFor(async()=>{const r=await fetch('http://127.0.0.1:6274/api/config',{headers:{Origin:origin,'x-mcp-remote-auth':'Bearer '+hostToken},signal:AbortSignal.timeout(1500)});if(r.status!==200){await r.body.cancel();return false;}const c=await r.json();return c.writable===false&&c.secretStorage?.kind==='memory'&&c.secretStorage?.durable===false;},'CLIENT_INSPECTOR_READY');
 check(cimd?'unmodified-released-cimd-config-without-preregistered-client-id':'unmodified-released-preregistration-memory-session',cimd?!Object.hasOwn(config.mcpServers.revetsec_self_issued.oauth,'clientId'):true);
 check('callback-registration-policy-exercised',input.returnMode==='native-port'?new URL(registeredRedirect).port!==new URL(redirect).port&&new URL(registeredRedirect).hostname===new URL(redirect).hostname&&new URL(registeredRedirect).pathname===new URL(redirect).pathname:registeredRedirect===redirect);
 check('browser-return-origin-transport-validated',input.returnMode==='https'?await tlsGet(origin)===200:new URL(origin).hostname==='127.0.0.1'&&new URL(origin).protocol==='http:');
 }
 const profile=root+'/chrome-profile';mkdirSync(profile,{mode:0o700});
 managed('browser','/ms-playwright/chromium-1243/chrome-linux-arm64/chrome',chromeArguments(profile).map(arg=>arg.startsWith('--host-resolver-rules=')?'--host-resolver-rules=MAP localhost [::1],MAP * ~NOTFOUND,EXCLUDE 127.0.0.1'+(native?',EXCLUDE ::1':''):arg));
 await waitFor(()=>existsSync(profile+'/DevToolsActivePort'),'CLIENT_BROWSER_READY');
 const [port,path]=readFileSync(profile+'/DevToolsActivePort','utf8').trim().split('\n');cdp=await connectCdp('ws://127.0.0.1:'+port+path);
 report.browser=browserVersion(await cdp.send('Browser.getVersion'));
 cdp.on('Log.entryAdded',event=>{const text=event.entry?.text??'';if(text.includes('Content Security Policy')||text.includes('form-action')){report.cspFacts??={};if(text.includes('[::1]'))report.cspFacts.ipv6SourceMentioned=true;if(text.includes('form-action')&&text.toLowerCase().includes('violat'))report.cspFacts.formActionViolation=true;}});
 cdp.on('Runtime.exceptionThrown',()=>{report.browserExceptions++;});
 cdp.on('Fetch.requestPaused',async(event,session)=>{
  let allowed=false;const req=event.request;
  try{const u=new URL(req.url);if([origin,untrustedOrigin,issuer,...(native&&new URL(redirect).port!=='0'?[new URL(redirect).origin]:[])].includes(u.origin)){allowed=true;report.network.local++;
   if(u.origin===(native?new URL(redirect).origin:origin)&&u.pathname==='/oauth/callback')report.callbackNoReferrer=!Object.keys(req.headers).some(k=>k.toLowerCase()==='referer');
   if(u.origin===issuer&&['/login','/consent'].includes(u.pathname)&&req.method==='POST'){const h=Object.fromEntries(Object.entries(req.headers).map(([k,v])=>[k.toLowerCase(),v]));report.formOrigin={sameOrigin:h.origin===issuer,opaqueNull:h.origin==='null',absent:h.origin==null};}
   if(u.origin===issuer&&u.pathname==='/authorize'){const q=u.searchParams;report.authorization={registeredClient:q.get('client_id')===clientId,exactCallback:q.get('redirect_uri')===redirect,resource:q.get('resource')===resource,s256:q.get('code_challenge_method')==='S256'&&/^[A-Za-z0-9_-]{43}$/.test(q.get('code_challenge')??'')};if(input.secondResource&&q.get('resource')===issuer+'/mcp-second')report.secondAuthorization={...report.authorization,resource:true};}
   if(u.origin===origin&&u.pathname==='/api/mcp/send'&&req.method==='POST'&&typeof req.postData==='string'&&req.postData.length<32768){const packet=JSON.parse(req.postData),message=packet.message;if(['initialize','server/discover','tools/list','tools/call'].includes(message?.method)&&!report.methods.includes(message.method))report.methods.push(message.method);if(message?.method==='tools/call'&&message.params?.name==='whoami'){const a=message.params.arguments??{};report.toolArgumentsLocalSelf=(a.tenant??'local')==='local'&&(a.object??'self')==='self';}}}
   else if(u.origin==='https://fonts.googleapis.com'&&u.pathname==='/css2')report.network.blockedFont++;
   else report.network.unexpected++;
  }catch{report.network.unexpected++;}
  if(!closing)await cdp.send(allowed?'Fetch.continueRequest':'Fetch.failRequest',{requestId:event.requestId,...(!allowed?{errorReason:'BlockedByClient'}:{})},session);
 });
 cdp.on('Network.loadingFailed',event=>{report.browserNetworkFailures??=[];if(report.browserNetworkFailures.length<16)report.browserNetworkFailures.push({error:/^(net::)?ERR_[A-Z_]+$/.test(event.errorText??'')?event.errorText:'OTHER',canceled:event.canceled===true,requestKind:requestKinds.get(event.requestId)??'OTHER'});});
 cdp.on('Network.requestWillBeSent',event=>{if(requestKinds.size<512){let kind=label(event.request.url);try{if(new URL(event.request.url).pathname==='/favicon.ico')kind='FAVICON';}catch{}requestKinds.set(event.requestId,kind);}if(requests.size<512)requests.set(event.requestId,['GET','POST','OPTIONS'].includes(event.request.method)?event.request.method:'OTHER');});
 cdp.on('Network.responseReceived',event=>{if(label(event.response.url)==='LOGIN'&&event.response.status===403)report.loginRejected=true;if(report.http.length<192)report.http.push({path:label(event.response.url),status:event.response.status,method:requests.get(event.requestId)??'OTHER'});});
 await cdp.send('Target.setDiscoverTargets',{discover:true});
 const {targetId}=await cdp.send('Target.createTarget',{url:'about:blank'});inspectorSession=await attach(targetId);
 if(native){
  const callbackConfig='http://'+nativeHost+':0/oauth/callback';
  const cli='/private/inspector-client/node_modules/@modelcontextprotocol/inspector/clients/cli/build/index.js';
  const cliEnv={...shared,MCP_AUTO_OPEN_ENABLED:'true',MCP_INSPECTOR_SECRET_STORE:'file'};
  function nativeClient(name,method,era,extra=[]){return managed(name,process.execPath,[cli,'--config',root+'/session.json','--server','revetsec_self_issued','--callback-url',callbackConfig,'--protocol-era',era,'--format','json','--method',method,...extra],{env:cliEnv});}
  function ownedListeners(handle){
   const inodes=new Set();for(const name of readdirSync('/proc/'+handle.child.pid+'/fd'))try{const target=readlinkSync('/proc/'+handle.child.pid+'/fd/'+name);if(/^socket:\[\d+\]$/.test(target))inodes.add(target.slice(8,-1));}catch{}
   const facts=[];for(const [file,family,address]of [['tcp','IPv4','0100007F'],['tcp6','IPv6','00000000000000000000000001000000']]){
    for(const line of readFileSync('/proc/'+handle.child.pid+'/net/'+file,'utf8').trim().split('\n').slice(1)){
     const fields=line.trim().split(/\s+/),[host,port]=fields[1].split(':');if(fields[3]==='0A'&&inodes.has(fields[9]))facts.push({family,port:parseInt(port,16),exactLoopback:host===address});
    }
   }return facts;
  }
  stage('NATIVE_AUTHORIZATION');const list=nativeClient('native-list','tools/list',input.era);let printed='',authorizationUrl;
  list.child.stderr.on('data',chunk=>{printed+=chunk.toString('utf8');if(printed.length>32768)printed=printed.slice(-32768);const match=printed.match(/Please navigate to: (https?:\/\/[^\s]+)\s/);if(match&&!authorizationUrl){authorizationUrl=match[1];printed='';}});
  await waitFor(()=>authorizationUrl!==undefined,'CLIENT_NATIVE_AUTHORIZATION_URL');
  const authorization=new URL(authorizationUrl),selected=authorization.searchParams.get('redirect_uri');let parsed;
  try{parsed=new URL(selected);}catch{failure('CLIENT_NATIVE_CALLBACK_FORMAT');}
  const registered=new URL(registeredRedirect);
  if(authorization.origin!==issuer||authorization.pathname!=='/authorize'||parsed.hostname!==nativeHost||parsed.protocol!=='http:'||parsed.pathname!==registered.pathname||parsed.search!==registered.search||parsed.hash!==''||parsed.username!==''||parsed.password!==''||selected!==parsed.href)failure('CLIENT_NATIVE_CALLBACK_FORMAT');
  const listeners=ownedListeners(list);report.nativeListenerFacts=listeners;
  report.nativePort={configuredPort:0,selectedPort:Number(parsed.port),registeredPort:6273,family:nativeHost==='[::1]'?'IPv6':'IPv4'};
  report.requestedRedirect=selected;redirect=selected;
  if(parsed.port==='0'){
   report.nativeFailureFacts={printedZeroPort:true,ownsNonzeroLoopbackListener:listeners.length===1&&listeners[0].port>0&&listeners[0].exactLoopback};
   await cdp.send('Page.navigate',{url:authorizationUrl},inspectorSession);
   await waitFor(()=>report.http.some(r=>r.path==='AUTHORIZE'&&r.status===400),'CLIENT_NATIVE_ZERO_PORT_ISSUER_REJECTION');
   failure('CLIENT_NATIVE_ZERO_REDIRECT');
  }
  check('native-client-own-os-selected-ip-loopback-listener',listeners.length===1&&listeners[0].exactLoopback&&listeners[0].port===Number(parsed.port)&&listeners[0].family===report.nativePort.family&&listeners[0].port!==6273);
  check('native-exception-varies-only-port',parsed.port!==registered.port&&parsed.protocol===registered.protocol&&parsed.hostname===registered.hostname&&parsed.pathname===registered.pathname&&parsed.search===registered.search);
  await cdp.send('Page.navigate',{url:authorizationUrl},inspectorSession);authorizationUrl=undefined;
  await waitFor(async()=>{
   if(report.loginRejected)failure('CLIENT_LOGIN_REJECTED');
   const session=inspectorSession;
   if(!loginObserved&&await evaluate(session,`document.querySelector('form[action="/login"]')!==null`)){
    const cookies=await cdp.send('Network.getCookies',{urls:[issuer]},session),cookie=cookies.cookies.find(c=>c.name==='__Host-RevetsecIssuer');
    const csrf=await evaluate(session,`document.querySelector('form[action="/login"]')?.elements.csrf.value`);appForms.set(session,{cookie:cookie?.value,csrf});
    check('browser-login-cookie-secure-httponly-host-lax',cookie?.secure===true&&cookie?.httpOnly===true&&cookie?.path==='/'&&cookie?.sameSite==='Lax'&&typeof cookie.value==='string');
    await evaluate(session,`(()=>{const f=document.querySelector('form[action="/login"]');f.elements.key.value=${JSON.stringify(keys.login)};f.requestSubmit();return true;})()`);loginObserved=true;
   }
   if(!consentObserved&&await evaluate(session,`document.querySelector('form[action="/consent"]')!==null`)){
    const previous=appForms.get(session),cookies=await cdp.send('Network.getCookies',{urls:[issuer]},session),cookie=cookies.cookies.find(c=>c.name==='__Host-RevetsecIssuer');
    const csrf=await evaluate(session,`document.querySelector('form[action="/consent"]')?.elements.csrf.value`);
    check('browser-login-rotates-session-and-csrf',previous?.cookie!==cookie?.value&&typeof previous?.csrf==='string'&&typeof csrf==='string'&&csrf!==previous.csrf);
    check('browser-consent-shows-checked-client-scopes-return',await evaluate(session,`document.body.textContent.includes(${JSON.stringify(input.clientType==='public'?'Local public client':'Local confidential client')})&&document.body.textContent.includes(${JSON.stringify(redirect)})&&document.body.textContent.includes('mcp:discover')&&document.body.textContent.includes('mcp:whoami')`));
    await evaluate(session,clickSelector('button[name="decision"][value="approve"]'));consentObserved=true;
   }
   if(consentObserved&&input.returnMode==='native-ephemeral-ipv6'&&!report.nativeReturnLinkClicked){
    const ready=await evaluate(session,`(()=>{const a=document.querySelector('a#native-return');if(!a)return false;const u=new URL(a.href),expected=new URL(${JSON.stringify(redirect)});return u.origin===expected.origin&&u.pathname===expected.pathname&&u.searchParams.has('code')&&a.rel==='noreferrer'&&document.referrer!==undefined;})()`);
    if(ready){check('ipv6-native-return-uses-checked-normal-link',true);await evaluate(session,`document.querySelector('a#native-return').click()`);report.nativeReturnLinkClicked=true;}
   }
   return consentObserved&&report.http.some(r=>r.path==='CALLBACK'&&r.status===200);
  },'CLIENT_NATIVE_BROWSER_OAUTH_COMPLETION',45000);
  const listed=await list.completion;let catalog;try{catalog=JSON.parse(listed.stdout).result;}catch{failure('CLIENT_NATIVE_CATALOG_JSON');}
  report.nativeOutputFacts={listExit:listed.code,catalogOneWhoami:catalog?.tools?.length===1&&catalog.tools[0].name==='whoami'};
  check('released-native-client-authenticated-tool-catalog',listed.code===0&&report.nativeOutputFacts.catalogOneWhoami);
  check('registered-client-exact-resource-callback-pkce',Object.values(report.authorization??{}).length===4&&Object.values(report.authorization).every(Boolean));
  check('real-browser-login-and-consent',loginObserved&&consentObserved);
  check('credential-callback-no-referrer',report.callbackNoReferrer===true);
  stage('NATIVE_STORED_AUTH_CALL');
  const call=await nativeClient('native-call','tools/call',input.nativeFollowupEra,['--stored-auth-only','--tool-name','whoami','--tool-args-json','{}']).completion;
  let result;try{result=JSON.parse(call.stdout).result;}catch{failure('CLIENT_NATIVE_CALL_JSON');}
  report.nativeOutputFacts.callExit=call.code;report.nativeOutputFacts.checkedIdentity=result?.isError!==true&&result?.content?.some(c=>c.type==='text'&&/^Checked identity partition: [A-Za-z0-9_-]{43}; permitted scopes:/.test(c.text)&&c.text.includes('mcp:whoami'))===true;
  check('native-separate-process-uses-own-saved-grant-for-permitted-call',call.code===0&&report.nativeOutputFacts.checkedIdentity);
  const denial=await nativeClient('native-denial','tools/call',input.nativeFollowupEra,['--stored-auth-only','--tool-name','whoami','--tool-args-json','{"tenant":"other"}']).completion;
  try{result=JSON.parse(denial.stdout).result;}catch{failure('CLIENT_NATIVE_DENIAL_JSON');}
  report.nativeOutputFacts.denialExit=denial.code;report.nativeOutputFacts.applicationDenial=result?.isError===true&&result?.content?.some(c=>c.type==='text'&&c.text==='Operation not permitted')===true;
  check('native-client-reports-application-tenant-denial',denial.code===5&&report.nativeOutputFacts.applicationDenial);
  report.wire=JSON.parse(readFileSync(root+'/wire.json'));
  const codes=report.wire.filter(r=>r.tokenRequest?.codeGrant),authorizations=report.wire.filter(r=>r.path==='AUTHORIZE');
  check('native-single-normal-code-grant-no-refresh-dcr-reauthorization',codes.length===1&&authorizations.length===1&&!report.wire.some(r=>r.path==='DCR'||r.tokenRequest?.refreshGrant));
  check('native-authorization-observer-exact-resource-s256-port-only',Object.values(authorizations[0].nativeAuthorization??{}).length===4&&Object.values(authorizations[0].nativeAuthorization).every(Boolean));
  check('native-token-exchange-exact-actual-callback-resource-pkce',codes[0].status===200&&codes[0].tokenRequest.pkce&&codes[0].tokenRequest.exactResource&&codes[0].tokenRequest.exactCallback&&!codes[0].tokenRequest.ambientCookiePresent);
  check('native-public-or-basic-confidential-authentication',!codes[0].tokenRequest.bodySecretPresent&&(input.clientType==='public'?codes[0].tokenRequest.publicId&&!codes[0].tokenRequest.basic:codes[0].tokenRequest.basic&&!codes[0].tokenRequest.bodyClientIdPresent));
  check('native-received-bounded-bearer-and-refresh',Object.values(codes[0].tokenResponse??{}).length===5&&Object.values(codes[0].tokenResponse).every(Boolean));
  check('native-initial-era-authenticated-negotiation',report.wire.some(r=>r.kind==='MCP'&&r.method===(input.era==='legacy'?'initialize':'server/discover')&&r.status===200&&r.usesCurrentAccess));
  check('native-followup-era-authenticated-negotiation',report.wire.some(r=>r.kind==='MCP'&&r.method===(input.nativeFollowupEra==='legacy'?'initialize':'server/discover')&&r.status===200&&r.usesCurrentAccess));
  check('native-authenticated-wire-catalog-and-permitted-call',report.wire.some(r=>r.kind==='MCP'&&r.method==='tools/list'&&r.status===200&&r.usesCurrentAccess)&&report.wire.some(r=>r.kind==='MCP'&&r.method==='tools/call'&&r.status===200&&r.usesCurrentAccess&&!r.applicationDenial));
  check('native-policy-denial-observed-at-resource',report.wire.some(r=>r.kind==='MCP'&&r.method==='tools/call'&&r.status===200&&r.usesCurrentAccess&&r.applicationDenial));
  check('native-browser-callback-resolver-and-csp-controls',!(report.browserNetworkFailures??[]).some(r=>!r.canceled&&r.requestKind!=='FAVICON')&&report.cspFacts===undefined);
  check('native-client-file-storage-is-disposable-not-injected',cliEnv.MCP_INSPECTOR_SECRET_STORE==='file'&&existsSync(env.MCP_STORAGE_DIR+'/secrets.json'));
 }else{
 await cdp.send('Page.navigate',{url:origin},inspectorSession);
 await waitFor(()=>evaluate(inspectorSession,clickSelector(selector)),'CLIENT_CONNECT_CONTROL');
 stage('OAUTH');
 // Interact with the released client's prompt and ordinary app forms. No injected OAuth result/state.
 await waitFor(async()=>{
  if(report.loginRejected)failure('CLIENT_LOGIN_REJECTED');
  for(const t of (await cdp.send('Target.getTargets')).targetInfos.filter(t=>t.type==='page'))await attach(t.targetId);
  await evaluate(inspectorSession,clickText('Authorize'));
  for(const session of sessions.values()){
   const observed=await evaluate(session,`(()=>{if(location.origin!==${JSON.stringify(issuer)}||location.pathname!=='/authorize')return null;const q=new URL(location.href).searchParams;return {registeredClient:q.get('client_id')===${JSON.stringify(clientId)},exactCallback:q.get('redirect_uri')===${JSON.stringify(redirect)},resource:q.get('resource')===${JSON.stringify(resource)},s256:q.get('code_challenge_method')==='S256'&&/^[A-Za-z0-9_-]{43}$/.test(q.get('code_challenge')??'')};})()`);if(observed)report.authorization=observed;
   const login=await evaluate(session,`document.querySelector('form[action="/login"]')!==null`);
   if(login&&!loginObserved){
    const cookies=await cdp.send('Network.getCookies',{urls:[issuer]},session);const cookie=cookies.cookies.find(c=>c.name==='__Host-RevetsecIssuer');
    const csrf=await evaluate(session,`document.querySelector('form[action="/login"]')?.elements.csrf.value`);
    appForms.set(session,{cookie:cookie?.value,csrf});
    check('browser-login-cookie-secure-httponly-host-lax',cookie?.secure===true&&cookie?.httpOnly===true&&cookie?.path==='/'&&cookie?.sameSite==='Lax'&&typeof cookie.value==='string');
    await evaluate(session,`(()=>{const f=document.querySelector('form[action="/login"]');f.elements.key.value=${JSON.stringify(keys.login)};f.requestSubmit();return true;})()`);loginObserved=true;
   }
   const consent=await evaluate(session,`document.querySelector('form[action="/consent"]')!==null`);
   if(consent&&!consentObserved){
    const previous=appForms.get(session);const cookies=await cdp.send('Network.getCookies',{urls:[issuer]},session);const cookie=cookies.cookies.find(c=>c.name==='__Host-RevetsecIssuer');
    const csrf=await evaluate(session,`document.querySelector('form[action="/consent"]')?.elements.csrf.value`);
    check('browser-login-rotates-session-and-csrf',previous?.cookie!==cookie?.value&&typeof previous?.csrf==='string'&&csrf!==previous.csrf&&typeof csrf==='string');
    check('browser-consent-shows-checked-client-scopes-return',await evaluate(session,`document.body.textContent.includes(${JSON.stringify(cimd?'Local CIMD client':input.clientType==='public'?'Local public client':'Local confidential client')})&&document.body.textContent.includes(${JSON.stringify(redirect)})&&document.body.textContent.includes('mcp:discover')&&(document.body.textContent.includes('mcp:whoami')===${input.recovery!=='step-up'})`));
    await evaluate(session,clickSelector('button[name="decision"][value="approve"]'));consentObserved=true;
   }
  }
  return consentObserved&&await evaluate(inspectorSession,`document.querySelector(${JSON.stringify(selector)})?.checked===true`);
 },'CLIENT_BROWSER_OAUTH_COMPLETION',45000);
 check('registered-client-exact-resource-callback-pkce',Object.values(report.authorization??{}).length===4&&Object.values(report.authorization).every(Boolean));
 check('real-browser-login-and-consent',loginObserved&&consentObserved);
 check('credential-callback-no-referrer',report.callbackNoReferrer===true&&report.http.some(r=>r.path==='CALLBACK'&&r.status===200));
 stage('MCP');
 await waitFor(()=>evaluate(inspectorSession,`(()=>{const n=[...document.querySelectorAll('label')].find(n=>n.getClientRects().length&&n.textContent.trim()==='Tools');if(!n)return false;n.click();return true;})()`),'CLIENT_TOOL_NAVIGATION');
 await waitFor(()=>evaluate(inspectorSession,`document.querySelector('[data-testid=tools-screen]')?.getAttribute('data-tool-count')==='1'`),'CLIENT_TOOL_CATALOG');
 check('released-client-authenticated-mcp-catalog',true);
 await waitFor(()=>evaluate(inspectorSession,`(()=>{const n=[...document.querySelectorAll('button')].find(n=>n.getClientRects().length&&!n.disabled&&n.textContent.trim().includes('whoami'));if(!n)return false;n.click();return true;})()`),'CLIENT_TOOL_SELECT');
 if(input.recovery==='expiry'){
  stage('REAL_EXPIRY_WAIT');report.wire=JSON.parse(readFileSync(root+'/wire.json'));
  const initial=report.wire.find(r=>r.tokenRequest?.codeGrant&&r.status===200);
  check('issuer-reports-bounded-two-minute-token-lifetime',[119,120].includes(initial?.expirySeconds));
  report.realExpiryWaitMs=(initial.expirySeconds+2)*1000;const until=Date.now()+report.realExpiryWaitMs;
  await waitFor(()=>Date.now()>=until,'CLIENT_REAL_EXPIRY_WAIT',130000);
  stage('AUTOMATIC_REFRESH');
 }
 await waitFor(()=>evaluate(inspectorSession,clickText('Execute Tool')),'CLIENT_TOOL_EXECUTE');
 if(input.recovery==='step-up'){
  stage('SCOPE_STEP_UP');let extraConsent=false;
  await waitFor(async()=>{
   await evaluate(inspectorSession,clickText('Authorize'));
   const live=(await cdp.send('Target.getTargets')).targetInfos.filter(t=>t.type==='page');
   for(const t of live){const session=await attach(t.targetId);
    if(await evaluate(session,`location.origin===${JSON.stringify(issuer)}&&document.querySelector('form[action="/consent"]')!==null`)){
     if(!extraConsent){
      check('fresh-step-up-consent-shows-expanded-scopes-and-bound-return',await evaluate(session,`document.body.textContent.includes('mcp:discover')&&document.body.textContent.includes('mcp:whoami')&&document.body.textContent.includes(${JSON.stringify(redirect)})`));
      await evaluate(session,clickSelector('button[name="decision"][value="approve"]'));extraConsent=true;
     }
    }
   }
   const wire=JSON.parse(readFileSync(root+'/wire.json'));const codes=wire.filter(r=>r.tokenRequest?.codeGrant&&r.status===200);
   return extraConsent&&codes.length===2&&codes[1].grantedScopes?.whoami&&await evaluate(inspectorSession,`document.querySelector(${JSON.stringify(selector)})?.checked===true`);
  },'CLIENT_SCOPE_STEP_UP_COMPLETION',45000);
  check('step-up-required-fresh-application-consent',extraConsent);
  // An interactive authorization may require a normal UI retry after the callback.
  // This is never a reconnect or an injected OAuth result; record the distinction.
  const passiveUntil=Date.now()+2000;while(Date.now()<passiveUntil&&!await evaluate(inspectorSession,proofExpression))await pause();
  if(!await evaluate(inspectorSession,proofExpression)){
   report.scopeStepUpUserOperationRetry=true;
   await evaluate(inspectorSession,clickSelector('[aria-label="Close results"]'));
   await waitFor(()=>evaluate(inspectorSession,clickText('Execute Tool')),'CLIENT_STEP_UP_TOOL_RETRY');
  }else report.scopeStepUpUserOperationRetry=false;
 }
 await waitFor(()=>evaluate(inspectorSession,proofExpression),'CLIENT_TOOL_RESULT');
 report.wire=JSON.parse(readFileSync(root+'/wire.json'));
 check('released-client-wire-initialize-or-discover',report.wire.some(r=>r.method===(input.era==='legacy'?'initialize':'server/discover')&&r.status===200&&r.authorizationPresent));
 check('released-client-wire-authenticated-list-and-call',report.wire.some(r=>r.method==='tools/list'&&r.status===200&&r.authorizationPresent)&&report.wire.some(r=>r.method==='tools/call'&&r.status===200&&r.authorizationPresent));
 check('released-client-checked-self-issued-mcp-call',report.toolArgumentsLocalSelf===true&&report.methods.includes('tools/call'));
 await waitFor(()=>evaluate(inspectorSession,clickSelector('[aria-label="Close results"]')),'CLIENT_CLEAR_ALLOWED_RESULT');
 await waitFor(()=>evaluate(inspectorSession,`[...document.querySelectorAll('label')].some(n=>n.textContent.trim().startsWith('tenant'))`),'CLIENT_TOOL_TENANT_READY');
 check('released-client-tool-tenant-input',await evaluate(inspectorSession,`(()=>{const label=[...document.querySelectorAll('label')].find(n=>n.textContent.trim().startsWith('tenant'));const input=label?.htmlFor?document.getElementById(label.htmlFor):label?.querySelector('input');if(!input||input.type!=='text')return false;const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;setter.call(input,'other');input.dispatchEvent(new Event('input',{bubbles:true}));input.dispatchEvent(new Event('change',{bubbles:true}));return input.value==='other';})()`));
 await waitFor(()=>evaluate(inspectorSession,clickText('Execute Tool')),'CLIENT_POLICY_EXECUTE');
 await waitFor(()=>evaluate(inspectorSession,`(()=>{const n=document.querySelector('[data-testid=tools-screen]');return n?.textContent.includes('Operation not permitted')===true&&!${proofExpression};})()`),'CLIENT_POLICY_RESULT');
 check('released-client-displays-application-denial',true);
 check('application-denial-keeps-checked-tool-catalog',await evaluate(inspectorSession,`document.querySelector('[data-testid=tools-screen]')?.getAttribute('data-tool-count')==='1'`));
 stage('CORS');
 check('real-browser-registered-origin-can-read-metadata',await evaluate(inspectorSession,`(async()=>{const r=await fetch(${JSON.stringify(issuer+'/.well-known/oauth-authorization-server')});const d=await r.json();return r.status===200&&d.issuer===${JSON.stringify(issuer)}&&d.token_endpoint===${JSON.stringify(issuer+'/token')}&&(d.client_id_metadata_document_supported===true)===${cimd};})()`));
 check('real-browser-registered-origin-can-read-safe-token-rejection',await evaluate(inspectorSession,`(async()=>{const r=await fetch(${JSON.stringify(issuer+'/token')},{method:'POST',body:new URLSearchParams({grant_type:'unsupported'})});const d=await r.json();return r.status===400&&typeof d.error==='string';})()`));
 check('real-browser-token-preflight-readable-safe-rejection',await evaluate(inspectorSession,`(async()=>{const r=await fetch(${JSON.stringify(issuer+'/token')},{method:'POST',headers:{Authorization:'Basic dW5yZWdpc3RlcmVkOmludmFsaWQ='},body:new URLSearchParams({grant_type:'unsupported'})});const d=await r.json();return [400,401].includes(r.status)&&typeof d.error==='string';})()`));
 check('real-browser-token-options-completed',report.http.some(r=>r.path==='TOKEN'&&r.method==='OPTIONS'&&[200,204].includes(r.status)));
 check('real-browser-callback-origin-cannot-directly-read-mcp',await evaluate(inspectorSession,`(async()=>{try{const r=await fetch(${JSON.stringify(resource)},{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:99,method:'tools/list'})});await r.body.cancel();return false;}catch(e){return e instanceof TypeError;}})()`));
 const {targetId:other}=await cdp.send('Target.createTarget',{url:'about:blank'});const untrusted=await attach(other);
 await cdp.send('Page.navigate',{url:untrustedOrigin},untrusted);
 await waitFor(()=>evaluate(untrusted,`location.origin===${JSON.stringify(untrustedOrigin)}&&document.readyState==='complete'`),'CLIENT_OTHER_ORIGIN_READY');
 check('real-browser-unregistered-origin-cannot-read-issuer',await evaluate(untrusted,`(async()=>{try{const r=await fetch(${JSON.stringify(issuer+'/.well-known/oauth-authorization-server')});await r.body.cancel();return false;}catch(e){return e instanceof TypeError;}})()`));
 check('real-browser-unregistered-origin-cannot-submit-login',await evaluate(untrusted,`(async()=>{try{const r=await fetch(${JSON.stringify(issuer+'/login')},{method:'POST',credentials:'include',body:new URLSearchParams({csrf:'wrong',flow:'wrong',key:'wrong'})});await r.body.cancel();return false;}catch(e){return e instanceof TypeError;}})()`));
 report.wire=JSON.parse(readFileSync(root+'/wire.json'));
 check('unregistered-browser-login-rejected-by-server',report.wire.some(r=>r.kind==='AS'&&r.path==='LOGIN'&&r.status===403));
 const exchanges=report.wire.filter(r=>r.kind==='AS'&&r.tokenRequest?.codeGrant);
 check('released-client-exact-bounded-pkce-code-exchanges',exchanges.length===(input.recovery==='step-up'?2:1)&&exchanges.every(r=>r.status===200&&r.tokenRequest.pkce&&r.tokenRequest.exactResource&&r.tokenRequest.exactCallback&&!r.tokenRequest.ambientCookiePresent));
 check('released-client-public-or-confidential-authentication',exchanges.every(r=>r.tokenRequest.bodySecretPresent===false&&(input.clientType!=='confidential'?r.tokenRequest.publicId&&!r.tokenRequest.basic:r.tokenRequest.basic&&!r.tokenRequest.bodyClientIdPresent)));
 check('released-client-received-bounded-bearer-and-refresh',exchanges.every(r=>Object.values(r.tokenResponse??{}).length===5&&Object.values(r.tokenResponse).every(Boolean)));
 const refreshes=report.wire.filter(r=>r.kind==='AS'&&r.tokenRequest?.refreshGrant);
 if(input.recovery==='expiry'){
  const rejection=report.wire.find(r=>r.kind==='MCP'&&r.afterInitialExpiry&&r.usesInitialAccess&&r.status===401&&r.challenge?.invalidToken&&r.challenge?.exactResourceMetadata);
  check('real-expired-issued-access-token-challenged-by-resource',rejection!==undefined);
  check('bounded-expiry-challenge-attempts',report.wire.filter(r=>r.kind==='MCP'&&r.afterInitialExpiry&&r.usesInitialAccess&&r.status===401).length<=4);
  check('automatic-single-refresh-after-expired-token-challenge',refreshes.length===1&&refreshes[0].status===200&&refreshes[0].ordinal>rejection.ordinal);
  const refresh=refreshes[0];
  check('automatic-refresh-binds-client-and-exact-resource',refresh.tokenRequest.usesCurrentRefresh&&refresh.tokenRequest.exactResource&&!refresh.tokenRequest.bodySecretPresent&&!refresh.tokenRequest.ambientCookiePresent&&(input.clientType!=='confidential'?refresh.tokenRequest.publicId&&!refresh.tokenRequest.basic:refresh.tokenRequest.basic&&!refresh.tokenRequest.bodyClientIdPresent));
  check('automatic-refresh-rotates-access-and-refresh-values',refresh.rotation.accessChanged&&refresh.rotation.refreshChanged&&Object.values(refresh.tokenResponse).every(Boolean));
  check('released-client-retries-operation-with-rotated-access',report.wire.some(r=>r.kind==='MCP'&&r.method==='tools/call'&&r.status===200&&r.usesCurrentAccess&&!r.usesInitialAccess&&r.ordinal>refresh.ordinal&&!r.applicationDenial));
  check('refresh-recovery-needs-no-second-code-or-browser-authorization',exchanges.length===1&&report.wire.filter(r=>r.kind==='AS'&&r.path==='AUTHORIZE').length===1);
 }
 if(input.recovery==='step-up'){
  const rejection=report.wire.find(r=>r.kind==='MCP'&&r.method==='tools/call'&&r.status===403&&r.usesInitialAccess&&r.challenge?.insufficientScope&&r.challenge?.whoamiScope&&r.challenge?.exactResourceMetadata);
  check('initial-checked-grant-has-discover-without-tool-scope',exchanges[0].grantedScopes?.discover===true&&exchanges[0].grantedScopes?.whoami===false);
  check('real-tool-operation-requires-explicit-scope-step-up',rejection!==undefined);
  check('bounded-single-step-up-challenge',report.wire.filter(r=>r.kind==='MCP'&&r.method==='tools/call'&&r.status===403&&r.challenge?.insufficientScope).length===1);
  check('step-up-requires-second-code-grant-not-scope-widening-refresh',exchanges.length===2&&refreshes.length===0&&exchanges[1].ordinal>rejection.ordinal&&exchanges[1].grantedScopes.discover&&exchanges[1].grantedScopes.whoami);
  check('step-up-tool-call-uses-new-expanded-grant',report.wire.some(r=>r.kind==='MCP'&&r.method==='tools/call'&&r.status===200&&r.usesCurrentAccess&&!r.usesInitialAccess&&r.ordinal>exchanges[1].ordinal&&!r.applicationDenial));
 }
 if(cimd){
  const documents=report.wire.filter(r=>r.kind==='CIMD');report.cimd={documentFetches:documents.length,cacheMaxAgeSeconds:300,fixedPublicFormPeer:'8.8.8.8',privateJavaTrust:true};
  check('cimd-fresh-client-needs-no-dcr-fallback',!report.wire.some(r=>r.path==='DCR')&&exchanges.every(r=>r.tokenRequest.publicId&&!r.tokenRequest.basic&&!r.tokenRequest.bodySecretPresent));
  check('cimd-pinned-fetch-retains-original-host-sni-no-ambient-credentials',documents.length>=2&&documents.every(r=>r.httpMethod==='GET'&&r.status===200&&r.hostMatches&&r.sniMatches&&!r.authorizationPresent&&!r.cookiePresent&&!r.conditional&&r.documentBytes>0&&r.documentBytes<16384));
  check('cimd-code-redemption-fetches-new-200-despite-cacheable-document',documents[0]?.cacheMaxAgeSeconds===300&&documents[0].ordinal<exchanges[0].ordinal&&documents.some(r=>r.ordinal>exchanges[0].ordinal&&r.elapsedMs<=exchanges[0].completedElapsedMs&&r.elapsedMs-documents[0].elapsedMs<300000));
  if(input.recovery==='expiry')check('cimd-refresh-fetches-new-200-despite-still-fresh-cached-document',documents.some(r=>r.ordinal>refreshes[0].ordinal&&r.elapsedMs<=refreshes[0].completedElapsedMs&&r.status===200&&!r.conditional&&r.elapsedMs-documents[0].elapsedMs<300000));
 }
 check('released-client-policy-denial-observed-on-resource',report.wire.some(r=>r.kind==='MCP'&&r.method==='tools/call'&&r.status===200&&r.authorizationPresent&&r.applicationDenial));
 if(input.secondResource){
  await cdp.send('Target.activateTarget',{targetId});
  stage('SECOND_RESOURCE');const secondResource=issuer+'/mcp-second',secondSelector='[aria-label=\'Connect or disconnect "revetsec_second_resource"\']';
  // Ordinary UI disconnect/connect controls; never inject OAuth state or issued values into the client.
  await waitFor(()=>evaluate(inspectorSession,clickSelector('[aria-label="Disconnect from server"]')),'CLIENT_FIRST_RESOURCE_DISCONNECT');
  await waitFor(()=>evaluate(inspectorSession,`document.querySelector('[data-testid=connection-status]')?.getAttribute('data-status')==='disconnected'`),'CLIENT_FIRST_RESOURCE_DISCONNECTED');
  await waitFor(()=>evaluate(inspectorSession,clickSelector(secondSelector)),'CLIENT_SECOND_RESOURCE_CONNECT');
  let secondConsent=false;
  await waitFor(async()=>{
   await evaluate(inspectorSession,clickText('Authorize'));
   for(const t of (await cdp.send('Target.getTargets')).targetInfos.filter(t=>t.type==='page')){
    const session=await attach(t.targetId);
    if(await evaluate(session,`location.origin===${JSON.stringify(issuer)}&&document.querySelector('form[action="/consent"]')!==null`)){
     if(!secondConsent){
      check('second-resource-fresh-consent-shows-only-requested-resource',await evaluate(session,`document.body.textContent.includes(${JSON.stringify(secondResource)})&&document.body.textContent.includes('mcp:discover')&&document.body.textContent.includes('mcp:whoami')&&document.body.textContent.includes(${JSON.stringify(redirect)})`));
      await evaluate(session,clickSelector('button[name="decision"][value="approve"]'));secondConsent=true;
     }
    }
   }
   return secondConsent&&await evaluate(inspectorSession,`document.querySelector('[data-testid=connection-status]')?.getAttribute('data-status')==='connected'`);
  },'CLIENT_SECOND_RESOURCE_AUTHORIZATION',45000);
  check('second-resource-real-client-request-binds-resource-callback-pkce',Object.values(report.secondAuthorization??{}).length===4&&Object.values(report.secondAuthorization).every(Boolean));
  await waitFor(()=>evaluate(inspectorSession,`(()=>{const n=[...document.querySelectorAll('label')].find(n=>n.getClientRects().length&&n.textContent.trim()==='Tools');if(!n)return false;n.click();return true;})()`),'CLIENT_SECOND_TOOL_NAVIGATION');
  await evaluate(inspectorSession,clickSelector('[aria-label="Close results"]'));
  await waitFor(()=>evaluate(inspectorSession,`document.querySelector('[data-testid=tools-screen]')?.getAttribute('data-tool-count')==='1'`),'CLIENT_SECOND_TOOL_CATALOG');
  await waitFor(()=>evaluate(inspectorSession,`(()=>{const n=[...document.querySelectorAll('button')].find(n=>n.getClientRects().length&&!n.disabled&&n.textContent.trim().includes('whoami'));if(!n)return false;n.click();return true;})()`),'CLIENT_SECOND_TOOL_SELECT');
  await waitFor(()=>evaluate(inspectorSession,clickText('Execute Tool')),'CLIENT_SECOND_TOOL_EXECUTE');
  await waitFor(()=>evaluate(inspectorSession,proofExpression),'CLIENT_SECOND_TOOL_RESULT');
  report.wire=JSON.parse(readFileSync(root+'/wire.json'));
  const secondCodes=report.wire.filter(r=>r.tokenRequest?.codeGrant&&r.tokenRequest.resource==='SECONDARY');
  check('second-resource-single-independent-code-grant',secondCodes.length===1&&secondCodes[0].status===200&&secondCodes[0].tokenRequest.pkce&&Object.values(secondCodes[0].tokenResponse??{}).length===5&&Object.values(secondCodes[0].tokenResponse).every(Boolean)&&secondCodes[0].grantedScopes?.discover&&secondCodes[0].grantedScopes?.whoami&&secondCodes[0].tokenRequest.exactCallback&&!secondCodes[0].tokenRequest.exactResource&&!secondCodes[0].tokenRequest.ambientCookiePresent);
  check('second-resource-public-or-confidential-client-auth',secondCodes.every(r=>!r.tokenRequest.bodySecretPresent&&(input.clientType!=='confidential'?r.tokenRequest.publicId&&!r.tokenRequest.basic:r.tokenRequest.basic&&!r.tokenRequest.bodyClientIdPresent)));
  check('second-resource-ordinary-client-initialize-list-call-with-own-token',[(input.era==='legacy'?'initialize':'server/discover'),'tools/list','tools/call'].every(method=>report.wire.some(r=>r.kind==='MCP'&&r.resource==='SECONDARY'&&!r.diagnosticProbe&&r.method===method&&r.status===200&&r.usesOwnResourceAccess&&!r.usesOtherResourceAccess)));
  check('client-does-not-send-first-resource-token-to-second-resource',report.wire.filter(r=>r.kind==='MCP'&&r.resource==='SECONDARY'&&!r.diagnosticProbe).every(r=>!r.usesOtherResourceAccess));
  check('second-resource-authorized-without-refresh-or-dcr-fallback',report.wire.filter(r=>r.tokenRequest?.codeGrant).length===2&&!report.wire.some(r=>r.tokenRequest?.refreshGrant)&&report.wire.filter(r=>r.kind==='AS'&&r.path==='AUTHORIZE').length===2&&!report.wire.some(r=>r.path==='DCR'));
  await waitFor(()=>existsSync(root+'/wire.json.cross'),'CLIENT_CROSS_RESOURCE_PROBES');
  report.crossResourceProbes=JSON.parse(readFileSync(root+'/wire.json.cross'));
  check('cross-resource-probes-use-distinct-real-client-issued-values',report.crossResourceProbes.differentIssuedTokens&&report.crossResourceProbes.results.length===10);
  for(const row of report.crossResourceProbes.results)check('diagnostic-'+row.name,row.source===row.target?row.status===200&&row.success===true:row.status===401&&row.invalidToken===true&&row.exactResourceMetadata===true&&row.success===false);
  report.wire=JSON.parse(readFileSync(root+'/wire.json'));
 }
 }
 check('network-isolated-no-unexpected-browser-destinations',report.network.unexpected===0&&report.browserExceptions===0);
 report.clientTreeAfter=directoryIdentity('/private/inspector-client/node_modules');
 check('released-client-tree-unmodified',JSON.stringify(report.clientTreeAfter)===JSON.stringify(report.clientTreeBefore));
 report.status='PASS';
}catch(error){report.failure=/^(CLIENT|DEPENDENCY|INSTALLED|CDP)_[A-Z_]+$/.test(error.message)?error.message:'CLIENT_RUN_FAILED';
 report.failureClass=['Error','TypeError','SyntaxError'].includes(error.name)?error.name:'OTHER';report.failureLocations=[...String(error.stack??'').matchAll(/\/suite\/browser-client\.mjs:(\d+):(\d+)/g)].map(m=>({line:Number(m[1]),column:Number(m[2])}));
 if(existsSync(root+'/wire.json'))report.wire=JSON.parse(readFileSync(root+'/wire.json'));
 if(cdp)try{report.uiFacts=[];for(const session of sessions.values())try{report.uiFacts.push(await evaluate(session,`({browserErrorCode:/^ERR_[A-Z_]+$/.test(document.querySelector('#error-code')?.textContent?.trim()??'')?document.querySelector('#error-code').textContent.trim():null,insecureConnectionWarning:document.body.textContent.includes('secure connection'),localNetworkWarning:document.body.textContent.includes('local network'),connectionStatus:document.querySelector('[data-testid=connection-status]')?.getAttribute('data-status')??null,knownNavLabels:[...document.querySelectorAll('label')].map(n=>n.textContent.trim()).filter(t=>['Servers','Tools','Protocol','Network','Logs'].includes(t)),issuerPage:location.origin===${JSON.stringify(issuer)},callbackPage:location.pathname==='/oauth/callback',blankPage:location.href==='about:blank',requestBlocked:document.body.textContent.includes('ERR_BLOCKED_BY_CLIENT'),certificateError:document.body.textContent.includes('ERR_CERT'),login:document.querySelector('form[action="/login"]')!==null,consent:document.querySelector('form[action="/consent"]')!==null,connected:document.querySelector(${JSON.stringify(selector)})?.checked===true,serverSwitchFacts:[...document.querySelectorAll('[aria-label^=\"Connect or disconnect\"]')].map(n=>({checked:n.checked,disabled:n.disabled,visible:n.getClientRects().length>0})),authorize:[...document.querySelectorAll('button')].some(n=>n.textContent.trim()==='Authorize'),knownErrors:['invalid_request','invalid_client','invalid_scope','invalid_redirect_uri','access_denied','server_error'].filter(x=>document.body.textContent.includes(x)),formLabels:[...document.querySelectorAll('label')].map(n=>n.textContent.trim()).filter(t=>['tenant','object','Raw JSON'].includes(t)),formButtons:['Execute Tool','Raw JSON','Parameters','Arguments','whoami','Authorize','Authorize again','Continue','Retry','Cancel'].filter(t=>[...document.querySelectorAll('button')].some(n=>n.getClientRects().length&&n.textContent.trim()===t)),toolInputs:[...document.querySelectorAll('input,textarea')].map(n=>({tag:n.tagName,type:n.type,readOnly:n.readOnly,visible:n.getClientRects().length>0,placeholder:n.placeholder?.slice(0,128)})),tools:document.querySelector('[data-testid=tools-screen]')?.getAttribute('data-tool-count')??null})`));}catch{}}catch{}
}finally{
 closing=true;try{if(cdp&&!cdp.failure())await cdp.send('Browser.close');await cdp?.close();}catch{report.status='FAILED';report.cdpClosureFailure=true;}
 for(const name of ['browser','inspector','native-list','native-call','native-denial','application','wire','edge'])if(handles[name])try{await handles[name].stop();report.shutdown[name]='CLOSED';}catch{report.shutdown[name]='FAILED';report.status='FAILED';}
 rmSync(root,{recursive:true,force:true});report.privateStateRemoved=!existsSync(root);
 report.scope=native?'unmodified released native CLI with own port0 OS listener; real browser login/consent; selected IP family; exact actual token callback binding; own private saved grant for separate process tool call/denial; initial and followup eras labeled separately; no fresh modern OAuth claim from stored-auth followups; volatile issuer, no new browser CORS/durable/AF2 qualification':'selected preregistered or CIMD issuer/browser/MCP flows including explicit native port variation or exact HTTPS browser return, volatile single-process example; selected real-expiry/refresh or interactive scope-step-up flow when requested; optional normal second-resource client authorization plus separately labeled diagnostic cross-resource probes; optional released CIMD client with isolated public-form numeric peer and child-local CA trust; generic403 AF2 and durable browser deployment remain unqualified';
 report.AF2RemainsOpen=true;
 writeFileSync('/evidence/PROGRESS.json',JSON.stringify({stage:'CLOSED',status:report.status,recovery:input.recovery,checks:report.checks.length,elapsedMs:Date.now()-started}),{mode:0o600});
 writeFileSync('/evidence/RESULT.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({status:report.status,stage:report.stage,checks:report.checks.length,failure:report.failure}));
}
if(report.status!=='PASS')process.exitCode=1;
