// Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
// Owned CDP client. Never print protocol messages, response bodies, cookies or tokens.
import http from 'node:http';
const configuration=JSON.parse(process.env.REVETSEC_EDGE_BROWSER_INPUT);
const checks=[];
function check(name,condition){checks.push({name,passed:Boolean(condition)});if(!condition)throw new Error(name);}
function privateRequest(method,path,body='',headers={}){
  return new Promise((resolve,reject)=>{
    const request=http.request({host:'127.0.0.1',port:configuration.backend,method,path,headers:{Host:'app.example','X-Fixture-Credential':configuration.credential,'Content-Length':Buffer.byteLength(body),...headers}},response=>{
      const pieces=[];let size=0;response.on('data',piece=>{size+=piece.length;if(size>131072){request.destroy();reject(new Error('private-response-bound'));}else pieces.push(piece);});
      response.on('end',()=>resolve({status:response.statusCode,headers:response.headers,body:Buffer.concat(pieces).toString('utf8')}));
    });request.setTimeout(8000,()=>request.destroy());request.on('error',()=>reject(new Error('private-request-unavailable')));request.end(body);
  });
}
const websocket=new WebSocket(configuration.websocket);let sequence=0,session;const pending=new Map();
await new Promise((resolve,reject)=>{websocket.addEventListener('open',resolve,{once:true});websocket.addEventListener('error',()=>reject(new Error('cdp-connect')),{once:true});});
websocket.addEventListener('message',event=>{let value;try{value=JSON.parse(event.data);}catch{return;}if(value.id&&pending.has(value.id)){const item=pending.get(value.id);pending.delete(value.id);clearTimeout(item.timer);if(value.error)item.reject(new Error('cdp-'+item.method));else item.resolve(value.result);}});
websocket.addEventListener('close',()=>{for(const [id,item] of pending){clearTimeout(item.timer);pending.delete(id);if(item.method==='Browser.close')item.resolve({});else item.reject(new Error('cdp-closed-'+item.method));}});
function command(method,params={},attached=true){return new Promise((resolve,reject)=>{const id=++sequence;const timer=setTimeout(()=>{pending.delete(id);reject(new Error('cdp-deadline-'+method));},12000);pending.set(id,{resolve,reject,timer,method});websocket.send(JSON.stringify({id,method,params,...(attached?{sessionId:session}:{})}));});}
async function evaluate(expression){const result=await command('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});if(result.exceptionDetails)throw new Error('browser-expression');return result.result.value;}
async function fetchApp(path,method='GET',fields=null,headers={}){
  const options={method,credentials:'same-origin',cache:'no-store',redirect:'error',headers};
  if(fields!==null){options.headers={'Content-Type':'application/x-www-form-urlencoded',...headers};options.body=new URLSearchParams(fields).toString();}
  return evaluate(`(async()=>{const r=await fetch(${JSON.stringify(path)},${JSON.stringify(options)});return {status:r.status,body:await r.text()};})()`);
}
async function cookies(){return(await command('Network.getCookies',{urls:['https://app.example/']})).cookies;}
async function installIssuedCookie(line){check('issued-cookie-original-security-attributes',/; Secure(?:;|$)/.test(line)&&/; HttpOnly(?:;|$)/.test(line)&&/; Path=\/(?:;|$)/.test(line)&&/; SameSite=Lax(?:;|$)/.test(line)&&!/(?:^|;)\s*Domain=/i.test(line));const [name,value]=line.split(';',1)[0].split('=');const age=/; Max-Age=([0-9]+)/.exec(line);const result=await command('Network.setCookie',{name,value,url:'https://app.example/',path:'/',secure:true,httpOnly:true,sameSite:'Lax',...(age?{expires:Date.now()/1000+Number(age[1])}:{})});check('issued-cookie-install',result.success);return{name,value};}
function oneCookie(reply,name){const found=(reply.headers['set-cookie']||[]).filter(value=>value.startsWith(name+'='));check('one-issued-'+name,found.length===1);return found[0];}
async function state(){const r=await privateRequest('GET',configuration.profile==='logout'?'/fixture/control/state':'/fixture/state');check('private-state-available',r.status===200);return JSON.parse(r.body);}
async function logoutFlow(){
  const started=await privateRequest('POST','/fixture/login');check('logout-bootstrap-genuine-authentication',started.status===200&&JSON.parse(started.body).genuine_authentication===true);
  const csrf=JSON.parse(started.body).csrf;const first=await installIssuedCookie(oneCookie(started,'__Host-app-session'));
  let jar=await cookies();check('logout-browser-host-cookie-security',jar.some(c=>c.name===first.name&&c.value===first.value&&c.domain==='app.example'&&c.path==='/'&&c.secure&&c.httpOnly&&c.sameSite==='Lax'));
  check('logout-session-not-script-readable',!(await evaluate('document.cookie')).includes(first.name+'='));
  const before=(await state()).shared;
  const refused=await fetchApp('/logout?unused=1','POST',null,{'X-CSRF-Token':csrf});
  const guarded=(await state()).shared;check('logout-browser-query-before-close-save',refused.status===400&&guarded.closes===before.closes&&guarded.saves===before.saves);
  const output=await fetchApp('/logout','POST',null,{'X-CSRF-Token':csrf});check('logout-browser-form-delivery',output.status===200);
  const facts=await evaluate(`(()=>{const d=new DOMParser().parseFromString(${JSON.stringify(output.body)},'text/html');const f=d.querySelector('form');return {method:f?.method,action:f?.action,state:f?.querySelector('input[name=state]')?.value,hintCount:f?.querySelectorAll('input[name=id_token_hint]').length};})()`);
  check('logout-prepared-op-action-unmodified-http-loopback',facts.method==='post'&&/^http:\/\/127\.0\.0\.1:[0-9]+\/logout$/.test(facts.action)&&facts.hintCount===1&&/^[A-Za-z0-9_-]{43}$/.test(facts.state));
  // Deliberately do not submit the HTTP fixture OP form: no provider TLS or UI proof.
  jar=await cookies();check('logout-browser-local-cookie-cleared',!jar.some(c=>c.name==='__Host-app-session'));
  check('logout-browser-independent-pending-cookie',jar.some(c=>c.name==='__Host-rp-logout'&&c.secure&&c.httpOnly&&c.path==='/'&&c.domain==='app.example'));
  const after=(await state()).shared;check('logout-local-first-one-close-one-save',after.closes===before.closes+1&&after.saves===before.saves+1);
  check('logout-old-session-detached',JSON.parse((await privateRequest('GET','/fixture/live','',{Cookie:first.name+'='+first.value})).body).live===false);
  const fresh=await privateRequest('POST','/fixture/login');const newer=await installIssuedCookie(oneCookie(fresh,'__Host-app-session'));
  const returned=await fetchApp('/logout/callback?state='+facts.state);check('logout-browser-correlated-return',returned.status===200&&/correlat/i.test(returned.body));
  jar=await cookies();check('logout-return-clears-only-own-binding',!jar.some(c=>c.name==='__Host-rp-logout')&&jar.some(c=>c.name===newer.name&&c.value===newer.value));
  check('logout-newer-session-survives-return',JSON.parse((await privateRequest('GET','/fixture/live','',{Cookie:newer.name+'='+newer.value})).body).live===true);
  check('logout-browser-return-replay-refused',(await fetchApp('/logout/callback?state='+facts.state)).status===400);
  check('logout-no-provider-form-submit',(await state()).shared.logout_posts===0);
}
async function providerFlow(){
  check('provider-initial-status-unallocated',JSON.parse((await fetchApp('/session')).body).authenticated==='false');
  let baseline=await state();
  check('provider-query-browser-before-allocation',(await fetchApp('/google/begin?unused=1','POST',{begin:'1'})).status===400&&(await state()).attempts===baseline.attempts);
  async function beginComplete(fields={begin:'1'},mode='valid'){
    const begun=await fetchApp('/google/begin','POST',fields);check('google-browser-begin',begun.status===200);const data=JSON.parse(begun.body);
    const jar=await cookies();check('google-browser-pending-cookie',jar.some(c=>c.name==='__Host-provider-login'&&c.secure&&c.httpOnly&&c.domain==='app.example'&&c.path==='/'));
    const token=await privateRequest('GET','/fixture/token/google/'+mode,'',{'X-Fixture-Nonce':data.nonce});check('google-private-signature-fixture',token.status===200);
    await evaluate("document.cookie='g_csrf_token=TEST-ONLY-browser-csrf; Path=/; Secure; SameSite=Lax'");
    const before=await state();const complete={credential:JSON.parse(token.body).token,g_csrf_token:'TEST-ONLY-browser-csrf'};
    check('google-complete-query-before-provider-work',(await fetchApp('/google/complete?unused=1','POST',complete)).status===400&&(await state()).lookups===before.lookups);
    const output=await fetchApp('/google/complete','POST',complete);check('google-browser-real-validation-session',output.status===200);
    const current=await cookies();check('google-browser-session-pending-separated',!current.some(c=>c.name==='__Host-provider-login')&&current.some(c=>c.name==='__Host-provider-session'&&c.secure&&c.httpOnly&&c.domain==='app.example'&&c.path==='/'));
    check('google-session-not-script-readable',!(await evaluate('document.cookie')).includes('__Host-provider-session='));
    return current.find(c=>c.name==='__Host-provider-session');
  }
  const original=await beginComplete();check('google-browser-resource-authorized',(await fetchApp('/account/tenant/alice')).status===200);
  check('google-browser-current-tenant-owner',(await fetchApp('/account/other/alice')).status===403&&(await fetchApp('/account/tenant/bob')).status===403);
  const status=JSON.parse((await fetchApp('/session')).body);const rotated=await beginComplete({begin:'1',csrf:status.csrf},'legacy-issuer');check('google-browser-cookie-rotated',original.value!==rotated.value);
  check('google-old-session-revoked', (await privateRequest('GET','/account/tenant/alice','',{Cookie:'__Host-provider-session='+original.value})).status===401);
  check('google-browser-rotated-resource',(await fetchApp('/account/tenant/alice')).status===200);
  const csrf=JSON.parse((await fetchApp('/session')).body).csrf;baseline=await state();
  check('google-browser-logout-query-before-close',(await fetchApp('/logout?unused=1','POST',{csrf})).status===400&&(await state()).sessions===baseline.sessions);
  check('google-browser-logout-csrf',(await fetchApp('/logout','POST',{csrf:'wrong'})).status===403);
  check('google-browser-local-logout',(await fetchApp('/logout','POST',{csrf})).status===200&&(await fetchApp('/account/tenant/alice')).status===401);
  check('google-browser-session-cookie-cleared',!(await cookies()).some(c=>c.name==='__Host-provider-session'));
  // An ordinary browser POST carries Origin and cannot bootstrap the native-only route.
  baseline=await state();check('apple-browser-native-post-denied',(await fetchApp('/apple/begin','POST',{begin:'1'})).status===403&&(await state()).attempts===baseline.attempts);
  check('provider-token-directed-source-unused',(await state()).attacker_fetches===0);
}
let success=false,failure;
try{
  const target=await command('Target.createTarget',{url:'about:blank'},false);session=(await command('Target.attachToTarget',{targetId:target.targetId,flatten:true},false)).sessionId;
  await command('Page.enable');await command('Runtime.enable');await command('Network.enable');
  const navigation=await command('Page.navigate',{url:'https://app.example/__verification/index'});check('browser-navigation-no-error',!navigation.errorText);
  let context=false;for(let i=0;i<100;i++){try{context=await evaluate("location.href==='https://app.example/__verification/index'&&document.readyState==='complete'&&isSecureContext");}catch{}if(context)break;await new Promise(resolve=>setTimeout(resolve,50));}
  check('browser-fixed-origin-secure-context',context);
  const bare=await fetchApp(configuration.profile==='logout'?'/logout?':'/google/begin?');check('browser-bare-query-probe-never-dispatches-selected-method',bare.status===400||bare.status===405);
  if(configuration.profile==='logout')await logoutFlow();else await providerFlow();success=true;
}catch(error){failure=error.message;}
finally{for(const item of pending.values()){clearTimeout(item.timer);item.reject(new Error('cdp-ending'));}pending.clear();try{await command('Browser.close',{},false);}catch{}websocket.close();}
process.stdout.write(JSON.stringify({success,checks,...(failure?{failure}:{}),browserTrustScope:'owned-leaf-SPKI-exception-only',providerTransportScope:'local-fixture-no-hosted-provider-or-provider-HTTPS-proof'})+'\n');
if(!success)process.exitCode=1;
