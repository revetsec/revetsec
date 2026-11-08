// Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
// Exact provider/Caddy runtime oracle. Never writes credentials, cookies, tokens or bodies.
import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import http2 from 'node:http2';
import tls from 'node:tls';

const mode=process.env.REVETSEC_CADDY_PROBE_MODE;
const credential=process.env.REVETSEC_PROVIDER_FIXTURE_CREDENTIAL;
const ca=readFileSync('/tls/ca.pem');
const edgePort=18443,backendPort=18080,observerPort=18081;
if(!['control','plant'].includes(mode)||!credential)throw new Error('Invalid private probe configuration');

const receipt={mode,success:false,checks:[],queryCases:[],sensitiveValuesRetained:false};
class CheckFailure extends Error{constructor(name){super(name);this.name='CheckFailure';}}
function check(name,condition,observed){
  receipt.checks.push({name,passed:Boolean(condition),...(observed===undefined?{}:{observed})});
  if(!condition)throw new CheckFailure(name);
}
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const sha=value=>createHash('sha256').update(value).digest('hex');
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));

let dispatches=0;
let h2Client;
const observer=http.createServer((incoming,outgoing)=>{
  dispatches++;
  const headers={...incoming.headers,host:'app.example',connection:'close'};
  delete headers['transfer-encoding'];
  const request=http.request({host:'127.0.0.1',port:backendPort,method:incoming.method,path:incoming.url,headers},response=>{
    outgoing.writeHead(response.statusCode,response.headers);response.pipe(outgoing);
  });
  request.setTimeout(5000,()=>request.destroy(new Error('observer timeout')));
  request.on('error',()=>{if(!outgoing.headersSent)outgoing.writeHead(502);outgoing.end();});
  incoming.pipe(request);
});
observer.requestTimeout=6000;observer.headersTimeout=4000;observer.keepAliveTimeout=1000;

function collect(request,body=Buffer.alloc(0)){
  return new Promise((resolve,reject)=>{
    request.once('response',response=>{
      const chunks=[];let size=0;
      response.on('data',chunk=>{size+=chunk.length;if(size>131072)request.destroy(new Error('response bound'));else chunks.push(chunk);});
      response.once('error',reject);response.once('end',()=>resolve({status:response.statusCode,headers:response.headers,body:Buffer.concat(chunks)}));
    });
    request.once('error',reject);request.setTimeout?.(5000,()=>request.destroy(new Error('request timeout')));request.end(body);
  });
}
function direct(method,path,body=Buffer.alloc(0),headers={}){
  return collect(http.request({host:'127.0.0.1',port:backendPort,method,path,headers:{Host:'app.example','X-Fixture-Credential':credential,'Content-Length':String(body.length),Connection:'close',...headers}}),body);
}
function edgeH1(method,path,body=Buffer.alloc(0),headers={}){
  return collect(https.request({host:'127.0.0.1',port:edgePort,servername:'app.example',ca,rejectUnauthorized:true,method,path,headers:{Host:'app.example','Content-Length':String(body.length),Connection:'close',...headers}}),body);
}
function rawH1(method,target,body=Buffer.alloc(0),headers={}){
  return new Promise((resolve,reject)=>{
    const socket=tls.connect({host:'127.0.0.1',port:edgePort,servername:'app.example',ca,rejectUnauthorized:true,ALPNProtocols:['http/1.1']},()=>{
      const fields={Host:'app.example','Content-Length':String(body.length),Connection:'close',...headers};
      socket.write(Buffer.concat([Buffer.from(`${method} ${target} HTTP/1.1\r\n${Object.entries(fields).map(([k,v])=>`${k}: ${v}\r\n`).join('')}\r\n`,'ascii'),body]));
    });
    const chunks=[];let size=0;
    const timer=setTimeout(()=>socket.destroy(new Error('raw h1 timeout')),5000);
    socket.on('data',chunk=>{size+=chunk.length;if(size>131072)socket.destroy(new Error('raw h1 response bound'));else chunks.push(chunk);});
    socket.once('error',reject);socket.once('close',()=>{
      clearTimeout(timer);const bytes=Buffer.concat(chunks),match=/^HTTP\/1\.1 (\d{3}) /.exec(bytes.toString('latin1'));
      if(!match)reject(new Error('raw h1 response unavailable'));else resolve({status:Number(match[1])});
    });
  });
}
function openH2(){
  if(h2Client&&!h2Client.closed&&!h2Client.destroyed)return h2Client;
  h2Client=http2.connect(`https://app.example:${edgePort}`,{
    createConnection:()=>tls.connect({host:'127.0.0.1',port:edgePort,servername:'app.example',ca,rejectUnauthorized:true,ALPNProtocols:['h2']})
  });
  h2Client.on('error',()=>{});
  return h2Client;
}
function edgeH2(method,path,body=Buffer.alloc(0),headers={}){
  return new Promise((resolve,reject)=>{
    const client=openH2();
    const timer=setTimeout(()=>{request.close(http2.constants.NGHTTP2_CANCEL);reject(Object.assign(new Error('h2 timeout'),{code:'QUALIFICATION_H2_TIMEOUT'}));},5000);
    const request=client.request({':method':method,':path':path,':authority':`app.example:${edgePort}`,'content-length':String(body.length),...headers},{endStream:false});
    let responseHeaders={},size=0;const chunks=[];
    request.on('response',value=>responseHeaders=value);
    request.on('data',chunk=>{size+=chunk.length;if(size>131072)request.close(http2.constants.NGHTTP2_CANCEL);else chunks.push(chunk);});
    request.once('error',error=>{clearTimeout(timer);reject(error);});
    request.once('end',()=>{clearTimeout(timer);resolve({status:responseHeaders[':status'],headers:responseHeaders,body:Buffer.concat(chunks)});});
    request.end(body);
  });
}
async function tlsRefused(servername,trust){
  return await new Promise(resolve=>{
    const socket=tls.connect({host:'127.0.0.1',port:edgePort,servername,rejectUnauthorized:true,...(trust?{ca}:{}),ALPNProtocols:['http/1.1']},()=>{socket.destroy();resolve(false);});
    socket.once('error',()=>resolve(true));setTimeout(()=>{socket.destroy();resolve(false);},3000);
  });
}
function json(reply){return JSON.parse(reply.body.toString('utf8'));}
function oneCookie(reply,name){
  const values=Array.isArray(reply.headers['set-cookie'])?reply.headers['set-cookie']:[reply.headers['set-cookie']].filter(Boolean);
  const found=values.map(value=>value.split(';',1)[0]).filter(value=>value.startsWith(name+'='));
  if(found.length!==1)throw new Error('one private cookie required');return found[0];
}
async function state(){return json(await direct('GET','/fixture/state'));}
async function googleBegin(lane){
  const body=Buffer.from('begin=1','ascii'),headers={'content-type':'application/x-www-form-urlencoded','origin':'https://app.example'};
  const reply=lane==='h2'?await edgeH2('POST','/google/begin',body,headers):await edgeH1('POST','/google/begin',body,headers);
  check(`${lane}-google-begin-query-free`,reply.status===200,reply.status);return reply;
}
async function googleToken(started){
  const reply=await direct('GET','/fixture/token/google/valid',Buffer.alloc(0),{'X-Fixture-Nonce':json(started).nonce});
  check('private-token-control',reply.status===200,reply.status);return json(reply).token;
}
function completion(started,token){
  const body=Buffer.from(new URLSearchParams({credential:token,g_csrf_token:'TEST-ONLY-csrf'}).toString(),'ascii');
  const headers={'content-type':'application/x-www-form-urlencoded','cookie':oneCookie(started,'__Host-provider-login')+'; g_csrf_token=TEST-ONLY-csrf'};
  return {body,headers};
}
async function validEdgeFlow(lane){
  const started=await googleBegin(lane),token=await googleToken(started),request=completion(started,token),before=await state(),beforeDispatch=dispatches;
  const reply=lane==='h2'?await edgeH2('POST','/google/complete',request.body,request.headers):await edgeH1('POST','/google/complete',request.body,request.headers);
  const after=await state();check(`${lane}-query-free-valid-google-completion`,reply.status===200&&after.lookups===before.lookups+1&&after.sessions===before.sessions+1&&dispatches===beforeDispatch+1,{status:reply.status,lookupsDelta:after.lookups-before.lookups,sessionsDelta:after.sessions-before.sessions,dispatchDelta:dispatches-beforeDispatch});
}
async function failingBefore(){
  const body=Buffer.from('begin=1','ascii'),started=await direct('POST','/google/begin',body,{'Content-Type':'application/x-www-form-urlencoded','Origin':'https://app.example'}),token=await googleToken(started),request=completion(started,token),before=await state();
  const reply=await direct('POST','/google/complete?',request.body,request.headers),after=await state();
  receipt.failingBefore={status:reply.status,lookupsDelta:after.lookups-before.lookups,sessionsDelta:after.sessions-before.sessions};
  check('current-PIN56-direct-bare-query-valid-completion',reply.status===200&&after.lookups===before.lookups+1&&after.sessions===before.sessions+1,receipt.failingBefore);
}

const routes=[
  ['POST','/google/begin'],['POST','/google/complete'],['POST','/apple/begin'],['POST','/apple/complete'],
  ['GET','/session'],['GET','/native/session'],['GET','/account/tenant/alice'],['GET','/native/account/tenant/alice'],
  ['POST','/logout'],['POST','/native/logout']
];
async function queryMatrix(lane){
  for(const [method,path]of routes)for(const suffix of ['?','?x=1']){
    const target=path+suffix,before=await state(),beforeDispatch=dispatches;
    const reply=lane==='h2'?await edgeH2(method,target):await rawH1(method,target);
    const after=await state(),passed=reply.status===400&&dispatches===beforeDispatch&&same(after,before);
    receipt.queryCases.push({lane,method,path,targetSha256:sha(target),kind:suffix==='?'?'bare':'nonempty',status:reply.status,dispatchDelta:dispatches-beforeDispatch,stateUnchanged:same(after,before),passed});
    check(`${lane}-${path}-${suffix==='?'?'bare':'nonempty'}-query-refused-before-dispatch`,passed,reply.status);
  }
}
async function plantProbe(){
  const beforeNonempty=await state(),dispatchNonempty=dispatches,nonempty=await rawH1('GET','/session?x=1'),afterNonempty=await state();
  check('plant-nonempty-query-still-refused',nonempty.status===400&&dispatches===dispatchNonempty&&same(beforeNonempty,afterNonempty),nonempty.status);
  const started=await googleBegin('h1'),token=await googleToken(started),request=completion(started,token),before=await state(),beforeDispatch=dispatches;
  const reply=await rawH1('POST','/google/complete?',request.body,request.headers),after=await state();
  receipt.plantEffect={status:reply.status,lookupsDelta:after.lookups-before.lookups,sessionsDelta:after.sessions-before.sessions,dispatchDelta:dispatches-beforeDispatch};
  check('bare-query-valid-completion-never-dispatches',reply.status===400&&same(before,after)&&dispatches===beforeDispatch,receipt.plantEffect);
}

try{
  await new Promise((resolve,reject)=>{observer.once('error',reject);observer.listen(observerPort,'127.0.0.1',resolve);});
  let ready=false;for(let i=0;i<200;i++){try{if((await direct('GET','/fixture/health')).status===200&&(await rawH1('GET','/session')).status===200){ready=true;break;}}catch{}await sleep(50);}
  check('owned-provider-and-caddy-ready',ready);
  if(mode==='plant')await plantProbe();
  else{
    await failingBefore();
    const tlsBefore=dispatches;check('normal-private-CA-SAN-TLS', (await rawH1('GET','/session')).status===200&&dispatches===tlsBefore+1);
    const negativeBefore=dispatches;check('untrusted-CA-refused-before-dispatch',await tlsRefused('app.example',false)&&dispatches===negativeBefore);check('wrong-hostname-refused-before-dispatch',await tlsRefused('wrong.example',true)&&dispatches===negativeBefore);
    const hostBefore=dispatches,badHost=await new Promise((resolve,reject)=>{const socket=tls.connect({host:'127.0.0.1',port:edgePort,servername:'app.example',ca,rejectUnauthorized:true},()=>socket.end('GET /session HTTP/1.1\r\nHost: attacker.invalid\r\nConnection: close\r\n\r\n'));let bytes='';socket.on('data',value=>bytes+=value.toString('latin1'));socket.on('error',reject);socket.on('close',()=>resolve(Number((/^HTTP\/1\.1 (\d{3}) /.exec(bytes)||[])[1]||0)));});
    check('foreign-host-refused-before-dispatch',badHost>=400&&dispatches===hostBefore,badHost);
    const privateBefore=dispatches,privateHeader=await rawH1('GET','/session',Buffer.alloc(0),{'X-Fixture-Credential':'attacker'});check('private-edge-header-spoof-refused-before-dispatch',privateHeader.status===400&&dispatches===privateBefore,privateHeader.status);
    await queryMatrix('h1');await queryMatrix('h2');await validEdgeFlow('h1');await validEdgeFlow('h2');
    receipt.success=true;
  }
}catch(error){
  receipt.failure={type:error.name==='CheckFailure'?'AssertionError':'PreparationOrTransportFailure',check:error.name==='CheckFailure'?error.message:'preparation-or-transport',...(error.name==='CheckFailure'||!error.code?{}:{transportCode:String(error.code).slice(0,80)})};
}finally{
  if(h2Client&&!h2Client.destroyed){h2Client.close();await Promise.race([new Promise(resolve=>h2Client.once('close',resolve)),sleep(1000)]);}
  observer.closeAllConnections();await new Promise(resolve=>observer.close(resolve));receipt.observerClosed=!observer.listening;
  writeFileSync('/evidence/RESULT.json',JSON.stringify(receipt,null,2)+'\n');
}
if(!receipt.success)process.exitCode=1;
