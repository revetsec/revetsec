// Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
// Synthetic secrets calibrate byte transparency and receipt redaction; no real OAuth authority.
import http from 'node:http';
import {spawn} from 'node:child_process';
import {mkdtempSync,writeFileSync,readFileSync,rmSync,existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {createHash,randomBytes} from 'node:crypto';
const root=mkdtempSync(tmpdir()+'/revetsec-wire-check-');
const clientId='https://goose-docs.ai/oauth/client-metadata.json',issuer='https://localhost:37499',resource=issuer+'/mcp',redirect='http://127.0.0.1:33419/oauth_callback';
const secret=()=>randomBytes(32).toString('base64url');
const verifier=secret(),code=secret(),access=secret(),refresh=secret(),nextAccess=secret(),nextRefresh=secret(),identity=secret(),cookie=secret();
const challenge=createHash('sha256').update(verifier).digest('base64url');
const config={root,issuer,resource,clientId,port:37499,metadataDelayMs:0};writeFileSync(root+'/input.json',JSON.stringify(config));
let receivedBody,receivedHeader,badJson=false;
const codeJson=JSON.stringify({access_token:access,refresh_token:refresh,token_type:'Bearer',expires_in:120});
const refreshJson=JSON.stringify({access_token:nextAccess,refresh_token:nextRefresh,token_type:'Bearer',expires_in:120});
const as=http.createServer((request,response)=>{let parts=[];request.on('data',p=>parts.push(p));request.on('end',()=>{receivedBody=Buffer.concat(parts);receivedHeader=request.headers['x-wire-check'];const body=badJson?'not-json-'+cookie:request.url.startsWith('/token')?(new URLSearchParams(receivedBody.toString()).get('grant_type')==='refresh_token'?refreshJson:codeJson):'auth';response.writeHead(200,{'Cache-Control':'no-store','Content-Type':'application/json','X-Wire-Check':'preserve'});response.end(body);});});
const mcp=http.createServer((request,response)=>{let parts=[];request.on('data',p=>parts.push(p));request.on('end',()=>{const json=JSON.parse(Buffer.concat(parts));const denied=json.params?.arguments?.tenant==='other';response.writeHead(200,{'Content-Type':'application/json'});response.end(JSON.stringify({jsonrpc:'2.0',id:1,result:{content:[{type:'text',text:denied?'Operation not permitted':'Checked identity partition: '+identity+'; permitted scopes: mcp:whoami'}],...(denied?{isError:true}:{})}}));});});
const checks=[];let child;
function check(name,value){checks.push({name,status:value?'PASS':'FAIL'});if(!value)throw new Error('WIRE_ASSERTION');}
function request(port,path,body='',headers={}){return new Promise((resolve,reject)=>{const r=http.request({host:'127.0.0.1',port,path,method:body?'POST':'GET',headers,timeout:2000},s=>{let parts=[];s.on('data',p=>parts.push(p));s.on('end',()=>resolve({status:s.statusCode,headers:s.headers,body:Buffer.concat(parts).toString()}));});r.on('timeout',()=>r.destroy());r.on('error',()=>reject(new Error('REQUEST_FAILED')));r.end(body);});}
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const wire=()=>JSON.parse(readFileSync(root+'/wire.json','utf8'));
const packet=tenant=>JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'whoami',arguments:{tenant}}});
try{
 await new Promise(resolve=>as.listen(8089,'127.0.0.1',resolve));await new Promise(resolve=>mcp.listen(37499,'127.0.0.1',resolve));
 child=spawn(process.execPath,['/suite/wire.mjs',root+'/input.json'],{stdio:'ignore'});
 for(let i=0;i<100&&!existsSync(root+'/wire.json');i++)await pause(20);
 check('wire-ready',existsSync(root+'/wire.json'));
 const authorize='/authorize?'+new URLSearchParams({client_id:clientId,resource,redirect_uri:redirect,code_challenge:challenge,code_challenge_method:'S256'});await request(8088,authorize);
 const body=new URLSearchParams({client_id:clientId,grant_type:'authorization_code',resource,redirect_uri:redirect,code_verifier:verifier,code}).toString();
 const first=await request(8088,'/token',body,{'Content-Type':'application/x-www-form-urlencoded','X-Wire-Check':'preserve'});
 check('request-body-and-header-preserved',receivedBody.toString()===body&&receivedHeader==='preserve');
 check('response-body-and-header-preserved',first.body===codeJson&&first.headers['x-wire-check']==='preserve');
 check('pkce-and-callback-observed',wire().events.some(e=>e.kind==='TOKEN'&&e.pkceBound&&e.exactCallback));
 await request(8090,'/mcp',packet('local'),{Authorization:'Bearer '+access});
 check('local-self-tool-arguments-observed',wire().events.some(e=>e.localSelf&&e.toolNameMatches&&!e.otherTenant));
 check('permitted-current-access-observed',wire().events.some(e=>e.permittedTool&&e.usesCurrentAccess&&e.usesInitialAccess));
 const secondBody=new URLSearchParams({client_id:clientId,grant_type:'refresh_token',resource,refresh_token:refresh}).toString();
 const second=await request(8088,'/token',secondBody,{'Content-Type':'application/x-www-form-urlencoded'});
 check('refresh-bytes-preserved',receivedBody.toString()===secondBody&&second.body===refreshJson);
 check('rotation-observed',wire().events.some(e=>e.refreshGrant&&e.usesCurrentRefresh&&e.accessChanged&&e.refreshChanged));
 await request(8090,'/mcp',packet('other'),{Authorization:'Bearer '+nextAccess});
 check('other-tenant-tool-arguments-observed',wire().events.some(e=>e.otherTenant&&e.toolNameMatches&&!e.localSelf));
 check('denial-and-new-access-observed',wire().events.some(e=>e.applicationDenial&&e.usesCurrentAccess&&!e.usesInitialAccess));
 const metadata=await request(6278,'/oauth/client-metadata.json','',{Host:'goose-docs.ai','X-Fixture-Tls-Sni':'goose-docs.ai'});
 check('metadata-capture-bytes-and-publisher-max-age',metadata.status===200&&metadata.body===readFileSync('/suite/goose-client-metadata.json','utf8')&&metadata.headers['cache-control']==='max-age=600');
 await request(6278,'/oauth/client-metadata.json','',{Host:'goose-docs.ai','X-Fixture-Tls-Sni':'goose-docs.ai',Cookie:cookie,'If-None-Match':cookie});
 check('nonanonymous-conditional-metadata-detected',wire().events.some(e=>e.kind==='CIMD'&&!e.anonymous&&!e.unconditional));
 badJson=true;await request(8088,'/token',body);check('malformed-token-response-is-only-a-fixed-fact',wire().events.some(e=>e.invalidTokenJson));
 const serialized=readFileSync(root+'/wire.json','utf8');
 check('no-credential-cookie-identity-or-credential-hash-persisted',[verifier,code,access,refresh,nextAccess,nextRefresh,identity,cookie,challenge,...[verifier,code,access,refresh].map(s=>createHash('sha256').update(s).digest('base64url'))].every(s=>!serialized.includes(s)));
 let rejected=false;try{await request(8088,'/token','Z'.repeat(65537));}catch{rejected=true;}check('oversized-request-bounded',rejected);
 for(let i=wire().events.length;i<256;i++)await request(8088,'/other');
 const full=await request(8088,'/other');check('event-cap-refuses-without-growth',full.status===503&&wire().events.length===256);
 console.log(JSON.stringify({status:'PASS',checks}));
}catch(error){console.log(JSON.stringify({status:'FAILED',checks,failure:['WIRE_ASSERTION','REQUEST_FAILED'].includes(error.message)?error.message:'FIXED_WIRE_FAILURE'}));process.exitCode=1;
}finally{
 child?.kill();if(child)await new Promise(resolve=>{if(child.exitCode!==null)resolve();else child.once('exit',resolve);});
 for(const server of [as,mcp]){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
 rmSync(root,{recursive:true,force:true});
}
