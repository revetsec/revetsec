// Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
// Test-only loopback observer. Forward body bytes and headers; persist structural facts only.
import http from 'node:http';
import {request as httpsRequest} from 'node:https';
import {writeFileSync,renameSync} from 'node:fs';
const methods=new Set(['initialize','notifications/initialized','server/discover','tools/list','tools/call','ping','resources/list','prompts/list','resources/templates/list']);
const paths=new Map([['/register','DCR'],['/registration','DCR'],['/token','TOKEN'],['/login','LOGIN'],['/consent','CONSENT'],['/authorize','AUTHORIZE'],['/jwks','JWKS'],['/.well-known/oauth-authorization-server','METADATA'],['/.well-known/oauth-protected-resource/mcp','RESOURCE_METADATA'],['/.well-known/oauth-protected-resource/mcp-second','SECOND_RESOURCE_METADATA']]);
const events=[],servers=[];
const cimdId=process.argv[7]??'';
const native=process.argv[8]==='native';let selectedRedirect=process.argv[5];
function nativeRedirect(value){try{const a=new URL(value),b=new URL(process.argv[5]);return a.protocol===b.protocol&&a.hostname===b.hostname&&a.pathname===b.pathname&&a.search===b.search&&a.hash===b.hash&&a.username===b.username&&a.password===b.password&&Number(a.port)>0&&Number(a.port)<=65535&&a.port!==b.port&&value===a.href;}catch{return false;}}
// Volatile comparisons only; never store bearer/refresh bytes or their hashes in receipts.
let initialAccess,currentAccess,currentRefresh,initialExpiry=Infinity;
const start=Date.now(),issuedByResource=new Map();let probesStarted=false;
const resourceKind=value=>value===process.argv[4]+'/mcp'?'PRIMARY':value===process.argv[4]+'/mcp-second'?'SECONDARY':'UNKNOWN';
// Diagnostic traffic is separate from consumer traffic. Credentials issued by the real
// client flows stay in this process; requests cross only the two owned same-issuer resources.
async function crossResourceProbes(){
 const results=[];const primary=issuedByResource.get('PRIMARY'),secondary=issuedByResource.get('SECONDARY');
 const cases=[['primary-list','PRIMARY','PRIMARY','tools/list'],['primary-call','PRIMARY','PRIMARY','tools/call'],['secondary-list','SECONDARY','SECONDARY','tools/list'],['secondary-call','SECONDARY','SECONDARY','tools/call'],['primary-token-secondary-list','PRIMARY','SECONDARY','tools/list'],['primary-token-secondary-call','PRIMARY','SECONDARY','tools/call'],['secondary-token-primary-list','SECONDARY','PRIMARY','tools/list'],['secondary-token-primary-call','SECONDARY','PRIMARY','tools/call'],['primary-still-active','PRIMARY','PRIMARY','tools/call'],['secondary-still-active','SECONDARY','SECONDARY','tools/call']];
 for(const [name,source,target,method]of cases){
  try{results.push(await new Promise((resolve,reject)=>{
   const path=target==='PRIMARY'?'/mcp':'/mcp-second',token=source==='PRIMARY'?primary:secondary;
   const params={_meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientCapabilities':{}},...(method==='tools/call'?{name:'whoami',arguments:{}}:{})};
   const body=JSON.stringify({jsonrpc:'2.0',id:'diagnostic',method,params});
   const request=httpsRequest(process.argv[4]+path,{method:'POST',rejectUnauthorized:true,timeout:8000,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json',Accept:'application/json, text/event-stream','MCP-Protocol-Version':'2026-07-28','Mcp-Method':method,...(method==='tools/call'?{'Mcp-Name':'whoami'}:{}),'X-Revetsec-Fixture-Probe':'cross-resource'}},response=>{
    let size=0,parts=[];response.on('data',p=>{size+=p.length;if(size>16384){response.destroy();return;}parts.push(p);});
    response.on('error',reject);response.on('end',()=>{
     let data;try{data=JSON.parse(Buffer.concat(parts).toString('utf8'));}catch{}
     const h=response.headers['www-authenticate']??'';
     resolve({name,source,target,method,status:response.statusCode,invalidToken:h.includes('error="invalid_token"'),exactResourceMetadata:h.includes('resource_metadata="'+process.argv[4]+'/.well-known/oauth-protected-resource'+path+'"'),success:method==='tools/list'?data?.result?.tools?.length===1:data?.result?.isError!==true&&data?.result?.content?.some(c=>c.type==='text'&&/^Checked identity partition: [A-Za-z0-9_-]{43}; permitted scopes:/.test(c.text))===true});
    });
   });request.on('error',reject);request.on('timeout',()=>request.destroy());request.end(body);
  }));}catch{results.push({name,source,target,method,status:null,failure:'PROBE_TRANSPORT_FAILURE'});break;}
 }
 writeFileSync(process.argv[2]+'.cross',JSON.stringify({differentIssuedTokens:typeof primary==='string'&&typeof secondary==='string'&&primary!==secondary,credentialSource:'unmodified-client-code-exchanges',protocolEra:'modern-diagnostic',results}),{mode:0o600});
}
const persist=()=>{const path=process.argv[2];writeFileSync(path+'.next',JSON.stringify(events),{mode:0o600});renameSync(path+'.next',path);};
function listen(port,targetPort,kind){
 const server=http.createServer({maxHeaderSize:16384,requestTimeout:10000,headersTimeout:10000},(incoming,outgoing)=>{
  let bytes=0,chunks=[],started=false;
  incoming.on('data',chunk=>{bytes+=chunk.length;if(bytes>16384){incoming.destroy();return;}chunks.push(chunk);});
  incoming.on('end',()=>{
   const body=Buffer.concat(chunks);chunks=[];
   let method='OTHER';if(kind==='MCP')try{const parsed=JSON.parse(body.toString('utf8'));if(methods.has(parsed.method))method=parsed.method;}catch{}
   const path=kind==='MCP'?'MCP':paths.get(new URL(incoming.url,'http://fixture.invalid').pathname)??'OTHER';
   const row={kind,path,method,ordinal:events.length,elapsedMs:Date.now()-start,afterInitialExpiry:Date.now()>=initialExpiry,httpMethod:['GET','POST','OPTIONS'].includes(incoming.method)?incoming.method:'OTHER',authorizationPresent:typeof incoming.headers.authorization==='string',status:null};
   if(native&&kind==='AS'&&path==='AUTHORIZE'){const q=new URL(incoming.url,'http://fixture.invalid').searchParams,value=q.get('redirect_uri');const valid=nativeRedirect(value);row.nativeAuthorization={onlyPortVaries:valid,nonzeroPort:valid,s256:q.get('code_challenge_method')==='S256'&&/^[A-Za-z0-9_-]{43}$/.test(q.get('code_challenge')??''),exactResource:q.get('resource')===process.argv[4]+'/mcp'};if(valid)selectedRedirect=value;}
   if(kind==='MCP'){row.resource=resourceKind(process.argv[4]+new URL(incoming.url,'http://fixture.invalid').pathname);row.diagnosticProbe=incoming.headers['x-revetsec-fixture-probe']==='cross-resource';row.usesOwnResourceAccess=issuedByResource.has(row.resource)&&incoming.headers.authorization==='Bearer '+issuedByResource.get(row.resource);row.usesOtherResourceAccess=[...issuedByResource].some(([r,t])=>r!==row.resource&&incoming.headers.authorization==='Bearer '+t);row.usesInitialAccess=initialAccess!==undefined&&incoming.headers.authorization==='Bearer '+initialAccess;row.usesCurrentAccess=currentAccess!==undefined&&incoming.headers.authorization==='Bearer '+currentAccess;}
   if(kind==='AS'&&path==='TOKEN'&&incoming.method==='POST'){
    const form=new URLSearchParams(body.toString('utf8'));
    row.tokenRequest={resource:resourceKind(form.get('resource')),codeGrant:form.get('grant_type')==='authorization_code',refreshGrant:form.get('grant_type')==='refresh_token',basic:incoming.headers.authorization?.startsWith('Basic ')===true,publicId:form.get('client_id')===(cimdId||'demo-public'),bodyClientIdPresent:form.has('client_id'),bodySecretPresent:form.has('client_secret'),pkce:/^[A-Za-z0-9._~-]{43,128}$/.test(form.get('code_verifier')??''),exactResource:form.get('resource')===process.argv[4]+'/mcp',exactCallback:form.get('redirect_uri')===selectedRedirect,ambientCookiePresent:incoming.headers.cookie!==undefined,usesCurrentRefresh:currentRefresh!==undefined&&form.get('refresh_token')===currentRefresh};
   }
   if(events.length===256){outgoing.writeHead(503);outgoing.end();return;}
   events.push(row);persist();
   const target=http.request({host:'127.0.0.1',port:targetPort,path:incoming.url,method:incoming.method,headers:incoming.rawHeaders,timeout:10000},response=>{
    started=true;row.status=response.statusCode;row.completedElapsedMs=Date.now()-start;
    if(kind==='MCP'&&[401,403].includes(row.status)){
     const header=response.headers['www-authenticate']??'';
     row.challenge={present:typeof header==='string'&&header.startsWith('Bearer '),invalidToken:header.includes('error="invalid_token"'),insufficientScope:header.includes('error="insufficient_scope"'),whoamiScope:header.includes('scope="mcp:whoami"'),exactResourceMetadata:header.includes('resource_metadata="'+process.argv[4]+'/.well-known/oauth-protected-resource'+(row.resource==='SECONDARY'?'/mcp-second':'/mcp')+'"')};
    }
    let length=0,parts=[];
    response.on('data',chunk=>{length+=chunk.length;if(length<=16384)parts.push(chunk);else parts=[];});
    response.on('end',()=>{
     if(kind==='AS'&&path==='TOKEN'&&row.status===200&&length<=16384)try{
      const data=JSON.parse(Buffer.concat(parts).toString('utf8'));
      row.tokenResponse={accessPresent:typeof data.access_token==='string',refreshPresent:typeof data.refresh_token==='string',bearer:data.token_type==='Bearer',finiteExpiry:Number.isSafeInteger(data.expires_in)&&data.expires_in>0,noStore:response.headers['cache-control']==='no-store'};
     
      row.expirySeconds=Number.isSafeInteger(data.expires_in)&&data.expires_in>0?data.expires_in:null;
      const scopes=typeof data.scope==='string'?data.scope.split(' '):[];row.grantedScopes={discover:scopes.includes('mcp:discover'),whoami:scopes.includes('mcp:whoami'),onlyKnown:scopes.every(s=>['mcp:discover','mcp:whoami'].includes(s))};
      row.rotation={accessChanged:currentAccess!==undefined&&currentAccess!==data.access_token,refreshChanged:currentRefresh!==undefined&&currentRefresh!==data.refresh_token};
      if(typeof data.access_token==='string'&&typeof data.refresh_token==='string'&&Number.isSafeInteger(data.expires_in)&&data.expires_in>0){
       if(initialAccess===undefined){initialAccess=data.access_token;initialExpiry=Date.now()+data.expires_in*1000;}
       currentAccess=data.access_token;currentRefresh=data.refresh_token;
       if(row.tokenRequest?.resource!=='UNKNOWN')issuedByResource.set(row.tokenRequest.resource,data.access_token);
       if(process.argv[6]==='true'&&!probesStarted&&issuedByResource.has('PRIMARY')&&issuedByResource.has('SECONDARY')){probesStarted=true;void crossResourceProbes();}
      }
     }catch{row.tokenResponse={invalidJson:true};}
     if(kind==='MCP'&&method==='tools/list'&&row.status===200&&length<=16384)try{const data=JSON.parse(Buffer.concat(parts).toString('utf8'));const schema=data.result?.tools?.[0]?.inputSchema;row.toolSchema={tenantString:schema?.properties?.tenant?.type==='string',objectString:schema?.properties?.object?.type==='string'};}catch{}
     if(kind==='MCP'&&method==='tools/call'&&row.status===200&&length<=16384)try{
      const data=JSON.parse(Buffer.concat(parts).toString('utf8'));row.applicationDenial=data.result?.isError===true&&data.result?.content?.some(c=>c.type==='text'&&c.text==='Operation not permitted')===true;
     }catch{}
     parts=[];persist();
    });
    persist();outgoing.writeHead(response.statusCode,response.rawHeaders);response.pipe(outgoing);
   });
   target.on('timeout',()=>target.destroy());target.on('error',()=>{row.status=502;persist();if(!started)outgoing.writeHead(502);outgoing.end();});
   outgoing.on('close',()=>target.destroy());target.end(body);
  });
  incoming.on('error',()=>outgoing.destroy());
 });
 server.listen(port,'127.0.0.1');servers.push(server);
}
listen(8090,Number(process.argv[3]),'MCP');listen(8088,8089,'AS');
if(cimdId){
 const document=Buffer.from(JSON.stringify({client_id:cimdId,client_name:'Local CIMD client',redirect_uris:[process.argv[5]],token_endpoint_auth_method:'none',application_type:'web',grant_types:['authorization_code','refresh_token'],response_types:['code']}));
 const metadata=http.createServer({maxHeaderSize:16384,requestTimeout:10000,headersTimeout:10000},(request,response)=>{
  const eligible=request.method==='GET'&&request.url==='/client.json'&&request.headers.host==='cimd.example.com:6277';
  if(events.length===256){response.writeHead(503);response.end();return;}
  events.push({kind:'CIMD',path:'CIMD_METADATA',method:'OTHER',ordinal:events.length,elapsedMs:Date.now()-start,httpMethod:request.method==='GET'?'GET':'OTHER',status:eligible?200:404,hostMatches:request.headers.host==='cimd.example.com:6277',sniMatches:request.headers['x-fixture-tls-sni']==='cimd.example.com',authorizationPresent:request.headers.authorization!==undefined,cookiePresent:request.headers.cookie!==undefined,conditional:request.headers['if-none-match']!==undefined||request.headers['if-modified-since']!==undefined,cacheMaxAgeSeconds:300,documentBytes:document.length});persist();
  response.writeHead(eligible?200:404,{'Content-Type':'application/json','Content-Length':eligible?document.length:0,'Cache-Control':'public, max-age=300'});response.end(eligible?document:undefined);
 });metadata.listen(6278,'127.0.0.1');servers.push(metadata);
}
const untrusted=http.createServer({maxHeaderSize:16384,requestTimeout:10000,headersTimeout:10000},(request,response)=>{response.writeHead(request.method==='GET'?200:403,{'Content-Type':'text/html; charset=UTF-8','Cache-Control':'no-store','Content-Security-Policy':"default-src 'none'; connect-src "+process.argv[4]});response.end('<!doctype html><title>Unregistered local origin</title>');});untrusted.listen(6275,'127.0.0.1');servers.push(untrusted);
for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>{for(const server of servers){server.closeAllConnections();server.close();}process.exitCode=0;});
