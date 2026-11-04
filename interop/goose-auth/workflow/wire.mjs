// Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
// Bounded transparent test observer: unchanged request/response bytes; fixed facts only on disk.
import http from 'node:http';
import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync,renameSync} from 'node:fs';
const config=JSON.parse(readFileSync(process.argv[2],'utf8'));
const events=[],servers=[],startedAt=Date.now(),began=performance.now();
const elapsed=()=>Math.floor(performance.now()-began);
let challenge,selectedRedirect,currentAccess,currentRefresh,initialAccess;
const persist=()=>{writeFileSync(config.root+'/wire.json.tmp',JSON.stringify({startedAt,events}),{mode:0o600});renameSync(config.root+'/wire.json.tmp',config.root+'/wire.json');};
const allowedMethods=new Set(['initialize','notifications/initialized','server/discover','tools/list','tools/call','ping','resources/list','prompts/list','resources/templates/list']);
const classify=path=>path==='/token'?'TOKEN':path==='/authorize'?'AUTHORIZE':path==='/consent'?'CONSENT':path==='/login'?'LOGIN':path==='/register'||path==='/registration'?'DCR':path.includes('.well-known')?'METADATA':'OTHER';
function proxy(port,targetPort,mcp){
 const server=http.createServer({maxHeaderSize:16384,requestTimeout:15000,headersTimeout:15000},(incoming,outgoing)=>{
  let size=0,parts=[];
  incoming.on('data',p=>{size+=p.length;if(size>65536){incoming.destroy();return;}parts.push(p);});
  incoming.on('end',()=>{
   const body=Buffer.concat(parts);parts=[];const url=new URL(incoming.url,'http://localhost');
   if(events.length>=256){outgoing.writeHead(503);outgoing.end();return;}
   const row={ordinal:events.length,kind:mcp?'MCP':classify(url.pathname),method:incoming.method==='GET'?'GET':incoming.method==='POST'?'POST':'OTHER',elapsedMs:elapsed()};
   if(row.kind==='METADATA')row.metadataKind=url.pathname==='/.well-known/oauth-authorization-server'?'AUTH_SERVER':url.pathname==='/.well-known/oauth-protected-resource/mcp'?'PROTECTED_RESOURCE':'OTHER';
   if(mcp){
    const pv=incoming.headers['mcp-protocol-version'];row.protocolHeader=typeof pv==='string'&&/^20\d\d-\d\d-\d\d$/.test(pv)?pv:'ABSENT_OR_OTHER';
    row.methodHeader=allowedMethods.has(incoming.headers['mcp-method'])?incoming.headers['mcp-method']:'ABSENT_OR_OTHER';row.sessionHeaderPresent=incoming.headers['mcp-session-id']!==undefined;
    row.originPresent=incoming.headers.origin!==undefined;row.originMatches=incoming.headers.origin===config.issuer;
    row.acceptsJson=(incoming.headers.accept??'').includes('application/json');row.acceptsSse=(incoming.headers.accept??'').includes('text/event-stream');
    row.usesCurrentAccess=currentAccess!==undefined&&incoming.headers.authorization==='Bearer '+currentAccess;
    row.usesInitialAccess=initialAccess!==undefined&&incoming.headers.authorization==='Bearer '+initialAccess;
    try{const json=JSON.parse(body);row.mcpMethod=allowedMethods.has(json.method)?json.method:'OTHER';if(json.method==='tools/call'){row.toolNameMatches=json.params?.name==='whoami';const a=json.params?.arguments??{};row.localSelf=(a.tenant??'local')==='local'&&(a.object??'self')==='self';row.otherTenant=a.tenant==='other';}row.protocolVersion=json.params?.protocolVersion==='2026-07-28'?'2026-07-28':json.params?.protocolVersion==='2025-11-25'?'2025-11-25':incoming.headers['mcp-protocol-version']==='2026-07-28'?'2026-07-28':'OTHER';}catch{row.mcpMethod='OTHER';}
   }
   if(row.kind==='AUTHORIZE'){
    const q=url.searchParams;challenge=q.get('code_challenge');selectedRedirect=q.get('redirect_uri');
    row.cimdClient=q.get('client_id')===config.clientId;row.exactResource=q.get('resource')===config.resource;
    row.s256=q.get('code_challenge_method')==='S256'&&/^[A-Za-z0-9_-]{43}$/.test(challenge??'');
    const scopes=(q.get('scope')??'').split(' ');row.scopesDiscover=scopes.includes('mcp:discover');row.scopesWhoami=scopes.includes('mcp:whoami');row.onlyKnownScopes=scopes.length>0&&scopes.every(s=>['mcp:discover','mcp:whoami'].includes(s));
    row.exactCallback=selectedRedirect==='http://127.0.0.1:33419/oauth_callback';
   }
   if(row.kind==='TOKEN'){
    const q=new URLSearchParams(body.toString('utf8'));
    row.codeGrant=q.get('grant_type')==='authorization_code';row.refreshGrant=q.get('grant_type')==='refresh_token';
    row.cimdClient=q.get('client_id')===config.clientId;row.exactResource=q.get('resource')===config.resource;
    row.noAmbientCredentials=incoming.headers.cookie===undefined&&incoming.headers.authorization===undefined&&!q.has('client_secret');
    if(row.codeGrant){row.exactCallback=q.get('redirect_uri')===selectedRedirect;row.pkceBound=typeof challenge==='string'&&createHash('sha256').update(q.get('code_verifier')??'').digest('base64url')===challenge;}
    if(row.refreshGrant)row.usesCurrentRefresh=currentRefresh!==undefined&&q.get('refresh_token')===currentRefresh;
   }
   events.push(row);persist();let responseStarted=false;
   const target=http.request({host:'127.0.0.1',port:targetPort,path:incoming.url,method:incoming.method,headers:incoming.rawHeaders,timeout:15000},response=>{
    responseStarted=true;row.status=response.statusCode;let length=0,responseParts=[];
    if(mcp&&row.status===403){const header=response.headers['www-authenticate']??'';row.insufficientScope=header.includes('error="insufficient_scope"');row.whoamiChallenge=header.includes('scope="mcp:whoami"');}
    response.on('data',p=>{length+=p.length;if(length<=16384)responseParts.push(p);else responseParts=[];});
    response.on('end',()=>{
     row.completedElapsedMs=elapsed();row.durationMs=row.completedElapsedMs-row.elapsedMs;
     if(row.kind==='TOKEN'&&row.status===200&&length<=16384)try{
      const json=JSON.parse(Buffer.concat(responseParts).toString('utf8'));
      row.accessPresent=typeof json.access_token==='string';row.refreshPresent=typeof json.refresh_token==='string';
      row.bearer=json.token_type==='Bearer';row.noStore=response.headers['cache-control']==='no-store';
      row.expirySeconds=Number.isSafeInteger(json.expires_in)&&json.expires_in>0?json.expires_in:null;
      const scopes=typeof json.scope==='string'?json.scope.split(' '):[];row.scopesDiscover=scopes.includes('mcp:discover');row.scopesWhoami=scopes.includes('mcp:whoami');row.onlyKnownScopes=scopes.length>0&&scopes.every(s=>['mcp:discover','mcp:whoami'].includes(s));
      row.accessChanged=currentAccess!==undefined&&json.access_token!==currentAccess;row.refreshChanged=currentRefresh!==undefined&&json.refresh_token!==currentRefresh;
      if(row.codeGrant)initialAccess=json.access_token;currentAccess=json.access_token;currentRefresh=json.refresh_token;
     }catch{row.invalidTokenJson=true;}
     if(mcp&&row.mcpMethod==='initialize'&&row.status===200&&length<=16384)try{const json=JSON.parse(Buffer.concat(responseParts).toString('utf8'));const version=json.result?.protocolVersion;row.negotiatedProtocol=typeof version==='string'&&/^20\d\d-\d\d-\d\d$/.test(version)?version:'OTHER';row.responseSessionHeaderPresent=response.headers['mcp-session-id']!==undefined;}catch{}
     if(mcp&&row.status===400&&length<=16384)try{const json=JSON.parse(Buffer.concat(responseParts).toString('utf8'));row.errorCode=Number.isSafeInteger(json.error?.code)?json.error.code:null;const message=typeof json.error?.message==='string'?json.error.message:'';row.errorCategories=['protocol','Mcp-Method','Content-Type','session','initialized','Accept','Origin'].filter(word=>message.toLowerCase().includes(word.toLowerCase()));}catch{}
     if(row.kind==='CONSENT'&&response.headers.location)try{const location=new URL(response.headers.location);row.codeInPreparedRedirect=location.searchParams.has('code');row.issuerBoundResponse=location.searchParams.get('iss')===config.issuer;row.redirectMatchesAuthorization=location.origin+location.pathname===selectedRedirect;}catch{}
     if(mcp&&row.mcpMethod==='tools/call'&&row.status===200&&length<=16384)try{
      const json=JSON.parse(Buffer.concat(responseParts).toString('utf8'));const content=json.result?.content??[];
      row.applicationDenial=json.result?.isError===true&&content.some(p=>p.type==='text'&&p.text==='Operation not permitted');
      row.permittedTool=content.some(p=>p.type==='text'&&/^Checked identity partition: [A-Za-z0-9_-]{43}; permitted scopes:/.test(p.text));
     }catch{}
     responseParts=[];persist();
    });
    outgoing.writeHead(response.statusCode,response.rawHeaders);response.pipe(outgoing);
   });
   target.on('timeout',()=>target.destroy());target.on('error',()=>{row.status=502;persist();if(!responseStarted)outgoing.writeHead(502);outgoing.end();});
   outgoing.on('close',()=>target.destroy());target.end(body);
  });
  incoming.on('error',()=>outgoing.destroy());
 });server.listen(port,'127.0.0.1');servers.push(server);
}
proxy(8088,8089,false);proxy(8090,config.port,true);
const document=readFileSync('/suite/goose-client-metadata.json');
const metadata=http.createServer({maxHeaderSize:16384,requestTimeout:15000,headersTimeout:15000},(request,response)=>{
 const eligible=request.method==='GET'&&request.url==='/oauth/client-metadata.json'&&request.headers.host==='goose-docs.ai';
 if(events.length>=256){response.writeHead(503);response.end();return;}
 const row={ordinal:events.length,kind:'CIMD',elapsedMs:elapsed(),status:eligible?200:404,get:request.method==='GET',hostMatches:request.headers.host==='goose-docs.ai',sniMatches:request.headers['x-fixture-tls-sni']==='goose-docs.ai',anonymous:request.headers.authorization===undefined&&request.headers.cookie===undefined,unconditional:request.headers['if-none-match']===undefined&&request.headers['if-modified-since']===undefined,maxAge600:true,configuredDelayMs:config.metadataDelayMs};events.push(row);persist();
 setTimeout(()=>{row.completedElapsedMs=elapsed();row.durationMs=row.completedElapsedMs-row.elapsedMs;persist();response.writeHead(eligible?200:404,{'Content-Type':'application/json','Content-Length':eligible?document.length:0,'Cache-Control':'max-age=600'});response.end(eligible?document:undefined);},config.metadataDelayMs);
});metadata.listen(6278,'127.0.0.1');servers.push(metadata);persist();
for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>{for(const server of servers){server.closeAllConnections();server.close();}process.exitCode=0;});
