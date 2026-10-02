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

import {spawn,spawnSync} from 'node:child_process';
import {createServer} from 'node:http';
import {connect as connectHttp2} from 'node:http2';
import {connect as connectTls} from 'node:tls';
import {mkdirSync,readFileSync,writeFileSync,rmSync,existsSync} from 'node:fs';

const input=JSON.parse(readFileSync(0,'utf8'));
const root='/tmp/revetsec-edge-probe';mkdirSync(root,{mode:0o700});
for(const [name,value]of Object.entries({ca:input.ca,cert:input.cert,key:input.key}))
  writeFileSync(root+'/'+name+'.pem',value,{mode:0o600});
const report={status:'FAILED',image:input.image,caddy:spawnSync('/runtime/caddy',['version'],{encoding:'utf8'}).stdout.trim(),
  cases:[],hostnameVerification:true,certificateErrorBypass:false,globalTrustMutation:false};
const servers=[],observed=[];
let caddy,caddyClosed=false;
const pause=()=>new Promise(resolve=>setTimeout(resolve,50));
function request(bytes,port=8443) {
  return new Promise((resolve,reject)=>{
    const socket=connectTls({host:'127.0.0.1',port,servername:'localhost',ca:input.ca,
      ALPNProtocols:['http/1.1'],rejectUnauthorized:true},()=>socket.write(bytes));
    const chunks=[];let size=0;
    const timer=setTimeout(()=>{socket.destroy();reject(new Error('EDGE_EXCHANGE_TIMEOUT'));},3000);
    socket.on('data',chunk=>{size+=chunk.length;if(size>65536){socket.destroy();reject(new Error('EDGE_RESPONSE_BOUND'));}else chunks.push(chunk);});
    socket.once('error',reject);
    socket.once('close',()=>{clearTimeout(timer);const response=Buffer.concat(chunks).toString('utf8');
      const match=/^HTTP\/1\.1 (\d{3}) /.exec(response);resolve({status:match?Number(match[1]):0,
        emptyBody:response.split('\r\n\r\n')[1]===''});});
  });
}
async function h2Cookie() {
  const client=connectHttp2('https://localhost:8443',{ca:input.ca,rejectUnauthorized:true});
  try {
    return await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>reject(new Error('EDGE_H2_TIMEOUT')),3000);
      client.once('error',reject);
      const req=client.request({':path':'/cookie-control',':method':'GET',cookie:['first=one','second=two']});
      let status,size=0;
      req.on('response',headers=>status=headers[':status']);
      req.on('data',chunk=>{size+=chunk.length;if(size>65536)req.close();});
      req.once('error',reject);
      req.once('end',()=>{clearTimeout(timer);resolve({status,cookieSemicolonCoalesced:
        observed.at(-1)?.cookie==='first=one; second=two'});});req.end();
    });
  } finally {client.destroy();}
}
try {
  for(const [port,label]of [[8080,'frontend'],[8081,'mcp'],[8082,'barebones']]) {
    const server=createServer((incoming,outgoing)=>{
      observed.push({backend:label,host:incoming.headers.host,cookie:incoming.headers.cookie??null});
      outgoing.writeHead(200,{'content-type':'application/json','cache-control':'no-store'});outgoing.end('{}');
    });server.requestTimeout=3000;server.headersTimeout=3000;
    await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve);});servers.push(server);
  }
  const env={PATH:process.env.PATH,HOME:root,XDG_CONFIG_HOME:root+'/config',XDG_DATA_HOME:root+'/data',
    REVETSEC_TLS_CERT:root+'/cert.pem',REVETSEC_TLS_KEY:root+'/key.pem'};
  const adapt=spawnSync('/runtime/caddy',['adapt','--config','/source/interop/local-https/Caddyfile','--adapter','caddyfile'],
    {encoding:'utf8',env,timeout:10000,maxBuffer:1048576});
  report.adaptExit=adapt.status;if(adapt.status!==0)throw new Error('EDGE_ADAPT_FAILED');
  caddy=spawn('/runtime/caddy',['run','--config','/source/interop/local-https/Caddyfile','--adapter','caddyfile'],{env,stdio:'ignore'});
  caddy.once('exit',()=>caddyClosed=true);
  const deadline=Date.now()+10000;let ready=false;
  while(Date.now()<deadline&&!caddyClosed){try{if((await request('GET /ready HTTP/1.1\r\nHost: localhost:8443\r\nConnection: close\r\n\r\n')).status===200){ready=true;break;}}catch{}await pause();}
  if(!ready)throw new Error('EDGE_START_FAILED');
  const cases=[{name:'absent-sensitive-headers',fields:[],status:200}];
  for(const [name,value]of [['Authorization','Bearer public-edge-control'],['Origin','https://localhost:8443'],
    ['Content-Type','application/x-www-form-urlencoded; charset=UTF-8'],['Cookie','first=one; second=two']]) {
    cases.push({name:'single-'+name,fields:[name+': '+value],status:200});
    cases.push({name:'identical-duplicate-'+name,fields:[name+': '+value,name+': '+value],status:400});
    cases.push({name:'mixed-case-identical-duplicate-'+name,fields:[name+': '+value,name.toLowerCase()+': '+value],status:400});
  }
  cases.push({name:'identical-duplicate-Host',fields:['Host: localhost:8443'],status:400,nativeParser:true});
  cases.push({name:'mixed-case-identical-duplicate-Host',fields:['hOsT: localhost:8443'],status:400,nativeParser:true});
  for(const row of cases) {
    const before=observed.length;
    const result=await request('GET /header-control HTTP/1.1\r\nHost: localhost:8443\r\n'+row.fields.map(x=>x+'\r\n').join('')+'Connection: close\r\n\r\n');
    const passed=result.status===row.status&&(row.status!==400||observed.length===before)
      &&(row.status!==400||row.nativeParser||result.emptyBody);
    report.cases.push({name:row.name,status:result.status,expected:row.status,backendReached:observed.length!==before,
      fixedEmptyEdgeBody:row.status===400&&!row.nativeParser?result.emptyBody:null,passed});
  }
  for(const [name,path,port,backend,host]of [['mcp-route','/mcp',8443,'mcp','127.0.0.1:8081'],
    ['metadata-route','/.well-known/oauth-protected-resource',8443,'frontend','localhost:8443'],
    ['barebones-route','/',8445,'barebones','localhost:8445']]) {
    const response=await request(`GET ${path} HTTP/1.1\r\nHost: localhost:${port}\r\nConnection: close\r\n\r\n`,port),last=observed.at(-1);
    report.cases.push({name,status:response.status,backendMatches:last?.backend===backend,hostMatches:last?.host===host,
      passed:response.status===200&&last?.backend===backend&&last?.host===host});
  }
  const h2=await h2Cookie();report.cases.push({name:'http2-cookie-coalescing',...h2,passed:h2.status===200&&h2.cookieSemicolonCoalesced});
  report.status=report.cases.every(row=>row.passed)?'PASS':'FAILED';
} catch(error) {report.failure=/^EDGE_[A-Z_]+$/.test(error.message)?error.message:'EDGE_PROBE_FAILED';}
finally {
  if(caddy&&!caddyClosed)caddy.kill('SIGTERM');
  const until=Date.now()+3000;while(caddy&&!caddyClosed&&Date.now()<until)await pause();
  if(caddy&&!caddyClosed)caddy.kill('SIGKILL');
  for(const server of servers){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
  report.caddyClosed=caddyClosed;rmSync(root,{recursive:true,force:true});report.privateTlsRemoved=!existsSync(root);
  if(!caddyClosed||!report.privateTlsRemoved)report.status='FAILED';
  writeFileSync('/evidence/caddy-edge.RESULT.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
}
if(report.status!=='PASS')process.exitCode=1;
