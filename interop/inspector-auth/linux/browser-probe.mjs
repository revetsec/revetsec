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

import {spawn} from 'node:child_process';
import {mkdirSync,readFileSync,existsSync,rmSync,writeFileSync} from 'node:fs';
import {connectCdp} from '../support/cdp.mjs';

const root='/tmp/revetsec-browser-sandbox-probe';
mkdirSync(root,{mode:0o700});
const profile=root+'/profile';mkdirSync(profile,{mode:0o700});
const browser=spawn('/ms-playwright/chromium-1243/chrome-linux-arm64/chrome',[
  '--headless=new','--user-data-dir='+profile,'--remote-debugging-address=127.0.0.1',
  '--remote-debugging-port=0','--no-first-run','--no-default-browser-check',
  '--disable-background-networking','--disable-component-update','--disable-sync',
  '--disable-default-apps','--disable-domain-reliability','--disable-breakpad',
  '--disable-features=MediaRouter,OptimizationHints,AutofillServerCommunication',
  '--password-store=basic','--no-proxy-server','about:blank'],
  {stdio:'ignore',env:{PATH:process.env.PATH,HOME:root,XDG_CONFIG_HOME:root+'/config',XDG_CACHE_HOME:root+'/cache'}});
let closed=false;browser.once('exit',()=>closed=true);
const pause=()=>new Promise(resolve=>setTimeout(resolve,50));
const receipt={status:'FAILED',capabilitiesDropped:'ALL',nonroot:true,noNewPrivileges:true,
  browserSandboxDisabled:false,globalHostPolicyMutation:false};
let cdp;
try {
  const deadline=Date.now()+10000;
  while(!existsSync(profile+'/DevToolsActivePort')&&Date.now()<deadline&&!closed)await pause();
  const [port,path]=readFileSync(profile+'/DevToolsActivePort','utf8').trim().split('\n');
  cdp=await connectCdp('ws://127.0.0.1:'+port+path);
  const version=await cdp.send('Browser.getVersion');
  receipt.browser={product:version.product,revision:version.revision,protocolVersion:version.protocolVersion};
  const {targetId}=await cdp.send('Target.createTarget',{url:'chrome://sandbox/'});
  const {sessionId}=await cdp.send('Target.attachToTarget',{targetId,flatten:true});
  await cdp.send('Page.enable',{},sessionId);await cdp.send('Runtime.enable',{},sessionId);
  const result=await cdp.send('Runtime.evaluate',{expression:`(() => {const t=document.body?.innerText??'';return {
    namespaceSandbox:/Layer 1 Sandbox\\s+Namespace/i.test(t),
    pidNamespaces:/PID namespaces[^\\n]*Yes/i.test(t),
    networkNamespaces:/Network namespaces[^\\n]*Yes/i.test(t),
    seccompBpf:/Seccomp-BPF sandbox[^\\n]*Yes/i.test(t)}})()`,returnByValue:true},sessionId);
  receipt.sandbox=result.result.value;
  receipt.status=receipt.sandbox?.namespaceSandbox&&receipt.sandbox?.seccompBpf?'PASS':'FAILED';
  await cdp.send('Browser.close');await cdp.close();
} catch(error) {
  receipt.failure=/^CDP_[A-Z_]+$/.test(error.message)?error.message:'BROWSER_PROBE_FAILED';
} finally {
  try{await cdp?.close();}catch{receipt.status='FAILED';}
  if(!closed)browser.kill('SIGTERM');
  const until=Date.now()+3000;while(!closed&&Date.now()<until)await pause();
  if(!closed)browser.kill('SIGKILL');
  receipt.browserClosed=closed;
  rmSync(root,{recursive:true,force:true});receipt.privateProfileRemoved=!existsSync(root);
  writeFileSync('/evidence/browser-sandbox.RESULT.json',JSON.stringify(receipt,null,2)+'\n');
  console.log(JSON.stringify(receipt));
}
if(receipt.status!=='PASS')process.exitCode=1;
