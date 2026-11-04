// Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
// Disposable, synthetic browser/virtual-authenticator evidence; no raw credentials in reports.
const { chromium, firefox, webkit } = await import(process.env.REVETSEC_PLAYWRIGHT_MODULE ?? 'playwright-core');
import { createServer } from 'node:https';
import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { createHash, X509Certificate } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { once } from 'node:events';
import { join } from 'node:path';
import assert from 'node:assert/strict';

const [work, classpath] = process.argv.slice(2);
if (!work || !classpath) throw new Error('Private work directory and worker classpath required');
const report = { policyCheckpoint: '2026-11-03', observedAtUtc: new Date().toISOString(), scope: 'Synthetic virtual-authenticator/current-source public API join; not physical, synced, platform or deployment qualification', rawCredentialsArchived: false, profiles: [], capabilityOnly: [] };
const cert = await readFile(join(work, 'private-tls/leaf.crt'));
const key = await readFile(join(work, 'private-tls/leaf.key'));
const pin = createHash('sha256').update(new X509Certificate(cert).publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
const server = createServer({cert,key}, (_req,res) => {res.writeHead(200, {'content-type':'text/html','cache-control':'no-store'});res.end('<!doctype html><title>Disposable WebAuthn extension probe</title><input autocomplete="username webauthn">');});
await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
const port=server.address().port;
const java=process.env.REVETSEC_JAVA ?? 'java';
function worker(origin) {
  const child=spawn(java,['-cp',classpath,'com.revetsec.webauthn.BrowserExtensionWorker',origin],{stdio:['pipe','pipe','pipe']});
  const lines=createInterface({input:child.stdout})[Symbol.asyncIterator]();let error=false;child.stderr.on('data',()=>{error=true;});
  return { async ready(){const result=await lines.next();assert.equal(result.done,false);return JSON.parse(result.value);}, async send(value){child.stdin.write(JSON.stringify(value)+'\n');const result=await Promise.race([lines.next(),new Promise((_,reject)=>setTimeout(()=>reject(new Error('Worker timeout')),15000).unref())]);assert.equal(result.done,false);assert.equal(error,false);return JSON.parse(result.value);},async close(){child.stdin.end();await Promise.race([once(child,'exit'),new Promise(resolve=>setTimeout(()=>{child.kill('SIGKILL');resolve();},1500).unref())]);} };
}
function shape(value){return {rootKeys:Object.keys(value).sort(),responseKeys:Object.keys(value.response).sort(),clientExtensionKeys:Object.keys(value.clientExtensionResults??{}).sort(),credPropsKeys:value.clientExtensionResults?.credProps?Object.keys(value.clientExtensionResults.credProps).sort():[],residentKey:value.clientExtensionResults?.credProps?.rk??null,publicKeyAlgorithm:value.response.publicKeyAlgorithm??null,authenticatorFlags:value.response.authenticatorData?Buffer.from(value.response.authenticatorData,'base64url')[32]:null};}
async function negative(peer,op,start,response,label){const result=await peer.send({op,ceremonyId:start.ceremonyId,response});assert.equal(result.status,'Rejected',label);assert.equal(result.recordsUnchanged,true,label);return label;}
try {
  for(const [label,executablePath] of [['installed-chrome',process.env.REVETSEC_CHROME],['bundled-chromium',process.env.REVETSEC_CHROMIUM]]){
    const profile=join(work,'private-'+label);await mkdir(profile);let context;if(!executablePath)throw new Error('Explicit disposable-browser executable required');
    try{
      context=await chromium.launchPersistentContext(profile,{executablePath,headless:true,chromiumSandbox:true,args:['--disable-background-networking','--disable-extensions','--no-proxy-server','--host-resolver-rules=MAP passkeys.example.test 127.0.0.1, MAP login.passkeys.example.test 127.0.0.1',`--ignore-certificate-errors-spki-list=${pin}`]});
      for(const host of ['passkeys.example.test','login.passkeys.example.test']){
        const origin=`https://${host}:${port}`;const peer=worker(origin);const page=await context.newPage();let cdp,authenticatorId;
        try{
          const readiness=await peer.ready();
          assert.equal(readiness.status,'Ready');
          cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');({authenticatorId}=await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',ctap2Version:'ctap2_1',transport:'usb',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}}));
          await page.goto(origin);const capabilities=await page.evaluate(async()=>({secureContext:isSecureContext,creationJSON:typeof PublicKeyCredential.parseCreationOptionsFromJSON==='function',requestJSON:typeof PublicKeyCredential.parseRequestOptionsFromJSON==='function',toJSON:typeof PublicKeyCredential.prototype.toJSON==='function',conditionalAvailable:await PublicKeyCredential.isConditionalMediationAvailable()}));assert.equal(capabilities.secureContext,true);
          const started=await peer.send({op:'register-start'});assert.equal(started.status,'Prepared');
          const created=await page.evaluate(async options=>(await navigator.credentials.create({publicKey:PublicKeyCredential.parseCreationOptionsFromJSON(options)})).toJSON(),started.publicKey);
          const rejected=[];
          for(const [name,extension] of [['draft-display-name',{credProps:{rk:true,authenticatorDisplayName:'synthetic'}}],['additional-client-output',{credProps:{rk:true},unknownOutput:true}],['rk-false',{credProps:{rk:false}}]])rejected.push(await negative(peer,'register-finish',started,{...created,clientExtensionResults:extension},name));
          const baseClient=JSON.parse(Buffer.from(created.response.clientDataJSON,'base64url').toString());
          for(const [name,badOrigin] of [['unlisted-origin',`https://unlisted.passkeys.example.test:${port}`],['suffix-lookalike',`https://passkeys.example.test.evil.test:${port}`],['sibling-origin',`https://foreign.example.test:${port}`],['eligible-but-unlisted-origin',`https://${host==='passkeys.example.test'?'login.passkeys.example.test':'passkeys.example.test'}:${port}`]]){
            const wrongOrigin=structuredClone(created);wrongOrigin.response.clientDataJSON=Buffer.from(JSON.stringify({...baseClient,origin:badOrigin})).toString('base64url');rejected.push(await negative(peer,'register-finish',started,wrongOrigin,name));
          }
          const challenge=Buffer.from(baseClient.challenge,'base64url');challenge[0]^=1;
          for(const [name,client] of [['wrong-challenge',{...baseClient,challenge:challenge.toString('base64url')}],['cross-origin',{...baseClient,crossOrigin:true}],['top-origin',{...baseClient,topOrigin:origin}]]){
            const bad=structuredClone(created);bad.response.clientDataJSON=Buffer.from(JSON.stringify(client)).toString('base64url');rejected.push(await negative(peer,'register-finish',started,bad,name));
          }
          const registered=await peer.send({op:'register-finish',ceremonyId:started.ceremonyId,response:created});assert.equal(registered.status,'Succeeded');
          const authStart=await peer.send({op:'authenticate-start'});assert.equal(authStart.status,'Prepared');const assertion=await page.evaluate(async options=>(await navigator.credentials.get({publicKey:PublicKeyCredential.parseRequestOptionsFromJSON(options)})).toJSON(),authStart.publicKey);
          rejected.push(await negative(peer,'authenticate-finish',authStart,{...assertion,clientExtensionResults:{unknownOutput:true}},'authentication-client-output'));
          const badHash=structuredClone(assertion);const signed=Buffer.from(badHash.response.authenticatorData,'base64url');signed[0]^=1;badHash.response.authenticatorData=signed.toString('base64url');rejected.push(await negative(peer,'authenticate-finish',authStart,badHash,'wrong-rp-hash-or-signature'));
          const authenticated=await peer.send({op:'authenticate-finish',ceremonyId:authStart.ceremonyId,response:assertion});assert.equal(authenticated.status,'Succeeded');
          report.profiles.push({browser:label,version:context.browser().version(),originProfile:host.startsWith('login.')?'configured-subdomain':'exact-rp-host',capabilities,registration:shape(created),authentication:shape(assertion),registrationOutcome:registered.status,authenticationOutcome:authenticated.status,attestationFormatConfirmedBySuccessfulCoreProfile:'none',negativeCasesRejectedWithoutMutation:rejected,conditionalCeremony:'not executed; availability is not autofill qualification',authenticator:'CDP CTAP2.1 virtual USB, resident key and UV; no physical/synced/platform claim',tls:'private leaf SPKI pin only; no system trust change; browser sandbox enabled'});
        }finally{if(cdp&&authenticatorId)await cdp.send('WebAuthn.removeVirtualAuthenticator',{authenticatorId}).catch(()=>{});try{await page.close();}finally{await peer.close();}}
      }
    }finally{if(context)await context.close();await rm(profile,{recursive:true,force:true});}
  }
  for(const [label,type] of [['bundled-firefox',firefox],['bundled-webkit',webkit]]){
    let browser;try{browser=await type.launch({headless:true});const context=await browser.newContext({ignoreHTTPSErrors:true});const page=await context.newPage();await page.goto(`https://localhost:${port}`);const capabilities=await page.evaluate(async()=>({secureContext:isSecureContext,credentialAPI:typeof PublicKeyCredential!=='undefined',creationJSON:typeof PublicKeyCredential!=='undefined'&&typeof PublicKeyCredential.parseCreationOptionsFromJSON==='function',requestJSON:typeof PublicKeyCredential!=='undefined'&&typeof PublicKeyCredential.parseRequestOptionsFromJSON==='function',toJSON:typeof PublicKeyCredential!=='undefined'&&typeof PublicKeyCredential.prototype.toJSON==='function',conditionalAvailable:typeof PublicKeyCredential!=='undefined'&&typeof PublicKeyCredential.isConditionalMediationAvailable==='function'?await PublicKeyCredential.isConditionalMediationAvailable():null}));report.capabilityOnly.push({browser:label,version:browser.version(),capabilities,scope:'API capability probe only; context-local TLS verification bypass; no WebAuthn ceremony, extension output or Revetsec compatibility claim; patched WebKit is not installed Safari'});await context.close();}catch(error){report.capabilityOnly.push({browser:label,outcome:'probe unavailable',errorClass:error.constructor.name,scope:'No ceremony or compatibility claim'});}finally{if(browser)await browser.close();}
  }
  report.status='PASS_NATIVE_ORIGIN_PROFILES';report.remainingUnproven=['Firefox/WebKit ceremonies','installed Safari','conditional autofill','platform/synced providers','current physical-key refresh','deployment time/witness/restore'];
}catch(error){report.status='FAIL';report.failure={kind:error.constructor.name,message:'Disposable browser check failed; raw browser data is not included'};throw error;}
finally{await new Promise(resolve=>server.close(resolve));await writeFile(join(work,'BROWSER-RESULTS.json'),JSON.stringify(report,null,2)+'\n');}
