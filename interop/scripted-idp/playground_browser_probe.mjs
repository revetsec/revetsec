// Copyright 2026 Revetware LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import {spawn, execFileSync} from 'node:child_process';
import {existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync} from 'node:fs';
import {networkInterfaces, tmpdir} from 'node:os';
import {join} from 'node:path';
import {connectCdp} from '/support/cdp.mjs';
import {chromeArguments} from '/support/web.mjs';

const app = 'https://localhost:9443';
const idp = 'https://localhost:8443';
if (process.env.NODE_EXTRA_CA_CERTS !== '/shared/ca.crt'
    || Object.keys(networkInterfaces()).some(name => name !== 'lo'))
  throw new Error('BROWSER_ISOLATION_REQUIRED');
const root = mkdtempSync(join(tmpdir(), 'revetsec-saml-browser-'));
const home = join(root, 'home');
const nss = join(home, '.pki', 'nssdb');
const profile = join(root, 'profile');
mkdirSync(nss, {recursive: true, mode: 0o700});
mkdirSync(profile, {mode: 0o700});
execFileSync('certutil', ['-N', '--empty-password', '-d', 'sql:' + nss]);
execFileSync('certutil', ['-A', '-n', 'Revetsec disposable local CA', '-t', 'C,,',
                         '-i', '/shared/ca.crt', '-d', 'sql:' + nss]);
const browser = spawn('/ms-playwright/chromium-1243/chrome-linux-arm64/chrome',
                      chromeArguments(profile), {stdio: 'ignore', env: {
  PATH: process.env.PATH, HOME: home,
  XDG_CONFIG_HOME: join(root, 'config'), XDG_CACHE_HOME: join(root, 'cache'),
}});
let browserClosed = false;
browser.once('exit', () => { browserClosed = true; });
let cdp;
let session;
const rows = [];
const result = {status: 'FAILED', stage: 'BROWSER_START', browserSandboxDisabled: false,
                certificateErrorBypass: false, globalTrustMutation: false, networkIsolated: true,
                checks: [], http: rows};
const delay = () => new Promise(resolve => setTimeout(resolve, 50));
function check(name, value) {
  result.checks.push({name, pass: Boolean(value)});
  if (!value) throw new Error('CHECK_' + name);
}
async function waitFor(name, predicate, ms = 15000) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try { if (await predicate()) return; } catch {}
    await delay();
  }
  throw new Error('TIMEOUT_' + name);
}
async function evaluate(expression) {
  const response = await cdp.send('Runtime.evaluate',
                                  {expression, returnByValue: true, awaitPromise: true}, session);
  if (response.exceptionDetails) throw new Error('DOM_EVALUATION');
  return response.result.value;
}
async function put(path, data) {
  const response = await fetch(idp + path, {
    method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data),
    signal: AbortSignal.timeout(5000),
  });
  if (response.status !== 200) throw new Error('IDP_CONTROL_' + response.status);
  await response.arrayBuffer();
}
function now() { return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'); }
const entity = app + '/saml/metadata';
async function armSso() {
  await put('/control/armed/sso', {entity_id: entity, spec: {
    clock: {now: now()}, subject: {name_id: 'browser-user', session_index: '_browser-session-1'},
    signing: {placement: 'assertion', algorithm: 'rsa-sha256'},
  }});
}
async function receivedFacts() {
  const response = await fetch(idp + '/control/received', {signal: AbortSignal.timeout(5000)});
  if (response.status !== 200) throw new Error('IDP_RECEIPT_' + response.status);
  const entries = (await response.json()).received;
  return {
    signedAuthn: entries.filter(entry => entry.binding === 'redirect'
      && entry.signature_valid === true && entry.schema_valid === true).length,
    signedLogout: entries.filter(entry => entry.binding === 'redirect-slo'
      && entry.signature_valid === true).length,
    spMetadata: entries.filter(entry => entry.binding === 'sp-metadata'
      && entry.schema_valid === true).length,
  };
}
async function issueLogoutRequest(sessionIndex) {
  const response = await fetch(idp + '/control/logout-requests', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      clock: {now: now()},
      sp: {entity_id: entity, slo_url: app + '/saml/slo'},
      subject: {name_id: 'browser-user', session_index: sessionIndex},
    }),
    signal: AbortSignal.timeout(5000),
  });
  if (response.status !== 200) throw new Error('IDP_REQUEST_' + response.status);
  const body = await response.json();
  const redirect = new URL(body.redirect_url);
  if (redirect.origin !== app || redirect.pathname !== '/saml/slo')
    throw new Error('IDP_REQUEST_REDIRECT');
  return redirect.href;
}
async function visitLogoutRequest(index) {
  const redirect = await issueLogoutRequest(index);
  await cdp.send('Page.navigate', {url: redirect}, session);
  await waitFor('idp-logout-ack', async () => await evaluate(
    `location.origin===${JSON.stringify(idp)} && location.pathname==='/slo'`), 15000);
  await cdp.send('Page.navigate', {url: app + '/'}, session);
  await waitFor('app-after-idp-logout', async () => await evaluate(
    `document.querySelector('#saml-login input[name=csrf]')?.value.length>0`), 15000);
}
async function loggedIn() {
  return await evaluate(`document.getElementById('identity')?.textContent.includes('"method": "SAML"')===true`);
}
async function clickButton(selector) {
  check('button-enabled-' + selector.slice(1), await evaluate(`(() => {
    const b=document.querySelector(${JSON.stringify(selector)});
    if(!b || b.disabled) return false;
    b.click(); return true;
  })()`));
}
try {
  await waitFor('browser-ready', () => existsSync(join(profile, 'DevToolsActivePort')), 10000);
  const [port, path] = readFileSync(join(profile, 'DevToolsActivePort'), 'utf8').trim().split('\n');
  cdp = await connectCdp('ws://127.0.0.1:' + port + path);
  const version = await cdp.send('Browser.getVersion');
  result.browser = {product: version.product, revision: version.revision};
  const {targetId} = await cdp.send('Target.createTarget', {url: 'chrome://sandbox/'});
  session = (await cdp.send('Target.attachToTarget', {targetId, flatten: true})).sessionId;
  for (const domain of ['Page', 'Runtime', 'Network']) await cdp.send(domain + '.enable', {}, session);
  await waitFor('sandbox-page', async () => (await evaluate('document.body?.innerText??""')).includes('Layer 1 Sandbox'));
  const sandbox = await evaluate(`(() => {
    const t=document.body.innerText;
    return {namespace:/Layer 1 Sandbox\\s+Namespace/i.test(t),
            seccomp:/Seccomp-BPF sandbox[^\\n]*Yes/i.test(t)};
  })()`);
  check('chromium-namespace-and-seccomp-sandbox', sandbox.namespace && sandbox.seccomp);
  cdp.on('Network.responseReceived', event => {
    try {
      const url = new URL(event.response.url);
      if (![app, idp].includes(url.origin)) return;
      if (rows.length < 80) rows.push({site: url.origin === app ? 'app' : 'idp',
                                       path: url.pathname, status: event.response.status});
    } catch {}
  });
  const before = await receivedFacts();
  check('idp-validated-sp-metadata', before.spMetadata >= 1);
  result.stage = 'LOGIN';
  await cdp.send('Page.navigate', {url: app + '/'}, session);
  await waitFor('login-button-ready', async () => await evaluate(
    `document.querySelector('#saml-login input[name=csrf]')?.value.length>0
      && document.querySelector('#saml-login button')?.disabled===false`));
  await armSso();
  await clickButton('#saml-login button');
  await waitFor('saml-login', loggedIn, 20000);
  check('browser-checked-saml-identity', await loggedIn());
  const cookies = (await cdp.send('Network.getCookies', {urls: [app]}, session)).cookies;
  check('secure-http-only-session-cookie', cookies.some(cookie =>
    cookie.name === '__Host-RevetsecPlayground' && cookie.secure && cookie.httpOnly));
  result.stage = 'SP_LOGOUT';
  await put('/control/armed/slo', {entity_id: entity, clock: {now: now()}});
  await clickButton('#saml-logout button');
  await waitFor('saml-sp-logout', async () => await evaluate(
    `document.getElementById('identity')?.textContent==='No browser identity'`), 20000);
  await waitFor('sp-logout-ui-ready', async () => await evaluate(
    `document.querySelector('#saml-login input[name=csrf]')?.value.length>0
      && document.querySelector('#saml-login button')?.disabled===false`));
  check('sp-initiated-logout-clears-app-identity', true);
  result.stage = 'IDP_LOGOUT';
  await armSso();
  await clickButton('#saml-login button');
  await waitFor('second-saml-login', loggedIn, 20000);
  check('second-checked-saml-identity', await loggedIn());
  await visitLogoutRequest('_different-session');
  check('different-session-index-preserves-identity', await loggedIn());
  await visitLogoutRequest('_browser-session-1');
  check('matching-session-index-ends-identity', !(await loggedIn()));
  const after = await receivedFacts();
  result.idpVerified = {
    signedAuthnRequests: after.signedAuthn - before.signedAuthn,
    signedLogoutMessages: after.signedLogout - before.signedLogout,
  };
  check('idp-verified-two-signed-schema-valid-authn-requests',
        result.idpVerified.signedAuthnRequests === 2);
  check('idp-verified-sp-logout-and-two-signed-logout-responses',
        result.idpVerified.signedLogoutMessages === 3);
  result.stage = 'COMPLETE';
  result.status = 'PASS';
} catch (error) {
  result.failure = typeof error?.message === 'string'
    && /^[A-Za-z0-9_-]{1,80}$/.test(error.message) ? error.message : 'BROWSER_PROBE_FAILED';
} finally {
  try { await cdp?.send('Browser.close'); } catch {}
  try { await cdp?.close(); } catch {}
  if (!browserClosed) browser.kill('SIGTERM');
  const until = Date.now() + 3000;
  while (!browserClosed && Date.now() < until) await delay();
  if (!browserClosed) browser.kill('SIGKILL');
  result.browserClosed = browserClosed;
  rmSync(root, {recursive: true, force: true});
  result.privateProfileRemoved = !existsSync(root);
  console.log(JSON.stringify(result));
}
if (result.status !== 'PASS') process.exitCode = 1;
