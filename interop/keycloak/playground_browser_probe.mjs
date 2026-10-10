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
const idp = 'https://localhost:8444';
const entity = app + '/saml/metadata';
if (process.env.NODE_EXTRA_CA_CERTS !== '/shared/ca.crt'
    || Object.keys(networkInterfaces()).some(name => name !== 'lo'))
  throw new Error('BROWSER_ISOLATION_REQUIRED');

const root = mkdtempSync(join(tmpdir(), 'revetsec-keycloak-browser-'));
const home = join(root, 'home');
const nss = join(home, '.pki', 'nssdb');
const profile = join(root, 'profile');
mkdirSync(nss, {recursive: true, mode: 0o700});
mkdirSync(profile, {mode: 0o700});
execFileSync('certutil', ['-N', '--empty-password', '-d', 'sql:' + nss]);
execFileSync('certutil', ['-A', '-n', 'Revetsec test CA', '-t', 'C,,',
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
const routes = [];
const acsOrigins = [];
const result = {status: 'FAILED', stage: 'BROWSER_START', browserSandboxDisabled: false,
                certificateErrorBypass: false, globalTrustMutation: false,
                networkIsolated: true, checks: [], http: rows, routes, acsOrigins};
const delay = () => new Promise(resolve => setTimeout(resolve, 50));
function check(name, value) {
  result.checks.push({name, pass: Boolean(value)});
  if (!value) throw new Error('CHECK_' + name);
}
async function waitFor(name, predicate, ms = 20000) {
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
async function loggedIn() {
  return await evaluate(`location.origin===${JSON.stringify(app)}
    && document.getElementById('identity')?.textContent.includes('"method": "SAML"')===true`);
}
async function click(selector) {
  check('button-enabled-' + selector.slice(1), await evaluate(`(() => {
    const b=document.querySelector(${JSON.stringify(selector)});
    if(!b || b.disabled) return false;
    b.click(); return true;
  })()`));
}
async function login(label) {
  await cdp.send('Page.navigate', {url: app + '/'}, session);
  await waitFor(label + '-app-ready', async () => await evaluate(
    `document.querySelector('#saml-login input[name=csrf]')?.value.length>0
      && document.querySelector('#saml-login button')?.disabled===false`));
  await click('#saml-login button');
  await waitFor(label + '-keycloak-form', async () => await evaluate(
    `location.origin===${JSON.stringify(idp)}
      && !!document.querySelector('#kc-form-login #username')
      && !!document.querySelector('#kc-form-login #password')`));
  check(label + '-keycloak-credential-form', await evaluate(`(() => {
    const f=document.querySelector('#kc-form-login');
    if(!f) return false;
    f.querySelector('#username').value='test-user';
    f.querySelector('#password').value='test-only-password-not-a-secret';
    f.requestSubmit(); return true;
  })()`));
  await waitFor(label + '-checked-identity', loggedIn, 30000);
  check(label + '-checked-saml-identity', await loggedIn());
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
      if (rows.length < 40 && (url.pathname === '/' || url.pathname === '/api/session'
          || url.pathname.endsWith('/protocol/saml')
          || url.pathname.endsWith('/protocol/openid-connect/logout')))
        rows.push({site: url.origin === app ? 'app' : 'keycloak',
                   path: url.pathname, status: event.response.status});
    } catch {}
  });
  cdp.on('Network.requestWillBeSent', event => {
    try {
      const url = new URL(event.request.url);
      if ([app, idp].includes(url.origin) && routes.length < 50
          && (url.pathname.startsWith('/saml/') || url.pathname.includes('/protocol/saml')
              || url.pathname.includes('/protocol/openid-connect/logout')))
        routes.push({site: url.origin === app ? 'app' : 'keycloak',
                     path: url.pathname, method: event.request.method,
                     saml: url.searchParams.has('SAMLResponse') ? 'response'
                       : url.searchParams.has('SAMLRequest') ? 'request' : null});
      if (url.origin !== app || url.pathname !== '/saml/acs') return;
      const headers = event.request.headers;
      const origin = headers.Origin ?? headers.origin ?? null;
      acsOrigins.push(origin === 'null' ? 'opaque'
        : origin === idp ? 'keycloak' : origin === app ? 'app'
          : origin === null ? 'absent' : 'other');
    } catch {}
  });

  result.stage = 'SP_LOGIN';
  await login('sp-login');
  check('opaque-origin-keycloak-post-accepted', acsOrigins.includes('opaque'));
  const cookies = (await cdp.send('Network.getCookies', {urls: [app]}, session)).cookies;
  check('secure-http-only-session-cookie', cookies.some(cookie =>
    cookie.name === '__Host-RevetsecPlayground' && cookie.secure && cookie.httpOnly));

  result.stage = 'SP_LOGOUT';
  await click('#saml-logout button');
  await waitFor('sp-logout-request', () => routes.some(route =>
    route.site === 'app' && route.path === '/saml/logout'));
  await waitFor('keycloak-sp-logout-return', () => routes.some(route =>
    route.site === 'app' && route.path === '/saml/slo'), 30000);
  await waitFor('sp-logout-return', async () => await evaluate(
    `location.origin===${JSON.stringify(app)}
      && document.querySelector('#saml-login input[name=csrf]')?.value.length>0
      && document.getElementById('identity')?.textContent==='No browser identity'`), 30000);
  check('sp-initiated-logout-clears-app-identity', true);
  check('keycloak-returned-saml-logout-response', routes.some(route =>
    route.site === 'app' && route.path === '/saml/slo' && route.saml === 'response'));

  result.stage = 'IDP_LOGOUT';
  await login('second-login');
  check('second-opaque-origin-keycloak-post-accepted',
    acsOrigins.filter(origin => origin === 'opaque').length === 2);
  await cdp.send('Page.navigate', {url: idp + '/realms/revetsec-test/protocol/openid-connect/logout?client_id='
    + encodeURIComponent(entity)}, session);
  await waitFor('keycloak-logout-confirmation', async () => await evaluate(
    `location.origin===${JSON.stringify(idp)} && !!document.querySelector('form[method=post]')`));
  check('keycloak-logout-confirmed', await evaluate(`(() => {
    const f=document.querySelector('form[method=post]');
    if(!f) return false; f.requestSubmit(); return true;
  })()`));
  await waitFor('idp-logout-ack', async () => await evaluate(
    `location.origin===${JSON.stringify(idp)}
      && (document.body?.innerText??'').includes('logged out')`), 30000);
  await cdp.send('Page.navigate', {url: app + '/'}, session);
  await waitFor('app-after-idp-logout', async () => await evaluate(
    `document.getElementById('identity')?.textContent==='No browser identity'`));
  check('idp-initiated-logout-clears-app-identity', true);
  check('keycloak-sent-saml-logout-request', routes.filter(route =>
    route.site === 'app' && route.path === '/saml/slo' && route.saml === 'request').length === 1);
  check('app-returned-saml-logout-response', routes.some(route =>
    route.site === 'keycloak' && route.path === '/realms/revetsec-test/protocol/saml'
      && route.saml === 'response'));
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
