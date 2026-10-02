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

import {resolve} from 'node:path';

const fail = code => { throw new Error(code); };
// Pinned upstream index.html requests an optional Google Fonts stylesheet.
// Block it, use system fonts, and distinguish this known denial from a new URL.
const PINNED_FONT = 'https://fonts.googleapis.com/css2?family=Fredoka:wght@300..700&family=Roboto+Mono:ital,wght@0,100..700;1,100..700&display=swap';

export function browserRequestPolicy(request, origin, resourceType) {
  try {
    if (typeof request?.url !== 'string' || typeof request?.method !== 'string') return 'BLOCKED_UNEXPECTED';
    const url = new URL(request.url);
    if (url.origin === origin && !url.username && !url.password) return 'SAME_ORIGIN';
    if (request.url === PINNED_FONT && request.method === 'GET' && resourceType === 'Stylesheet')
      return 'BLOCKED_PINNED_FONT';
  } catch { /* A malformed URL is never forwarded or persisted. */ }
  return 'BLOCKED_UNEXPECTED';
}

export function chromeArguments(profile) {
  if (typeof profile !== 'string' || profile !== resolve(profile) || profile === '/'
      || /[\u0000-\u001f\u007f]/u.test(profile))
    fail('BROWSER_PROFILE_INVALID');
  return ['--headless=new', `--user-data-dir=${profile}`, '--remote-debugging-address=127.0.0.1',
    '--remote-debugging-port=0', '--no-first-run', '--no-default-browser-check',
    '--disable-background-networking', '--disable-component-update', '--disable-sync',
    '--disable-default-apps', '--disable-domain-reliability', '--disable-breakpad',
    '--disable-features=MediaRouter,OptimizationHints,AutofillServerCommunication',
    '--password-store=basic', '--use-mock-keychain', '--no-proxy-server',
    '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost',
    '--window-size=1440,1000', 'about:blank'];
}

export function validWebConfig(config, origin) {
  if (config?.writable !== false || config.secretStorage?.kind !== 'memory'
      || config.secretStorage?.reason !== 'configured' || config.secretStorage?.durable !== false)
    return false;
  try {
    const main = new URL(origin);
    const sandbox = new URL(config.sandboxUrl);
    return typeof origin === 'string' && main.origin === origin && Number(main.port) > 0
      && main.protocol === 'http:' && main.hostname === '127.0.0.1'
      && typeof config.sandboxUrl === 'string' && sandbox.href === config.sandboxUrl
      && sandbox.protocol === 'http:' && sandbox.hostname === '127.0.0.1'
      && sandbox.origin !== origin && Number(sandbox.port) > 0 && sandbox.username === ''
      && sandbox.password === '' && sandbox.pathname === '/sandbox' && !sandbox.search && !sandbox.hash;
  } catch { return false; }
}

export function browserVersion(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || typeof value.product !== 'string' || typeof value.revision !== 'string'
      || value.product.length > 80
      || /[\r\n]/.test(value.product + value.revision)
      || !/^(?:Headless)?Chrome\/\d+\.\d+\.\d+\.\d+$/.test(value.product)
      || !/^@[a-f0-9]{40}$/.test(value.revision) || value.protocolVersion !== '1.3')
    fail('BROWSER_VERSION_INVALID');
  return { product: value.product, revision: value.revision, protocolVersion: value.protocolVersion };
}

