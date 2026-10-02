/*
 * Copyright 2026 Revetware LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
'use strict';
let csrf = '';
const byId = id => document.getElementById(id);
const show = value => { byId('result').textContent = JSON.stringify(value, null, 2); };
const presetNotes = {
  keycloak: 'Use the pinned local HTTPS Keycloak recipe and explicit client/audience mappings. Its JWT access tokens support audience-checked introspection.',
  node: 'Use the pinned local HTTPS node-provider Playground mode. For JSON introspection, set TEST_PLAYGROUND_TOKEN_FORMAT=opaque in the provider recipe, restart the provider, and select introspection. Both modes use the exact same resource audience.',
  generic: 'Configure an exact HTTPS issuer, registered callback and exact resource audience. Resource JWT validation uses RS256 and strict at+jwt.',
  google: 'Hosted OIDC login setup is unrun. Register the exact callback. Resource-token support requires separate verification.',
  entra: 'Hosted OIDC login setup is unrun. Use an exact tenant issuer and registered callback. Resource-token support requires separate verification.',
  okta: 'Hosted OIDC login setup is unrun. Register the exact callback and obtain account access. Resource-token support requires separate verification.',
  auth0: 'Hosted OIDC login setup is unrun. Register the exact callback and obtain account access. Resource-token support requires separate verification.'
};
async function refresh() {
  const response = await fetch('/api/session', {credentials: 'same-origin', cache: 'no-store'});
  const state = await response.json();
  if (!response.ok) { show(state); return; }
  csrf = state.csrf;
  for (const name of ['issuer', 'clientId', 'secretReference', 'probeClientId', 'probeSecretReference', 'strategy']) {
    byId('configuration').elements[name].value = state[name];
  }
  byId('login').elements.csrf.value = csrf;
  byId('resource').textContent = `Exact resource: ${state.resource}. Loopback HTTP exception: ${state.loopbackHttp ? 'explicitly enabled' : 'disabled'}.`;
  byId('identity').textContent = state.identity ? JSON.stringify(state.identity, null, 2) : 'No browser identity';
  byId('events').textContent = state.events.join('\n');
  const selected = state.issuer === 'https://localhost:9443' && state.clientId === 'revetsec-test-client' ? 'node'
    : state.issuer === 'https://localhost:9443/realms/revetsec-playground' && state.clientId === 'revetsec-playground' ? 'keycloak' : 'generic';
  byId('preset').value = selected;
  byId('preset-note').textContent = presetNotes[selected];
  byId('capture').disabled = !state.replayEnabled;
  byId('replay').disabled = !state.journalAvailable;
}
async function post(path, body, type) {
  const response = await fetch(path, {method: 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: {'Content-Type': type, 'X-CSRF-Token': csrf}, body});
  show(await response.json());
  await refresh();
  return response.ok;
}
byId('configuration').addEventListener('submit', async event => {
  event.preventDefault();
  if (await post('/api/config', new URLSearchParams(new FormData(event.currentTarget)), 'application/x-www-form-urlencoded')) location.reload();
});
byId('inspection').addEventListener('submit', async event => {
  event.preventDefault();
  const credential = byId('credential').value;
  byId('credential').value = '';
  await post('/api/inspect', credential, 'text/plain; charset=UTF-8');
});
byId('probe').addEventListener('click', async () => { await post('/api/probe', '', 'application/x-www-form-urlencoded'); });
byId('replay').addEventListener('click', async () => { await post('/api/replay', '', 'application/x-www-form-urlencoded'); });
byId('preset').addEventListener('change', event => {
  const preset = event.target.value;
  byId('preset-note').textContent = presetNotes[preset];
  if (preset === 'node' || preset === 'keycloak') {
    const fields = byId('configuration').elements;
    fields.issuer.value = preset === 'node' ? 'https://localhost:9443' : 'https://localhost:9443/realms/revetsec-playground';
    fields.clientId.value = preset === 'node' ? 'revetsec-test-client' : 'revetsec-playground';
    fields.probeClientId.value = fields.clientId.value;
    fields.secretReference.value = 'env:PLAYGROUND_CLIENT_SECRET';
    fields.probeSecretReference.value = 'env:PLAYGROUND_CLIENT_SECRET';
  }
});
refresh().catch(() => show({outcome: 'Local app unavailable'}));
