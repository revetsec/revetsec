#!/usr/bin/env bash
# Copyright 2026 Revetware LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Run only with previously built local core, adapter and Playground artifacts.
# SOKLET_JAR is the checksum-pinned Soklet 4.0.0 JAR; BROWSER_SECCOMP is the
# private derived Playwright profile described in inspector-auth/linux/README.md.
set -euo pipefail
umask 077
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SOKLET_JAR=${SOKLET_JAR:?Set SOKLET_JAR to the pinned Soklet 4.0.0 JAR}
BROWSER_SECCOMP=${BROWSER_SECCOMP:?Set BROWSER_SECCOMP to the derived browser seccomp profile}
CORE_JAR=${CORE_JAR:-$ROOT/target/revetsec-1.0.0-SNAPSHOT.jar}
ADAPTER_JAR=${ADAPTER_JAR:-$ROOT/../revetsec-soklet/target/revetsec-soklet-1.0.0-SNAPSHOT.jar}
PLAYGROUND_CLASSES=${PLAYGROUND_CLASSES:-$ROOT/examples/playground/target/classes}
for path in "$SOKLET_JAR" "$BROWSER_SECCOMP" "$CORE_JAR" "$ADAPTER_JAR"; do
  if [ ! -f "$path" ]; then echo 'A required local artifact is missing.' >&2; exit 1; fi
done
if [ ! -f "$PLAYGROUND_CLASSES/example/playground/Playground.class" ]; then
  echo 'Build the Playground before running the browser probe.' >&2; exit 1
fi
python3 - "$SOKLET_JAR" "$ROOT/examples/pins.json" <<'PY'
import hashlib, json, pathlib, sys
actual = hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()
expected = json.loads(pathlib.Path(sys.argv[2]).read_text())['framework']['jar_sha256']
if actual != expected:
    raise SystemExit('Soklet JAR does not match the pinned 4.0.0 artifact.')
PY

WORK=$(mktemp -d "${TMPDIR:-/tmp}/revetsec-keycloak-playground.XXXXXX")
NAME=revetsec-keycloak-playground-$$
NS=$NAME-ns
KC=$NAME-kc
NODE=$NAME-node
EDGE=$NAME-edge
APP=$NAME-app
cleanup() {
  docker rm -f "$APP" "$EDGE" "$NODE" "$KC" "$NS" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
python3 - "$ROOT" "$WORK" <<'PY'
import copy, json, pathlib, sys
root, work = map(pathlib.Path, sys.argv[1:])
realm = json.loads((root / 'interop/keycloak/revetsec-test-realm.json').read_text())
original = next(c for c in realm['clients'] if c['clientId'] == 'https://sp.test/KeycloakSamlIT')
client = copy.deepcopy(original)
client['clientId'] = 'https://localhost:9443/saml/metadata'
client['name'] = 'Revetsec Playground SAML browser SP (TEST ONLY)'
client['redirectUris'] = ['https://localhost:9443/saml/acs']
client['attributes']['saml_assertion_consumer_url_post'] = 'https://localhost:9443/saml/acs'
client['attributes']['saml_single_logout_service_url_redirect'] = 'https://localhost:9443/saml/slo'
client['attributes']['saml.client.signature'] = 'true'
client['attributes']['saml_idp_initiated_sso_url_name'] = 'revetsec-playground'
realm['clients'].append(client)
(work / 'realm.json').write_text(json.dumps(realm))
caddy = (root / 'interop/local-https/Caddyfile').read_text()
(work / 'Caddyfile').write_text(caddy.replace('https://localhost:8443', 'https://localhost:9443'))
PY

TLS=$ROOT/src/test/resources/tls
docker run --pull never --rm -d --name "$NS" --network none alpine:latest sleep 900 >/dev/null
docker run --pull never --rm -d --name "$KC" --network "container:$NS" \
  -v "$TLS:/tls:ro" -v "$WORK/realm.json:/opt/keycloak/data/import/realm.json:ro" \
  quay.io/keycloak/keycloak@sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c \
  start --db=dev-file --hostname-strict=false --http-enabled=false --https-port=8444 \
  --https-certificate-file=/tls/server.pem --https-certificate-key-file=/tls/server-key.pem \
  --import-realm >/dev/null
docker run --pull never --rm -d --name "$NODE" --network "container:$NS" \
  -v "$WORK:/work" -v "$TLS/test-ca.pem:/shared/ca.crt:ro" \
  -e NODE_EXTRA_CA_CERTS=/shared/ca.crt node:24.18.0-bookworm-slim sleep 900 >/dev/null

READY=0
for _ in $(seq 1 80); do
  if docker exec "$NODE" node -e "fetch('https://localhost:8444/realms/revetsec-test/protocol/saml/descriptor').then(r=>{if(!r.ok)process.exit(1);return r.text()}).then(x=>require('fs').writeFileSync('/work/metadata.xml',x)).catch(()=>process.exit(1))" >/dev/null 2>&1; then
    READY=1; break
  fi
  sleep 2
done
if [ "$READY" != 1 ]; then echo KEYCLOAK_NOT_READY >&2; exit 1; fi

docker run --pull never --rm -d --name "$EDGE" --network "container:$NS" \
  -v "$WORK/Caddyfile:/etc/caddy/Caddyfile:ro" -v "$TLS:/tls:ro" \
  -e REVETSEC_TLS_CERT=/tls/server.pem -e REVETSEC_TLS_KEY=/tls/server-key.pem \
  caddy@sha256:0c994536bddb66445885237f1a5dcc1916bccea922661c76b4e9fc24061f9b52 \
  caddy run --config /etc/caddy/Caddyfile >/dev/null
docker run --pull never --rm -d --name "$APP" --network "container:$NS" \
  -v "$PLAYGROUND_CLASSES:/app:ro" -v "$CORE_JAR:/lib/core.jar:ro" \
  -v "$ADAPTER_JAR:/lib/adapter.jar:ro" -v "$SOKLET_JAR:/lib/soklet.jar:ro" \
  -v "$ROOT/src/test/resources/fixtures/keys:/keys:ro" \
  -v "$TLS/truststore.p12:/tls/truststore.p12:ro" \
  -v "$WORK/metadata.xml:/work/metadata.xml:ro" \
  -e PLAYGROUND_ORIGIN=https://localhost:9443 \
  -e PLAYGROUND_ISSUER=https://localhost:8444/realms/revetsec-test \
  -e PLAYGROUND_CLIENT_SECRET=test-only-client-secret-not-a-real-secret \
  -e PLAYGROUND_SAML_METADATA_FILE=/work/metadata.xml \
  -e PLAYGROUND_SAML_IDP_ENTITY_ID=https://localhost:8444/realms/revetsec-test \
  -e PLAYGROUND_SAML_CONNECTION_ID=keycloak-browser-test \
  -e PLAYGROUND_SAML_SIGNING_KEY_FILE=/keys/sp-encryption-rsa-2048-key.pem \
  -e PLAYGROUND_SAML_SIGNING_CERT_FILE=/keys/sp-encryption-rsa-2048-cert.pem \
  -e PLAYGROUND_SAML_DECRYPTION_KEY_FILE=/keys/sp-encryption-rsa-2048-key.pem \
  -e PLAYGROUND_SAML_DECRYPTION_CERT_FILE=/keys/sp-encryption-rsa-2048-cert.pem \
  eclipse-temurin:17-jdk-noble \
  java -Djavax.net.ssl.trustStore=/tls/truststore.p12 \
  -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit \
  -cp /app:/lib/core.jar:/lib/adapter.jar:/lib/soklet.jar example.playground.Playground >/dev/null

READY=0
for _ in $(seq 1 30); do
  if docker exec "$NODE" node -e "fetch('https://localhost:9443/saml/metadata').then(r=>{if(!r.ok)process.exit(1);return r.text()}).then(x=>{if(!x.includes('https://localhost:9443/saml/metadata'))process.exit(1)}).catch(()=>process.exit(1))" >/dev/null 2>&1; then
    READY=1; break
  fi
  sleep 1
done
if [ "$READY" != 1 ]; then echo PLAYGROUND_NOT_READY >&2; exit 1; fi

set +e
docker run --pull never --rm --network "container:$NS" --user pwuser \
  --cap-drop ALL --security-opt no-new-privileges \
  --security-opt "seccomp=$BROWSER_SECCOMP" --shm-size 512m \
  -v "$TLS/test-ca.pem:/shared/ca.crt:ro" \
  -v "$ROOT/interop/keycloak:/probe:ro" \
  -v "$ROOT/interop/inspector-auth/support:/support:ro" \
  -e NODE_EXTRA_CA_CERTS=/shared/ca.crt \
  revetsec-interop/inspector-linux:m5-phase4-locked \
  node /probe/playground_browser_probe.mjs > "$WORK/browser.json"
RESULT=$?
set -e
if [ -f "$WORK/browser.json" ]; then cat "$WORK/browser.json"; fi
exit "$RESULT"
