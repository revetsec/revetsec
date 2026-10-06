# Self-issued MCP Playground (unpublished)

A Soklet app using Revetsec as its OAuth issuer and online resource validator. The app owns a fixed demo account, browser sessions, CSRF, consent, client registrations, signing/sealing keys and persistence. Core owns OAuth admission, PKCE, issuance, refresh rotation, replay detection, revocation and checked token results. No external identity provider is required for this demonstration. Revetsec has not been independently audited.

## Storage and startup qualification

This bounded single-process **volatile** store keeps permanent issuer/subject fences during the process and refuses capacity exhaustion instead of evicting live grants or fences. It does not qualify durability, multiple nodes, rollback detection, backup restore or recovery. Startup generates fresh signing/sealing keys, a unique key ID/generation, and discards prior sessions/grants. Use a never-used issuer origin for each fresh run; do not restart an established issuer this way. `REVETSEC_ISSUER_FRESH_NAMESPACE=true` explicitly asserts the configured namespace has never been used or restored. Missing rows do not prove that assertion. For an established service, provide durable storage and managed keys and follow core's [application contracts](../../docs/oauth-server-application-contracts.md).

The fresh local issuer sets metadata freshness to zero; this does not demonstrate key rotation/publication timing. Access tokens live for two minutes. Every MCP message calls `validateAccessTokenResult` online, then checks scopes and application permissions. Storage outages produce unavailable responses separate from invalid credentials.

## Build exact local sources

The module is outside the reactor and cannot install/deploy itself. It records current core/helper source inventories, including uncommitted files. Matching CI pins await the owner's pushed revisions; existing example pins are unchanged.

```sh
python3 examples/self-issued/build.py --work /absolute/new/self-issued-build \
  --maven /absolute/path/to/mvn --java-home /absolute/path/to/jdk \
  --core-source /absolute/core-checkout --adapter-source /absolute/helper-checkout \
  --framework-jar /absolute/pinned/soklet-4.0.0.jar \
  --repository-tail /absolute/read-only/maven-cache --offline
```

The framework JAR must have SHA-256 `c454eac7ff5fd58d564a2c1603133ed1c47a01210d2910be4d60f392ebe1184f` (Soklet source `bf9046f5384c367dfa2ddee2105f2f1ed3e4c8d1`). The builder copies both sources privately, installs exact artifacts, runs example tests and attributed nullability checks, then starts a standalone runtime with only core/helper/framework JARs. It records commands, inventories, hashes and boolean evidence without retaining credentials. Socket tests use the JDK HTTP client; they do not qualify a browser or independent MCP client.

## Start a disposable run

Create three distinct random access keys in private POSIX files containing 43 base64url characters with an optional final newline. These are demo access keys, not human passwords. Never commit them.

```sh
python3 - <<'PY'
import os, secrets
from pathlib import Path
folder = Path('/absolute/private/issuer-keys')
folder.mkdir(mode=0o700)
for name in ('login', 'client', 'resource'):
    with os.fdopen(os.open(folder / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as out:
        out.write(secrets.token_urlsafe(32) + '\n')
PY
```

Set `REVETSEC_ISSUER_LOGIN_KEY_FILE`, `REVETSEC_ISSUER_CLIENT_KEY_FILE` and `REVETSEC_ISSUER_RESOURCE_KEY_FILE` to those files. Set `REVETSEC_ISSUER_FRESH_NAMESPACE=true` only after verifying the origin is new. For disposable numeric-loopback HTTP, additionally set `REVETSEC_ISSUER_ALLOW_HTTP_LOOPBACK=true` and distinct unused `REVETSEC_ISSUER_HTTP_PORT` / `REVETSEC_ISSUER_MCP_PORT` (defaults 8089/8090). The local origin/resource default to those listeners. Do not reuse an established issuer origin.

HTTPS requires a trusted TLS edge. Configure `REVETSEC_ISSUER_ORIGIN` (default `https://localhost:8443`) and `REVETSEC_ISSUER_RESOURCE` (default origin plus `/mcp`) to exact public locations. Route `/mcp` to the MCP listener and other routes to the HTTP listener. All listeners bind IPv4 loopback. Never derive issuer/resource identity from forwarded headers. Set `REVETSEC_ISSUER_REDIRECT` to your client's exact registered URI; `https://client.example/callback` is only an illustrative default.

```sh
java -cp "PRIVATE_BUILD/example/target/classes:$(cat PRIVATE_BUILD/example/target/runtime-classpath.txt)" example.issuer.IssuerPlayground
```

Configure a client using `/.well-known/oauth-authorization-server`. Authorization requires S256 PKCE and the exact resource. The browser displays the checked client/redirect/scopes and accepts the login file's key. Login rotates its cookie and CSRF value while retaining an independent server-side browser binding. After consent the application supplies the fixed subject and freshly checked requested scopes. Every login/consent form also carries an independent action nonce bound to its exact interaction; old tabs cannot approve replacement clients. Browser controls cannot supply another subject/resource/return target. Logout ends the browser session; revoke grants separately.

| Client | Allowed use | Authentication |
|---|---|---|
| `demo-public` | Authorization code and rotating refresh | Public ID; S256 PKCE |
| `demo-confidential` | Authorization code and rotating refresh | `client_secret_basic` with client key; S256 PKCE |
| `resource-client` | Introspection for this MCP resource only | `client_secret_basic` with resource key |

Confidential Basic requests must omit body `client_id` / `client_secret`. Registration is fixed and app-owned. No DCR, client-credentials issuance, OP/ID tokens or other server extensions are implemented here. `mcp:discover` permits discovery/list/initialize; `mcp:whoami` permits `whoami` for tenant `local` and object `self` only. Missing scopes produce a step-up challenge. Tool output omits raw subjects/credentials. Host/Origin checks use exact configured identities. CORS preflight does not establish an authenticated principal.

## Trusted transport

Soklet's Set-valued headers lose identical physical duplicates, including mixed-case names. A trusted edge must reject forbidden duplicate Authorization/Content-Type/Origin/Host/Cookie fields before materialization, enforce framing/body/header limits, and reject incomplete/oversized requests. Core receives all distinct materialized fields and unchanged raw query/body input. Responses use exact prepared bytes through `MarshaledResponse`, with credential-bearing Location kept separate. Do not log responses, credentials, cookies, keys, subjects or request bodies. The example logger emits event types only.
