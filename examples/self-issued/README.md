# Self-issued MCP Playground (unpublished)

A Soklet app using Revetsec as its OAuth issuer and online resource validator. The app owns a fixed demo account, browser sessions, CSRF, consent, client registrations, signing/sealing keys and persistence. Core owns OAuth admission, PKCE, issuance, refresh rotation, replay detection, revocation and checked token results. No external identity provider is required for this demonstration. Revetsec has not been independently audited.

## Storage and startup qualification

This bounded single-process **volatile** store keeps permanent issuer/subject fences during the process and refuses capacity exhaustion instead of evicting live grants or fences. It does not qualify durability, multiple nodes, rollback detection, backup restore or recovery. Startup generates fresh signing/sealing keys, a unique key ID/generation, and discards prior sessions/grants. Use a never-used issuer origin for each fresh run; do not restart an established issuer this way. `REVETSEC_ISSUER_FRESH_NAMESPACE=true` explicitly asserts the configured namespace has never been used or restored. Missing rows do not prove that assertion. For an established service, provide durable storage and managed keys and follow core's [application contracts](../../docs/oauth-server-application-contracts.md).

The application source has an injection constructor that accepts an app-owned `OAuthAuthorizationServerStore`, `OAuthIssuerKeyProvider` and `StateSealer`, plus an explicit `FRESH` or `ESTABLISHED` startup mode. `FRESH` performs the one-time issuer and demo-subject creation; `ESTABLISHED` only warms up the existing issuer and never creates a missing fence or generates replacement keys. The default `IssuerPlayground` launcher still uses fresh volatile state. An application using the established path must retain the same authorized signing and sealing material, close and drain routes during restore, and complete its external recovery fence before constructing a serving instance. `warmUp()` does not establish that a restored database is current or that every subject fence exists. Browser sessions are process-local, so an interrupted browser flow must start again after a process restart.

The companion [PostgreSQL storage example](../postgresql-pending-store/README.md) optionally compiles this app source with `PostgresqlIssuerStore` and checks fresh/established startup, token status and refresh rotation in separate JVMs against one primary. Its established Soklet process serves HTTP metadata, introspection and an MCP tool call on loopback; a replay committed in another JVM is denied on the next live MCP request. A scripted HTTP client completes login and consent, then redeems the issued code after a Soklet process restart, while the old browser cookie is rejected. The still-running issuer returns unavailable responses without releasing credentials during a primary outage and accepts the unchanged token when that primary returns. This is local application wiring evidence, not an independent browser test, durable launcher or production recovery procedure.

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

The framework JAR must have SHA-256 `c454eac7ff5fd58d564a2c1603133ed1c47a01210d2910be4d60f392ebe1184f` (Soklet source `bf9046f5384c367dfa2ddee2105f2f1ed3e4c8d1`). The builder copies both sources privately, installs exact artifacts, runs example tests and attributed nullability checks, then starts a standalone runtime with only core/helper/framework JARs. It records commands, inventories, hashes and boolean evidence without retaining credentials. Socket tests use the JDK HTTP client and raw bounded loopback sockets, including public-host and private-listener-port rejection. They do not qualify a browser or independent MCP client; see `interop/self-issued` for a separately pinned browser fixture.

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

HTTPS requires a trusted TLS edge. Configure `REVETSEC_ISSUER_ORIGIN` (default `https://localhost:8443`) and `REVETSEC_ISSUER_RESOURCE` (default origin plus `/mcp`) to exact public locations. Route `/mcp` to the MCP listener and other routes to the HTTP listener. All application listeners bind IPv4 loopback. The pinned Soklet artifact requires the public MCP port to equal the MCP listener port, even for explicitly allowed hostnames. Set `REVETSEC_ISSUER_MCP_PORT` to the configured resource port. Run the TLS edge on a separate address or in another network namespace so it can use the same public port without a bind conflict, and preserve the public Host header. The local browser fixture uses an IPv6 loopback edge and IPv4 loopback application. Never derive issuer/resource identity from forwarded headers. Set `REVETSEC_ISSUER_REDIRECT` to your client's registered URI; `https://client.example/callback` is only an illustrative default. HTTPS returns match the exact registered URI. Native numeric-loopback returns may vary only the port; the checked actual URI is retained for consent, redirect and token redemption. Set `REVETSEC_ISSUER_BROWSER_ORIGIN` to the explicitly trusted client browser origin when it differs from the registration origin (for example, a native callback's actual port). It defaults to the registration origin and accepts only an HTTPS origin or numeric IPv4 loopback HTTP origin. It does not add callback registrations or relax app login/consent Origin checks.

```sh
java -cp "PRIVATE_BUILD/example/target/classes:$(cat PRIVATE_BUILD/example/target/runtime-classpath.txt)" example.issuer.IssuerPlayground
```

Configure a client using `/.well-known/oauth-authorization-server`. Authorization requires S256 PKCE and the exact resource. The browser displays the checked client/redirect/scopes and accepts the login file's key. Login rotates its cookie and CSRF value while retaining an independent server-side browser binding. After consent the application supplies the fixed subject and freshly checked requested scopes. Every login/consent form also carries an independent action nonce bound to its exact interaction; old tabs cannot approve replacement clients. Form pages use `Referrer-Policy: same-origin` so normal browser form POSTs retain the exact Origin check; missing or opaque `null` origins still fail. Consent’s CSP permits only the app and library-checked interaction callback origin, including the browser’s redirect check. Credential-bearing redirects retain `Referrer-Policy: no-referrer`. Browser controls cannot supply another subject/resource/return target. Logout ends the browser session; revoke grants separately.

| Client | Allowed use | Authentication |
|---|---|---|
| `demo-public` | Authorization code and rotating refresh | Public ID; S256 PKCE |
| `demo-confidential` | Authorization code and rotating refresh | `client_secret_basic` with client key; S256 PKCE |
| `resource-client` | Introspection for this MCP resource only | `client_secret_basic` with resource key |

Confidential Basic requests must omit body `client_id` / `client_secret`. Registration is fixed and app-owned. No DCR, client-credentials issuance, OP/ID tokens or other server extensions are implemented here. `mcp:discover` permits discovery/list/initialize; `mcp:whoami` permits `whoami` for tenant `local` and object `self` only. Its optional string arguments are advertised explicitly so ordinary client forms can exercise both allowed and denied selections; the schema does not grant permission. Missing scopes produce a step-up challenge. Tool output omits raw subjects/credentials. The MCP hostname allowlist comes from the configured resource, and app Host/Origin checks use exact configured identities. CORS preflight does not establish an authenticated principal.

## Optional second resource

Set `REVETSEC_ISSUER_SECOND_RESOURCE=true` to add `/mcp-second` on the same MCP listener and resource origin. Route both exact endpoint paths to that listener and both `/.well-known/oauth-protected-resource/...` routes to the HTTP listener. The default remains one resource. Both demo authorization clients can request the same scopes for either resource; `resource-client` can introspect the configured resources. Each authorization still grants only the requested resource.

Admission selects the configured resource from Soklet's checked endpoint context, validates online for that exact resource, checks its audience/scopes, and challenges with its corresponding metadata URI. A token issued for `/mcp` cannot authorize `/mcp-second`, or vice versa, even though both use the same issuer, signing keys, client and scope names. Each endpoint retains independent application permission checks. This fixed optional demonstration does not provide dynamic resource provisioning or distributed deployment.

## Trusted transport

Soklet's Set-valued headers lose identical physical duplicates, including mixed-case names. A trusted edge must reject forbidden duplicate Authorization/Content-Type/Origin/Host/Cookie fields before materialization, enforce framing/body/header limits, and reject incomplete/oversized requests. Core receives all distinct materialized fields and unchanged raw query/body input. Responses use exact prepared bytes through `MarshaledResponse`, with credential-bearing Location kept separate. Do not log responses, credentials, cookies, keys, subjects or request bodies. The example logger emits event types only.

## Optional client metadata documents

CIMD is disabled by default. For a controlled fixed mapping, set both `REVETSEC_ISSUER_CIMD_ORIGIN` to an exact eligible public HTTPS origin (no path/query) and `REVETSEC_ISSUER_CIMD_ADDRESS` to its trusted canonical numeric IPv4 address. The application resolver returns only that configured address for that hostname, under the supplied budget, without DNS. This is trusted deployment configuration, never request input; changes to DNS/service addresses require updating the mapping. Unpaired or malformed settings fail startup.

The example passes this resolver and allowed origin to `OAuthClientMetadataPolicy`. Revetsec retains all destination/address checks, original Host/SNI/hostname validation, pinned HTTPS transport, bounded document parsing, safe local cache and fresh code/refresh retrieval. An allowed origin or fixed mapping cannot permit a private/special destination. No custom trust bypass, proxy, redirect or DCR fallback is provided. Real deployments must use an appropriate bounded trusted resolver and CA configuration; the interface supports application infrastructure.

Retrieved names are untrusted display text, not identity evidence or authorization. Login, explicit consent, exact requested resource/scopes/return, S256 and continuing application decisions remain required. The client document must permit refresh for the example to issue it. This optional volatile demonstration does not supply durable or distributed deployment/recovery.

### IPv6 native browser return

For an explicitly registered native `[::1]` callback, consent forms retain `form-action 'self'`. CSP host sources cannot express an IPv6 literal. After approval or denial the application renders an escaped **Return to application** link containing only the issuer's checked prepared callback, with `no-store`, `no-referrer`, `rel=noreferrer`, no scripts and frame/base restrictions. The user follows that normal link to the native listener. It does not broaden form submission to arbitrary HTTP origins or change client/resource/PKCE/token binding. IPv4 native and exact HTTPS returns continue to use the prepared redirect response.
