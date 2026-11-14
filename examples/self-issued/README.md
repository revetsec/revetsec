# Self-issued MCP Playground (unpublished)

**Shared-clock consumer join:** build this recipe with the same selected core artifact as the companion TOTP, WebAuthn and issuer consumers and all three framework adapters. A typed successful service result is still subject to the host's session/action/recovery-controller completion before output. Handle known committed reconciliation and uncertain effects deliberately, with no automatic retry or reconstruction from a later matching row. Raw initialization/reseal receipts are effect acknowledgements; they cannot open serving admission by themselves. This example's local checks do not qualify a live shared clock, retained-data migration or combined production deployment.

Use JDK 21 or newer for this Soklet application. Revetsec core retains Java 17 compatibility.

A Soklet app using Revetsec as its OAuth issuer and online resource validator. The app owns a fixed demo account, browser sessions, CSRF, consent, client registrations, signing/sealing keys and persistence. Core owns OAuth admission, PKCE, issuance, refresh rotation, replay detection, revocation and checked token results. No external identity provider is required for this demonstration. Revetsec has not been independently audited.

## Storage and startup qualification

This bounded single-process **volatile** store keeps permanent issuer/subject fences during the process and refuses capacity exhaustion instead of evicting live grants or fences. It owns a lazy UTC/elapsed projection separate from the issuer worker clock and returns coherent authority observations and contextual commit receipts. Ordinary reads, barriers and refusals never prune expired records; capacity can remain exhausted until explicit admitted application lifecycle handling. Normal issuer records use outer schema 2 and immutable admitted minima/entity floors. A raw initialization `COMMITTED` receipt acknowledges its effect; an explicit fresh operation checks serving admission. It does not qualify durability, multiple nodes, rollback detection, backup restore or recovery. Startup generates fresh signing/sealing keys, a unique key ID/generation, and discards prior sessions/grants. Use a never-used issuer origin for each fresh run; do not restart an established issuer this way. `REVETSEC_ISSUER_FRESH_NAMESPACE=true` explicitly asserts the configured namespace has never been used or restored. Missing rows do not prove that assertion. For an established service, provide durable storage and managed keys and follow core's [application contracts](../../docs/oauth-server-application-contracts.md).

The application source has an injection constructor that accepts an app-owned `OAuthAuthorizationServerStore`, `OAuthIssuerKeyProvider` and `StateSealer`, plus an explicit `FRESH` or `ESTABLISHED` startup mode. `FRESH` performs the one-time issuer and demo-subject creation; `ESTABLISHED` only warms up the existing issuer and never creates a missing fence or generates replacement keys. Established instances must also supply the same independent 32-byte admission partition key across nodes and restarts; the demo HMACs subjects with that key to derive Soklet admission/rate-limit partitions. Keep this key outside database snapshots and protect it as application secret material. The fresh volatile launcher generates a disposable partition key. The default `IssuerPlayground` launcher still uses fresh volatile state. An application using the established path must retain the same authorized signing and sealing material, close and drain routes during restore, and complete its external recovery fence before constructing a serving instance. `warmUp()` does not establish that a restored database is current or that every subject fence exists.

The application also selects a `BrowserSessionStore`. Its local default is the bounded process-local `BrowserSessions`; a browser flow using that default restarts after process loss. At capacity it refuses new sessions and preserves all live sessions. Anonymous authorization reads allocate no browser state; explicit session admission and expiry are described below. An actual deployment needs edge admission and shared rate limits. The optional PostgreSQL fixture supplies a shared store across JVMs. Both backends rotate the cookie and CSRF at login, bind a separate browser value to Revetsec's pending interaction, replace stale form actions, and claim consent once before calling core completion. A failed or uncertain claim releases no authorization response. An application backend must make these transitions atomic, keep a monotonic expiry fence, and return unavailable rather than treating a database outage as a missing session. This is application session/CSRF infrastructure, not a new Revetsec core session API.

The fixture can run two established Soklet nodes concurrently on IPv4 and IPv6 loopback with the same checked issuer/resource ports. `IssuerPlayground.sokletConfig` accepts a loopback listen address for this purpose; public issuer and resource identities remain fixed. The scripted cross-node login, consent, token, MCP and outage checks use the application-provided stores. A production deployment must supply its own routing, TLS edge and node coordination.

`IssuerPlayground.sokletConfig(app, toolRateLimiter)` accepts an application-supplied Soklet `McpRateLimiter`, so a deployment can use shared rate-limit state. The one-argument demo configuration uses Soklet's in-memory default, whose counters are local to one process. Revetsec still validates every bearer and the application still makes its own scope, tenant and object decisions before a tool runs; a rate limiter is not an authorization provider.

The companion [PostgreSQL storage example](../postgresql-pending-store/README.md) optionally compiles this app source with `PostgresqlIssuerStore` and checks fresh/established startup, token status and refresh rotation in separate JVMs against one primary. Its established Soklet process serves HTTP metadata, introspection and an MCP tool call on loopback; a replay committed in another JVM is denied on the next live MCP request. A scripted HTTP client completes login and consent, then redeems the issued code after a Soklet process restart. Its rotated cookie can also continue a pending consent flow after that restart, while the old pre-login cookie stays rejected. The still-running issuer returns unavailable responses without releasing credentials during a primary outage and accepts the unchanged token when that primary returns. This is local application wiring evidence, not an independent browser test, durable launcher or production recovery procedure.

The fresh local issuer sets `publicMetadataHttpCacheMaxAge(Duration.ZERO)`, advertising zero HTTP cache max-age for metadata and JWKS responses and using no publication-wait contribution from that policy; this does not demonstrate key rotation/publication timing. Access tokens live for two minutes. Every MCP message calls `validateAccessTokenResult` online, then checks scopes and application permissions. Its successful result also exposes the sensitive issuer-local grant handle checked by that same committed status barrier. Storage outages produce unavailable responses separate from invalid credentials.

### Application-owned grant binding

`IssuerApplicationTests.checkedGrantHandlesBindOtherwiseIdenticalGrantsAndSurviveRefresh` is a synthetic organization-binding example. Two grants with the same subject, client, resource and scopes receive different handles; access tokens issued by refresh retain their grant's handle. Its fake repository keys rows by issuer plus handle, performs idempotent `putIfAbsent`, refuses reassignment, and rechecks the token's subject/client/resource, live membership, association generation and required scope at resource admission. An orphan prepared row cannot select a different binding because lookup starts from `OAuthIssuerAccessTokenResult.Succeeded.getGrantValue()`.

A production binding is created only around trusted application consent. A narrow lexical context may supply the verified organization/member selection to the continuing grant-policy callback. That callback runs outside issuer transactions and may repeat with abandoned candidate handles, so its write must be idempotent and must not send notifications or imply the OAuth grant committed. Later code exchange and refresh callbacks have no trusted consent context: even though their checked grant type can be `authorization_code` or `refresh_token`, they only validate an existing mapping and never create or reassign one. Resource admission still requires the exact successful issuer result, current membership and current association generation. Application storage and the issuer store do not form a distributed atomic transaction; keep cleanup conservative while a grant may remain active.

## Build and run

Install the matching core, adapter and Soklet dependencies using the
[parent Maven instructions](../README.md#build-with-maven), then build from
the core repository root:

```sh
mvn -B -ntp -f examples/self-issued/pom.xml verify
```

The build runs the Java integration tests and packages an executable JAR with
its runtime dependencies in `target/lib`. After setting the trusted startup
configuration below, launch it with:

```sh
java -jar examples/self-issued/target/self-issued-1.0.0.jar
```

Keep the JAR beside its `lib` directory. Provided annotations and JUnit are not
runtime dependencies. Python is not required for this build or launch.

## Start a disposable run

Build the demo-key utility with `mvn -f examples/tools/pom.xml package` if you selected a single example rather than the full reactor. Create three distinct random access keys in private POSIX files containing 43 base64url characters with an optional final newline. These are demo access keys, not human passwords. Never commit them.

```sh
mkdir -m 700 /absolute/private/issuer-keys
java -jar examples/tools/target/example-tools-1.0.0.jar \
  /absolute/private/issuer-keys/login \
  /absolute/private/issuer-keys/client \
  /absolute/private/issuer-keys/resource
```

Set `REVETSEC_ISSUER_LOGIN_KEY_FILE`, `REVETSEC_ISSUER_CLIENT_KEY_FILE` and `REVETSEC_ISSUER_RESOURCE_KEY_FILE` to those files. Set `REVETSEC_ISSUER_FRESH_NAMESPACE=true` only after verifying the origin is new. For disposable numeric-loopback HTTP, additionally set `REVETSEC_ISSUER_ALLOW_HTTP_LOOPBACK=true` and distinct unused `REVETSEC_ISSUER_HTTP_PORT` / `REVETSEC_ISSUER_MCP_PORT` (defaults 8089/8090). The local origin/resource default to those listeners. Do not reuse an established issuer origin.

HTTPS requires a trusted TLS edge. Configure `REVETSEC_ISSUER_ORIGIN` (default `https://localhost:8443`) and `REVETSEC_ISSUER_RESOURCE` (default origin plus `/mcp`) to exact public locations. Route `/mcp` to the MCP listener and other routes to the HTTP listener. The default launcher binds IPv4 loopback; the two-node fixture can bind its second node on IPv6 loopback. The pinned Soklet artifact requires the public MCP port to equal the MCP listener port, even for explicitly allowed hostnames. Set `REVETSEC_ISSUER_MCP_PORT` to the configured resource port. Run the TLS edge on a separate address or in another network namespace so it can use the same public port without a bind conflict, and preserve the public Host header. The local browser fixture uses an IPv6 loopback edge and IPv4 loopback application. Never derive issuer/resource identity from forwarded headers. Set `REVETSEC_ISSUER_REDIRECT` to your client's registered URI; `https://client.example/callback` is only an illustrative default. HTTPS returns match the exact registered URI. Native numeric-loopback returns may vary only the port; the checked actual URI is retained for consent, redirect and token redemption. Set `REVETSEC_ISSUER_BROWSER_ORIGIN` to the explicitly trusted client browser origin when it differs from the registration origin (for example, a native callback's actual port). It defaults to the registration origin and accepts only an HTTPS origin or numeric IPv4 loopback HTTP origin. It does not add callback registrations or relax app login/consent Origin checks.

```sh
java -jar examples/self-issued/target/self-issued-1.0.0.jar
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

Soklet 4 preserves header values in lists. The adapter passes every materialized occurrence, including identical duplicates and differently cased names, to core for ambiguity checks. A trusted edge must still enforce framing/body/header limits and reject incomplete or oversized requests before protocol handling. Core receives unchanged raw query/body input. Responses use exact prepared bytes through `MarshaledResponse`, with credential-bearing Location kept separate. Do not log responses, credentials, cookies, keys, subjects or request bodies. The example logger emits event types only.

## Optional client metadata documents

CIMD is disabled by default. For a controlled fixed mapping, set both `REVETSEC_ISSUER_CIMD_ORIGIN` to an exact eligible public HTTPS origin (no path/query) and `REVETSEC_ISSUER_CIMD_ADDRESS` to its trusted canonical numeric IPv4 address. The application resolver returns only that configured address for that hostname, under the supplied budget, without DNS. This is trusted deployment configuration, never request input; changes to DNS/service addresses require updating the mapping. Unpaired or malformed settings fail startup.

The example passes this resolver and allowed origin to `OAuthClientMetadataPolicy`. Revetsec retains all destination/address checks, original Host/SNI/hostname validation, pinned HTTPS transport, bounded document parsing, safe local cache and fresh code/refresh retrieval. An allowed origin or fixed mapping cannot permit a private/special destination. No custom trust bypass, proxy, redirect or DCR fallback is provided. Real deployments must use an appropriate bounded trusted resolver and CA configuration; the interface supports application infrastructure.

Retrieved names are untrusted display text, not identity evidence or authorization. Login, explicit consent, exact requested resource/scopes/return, S256 and continuing application decisions remain required. The client document must permit refresh for the example to issue it. This optional volatile demonstration does not supply durable or distributed deployment/recovery.

Discovered clients remain public. Missing authentication declarations select `none`; a plural `token_endpoint_auth_methods_supported` must contain `none`. It may also advertise `private_key_jwt` or another unsupported method, and a consistent singular legacy preference may name that method, but the effective registration is still `none`. Shared-secret methods are always rejected. A signing-algorithm string is unused metadata, and `jwks`/`jwks_uri` are mutually exclusive and never fetched for client authentication. This is bounded CIMD negotiation, not private-key assertion support. A complete client-assertion pair at the token endpoint receives `invalid_client` without parsing the assertion; incomplete pairs remain malformed requests.

### IPv6 native browser return

For an explicitly registered native `[::1]` callback, consent forms retain `form-action 'self'`. CSP host sources cannot express an IPv6 literal. After approval or denial the application renders an escaped **Return to application** link containing only the issuer's checked prepared callback, with `no-store`, `no-referrer`, `rel=noreferrer`, no scripts and frame/base restrictions. The user follows that normal link to the native listener. It does not broaden form submission to arbitrary HTTP origins or change client/resource/PKCE/token binding. IPv4 native and exact HTTPS returns continue to use the prepared redirect response.

## Browser session admission

Anonymous `GET /authorize` displays a Continue form without creating a browser session or OAuth interaction. Its explicit same-origin `POST /session` preserves the original raw authorization query and redirects back to `/authorize`; core then validates the request normally. The POST accepts only the fixed `begin=1` form, exact Host/Origin and one form Content-Type. It creates no identity and grants no consent. Later login, consent and logout still require the session CSRF token and applicable action nonce.

The default local store admits at most 64 sessions (constructor range 1–128), rejects new admission with a fixed 503 when full, and never evicts a live session. Each session has an absolute ten-minute lifetime from creation or login rotation. Reads and bootstrap reuse do not renew it; request-time cleanup reclaims entries at the deadline. Existing sessions remain usable while new admission is full. A browser can deliberately request multiple sessions by dropping cookies; deployments must enforce trusted edge admission/rate limits. These local caps are not a distributed abuse-control service.
