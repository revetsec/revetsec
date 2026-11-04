# OAuth authorization-server application guide

<a id="oauth-authorization-server-application-contracts"></a>

**Pre-release:** `com.revetsec.oauth.server` implements an application-integrated OAuth authorization-code issuer with strict refresh rotation, revocation, resource introspection, online access-token validation, metadata/JWKS publication and opt-in client-ID metadata documents (CIMD). Qualification and release acceptance remain open for the current deployment profile. Use matching core, adapter and store contracts; see [shared-clock storage and consumer rules](shared-clock-stores.md).

The application supplies users, login/session handling, CSRF defenses, permission decisions and storage. Revetsec's issuer validates the protocol, binds those decisions and manages credentials. An application decision is trusted configuration, not a Revetsec-verified authentication proof.

| Application task | Start here |
| --- | --- |
| Configure shared instances, keys and bounds | [Configure the issuer](#configure-the-issuer) |
| Register browser/resource clients or opt into CIMD | [Register and resolve clients](#register-and-resolve-clients) |
| Authenticate the browser and complete consent | [Authorize a browser](#authorize-a-browser) |
| Exchange a code and rotate refresh credentials | [Issue and refresh tokens](#issue-and-refresh-tokens) |
| Validate resources, revoke grants and emit responses | [Operate the issuer](#operate-the-issuer) |
| Initialize a genuinely new namespace, restore or migrate | [Manage storage and recovery](#manage-storage-and-recovery) |
| Change configuration across nodes | [Roll out configuration changes](#roll-out-configuration-changes) |
| Qualify the actual deployment | [Deployment obligations and evidence](#deployment-obligations-and-evidence) |

<a id="public-authorization-server"></a>

## Configure the issuer

Use one shared `OAuthAuthorizationServer` per exact issuer and application store/key/admission/policy configuration. Configure its builder during application startup, not for each request. The builder snapshots values; repositories, stores, key providers, clocks and callbacks remain application-owned references and must satisfy their thread-safety and budget contracts. The issuer is an OAuth code issuer, not an OpenID Connect provider: it does not issue ID tokens or provide dynamic client registration or arbitrary grants.

The following construction example assumes application-supplied `clients`, `store`, `signingKeys`, `stateSealer`, `grantPolicy` and `workerClock`. It does not initialize the issuer or demonstrate a production backend:

```java
OAuthAuthorizationServer server = OAuthAuthorizationServer
    .withIssuer("https://issuer.example")
    .authorizationEndpoint(URI.create("https://issuer.example/authorize"))
    .tokenEndpoint(URI.create("https://issuer.example/token"))
    .jwksEndpoint(URI.create("https://issuer.example/jwks"))
    .revocationEndpoint(URI.create("https://issuer.example/revoke"))
    .introspectionEndpoint(URI.create("https://issuer.example/introspect"))
    .clientRepository(clients)
    .store(store)
    .signingKeys(signingKeys)
    .stateSealer(stateSealer)
    .resources(Map.of("https://api.example/mcp", Set.of("read", "write")))
    .grantPolicy(grantPolicy)
    .clock(workerClock)
    .build();
```

| Setting or dependency | Application contract |
| --- | --- |
| Issuer and authorization/token/JWKS routes | Required exact issuer and distinct same-authority routes; request Host/Forwarded headers never select authority. No routes are inferred. |
| Client repository, authoritative store, signing-key provider, state sealer, grant policy and resource map | Required; null clears the requirement and makes build fail. Supply managed keys, admitted-time atomic persistence and continuing permission decisions. A volatile example store is not a durable deployment. |
| Revocation and introspection routes | Optional; null means absent. Refresh defaults off. Enabling refresh requires a revocation route plus client and application approval. |
| Worker clock | Defaults to system UTC; used for worker health, provisional key history and optional CIMD freshness. It never substitutes for admitted store time or initializes durable floors. |
| CIMD, observer and outbound policy | CIMD defaults disabled, observer defaults silent, outbound CIMD policy defaults to public addresses only. Runtime-floor acknowledgment is CIMD-only and has no issuer acknowledgment hook; see the [compatibility registry](compatibility-modes.md#acknowledgeunpatchedruntimetrue). |
| Loopback and localhost options | All default off and remain separate. HTTP numeric-loopback issuer routes, native IP-loopback client redirects, exact localhost redirects and port-less localhost any-port matching each require their own applicable opt-in. |

Build does no repository/store/key-provider/grant-policy/resolver callback, worker-clock sampling, network I/O, signing or owned thread startup. Enabling localhost any-port redirects emits its explicit construction observer event. A successful build does not establish trusted startup time, initialize persistence, open serving admission or qualify the backend. See the [complete builder contracts](../src/main/java/com/revetsec/oauth/server/OAuthAuthorizationServer.java) and the [self-issued application](../examples/self-issued/README.md), whose volatile state and fresh-namespace limits remain explicit.

### Values, bounds and diagnostics

Collections replace complete values and are copied at setter time; nested scope sets are immutable. Client/resource/scope identifiers retain exact String spelling. Redirects retain each URI's original `toString()` spelling: `URI.equals()` is unsuitable for protocol identity. Resource identifiers are absolute URIs without fragments; they are never URLs to fetch.

HTTPS redirects have no userinfo, fragment or wildcard. Preexisting query parameter names `code`, `state`, `iss`, `error`, `error_description` and `error_uri` are rejected, including percent-encoded names. Only exact HTTP `127.0.0.1`, `[::1]` and `localhost` configurations are representable. Their use requires separate explicit server opt-ins; registration alone enables no loopback feature. Endpoint admission enforces the IP-literal port exception, exact localhost policy and the separately enabled port-less localhost port exception.

Carrier ceilings support the approved configurable server maxima: 4096 UTF-16 code units for client ID/name/version, 1024 for subject, 65536 for URI spelling, 64 redirects, 1024 resources, 128 scopes per resource and 128 ASCII characters per scope. Each collection's resource/scope or redirect spellings also have a 131072-byte UTF-8 aggregate ceiling. These are construction bounds; operations must apply the configured narrower request, response and sealed-record limits. Invalid supplied values throw fixed `IllegalArgumentException`; a missing required builder value throws `IllegalStateException`; null required-primary arguments throw `NullPointerException`. Nullable setters clear required settings or reset the documented defaults.

Value and builder `toString()` methods redact identifiers, display names, configuration versions, subjects, scopes, handles and callbacks. Explicit data getters remain sensitive application data. The package adds no runtime dependency. Construction performs no repository, store, signing-key, grant-policy or address-resolver callbacks, worker-clock sampling, network I/O, signing or owned thread startup. The explicit exception is `OAuthServerObserver.didEnableLocalhostAnyPortRedirects()` after a successful build with that option enabled; it follows the observer's containment rules.

### Issuer signing keys and public metadata

`OAuthIssuerSigningKey.fromKeyPair` checks an RS256/RSA public projection locally without signing,
encoding private material or exposing a private-key getter. Mismatched pairs fail during actual bounded
signing or warm-up. `OAuthIssuerKeySnapshot.withActiveKey` builds an immutable active/public key declaration;
`generation` and `publishedAt` are required, null clears them, and null maps reset empty. An equal duplicate
of the active public key is accepted; another key under that ID is rejected. Public projections, maps and
retirement declarations are snapshotted. At most 100 keys and 128 KiB of aggregate configuration are accepted.
The application supplies `OAuthIssuerKeyProvider`, or uses `fromSnapshot` for a fixed declaration.
The [cross-process key lifecycle recipe](oauth-server-key-lifecycle.md) specifies durable publication and
retention facts, staged activation, conservative restart waits and recovery of missing history.

The provider is trusted infrastructure: it owns durable key history, publication to independent resources,
never reusing an identifier for different material, and overlap across nodes, restarts and in-flight operations.
Construction performs no provider lookup or signing. Operations fetch a fresh snapshot on the caller thread
under the original shrinking deadline. Provider faults, null, interruption and exhausted budgets fail closed;
fatal VM errors propagate. A generation's facts remain immutable. Every new generation has a strictly later
publication instant, and signing waits the configured public metadata HTTP cache max-age after publication. Delaying
or cancelling a retirement is allowed; moving it earlier is rejected. A key without a retirement declaration
cannot disappear from the next observed snapshot. Declared removal also waits through all locally reserved
access expiries plus skew, deadline and metadata cache margins. Failed signing may conservatively reserve an
unused horizon. This observed guard is bounded by the retained public set; it is not a durable history or proof
of actual external publication. Initial snapshots and safely retired identifiers remain application obligations.

Managed internal issuance checks publication, reserves retention, signs and verifies the pair, then reloads
and checks public overlap before preparing a response or committing issuance. Signing, post-sign retirement and managed proof/status/revocation phases use their actual session authority. Worker/provisional metadata history and admitted lifecycle history are separate; a fast metadata call cannot move a later admitted signing or proof floor. A failed check leaves the unused
code and ledger unchanged. Online status loads checked public keys for the existing uncached atomic status
barrier. Ordinary rotation does not advance the issuer epoch; compromise/restore handling still requires
explicit issuer revocation and reconciliation of uncertain outcomes.

Internal metadata preparation preserves the exact configured issuer and inserts the RFC 8414 well-known
path before its tenant path, removing a terminating slash only for discovery location construction. Trusted
configured endpoints supply authority. Metadata advertises code, S256, none/Basic authentication, configured
refresh/revocation/introspection and nonempty scope unions. It does not advertise OP/ID tokens, dynamic client
registration or custom grants. CIMD support is advertised only when enabled. JWKS contains only checked RSA public n/e, identifiers,
RS256 and verification use. GET/HEAD responses have copied bounded bytes, finite public max-age, must-revalidate
and a representation ETag. Unsupported methods receive an empty no-store 405 with Allow: GET, HEAD. Conditional
request handling remains application-owned; the engine prepares bounded route responses.

The `OAuthAuthorizationServer.Builder.publicMetadataHttpCacheMaxAge(...)` setting supplies the HTTP
`Cache-Control: max-age` value for both public metadata and JWKS responses. It defaults to 60 seconds,
accepts durations from zero through five minutes inclusive, and resets to the default when passed null.
Headers use whole seconds through `Duration.toSeconds()`; publication waits and retention calculations
use the exact configured duration. This setting does not load or refresh keys. The application remains
responsible for publishing the provider's declared key snapshot before its publication wait begins.

## Register and resolve clients

### Register a browser client

```java
OAuthServerClientRegistration client = OAuthServerClientRegistration
    .withClientId("desktop-client")
    .redirectUris(List.of(URI.create("https://client.example/callback")))
    .allowedScopesByResource(Map.of("https://api.example/mcp", Set.of("read", "write")))
    .configurationVersion("v1")
    .build();

OAuthServerClientRepository clients = (clientId, remainingTime) ->
    clientId.equals(client.getClientId()) ? Optional.of(client) : Optional.empty();
```

Public authentication, authorization-code permission, and no refresh permission are the defaults. The configuration version is required; update it when security configuration changes. Registry absence means a genuinely unknown client. A callback that throws, returns null or exceeds its cooperative budget is an infrastructure fault. Revetsec cannot forcibly interrupt an arbitrary synchronous app callback.

Confidential registrations use `OAuthServerClientAuthentication.fromClientSecretVerifier(verifier)` with an application-owned `OAuthClientSecretVerifier`. That selects `client_secret_basic`. The issuer decodes the credentials, rejects duplicate/mixed authentication and clears the temporary secret bytes after the callback. The app performs constant-time verification and must not retain those bytes. Construction never calls the verifier.

### Resource-only registrations

A confidential client that introspects resource tokens can use `authorizationCodePermitted(false)` and an explicit `introspectionResources` allowlist. It requires no fake browser callback. Introspection authority is independent of its authorization-code scopes and always requires confidential authentication.

Setting code permission false clears the builder's browser configuration. A code-disabled registration exposes empty browser redirects/scopes, even if replacements were supplied afterward. Setting permission back to true requires complete browser configuration. Null resets code permission true; it does not restore cleared values.

### Opt-in client metadata configuration and admission

`OAuthClientMetadataPolicy.disabledInstance()` is the default. Enable configuration with
`withAddressResolver(resolver).cache(selectedCache).build()` or
`fromAddressResolverAndCache(resolver, selectedCache)`. Both the resolver and cache backend
must be selected explicitly. Clearing either required builder property with null makes build fail.
Select `InMemoryOAuthClientMetadataCache.fromMaximumEntries(128)` for a bounded, volatile
single-process cache, or supply application-owned shared storage. The required
`OAuthClientMetadataAddressResolver` is trusted infrastructure that returns all numeric answers,
honors the shrinking remaining budget and supports concurrent callers. Building invokes no resolver,
provider, signing, HTTP or thread creation. Clearing the builder resolver with null makes build fail;
there is no system resolver, alias setter or implicit transport fallback.

`allowedOrigins(null)` resets to all eligible public HTTPS origins, an empty set denies all, and a
nonempty set is a complete immutable restriction snapshot. Supply origins with scheme, host and
optional port only, without a slash, path, query, fragment or userinfo. Scheme and host comparison is
case insensitive; port is exact, including absent versus explicit 443. Origins cannot relax the
mandatory public destination rule. At most 4096 origins and 128 KiB aggregate text are accepted.

| Policy setter | Default | Inclusive range |
|---|---:|---|
| maximumDocumentBytes |5120 bytes|1024–5120|
| maximumFreshness |300 seconds|0–1 hour|
| maximumConcurrentFetches |8 fetches|1–64|
| maximumResolvedAddresses |16 addresses|1–64|

Null resets each exact default. Invalid supplied values fail immediately. Integer getters are boxed;
optional absence is explicit. These four policy rows and the selected in-memory cache's separate capacity range are part of the issuer limits surface. The integrated transport and selected backend enforce their respective bounds.

The internal parser uses strict UTF-8 and bounded JSON, including duplicate-member and depth checks.
It requires exact `client_id`, nonempty `client_name`, nonempty safe `redirect_uris`, and an explicit
`token_endpoint_auth_method` of `none`. Unsupported authentication is rejected. The grant list must contain `authorization_code`, which is
also the default when `grant_types` is omitted. Additional grant strings are ignored for capabilities;
they do not enable device, client-credentials, password, implicit or extension grant issuance. JSON
array/member types and duplicate entries remain checked. Refresh permission requires the listed
`refresh_token`, server refresh support and application approval. Only the code response type is
accepted. HTTP IP
loopback redirects to literal `127.0.0.1` or `[::1]` require the explicit
`allowNativeLoopbackRedirects(true)` server opt-in for an omitted, `web` or `native`
`application_type` declaration. Exact localhost redirects require their separate
`allowLocalhostRedirects(true)` opt-in for exact matching, or the separate
`allowLocalhostAnyPortRedirects(true)` option for a port-less `http://localhost` registration. The
new option enables only the port-less profile; fixed-port localhost metadata still requires the
exact option. A document listing IP literals and localhost requires its applicable flags for both
forms. Scheme, host, raw path and query stay exact under either port exception. Code redemption
remains bound to the exact redirect actually admitted. All options default off; false or null disables
the selected option without changing the others. Redirect spellings are preserved, and current ingress capacities still apply.

Recognized optional fields have checked JSON types. The optional application type retains its checked `web`/`native` values and conservative fingerprint binding; it does not enable a redirect policy. Scope, software statements and public key
descriptions confer no application authorization, trusted scopes or authentication authority.
References in metadata and unknown ordinary extensions are never fetched. Symmetric key material,
client secrets and private JWK members are rejected recursively, including nested extensions. Public
JWK descriptions receive structural/type checks only; they are not used to verify client credentials.
The security fingerprint covers exact client ID, authentication, redirect set, declared native flag and refresh
permission using structured facts. Display names, redirect order, ignored grant strings and ignored extensions do not change it.
Display text must be escaped by the application, and URL possession does not establish benevolent software.

CIMD document validation, pinned HTTPS retrieval, registry-first selection and fresh retrieval before eligible credential transitions are integrated into `OAuthAuthorizationServer`. Parsing or reconstructing a cache carrier is not proof of a current fetch. Metadata advertises CIMD only when the configured policy is enabled; exact registered clients always take precedence. Each eligible code/refresh attempt requires its own successful HTTP 200 and the final grant/fingerprint/store checks described below.

### Client-metadata cache storage

`OAuthClientMetadataPolicy.Builder.cache(...)` accepts application-supplied storage, including
a shared backend. Omitting it or passing null makes an enabled policy fail to build; there is
no implicit backend or local fallback. Building a policy never calls a provider or starts a thread.
Reuse a selected backend explicitly when engines should share storage. An in-memory backend
still shares only within its JVM. Its `fromMaximumEntries(...)` factory accepts 1–4096 entries;
`fromDefaults()` selects 128. Applications bound their custom backend's capacity.

`OAuthClientMetadataCache` reads opaque carriers and performs atomic exact-version replacement
or removal. A missing expected version requires absence. A comparison conflict changes nothing.
Failures are distinct from misses and conflicts and use the fixed-diagnostic
`OAuthClientMetadataCacheException`. Providers honor the shrinking positive operation budget
and interruption; application code remains cooperative. A failed optional-cache write may
have applied, and eviction/expiry removes historical version ordering. This interface provides
no credential consumption, distributed lock, authoritative-store fallback or loader callback.

Keys and entries reconstructed from storage are syntax-bounded data. Core must authenticate their sealed form, namespace/provenance and current policy/time before metadata use. Stored expiry is a cleanup hint, not trusted freshness; the selected in-memory backend does not interpret it. A cache hit never supplies the fresh HTTP 200 required at code exchange or refresh. Cache storage is optional reuse, not an authoritative store, durable ordering or a deployment qualification.

The explicitly selected `InMemoryOAuthClientMetadataCache` serializes access to a private bounded map, evicts before insertion and drains each mutation. Timed interruptible outer locking keeps retained entries within the configured capacity; it exposes no map, listener, loader or worker thread. This is a volatile JVM-local backend, not an implicit default or a distributed cache.


#### Authenticated optional client metadata reuse

The internal metadata coordinator selects the configured cache once, authenticates a distinct cache envelope, and re-admits the stored document under its current policy. Stable keys bind the exact issuer/configuration/client identity, shared freshness policy and fixed anonymous request profile; compatible nodes need the same sealing keys and trustworthy clocks. Cache carrier reconstruction alone grants no metadata or credential authority. Stored UTC fetch and expiry facts, key, version and document bytes are authenticated.

Clock sampling validates its order against the previously published observation. A concurrent publication causes a fresh sample, rather than a rollback classification. No clock, cache or transport callback runs under a sampling lock. The earliest receipt sample remains the freshness anchor when sampling repeats; a newer checked time cannot extend expiry or return an expired snapshot. Once a sample reports rollback, the operation skips further reuse and cache publication, even if time recovers before a fallback fetch. A rollback first noticed after an optional write blocks subsequent reuse while time remains behind; it does not undo an applied cache write. Sampling retries retain the original deadline and interruption checks. This local optional-cache detector does not change authoritative issuer state, coordinate clocks across nodes or detect an unobserved rollback after restart. Encryption cannot prevent replay of a still-fresh authentic cache record.

CIMD reuse selects shared HTTP freshness semantics even for a single-process backend: valid `s-maxage` overrides `max-age` and `Expires`. Named `Vary` fields match because the pinned request fixes every header value or absence; its method/header template and exact target URI are bound into cache identity. `Vary: *` and malformed variation lists cannot match. See [RFC 9111 §4.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1) and [§5.2.2.10](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.10).

Reuse still requires explicit finite freshness. HTTP Age, apparent age from Date and a conservative transport-delay bound are subtracted before applying the local maximum and rounding expiry down to a whole second. Missing/ambiguous freshness, malformed Age/Date/Expires, conflicting age directives, no-store/no-cache and private remain non-reusable. There is no heuristic freshness, stale fallback or conditional revalidation. This CIMD profile does not change JWKS or discovery lifetime rules.

The localhost any-port option is bound into cache configuration when enabled. Disabled, absent and
null retain the earlier namespace byte-for-byte. Enabled/disabled entries cannot be exchanged or
rekeyed across contexts. The envelope format and authoritative records are unchanged; no bulk
migration is required. Existing admitted documents retain their security fingerprints, and stored
codes retain their actual authorization redirect. These matching options govern new authorization
admission; applications use client configuration versions or grant revocation for existing authority.

The corrected policy uses a new configuration namespace within the existing cache-key/envelope format. Earlier-policy envelopes are cold misses, including rewrapped carriers; no old lifetime is trusted without a new fetch. Old and new nodes cannot populate one another's namespace. Optional cache entries may age out or be evicted normally; no authoritative store migration, bulk deletion or backend API change is needed. A future change to the fixed request template changes its namespace binding as well.

Optional-cache corruption, absence or failure can lead to a new fetch within the original shrinking deadline. Interrupt or exhausted budget aborts. A valid fetch may skip storage if its envelope does not fit the configured sealer cap; the cap is never raised. Observed-version writes are conditional, with no blind retry after conflict or uncertain write. An authenticated newer fetch timestamp also prevents an older-clock replacement. Eviction removes history, so this is not durable ordering or distributed fencing.

Only HTTP 200 can supply a metadata document. Metadata responses with 401, 403, 404 or 410 reject the client as `INVALID_CLIENT`; the public issuer returns its fixed local 400 `invalid_client` response, without a redirect or an authentication challenge from the metadata server. Other non-200 statuses, including 408, 429 and 5xx, remain `CLIENT_METADATA_UNAVAILABLE`, whose failure response is fixed 503 `server_error`. Redirect refusal and transport, TLS, deadline or interruption failures also remain unavailable. These are local CIMD classifications, not forwarded origin statuses. Remote response bodies, Location, WWW-Authenticate and Retry-After values never enter the issuer error response or cause an authentication retry, redirect, sleep or automatic retry. Error responses are not cached and cannot satisfy a required fresh fetch. A failed fresh fetch neither falls back to nor replaces an existing optional success entry; a separately eligible fresh cache entry can still serve later reusable lookups until its original expiry.

Fetches run synchronously on caller threads through the pinned HTTPS driver, outside authoritative transactions. A per-coordinator permit bound limits active fetches. Callers wait interruptibly for capacity within the original shrinking operation deadline; neither waiting for the authorization sublimit nor waiting for total capacity renews that budget. No background executor or single-flight sharing is introduced. When the configured bound is at least two, authorization requests cannot occupy the last credential-transition slot. Applications must bound incoming concurrent requests and their waiting caller threads. The bypass path owns its new successful 200 and reads no reusable cache record. Registry-first selection and code/refresh before-consumption fingerprint checks are integrated into the public engine. These internal fetch helpers expose no transferable current-fetch capability.

<a id="pinned-transport-admission-helpers"></a>

### Pinned HTTPS transport contract

The CIMD transport uses copied numeric-address admission and bounded HTTP/1.1 response
parsing. Address admission inspects every supplied answer, applies the configured answer cap before
deduplication, and returns immutable copied numeric values without retaining resolver hostnames or
performing hostname/reverse lookup. Private, local, metadata, special-purpose, scoped and represented
mapped/translated/known NAT64 destinations are rejected. Numeric bytes cannot reveal unknown
network-specific translation, and an already normalized IPv4 answer cannot reveal a lost IPv6 spelling;
applications still supply trusted resolver/network controls.

Response parsing bounds lines, header bytes/fields, informational responses, complete framing bytes
and configured document bytes. It requires strict CRLF and unambiguous content length or chunked
framing. A200 document requires supported JSON media and identity content encoding. Redirects,
including304, reject; other final statuses supply no admitted document body. Informational fields
are discarded. Repeated cache fields are preserved for freshness policy, without merging
away ambiguity. Chunk extensions are validated, and nonempty trailers are rejected. Declared,
chunked and close-delimited documents remain bounded; premature or malformed endings fail.

The address and HTTP helpers remain pure. The pinned driver connects with JDK
SocketChannel/Selector and SSLEngine to a copied numeric answer, verifies the connected peer and
port, and keeps the original hostname for HTTPS certificate checks, SNI and HTTP Host. Each fetch
resolves once and admits every answer before selecting the first; a later fetch resolves again.
There is no proxy, stock HttpClient fallback, redirect, connection retry, cookie or credential.
TLS 1.2/1.3 and HTTP/1.1 are supported. A fresh context per exchange prevents connection/session reuse.
Three fixed 64KiB TLS buffers, a 512KiB aggregate wire bound including cleanup writes, request/header/
document bounds and the shrinking operation/request deadline limit work. Partial writes and reads
remain nonblocking. Raw TCP EOF is an error; only authenticated TLS close_notify supplies clean EOF.
Cleanup closes the socket and selector on every outcome, with a bounded best-effort TLS close alert.

The private context uses local trust material and explicit revocation-disabled PKIX parameters.
It keeps the first supplied certificate as the leaf and constructs paths from the remaining supplied
certificates and configured local trust anchors. Shuffled intermediates, cross-signed roots and
alternate issuer certificates can be used without retrieving missing certificates. The entire input
is bounded to ten certificates of at most 32KiB each; at most 128 candidate prefixes are checked,
and exhausting that allowance fails closed. Each path must pass local PKIX validation before a
complete anchored chain reaches the JDK extended trust manager for normal TLS algorithm,
end-entity and hostname checks. A rejected alternative may be backtracked within the same bound. This
specialized path requires the inspected java.base SunJSSE/SUN providers and the standard extended
trust-manager implementation; unsupported providers fail closed. No application TLS-context bypass
or process-global security-property change is exposed. JDK implementation changes require continued
qualification. Provider, resolver and local trust-store work are trusted cooperative callbacks;
Revetsec cannot forcibly preempt blocking work inside them. Revocation is intentionally disabled
for this anonymous metadata fetch so certificate-related AIA/OCSP/CRL network retrieval cannot
escape the selected numeric destination. Applications control their trusted runtime/network setup.

The application cache-storage interface, explicitly selected bounded in-memory implementation and builder injection are implemented. Revetsec owns document validation, freshness and security fingerprints for every backend. Code redemption and refresh require a new successful 200 for that operation before consuming state; shared cached data cannot satisfy the fresh-fetch requirement. CIMD remains opt-in, and registered clients take precedence without metadata fallback.

<a id="internal-registry-and-credential-binding"></a>

### Client binding before credential transitions

Exact registered clients take precedence, including URL-shaped IDs. A registry fault, null result or mismatched identity is an infrastructure failure and never permits metadata fallback. Basic authentication and introspection remain registry-only. Unknown public URL clients use CIMD only when the engine selects an enabled metadata fetcher.

CIMD's scope/software/key declarations confer no authority. Configured server resources/scopes form the request ceiling; explicit application approval is still necessary. Consent and grants retain an authenticated security fingerprint with a distinct CIMD source discriminator, including exact identity, authentication, redirects, declared native flag and refresh semantics. Display-only changes do not invalidate it. Switching between registration and metadata requires new authorization. Code and refresh descendants resolve their client binding through the authenticated grant.

Every eligible code/refresh attempt, including a retry after a store conflict and a bound used-credential replay against an active grant, performs its own successful 200 via the pinned transport before final authoritative state reads/consumption or replay invalidation. It bypasses all cache reads and writes. A prior snapshot, another operation's200 or shared cache cannot replace this fetch. Registry, fetch, store, policy and signing share the original shrinking deadline. Failure, invalid metadata or fingerprint mismatch releases no credentials and leaves an unused code/current refresh unconsumed; valid fully bound reuse retains strict whole-grant invalidation. No callback/network/signing runs inside a backend commit.

Before a credential transition can spend CIMD fetch capacity, local reads must identify a retained credential and its grant with matching owner, resource and current issuer/subject fences. Code requests also match PKCE and any supplied redirect. An unused code must remain pending and unexpired; an unused refresh must remain current and unexpired. A bound used credential remains eligible while fresh authentication could still authorize replay-triggered revocation of its active grant; once that grant is revoked, it cannot drive repeated fetches. A refresh pre-read can straddle a concurrent rotation: head contradictions require an unchanged-read-set barrier before they are reported as corruption; a changed observation retries within the same attempt/deadline bound. These pre-reads admit only external work. Fresh metadata fingerprint checks and complete final store reads remain mandatory, including after conflicts and concurrent expiry or revocation.

Unregistered public URL clients use the same local gate on revocation. Unknown, malformed, wrong-owner, wrong-resource, fenced or already-revoked credentials do not fetch metadata; they retain the ordinary empty 200 response after applicable authentication and a confirmed store barrier where authoritative absence/unchanged state is involved. Registry and Basic authentication retain precedence and their normal failures. Retained expired access/refresh credentials may still fetch fresh metadata to revoke an active grant, preserving the revocation-only retention contract. No pre-read releases a credential, changes a grant or supplies a transferable authentication proof.

## Authorize a browser

The application owns login, session fixation defenses, browser binding, consent UI and CSRF checks. Keep the issuer continuation handle in protected server-side session state; never take a submitted subject or scope list as proof of authentication or approval. Establish a never-used subject through the trusted account lifecycle before approving a grant for it; do not auto-create missing subject fences while processing authorization traffic.

Register the exact configured routes and preserve materialized body, raw query and header occurrences. Call `beginAuthorizationResult` for GET authorization, render its restricted interaction after app authentication, and submit the trusted decision through `completeAuthorizationResult` with app session and CSRF protection. `resumeAuthorizationResult` rechecks a continuation before rendering. An interaction does not authenticate a user. Initial approval rechecks grant policy before committing, keeps the app subject and only narrows scopes/refresh. Each conflict resolves current client facts and runs policy again; denial consumes the interaction without a credential.

Use one app-generated canonical 32-byte random browser binding independent of OAuth state. Resume the issuer interaction before rendering a later consent view, escape untrusted client display text, and complete with a server-derived decision. Emit a credential-bearing response only from the returned admitted completion variant. Unknown or confirmed-but-not-admitted mutations require reconciliation, even if a local session still holds an interaction handle.

### Supply an application decision

```java
OAuthAuthorizationDecision decision = OAuthAuthorizationDecision
    .withSubject("issuer-local-user-id")
    .authorizedScopesByResource(Map.of("https://api.example/mcp", Set.of("read")))
    .build();
```

The app authenticates the subject on the server and protects the session and consent submission. The issuer checks that the decision retains the subject and is a subset of the interaction, current client and server configuration. `deniedInstance()` expresses denial with no subject or resource map. An explicit one-resource empty scope set is representable for a policy denial; it never authorizes a zero-scope credential. Refresh defaults false and also requires server/client approval.

`OAuthGrantPolicy` rechecks permissions at approval, code exchange and refresh. Its `OAuthGrantContext` has no public constructor, factory or builder. The issuer supplies checked facts; the application may return denial or a decision that keeps the subject and narrows authority. `getGrantValue()` explicitly releases a sensitive grant-management handle to trusted application code; never log it.

<a id="internal-ingress-implementation"></a>

### Preserve and bound HTTP inputs

The internal ingress helpers serve the public `OAuthAuthorizationServer` entry points. The consent ledger prepares interactions and unused codes; code redemption and refresh rotation issue credentials only after the authoritative store commits.

Raw query/form parsing retains duplicate occurrences until validation. Recognized security parameters cannot repeat, even with identical values or percent-encoded names. Unknown ordinary extensions are ignored after strict decoding and consume the same field and input limits. Malformed escapes, malformed UTF-8 and unpaired surrogates reject the whole input. Bounds apply before copying/decoding; the fixed structure caps are 128 query/form fields across both channels and 64 header occurrences. Header sizes include serialized names, separators and CRLF bytes. The trusted HTTP edge must preserve every occurrence and enforce allocation, framing, routing and TLS before calling the engine.

For authorization requests, nonempty `state` is restricted to ASCII U+0020–U+007E before client lookup or store access; its exact decoded value is preserved, with no normalization. Existing absent/empty handling is unchanged. An individually valid set of fields can still exceed the configured sealed-record capacity. New interactions are refused with a fixed local `400 invalid_request` before mutation when their pending or completed representation cannot fit, including full nanosecond floor precision. This admission bound performs no sealing and does not reclassify authenticated stored-row decode failures. Previously stored Unicode state remains readable; no record format, address or migration changes are introduced.

Authorization admission accepts GET with an empty body. Form endpoints accept POST with one `application/x-www-form-urlencoded` Content-Type and UTF-8 or absent charset; content encoding and query security parameters are rejected. Authorization and Content-Type duplicates include differently cased header names. Basic credentials use percent-decoded exact client IDs and UTF-8 secret bytes. This profile rejects body client IDs combined with Basic, secret-post, assertions and public-client fallback. A false verifier result is a client rejection; a null result, nonfatal callback failure, interruption or exhausted cooperative deadline is an infrastructure fault. Temporary decoded arrays are cleared on every exit, including a fatal VM error; decoded secrets are never materialized as immutable Strings.

Registered redirect matching preserves every component's spelling. HTTPS redirects match exactly. Explicit native IP-loopback policy can vary only the port of literal `127.0.0.1` or `[::1]`; the exact localhost policy matches its configured port. The separate `allowLocalhostAnyPortRedirects(true)`
option permits port variation only for registered port-less `http://localhost` redirects. Its scheme, host,
raw path and query stay exact, including percent-encoding spelling. A supplied port must be valid;
an omitted request port is also representable. Fixed-port localhost registrations require the exact
localhost option and remain fixed. These policies default off in the server builder. Resources compare as exact identifiers and are never fetched. Omitted scope selects the client/server intersection; explicit scope must fit that intersection, and empty authority is rejected. S256 challenges require canonical 43-character Base64url; code verifiers require 43–128 ASCII unreserved characters. These checks admit requests, not grants: policy decisions, replay protection, grant/resource binding and credential publication remain engine responsibilities.

The observer's `didEnableLocalhostAnyPortRedirects()` hook runs once after successful construction
when that option is enabled. The separate `didUseLocalhostAnyPortRedirects()` hook runs once per
authorization operation that needs its matching relaxation, before store work, including a later
admission rejection. An exact match already admitted by the exact-localhost option does not emit
use. Hooks carry no request data and use the usual caller-thread failure containment; interruption
remains visible and fatal VM errors propagate. They do not replace the endpoint event pair.

The server builder applies the approved ingress ranges together with the remaining issuer limits. The limits registry remains internal.

<a id="internal-consent-ledger-and-pending-grants"></a>

### Consent, one-use codes and grant binding

The internal ledger creates independent random 32-byte interaction handles and codes. Storage addresses hash
those credentials; the application supplies a separate canonical 32-byte random browser binding. Its digest
is compared in constant time. Neither OAuth state nor an application subject substitutes for this binding.
An immutable consent record binds the exact selected redirect, resource, S256 challenge, requested scopes,
optional state, current issuer incarnation/epoch and a digest of the client security configuration. Display text
is excluded from that digest; the application must change configurationVersion when secret-verifier or key
semantics change. Resolution of the current client, application login/session fixation/CSRF protection and
policy callbacks remain responsibilities of the engine and application edge.

Resume uses an authoritative condition-only barrier. Completion re-reads consent and current
fences, checks the browser/client configuration and the application resource/scope subset against the reviewed
request and current server authority. An allowed nonempty decision requires an established subject fence.
It atomically completes the interaction and inserts an unused code and pending grant with their authority-derived floors. The internal code return requires a known COMMITTED receipt and final release admission. A denial, including an explicit empty
scope decision, completes consent without creating a code or grant. Duplicate or racing completion cannot
re-emit a code. UNKNOWN yields no handle, review or code and is never automatically retried.

Code and grant records bind issuer and subject incarnation **and** epoch. They use exact bounded schemas;
authentication of the common envelope alone cannot authorize a transition. Pending grant retention currently
ends at unused code expiry. The internal first-redemption transition atomically pins the maximum access lifetime and extend
code/grant retention to H, alongside issued-jti and optional refresh facts. The checked calculator includes
family absolute expiry (or first no-refresh token expiry), the pinned maximum access lifetime, skew, total
deadline and public metadata HTTP cache max-age. Physical retention rounds up to whole seconds; credential validity
rounds down. Overflow and an attempted increase of a pinned lifetime reject. The calculator alone confers no issuance authority. The internal redemption transition below consumes
pending grants; the integrated refresh, key lifecycle and online-status paths enforce the descendant contracts below.

Operation expiry is checked before and after a cooperative backend callback. A callback returning after code
or consent expiry cannot publish success, even when the backend committed. Tests use deterministic
interleavings over the existing single-process atomic fixture. They do not prove a durable backend, process
recovery, failover or actual parallel execution.

## Issue and refresh tokens

`tokenResult` handles code exchange and strict refresh rotation. `revokeResult` invalidates the whole credential-owning grant for registered or admitted dynamic clients; dynamic owner authentication requires a fresh pinned 200 fetch. `introspectionResult` accepts registered confidential resource-only callers; an optional resource selector must belong to the server registry and caller allowlist. Omitting it is supported only with a sole configured server resource. Metadata/JWKS advertise the configured profile, including CIMD only when enabled. Request Host/Forwarded values provide no authority.

Register the exact configured routes before passing the original materialized method, query, body and all header occurrences to the issuer. Transport helpers do not supply application login, authorization or session recovery. The host still owns body/query/header acquisition limits, request framing, TLS and route selection.

| Route/work | Public operation | Host action |
| --- | --- | --- |
| Browser authorization GET | `beginAuthorizationResult`, then `resumeAuthorizationResult` / `completeAuthorizationResult` | Protect login/consent and the independent browser binding; do not expose a continuation as identity. |
| Token POST | `tokenResult` | Emit only the returned success/rejection response; do not replay credential work after uncertain or withheld commitment. |
| Optional revocation POST | `revokeResult` | Preserve uniform unknown-token response semantics and distinguish infrastructure failure. |
| Optional introspection POST | `introspectionResult` | Use registered confidential resource authorization and the configured resource selector. |
| Public metadata/JWKS GET or HEAD | `metadataResponse` / `jwksResponse` | Publish the configured issuer profile, preserve HEAD representation headers, and implement conditional HTTP handling if needed. |
| Resource access | `validateAccessTokenResult` | Authorize the application's resource only from the successful `VerifiedAccessToken`; raw parsing or a signature alone is insufficient. |

Normal credential/proof output needs a known authoritative commitment or barrier **and final release admission**, including the current root/recovery, time, health and original budget checks. This is distinct from raw initialization/reseal receipts, which acknowledge factual effects and do not open serving admission.

<a id="internal-code-exchange-and-first-issuance"></a>

### Exchange a one-use code

The internal code-exchange transition reauthenticates the current registered client on each bounded attempt.
It reloads the authenticated code and owning grant, binds their exact cross-links and issuer/subject
incarnation plus epoch, and checks S256, exact resource, client security fingerprint and selected redirect
when supplied. Wrong client, verifier, resource, redirect or random code causes no mutation. An expired
unused code cannot issue. Continuing application policy runs outside storage transactions with the original
remaining budget. It can narrow scopes and refresh permission. Null, callback exceptions and exhausted budgets
are unavailable service failures; a returned decision that changes identity or widens authority is an application
configuration failure. Neither consumes the code. Denial or removed server authority atomically terminates pending state.

Before consumption, the transition prepares an RS256 at+jwt with fixed issuer, subject, single audience,
client_id, iat, exp, random jti and sorted scope. It retains the exact bounded JSON response and serialized
no-store headers. Signing, record preparation or response size failure occurs before commit. No caller claim
map is accepted. The public engine applies publication and rotation checks to application-owned key snapshots; the internal encoder alone does not establish durable key lifecycle authority.

One complete transaction consumes code, activates the grant with its maximum access lifetime and H,
inserts the issued-jti record and optional initial refresh record with entity floors while preserving the issuer minimum. Optional refresh
requires server, client, original approval and continuing policy permission. Used code and grant retain together
through at least H and the original code expiry; access rows retain through their own expiry plus margins.
Only a known committed receipt followed by final release admission returns the prepared bytes. CONFLICT discards them and reloads under the original deadline;
UNKNOWN releases nothing and never triggers hidden retransmission. Cooperative expiry/deadline checks
also discard late output when writes may already have occurred.

A fully bound consumed-code replay remains recognizable after ordinary code expiry until retained state
expires. Its transaction revokes the entire grant, including its initial refresh token and access descendants.
A racing redemption loser follows that same path; it cannot release its discarded response. Subsequent
required online status checks the current grant and complete read-set barrier. The public engine composes this status boundary with JWT access-token validation, uses the typed code/refresh wire credentials and prepares complete Location/header bytes before consent commit.

<a id="internal-strict-refresh-rotation"></a>

### Rotate refresh credentials

Each attempt freshly authenticates a registered client and checks the grant's exact owner, security
fingerprint and resource before any replay invalidation. Issuer and subject incarnations and epochs must
still match. An unused active refresh must also precede its idle and family absolute expiry. The continuing
policy receives the original grant scopes under the remaining operation budget, outside the transaction.
Denial, revoked refresh permission or reduction of that original authority terminates the grant. A returned
decision that changes identity or widens authority is an application configuration failure; null, callback
exceptions and exhausted budgets are unavailable service failures. Those failures do not consume the refresh.

A request may downscope its access token while the replacement refresh retains the original grant scopes.
Future refresh can request those original scopes again. Rotation preserves the original absolute expiry,
maximum access lifetime and fixed retention horizon H. A later configuration cannot silently enlarge them.
The final access token may outlive family expiry, and required online status checks its own expiry plus skew.

Before commit, the helper prepares independent random replacement refresh and access-jti identifiers,
signed fixed RS256 at+jwt, sealed records and bounded immutable response bytes. One complete CAS marks
the old refresh USED, replaces the grant head and creates new refresh and issuance rows with authority-derived floors. Known commitment plus final release admission releases those bytes. CONFLICT discards output and reloads under the
same deadline; UNKNOWN releases nothing and permits no guessed rollback or automatic credential retry.

Fully bound used-refresh replay remains recognizable through H, including after its original idle or family
expiry. It atomically revokes the whole grant and every access/refresh descendant. A racing rotation loser
reloads USED and revokes the winner. There is no retry grace or re-emission of a prior response. Used rows,
code and grant retain through H; access rows retain through their own expiry plus the configured margins.

## Operate the issuer

`validateAccessTokenResult` uses the JWT access-token validator with a fresh static local public-key snapshot and the original operation Deadline, followed by the uncached exact-profile issuance/grant/subject/issuer check and atomic complete read-set barrier. Only committed admission followed by the final release check releases `VerifiedAccessToken`. No raw BearerToken accessor or proof factory was added to the public API. All callbacks use the shrinking caller budget; trusted synchronous callbacks must honor it.

<a id="internal-online-token-status-admission"></a>

### Validate online access-token status

The internal validator checks a bounded RS256 at+jwt against an explicit local public-key snapshot, exact
issuer and single resource audience and required fixed claims before accessing storage. Token-time admission and restricted access-token proof creation use the healthy authority observed by the actual session; signature/profile recognition creates no proof or temporal-history writes. It then binds the issued-jti record to the exact subject, client, resource, canonical scopes, issuance time and
expiry. The active grant must share the same issuer/subject incarnations and epochs, contain the issued
scopes and cover the access token's pinned lifetime and retention horizon. Grant family expiry does not
prematurely invalidate an access token issued near that expiry. Token expiry plus configured skew remains
the admission boundary and is checked around the backend commit.

A successful admission requires one COMMITTED condition-only transaction containing every observed
issuer fence, issued-jti, grant and subject-fence version. Missing issuance/grant returns an inactive verdict
only after an authoritative absence barrier. Missing permanent fences, contradictory authenticated records,
backend faults and unknown barrier acknowledgements remain infrastructure failures. A read barrier creates no uncertain mutation. CONFLICT reloads the entire read set
under the original bounded deadline. No positive token-status cache is used.

The barrier is the admission point: revocation racing before it prevents admission after reload; work
admitted before revocation may finish, while subsequent validation rejects. The helper releases only immutable
checked claims internally and retains no received credential. The public engine releases a restricted `VerifiedAccessToken` only after this admission; key publication and retirement follow the [application lifecycle declarations](#issuer-signing-keys-and-public-metadata).
The tests use deterministic single-process store interleavings; durable multi-node, crash and failover
contracts require separate evidence.

<a id="internal-grant-revocation-and-resource-introspection"></a>

### Revoke grants and introspect resource tokens

Fresh registered client authentication precedes credential lookup and every conflict retry. Access and
refresh credentials revoke their whole owning grant, including all access and refresh descendants.
Exact owner, client security fingerprint, resource, persisted issuance and current issuer/subject fences
must match before mutation. An optional revocation resource selector must match the grant; token hints
never select authority. Unknown, malformed, wrong-owner and already-revoked credentials receive identical
empty 200 response bytes after applicable authentication. Authoritative absence and unchanged state
require a complete condition-only barrier. Known grant invalidation uses one exact timed CAS without changing the issuer minimum.
Backend faults, corruption, exhausted budgets and uncertain requested mutations cannot produce success; pure barrier uncertainty is unavailable unless an earlier requested commitment requires reconciliation.

Retained expired access credentials can revoke a still-live refresh grant. This uses an internal signature
recognition profile without time admission, then exact persisted issuance and ownership checks. It never
admits a token to a resource or introspection: those paths still enforce ordinary expiry and skew. Expired
refresh rows remain usable for revocation while retained through H, without authorizing token issuance.
The trusted app grant-reference operation is monotonic and can safely be repeated after reconciliation;
it also terminates a pending grant. Subject and issuer epoch operations retain their separate non-idempotent
UNKNOWN reconciliation rules.

Introspection authenticates a registered confidential resource-only client with an exact resource allowlist.
The selected resource is trusted endpoint configuration; Host and token claims cannot select its authority.
Only active access JWTs release checked claims, active:true and token_type:Bearer after the full four-row
COMMITTED admission barrier and final release admission. Exact bounded body/header bytes are prepared before that barrier. Unknown,
expired, revoked, wrong-resource or refresh credentials return only {"active":false}. Storage failure remains
a service failure, never inactive. Every operation checks current status with no positive cache. Responses
are immutable copied bytes with no-store/no-cache headers and redacted diagnostics.

<a id="prepared-response-and-credential-wire-contracts"></a>

### Emit prepared HTTP responses

`OAuthServerResponse` is immutable and restricted to server preparation. Its public methods are
`getStatusCode()`, `getHeaders()`, `getLocationWithCredentials()` and `toHttpBodyWithCredentials()`.
The header map and its lists are immutable and exclude `Location`. The explicit Location accessor
and defensive body copy are privileged HTTP emission: token/introspection bodies may contain
credentials or personal data. Identity equality and a fixed redacted `toString()` prevent accidental
credential comparison or diagnostic serialization. There is no public factory or builder.

Internal token, status and public metadata helpers retain this response. Private responses include
`Cache-Control: no-store`, `Pragma: no-cache` and `Referrer-Policy: no-referrer`. Public metadata
has its existing finite freshness/revalidation policy; HEAD retains the representation length while
emitting no body. Response-body limits are separate from the aggregate serialized header limit,
which includes the status line, Location, all field names/values and every CRLF.

The response-producing consent path authenticates the saved interaction and checks its browser
and current client fingerprint before preparing a 303. Approval emits a typed code; denial or an
explicit empty scope decision emits only `access_denied`. The original query spelling is retained,
with one strict UTF-8/form encoding of state and issuer. Absent and empty state remain distinct.
Original non-ASCII URI characters receive URI ASCII encoding for the HTTP Location field; existing
ASCII query percent spelling is preserved. Response overflow occurs before atomic completion and
leaves consent pending. A known COMMITTED receipt and final release admission are required before returning the prepared response;
a conflict prepares again and an unknown outcome releases no response. Subsequent emission never
recomputes code, timestamps or contents.

Authorization codes use `rsc1_` and refresh tokens use `rsr1_`, followed by 43 canonical unpadded
base64url characters encoding 32 random bytes. Their complete typed wire spelling is hashed into
ledger identifiers. Wrong kinds, bare nonce handles, padding and noncanonical trailing bits reject
before authoritative code/refresh reads. Revocation retains its authenticated uniform-success
handling for unknown/malformed/wrong-kind credentials; hints do not override grammar. These are
internal issuance contracts, with no public credential-construction API or additional store schema.

The issuer builder exposes 22 numeric settings; the CIMD policy and selected cache add their own bounds. See the [builder source contracts](../src/main/java/com/revetsec/oauth/server/OAuthAuthorizationServer.java) for defaults, inclusive intervals and null resets. Build checks request timeout within total deadline, code lifetime within interaction lifetime, refresh-enabled access/idle/absolute ordering, skew within half the access lifetime, copied resource/scope limits and sealed-record capacity within the configured sealer cap. Retention arithmetic keeps fractional-duration precision. Construction does not initialize storage or qualify a deployment.

### Restricted outcomes and failure boundary

The public issuer result types are sealed and cannot be constructed by applications. Authorization yields a restricted interaction, completed response, denial response or fixed rejection; token, revocation and introspection yield success or fixed rejection. A restricted interaction exposes its secret continuation handle, checked client ID, optional untrusted display name, exact selected redirect, requested resource/scopes and expiry. Escape display text and keep the handle in the protected app session. It is not user authentication, and a previous UI view is never completion authority.

Issuer access-token success releases the existing `VerifiedAccessToken` only after the public engine composes JWT access-token validation and an authoritative uncached issuer status barrier. Its rejection carries only fixed issuer/M5/JOSE reasons and a safe BearerError. No public proof factory is exposed.

OAuthServerException directly extends RevetsecException and is sealed to validation, store, transport, configuration and signing leaves. Construction is restricted. Messages, diagnostics and suppression never retain external callback failures or their data. COMMIT_OUTCOME_UNKNOWN and COMMIT_CONFIRMED_NOT_ADMITTED are distinct nontransient store infrastructure exceptions; reconcile either rather than blindly retransmit credential or subject-revocation work. Store corruption and invalid configuration remain configuration failures. Generic SPI unavailability is nontransient because its fixed internal classification cannot prove the cause. A future operation may classify a known timeout, I/O failure or request held back as transient; this never overrides UNKNOWN or interruption. Cooperative interruption preserves the interrupt flag and prevents transient classification.

Generic admission dependency/budget failures use `OAuthServerTransportException` with `SERVICE_UNAVAILABLE`, a nontransient reason. This includes client-repository, client-secret-verifier and grant-policy throws or null results, including failures while constructing a callback result. It does not imply that the authoritative store failed. CIMD transport failures retain the specific `CLIENT_METADATA_UNAVAILABLE` reason, store failures retain their store reasons and signing failures retain `SIGNING_FAILED`. A returned trusted consent or continuing-policy decision that violates the checked resource/scope/subject/refresh constraints uses `CONFIGURATION_INVALID`; it is not a client `invalid_request`. Both classes produce the same fixed local 503 `server_error` through `responseForFailure`, without consuming the pending credential. Known/uncertain earlier commit effects still take precedence over a later failure classification. Generic failures do not authorize automatic retries or metadata fallback.

The local HTTP boundary emits fixed JSON errors with no Location, no reflected error description, no-store/no-cache/no-referrer and bounded bodies/headers. Infrastructure fallback is always 503 server_error. Invalid and unknown clients share invalid_client; Basic authentication failure uses401 with a fixed Basic challenge, while public-client rejection uses400. Introspection caller failure uses401. Invalid/replayed grants and PKCE mismatch share invalid_grant. Unsupported methods use405 and endpoint-specific GET/POST Allow. Consent denial redirects still require the existing authenticated, prepared-before-commit path.

OAuthServerObserver has synchronous caller-thread hooks and fixed operation kinds, including trusted grant/subject/issuer invalidation and store resealing. The internal dispatcher emits one will and one terminal hook during ordinary completion, contains hook failures through the existing dispatcher, restores interruption, and propagates VirtualMachineError. Events carry no request, URL, client, subject, grant, credential, key identifier or claims. The engine dispatches these hooks outside locks and store transactions. Terminal hooks describe the processing checkpoint before their callback runs. A final pure release guard runs after the terminal callback; callback delay can still withhold a service return, without a second terminal event. Raw receipts preserve effect truth despite such delay.

A fixed validation exception exposed by a trusted management method also completes its rejection event, with a null HTTP status, before the exception escapes. This includes a foreign-namespace maintenance key. Caller programming preconditions checked before the will event retain their ordinary exceptions and emit no event. Nonfatal terminal-hook faults are contained and interruption is preserved; fatal VM errors retain their propagation contract.

Metadata and JWKS publication serialize trusted configuration. A representation exceeding the configured response capacity is `CONFIGURATION_INVALID`, with one failure event and the fixed local 503 `server_error` translation, rather than a malformed-client rejection. HEAD must admit the full representation within that same cap even though its successful body is empty. Successful GET/HEAD cache headers, ETag and representation length remain paired. Unsupported methods retain the fixed 405 response without fetching keys. Provider and budget failures retain their existing unavailable boundary; publication is neither truncated nor given a larger cap automatically.

Do not log request credentials, sealed state, continuation handles, key identifiers or explicit credential-bearing response accessors. Preserve result distinctions and use a rejecting default when matching extensible outcomes. Success in an observer event is not a delivery receipt; event callbacks can affect whether final service output remains admissible.

Expected remote errors are fixed result variants. Infrastructure/corruption/signing/UNKNOWN stays typed and redacted; `responseForFailure` emits fixed 503 JSON with no Location. Observer hooks have fixed operation kinds, no credentials or identities, and one terminal event during ordinary completion. InteractionRequired has logical HTTP200; management/validation status is absent. Infrastructure faults never become invalid credentials or implicit retry approval.

## Manage storage and recovery

<a id="explicit-deployment-and-maintenance"></a>

### Initialize and maintain an admitted namespace

Before traffic, `initializeFreshIssuer()` is an operator assertion that the issuer namespace has never held grants or been restored. It returns a contextual `OAuthStoreCommitReceipt`: COMMITTED records factual initialization, CONFLICT reports an authenticated existing fence, and UNKNOWN requires authoritative reconciliation. The receipt does not establish current readiness or replace a fresh admitted operation. Absence cannot prove freshness. Do not call it to repair a lost fence. `establishNewSubject(subject)` similarly asserts first registration of a never-used subject; normal approval/status/revocation requires an established permanent subject fence. UNKNOWN is a typed uncertainty and never permission to retry blindly. Restored databases and lost permanent fences require the deployment recovery procedure before traffic.

`warmUp()` checks configured signing capability and an existing issuer fence; it never initializes state or fetches arbitrary metadata URLs. Trusted grant, subject and issuer revocation use authoritative state; epoch advances are non-idempotent under UNKNOWN. `resealStoreEntry(key)` authenticates retained typed payloads and performs one namespace-bound version CAS without changing authority/retention. It returns a contextual factual receipt, including CONFLICT for absence/retention-expired rows/races and UNKNOWN for uncertain outcomes. Finite reseal can authenticate used or credential-expired state strictly before its original full retention; it preserves the floor, authorization payload and retention, releases no credential and never becomes FENCE_ONLY. Raw initialization/reseal do not require the service final-read checkpoint and preserve COMMITTED/UNKNOWN after late acknowledgement. Keep old decrypt keys until all retained rows, including permanent fences, are migrated.

<a id="issuer-persistence-foundation"></a>

### Implement authoritative storage

The `com.revetsec.oauth.server` store SPI and carriers describe an application-owned durable backend.
`read` returns a coherent `OAuthStoreReadResult.Available` containing the exact key, entry or confirmed absence, and `StoreTimeObservation`; `Fenced` and `Unavailable` never mean absence. A time-unavailable observation can support only the narrow emergency fence path. `commit` checks all exact predicates and admission plus the required temporal condition for `TIMED`, then returns `OAuthStoreCommitReceipt`. COMMITTED means the requested mutation or barrier committed with its contextual validation timing; CONFLICT and the explicit capacity/admission/time refusals have zero effects. UNKNOWN requires reconciliation and never implies rollback or safe retry. A known requested commitment whose service output cannot be admitted becomes `COMMIT_CONFIRMED_NOT_ADMITTED`, not UNKNOWN. Zero-mutation barriers remain atomic and create no uncertain business mutation if their acknowledgement is unknown. A cache or example map does not supply durability or recovery protection.

Persist the key, opaque version, complete retainUntil instant (seconds and nanoseconds) and encrypted toSealedForm verbatim. Reconstruction
factories only validate bounded transport syntax; they never confer authorization. The storage grammar is
`revetsec:as:1:<issuer-digest>:<KIND>:<identifier>`, with canonical 43-character base64url SHA-256/256-bit
components. The issuer digest hashes the exact UTF-8 issuer spelling. ISSUER_STATE uses that digest as its
singleton identifier; SUBJECT_STATE hashes the issuer-local subject. Namespace separation and record kind are
part of authenticated storage binding. Treat every address, version and envelope as sensitive.

ISSUER_STATE and SUBJECT_STATE have permanent retention `Instant.ofEpochSecond(Instant.MAX.getEpochSecond())`:
never TTL-delete or evict them. Other records have finite retention. Cleanup authority is distinct from credential
expiry; replay tombstones must survive through their descendant horizon. Retain decrypt keys until every retained
record, including permanent fences, has migrated. Encryption detects substitution, not authentic backup rollback.
Restored deployments must fence old grants before serving traffic.

The engine creates bounded transactions from complete observed read sets; applications cannot construct issuer transactions through a public factory. The unpublished PostgreSQL fixture exercises the store contract across independent JVMs on one authoritative primary. It supplies no shipped backend or arbitrary deployment guarantee.
Application store implementations must honor budgets; no library thread forcibly preempts a blocked callback.

<a id="internal-permanent-fences-and-store-coordination"></a>

### Preserve floors, fences and commit outcomes

The internal coordinator authenticates permanent issuer and subject revocation fences with random incarnation and checked monotonic epoch; grants and status records bind both. The schema-2 issuer root binds its admitted authority and immutable exact minimum `L`. Its outer floor equals `L`; subject and authorization records carry their own authenticated entity floors. Ordinary time passage never rewrites the issuer root. Healthy coherent store observations supply time; worker clocks are checked only for health and never advance `L` or entity floors. Every transaction retains exact issuer/entity versions and absences. A timed lower bound includes the selected authority observation and all relevant floors; the exclusive upper bound remains no later than the original applicable credential/policy expiry. Unsupported or future legacy floors close timed admission without clamping. Normal decoders reject outer schema 1; its authentication and conversion remain restricted to closed migration.

Fresh issuer initialization is an explicit trusted deployment action using an ABSENT condition. A missing established issuer fence fails closed. Subject creation is likewise separate from established subject reads and revocation. An authoritative missing row cannot establish that a namespace is unused: the operator must know that it has never held grants or been restored. Restore recovery must advance the issuer fence before traffic resumes. Encryption detects substitution and corruption; it cannot detect rollback of an authentic database backup.

Store callbacks receive the remaining original monotonic budget. Client/CIMD/policy and signing are provisional preparation; the session freshly joins every complete entry fingerprint before the exact timed transaction. A full conflict retry repeats the relevant client and policy preparation under that original budget. Callback facts are recorded before post-callback health/deadline checks: a throw or null after entering a mutating write is uncertain, while a known durable commitment stays known even if acknowledged late. Interruption persists; fatal VM errors propagate. Only a zero-effect conflict permits bounded reload; UNKNOWN and confirmed requested commitment stop automatic retry. Normal output requires the minimum fresh issuer-root checkpoint and final budget/health/finite-bound check. Raw effect-only maintenance follows the separate [namespace maintenance receipt contract](#initialize-and-maintain-an-admitted-namespace). A completed, uncertain or invalid submitted session cannot be reused.

`revokeAllGrants()` and `revokeSubject(subject)` alone use `FENCE_ONLY`: exactly one existing permanent root epoch advances, with current authority/recovery admission, exact issuer/subject predicates, preserved incarnation, authority binding, `L`, entity floor and permanent retention. They cannot initialize roots or subjects, issue credentials, reseal, or serve as a fallback for timed work. Their postcommit minimum issuer-root acknowledgement accepts time unavailable and ignores clock generation/worker health; loss of current recovery admission or the original budget withholds acknowledgement while preserving known commitment.

The runnable issuer PostgreSQL source uses shared admission for ordinary operations, exclusive first-root activation, sorted strongest logical-key locks and changed entry-escrow buckets. It samples the supplied authority after lock waits, evaluates lower then upper bound before capacity and atomic mutation, and performs no read/failure cleanup or normal namespace-wide count/mutex. A current data-admission observation with an unadmitted clock profile exposes unavailable time so emergency fences remain possible while timed work closes. These owned one-primary fixtures do not qualify live witness integration or deployment throughput.

For an established namespace or a restored backup, keep serving admission closed while excluding old writers and following the [shared-clock migration and recovery contract](shared-clock-stores.md) and [closed migration/restore fixture](../verification/shared-clock-migration/README.md). Authentication of an old backup does not prove that its epochs, replay history or floors are current. Reconcile factual uncertain/late commitments before reopening; neither missing rows, successful construction nor a raw COMMITTED receipt grants that authority.

## Roll out configuration changes

### Configuration changes across restarts and nodes

A rebuilt issuer reads the existing authenticated grants; it does not migrate them to its new settings.
For 1.0.0, incompatible changes require revocation and new authorization. There is no persisted policy-budget
upgrade or automatic reissue. Use the same settings and registration security versions on all serving nodes.
A successful build checks local settings, not their compatibility with grants already in the store.

#### Retention and lifetime settings

First code redemption pins the family's absolute expiry, maximum access lifetime and retention horizon H.
For an otherwise eligible authenticated refresh, the current retention requirement is the whole-second ceiling of:

`original family expiry + pinned maximum access lifetime + current clockSkew + current totalDeadline + current publicMetadataHttpCacheMaxAge`

If that requirement exceeds stored H, or the current access-token lifetime exceeds the pinned maximum,
the refresh transition atomically marks the entire grant REVOKED and returns the fixed local
`400 {"error":"invalid_grant"}` response. It issues no replacement credential and does not extend H.
The revocation applies to the family's access and refresh descendants on every node sharing that store,
including a node still using the earlier settings. Merely constructing a new engine does not revoke
anything: an otherwise valid access token can still pass online status before this refresh transition.

The comparison uses the full configured durations, including fractions of a second; public HTTP headers
use whole seconds. A larger setting can fit existing rounding slack, and an increase offset by another
margin's decrease can leave the required H unchanged. An unchanged or smaller combined margin and an
access lifetime within the pin can continue the family, subject to all ordinary policy, freshness, expiry
and fence checks. Every replacement still retains the original absolute expiry, maximum and H. A decreased
margin does not shorten the stored H or authorize early deletion of already-retained records.

Treat an increase of any contributing margin or the access lifetime as a potentially incompatible rollout.
Do not rely on rounding slack, the next refresh, or traffic distribution to revoke all affected families.
With mixed settings, an old node can rotate successfully and a new node can then revoke that same family.
Reducing settings again cannot undo a revocation already committed. Changing refresh idle or absolute
settings also does not reset a stored family's original absolute expiry; each replacement idle expiry is
bounded by that original expiry. The application key provider must separately preserve publication and
verification overlap under the required margins across nodes and restarts.

#### Registration edits

Stored interactions and grants bind a security fingerprint of the registration. The following changes have
different effects even when the application does not change `configurationVersion`:

| Registration edit | Existing authorization state |
|---|---|
| Change `configurationVersion`, authentication mode, code/refresh permission, redirect spelling/set, or allowed resource/scope set | Fingerprint changes. Pending interaction resume/completion and code/refresh exchange cannot use the old binding. Adding authority also requires new authorization. Authentication or code-permission checks can reject before the fingerprint check. |
| Change only `clientName`, or reorder otherwise identical redirect/resource/scope collections | Fingerprint stays the same; ordinary checks still apply. A display edit accompanied by a version change is incompatible. |
| Replace secret-verifier implementation or change its secret/key semantics | Callback identity and behavior are not fingerprinted. Change `configurationVersion` explicitly; using a new callback object alone does not invalidate old bindings. |
| Change `introspectionResources` only | This separate current endpoint allowlist is checked at introspection. It is not part of the code/refresh grant fingerprint. Bump the version too if the application intends to invalidate those bindings. |

A fingerprint mismatch rejects use of a stored binding; it does **not** rewrite or revoke that grant.
In particular, already-issued access tokens can still pass online status: that path checks authenticated
issuance/grant/fence facts and does not reload the current client registration. The ordinary client token
revocation endpoint can return its indistinguishable empty 200 without revoking an old-fingerprint grant.
Restoring the earlier registration/version can make still-live old interactions, codes and refresh
credentials usable again. A configuration version is an equality binding, not a monotonic revocation epoch.
When permanent invalidation is required, use trusted management revocation as well as the new configuration.

#### Rollout procedure

1. Classify the proposed edits against both tables and test them using the application's retained-grant
   inventory and store/key-provider contracts. Inventory sensitive grant-management references through
   trusted application state, such as `OAuthGrantContext.getGrantValue()`; do not log them. There is no
   built-in client-wide grant enumeration or bulk client-revocation API.
2. For an incompatible rollout, quiesce issuance, consent completion, code/refresh exchange and configuration
   writers on **all** old nodes. Drain their in-flight operations before changing authority. An operation
   admitted before a revocation fence may already have finished; revocation cannot recall a released result.
3. Revoke affected known grants with `revokeGrant`, or choose the broader `revokeSubject` / `revokeAllGrants`
   fence when the inventory or desired scope requires it. Those broader methods affect other grants too.
   Issuer-wide revocation also invalidates prior issuer-bound interactions; revoking one grant is not a
   purge of other pending consent. Obtain confirmed management completion. If an exception, UNKNOWN or
   a committed-but-not-admitted result leaves acknowledgement withheld, keep traffic closed and reconcile
   the factual commit outcome under the store recovery contract; do not assume rollback or retry credentials.
4. Deploy consistent settings, registration versions and durable key-provider declarations on every serving
   node. Preserve permanent issuer/subject roots, authority bindings, floors, existing retain-until values
   and required verification keys. Ordinary configuration changes need no envelope/payload migration.
   Never initialize a replacement root, reseal to extend H, delete live replay evidence, or grandfather old
   grants beyond their recorded bounds. Startup/restore admission remains a separate requirement.
5. Reopen traffic and require a new browser authorization/consent and S256 code exchange for affected
   clients. New grants use the new settings. Test that old credentials remain unusable even if configuration
   is rolled back. Expired rows may be cleaned only under their existing retention and store-time contract;
   deletion supplies no authority to recreate a missing family.

## Deployment obligations and evidence

| Application responsibility | Required boundary |
| --- | --- |
| Identity, authorization and browser/session lifecycle | Authenticate subjects, protect consent with session/CSRF controls, bind the browser separately from state, rotate application sessions when appropriate, escape display data and enforce resource authorization. Issuer interactions are not authentication proofs. |
| Durable state and trusted time | Qualify exact admitted authority/witness/recovery behavior, atomic post-wait predicates, loss/restore fencing, capacity, retained replay records and permanent roots. Worker clocks, encryption and example maps do not supply those guarantees. |
| Keys and configuration rollout | Own private-key custody, old decrypt/verify key retention, publication history and cross-node overlap. Coordinate incompatible policy/registration edits with revocation and new authorization; rollback must not resurrect old authority. |
| HTTP and operational failure handling | Preserve raw multiplicity and configured authority; bound acquisition before library calls; emit only returned admitted output; reconcile UNKNOWN and COMMIT_CONFIRMED_NOT_ADMITTED rather than guessing rollback or replaying credentials. |
| Actual deployment qualification | Select matching core/adapter/schema artifacts and qualify the actual platform, store, trusted time, recovery owner and clients. Type/API compilation or local fixtures do not close those gates. |

The [unpublished issuer PostgreSQL fixture](../verification/issuer-store/README.md) documents selected independent-JVM races, uncertain COMMIT and logical restore on one primary and host. Its receipts are bound to their exact artifacts and profiles; it supplies no shipped backend and does not qualify replica failover, cross-host recovery, power loss, live witness integration or arbitrary application stores. The self-issued example is explicitly volatile and disposable.

Historical reviews, browser/client receipts and release-owner API acceptance apply to their recorded artifacts. They do not establish current shared-profile, retained migration, deployment recovery or release approval. Use the current contracts above and preserve those evidence limits when selecting a deployment. Current release qualification remains open.
