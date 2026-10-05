# OAuth authorization-server application contracts

The `com.revetsec.oauth.server` package starts the app-integrated token-issuance API planned for 1.0.0. Registered-client and application-policy contracts are implemented. Authorization endpoints, issuance, durable store transitions and client-metadata fetching are still under implementation.

The application supplies users, login/session handling, CSRF defenses, permission decisions and storage. Revetsec's issuer will validate the protocol, bind those decisions and manage credentials. An application decision is trusted configuration, not a Revetsec-verified authentication proof.

## Register a browser client

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

Confidential registrations use `OAuthServerClientAuthentication.fromClientSecretVerifier(verifier)` with an application-owned `OAuthClientSecretVerifier`. That selects `client_secret_basic`. The issuer will decode the credentials, reject duplicate/mixed authentication and clear the temporary secret bytes after the callback. The app performs constant-time verification and must not retain those bytes. Construction never calls the verifier.

## Supply an application decision

```java
OAuthAuthorizationDecision decision = OAuthAuthorizationDecision
    .withSubject("issuer-local-user-id")
    .authorizedScopesByResource(Map.of("https://api.example/mcp", Set.of("read")))
    .build();
```

The app authenticates the subject on the server and protects the session and consent submission. The issuer must check that the decision retains the subject and is a subset of the interaction, current client and server configuration. `deniedInstance()` expresses denial with no subject or resource map. An explicit one-resource empty scope set is representable for a policy denial; it never authorizes a zero-scope credential. Refresh defaults false and will also require server/client approval.

`OAuthGrantPolicy` rechecks permissions at approval, code exchange and refresh. Its `OAuthGrantContext` has no public constructor, factory or builder. The issuer supplies checked facts; the application may return denial or a decision that keeps the subject and narrows authority. `getGrantValue()` explicitly releases a sensitive grant-management handle to trusted application code; never log it.

## Resource-only registrations

A confidential client that introspects resource tokens can use `authorizationCodePermitted(false)` and an explicit `introspectionResources` allowlist. It requires no fake browser callback. Introspection authority is independent of its authorization-code scopes and always requires confidential authentication.

Setting code permission false clears the builder's browser configuration. A code-disabled registration exposes empty browser redirects/scopes, even if replacements were supplied afterward. Setting permission back to true requires complete browser configuration. Null resets code permission true; it does not restore cleared values.

## Values, bounds and diagnostics

Collections replace complete values and are copied at setter time; nested scope sets are immutable. Client/resource/scope identifiers retain exact String spelling. Redirects retain each URI's original `toString()` spelling: `URI.equals()` is unsuitable for protocol identity. Resource identifiers are absolute URIs without fragments; they are never URLs to fetch.

HTTPS redirects have no userinfo, fragment or wildcard. Preexisting query parameter names `code`, `state`, `iss`, `error`, `error_description` and `error_uri` are rejected, including percent-encoded names. Only exact HTTP `127.0.0.1`, `[::1]` and `localhost` configurations are representable. Their use will require separate explicit server opt-ins; registration alone enables no loopback feature. The native IP-literal profile's port exception and exact localhost policy will be enforced by endpoint admission.

Carrier ceilings support the approved configurable server maxima: 4096 UTF-16 code units for client ID/name/version, 1024 for subject, 65536 for URI spelling, 64 redirects, 1024 resources, 128 scopes per resource and 128 ASCII characters per scope. Each collection's resource/scope or redirect spellings also have a 131072-byte UTF-8 aggregate ceiling. These are construction bounds; operations must apply the configured narrower request, response and sealed-record limits. Invalid supplied values throw fixed `IllegalArgumentException`; a missing required builder value throws `IllegalStateException`; null required-primary arguments throw `NullPointerException`. Nullable setters clear required settings or reset the documented defaults.

Value and builder `toString()` methods redact identifiers, display names, configuration versions, subjects, scopes, handles and callbacks. Explicit data getters remain sensitive application data. The package adds no runtime dependency and does no callback, network, storage or thread work during construction.


## Internal ingress implementation

The registered-client ingress helpers are implemented internally. They have no public endpoint entry point yet and issue no interaction, code or token. The store, CIMD and issuer engine are still under implementation.

Raw query/form parsing retains duplicate occurrences until validation. Recognized security parameters cannot repeat, even with identical values or percent-encoded names. Unknown ordinary extensions are ignored after strict decoding and consume the same field and input limits. Malformed escapes, malformed UTF-8 and unpaired surrogates reject the whole input. Bounds apply before copying/decoding; the fixed structure caps are 128 query/form fields across both channels and 64 header occurrences. Header sizes include serialized names, separators and CRLF bytes. The trusted HTTP edge must preserve every occurrence and enforce allocation, framing, routing and TLS before calling the future engine.

Authorization admission accepts GET with an empty body. Form endpoints accept POST with one `application/x-www-form-urlencoded` Content-Type and UTF-8 or absent charset; content encoding and query security parameters are rejected. Authorization and Content-Type duplicates include differently cased header names. Basic credentials use percent-decoded exact client IDs and UTF-8 secret bytes. This profile rejects body client IDs combined with Basic, secret-post, assertions and public-client fallback. A false verifier result is a client rejection; a null result, nonfatal callback failure, interruption or exhausted cooperative deadline is an infrastructure fault. Temporary decoded arrays are cleared on every exit, including a fatal VM error; decoded secrets are never materialized as immutable Strings.

Registered redirect matching preserves every component's spelling. HTTPS redirects match exactly. Explicit native IP-loopback policy can vary only the port of literal `127.0.0.1` or `[::1]`; separate localhost policy matches its exact configured port. Both policies default off when the future builder wires these helpers. Resources compare as exact identifiers and are never fetched. Omitted scope selects the client/server intersection; explicit scope must fit that intersection, and empty authority is rejected. S256 challenges require canonical 43-character Base64url; code verifiers require 43–128 ASCII unreserved characters. These checks admit requests, not grants: policy decisions, replay protection, grant/resource binding and credential publication remain engine responsibilities.

The nine internal ingress settings use the approved ranges, but they do not add public Limits registry rows before the owning server builder exists.

## Issuer persistence foundation

The `com.revetsec.oauth.server` store SPI and carriers describe an application-owned durable backend.
`read` returns authoritative linearizable data or confirmed absence. `commit` checks every ABSENT/version
condition and applies every mutation atomically across participating keys and nodes. COMMITTED means durable;
CONFLICT means zero effects; UNKNOWN requires reconciliation and never implies rollback or safe issuance retry.
Zero-mutation transactions are required read-set barriers. A cache or example map does not supply these guarantees.

Persist the key, opaque version, whole-second retainUntil and encrypted toSealedForm verbatim. Reconstruction
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

This slice implements bounded carriers, common sealed record bindings and complete read-set construction.
It has no public transaction factory, endpoint engine, credential issuance, durable backend or replay transition.
Application store implementations must honor budgets; no library thread forcibly preempts a blocked callback.


## Internal permanent fences and store coordination

The internal coordinator implements sealed issuer and subject revocation fences. Each fence has a random incarnation and a checked monotonic epoch; later grant and status records must bind both. These records retain permanently. Issuer state also persists the complete clock high-water instant. Every mutating transaction conditions and updates issuer state; a node behind that clock fails unavailable. A condition-only admission barrier checks the complete observed versions and absences without writing the global clock on every resource request.

Fresh issuer initialization is an explicit trusted deployment action using an ABSENT condition. A missing established issuer fence fails closed. Subject creation is likewise separate from established subject reads and revocation. An authoritative missing row cannot establish that a namespace is unused: the operator must know that it has never held grants or been restored. Restore recovery must advance the issuer fence before traffic resumes. Encryption detects substitution and corruption; it cannot detect rollback of an authentic database backup.

Store callbacks receive the remaining original monotonic operation budget, checked before and after each callback. Nonfatal callback faults and null returns are fixed failures. Interruption persists; fatal VM errors propagate. Only a zero-effect CONFLICT permits a bounded reload under that same budget. UNKNOWN ends the operation without automatic retry, rollback or success publication. A completed or uncertain transaction session cannot be reused.

The tests exercise two internal coordinators sharing an atomic single-process test double, with controlled interleavings, complete condition checks, clock rollback and uncertain commits before and after writes. They do not establish persistence, process-crash recovery, multi-node durability or failover. The public issuer engine, credential ledgers and full online token status are still being implemented.
