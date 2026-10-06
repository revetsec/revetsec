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

The registered-client ingress helpers are implemented internally. They have no public endpoint entry point yet. The internal consent ledger described below can create interactions and unused codes; it does not issue access or refresh tokens. The store, CIMD and issuer engine are still under implementation.

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

The tests exercise two internal coordinators sharing an atomic single-process test double, with controlled interleavings, complete condition checks, clock rollback and uncertain commits before and after writes. They do not establish persistence, process-crash recovery, multi-node durability or failover. The public issuer engine and full online token status are still being implemented.


## Internal consent ledger and pending grants

The internal ledger creates independent random 32-byte interaction handles and codes. Storage addresses hash
those credentials; the application supplies a separate canonical 32-byte random browser binding. Its digest
is compared in constant time. Neither OAuth state nor an application subject substitutes for this binding.
An immutable consent record binds the exact selected redirect, resource, S256 challenge, requested scopes,
optional state, current issuer incarnation/epoch and a digest of the client security configuration. Display text
is excluded from that digest; the application must change configurationVersion when secret-verifier or key
semantics change. Resolution of the current client, application login/session fixation/CSRF protection and
policy callbacks remain requirements of the future engine and application edge.

Resume uses an authoritative condition-only barrier. Completion re-reads consent and current
fences, checks the browser/client configuration and the application resource/scope subset against the reviewed
request and current server authority. An allowed nonempty decision requires an established subject fence.
It atomically completes the interaction and inserts an unused code and pending grant, together with the issuer
clock update. The internal code return occurs only after COMMITTED. A denial, including an explicit empty
scope decision, completes consent without creating a code or grant. Duplicate or racing completion cannot
re-emit a code. UNKNOWN yields no handle, review or code and is never automatically retried.

Code and grant records bind issuer and subject incarnation **and** epoch. They use exact bounded schemas;
authentication of the common envelope alone cannot authorize a transition. Pending grant retention currently
ends at unused code expiry. The internal first-redemption transition atomically pins the maximum access lifetime and extend
code/grant retention to H, alongside issued-jti and optional refresh facts. The checked calculator includes
family absolute expiry (or first no-refresh token expiry), the pinned maximum access lifetime, skew, total
deadline and public metadata freshness. Physical retention rounds up to whole seconds; credential validity
rounds down. Overflow and an attempted increase of a pinned lifetime reject. The calculator alone confers no issuance authority. The internal redemption transition below consumes
pending grants; refresh rotation, key lifecycle and full token status remain under implementation.

Operation expiry is checked before and after a cooperative backend callback. A callback returning after code
or consent expiry cannot publish success, even when the backend committed. Tests use deterministic
interleavings over the existing single-process atomic fixture. They do not prove a durable backend, process
recovery, failover or actual parallel execution.


## Internal code exchange and first issuance

The internal code-exchange transition reauthenticates the current registered client on each bounded attempt.
It reloads the authenticated code and owning grant, binds their exact cross-links and issuer/subject
incarnation plus epoch, and checks S256, exact resource, client security fingerprint and selected redirect
when supplied. Wrong client, verifier, resource, redirect or random code causes no mutation. An expired
unused code cannot issue. Continuing application policy runs outside storage transactions with the original
remaining budget. It can narrow scopes and refresh permission; changed identity, widening, null or callback
fault is an infrastructure failure. Denial or removed server authority atomically terminates pending state.

Before consumption, the transition prepares an RS256 at+jwt with fixed issuer, subject, single audience,
client_id, iat, exp, random jti and sorted scope. It retains the exact bounded JSON response and serialized
no-store headers. Signing, record preparation or response size failure occurs before commit. No caller claim
map is accepted. Signing-key publication, persistent provider snapshots and rotation checks are requirements
of the future engine; the internal encoder alone does not establish key lifecycle authority.

One complete transaction consumes code, activates the grant with its maximum access lifetime and H,
inserts the issued-jti record and optional initial refresh record, and updates the issuer clock. Optional refresh
requires server, client, original approval and continuing policy permission. Used code and grant retain together
through at least H and the original code expiry; access rows retain through their own expiry plus margins.
Only COMMITTED returns the prepared bytes. CONFLICT discards them and reloads under the original deadline;
UNKNOWN releases nothing and never triggers hidden retransmission. Cooperative expiry/deadline checks
also discard late output when writes may already have occurred.

A fully bound consumed-code replay remains recognizable after ordinary code expiry until retained state
expires. Its transaction revokes the entire grant, including its initial refresh token and access descendants.
A racing redemption loser follows that same path; it cannot release its discarded response. Subsequent
required online status must check the current grant and complete read-set barrier. The internal token-status boundary is implemented; public validation wiring
and public refresh endpoints are still being implemented. The current internal random credentials are not yet the
public typed code/refresh wire carriers, and the consent ledger still requires precommit Location/header
preparation when public authorization endpoints are wired.

The added tests check signatures using raw JCA, response byte retention, binding failures, policy containment,
uncertain commits and deterministic two-redemption interleavings over a single-process atomic fixture.
They do not establish durable storage, process recovery, multi-node failover or actual parallel execution.


## Internal online token-status admission

The internal validator checks a bounded RS256 at+jwt against an explicit local public-key snapshot, exact
issuer and single resource audience, required fixed claims and token times before accessing storage. It
then binds the issued-jti record to the exact subject, client, resource, canonical scopes, issuance time and
expiry. The active grant must share the same issuer/subject incarnations and epochs, contain the issued
scopes and cover the access token's pinned lifetime and retention horizon. Grant family expiry does not
prematurely invalidate an access token issued near that expiry. Token expiry plus configured skew remains
the admission boundary and is checked around the backend commit.

A successful admission requires one COMMITTED condition-only transaction containing every observed
issuer fence, issued-jti, grant and subject-fence version. Missing issuance/grant returns an inactive verdict
only after an authoritative absence barrier. Missing permanent fences, contradictory authenticated records,
backend faults and UNKNOWN outcomes remain infrastructure failures. CONFLICT reloads the entire read set
under the original bounded deadline. No positive token-status cache is used.

The barrier is the admission point: revocation racing before it prevents admission after reload; work
admitted before revocation may finish, while subsequent validation rejects. The helper releases only immutable
checked claims internally and retains no received credential. Public issuer result/proof wiring, signing-key
publication and retirement snapshots and external endpoints remain under implementation.
The tests use deterministic single-process store interleavings; durable multi-node, crash and failover
contracts require separate evidence.


## Internal strict refresh rotation

Each attempt freshly authenticates a registered client and checks the grant's exact owner, security
fingerprint and resource before any replay invalidation. Issuer and subject incarnations and epochs must
still match. An unused active refresh must also precede its idle and family absolute expiry. The continuing
policy receives the original grant scopes under the remaining operation budget, outside the transaction.
Denial, revoked refresh permission or reduction of that original authority terminates the grant; identity
changes, widening and callback faults remain infrastructure failures.

A request may downscope its access token while the replacement refresh retains the original grant scopes.
Future refresh can request those original scopes again. Rotation preserves the original absolute expiry,
maximum access lifetime and fixed retention horizon H. A later configuration cannot silently enlarge them.
The final access token may outlive family expiry, and required online status checks its own expiry plus skew.

Before commit, the helper prepares independent random replacement refresh and access-jti identifiers,
signed fixed RS256 at+jwt, sealed records and bounded immutable response bytes. One complete CAS marks
the old refresh USED, replaces the grant head, creates the new refresh and issuance rows and advances
the issuer clock. Only COMMITTED releases those bytes. CONFLICT discards output and reloads under the
same deadline; UNKNOWN releases nothing and permits no guessed rollback or automatic credential retry.

Fully bound used-refresh replay remains recognizable through H, including after its original idle or family
expiry. It atomically revokes the whole grant and every access/refresh descendant. A racing rotation loser
reloads USED and revokes the winner. There is no retry grace or re-emission of a prior response. Used rows,
code and grant retain through H; access rows retain through their own expiry plus the configured margins.

This is an internal registered-client helper. Public refresh/revocation/introspection endpoints, typed wire
credentials, CIMD and key lifecycle wiring remain under implementation. Tests demonstrate deterministic
interleavings over a single-process atomic fixture; durable multi-node, crash/failover, actual parallel
execution and issuer interoperability require separate evidence.


## Internal grant revocation and resource introspection

Fresh registered client authentication precedes credential lookup and every conflict retry. Access and
refresh credentials revoke their whole owning grant, including all access and refresh descendants.
Exact owner, client security fingerprint, resource, persisted issuance and current issuer/subject fences
must match before mutation. An optional revocation resource selector must match the grant; token hints
never select authority. Unknown, malformed, wrong-owner and already-revoked credentials receive identical
empty 200 response bytes after applicable authentication. Authoritative absence and unchanged state
require a complete condition-only barrier. Known grant invalidation and issuer clock update share one CAS.
Backend faults, corruption, exhausted budgets and UNKNOWN cannot produce success.

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
COMMITTED admission barrier. Exact bounded body/header bytes are prepared before that barrier. Unknown,
expired, revoked, wrong-resource or refresh credentials return only {"active":false}. Storage failure remains
a service failure, never inactive. Every operation checks current status with no positive cache. Responses
are immutable copied bytes with no-store/no-cache headers and redacted diagnostics.

These are package-private helpers. Public engine/results, endpoint failure mapping, typed credential prefixes,
key lifecycle, CIMD and Soklet issuance remain under implementation. Tests establish deterministic
single-process interleavings; durable multi-node, crash/failover, actual parallel execution and issuer
interoperability require separate evidence.


## Issuer signing keys and public metadata

`OAuthIssuerSigningKey.fromKeyPair` checks an RS256/RSA public projection locally without signing,
encoding private material or exposing a private-key getter. Mismatched pairs fail during actual bounded
signing or warm-up. `OAuthIssuerKeySnapshot.withActiveKey` builds an immutable active/public key declaration;
`generation` and `publishedAt` are required, null clears them, and null maps reset empty. An equal duplicate
of the active public key is accepted; another key under that ID is rejected. Public projections, maps and
retirement declarations are snapshotted. At most 100 keys and 128 KiB of aggregate configuration are accepted.
The application supplies `OAuthIssuerKeyProvider`, or uses `fromSnapshot` for a fixed declaration.

The provider is trusted infrastructure: it owns durable key history, publication to independent resources,
never reusing an identifier for different material, and overlap across nodes, restarts and in-flight operations.
Construction performs no provider lookup or signing. Operations fetch a fresh snapshot on the caller thread
under the original shrinking deadline. Provider faults, null, interruption and exhausted budgets fail closed;
fatal VM errors propagate. A generation's facts remain immutable. Every new generation has a strictly later
publication instant, and signing waits the configured public metadata freshness after publication. Delaying
or cancelling a retirement is allowed; moving it earlier is rejected. A key without a retirement declaration
cannot disappear from the next observed snapshot. Declared removal also waits through all locally reserved
access expiries plus skew, deadline and metadata cache margins. Failed signing may conservatively reserve an
unused horizon. This observed guard is bounded by the retained public set; it is not a durable history or proof
of actual external publication. Initial snapshots and safely retired identifiers remain application obligations.

Managed internal issuance checks publication, reserves retention, signs and verifies the pair, then reloads
and checks public overlap before preparing a response or committing issuance. A failed check leaves the unused
code and ledger unchanged. Online status loads checked public keys for the existing uncached atomic status
barrier. Ordinary rotation does not advance the issuer epoch; compromise/restore handling still requires
explicit issuer revocation and reconciliation of uncertain outcomes.

Internal metadata preparation preserves the exact configured issuer and inserts the RFC 8414 well-known
path before its tenant path, removing a terminating slash only for discovery location construction. Trusted
configured endpoints supply authority. Metadata advertises code, S256, none/Basic authentication, configured
refresh/revocation/introspection and nonempty scope unions. It does not advertise OP/ID tokens, dynamic client
registration, unimplemented CIMD or custom grants. JWKS contains only checked RSA public n/e, identifiers,
RS256 and verification use. GET/HEAD responses have copied bounded bytes, finite public max-age, must-revalidate
and a representation ETag. Unsupported methods receive an empty no-store 405 with Allow: GET, HEAD. Conditional
request handling and HTTP route integration remain application/public-engine work.

The key contracts are public; lifecycle enforcement and metadata response helpers remain internal. Public
engine/results, endpoint failure mapping, CIMD and Soklet issuance are still being implemented. Deterministic
fixtures and an independent JCA signature oracle do not establish durable multi-node key distribution or full
issuer interoperability.


## Opt-in client metadata configuration and admission

`OAuthClientMetadataPolicy.disabledInstance()` is the default. Enable configuration with
`withAddressResolver(resolver)` or `fromAddressResolver(resolver)`. The required
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
| maximumCacheEntries |128 entries|1–4096|
| maximumFreshness |300 seconds|0–1 hour|
| maximumConcurrentFetches |8 fetches|1–64|
| maximumResolvedAddresses |16 addresses|1–64|

Null resets each exact default. Invalid supplied values fail immediately. Integer getters are boxed;
optional absence is explicit. These five approved policy rows extend the limits registry to 57;
the remaining issuer rows arrive with the public engine. Cache and concurrency limits are currently
configuration; their operational enforcement arrives with transport and cache integration.

The internal parser uses strict UTF-8 and bounded JSON, including duplicate-member and depth checks.
It requires exact `client_id`, nonempty `client_name`, nonempty safe `redirect_uris`, and an explicit
`token_endpoint_auth_method` of `none`. Unsupported authentication is rejected. Only authorization
code and optionally refresh grant declarations, and the code response type, are accepted. HTTP IP
loopback redirects require native application mode and the separate native opt-in; exact localhost
has its own opt-in. Redirect spellings are preserved, and current ingress capacities still apply.

Recognized optional fields have checked JSON types. Scope, software statements and public key
descriptions confer no application authorization, trusted scopes or authentication authority.
References in metadata and unknown ordinary extensions are never fetched. Symmetric key material,
client secrets and private JWK members are rejected recursively, including nested extensions. Public
JWK descriptions receive structural/type checks only; they are not used to verify client credentials.
The security fingerprint covers exact client ID, authentication, redirect set, native mode and refresh
permission using structured facts. Display names, redirect order and ignored extensions do not change it.
Display text must be escaped by the application, and URL possession does not establish benevolent software.

The policy and resolver are public; document and URL admission are internal helpers. Parsing is not
proof of a fresh retrieval. The dedicated numeric-peer-pinned HTTPS transport, all-answer address
classification, response framing/media/cache/deadline checks, registry-first selection and fresh 200
retrieval at code redemption/refresh still need integration. Existing issuer metadata does not advertise
CIMD, and existing registered-client code/refresh paths do not start fetching URL client identifiers.


## Pinned transport admission helpers

The internal transport now has copied numeric-address admission and bounded HTTP/1.1 response
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
are discarded. Repeated cache fields are preserved for the later freshness policy, without merging
away ambiguity. Chunk extensions are validated, and nonempty trailers are rejected. Declared,
chunked and close-delimited documents remain bounded; premature or malformed endings fail.

The address and HTTP helpers remain pure. The live internal driver now connects with JDK
SocketChannel/Selector and SSLEngine to a copied numeric answer, verifies the connected peer and
port, and keeps the original hostname for HTTPS certificate checks, SNI and HTTP Host. Each fetch
resolves once and admits every answer before selecting the first; a later fetch resolves again.
There is no proxy, stock HttpClient fallback, redirect, connection retry, cookie or credential.
TLS1.2/1.3 and HTTP/1.1 are supported. A fresh context per exchange prevents connection/session reuse.
Three fixed64KiB TLS buffers, a512KiB aggregate wire bound including cleanup writes, request/header/
document bounds and the shrinking operation/request deadline limit work. Partial writes and reads
remain nonblocking. Raw TCP EOF is an error; only authenticated TLS close_notify supplies clean EOF.
Cleanup closes the socket and selector on every outcome, with a bounded best-effort TLS close alert.

The private context uses local trust material and explicit revocation-disabled PKIX parameters.
It validates a supplied ordered certificate path locally before passing a complete anchored chain
to the JDK extended trust manager for normal TLS algorithm, end-entity and hostname checks. This
specialized path requires the inspected java.base SunJSSE/SUN providers and the standard extended
trust-manager implementation; unsupported providers fail closed. No application TLS-context bypass
or process-global security-property change is exposed. JDK implementation changes require continued
qualification. Provider, resolver and local trust-store work are trusted cooperative callbacks;
Revetsec cannot forcibly preempt blocking work inside them. Revocation is intentionally disabled
for this anonymous metadata fetch so certificate-related AIA/OCSP/CRL network retrieval cannot
escape the selected numeric destination. Applications control their trusted runtime/network setup.

Local TCP/TLS fixtures cover partial I/O, deadlines, interruption, hostname mismatch and closure.
Isolated child checks exercise complete/incomplete chains with global retrieval flags enabled and
an active AIA positive control. An offline network namespace exercises the full public-address fetch
entry point, original DNS SNI/Host and changed numeric answers on a subsequent fetch. These results
cover transport behavior; no real public service, distributed cache or issuer credential flow is proven.

The application cache-storage interface, bounded in-memory default and builder injection are still
pending. Revetsec will own document validation, freshness and security fingerprints for every backend.
Code redemption and refresh will require a new successful200 for that operation before consuming
state; shared cached data cannot satisfy the fresh-fetch requirement. No CIMD support advertisement
or registered-client credential path starts fetching metadata yet.

## Client-metadata cache storage

`OAuthClientMetadataPolicy.Builder.cache(...)` accepts application-supplied storage, including
a shared backend. Omitting it (or passing null) defers construction of a separate in-memory
cache for each engine selection. Building a policy never calls a provider or starts a thread.
`maximumCacheEntries` configures the default only; applications bound their custom backend.

`OAuthClientMetadataCache` reads opaque carriers and performs atomic exact-version replacement
or removal. A missing expected version requires absence. A comparison conflict changes nothing.
Failures are distinct from misses and conflicts and use the fixed-diagnostic
`OAuthClientMetadataCacheException`. Providers honor the shrinking positive operation budget
and interruption; application code remains cooperative. A failed optional-cache write may
have applied, and eviction/expiry removes historical version ordering. This interface provides
no credential consumption, distributed lock, authoritative-store fallback or loader callback.

Keys and entries reconstructed from storage are syntax-bounded data. Their sealed form requires
core authentication, namespace/provenance and current policy/time validation before metadata use.
Stored expiry is a cleanup hint, not trusted freshness. The default does not interpret it. A
cache hit never supplies the fresh200 proof needed at code exchange or refresh. Those codec,
HTTP freshness and fetch/credential transitions are the next implementation slice. The current
shared-provider tests exercise in-process selections and races, not a durable distributed backend.

The default serializes access to a private copy of Soklet's `ConcurrentLruMap`, evicts before
insertion and drains every mutation, keeping retained entries within the configured bound.
It has timed interruptible outer locking and exposes no map, listener, loader or worker thread.
The copied source retains its upstream header and algorithm; a pinned source fixture verifies
that only its package and explicit nullability annotations changed.


### Authenticated optional client metadata reuse

The internal metadata coordinator selects the configured cache once, authenticates a distinct cache envelope, and re-admits the stored document under its current policy. Stable keys bind the exact issuer/configuration/client identity; compatible nodes need the same sealing keys and trustworthy clocks. Cache carrier reconstruction alone grants no metadata or credential authority. Stored UTC fetch and expiry facts, key, version and document bytes are authenticated. Local observed clock rollback disables reuse and writes for that operation. Encryption cannot detect an unobserved clock rollback after restart or prevent replay of a still-fresh authentic record.

Reuse requires explicit finite freshness. Revetsec subtracts HTTP Age, apparent age from Date and a conservative transport-delay bound, then caps the remaining time and rounds the stored expiry down to a whole second. Missing/ambiguous freshness, malformed Age/Date/Expires, no-store/no-cache, private, s-maxage and Vary responses receive no reuse permission. These conservative shared-storage restrictions can cause additional fetches; they never permit stale metadata. Refer to [RFC9111 §4.2.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.3) for age calculation.

Optional-cache corruption, absence or failure can lead to a new fetch within the original shrinking deadline. Interrupt or exhausted budget aborts. A valid fetch may skip storage if its envelope does not fit the configured sealer cap; the cap is never raised. Observed-version writes are conditional, with no blind retry after conflict or uncertain write. An authenticated newer fetch timestamp also prevents an older-clock replacement. Eviction removes history, so this is not durable ordering or distributed fencing.

Fetches run synchronously on caller threads through the pinned HTTPS driver, outside authoritative transactions. A per-coordinator permit bound rejects excess concurrent work; there is no background executor, unbounded waiter list or single-flight sharing. The bypass path owns its new successful200 and reads no reusable cache record. Registry-first client selection and code/refresh before-consumption fingerprint checks remain the following integration slice; these helpers are not public issuer endpoints or transferable current-fetch capabilities.


## Internal registry and credential binding

Exact registered clients take precedence, including URL-shaped IDs. A registry fault, null result or mismatched identity is an infrastructure failure and never permits metadata fallback. Basic authentication and introspection remain registry-only. Unknown public URL clients use CIMD only when the engine selects an enabled metadata fetcher.

CIMD's scope/software/key declarations confer no authority. Configured server resources/scopes form the request ceiling; explicit application approval is still necessary. Consent and grants retain an authenticated security fingerprint with a distinct CIMD source discriminator, including exact identity, authentication, redirects, native application and refresh semantics. Display-only changes do not invalidate it. Switching between registration and metadata requires new authorization. Code and refresh descendants resolve their client binding through the authenticated grant.

Every code/refresh attempt, including a retry after a store conflict and a bound used-credential replay, performs its own successful200 via the pinned transport before authoritative state reads/consumption or replay invalidation. It bypasses all cache reads and writes. A prior snapshot, another operation's200 or shared cache cannot replace this fetch. Registry, fetch, store, policy and signing share the original shrinking deadline. Failure, invalid metadata or fingerprint mismatch releases no credentials and leaves an unused code/current refresh unconsumed; valid fully bound reuse retains strict whole-grant invalidation. No callback/network/signing runs inside a backend commit.

These are internal helpers. Public engine routing/results, full endpoint failure mapping, dynamic revocation integration, durable multi-node recovery and final issuer assurance remain pending. Deterministic transport and single-process atomic fixtures do not establish those results.


## Prepared response and credential wire contracts

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
and current client fingerprint before preparing a303. Approval emits a typed code; denial or an
explicit empty scope decision emits only `access_denied`. The original query spelling is retained,
with one strict UTF-8/form encoding of state and issuer. Absent and empty state remain distinct.
Original non-ASCII URI characters receive URI ASCII encoding for the HTTP Location field; existing
ASCII query percent spelling is preserved. Response overflow occurs before atomic completion and
leaves consent pending. Only an acknowledged COMMITTED result can release the prepared response;
a conflict prepares again and an unknown outcome releases no response. Subsequent emission never
recomputes code, timestamps or contents. The legacy internal code-only helper remains a test seam;
the forthcoming public engine will use the response-producing path.

Authorization codes use `rsc1_` and refresh tokens use `rsr1_`, followed by43 canonical unpadded
base64url characters encoding32 random bytes. Their complete typed wire spelling is hashed into
ledger identifiers. Wrong kinds, bare nonce handles, padding and noncanonical trailing bits reject
before authoritative code/refresh reads. Revocation retains its authenticated uniform-success
handling for unknown/malformed/wrong-kind credentials; hints do not override grammar. These are
internal issuance contracts, with no public credential-construction API or additional store schema.

The registry now contains all27 approved issuer rows, including the five CIMD rows. Internal
settings enforce each range, exact nullable default resets, request timeout within total deadline,
code lifetime within interaction lifetime, refresh-enabled access/idle/absolute lifetime ordering,
skew within half the access lifetime, and sealed-record capacity within the actual configured
sealer cap. Checked retention arithmetic keeps fractional-duration precision. Building settings
performs no application/provider/store callback, network access or signing. Public builder and
endpoint/result wiring, dynamic revocation, Soklet issuance and distributed backend/recovery/browser
qualification remain subsequent work.


## Restricted outcomes and failure boundary

The public issuer result types are sealed and cannot be constructed by applications. Authorization yields a restricted interaction, completed response, denial response or fixed rejection; token, revocation and introspection yield success or fixed rejection. A restricted interaction exposes its secret continuation handle, checked client ID, optional untrusted display name, exact selected redirect, requested resource/scopes and expiry. Escape display text and keep the handle in the protected app session. It is not user authentication, and a previous UI view is never completion authority.

Issuer access-token success releases the existing VerifiedAccessToken only after the future engine composes M5 validation and an authoritative uncached issuer status barrier. Its rejection carries only fixed issuer/M5/JOSE reasons and a safe BearerError. These contracts do not yet expose a public issuer engine, and no public proof factory has been added.

OAuthServerException directly extends RevetsecException and is sealed to validation, store, transport, configuration and signing leaves. Construction is restricted. Messages, diagnostics and suppression never retain external callback failures or their data. COMMIT_OUTCOME_UNKNOWN remains a nontransient store infrastructure exception; reconcile it rather than blindly retransmit credential or subject-revocation work. Store corruption and invalid configuration remain configuration failures. Generic SPI unavailability is nontransient because its fixed internal classification cannot prove the cause. A future operation may classify a known timeout, I/O failure or request held back as transient; this never overrides UNKNOWN or interruption. Cooperative interruption preserves the interrupt flag and prevents transient classification.

The local HTTP boundary emits fixed JSON errors with no Location, no reflected error description, no-store/no-cache/no-referrer and bounded bodies/headers. Infrastructure fallback is always503 server_error. Invalid and unknown clients share invalid_client; Basic authentication failure uses401 with a fixed Basic challenge, while public-client rejection uses400. Introspection caller failure uses401. Invalid/replayed grants and PKCE mismatch share invalid_grant. Unsupported methods use405 and endpoint-specific GET/POST Allow. Consent denial redirects still require the existing authenticated, prepared-before-commit path.

OAuthServerObserver has synchronous caller-thread hooks and fixed operation kinds, including trusted grant/subject/issuer invalidation and store resealing. The internal dispatcher emits one will and one terminal hook during ordinary completion, contains hook failures through the existing dispatcher, restores interruption, and propagates VirtualMachineError. Events carry no request, URL, client, subject, grant, credential, key identifier or claims. Future engine callers must dispatch outside locks and store transactions. The issuer builder and endpoint wiring remain the next slice.


## Public authorization server

`OAuthAuthorizationServer.withIssuer(issuer)` selects the exact issuer. Configure authorization, token and JWKS endpoints on that same authority, a registered client repository, an atomic authoritative store, issuer signing keys, a state sealer, a nonempty resource/scope registry and a continuing grant policy. Missing required fields fail at build; null property setters clear requirements or restore documented defaults. Configuration is snapshotted without provider/store/resolver callbacks, signing, network I/O or owned threads. Refresh requires an explicit revocation endpoint; introspection and revocation otherwise remain optional. HTTP numeric loopback requires explicit development opt-in.

Register the exact configured routes and preserve materialized body, raw query and header occurrences. Call `beginAuthorizationResult` for GET authorization, render its restricted interaction after app authentication, and submit the trusted decision through `completeAuthorizationResult` with app session and CSRF protection. `resumeAuthorizationResult` rechecks a continuation before rendering. An interaction does not authenticate a user. Initial approval rechecks grant policy before committing, keeps the app subject and only narrows scopes/refresh. Each conflict resolves current client facts and runs policy again; denial consumes the interaction without a credential.

`tokenResult` handles code exchange and strict refresh rotation. `revokeResult` invalidates the whole credential-owning grant for registered or admitted dynamic clients; dynamic owner authentication requires a fresh pinned200 fetch. `introspectionResult` accepts registered confidential resource-only callers; an optional resource selector must belong to the server registry and caller allowlist. Omitting it is supported only with a sole configured server resource. Metadata/JWKS advertise the configured profile, including CIMD only when enabled. Request Host/Forwarded values provide no authority.

`validateAccessTokenResult` uses the existing M5 validator with a fresh static local public-key snapshot and the original operation Deadline, followed by the uncached exact-profile issuance/grant/subject/issuer check and atomic complete read-set barrier. Only the committed success releases `VerifiedAccessToken`. No raw BearerToken accessor or proof factory was added to the public API. All callbacks use the shrinking caller budget; trusted synchronous callbacks must honor it.

### Explicit deployment and maintenance

Before traffic, `initializeFreshIssuer()` is an operator assertion that the issuer namespace has never held grants or been restored. It returns COMMITTED, CONFLICT when an authenticated issuer fence already exists, or UNKNOWN requiring authoritative reconciliation. Absence cannot prove freshness. Do not call it to repair a lost fence. `establishNewSubject(subject)` similarly asserts first registration of a never-used subject; normal approval/status/revocation requires an established permanent subject fence. UNKNOWN is a typed uncertainty and never permission to retry blindly. Restored databases and lost permanent fences require the deployment recovery procedure before traffic.

`warmUp()` checks configured signing capability and an existing issuer fence; it never initializes state or fetches arbitrary metadata URLs. Trusted grant, subject and issuer revocation use authoritative state; epoch advances are non-idempotent under UNKNOWN. `resealStoreEntry(key)` authenticates retained typed payloads and performs one namespace-bound version CAS without changing authority/retention. It returns CONFLICT for absence/expired rows/races and UNKNOWN for uncertain outcomes. Keep old decrypt keys until all retained rows, including permanent fences, are migrated.

Expected remote errors are fixed result variants. Infrastructure/corruption/signing/UNKNOWN stays typed and redacted; `responseForFailure` emits fixed503 JSON with no Location. Observer hooks have fixed operation kinds, no credentials or identities, and one terminal event during ordinary completion. InteractionRequired has logical HTTP200; management/validation status is absent. Infrastructure faults never become invalid credentials or implicit retry approval.

This public wiring is checked with deterministic atomic single-process fixtures and the existing regression matrix. Durable/distributed backend, crash/restore recovery, live issuer/browser/Soklet integration and final issuer assurance remain separate work.
