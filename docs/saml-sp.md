# SAML service provider integration

Revetsec implements the service provider (SP) side of SAML 2.0 and connects to an
approved identity provider (IdP). It prepares SAML requests and checks POST responses
and signed Redirect or POST logout messages.
If JVM-global XML-signature secure validation is disabled, the SP builder fails unless the
application explicitly calls `acknowledgeGlobalSecureValidationDisabled(true)`. This choice
is reported to [`SamlObserver`](https://javadoc.revetsec.com/com/revetsec/saml/SamlObserver.html) at build time. Revetsec sets secure validation on each
verification context and enforces its signature allowlists even when the JVM policy differs.
The application owns its users, account links, browser sessions, pending-state transport,
and the decision to end a session. SAML support is part of Revetsec 1.0.0; the scripted IdP and a
pinned Keycloak container exercise bounded browser flows. [RC-2 SAML readiness](reviews/rc-2-round-1.md#rc-2-closure--2026-10-14)
closed on 2026-10-14 as historical supporting evidence, not an independent audit or universal provider qualification.

Configure [`SamlServiceProvider.Builder`](https://javadoc.revetsec.com/com/revetsec/saml/SamlServiceProvider.Builder.html)`.observer(`[`SamlObserver`](https://javadoc.revetsec.com/com/revetsec/saml/SamlObserver.html)`)` to receive one start and
one terminal event for each SP operation. Events contain fixed operation and
outcome kinds plus monotonic elapsed time; they never include XML, identities, connection
IDs, request IDs or browser state. Hooks run on the caller's thread, outside replay-store
calls, and a hook failure cannot change a SAML result. The default observer does nothing.

## Trust and account identity

Approve an IdP connection in application configuration. Parse its metadata locally with
[`SamlIdentityProviderMetadata`](https://javadoc.revetsec.com/com/revetsec/saml/SamlIdentityProviderMetadata.html)`.fromXmlResult`, select the expected entity ID, check the
source or a pinned metadata signature, then build [`SamlIdentityProvider`](https://javadoc.revetsec.com/com/revetsec/saml/SamlIdentityProvider.html) with an
application-assigned `connectionId`. The metadata's entity ID is supplied by the IdP and
must not be the tenant or account namespace.
An IdP connection accepts one through eight trusted message-signing keys for
rollover. Metadata-signature verification has a separate one-through-four
trust-key limit; the application selects those anchors separately.
Metadata signing keys use one direct `ds:X509Certificate` per `md:KeyDescriptor`;
publish rollover keys in separate descriptors. Certificate contents must be text-only
Base64 of exactly one certificate with a minimally encoded outer DER sequence.
When a pinned signature covers only the selected entity inside an aggregate, Revetsec
ignores expiry on the unsigned aggregate; only a verified aggregate signature can
authenticate that parent's `validUntil`.

A pinned metadata signature authenticates the selected content; it does not establish
when it was published or obtained. The existing pinned `fromXmlResult` overload accepts
metadata without `validUntil` for applications that manage freshness themselves. Its
`Parsed` result is not an assertion that the metadata is recent or has a bounded age.
For a signed expiry requirement, use
`SamlIdentityProviderMetadata.fromXmlRequiringValidUntilResult(xml, expectedEntityId,
clock, trustedMetadataKeys)`. It requires a future deadline on the signed selected
entity/IdP role or a verified containing aggregate. The earliest covered deadline wins;
an unsigned parent's deadline cannot supply, extend or shorten it. A malformed or expired
covered deadline rejects. Both pinned entry points recheck the applicable deadline after
signature/certificate work; equality is expired, and a clock failure or rollback during
that parse returns `Unavailable`.

Choose and enforce an application maximum acquisition age as well. Record the trusted
acquisition time and source with the approved metadata, cap its use at the earlier of
that time plus the chosen maximum age and any applicable `getValidUntil`, and use a
trusted clock. Deny use if the clock rolls back or acquisition time cannot be trusted.
For undated metadata, the acquisition-age deadline is mandatory in this recipe. A local
reparse, cache hit, restart, or failed refresh must not reset the acquisition time. Renew
it only after a fresh retrieval approved by the application's source/trust policy. This
is a local acquisition-age policy: without authenticated publication-age evidence, it
cannot prove that signed bytes were recently published. A distant signed `validUntil`
does not satisfy a shorter application maximum age. Certificate `notAfter`, an HTTP
cache lifetime, and metadata `cacheDuration` do not substitute for this decision.

Revetsec does not fetch or refresh metadata. Refresh before the effective deadline,
reapprove changed keys/endpoints/entity IDs, and disable the connection if refresh cannot
restore a valid policy before expiry. Check the effective deadline before activating and
while using a `SamlIdentityProvider` built from the snapshot: building the connection does
not carry a live expiry lease or automatically retire old keys/endpoints. Keep the trusted
age anchor across restarts or discard the cached approval and reacquire it. Strict parsing
is an opt-in expiry check; it does not add a metadata cache, rollback floor, revocation
service, publication-age proof or automatic connection renewal.

Use `(connectionId, `[`SamlSubjectKey`](https://javadoc.revetsec.com/com/revetsec/saml/SamlSubjectKey.html)`)` as the application account key. A persistent NameID
produces a subject key. Scope-authorized `subject-id` or `pairwise-id` can also produce one;
the application decides whether to link it to an existing user. Transient identifiers
do not become stable account keys. Treat attributes as IdP assertions, subject to the
application's authorization policy.
The persistent-NameID key preserves the exact qualifier presence and `SPProvidedID`
received on the wire. If an IdP changes an omitted qualifier to its explicit default,
or changes `SPProvidedID`, the same person can receive a different key. Plan account
linking and migration with the IdP; do not silently merge keys using untrusted attributes.

The [`SamlAttribute`](https://javadoc.revetsec.com/com/revetsec/saml/SamlAttribute.html)`.getTypedValues()` preserves the order and shape of each value. Text
values appear in `getValues()`; a sole nested `saml:NameID` is exposed with its
qualifiers and `SPProvidedID`, while other element content remains opaque `COMPLEX`. Neither complex
content nor a mixed text/complex identifier is promoted to a stable subject ID.
An `AttributeValue` declared nil stays opaque. An element-free non-nilled value
remains text regardless of `xsi:type`: exclusive XML canonicalization may leave
the type prefix's namespace binding unsigned, so applications must interpret
domain-specific text types themselves. Applications never receive the raw XML
for an opaque value.

The assertion attribute profile has fixed limits; there is no builder override:

| Limit | How it is counted |
|---|---|
| 128 `Attribute` elements | Total across every `AttributeStatement` in the assertion, including duplicate names and attributes with no values. |
| 256 `AttributeValue` elements | Total across every attribute and statement, including text, nested NameID, nilled and opaque complex values. |
| 4,096 UTF-16 code units per exposed text value | Length of the decoded element-free, non-nilled text, using Java `String.length()`. Supplementary characters use two units; XML escaping and UTF-8 byte length do not change this count. |
| 2,048 UTF-16 code units each for `Name`, `NameFormat` and `FriendlyName` | Each attribute field is checked separately. `Name` must also be nonempty; the other two fields are optional. |

All limits apply together with the response's XML byte and structural limits, so
meeting the attribute limits alone does not guarantee acceptance. They apply to
both SP-initiated and explicitly enabled IdP-initiated login. The 4,096-unit text
limit is not a serialized-size allowance for opaque complex values: that XML is
not exposed or flattened. Nested NameID values follow their separate validation;
an unsupported nested value remains opaque.

A response that reaches attribute validation and exceeds a limit rejects the entire login with
`SamlAuthenticationResult.Reason.ASSERTION_SHAPE`, before replay admission. Revetsec
does not truncate claims or return a partial identity. Store-backed login pending
state is consumed before XML parsing, so it is already spent on this rejection;
clear the browser's pending cookie on every terminal outcome and start a new login.
Configure the IdP to release only the claims the application needs and exercise
its largest expected signed response against these limits before rollout. Do not
trim or rewrite a signed response to make it fit.

Revetsec also requires the checked Assertion to declare SAML version 2.0 and
rejects nilled or misdeclared NameID, Issuer, Audience and authentication-context
scalars. Subject and authentication-statement children must follow the supported
SAML order before identity is released. An `AuthnStatement` must include its required
`AuthnContext`; a signed statement without one is rejected before replay admission.
Each accepted bearer confirmation must have one
unambiguous binding and a forward time window; a redundant confirmation NameID
must match the Subject NameID, its qualifiers and `SPProvidedID`. Conditions, audience
restrictions, OneTimeUse and ProxyRestriction must have supported types and
children. ProxyRestriction applies to downstream proxying; it is not treated as
an audience restriction for this SP.
The signed Assertion itself must place Issuer, optional Signature, Subject,
Conditions and optional Advice in SAML order before its statements. Nilled or
misdeclared AttributeStatement and Attribute containers cannot supply account
identifiers, even when a nested AttributeValue looks valid.

Configure an SP entity ID, HTTPS ACS URL, replay cache, signing credential and optional
decryption credentials. A distributed deployment must supply a replay cache whose
`markIfAbsent` operation is atomic across all nodes. The in-memory implementation is for
one node. For mutually untrusted IdP connections, use
`InMemorySamlReplayCache.fromConnectionLimits(clock, Map.of("employee-idp", 10000,
"partner-idp", 1000))` with the exact application-approved connection IDs. Each
connection owns its full fixed reservation; other connections cannot borrow it,
and unknown or namespace-free admissions cannot spend it. The immutable map has
1–1024 IDs of at most 256 characters and positive quotas totaling at most 1,000,000
live marks. Construction reads no clock. Size each reservation for that connection's
peak login/logout volume over the replay lifetime. `fromLimit`/`fromDefaults` keep
the historical shared-pool quarter-cap heuristic (at least one); that heuristic does
not reserve capacity for an independent healthy connection. Replacing a populated
cache to change configuration requires preserving every still-live replay mark. A shared custom cache must override the
connection-aware `markIfAbsent(connectionId, key, expiresAt, remaining)` operation
to isolate capacity per approved IdP connection; its compatibility default does
not provide isolation. Limit the number of connections an untrusted tenant can
register, and rate-limit verified login and logout requests per connection before
they can fill that connection's quota. Retain each replay key through the absolute
`expiresAt` passed to the cache, without rounding the deadline down; it can be later than an individual
authentication's `getAssertionExpiresAt()` because the same signed assertion may carry
other valid request bindings or time windows. Use a durable atomic pending store across
nodes when a single-use browser pending record is required; a sealed cookie alone does
not provide server-side single use. Rate-limit unauthenticated begin requests before
saving to the in-memory pending store: arbitrary browser bindings can fill its shared
capacity. Expiry maintenance uses an ordered index with one node per retained record,
removing at most 64 unrelated expired records per operation plus an expired addressed
record. Save and consume traffic, including consume misses, gradually drain a backlog;
cleanup never evicts a live attempt to admit another. Consuming a record immediately
unlinks its expiry node, so churn does not leave an unbounded queue of stale nodes.
Operations and conditional validation still share one lock. Keep conditional predicates
bounded: the operation budget limits waiting and checks progress but cannot preempt a
clock or predicate, and does not promise a wall-clock or throughput bound. Clock rollback
denies the operation until the last observed time is reached again, before cleanup or
admission. Capacity, expiry and browser binding checks still apply.

The POST binding accepts canonical **standard Base64** after a single form decode:
`A–Z`, `a–z`, `0–9`, `+`, `/`, with `=` padding required for a final partial quartet
and zero unused pad bits. Complete quartets need no padding. It permits at most 4,096
ASCII space, tab, CR or LF characters anywhere in the decoded SAML field, including
around padding; their combined count is bounded. Other whitespace, URL-safe alphabet,
omitted required padding, noncanonical pad bits and excessive wrapping reject as
`BASE64`. This grammar applies to login SAMLResponse and logout SAMLRequest/SAMLResponse.

Send a literal Base64 `+` as `%2B` in `application/x-www-form-urlencoded` data. A form
`+` means SPACE and counts toward the whitespace allowance; the parser does not repair
it into a Base64 character or percent-decode twice. The existing raw-body limit
(1,061,128 bytes), non-whitespace Base64 limit (349,528 characters), decoded XML limit
(262,144 bytes) and RelayState limit (80 UTF-8 bytes) remain separate. Body/framing
checks run first; the non-whitespace encoded-size cap is enforced before Base64 decoding.
Encoded/decoded-size refusal remains `XML_SIZE`. Successful binding parsing
still yields untrusted bytes, not a verified SAML message or an authenticated RelayState.

Before rollout, fix senders that omit padding, emit nonzero pad bits or exceed the
wrapping allowance. Existing canonical padded output and bounded CR/LF wrapping remain
supported. Do not repair or normalize a rejected request into an admitted login/logout;
retain the original form body and header multiplicity for binding parsing, then perform
the existing signature, pending-state and replay checks.

## Browser sign-in

1. Call `beginAuthenticationResult(idp)` for HTTP-Redirect, or
   `beginPostAuthenticationResult(idp)` for HTTP-POST. The prepared result contains a
   redirect URI or form and a [`PendingSamlAuthentication`](https://javadoc.revetsec.com/com/revetsec/saml/PendingSamlAuthentication.html).
2. Before sending the browser to the IdP, save pending state through a browser-bound,
   Secure, HttpOnly cookie or through [`PendingSamlAuthenticationStore`](https://javadoc.revetsec.com/com/revetsec/saml/PendingSamlAuthenticationStore.html). Prefer a
   `__Host-` cookie with `Path=/` and no `Domain` attribute. For a cross-site
   IdP POST to the ACS, use `SameSite=None; Secure`. Use the same application context and
   [`BrowserBinding`](https://javadoc.revetsec.com/com/revetsec/BrowserBinding.html) when constructing [`PendingSamlAuthenticationSource`](https://javadoc.revetsec.com/com/revetsec/saml/PendingSamlAuthenticationSource.html) later. Generate new values with `BrowserBinding.fresh()` or restore the exact value from protected server persistence. Do not type a raw ACS cookie with `fromTrustedPersistence`; use it only to select/compare the server-retained attempt, then pass that attempt's carrier. SAML retains its existing nonempty 4,096-Java-code-unit limit and exact raw spelling, including historically accepted unmatched-surrogate strings. The broad carrier does not normalize them. The low-level pending-store SPI remains an opaque raw-`String` compatibility boundary.
3. At the ACS, retain the original POST body, every Content-Type value and the raw query.
   Decode with [`SamlPostBindingMessage`](https://javadoc.revetsec.com/com/revetsec/saml/SamlPostBindingMessage.html)`.fromFormBodyResult`, then call
   `completeAuthenticationResult`. Clear the pending browser cookie on every terminal
   outcome. Only `Succeeded` contains a checked identity.
4. Rotate the application's browser session ID after local account mapping, then
   create or update that session. Persist
   [`SamlAuthentication`](https://javadoc.revetsec.com/com/revetsec/saml/SamlAuthentication.html)`.getSessionReference()` if front-channel logout is enabled.
   Use `toSerializedForm()` and `fromSerializedFormResult()` only in trusted server-side
   storage. For browser-side storage, use `toSealedFormResult(sealer, sessionContext,
   expiresAt)` and `fromSealedFormResult(...)`; bind the context to the application's
   own browser session and choose an expiry no later than that session's lifetime.
   Only `SamlSessionReferenceSealResult.Succeeded` supplies a sealed value.
   `TooLarge` is an expected size refusal; persist the complete reference in trusted
   server-side storage and use an opaque browser session ID, or decline session creation
   if required logout continuity cannot be stored. `Unavailable` means the cryptographic
   provider could not seal; do not publish a browser session whose required continuity
   has not been persisted. The existing `toSealedForm(...)` convenience throws for these
   failures. Null or invalid arguments remain programmer errors in either method.
   Only [`SamlSessionReferenceParseResult.Succeeded`](https://javadoc.revetsec.com/com/revetsec/saml/SamlSessionReferenceParseResult.Succeeded.html) supplies restored logout continuity fields. Structural rejection and opaque sealed-state rejection have separate variants. Neither form creates a fresh identity.

The version-1 trusted storage form is bounded to 66,631 ASCII characters. That bound
includes UTF-8 and base64url expansion of every well-formed field at its existing
validation limit; no identifier or qualifier is shortened. Use storage and transport
quotas that cover the complete form, which contains personal data. Readers from before
this correction reject serialized forms over 32,768 characters: deploy the wider reader
everywhere that restores references before writers persist larger ones, and retain it
through any rollback or migration. Existing small version-1 forms keep the same grammar.
If the same application nodes both read and write references, hold an application write
gate at `serialized.length() <= 32_768` during the mixed-version phase, or quiesce those
writes until every reader is upgraded. Decline session creation when required continuity
cannot be stored under that temporary gate. Keep the wider reader on rollback until
larger stored references have been migrated or their application sessions revoked.

The serialized allowance does not change `StateSealer.Builder.maximumSealedLength`: its default
is 3,800 characters and its configurable range remains 1,024–16,384. Some valid references
cannot fit even the largest seal. The result method checks the actual active key-ID
overhead and complete serialized plaintext before random draws or encryption. A
`TooLarge` outcome must not trigger truncation or an unchecked cap increase. Browser
cookie/header budgets still apply separately; keep large references server-side and
establish the protected session only after its required logout continuity is stored.
Sealed values retain the SAML-specific type, context, keys and expiry checks.

Pending login and logout records use a separate bounded version-3 codec. The SP/IdP
entity IDs retain their 2,048 UTF-16-code-unit limits and connection IDs retain 256;
text must be well formed. Their UTF-8 field ceilings are 6,144 and 768 bytes respectively,
with decoded character limits checked separately. ACS and both SP logout receiver URLs
must fit 2,048 ASCII URI characters, including percent expansion; an overlong receiver
is rejected at configuration. Authentication contexts retain at most eight absolute URIs
of 512 UTF-16 code units each; application data retains its strict 512-byte UTF-8 limit.
No identifier or option is truncated or normalized to make a record fit.

Individual field validity does not guarantee the complete pending record will fit the
configured sealer. Both `saveToResult` methods preflight the complete ASCII codec frame,
active key ID and seal overhead. A size refusal returns `UNAVAILABLE` without store calls
or sealing entropy; no record was saved. Shorten configuration/options before retrying,
and persist successfully before sending a login or logout request. The existing
`toSealedForm` convenience throws `IllegalArgumentException` on size refusal. Invalid
contexts remain argument errors, while a possibly completed store operation remains
`INDETERMINATE`. The sealer's default and maximum limits and cookie/header budgets stay
separate; increasing a cap is not a substitute for successful pending-state persistence.

For a rolling upgrade, deploy the corrected readers on every callback node before
writers can emit Unicode IDs whose UTF-8 form exceeds the previous 2,048/256-byte field
limits. Existing readers reject those new records even though they use the same version-3
grammar. Otherwise quiesce new attempts and drain or discard pending attempts before
upgrading all nodes. Do not roll readers back while such records remain live; wait for
expiry or invalidate the attempts. Versions 1/2 and existing valid version-3 records
remain readable; no keys, seal types, contexts or store SPI change.

The [`SamlAuthenticationRequestOptions`](https://javadoc.revetsec.com/com/revetsec/saml/SamlAuthenticationRequestOptions.html) can request fresh authentication, passive behavior,
an exact authentication context, and bounded local application data. Revetsec seals the
options in pending state and checks the returned assertion against them. RelayState is
an opaque correlation handle, never a return URL. Validate application data as a local
route before using it for a redirect.

A request-bound non-success IdP response produces `StatusReceived` only when the
Response, Issuer and Status have the supported SAML shape. `isAuthenticated()` is
true only when the IdP signature covers that Response. Malformed status structures
are rejected and never promoted to a provider status result.
For a `Requester` or `Responder` primary code, an immediate `AuthnFailed`,
`NoAuthnContext` or `RequestDenied` subcode supplies `getStatusCode()`. An unknown
immediate subcode falls back to the primary classification; deeper extension codes
are validated but cannot override it. `VersionMismatch` retains its primary
classification. Existing flat non-success mappings, including `OTHER` for unknown
flat codes, remain accepted for compatibility. This bounded diagnostic does not
establish signature provenance: an unsigned error response still reports
`isAuthenticated() == false` and never supplies an identity. Login requires a flat
Success status before assertion admission; a nested PartialLogout cannot authenticate
an assertion.

IdP-initiated SSO is disabled by default. A selected IdP connection can enable
[`SamlCompatibilityMode`](https://javadoc.revetsec.com/com/revetsec/saml/SamlCompatibilityMode.html)`.UNSOLICITED_RESPONSES`; Revetsec then rejects RelayState and
applies a shorter response-age bound. Apply explicit application session and account
linking policy to this flow.

## Metadata, encryption and logout

The [`SamlServiceProviderMetadata`](https://javadoc.revetsec.com/com/revetsec/saml/SamlServiceProviderMetadata.html)`.fromServiceProviderResult(sp)` publishes SP metadata with
an explicit signing `KeyDescriptor`. When decryption credentials are configured, it
advertises GCM and RSA-OAEP, not CBC. Publish metadata only after choosing stable
entity, ACS and logout URLs and the active certificate. Keep old decryption credentials
during rollover until old assertions can no longer arrive.

Encrypted assertions and encrypted NameID use the configured SP private keys. AES-GCM
with RSA-OAEP is the preferred profile. `AES_CBC_ENCRYPTION` is a per-IdP compatibility
mode and requires a verified signature over the whole Response before CBC decryption.
RSA1_5 key transport is rejected.
Before a valid enclosing signature has been verified, an encrypted assertion must
resolve to exactly one `EncryptedKey`. Revetsec tries that candidate against every
configured decryption credential, up to four RSA-OAEP unwrap attempts. Multiple
resolved candidates reject before private-key work, with the same fixed `DECRYPTION`
rejection used for unwrap/content-decryption failures. No candidate is silently
selected by position or truncated out of an ambiguous set.

Inline keys and same-document `RetrievalMethod` references retain their existing
bounded resolution rules. One reference may select a single key among up to eight
sibling keys; unselected siblings do not create unwrap attempts. `Recipient` and
`KeyName` hints are not proof of sender identity or authority to select a local
credential. All configured rollover credentials are tried even after a successful
unwrap; failed unwraps retain the substitute-key content-decryption path, and a
substitute can never supply accepted plaintext.

After a configured peer's signature covering the exact ciphertext is verified,
the existing maximum of eight candidates times four credentials remains available
per encrypted object. A verified outer Response supplies this proof for an encrypted
assertion. An encrypted NameID is processed only after a covering Response or
Assertion signature has been verified. Assertion-only proof permits the wider
GCM key handling but does not enable CBC: CBC still requires the signed outer
Response and the connection's explicit opt-in.

This narrows the unsigned multi-key profile. Before upgrading a connection that
sends several wrapped keys without an outer signature, configure its IdP to select
one SP encryption certificate/one resolved wrapped key, or to sign the outer Response.
Keep the current and necessary rollover credentials on the SP; one wrapped key can
still target any of the four. Do not merely reorder ambiguous keys or relax the
work bound to make such a response fit.

The bound is at most four RSA-OAEP unwrap calls before cryptographic sender proof,
not a wall-clock or constant-time guarantee. Later semantic and replay admission
still apply. An unsigned outer message with a verified inner assertion can reach
36 calls across an encrypted assertion and encrypted NameID; a signed outer message
can reach 64 across those two objects. Signed replays can still incur this work
before rejection. Rate-limit inbound ACS requests before XML decryption and size
the active/rollover key set for the deployment. Signature-layer failures remain
signature failures; the opaque decryption category does not authenticate a message
or promise identical total request timing.

Some IdPs prioritize the SP metadata's advertised GCM algorithms over their own
CBC setting. In the Shibboleth 5.2.3 capture, the generated metadata selected
GCM even with Shibboleth configured for CBC. A CBC-only connection therefore
needs an explicitly approved IdP-facing metadata variant without those algorithm
hints, while retaining the same SP entity ID, signing certificate, encryption
certificate and ACS. Keep CBC enabled only for that connection and require a
signed Response; do not change the default generated metadata for other IdPs.
The SimpleSAMLphp 2.5.0 capture demonstrates a signed CBC Response that works
with this per-IdP opt-in. Its assertion-signed CBC Response with no outer
Response signature is rejected, even when CBC is enabled.

For SP-initiated logout, call `beginLogoutResult(idp, sessionReference)`, retain its
pending logout state, **end the local application session before sending** the signed
Redirect, and send it. A failed or missing IdP return must not restore that session.
At the logout endpoint, parse the raw query with
[`SamlRedirectBindingMessage`](https://javadoc.revetsec.com/com/revetsec/saml/SamlRedirectBindingMessage.html)`.fromRawQueryResult` and call `completeLogoutResult` to
report a verified IdP terminal status and clear pending state, or clear it when the attempt
expires. Invalid callbacks preserve a live attempt and its browser cookie. The Playground
follows this order.
For stored pending state, an invalid Redirect signature is rejected before the pending
record is consumed; a valid response still consumes the record once.
For an IdP-initiated LogoutRequest, call `acceptLogoutRequestResult`, match its NameID
qualifiers and SessionIndex against stored [`SamlSessionReference`](https://javadoc.revetsec.com/com/revetsec/saml/SamlSessionReference.html)s within the same
connection ID, end only matching sessions, then call `respondToLogoutRequestResult`.
An unmatched SessionIndex ends no application session.
The pinned SimpleSAMLphp 2.5.0 interoperability capture exercises both directions
against a real IdP. Revetsec accepts its signed IdP-initiated LogoutRequest and
the IdP accepts Revetsec's signed LogoutResponse. Revetsec also sends a signed
SP-initiated LogoutRequest that the IdP accepts; Revetsec accepts the IdP's
signed LogoutResponse. Both captured SSO sessions and logout messages are
replayed with their identity, request and RelayState bindings in offline tests.
For HTTP-POST logout, configure the SP's `postSingleLogoutServiceUrl` and the IdP's
`postSingleLogoutService`. IdP metadata parsing exposes `getPostSingleLogoutService`,
plus a distinct `getPostSingleLogoutResponseService` when `ResponseLocation` is present;
the Redirect binding has the corresponding response getter. Responses use that distinct
endpoint while outbound LogoutRequests use `Location`. Generated SP metadata advertises
POST logout only when its receiver is configured.
Each binding uses its explicitly configured endpoint; no binding fallback is selected implicitly.

For SP-initiated POST logout, call `beginPostLogoutResult`, save
`Prepared.getPendingLogout()`, end the local application session, then deliver
`Prepared.getPostForm()`. At the POST logout receiver, retain the raw form body,
every Content-Type value and raw query; parse them with
[`SamlPostBindingMessage`](https://javadoc.revetsec.com/com/revetsec/saml/SamlPostBindingMessage.html)`.fromLogoutFormBodyResult`. A `Kind.RESPONSE` is completed
with the POST overload of `completeLogoutResult`. Pending browser cookies need
`SameSite=None; Secure`, with `HttpOnly`; use the same `__Host-` scope as sign-in.
Clear them after a verified `Succeeded` or
`StatusReceived` outcome, or when the attempt expires; a rejected callback does not
cancel a valid pending attempt. Reconcile unavailable or indeterminate store outcomes
before retrying. Once a pending store confirms removal, any later validation or replay-admission
failure returns `Indeterminate`; do not assume that state remains reusable. A durable pending
store still supplies atomic single use across nodes. The login
factory `fromFormBodyResult` remains response-only and does not accept `SAMLRequest`.

For an IdP-initiated POST `Kind.REQUEST`, call the POST overload of
`acceptLogoutRequestResult`, match the checked NameID qualifiers and SessionIndex
against the selected connection's stored sessions, end only matching sessions,
then call `respondToPostLogoutRequestResult`. Both POST preparation methods produce
an RSA-SHA256 enveloped XML signature over the exact logout root, using the same
XML-signature profile as POST authentication requests. [`SamlPostForm`](https://javadoc.revetsec.com/com/revetsec/saml/SamlPostForm.html) renders either
a `SAMLRequest` or `SAMLResponse` and echoes bounded RelayState as an opaque field.
RelayState is outside the XML signature and must never become an application redirect URL.

POST receivers require a signature covering the original logout root and use the
same pinned IdP signing keys, rollover and explicit SHA1 compatibility rules as SSO.
Unsigned roots, nested/duplicate signatures, external references and signature wrapping
are rejected. Signature and response-semantic rejection occur before pending-state
consumption or replay writes in both bindings. Pending SP, IdP connection/entity,
endpoint, expiry, RelayState and request correlation are checked against the
authenticated sealed record before atomic removal. Custom pending stores must
implement `consumeIfMatches`: validate the supplied opaque record with the predicate,
then atomically remove only that same live record if it matched. A distributed store
can use a read followed by compare-and-delete of the exact approved record; an
unconditional consume or consume-and-restore is insufficient. The default method
returns unavailable without consuming, so legacy custom stores fail closed for logout
until they implement this operation. Login retains its existing consume contract.
Both bindings share the same strict logout semantic checks and atomic replay keys,
scoped by SP, IdP connection, message kind and ID; changing the binding cannot admit
an already accepted message a second time. Successful logout admissions retain their
replay key until the signed IssueInstant plus the supported maximum response age
(15 minutes) and maximum clock skew (5 minutes), even when the accepting instance
uses a narrower time policy. Each instance still rejects messages outside its own
configured age/skew window. This prevents replay during policy changes or mixed-policy
deployments sharing the same cache. Replay-cache failures release no accepted request
or accepted provider status. The new POST paths are covered by
`SamlPostLogoutTests`, `SamlPostLogoutMetadataTests`, `ScriptedIdpSsoIT` and
`KeycloakSamlIT`; the Redirect captures remain evidence for their documented binding.

Both Redirect logout entry points verify the query signature and require the supported SAML
element order and types before accepting identity fields or status. Nilled fields,
unexpected direct text and malformed status hierarchies are rejected. The supported Redirect logout
profile uses Issuer, NameID and optional SessionIndex elements in a request, and
Issuer followed by Status in a response. Both Redirect and POST validate a single
StatusCode chain of at most 32 code elements, including the primary. Siblings, empty
codes, wrong namespaces and any subordinate Success are rejected. A response may also carry
the standard optional StatusMessage and StatusDetail in order; these fields do not
change the checked outcome or expose IdP text through the result.

After signature verification, exact pending binding and successful replay admission,
logout completion distinguishes these fixed outcomes:

| Provider status | Result |
|---|---|
| Flat Success | `SamlLogoutResult.Succeeded.INSTANCE` |
| Success with immediate PartialLogout | `SamlLogoutResult.StatusReceived.PARTIAL_LOGOUT` |
| A well-shaped non-success primary, with or without subordinate detail | `SamlLogoutResult.StatusReceived.NON_SUCCESS` |
| Success with a different immediate subcode | `SamlLogoutResult.Rejected.INSTANCE` |

PartialLogout is the authority's authenticated report that its own logout completed
but not every other participant confirmed logout; it is not complete global logout
or proof that the application's local sessions ended. Deeper extension codes are
validated but cannot upgrade a partial outcome to success. A non-success primary
with PartialLogout detail remains `NON_SUCCESS`. Both reported status outcomes
finish the pending attempt and are replay-fenced; clear the pending cookie as above
and reconcile incomplete logout under application policy. Do not retry the same
callback as a fresh operation. Update exhaustive switches for the added enum value;
unknown outcomes must not be treated as complete success. These distinctions follow
[SAML Core §§3.2.2.2 and 3.7.3.2](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf);
the application continues to own its local session lifecycle.

Protocol and assertion IDs must be XML NCNames. Logout request and response replay
entries use separate message-kind domains, even when the IdP reuses an ID.
IdP Redirect SSO and logout endpoints may carry their own query fields. Revetsec
preserves those fields ahead of the signed SAML binding fields. POST SSO actions may
also carry ordinary query fields. All three paths reject binding-field name collisions,
empty field names, unencoded spaces, decoded control characters, and malformed percent-encoding or UTF-8
in names or values.

The Soklet adapter's [`SokletSaml`](https://javadoc.revetsec.com/com/revetsec/soklet/SokletSaml.html) and both Servlet adapters' [`ServletSaml`](https://javadoc.revetsec.com/com/revetsec/servlet/jakarta/ServletSaml.html) pass raw
request fields to core and write prepared Redirect/form responses. Their dedicated
`postLogoutBindingResultFor` helper preserves the POST logout boundary, and typed
POST logout request/response form helpers preserve the core-rendered fields and headers. The
[local Soklet Playground](../examples/playground/README.md) demonstrates one approved
IdP, sealed browser pending state, local account mapping and both Redirect logout
directions. The adapter verification tooling includes POST logout transport checks in real Tomcat
containers; those checks qualify transport preservation, while the core interop tests
exercise protocol partners.

## Explicit type declarations and namespace coverage

Structural SAML `xsi:type` declarations are accepted only when the type uses the consumed element's own nonempty prefix, its expanded namespace is the expected type namespace, and its local type name is exact. This keeps type interpretation tied to a visibly used element-name binding when that element is covered by the required signature. Signature coverage, structural validation and all transaction/identity/replay checks must each still pass.

A prefix used only inside an attribute value can be omitted by exclusive canonicalization; see the [W3C limitations](https://www.w3.org/TR/xml-exc-c14n/#sec-Limitations). Merely declaring that prefix locally does not authenticate the binding. Revetsec deliberately refuses such aliases and redundant XML Schema type annotations on SAML text fields, including `xs:anyURI`, even if a particular signer included extra namespace context. Have the sender omit redundant annotations or use the supported SAML element prefix before signing. Never strip or rewrite a received signed document to make it fit. This is the accepted 1.0.0 input profile; qualify actual IdP output after adoption.

The earlier AttributeValue rule is unchanged: leaf text is exposed without interpreting mutable type-prefix bindings, while literal `xsi:nil` and element structure still apply. It creates no typed Boolean/number or whole-schema-validation claim. Unprefixed or malformed type values, wrong type-local names and nilled structural data retain refusal. Logout request/response/issuer/session-index callers use the same declaration rule; full browser/provider and final candidate qualification remain separate.
