# SAML service provider integration

Revetsec prepares SAML requests and checks POST responses and signed Redirect or POST logout messages.
If JVM-global XML-signature secure validation is disabled, the SP builder fails unless the
application explicitly calls `acknowledgeGlobalSecureValidationDisabled(true)`. This choice
is reported to [`SamlObserver`](https://javadoc.revetsec.com/com/revetsec/saml/SamlObserver.html) at build time. Revetsec sets secure validation on each
verification context and enforces its signature allowlists even when the JVM policy differs.
The application owns its users, account links, browser sessions, pending-state transport,
and the decision to end a session. SAML support is pre-release; the scripted IdP and a
pinned Keycloak container exercise browser flows. [RC-2 SAML readiness](reviews/rc-2-round-1.md#rc-2-closure--2026-10-14)
closed on 2026-10-14; other 1.0.0 release checkpoints remain open.

Configure [`SamlServiceProvider.Builder`](https://javadoc.revetsec.com/com/revetsec/saml/SamlServiceProvider.Builder.html)`.observer(`[`SamlObserver`](https://javadoc.revetsec.com/com/revetsec/saml/SamlObserver.html)`)` to receive one start and
one terminal event for each service-provider operation. Events contain fixed operation and
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
one node and reserves at most one quarter of its configured live entries per IdP
connection (at least one). Size the cache for each connection's peak login and logout
volume over the replay lifetime. A shared custom cache must override the
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
capacity, and its expiry cleanup scans live entries under one lock.

## Browser sign-in

1. Call `beginAuthenticationResult(idp)` for HTTP-Redirect, or
   `beginPostAuthenticationResult(idp)` for HTTP-POST. The prepared result contains a
   redirect URI or form and a [`PendingSamlAuthentication`](https://javadoc.revetsec.com/com/revetsec/saml/PendingSamlAuthentication.html).
2. Before sending the browser to the IdP, save pending state through a browser-bound,
   Secure, HttpOnly cookie or through [`PendingSamlAuthenticationStore`](https://javadoc.revetsec.com/com/revetsec/saml/PendingSamlAuthenticationStore.html). Prefer a
   `__Host-` cookie with `Path=/` and no `Domain` attribute. For a cross-site
   IdP POST to the ACS, use `SameSite=None; Secure`. Use the same application context and
   browser binding when constructing [`PendingSamlAuthenticationSource`](https://javadoc.revetsec.com/com/revetsec/saml/PendingSamlAuthenticationSource.html) later.
3. At the ACS, retain the original POST body, every Content-Type value and the raw query.
   Decode with [`SamlPostBindingMessage`](https://javadoc.revetsec.com/com/revetsec/saml/SamlPostBindingMessage.html)`.fromFormBodyResult`, then call
   `completeAuthenticationResult`. Clear the pending browser cookie on every terminal
   outcome. Only `Succeeded` contains a checked identity.
4. Rotate the application's browser session ID after local account mapping, then
   create or update that session. Persist
   [`SamlAuthentication`](https://javadoc.revetsec.com/com/revetsec/saml/SamlAuthentication.html)`.getSessionReference()` if front-channel logout is enabled.
   Use `toSerializedForm()` and `fromSerializedFormResult()` only in trusted server-side
   storage. For browser-side storage, use `toSealedForm(sealer, sessionContext,
   expiresAt)` and `fromSealedFormResult(...)`; bind the context to the application's
   own browser session and choose an expiry no later than that session's lifetime.
   Only [`SamlSessionReferenceParseResult.Succeeded`](https://javadoc.revetsec.com/com/revetsec/saml/SamlSessionReferenceParseResult.Succeeded.html) supplies restored logout continuity fields. Structural rejection and opaque sealed-state rejection have separate variants. Neither form creates a fresh identity.

The [`SamlAuthenticationRequestOptions`](https://javadoc.revetsec.com/com/revetsec/saml/SamlAuthenticationRequestOptions.html) can request fresh authentication, passive behavior,
an exact authentication context, and bounded local application data. Revetsec seals the
options in pending state and checks the returned assertion against them. RelayState is
an opaque correlation handle, never a return URL. Validate application data as a local
route before using it for a redirect.

A request-bound non-success IdP response produces `StatusReceived` only when the
Response, Issuer and Status have the supported SAML shape. `isAuthenticated()` is
true only when the IdP signature covers that Response. Malformed status structures
are rejected and never promoted to a provider status result.

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
An encrypted assertion with no outer Response signature can require several private-key
operations before its inner signature can be checked. Limit each connection to the
current and necessary rollover decryption keys, and rate-limit inbound ACS requests
before XML decryption.

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
or successful status. The new POST paths are covered by
`SamlPostLogoutTests`, `SamlPostLogoutMetadataTests`, `ScriptedIdpSsoIT` and
`KeycloakSamlIT`; the Redirect captures remain evidence for their documented binding.

Both Redirect logout entry points verify the query signature and require the supported SAML
element order and types before accepting identity fields or status. Nilled fields,
unexpected direct text and nested status codes are rejected. The supported Redirect logout
profile uses Issuer, NameID and optional SessionIndex elements in a request, and
Issuer followed by a single flat StatusCode in a response. A response may also carry
the standard optional StatusMessage and StatusDetail in order; these fields do not
change the checked outcome or expose IdP text through the result.
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
