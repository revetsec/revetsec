# SAML service provider integration

Revetsec prepares SAML requests and checks POST responses and Redirect logout messages.
The application owns its users, account links, browser sessions, pending-state transport,
and the decision to end a session. SAML support is pre-release; the scripted IdP and a
pinned Keycloak container exercise browser flows, while RC-2 interoperability and
hostile-input work is still open.

## Trust and account identity

Approve an IdP connection in application configuration. Parse its metadata locally with
`SamlIdentityProviderMetadata.fromXmlResult`, select the expected entity ID, check the
source or a pinned metadata signature, then build `SamlIdentityProvider` with an
application-assigned `connectionId`. The metadata's entity ID is supplied by the IdP and
must not be the tenant or account namespace.

Use `(connectionId, SamlSubjectKey)` as the application account key. A persistent NameID
produces a subject key. Scope-authorized `subject-id` or `pairwise-id` can also produce one;
the application decides whether to link it to an existing user. Transient identifiers
do not become stable account keys. Treat attributes as IdP assertions, subject to the
application's authorization policy.

`SamlAttribute.getTypedValues()` preserves the order and shape of each value. Text
values appear in `getValues()`; a sole nested `saml:NameID` is exposed with its
qualifiers, while other element content remains opaque `COMPLEX`. Neither complex
content nor a mixed text/complex identifier is promoted to a stable subject ID.
An `AttributeValue` declared nil or with a non-string `xsi:type` also stays opaque;
an explicit XML Schema string type remains text. Applications never receive the
raw XML for an opaque value.
Revetsec also requires the checked Assertion to declare SAML version 2.0 and
rejects nilled or misdeclared NameID, Issuer, Audience and authentication-context
scalars. Subject and authentication-statement children must follow the supported
SAML order before identity is released. Each accepted bearer confirmation must have one
unambiguous binding and a forward time window; a redundant confirmation NameID
must match the Subject NameID and all its qualifiers. Conditions, audience
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
one node. Use a durable atomic pending store across nodes when a single-use browser
pending record is required; a sealed cookie alone does not provide server-side single use.

## Browser sign-in

1. Call `beginAuthenticationResult(idp)` for HTTP-Redirect, or
   `beginPostAuthenticationResult(idp)` for HTTP-POST. The prepared result contains a
   redirect URI or form and a `PendingSamlAuthentication`.
2. Before sending the browser to the IdP, save pending state through a browser-bound,
   Secure, HttpOnly cookie or through `PendingSamlAuthenticationStore`. For a cross-site
   IdP POST to the ACS, use `SameSite=None; Secure`. Use the same application context and
   browser binding when constructing `PendingSamlAuthenticationSource` later.
3. At the ACS, retain the original POST body, every Content-Type value and the raw query.
   Decode with `SamlPostBindingMessage.fromFormBodyResult`, then call
   `completeAuthenticationResult`. Clear the pending browser cookie on every terminal
   outcome. Only `Succeeded` contains a checked identity.
4. Create or update the application's own session after local account mapping. Persist
   `SamlAuthentication.getSessionReference()` if front-channel logout is enabled.

`SamlAuthenticationRequestOptions` can request fresh authentication, passive behavior,
an exact authentication context, and bounded local application data. Revetsec seals the
options in pending state and checks the returned assertion against them. RelayState is
an opaque correlation handle, never a return URL. Validate application data as a local
route before using it for a redirect.

IdP-initiated SSO is disabled by default. A selected IdP connection can enable
`SamlCompatibilityMode.UNSOLICITED_RESPONSES`; Revetsec then rejects RelayState and
applies a shorter response-age bound. Apply explicit application session and account
linking policy to this flow.

## Metadata, encryption and logout

`SamlServiceProviderMetadata.fromServiceProviderResult(sp)` publishes SP metadata with
an explicit signing `KeyDescriptor`. When decryption credentials are configured, it
advertises GCM and RSA-OAEP, not CBC. Publish metadata only after choosing stable
entity, ACS and logout URLs and the active certificate. Keep old decryption credentials
during rollover until old assertions can no longer arrive.

Encrypted assertions and encrypted NameID use the configured SP private keys. AES-GCM
with RSA-OAEP is the preferred profile. `AES_CBC_ENCRYPTION` is a per-IdP compatibility
mode and requires a verified signature over the whole Response before CBC decryption.
RSA1_5 key transport is rejected.

For SP-initiated logout, call `beginLogoutResult(idp, sessionReference)`, retain its
pending logout state, and send the signed Redirect. At the logout endpoint, parse the
raw query with `SamlRedirectBindingMessage.fromRawQueryResult` and call
`completeLogoutResult`. End the application session only after the checked result.
For an IdP-initiated LogoutRequest, call `acceptLogoutRequestResult`, match its NameID
qualifiers and SessionIndex against stored `SamlSessionReference`s within the same
connection ID, end only matching sessions, then call `respondToLogoutRequestResult`.
An unmatched SessionIndex ends no application session.

The Soklet adapter's `SokletSaml` and both Servlet adapters' `ServletSaml` pass raw
request fields to core and write prepared Redirect/form responses. The
[local Soklet Playground](../examples/playground/README.md) demonstrates one approved
IdP, sealed browser pending state, local account mapping and both Redirect logout
directions. Real servlet container qualification remains open release work.
