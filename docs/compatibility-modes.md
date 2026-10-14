# Compatibility Modes

**Status: pre-release.** The registry below describes implemented JOSE, OAuth, OIDC and SAML switches. SAML interoperability and release qualification are still in progress.

A compatibility mode is a named, explicit relaxation that lets Revetsec work with a provider or a deployment that departs from a specification or from Revetsec's defaults. The rules for every mode:

- It is off by default.
- It is set per instance: per client, per identity provider or per tenant, never globally.
- It has an entry on this page, and tests cover both the enabled and the disabled state.
- It is never switched on by detecting a provider automatically.
- Named presets bundle modes for one provider. A preset only widens what is accepted, and every change to a preset is recorded in the CHANGELOG.

Some relaxations are never available as a mode: accepting an unsigned message where a signature is required, the JOSE `none` algorithm, and unauthenticated AES-CBC decryption.

## Registry

Each entry gives the mode's name, protocol area, effect, conditions and safeguards, the tests that cover it (named relative to [`src/test/java/com/revetsec/`](../src/test/java/com/revetsec/)), and the release that added it. There are no presets yet.

### `acceptAnyAudience(true)`

- **Where:** `JwtValidator.Builder` (JOSE).
- **Effect:** the validator does not compare the token's `aud` claim with any expected audience, and `aud` is no longer required. An `aud` that is present must still be a string or a non-empty array of strings. Every other check still applies: the signature, `iss`, `exp`, `nbf` and `iat`, the key rules, the required claims and the refusal of `cnf`.
- **Risk:** a token the same issuer issued for another application is accepted. Use it only when the issuer serves this application alone.
- **Safeguards:** it cannot be combined with `expectedAudiences`: setting both makes `build()` throw `IllegalArgumentException`. Without it, `build()` throws `IllegalStateException` unless expected audiences are set. It is reported to `JoseObserver.didAcceptAnyAudience(issuer)` when the validator is built and on every `validate()` call, whatever the outcome.
- **Tests:** `jose.JwtValidatorBuilderTests` (`missingRequiredSettingsAreIllegalState`, `audienceSettingsThatConflictOrAreEmptyAreIllegalArguments` and `acceptingAnyAudienceIsObservedAtBuild`), `jose.JoseObserverTests.acceptingAnyAudienceIsObservedOnEveryValidation`, and, for the disabled state, `jose.JwtValidatorClaimsTests.theAudienceMustNameAnExpectedAudience`.
- **Added in:** 1.0.0 (unreleased).

### `acknowledgeUnpatchedRuntime(true)`

- **Where:** `RemoteJsonWebKeySource.Builder` (JOSE) and `OAuthClient.Builder` (OAuth).
- **Effect:** the source builds and fetches on a Java runtime below Revetsec's minimum for network I/O, 17.0.3 (18.0.1 on Java 18), whose TLS and certificate checks are exposed to CVE-2022-21449 (ECDSA signature verification). Without it, `build()` throws `IllegalStateException` on such a runtime.
- **Safeguards:** while the runtime is below the minimum, the choice is reported to `JoseObserver.didUseUnpatchedRuntime(runtimeVersion)` when a key source is built and on every fetch, or when an `OAuthClient` is built. On a runtime at or above the minimum, the setting changes nothing and nothing is reported. Revetsec's own ECDSA range check protects the tokens a validator verifies on every runtime; what the setting accepts is the runtime's own TLS. A `StaticJsonWebKeySource` does no I/O and never needs the setting.
- **Tests:** `jose.RemoteJsonWebKeySourceBuilderTests.theRuntimeFloorIsEnforcedAndAnAcknowledgmentIsObserved` (17.0.2, 18, 17.0.2.0.1 and 17-ea each refused unless acknowledged, and reported at build and on every fetch), `aRuntimeAtOrAboveTheFloorIsNeverReported`, and `oauth.OAuthClientRuntimeFloorTests` (the Java 18.0.0 release is represented by `Runtime.Version.parse("18")`).
- **Added in:** 1.0.0 (unreleased).

### `ClientSecretBasicEncoding.UNENCODED`

- **Where:** `ClientAuthentication.fromClientSecretBasic(secret, encoding)` (OAuth).
- **Effect:** the client ID and secret are joined with `:` as supplied before Base64, instead of each being form-encoded as RFC 6749 Appendix B requires. It exists for an explicitly configured provider that expects these bytes. It cannot place a secret in the request URI, and no second client-authentication method is added.
- **Risk:** some credentials become ambiguous to a provider parser, especially a client ID containing `:`. Use `FORM_URLENCODED`, the default, unless provider evidence requires the alternative.
- **Safeguards:** the mode is selected per `ClientAuthentication` instance. `OAuthObserver.didUseUnencodedBasic()` is called when its client is built and on every token or revocation request that uses it, with no credential value.
- **Tests:** `oauth.ClientAuthenticationTests.explicitUnencodedCompatibilityChangesBytes`, `unencodedBasicIsObservedAtBuildAndUse`, and `basicFormEncodesBothFieldsBeforeJoining` (default mode).
- **Added in:** 1.0.0 (unreleased).

### `OidcCompatibilityMode.HMAC_ID_TOKENS`

- **Where:** `OidcClient.Builder.compatibility(Set<OidcCompatibilityMode>)` (OIDC).
- **Effect:** permits explicitly allowlisted `HS256`, `HS384` or `HS512` ID tokens. The default allowlist remains `{RS256}`, and provider advertisement still restricts the effective set. The mode does not enable HMAC in ordinary `JwtValidator` or signed UserInfo.
- **Conditions:** confidential client-secret Basic or POST authentication; the exact secret's UTF-8 bytes must be at least 32/48/64 bytes for each configured HMAC algorithm, respectively. The secret is not base64-decoded. Length is checked at build, before each token POST and again by the HMAC verifier. Use a high-entropy secret. A supplier is called once at build and once per token POST; keep it fast and thread-safe.
- **Risk:** the client and provider share the MAC key and can both construct ID tokens. Keep the secret private. An asymmetric public key, including its DER, PEM or JWK representation, is never used as that secret.
- **Safeguards:** each validation uses the secret actually sent in that request's client authentication, even if the supplier rotates before the response is verified. HMAC verification does no key lookup and HMAC-only warm-up does not fetch JWKS. Tokens with more than one audience entry are rejected, including trusted additional audiences and duplicate entries. Every normal signature, claim, nonce/hash and refresh-continuity check remains required. Raw secrets/ID tokens stay inside the call until validation succeeds, and are absent from result string forms and observer events.
- **Observation:** `OidcObserver.didEnableCompatibilityMode(mode)` reports enabled modes after successful build. `didUseCompatibilityMode(mode)` reports an actual allowlisted, structurally valid HMAC verification attempt, including a signature or later profile failure. An asymmetric token does not produce a HMAC-use event. Observer failures use the existing containment rules.
- **Tests:** `oidc.OidcHmacTests`: `optInRequiresConfidentialAuthenticationAndUtf8HashLength`, `eachHmacAlgorithmUsesExactUtf8SecretWithBasicOrPostAndNoKeys`, `supplierSnapshotSurvivesRotationAndIsReadOnceAtBuildAndOncePerPost`, `hmacStillChecksClaimsHashesSignatureAndExactAudience`, `hmacRefreshRetainsOriginalNonceAndRejectsSubjectDriftBeforeTokenRelease`, `rsaDerPemAndJwkBytesAreNeverHmacKeys`, `mixedAllowlistUsesPublicKeysOnlyForRsaAndModeDoesNotChangeDefaults`, and `lazyDiscoveryIntersectsHmacAndWarmUpFetchesNoJwks`.
- **Added in:** 1.0.0 (unreleased).

### `acknowledgeGlobalSecureValidationDisabled(true)`

- **Where:** `SamlServiceProvider.Builder` (SAML).
- **Effect:** permits building an SP when `org.jcp.xml.dsig.secureValidation` is globally set to a value other than `true`. Without acknowledgment, `build()` fails. Revetsec still sets secure validation explicitly on each XML-signature verification context, except where the IdP's explicit RSA-SHA1 compatibility mode requires it to be disabled for that signature; its own signature shape and algorithm allowlists apply in either case.
- **Risk:** other XML-signature consumers in the same JVM may inherit the disabled global setting. Audit them separately.
- **Safeguards:** false or null clears the acknowledgment. `SamlObserver.didAcknowledgeGlobalSecureValidationDisabled()` reports its use after a successful build without carrying the property value or message data.
- **Tests:** `saml.SamlConfigurationBoundaryTests.disabledGlobalSignatureValidationRequiresAnObservedAcknowledgment` and `internal.xml.EnvelopedSignatureVerifierTests.explicitVerificationContextWorksWithGlobalSecureValidationDisabled`.
- **Added in:** 1.0.0 (unreleased).

### `SamlCompatibilityMode.SHA1_SIGNATURES`

- **Where:** `SamlIdentityProvider.Builder.compatibility(Set<SamlCompatibilityMode>)` for one approved IdP connection.
- **Effect:** accepts RSA-SHA1 XML and Redirect signatures from that connection. The default rejects them. It does not enable HMAC, unsigned responses or RSA1_5 key transport.
- **Risk:** SHA-1 collision resistance is broken. Use this mode only for a partner that cannot be upgraded yet, with a dedicated connection and short migration plan.
- **Tests:** `saml.SamlIndependentFixtureTests`, `saml.SamlScriptedMintedFixtureTests` and `saml.SamlXswMutationTests` exercise the default and selected path.
- **Added in:** 1.0.0 (unreleased).

### `SamlCompatibilityMode.AES_CBC_ENCRYPTION`

- **Where:** the same per-IdP builder.
- **Effect:** permits AES-CBC assertion decryption only after a trusted IdP signature covers the whole Response. It never accepts CBC solely under an Assertion signature. SP metadata advertises GCM, not CBC.
- **Risk:** CBC encryption does not authenticate the ciphertext. Prefer changing the IdP to GCM or to sign the whole Response before enabling this mode.
- **Tests:** `saml.SamlScriptedMintedFixtureTests` covers AES-128/192/256-CBC, the default rejection, and an unsigned-Response negative. `saml.SimpleSamlCapturedResponseTests` replays real SimpleSAMLphp 2.5.0 signed and assertion-only CBC Responses.
- **Added in:** 1.0.0 (unreleased).

### `SamlCompatibilityMode.UNSOLICITED_RESPONSES`

- **Where:** the same per-IdP builder; `allowUnsolicitedResponses(true)` is the equivalent older spelling during pre-release development.
- **Effect:** allows IdP-initiated POST SSO without a pending AuthnRequest. RelayState is rejected and the response age is capped at two minutes before clock skew. Signature, issuer, destination, audience, bearer, replay and subject checks still apply.
- **Risk:** there is no initiating browser request to bind. The application must apply its own session and account-linking policy.
- **Tests:** `saml.SamlIndependentFixtureTests` and `saml.SamlScriptedMintedFixtureTests` replay fixed-clock unsolicited assertions; `saml.SamlServiceProviderTests` exercises the disabled path.
- **Added in:** 1.0.0 (unreleased).

### Settings that are not compatibility modes

- **`JwtValidator.Builder.allowedAlgorithms`** chooses among Revetsec's own algorithms (see [supported algorithms](supported-algorithms.md)); it cannot add `none` or an HMAC algorithm.
- **`RemoteJsonWebKeySource.Builder.allowInsecureLoopback(true)`** is for tests. It allows plain `http` only to a loopback address or exactly `localhost`, and never changes how a token or a key is validated.

## saml2int deviations

This checklist uses the [Kantara saml2int v2.0 deployment profile](https://kantarainitiative.github.io/SAMLprofiles/saml2int.html), version 2.00, 2019-12-09. It covers the common requirements and the SP requirements; the IdP requirements do not apply to Revetsec's SP. **Library** means the core API supplies the capability. **Deployment** means the application or operator must enforce the requirement. **Deviation** means the current SP profile does not meet the requirement as written. Library capability alone is not a claim that a deployment conforms. The application must review its IdP configuration, metadata publication, user interface, and session lifecycle.

| Requirement | Disposition for a Revetsec SP deployment |
| --- | --- |
| SDP-G01 | Library: three-minute default skew, configurable through five minutes. Set three to five minutes for a profile deployment; the API also permits less. |
| SDP-G02 | Deviation: emitted entity IDs and echoed NameIDs can exceed 256 characters. Limit application-configured entity IDs and accepted partner identifiers to 256 for this profile. |
| SDP-G03 | Library: outbound protocol XML writers do not emit DTDs. |
| SDP-G04 | Deployment: configure an absolute SP entity ID no longer than 256 characters. The general builder accepts longer and non-URI identifiers. |
| SDP-MD01 | Deviation: IdP metadata consumption and refresh are application-owned; Revetsec does not automate periodic federation metadata management. The application must refresh trusted metadata and provision endpoints, keys, and policy from it. |
| SDP-MD02 | Deployment: obtain metadata over authenticated TLS or use the pinned-signature `fromXmlResult` overload. The unsigned overload assumes application-approved bytes; it does not authenticate their origin. Keep metadata trust keys independent of IdP message-signing keys. |
| SDP-MD03 | Deviation: approved static IdP metadata without a trusted `validUntil` is accepted. The parser checks expiry on the selected entity and on an aggregate only when its signature is verified or the application supplied approved bytes. An unsigned aggregate around a separately signed entity cannot set that entity's expiry. A strict deployment must reject missing or overlong trusted validity before configuring an IdP. |
| SDP-MD04 | Deployment: `SamlServiceProviderMetadata` produces a descriptor; publication, stable rollover, and authenticated distribution belong to the application. |
| SDP-MD05 | Library: published signing and encryption keys use X.509 certificates in `KeyDescriptor` elements. |
| SDP-MD06 | Library: configured RSA credentials and IdP signing keys require at least 2048 bits. |
| SDP-MD07 | Library: accepted EC signing keys require at least 256 bits; SP credentials currently use RSA. |
| SDP-MD08 | Deviation when no decryption credential is configured: generated SP metadata then has no encryption certificate. Supply a decryption credential for this profile. |
| SDP-MD09 | Deviation: generated SP metadata has no `mdui:UIInfo`, `DisplayName`, `Logo`, or `PrivacyStatementURL`. Publish an enriched, reviewed descriptor for a strict federation. |
| SDP-MD10 | Deployment: if metadata is enriched with a logo, use HTTPS or an inline `data:` URI. The generator has no logo field. |
| SDP-MD11 | Deviation: generated SP metadata has no technical `ContactPerson`/`EmailAddress`. Add these during publication. |
| SDP-MD12 | IdP-only requirement; not applicable to an SP. |
| SDP-ALG01 | Library for incoming messages: SHA-256 XML signatures, AES-GCM assertion decryption, and RSA-OAEP are supported. The SP emits RSA-SHA256 Redirect signatures. The opt-in SHA-1 and AES-CBC modes are outside this profile. |
| SDP-SP01 | Library: SP-initiated browser SSO is implemented; the deviations below limit a strict saml2int claim. |
| SDP-SP02 | Library: `beginAuthenticationResult` emits HTTP-Redirect AuthnRequests. `beginPostAuthenticationResult` is an additional mode; choose Redirect for this profile. |
| SDP-SP03 | Deployment: send the returned redirect as a top-level browser navigation, not in a frame. |
| SDP-SP04 | Library: AuthnRequests emit `NameIDPolicy` with `AllowCreate="true"` and no `Format`. |
| SDP-SP05 | Library: AuthnRequests contain `AssertionConsumerServiceURL`, not `AssertionConsumerServiceIndex`. |
| SDP-SP06 | Library: the request URL is the same configured ACS URL that the metadata generator emits. Publish that exact URL. |
| SDP-SP07 | Library: `RequestedAuthnContext` is omitted by default; configured class references use `Comparison="exact"`. |
| SDP-SP08 | Library: `completeAuthenticationResult` accepts HTTP-POST SAML responses. |
| SDP-SP09 | Deployment: the builder requires an HTTPS ACS URL; the application must actually serve the ACS over TLS. |
| SDP-SP10 | Library when decryption credentials are configured: `EncryptedAssertion` decryption is supported. |
| SDP-SP11 | Library: a request-bound non-success Response yields a fixed `StatusReceived` result after structural and request checks. |
| SDP-SP12 | Deployment: show a useful local support message when the application cannot map or authorize an otherwise valid assertion. Revetsec does not render UI or disclose untrusted IdP status text. |
| SDP-SP13 | Deviation: successful assertions currently require a `NameID` in `Subject`. An attribute-only subject is rejected. |
| SDP-SP14 | Library: checked `subject-id` and `pairwise-id` attributes are exposed and may form stable subject keys when their scopes are approved. Legacy persistent NameID is also supported. |
| SDP-SP15 | Deviation: generated SP metadata does not signal subject-identifier requirements through `mdattr:EntityAttributes`. Enrich metadata for this profile. |
| SDP-SP16 | Library and deployment: use `(connectionId, SamlSubjectKey)` as the account key; the connection ID separates IdPs, and scoped subject identifiers are released only after scope approval. |
| SDP-SP17 | Deployment: configure each IdP's authorized identifier scopes from trusted policy or trusted third-party metadata. Revetsec can read literal `shibmd:Scope`, but the application decides whether that metadata is trusted. |
| SDP-SP18 | Deployment: use appropriate display attributes for UI; Revetsec does not assume opaque subject IDs are display names. |
| SDP-SP19 | Library: SAML attributes preserve multiple values. Application code must respect each attribute's external definition. |
| SDP-SP20 | Deployment: select among approved IdP connections for each resource or policy. The core does not bind an application resource to one IdP. |
| SDP-SP21 | Library and deployment: SP-initiated SSO and sealed `applicationData` can preserve an application-owned return location. The application validates and resumes deep links. |
| SDP-SP22 | Deployment: preservation of a POST body across login is application-owned and is not implemented by the SAML core. |
| SDP-SP23 | Deployment: implement IdP discovery for users when offering deep links. |
| SDP-SP24 | Library: Redirect Single Logout is optional and implemented. |
| SDP-SP25 | Library: SP LogoutRequests use HTTP-Redirect. |
| SDP-SP26 | Library: inbound IdP LogoutRequests use HTTP-Redirect. |
| SDP-SP27 | Deployment: issue logout redirects as top-level browser navigation. |
| SDP-SP28 | Library: SP LogoutRequests are signed. |
| SDP-SP29 | Partial: the standard NameID fields, including `SPProvidedID`, are retained and written in outbound LogoutRequests. Arbitrary extra XML attributes and lexical namespace details are not retained; partners needing those are outside this logout profile. |
| SDP-SP30 | Library: the outbound LogoutRequest NameID is cleartext. |
| SDP-SP31 | Library: LogoutResponses use HTTP-Redirect. |
| SDP-SP32 | Library: inbound LogoutResponses use HTTP-Redirect. |
| SDP-SP33 | Library: SP LogoutResponses are signed. |
| SDP-SP34 | Deployment: end the local session before sending the LogoutRequest, even if the IdP never returns. The Playground does this. |
| SDP-SP35 | Deployment: never invoke SLO solely because a local session idled out. |
| SDP-SP36 | Deployment: use distinct SP entity IDs and metadata where virtual hosts maintain distinct sessions. |
| SDP-SP37 | Library: an IdP connection can hold multiple message-signing keys for rollover. |
| SDP-SP38 | Library: the SP can configure multiple decryption credentials for rollover. |
| SDP-SP39 | Deviation: the generated descriptor has ACS and configured key/logout endpoints but lacks UIInfo, privacy, technical contact, and subject-identifier signaling. It is a starting point for application-owned federation metadata publication, not a complete saml2int descriptor. |

In particular, the missing metadata extensions and `NameID`-required success path prevent an unqualified saml2int conformance claim. The supported product claim is SAML 2.0 browser SSO aligned with the profile **with these deviations**. Local fuzz and the bounded Burp and ZAP passes are recorded. The hosted differential and Shibboleth checks passed on pushed source `eccaa18743bc2efc0287c171a7e027139e0e9eef` ([CI run](https://github.com/revetsec/revetsec/actions/runs/38456477929), [capture run](https://github.com/revetsec/revetsec/actions/runs/38456503172)). The [2026-10-13 full local PIT run](saml-mutation-triage-2026-10-11.md#2026-10-13-full-fixed-source-samlxml-pit-receipt) met the no unjustified survivors criterion for the intermediate bearer replay repair, with 158 uncovered limits; it does not qualify the stricter current checkout. The maintainer reviewed and confirmed the stricter cross-context replay fence on 2026-10-14. A [2026-10-14 full current-source PIT run](saml-mutation-triage-2026-10-11.md#2026-10-14-full-stricter-source-samlxml-pit-receipt) meets the local survivor criterion with 160 uncovered limits. RC-2 remains open pending push, green full CI and same-revision hosted differential and Shibboleth reruns.
