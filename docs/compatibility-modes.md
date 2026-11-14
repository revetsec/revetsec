# Compatibility Modes

**Status: 1.0.0 registry.** The registry below describes the JOSE, OAuth, OIDC, SAML and SCIM switches in the first compatibility release.

A compatibility mode is a named, explicit relaxation that lets Revetsec work with a provider or a deployment that departs from a specification or from Revetsec's defaults. The rules for every mode:

- It is off by default.
- It is set per instance: per client, per identity provider (IdP) or per tenant, never globally.
- It has an entry on this page, and tests cover both the enabled and the disabled state.
- It is never switched on by detecting a provider automatically.
- Named presets bundle modes for one provider. A preset only widens what is accepted, and every change to a preset is recorded in the CHANGELOG.

Some relaxations are never available as a mode: accepting an unsigned message where a signature is required, the JOSE `none` algorithm, and unauthenticated AES-CBC decryption.

## Registry

Each entry gives the mode's name, protocol area, effect, conditions and safeguards, the tests that cover it (named relative to [`src/test/java/com/revetsec/`](../src/test/java/com/revetsec/)), and the release that added it. SCIM has explicit provider presets.

### `acceptAnyAudience(true)`

- **Where:** [`JwtValidator.Builder`](https://javadoc.revetsec.com/com/revetsec/jose/JwtValidator.Builder.html) (JOSE).
- **Effect:** the validator does not compare the token's `aud` claim with any expected audience, and `aud` is no longer required. An `aud` that is present must still be a string or a non-empty array of strings. Every other check still applies: the signature, `iss`, `exp`, `nbf` and `iat`, the key rules, the required claims and the refusal of `cnf`.
- **Risk:** a token the same issuer issued for another application is accepted. Use it only when the issuer serves this application alone.
- **Safeguards:** it cannot be combined with `expectedAudiences`: setting both makes `build()` throw [`IllegalArgumentException`](https://docs.oracle.com/en/java/javase/27/docs/api/java.base/java/lang/IllegalArgumentException.html). Without it, `build()` throws [`IllegalStateException`](https://docs.oracle.com/en/java/javase/27/docs/api/java.base/java/lang/IllegalStateException.html) unless expected audiences are set. It is reported to [`JoseObserver`](https://javadoc.revetsec.com/com/revetsec/jose/JoseObserver.html)`.didAcceptAnyAudience(issuer)` when the validator is built and on every `validateResult()` call, whatever the outcome.
- **Tests:** `jose.JwtValidatorBuilderTests` (`missingRequiredSettingsAreIllegalState`, `audienceSettingsThatConflictOrAreEmptyAreIllegalArguments` and `acceptingAnyAudienceIsObservedAtBuild`), `jose.JoseObserverTests.acceptingAnyAudienceIsObservedOnEveryValidation`, and, for the disabled state, `jose.JwtValidatorClaimsTests.theAudienceMustNameAnExpectedAudience`.
- **Added in:** 1.0.0.

### `acknowledgeUnpatchedRuntime(true)`

- **Default and reset:** off, per builder instance. `true` explicitly accepts the runtime risk; `false` or `null` restores refusal where the guard applies. The flag is not inferred from a provider, HTTP client, static metadata, loopback setting or another component's configuration.
- **Floor and effect:** permits construction below Revetsec's network-runtime floor: **17.0.3 on Java 17, 18.0.1 on Java 18**; Java 19 and later pass this guard. Without acknowledgment, an applicable builder throws `IllegalStateException` below that floor, even though construction performs no network I/O. The guard addresses the runtime TLS/certificate exposure to CVE-2022-21449; acknowledgment does not patch the runtime or relax token signatures, claims, key rules, HTTPS/peer verification or protocol policy. It is not a general JDK support or security-update guarantee.
- **Risk:** the choice accepts the runtime's vulnerable TLS behavior. Revetsec's own ECDSA range checks protect the signatures it verifies itself; they do not repair the runtime's TLS checks.
- **Version comparison:** the [shared floor implementation](../src/main/java/com/revetsec/internal/http/RuntimeFloor.java) uses `Runtime.Version.compareToIgnoreOptional` on Java 17/18. For example, `17.0.2.0.1`, `17-ea`, `17.0.3-ea` and `18` (the parsed spelling of 18.0.0) remain below the relevant floor; `17.0.3+7-LTS` passes. Optional vendor text does not rescue an older patch level.

All five public entry points and their current behavior:

| Builder | When the floor applies | Runtime-acknowledgment observation |
| --- | --- | --- |
| [`RemoteJwksSource.Builder`](../src/main/java/com/revetsec/jose/RemoteJwksSource.java) | At source build, before any JWKS fetch. | `JoseObserver.didUseUnpatchedRuntime(runtimeVersion)` at source construction and before each JWKS fetch, while below the floor. Cache hits are not fetches. |
| [`OAuthClient.Builder`](../src/main/java/com/revetsec/oauth/OAuthClient.java) | At client build, including explicit/static authorization-server metadata. | The configured `OAuthObserver` inherits the same hook and receives it at client construction; ordinary endpoint/discovery requests do not repeat this acknowledgment event. |
| [`JwtAccessTokenValidator.Builder`](../src/main/java/com/revetsec/oauth/JwtAccessTokenValidator.java) | At validator build unless the configured source is a `StaticJwksSource`. Discovery and supplied remote-source configurations require the guard. | The configured `AccessTokenObserver` inherits the hook and receives it at networked validator construction. An internally created remote JWKS source additionally reports its own construction/fetch events; discovery alone has no repeated runtime-acknowledgment event. |
| [`OidcClient.Builder`](../src/main/java/com/revetsec/oidc/OidcClient.java) | Forwarded to the underlying OAuth client at build and to internally created remote JWKS sources. Static provider metadata or static keys do not bypass the OAuth-client floor. | The configured `OidcObserver` inherits the hook: underlying OAuth-client construction reports it, and an internally created remote source reports its own construction/fetch events. Source construction can occur while building explicit metadata or later after discovery; this is not one event per OIDC operation. |
| [`OAuthAuthorizationServer.Builder`](../src/main/java/com/revetsec/oauth/server/OAuthAuthorizationServer.java) | At issuer build **only when client-ID metadata documents (CIMD) are enabled** through `clientMetadataPolicy`. With CIMD disabled, this flag has no runtime-floor effect on issuer construction. | **No runtime-acknowledgment event is exposed by `OAuthServerObserver`.** Issuer endpoint lifecycle events do not report this configuration choice. |

**Observation and component ownership:** the JOSE hook is inherited through [OAuthObserver](../src/main/java/com/revetsec/oauth/OAuthObserver.java) by [AccessTokenObserver](../src/main/java/com/revetsec/oauth/AccessTokenObserver.java) and [OidcObserver](../src/main/java/com/revetsec/oidc/OidcObserver.java). It carries only the runtime version, not credentials or claims, and follows the usual observer-failure containment. At or above the floor, setting the flag does not cause this warning. A caller-supplied `JwksSource` retains its own acknowledgment and observer configuration; a wrapper flag does not reconfigure an already-built source. A `StaticJwksSource` does no key-fetch I/O and needs no acknowledgment itself. The resource-validator exception above does not apply to OIDC's underlying OAuth client. The [issuer observer](../src/main/java/com/revetsec/oauth/server/OAuthServerObserver.java) is a separate interface and has no such hook.

**Focused evidence:**

- [RuntimeFloorTests](../src/test/java/com/revetsec/internal/http/RuntimeFloorTests.java) checks version classification, refusal and acknowledgment, including early-access and extended patch versions.
- [RemoteJwksSourceBuilderTests](../src/test/java/com/revetsec/jose/RemoteJwksSourceBuilderTests.java): `theRuntimeFloorIsEnforcedAndAnAcknowledgmentIsObserved` and `aRuntimeAtOrAboveTheFloorIsNeverReported` cover refusal/opt-in, construction and repeated-fetch observation, and no warnings at/above the floor.
- [OAuthClientRuntimeFloorTests](../src/test/java/com/revetsec/oauth/OAuthClientRuntimeFloorTests.java) covers default refusal, observed opt-in and null reset.
- [AccessTokenPhase2ContractTests](../src/test/java/com/revetsec/oauth/AccessTokenPhase2ContractTests.java): `staticKeysBypassNetworkRuntimeGuardButNetworkedBuildFailsClosed` covers the static-key exception, network refusal, one construction warning and no build-time I/O; `mutableBuilderChangesCannotAffectBuiltValidatorAndAllSettersReset` includes the acknowledgment reset.
- [OidcAuthenticationFlowTests](../src/test/java/com/revetsec/oidc/OidcAuthenticationFlowTests.java): `nullableFlagsRestoreStrictDefaults` exercises true-to-null reset on the test JVM. OIDC's runtime-floor/observer forwarding is established by the linked source and underlying OAuth/source checks; there is no direct OIDC version-injection build seam.
- [OAuthAuthorizationServerTests](../src/test/java/com/revetsec/oauth/server/OAuthAuthorizationServerTests.java): `enabledClientMetadataConstructionRequiresAcknowledgmentOnUnpatchedRuntime` covers CIMD-off construction, CIMD-on refusal, explicit opt-in and at-floor construction.

The old-version checks inject `Runtime.Version` values on the test JVM; they do not qualify execution on an actual vulnerable runtime. This registry documents current per-role behavior and does not add an issuer observer hook or broaden release qualification. **Added in:** 1.0.0.

### [`ClientSecretBasicEncoding`](https://javadoc.revetsec.com/com/revetsec/oauth/ClientSecretBasicEncoding.html)`.UNENCODED`

- **Where:** [`ClientAuthentication`](https://javadoc.revetsec.com/com/revetsec/oauth/ClientAuthentication.html)`.fromClientSecretBasic(secret, encoding)` (OAuth).
- **Effect:** the client ID and secret are joined with `:` as supplied before Base64, instead of each being form-encoded as RFC 6749 Appendix B requires. It exists for an explicitly configured provider that expects these bytes. It cannot place a secret in the request URI, and no second client-authentication method is added.
- **Risk:** some credentials become ambiguous to a provider parser, especially a client ID containing `:`. Use `FORM_URLENCODED`, the default, unless provider evidence requires the alternative.
- **Safeguards:** the mode is selected per [`ClientAuthentication`](https://javadoc.revetsec.com/com/revetsec/oauth/ClientAuthentication.html) instance. [`OAuthObserver`](https://javadoc.revetsec.com/com/revetsec/oauth/OAuthObserver.html)`.didUseUnencodedBasic()` is called when its client is built and on every token or revocation request that uses it, with no credential value.
- **Tests:** `oauth.ClientAuthenticationTests.explicitUnencodedCompatibilityChangesBytes`, `unencodedBasicIsObservedAtBuildAndUse`, and `basicFormEncodesBothFieldsBeforeJoining` (default mode).
- **Added in:** 1.0.0.

### [`OidcCompatibilityMode`](https://javadoc.revetsec.com/com/revetsec/oidc/OidcCompatibilityMode.html)`.HMAC_ID_TOKENS`

- **Where:** [`OidcClient.Builder`](https://javadoc.revetsec.com/com/revetsec/oidc/OidcClient.Builder.html)`.compatibility(`[`Set`](https://docs.oracle.com/en/java/javase/27/docs/api/java.base/java/util/Set.html)`<`[`OidcCompatibilityMode`](https://javadoc.revetsec.com/com/revetsec/oidc/OidcCompatibilityMode.html)`>)` (OIDC).
- **Effect:** permits explicitly allowlisted `HS256`, `HS384` or `HS512` ID tokens. The default allowlist remains `{RS256}`, and provider advertisement still restricts the effective set. The mode does not enable HMAC in ordinary [`JwtValidator`](https://javadoc.revetsec.com/com/revetsec/jose/JwtValidator.html) or signed UserInfo.
- **Conditions:** confidential client-secret Basic or POST authentication; the exact secret's UTF-8 bytes must be at least 32/48/64 bytes for each configured HMAC algorithm, respectively. The secret is not base64-decoded. Length is checked at build, before each token POST and again by the HMAC verifier. Use a high-entropy secret. A supplier is called once at build and once per token POST; keep it fast and thread-safe.
- **Risk:** the client and provider share the MAC key and can both construct ID tokens. Keep the secret private. An asymmetric public key, including its DER, PEM or JWK representation, is never used as that secret.
- **Safeguards:** each validation uses the secret actually sent in that request's client authentication, even if the supplier rotates before the response is verified. HMAC verification does no key lookup and HMAC-only warm-up does not fetch JWKS. Tokens with more than one audience entry are rejected, including trusted additional audiences and duplicate entries. Every normal signature, claim, nonce/hash and refresh-continuity check remains required. Raw secrets/ID tokens stay inside the call until validation succeeds, and are absent from result string forms and observer events.
- **Observation:** [`OidcObserver`](https://javadoc.revetsec.com/com/revetsec/oidc/OidcObserver.html)`.didEnableCompatibilityMode(mode)` reports enabled modes after successful build. `didUseCompatibilityMode(mode)` reports an actual allowlisted, structurally valid HMAC verification attempt, including a signature or later profile failure. An asymmetric token does not produce a HMAC-use event. Observer failures use the existing containment rules.
- **Tests:** `oidc.OidcHmacTests`: `optInRequiresConfidentialAuthenticationAndUtf8HashLength`, `eachHmacAlgorithmUsesExactUtf8SecretWithBasicOrPostAndNoKeys`, `supplierSnapshotSurvivesRotationAndIsReadOnceAtBuildAndOncePerPost`, `hmacStillChecksClaimsHashesSignatureAndExactAudience`, `hmacRefreshRetainsOriginalNonceAndRejectsSubjectDriftBeforeTokenRelease`, `rsaDerPemAndJwkBytesAreNeverHmacKeys`, `mixedAllowlistUsesPublicKeysOnlyForRsaAndModeDoesNotChangeDefaults`, and `lazyDiscoveryIntersectsHmacAndWarmUpFetchesNoJwks`.
- **Added in:** 1.0.0.

### `acknowledgeGlobalSecureValidationDisabled(true)`

- **Where:** [`SamlServiceProvider.Builder`](https://javadoc.revetsec.com/com/revetsec/saml/SamlServiceProvider.Builder.html) (SAML).
- **Effect:** permits building a service provider (SP) when `org.jcp.xml.dsig.secureValidation` is globally set to a value other than `true`. Without acknowledgment, `build()` fails. Revetsec still sets secure validation explicitly on each XML-signature verification context, except where the IdP's explicit RSA-SHA1 compatibility mode requires it to be disabled for that signature; its own signature shape and algorithm allowlists apply in either case.
- **Risk:** other XML-signature consumers in the same JVM may inherit the disabled global setting. Audit them separately.
- **Safeguards:** false or null clears the acknowledgment. [`SamlObserver`](https://javadoc.revetsec.com/com/revetsec/saml/SamlObserver.html)`.didAcknowledgeGlobalSecureValidationDisabled()` reports its use after a successful build without carrying the property value or message data.
- **Tests:** `saml.SamlConfigurationBoundaryTests.disabledGlobalSignatureValidationRequiresAnObservedAcknowledgment` and `internal.xml.EnvelopedSignatureVerifierTests.explicitVerificationContextWorksWithGlobalSecureValidationDisabled`.
- **Added in:** 1.0.0.

### [`SamlCompatibilityMode`](https://javadoc.revetsec.com/com/revetsec/saml/SamlCompatibilityMode.html)`.SHA1_SIGNATURES`

- **Where:** [`SamlIdentityProvider.Builder`](https://javadoc.revetsec.com/com/revetsec/saml/SamlIdentityProvider.Builder.html)`.compatibility(`[`Set`](https://docs.oracle.com/en/java/javase/27/docs/api/java.base/java/util/Set.html)`<`[`SamlCompatibilityMode`](https://javadoc.revetsec.com/com/revetsec/saml/SamlCompatibilityMode.html)`>)` for one approved IdP connection.
- **Effect:** accepts RSA-SHA1 XML and Redirect signatures from that connection. The default rejects them. It does not enable HMAC, unsigned responses or RSA1_5 key transport.
- **Risk:** SHA-1 collision resistance is broken. Use this mode only for a partner that cannot be upgraded yet, with a dedicated connection and short migration plan.
- **Tests:** `saml.SamlIndependentFixtureTests`, `saml.SamlScriptedMintedFixtureTests` and `saml.SamlXswMutationTests` exercise the default and selected path.
- **Added in:** 1.0.0.

### [`SamlCompatibilityMode`](https://javadoc.revetsec.com/com/revetsec/saml/SamlCompatibilityMode.html)`.AES_CBC_ENCRYPTION`

- **Where:** the same per-IdP builder.
- **Effect:** permits AES-CBC assertion decryption only after a trusted IdP signature covers the whole Response. It never accepts CBC solely under an Assertion signature. SP metadata advertises GCM, not CBC.
- **Risk:** CBC encryption does not authenticate the ciphertext. Prefer changing the IdP to GCM or to sign the whole Response before enabling this mode.
- **Tests:** `saml.SamlScriptedMintedFixtureTests` covers AES-128/192/256-CBC, the default rejection, and an unsigned-Response negative. `saml.SimpleSamlCapturedResponseTests` replays real SimpleSAMLphp 2.5.0 signed and assertion-only CBC Responses.
- **Added in:** 1.0.0.

### [`SamlCompatibilityMode`](https://javadoc.revetsec.com/com/revetsec/saml/SamlCompatibilityMode.html)`.UNSOLICITED_RESPONSES`

- **Where:** the same per-IdP builder; `allowUnsolicitedResponses(true)` is the equivalent older spelling during pre-release development.
- **Effect:** allows IdP-initiated POST SSO without a pending AuthnRequest. RelayState is rejected and the response age is capped at two minutes before clock skew. Signature, issuer, destination, audience, bearer, replay and subject checks still apply.
- **Risk:** there is no initiating browser request to bind. The application must apply its own session and account-linking policy.
- **Tests:** `saml.SamlIndependentFixtureTests` and `saml.SamlScriptedMintedFixtureTests` replay fixed-clock unsolicited assertions; `saml.SamlServiceProviderTests` exercises the disabled path.
- **Added in:** 1.0.0.

### [`AccessTokenCompatibilityMode`](https://javadoc.revetsec.com/com/revetsec/oauth/AccessTokenCompatibilityMode.html)`.UNTYPED_ACCESS_TOKENS`

- **Where:** [`JwtAccessTokenValidator`](https://javadoc.revetsec.com/com/revetsec/oauth/JwtAccessTokenValidator.html) (OAuth resource server).
- **Effect:** permits a JWT access token with absent or ordinary `JWT` type only when additional required claims are configured. Strict validation expects an access-token type.
- **Risk and safeguards:** a provider's identity token must not be admitted as an API access token. Keep exact audience, issuer, signature and application authorization checks; this mode rejects identity-token-only claims and is reported to [`AccessTokenObserver`](https://javadoc.revetsec.com/com/revetsec/oauth/AccessTokenObserver.html).
- **Tests:** `oauth.JwtAccessTokenValidatorTests` and the pinned Keycloak resource-server integration profile.
- **Added in:** 1.0.0.

### [`ClientAssertionAudience`](https://javadoc.revetsec.com/com/revetsec/oauth/ClientAssertionAudience.html)`.TOKEN_ENDPOINT`

- **Where:** OAuth private-key client authentication; the default is `ISSUER`.
- **Effect:** uses the actual POST endpoint as the assertion audience with `JWT` type instead of the exact issuer with `client-authentication+jwt` type. The client keeps its fixed configured endpoint and does not fall back after a rejection.
- **Risk and safeguards:** select this only for an approved provider registration that requires endpoint audience. It changes which signed assertion a provider accepts; it does not change destination admission.
- **Tests:** `oauth.ClientAssertionTests`, `oauth.NodeClientAssertionIT` and `oauth.KeycloakClientAssertionIT`.
- **Added in:** 1.0.0.

### [`OidcIssuerPolicy`](https://javadoc.revetsec.com/com/revetsec/oidc/OidcIssuerPolicy.html)`.fromMicrosoftEntraMultiTenant`

- **Where:** an OIDC client configured for Microsoft's fixed public-cloud `common` or `organizations` v2.0 issuer.
- **Effect:** accepts the advertised `{tenantid}` issuer template only with a signature-verified tenant GUID and a trusted application predicate. The exact issuer policy remains the default.
- **Risk and safeguards:** an overly broad tenant predicate admits identities from unwanted tenants. The same policy instance must be shared with a shared key source; ID-token, UserInfo and refresh tenant checks remain bound.
- **Tests:** `oidc.OidcIssuerPolicyTests`; hosted Entra acceptance remains unproven.
- **Added in:** 1.0.0.

### [`ScimCompatibilityFeature`](https://javadoc.revetsec.com/com/revetsec/scim/ScimCompatibilityFeature.html) and presets

The [`ScimCompatibility`](https://javadoc.revetsec.com/com/revetsec/scim/ScimCompatibility.html)`.strictInstance()` enables no features. `microsoftEntraIdInstance()` enables the eight features through `IGNORE_UNDECLARED_SCHEMA_URIS` in the table; `oktaInstance()` enables `PATCH_OPERATION_NAME_CASE_INSENSITIVE`, `PATCH_READ_ONLY_ID_ECHO` and `PATCH_GROUP_MEMBER_DISPLAY_IGNORED`. [`ScimCompatibility`](https://javadoc.revetsec.com/com/revetsec/scim/ScimCompatibility.html)`.builder().features(...)` explicitly selects another reviewed set. No feature is inferred from request content. Each relaxation is confined to SCIM parsing or resource handling; schema binding, authorization policy, work budgets and output rules still apply.

| Feature | Effect |
| --- | --- |
| `PATCH_OPERATION_NAME_CASE_INSENSITIVE` | Accept ASCII case variants of PATCH operation names. |
| `BOOLEAN_STRINGS` | Accept true/false strings in Boolean-bound positions. |
| `PATCH_REMOVE_WITH_VALUE` | Accept reviewed member-removal value shapes. |
| `PATCH_VALUE_PATH_UPSERT` | Accept reviewed email type-selector upsert shapes. |
| `PATCH_VALUE_OBJECT_ATTRIBUTE_PATHS` | Accept dotted or qualified keys in reviewed PATCH objects. |
| `FILTER_VALUE_PATH_SUB_ATTRIBUTE_COMPARISON` | Rewrite a filtered suffix to a same-element predicate. |
| `INFER_MISSING_EXTENSION_SCHEMAS` | Infer registered extension declarations from present values. |
| `IGNORE_UNDECLARED_SCHEMA_URIS` | Ignore unknown schema declarations without admitting unknown attributes. |
| `COMPLEX_VALUE_AS_SCALAR` | Accept an Enterprise manager string as its value object. |
| `IGNORE_UNKNOWN_ATTRIBUTES` | Drop unknown attributes while preserving known-attribute rules. |
| `PATCH_READ_ONLY_ID_ECHO` | Ignore an identical current id in reviewed no-path PATCH objects. |
| `PATCH_GROUP_MEMBER_DISPLAY_IGNORED` | Ignore only supplied read-only display in standard Group member object merges; preserve stored display, provenance and all other protected-field checks. Direct child writes and custom lookalikes remain refused. |
| `PATCH_EXTENSION_SCHEMA_ROOT` | Accept an exact registered extension URI as a whole-extension PATCH target; absent from both provider presets. |

**Tests:** `scim.ScimM10ConfigurationTests`, `scim.ScimM11PatchParsingTests`, `scim.ScimM11PatchApplicationTests`, `scim.ScimM12ExtensionPatchTests`, `scim.ScimApiFreezeSelectionTests` and `scim.ScimRc3SecurityTests` cover selection and affected paths. **Added in:** 1.0.0.

### Settings that are not compatibility modes

- **[`JwtValidator.Builder`](https://javadoc.revetsec.com/com/revetsec/jose/JwtValidator.Builder.html)`.allowedAlgorithms`** chooses among Revetsec's own algorithms (see [supported algorithms](supported-algorithms.md)); it cannot add `none` or an HMAC algorithm.
- **[`RemoteJwksSource.Builder`](https://javadoc.revetsec.com/com/revetsec/jose/RemoteJwksSource.Builder.html)`.allowInsecureLoopback(true)`** is for tests. It allows plain `http` only to a loopback address or exactly `localhost`, and never changes how a token or a key is validated.
- **[`OAuthAuthorizationServer.Builder`](https://javadoc.revetsec.com/com/revetsec/oauth/server/OAuthAuthorizationServer.Builder.html)`.allowInsecureLoopback(true)`** permits a numeric HTTP loopback issuer only for local development. `allowNativeLoopbackRedirects(true)` separately permits the native IP-literal redirect port exception, and `allowLocalhostRedirects(true)` separately admits the configured exact-port localhost redirect profile. All three default off; no one flag implies another. See `oauth.server.OAuthServerApplicationContractsTests` and `oauth.server.OAuthServerWireContractTests`.

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
| SDP-MD04 | Deployment: [`SamlServiceProviderMetadata`](https://javadoc.revetsec.com/com/revetsec/saml/SamlServiceProviderMetadata.html) produces a descriptor; publication, stable rollover, and authenticated distribution belong to the application. |
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
| SDP-SP16 | Library and deployment: use `(connectionId, `[`SamlSubjectKey`](https://javadoc.revetsec.com/com/revetsec/saml/SamlSubjectKey.html)`)` as the account key; the connection ID separates IdPs, and scoped subject identifiers are released only after scope approval. |
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

In particular, the missing metadata extensions and `NameID`-required success path prevent an unqualified saml2int conformance claim. The supported product claim is SAML 2.0 browser SSO aligned with the profile **with these deviations**. Local fuzz and the bounded Burp and ZAP passes are recorded. The hosted differential and Shibboleth checks passed on pushed source `eccaa18743bc2efc0287c171a7e027139e0e9eef` ([CI run](https://github.com/revetsec/revetsec/actions/runs/38456477929), [capture run](https://github.com/revetsec/revetsec/actions/runs/38456503172)). The [2026-10-13 full local PIT run](saml-mutation-triage-2026-10-11.md#2026-10-13-full-fixed-source-samlxml-pit-receipt) met the no unjustified survivors criterion for the intermediate bearer replay repair, with 158 uncovered limits; it does not qualify the stricter current checkout. The maintainer reviewed and confirmed the stricter cross-context replay fence on 2026-10-14. A [2026-10-14 full current-source PIT run](saml-mutation-triage-2026-10-11.md#2026-10-14-full-stricter-source-samlxml-pit-receipt) meets the local survivor criterion with 160 uncovered limits. RC-2 subsequently closed after [same-revision green CI](https://github.com/revetsec/revetsec/actions/runs/38581827855) and [Shibboleth capture](https://github.com/revetsec/revetsec/actions/runs/38582202155) on `b91ff91f9ee1daf5c9065257111cb8521ba1f3e4`; see the [closure receipt](reviews/rc-2-round-1.md#rc-2-closure--2026-10-14).

The member-display profile is covered by `scim.ScimSecurityResidualTests` (strict/Entra/Okta/explicit use, one actual-use observation per operation, custom/direct/immutable/type controls), introduced in 1.0.0. It is a source compatibility policy; hosted Okta interoperability remains separately qualified. Nested extension child names containing a colon always reject and are not enabled by the dotted/qualified top-level path profile.
