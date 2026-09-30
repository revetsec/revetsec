# Compatibility Modes

**Status: JOSE, OAuth and OIDC modes.** Revetsec holds its foundations, JWT verification and an OAuth client under M3 verification. The modes below are the ones that exist; the registry is complete before 1.0.0.

A compatibility mode is a named, explicit relaxation that lets Revetsec work with a provider or a deployment that departs from a specification or from Revetsec's defaults. The rules for every mode:

- It is off by default.
- It is set per instance: per client, per identity provider or per tenant, never globally.
- It is reported to the observer when the configured object is built and every time the mode is used.
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

### Settings that are not compatibility modes

- **`JwtValidator.Builder.allowedAlgorithms`** chooses among Revetsec's own algorithms (see [supported algorithms](supported-algorithms.md)); it cannot add `none` or an HMAC algorithm.
- **`RemoteJsonWebKeySource.Builder.allowInsecureLoopback(true)`** is for tests. It allows plain `http` only to a loopback address or exactly `localhost`, and never changes how a token or a key is validated.

## saml2int deviations

The SAML service provider is being designed against the SP requirements of the saml2int profile (v2.0). Each deviation from it will be listed here with its reason.
