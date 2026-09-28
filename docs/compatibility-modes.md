# Compatibility Modes

**Status: two modes, both in JOSE.** Revetsec holds its foundations and JWT verification so far, and the modes below are the ones that exist. Each later mode is registered here when it lands, and the registry is complete before 1.0.0.

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

- **Where:** `RemoteJsonWebKeySource.Builder` (JOSE).
- **Effect:** the source builds and fetches on a Java runtime below Revetsec's minimum for network I/O, 17.0.3 (18.0.1 on Java 18), whose TLS and certificate checks are exposed to CVE-2022-21449 (ECDSA signature verification). Without it, `build()` throws `IllegalStateException` on such a runtime.
- **Safeguards:** while the runtime is below the minimum, the choice is reported to `JoseObserver.didUseUnpatchedRuntime(runtimeVersion)` when the source is built and on every fetch. On a runtime at or above the minimum, the setting changes nothing and nothing is reported. Revetsec's own ECDSA range check protects the tokens a validator verifies on every runtime; what the setting accepts is the runtime's own TLS. A `StaticJsonWebKeySource` does no I/O and never needs the setting.
- **Tests:** `jose.RemoteJsonWebKeySourceBuilderTests.theRuntimeFloorIsEnforcedAndAnAcknowledgmentIsObserved` (17.0.2, 18, 17.0.2.0.1 and 17-ea each refused unless acknowledged, and reported at build and on every fetch) and `aRuntimeAtOrAboveTheFloorIsNeverReported`.
- **Added in:** 1.0.0 (unreleased).

### Settings that are not compatibility modes

- **`JwtValidator.Builder.allowedAlgorithms`** chooses among Revetsec's own algorithms (see [supported algorithms](supported-algorithms.md)); it cannot add `none` or an HMAC algorithm.
- **`RemoteJsonWebKeySource.Builder.allowInsecureLoopback(true)`** is for tests. It allows plain `http` only to a loopback address or exactly `localhost`, and never changes how a token or a key is validated.

## saml2int deviations

The SAML service provider is being designed against the SP requirements of the saml2int profile (v2.0). Each deviation from it will be listed here with its reason.
