# Compatibility Policy

Revetsec is pre-release. The version is `1.0.0-SNAPSHOT`, and **there is no compatibility promise before 1.0.0**. Until then, any public type, member, default or behavior may change incompatibly, without deprecation.

From 1.0.0, Revetsec follows [Semantic Versioning](https://semver.org/), with release tags `vX.Y.Z`:

* **Major** (`2.0.0`): may remove or incompatibly change public API. Migration notes are provided in the CHANGELOG.
* **Minor** (`1.1.0`): additive public API, and behavior changes documented under "Migration Notes" in the CHANGELOG.
* **Patch** (`1.0.1`): fixes only; no new public API.

The [security-tightening policy](#security-tightening-policy) below is the one deliberate exception.

## What counts as public API

Everything `public` or `protected` in the exported packages of the `revetsec` artifact. The package layout is still under review and may change before 1.0.0. Each package's API is frozen when its protocol area is ready for release.

| Package | Planned contents |
| --- | --- |
| `com.revetsec` | shared, protocol-neutral types |
| `com.revetsec.json` | the immutable JSON value model that appears in public signatures |
| `com.revetsec.jose` | JWS verification, JWK and JWK Sets, JWT validation |
| `com.revetsec.oauth` | OAuth 2.0 client; bearer parsing/challenges/resource metadata, JWT access-token validation and JSON introspection |
| `com.revetsec.oidc` | OpenID Connect relying party |
| `com.revetsec.saml` | SAML 2.0 service provider |
| `com.revetsec.scim` | SCIM 2.0 server primitives |

### Public types so far

Milestone M1 (foundations) added the first public types, M2 added `com.revetsec.jose`, M3 added `com.revetsec.oauth`, M4 added `com.revetsec.oidc`, and M5 adds resource-server protocol helpers, both resource validators and additive sealed validation outcomes. SAML and SCIM hold no public types yet.

| Package | Public types | Count |
| --- | --- | --- |
| `com.revetsec` | `RevetsecException` (abstract), `ErrorCategory`, `InvalidSealedStateException`, `StateSealer`, `SealingKey`, `OutboundUriPolicy`, `StateUnsealResult` | 7, plus 3 nested: `StateSealer.Builder` and two unseal result variants |
| `com.revetsec.json` | `JsonValue` (sealed), `JsonObject`, `JsonArray`, `JsonString`, `JsonNumber`, `JsonBoolean`, `JsonNull` | 7, plus 1 nested: `JsonObject.Builder` |
| `com.revetsec.jose` | `JwtValidator`, `Jwt`, `JwtClaims`, `JwsAlgorithm`, `JsonWebKey`, `JsonWebKeySet`, `JsonWebKeySkipReason`, `JsonWebKeySource` (sealed), `StaticJsonWebKeySource`, `RemoteJsonWebKeySource`, `JoseObserver`, `JoseException` (abstract, sealed), `MalformedJoseInputException`, `UnsupportedJoseFeatureException`, `JwtValidationException`, `JsonWebKeySetUnavailableException`, `JwtValidationResult` | 17, plus 5 nested: two builders, `JoseException.Reason` and two validation result variants |
| `com.revetsec.oauth` | `OAuthClient`, `AuthorizationServerMetadata`, `ClientAuthentication`, `ClientSecretBasicEncoding`, `AuthorizationRequestOptions`, `AuthorizationRedirect`, `PendingAuthorization`, `PendingAuthorizationSource`, `PendingAuthorizationStore`, `InMemoryPendingAuthorizationStore`, `AuthorizationResponse`, `TokenResponse`, `AccessToken`, `RefreshToken`, `TokenRequestOptions`, `TokenTypeHint`, `ClientCredentialsTokenSource`, `IssuerParameterPolicy`, `OAuthObserver`, `OAuthEndpoint`, `OAuthException`, six final OAuth exception leaves, `BearerToken`, `BearerError`, `BearerChallenge`, `ProtectedResourceMetadata`, `AccessTokenValidationException`, `BearerTokenResult`, `AuthorizationCompletionResult`, `AccessTokenValidator`, `JwtAccessTokenValidator`, `TokenIntrospectionClient`, `VerifiedAccessToken`, `AccessTokenCompatibilityMode`, `AccessTokenObserver`, `AccessTokenValidationResult` | 41, plus 21 nested: ten builders, three enums and eight result variants |
| `com.revetsec.oidc` | `OidcClient`, `OidcProviderMetadata`, `OidcAuthenticationOptions`, `IdToken`, `OidcAuthentication`, `OidcSessionReference`, `OidcRefreshResult`, `OidcUserInfo`, `OidcCompatibilityMode`, `OidcObserver`, `OidcException` (abstract, sealed), `OidcValidationException`, `OidcAuthenticationResult` | 13, plus 8 nested: three builders, `OidcValidationException.Reason` and four authentication result variants |

`OutboundUriPolicy` has its final shape: two presets, `defaultInstance()` and `publicAddressesOnlyInstance()`, and `permits(URI)`. The addresses and names each preset rejects are dated lists, and adding to them is a security tightening (see below). `JsonValue`'s Javadoc designates its six permitted types for exhaustive matching, so they are frozen within a major version (see below). `JwsAlgorithm`, `JoseException.Reason`, `JsonWebKeySkipReason`, `AccessTokenCompatibilityMode`, `BearerError` and `AccessTokenValidationException.Reason` are not switch-stable: a later release may add constants, so a `switch` over one needs a default branch. Nor are the sealed `JsonWebKeySource`, `AccessTokenValidator` and operation result hierarchies: a later release may add permitted implementations or outcomes. Result switches need a rejecting default. Result payload accessors exist only on their appropriate variant; applications cannot construct outcomes. Existing throwing entry points remain available, and infrastructure/configuration failures retain exceptions.

These are not API:

* **`com.revetsec.internal` and every package under it.** Its types are `public` only because Java requires that for use across packages. They are excluded from Javadoc, a contract test keeps them out of every public signature, and they may change in any release, including a patch.
* Package-private types and members.
* **Diagnostic text**: exception messages and `toString()` renderings. When a change could break log parsers, the CHANGELOG says so, but such changes may occur in minor releases.
* Test code, and the unpublished tooling projects in the repository (such as `fuzz/`, `interop/` and `verification/`).

A sealed type whose Javadoc designates it for exhaustive `switch` keeps its permitted subtypes within a major version. Other sealed types may gain subtypes in a minor release.

The adapters (`revetsec-soklet`, `revetsec-servlet-jakarta` and `revetsec-servlet-javax`) are separate artifacts in their own repositories. Each starts at `1.0.0-SNAPSHOT`, releases 1.0.0 together with core, and then has its own version line. From 1.0.0, each adapter's README states the minimum core version it requires.

## How the policy is enforced

Before 1.0.0, contract tests run in every build:

* `PublicApiContractTests` checks the shape of the public API: no public records, JSpecify nullness annotations on every public element, and exactly one thread-safety annotation on every exported type.
* `PackageDependencyTests` checks the allowed dependencies between packages, and that no `internal` type appears in a public or protected signature.
* `SourcePolicyTests` bans a list of source constructs, including `sun.*` imports and `setAccessible`.

From 1.0.0, the [japicmp](https://siom79.github.io/japicmp/) Maven plugin (the `api-diff` profile) compares each build with the previous release. It fails the build on binary- or source-incompatible changes and checks the version number against the nature of the change. Until 1.0.0 the profile is a stub, because there is no baseline.

## Security-tightening policy

These changes may ship in a minor or patch release, and they are not treated as Semantic Versioning breaks:

* rejecting input that an earlier release accepted, when that input is insecure;
* removing an algorithm from a default allowlist.

Each such change is listed under Security in the CHANGELOG, with migration notes. Compatibility presets only ever widen what is accepted, and every change to a preset is recorded in the CHANGELOG.

## Supported JDKs

* **Source and binary baseline:** Java 17 (`<release>17</release>`). There is no multi-release JAR.
* **Minimum runtime:** Java 17.0.3, the first Java 17 update with the fixes for CVE-2022-21449 (ECDSA signature verification) and CVE-2022-21476 (XML Signature validation). Networked builders, including `RemoteJsonWebKeySource`, `OAuthClient` and `OidcClient`, refuse to build on an older runtime, or on Java 18 before 18.0.1, unless the application acknowledges it with `acknowledgeUnpatchedRuntime(true)`, a [compatibility mode](docs/compatibility-modes.md) that is reported to the observer.
* **JDK modules:** the JAR uses `java.base`, `java.net.http` (the JDK `HttpClient`, for outbound HTTPS) and `java.logging` (a guarded `FINE` log record when an observer throws). SAML adds `java.xml` and `java.xml.crypto`. A runtime image built with `jlink` needs these modules; the packaged-consumer check runs `jdeps` to keep the list within these five (INV-L1). `jdeps` does not see security providers, which the JDK loads as services: on Java 17 and 21 the elliptic-curve provider, which TLS with EC keys and ECDSA need, is in `jdk.crypto.ec`, so a `jlink` image there needs that module too. On Java 25 and 27, that provider is in `java.base`.
* **Outbound HTTP:** `RemoteJsonWebKeySource`, `OAuthClient` and `OidcClient` accept an application's `HttpClient`, which must not follow redirects; `build()` refuses one that does. When none is supplied, Revetsec creates one default client per JVM on first network use, pinned to HTTP/1.1 and never following redirects. That client starts the JDK's own threads; Revetsec's own code starts none. An injected HTTP/2 client has local ALPN, cancellation and protocol-error regression tests on JDK 17 and 27.
* **Tested:** CI is configured to build and test on Java 17, 21, 25 and 27 (Amazon Corretto).
* Revetsec uses no `sun.*` APIs and no `setAccessible` (a source-policy test bans both), so `--add-opens` is never required.
* The JAR declares `Automatic-Module-Name: com.revetsec`.

## Dependencies

The core `revetsec` artifact declares **zero compile or runtime dependencies**. A Maven Enforcer `bannedDependencies` rule enforces this at build time, and it is visible in the published POM. The annotation dependencies (JSpecify, JSR 305 concurrency annotations and Error Prone annotations) are `provided` scope and are not needed by consumers at compile time or runtime; packaged Maven/Gradle consumers verify both class paths contain only the Revetsec JAR. The Error Prone analyzer and NullAway run only in the library’s optional `static-analysis` build profile, and are not application dependencies.

Each adapter depends on Revetsec core and on its framework's API, both `provided`, so applications declare both explicitly.

## Supported algorithms

[docs/supported-algorithms.md](docs/supported-algorithms.md) lists, for each protocol area, the algorithms allowed by default, those available only by explicit opt-in, and those never accepted. So far it covers JWS signature verification and JSON Web Key types; the other areas are added as they land.

## Compatibility-mode registry

Every compatibility mode is registered in [docs/compatibility-modes.md](docs/compatibility-modes.md), with its conditions and the release that added it. The OAuth client adds explicit unencoded Basic credentials for providers that require them and the same acknowledged-runtime escape hatch as JOSE. OIDC adds explicitly allowlisted HMAC ID tokens for confidential clients with sufficient client-secret bytes; the default remains asymmetric RS256.

### saml2int deviations

Not yet written. The SAML service provider's deviations from the saml2int SP requirements will be listed in [docs/compatibility-modes.md](docs/compatibility-modes.md#saml2int-deviations), each with its reason.

## Interop matrix

Not yet written. It will be a dated provider matrix, modeled on Pyranid's table of wire-compatible databases. Each row will name the provider and version observed, say whether its CI leg gates or is advisory, carry an "observed on YYYY-MM-DD" date, and list divergences. Any combination found unsafe will carry an explicit warning.

Evidence for a first row exists: Microsoft Entra ID's public key sets and discovery documents, as read on 2026-09-27, are kept as test fixtures, and every key in them loads with none skipped. Verifying a token Entra itself signed needs an Entra account, so that part of the row is unproven so far. Entra's keys carry no `alg`, so a validator that allows two RSA algorithms cannot use them (see [docs/supported-algorithms.md](docs/supported-algorithms.md)).

Two self-hosted providers have been checked offline too. Key sets, discovery documents and tokens captured on 2026-09-28 from local Keycloak 26.7.4 and node-oidc-provider 9.12.2 test containers, with one token for each signing algorithm the provider offers, are kept as test fixtures. Every token whose algorithm Revetsec supports verifies with a fixed clock, and every key in their key sets loads except the ones the key rules skip: Keycloak's default RSA-OAEP encryption key and node-oidc-provider's ML-DSA-44 key. Both providers put `alg` on every RSA key.

The M3 Keycloak OAuth integration test uses the pinned local 26.7.4 image and a test-only realm. It has exercised confidential and public PKCE code flows, client credentials, refresh and revocation offline. Public Google, Apple and Entra metadata captured on 2026-09-27/28 loads under exact issuer comparison: Google advertises callback `iss` and S256; Apple omits the S256 advertisement; a tenant-specific Entra issuer loads, while `common` with `{tenantid}` fails M3's exact issuer rule. None of these captures proves a live sign-in. GitHub HTTP-200 error parsing is covered with a synthetic response; no live GitHub token POST has been run.

## Local resource-server checks (observed 2026-10-01)

| Provider | Executed resource profiles | Limits |
|---|---|---|
| node-oidc-provider 9.12.2 | Actual resource indicators with code and client-credentials RFC 9068 JWTs; same-validator key rotation; audience/scope rejection boundaries; uncached audience-checked JSON introspection and revocation for opaque tokens | Its structured JWT introspection/revocation rejection is preserved as a provider failure. No JWT introspection support claimed. |
| Keycloak 26.7.4 | Actual `at+jwt` on/off; strict code/client-credentials validation and explicitly configured untyped compatibility; JWT introspection/revocation; wrong-audience and read-without-write scope boundaries | The test realm explicitly maps subject/client ID/resource audience. Introspected tokens also name the authenticating client in audience, as Keycloak requires; its audience check stays enabled. |

These local test-only fixtures gate the integration profile. They use fresh scoped TLS trust and preserve provider defaults outside their explicit resource test mode/realm. Hosted provider sign-in and arbitrary realm configurations remain unproven. Thin Soklet helpers preserve distinct materialized raw input on official 3.5.1 and the pinned source-built 4.0 candidate; a trusted edge must reject identical physical duplicate Authorization/Content-Type fields discarded by Soklet's set representation.

**No production consumer.** Revetsec has no production consumer, and none is planned for 1.0.0, including for SCIM. The evidence at 1.0.0 will come from self-hosted test partners, conformance suites run locally, and dated captures from provider accounts.

## Conformance suites

On 2026-09-30, the local OIDF RP harness ran the four pinned release-v5.3.1 plans on JDK 17 and 21. Each run completed 37 modules: 34 passed and three unsigned-token rejection cases had the suite's documented skip outcome, with no warnings or review findings. [The harness documentation](conformance/README.md) records the release/source and image pins, exact outcome checks and skip dispositions. These are self-run results. Other planned suites have not been run yet.
