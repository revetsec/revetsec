# Compatibility Policy

Version 1.0.0 establishes Revetsec's first public compatibility baseline. Revetsec follows [Semantic Versioning](https://semver.org/) from this version, with release tags `vX.Y.Z`:

* **Major** (`2.0.0`): may remove or incompatibly change public API. Migration notes are provided in the CHANGELOG.
* **Minor** (`1.1.0`): additive public API, and behavior changes documented under "Migration Notes" in the CHANGELOG.
* **Patch** (`1.0.1`): fixes only; no new public API.

The [security-tightening policy](#security-tightening-policy) below is the one deliberate exception.

## What counts as public API

Public top-level types in the exported packages below, and their reachable public or protected members, are API. Public or protected member types are included recursively when every enclosing type is exported. Reachable public or protected members inherited from a non-exported Revetsec base are API too. A public declaration inside an internal or otherwise non-exported enclosing type does not by itself export that type. The exported package layout is part of the 1.0.0 public API.

| Package | Contents |
| --- | --- |
| `com.revetsec` | shared, protocol-neutral types |
| `com.revetsec.json` | the immutable JSON value model that appears in public signatures |
| `com.revetsec.jose` | JWS verification and bounded public-key signing, JWK and JWK Sets, JWT validation |
| `com.revetsec.oauth` | OAuth 2.0 client; bearer parsing/challenges/resource metadata, JWT access-token validation and JSON introspection |
| `com.revetsec.oauth.server` | application-integrated authorization, token issuance, refresh, revocation, introspection, metadata and key publication |
| `com.revetsec.oidc` | OpenID Connect relying party |
| `com.revetsec.saml` | SAML 2.0 service provider |
| `com.revetsec.scim` | SCIM 2.0 server primitives |
| `com.revetsec.webauthn` | relying-party registration, sign-in, reauthentication and credential management |
| `com.revetsec.password` | Argon2id password hashing, explicit legacy verification and migration, bounded work and pepper rotation |
| `com.revetsec.totp` | TOTP enrollment and verification, recovery codes, durable record/store contracts and recovery fencing |

### 1.0.0 declaration inventory (2026-11-16)

The [complete current type list](docs/public-api-inventory.md) measures the `1.0.0` release source using the same exported-type rules as `PublicApiContractTests`, cross-checked against compiled declarations. Count each public top-level declaration once and each accessible public or protected nested declaration once under its declaring type. Builders, enums and restricted result variants count as types; methods, constructors, fields, enum constants and compiler-generated helpers do not. No protected nested declarations occur in this release. Adapter artifacts and internal packages are outside these totals.

| Package | Top-level | Nested | Total |
| --- | ---: | ---: | ---: |
| [`com.revetsec`](docs/public-api-inventory.md#comrevetsec) | 18 | 11 | 29 |
| [`com.revetsec.jose`](docs/public-api-inventory.md#comrevetsecjose) | 26 | 13 | 39 |
| [`com.revetsec.json`](docs/public-api-inventory.md#comrevetsecjson) | 7 | 1 | 8 |
| [`com.revetsec.oauth`](docs/public-api-inventory.md#comrevetsecoauth) | 52 | 37 | 89 |
| [`com.revetsec.oauth.server`](docs/public-api-inventory.md#comrevetsecoauthserver) | 39 | 28 | 67 |
| [`com.revetsec.oidc`](docs/public-api-inventory.md#comrevetsecoidc) | 25 | 27 | 52 |
| [`com.revetsec.password`](docs/public-api-inventory.md#comrevetsecpassword) | 15 | 12 | 27 |
| [`com.revetsec.saml`](docs/public-api-inventory.md#comrevetsecsaml) | 43 | 63 | 106 |
| [`com.revetsec.scim`](docs/public-api-inventory.md#comrevetsecscim) | 58 | 59 | 117 |
| [`com.revetsec.totp`](docs/public-api-inventory.md#comrevetsectotp) | 34 | 67 | 101 |
| [`com.revetsec.webauthn`](docs/public-api-inventory.md#comrevetsecwebauthn) | 26 | 49 | 75 |
| **Total** | **343** | **367** | **710** |

This dated inventory is the 1.0.0 source baseline. It does not by itself qualify a runtime, provider or deployment.

### Selected application-security packages

The following packages are present in the 1.0.0 core source. They are included in the 1.0.0 declaration inventory above.

| Package | Surface overview (not a complete type list) | Documentation |
| --- | --- | --- |
| `com.revetsec.password` | `PasswordHasher`, `Argon2idParameters`, `PasswordWorkGate`, `PasswordVerificationLimits`, result and rejection types, optional pepper source/key/snapshot types, and explicit legacy preparation/HMAC selectors | [Password hashing](docs/password-hashing.md), [source and verification](docs/password-vendored-source.md) |
| `com.revetsec.totp` | `TotpAuthenticator`, enrollment/verification/status and recovery-code results, `TotpStore` and its record/read/commit types, `TotpRecoveryGate`, and the bounded volatile `InMemoryTotpStore` | [TOTP and recovery](docs/totp-recovery.md) |

`com.revetsec.internal.password` and the TOTP implementation helpers under `com.revetsec.internal` remain internal implementation, subject to the exclusion below. Neither public package supplies an application account database, login sessions or an HTTP adapter API; the TOTP package includes a store SPI and bounded volatile in-memory store. The 1.0.0 inventory, compatibility review and public baseline cover these declarations.

`OutboundUriPolicy` has its final shape: two presets, `defaultInstance()` and `publicAddressesOnlyInstance()`, and `permits(URI)`. The addresses and names each preset rejects are dated lists, and adding to them is a security tightening (see below). `JsonValue`'s Javadoc designates its six permitted types for exhaustive matching, so they are frozen within a major version (see below). `JwsAlgorithm`, `JwsSigningException.Reason`, `JoseException.Reason`, `JwkSkipReason`, `AccessTokenCompatibilityMode`, `BearerError` and `AccessTokenValidationException.Reason` are not switch-stable: a later release may add constants, so a `switch` over one needs a default branch. Nor are the sealed `JwksSource`, `AccessTokenValidator` and operation result hierarchies: a later release may add permitted implementations or outcomes. Result switches need a rejecting default. Result payload accessors exist only on their appropriate variant; applications cannot construct outcomes. Operations with several expected outcomes expose one result entry point; the earlier Optional/throwing facades have been removed without deprecated aliases. Genuine optional properties remain Optional. Infrastructure and configuration failures retain their documented exception boundaries; see the [validation-outcome overview](README.md#validation-outcomes).

`ScimFilter`'s six node kinds and `ScimFilterValue`'s four literal kinds are designated for exhaustive matching and remain stable within a major version. New abstract `ScimFilterVisitor` callbacks likewise require a major release. SCIM operation result hierarchies and enums may gain variants or constants in a minor release; applications include a rejecting default in those switches. AST inspection alone grants no query authority.

These are not API:

* **`com.revetsec.internal` and every package under it.** Its types are `public` only because Java requires that for use across packages. They are excluded from Javadoc, a contract test keeps them out of every public signature, and they may change in any release, including a patch.
* Package-private types and members.
* **Diagnostic text**: exception messages and `toString()` renderings. When a change could break log parsers, the CHANGELOG says so, but such changes may occur in minor releases.
* Test code, and the unpublished tooling projects in the repository (such as `fuzz/`, `interop/` and `verification/`).

A sealed type whose Javadoc designates it for exhaustive `switch` keeps its permitted subtypes within a major version. Other sealed types may gain subtypes in a minor release.

The adapters (`revetsec-soklet`, `revetsec-servlet-jakarta` and `revetsec-servlet-javax`) are separate artifacts in their own repositories. Each starts at 1.0.0 and then has its own version line. Each adapter's README states the minimum core version it requires.

Custom `PendingSamlAuthenticationStore` implementations used for logout must implement
`consumeIfMatches`, validating and atomically removing only the same approved live sealed
record. Its default returns unavailable without consuming state. Existing store implementations
remain source-compatible, but logout fails closed until this operation is implemented;
login's unconditional consume operation remains available. See [the SAML SP guide](docs/saml-sp.md).

## How the policy is enforced

Contract tests run in every build:

* `PublicApiContractTests` checks the shape of the public API: no public records, JSpecify nullness annotations on every public element, and exactly one thread-safety annotation on every exported type.
* `PackageDependencyTests` checks the allowed dependencies between packages, and that no `internal` type appears in a public or protected signature.
* `SourcePolicyTests` bans a list of source constructs, including `sun.*` imports and `setAccessible`.

For releases after 1.0.0, the [japicmp](https://siom79.github.io/japicmp/) Maven plugin (the `api-diff` profile) compares the build with the previous release. It fails the build on binary- or source-incompatible changes and checks the version number against the nature of the change. The profile is skipped for 1.0.0 itself because no earlier public baseline exists.

## Security-tightening policy

These changes may ship in a minor or patch release, and they are not treated as Semantic Versioning breaks:

* rejecting input that an earlier release accepted, when that input is insecure;
* removing an algorithm from a default allowlist.

Each such change is listed under Security in the CHANGELOG, with migration notes. Compatibility presets only ever widen what is accepted, and every change to a preset is recorded in the CHANGELOG.

## Supported JDKs

* **Source and binary baseline:** Java 17 (`<release>17</release>`). There is no multi-release JAR.
* **Minimum runtime:** Java 17.0.3, the first Java 17 update with the fixes for CVE-2022-21449 (ECDSA signature verification) and CVE-2022-21476 (XML Signature validation). Networked builders, including `RemoteJwksSource`, `OAuthClient` and `OidcClient`, refuse to build on an older runtime, or on Java 18 before 18.0.1, unless the application acknowledges it with `acknowledgeUnpatchedRuntime(true)`, a [compatibility mode](docs/compatibility-modes.md) that is reported to the observer.
* **JDK modules:** the JAR uses `java.base`, `java.net.http` (the JDK `HttpClient`, for outbound HTTPS) and `java.logging` (a guarded `FINE` log record when an observer throws). SAML adds `java.xml` and `java.xml.crypto`. A runtime image built with `jlink` needs these modules; the packaged-consumer check runs `jdeps` to keep the list within these five (INV-L1). `jdeps` does not see security providers, which the JDK loads as services: on Java 17 and 21 the elliptic-curve provider, which TLS with EC keys and ECDSA need, is in `jdk.crypto.ec`, so a `jlink` image there needs that module too. On Java 25 and 27, that provider is in `java.base`.
* **Outbound HTTP:** `RemoteJwksSource`, `OAuthClient` and `OidcClient` accept an application's `HttpClient`, which must not follow redirects; `build()` refuses one that does. When none is supplied, Revetsec creates one default client per JVM on first network use, pinned to HTTP/1.1 and never following redirects. That client starts the JDK's own threads; Revetsec's own code starts none. An injected HTTP/2 client has local ALPN, cancellation and protocol-error regression tests on JDK 17 and 27.
* **Tested:** CI is configured to build and test on Java 17, 21, 25 and 27 (Amazon Corretto).
* Revetsec uses no `sun.*` APIs and no `setAccessible` (a source-policy test bans both), so `--add-opens` is never required.
* The JAR declares `Automatic-Module-Name: com.revetsec`.

## Dependencies

The core `revetsec` artifact declares **zero compile or runtime dependencies**. A Maven Enforcer `bannedDependencies` rule enforces this at build time, and it is visible in the published POM. The annotation dependencies (JSpecify, JSR 305 concurrency annotations and Error Prone annotations) are `provided` scope and are not needed by consumers at compile time or runtime; packaged Maven/Gradle consumers verify both class paths contain only the Revetsec JAR. The Error Prone analyzer and NullAway run only in the library’s optional `static-analysis` build profile, and are not application dependencies.

Each adapter depends on Revetsec core and on its framework's API, both `provided`, so applications declare both explicitly. Core and the Servlet adapters retain Java 17 compatibility. The Soklet 4 adapter and Soklet applications require Java 21 or newer; their source-built framework revision and compiler are pinned separately from core.

## Supported algorithms

[docs/supported-algorithms.md](docs/supported-algorithms.md) covers JWS verification, bounded RSA signing, JSON Web Keys and OIDC ID-token algorithms, and links the implemented access-token, OAuth client-assertion, SAML and standalone publication profiles. It distinguishes defaults, explicit opt-ins and rejected algorithms. The interoperability results below apply only to the providers, versions and configurations they name.

## Compatibility-mode registry

Every compatibility mode is registered in [docs/compatibility-modes.md](docs/compatibility-modes.md), with its conditions and the release that added it. The OAuth client adds explicit unencoded Basic credentials for providers that require them and the same acknowledged-runtime escape hatch as JOSE. OIDC adds explicitly allowlisted HMAC ID tokens for confidential clients with sufficient client-secret bytes; the default remains asymmetric RS256.

### saml2int deviations

The SAML service provider's [saml2int SP checklist and deviations](docs/compatibility-modes.md#saml2int-deviations) distinguish library behavior from application deployment obligations. The listed deviations prevent an unqualified profile claim.

## Interop matrix

The SAML SP is tested against the SAML identity provider (IdP) partners below. Each row states what the partner check covers and its limits. The scripted partner and Keycloak are gating legs: CI requires their integration test methods. SimpleSAMLphp and Shibboleth are advisory evidence, with offline replay fixtures committed in the repository.

| SAML partner | Coverage | Limits |
|---|---|---|
| Scripted IdP (pinned libxmlsec1/signxml image), gating | 20 `ScriptedIdpSsoIT` cases cover signed browser SSO in both request bindings, encryption, metadata, and Redirect and POST logout in both directions. Seven of them are live libxmlsec differential cases for signature and decryption verdicts. | Our test partner supplies hostile variants; it is not an independent product. |
| Keycloak 26.7.4, gating | A digest-pinned local container runs five `KeycloakSamlIT` methods: SP Redirect login, explicitly enabled IdP-initiated login, signed IdP-initiated Redirect logout, and signed POST logout in both directions with tampering and replay rejection. | These cases do not establish every Keycloak encryption or SLO configuration. |
| Shibboleth IdP 5.2.3, advisory (dispatch capture) | A manually dispatched workflow captures GCM and signed-Response CBC responses from the pinned image. Six `ShibbolethCapturedResponseTests` replay methods check single-use GCM authentication, eight configured rollover keys, the per-IdP CBC opt-in, envelope-attack rejection, generated SP metadata including the documented CBC variant, and SP Redirect binding signatures. They run against each fresh capture and against the offline replay fixtures in `src/test/resources/fixtures/shibboleth/`. | The CBC profile requires a connection-specific opt-in and metadata variant. A strict Burp pass and a selected ZAP pass were run locally only. |
| SimpleSAMLphp 2.5.0, advisory | Offline replay of captured fixtures: `SimpleSamlCapturedResponseTests` accepts a fresh signed-Response CBC capture only with the opt-in, rejects its replay, rejects CBC under an unsigned Response, rejects envelope attacks and checks generated SP metadata; `SimpleSamlCapturedLogoutTests` accepts signed Redirect logout in both directions. | The IdP process is restarted between signing modes because it caches SP metadata. |
| Entra, Okta and Google SAML IdPs | No account-backed capture. | Explicitly unproven without account-backed captures; these rows are optional. |

Each check establishes only the listed flows and configurations. CI also runs the test-only [SAML differential comparison](differential/README.md) with Spring Security, a direct OpenSAML harness and a live libxmlsec1 oracle, and replays the fuzz corpus.

The [SAML SP guide](docs/saml-sp.md) describes deployment requirements and the supported binding/encryption profiles. SAML handling also had local fuzzing, mutation testing, an internal AI-assisted review and bounded Burp and ZAP passes; none of these is an independent audit. The saml2int deviations and the optional account-backed rows above retain their stated limits.

For OpenID Connect providers, Microsoft Entra ID's public key sets and discovery documents, as read on 2026-09-27, are kept as test fixtures, and every key in them loads with none skipped. Verifying a token Entra itself signed needs an Entra account, so that part remains unproven. Entra's keys carry no `alg`, so a validator that allows two RSA algorithms cannot use them (see [docs/supported-algorithms.md](docs/supported-algorithms.md)).

Two self-hosted providers have been checked offline too. Key sets, discovery documents and tokens captured on 2026-09-28 from local Keycloak 26.7.4 and node-oidc-provider 9.12.2 test containers, with one token for each signing algorithm the provider offers, are kept as test fixtures. Every token whose algorithm Revetsec supports verifies with a fixed clock, and every key in their key sets loads except the ones the key rules skip: Keycloak's default RSA-OAEP encryption key and node-oidc-provider's ML-DSA-44 key. Both providers put `alg` on every RSA key.

The Keycloak OAuth integration test uses the pinned local 26.7.4 image and a test-only realm. It exercises confidential and public PKCE code flows, client credentials, refresh and revocation offline. Public Google, Apple and Entra metadata captured on 2026-09-27/28 loads under exact issuer comparison: Google advertises callback `iss` and S256; Apple omits the S256 advertisement; a tenant-specific Entra issuer loads, while `common` with `{tenantid}` fails the exact issuer rule. None of these captures proves a live sign-in. GitHub HTTP-200 error parsing is covered with a synthetic response; no live GitHub token POST has been run.

The fixed Entra multi-tenant issuer policy requires signature-verified tenant/issuer/key binding and a trusted application tenant predicate. Local synthetic TLS flows cover identity, UserInfo and refresh; hosted Entra remains unproven. See [the issuer policy guide](docs/oidc-issuer-policy.md).

## Local resource-server checks

| Provider | Executed resource profiles | Limits |
|---|---|---|
| node-oidc-provider 9.12.2 | Actual resource indicators with code and client-credentials RFC 9068 JWTs; same-validator key rotation; audience/scope rejection boundaries; uncached audience-checked JSON introspection and revocation for opaque tokens | Its structured JWT introspection/revocation rejection is preserved as a provider failure. No JWT introspection support claimed. |
| Keycloak 26.7.4 | Actual `at+jwt` on/off; strict code/client-credentials validation and explicitly configured untyped compatibility; JWT introspection/revocation; wrong-audience and read-without-write scope boundaries | The test realm explicitly maps subject/client ID/resource audience. Introspected tokens also name the authenticating client in audience, as Keycloak requires; its audience check stays enabled. |

These local test-only fixtures gate the integration profile. They use fresh scoped TLS trust and preserve provider defaults outside their explicit resource test mode/realm. Hosted provider sign-in and arbitrary realm configurations remain unproven.

The Soklet adapter targets Soklet 4's list-valued headers. It collects every materialized occurrence case-insensitively and forwards duplicate singleton fields to core for rejection. Applications still enforce header/body limits and reject ambiguous framing at their trusted edge.

Revetsec has no production consumer, including for SCIM. Its interoperability evidence comes from self-hosted test partners, locally run conformance suites and captured provider fixtures.

## Conformance suites

The local OIDF RP harness runs the four pinned release-v5.3.1 plans. In its self-run results on JDK 17 and 21, each run completes 37 modules: 34 pass and three unsigned-token rejection cases have the suite's documented skip outcome, with no warnings or review findings. [The harness documentation](conformance/README.md) records the release/source and image pins, exact outcome checks and skip dispositions. The selected comprehensive private-key profile is described below; neither establishes every suite or profile.

## Local private-key client authentication

Fresh public RSA keys registered from the original JCA pairs exercise RS256, RS384 and PS256 with both issuer and actual endpoint audiences. Each configuration performs client credentials, PKCE code exchange, refresh, two uncached introspection calls and revocation. Actual providers reject unregistered keys on token/revocation/introspection and reject a registration algorithm mismatch; each operation sends one POST without fallback. The explicit client-assertion key and key-provider factories build without signing or I/O.

| Provider | Issuer audience (`client-authentication+jwt`) | Actual endpoint audience (`JWT`) | Fixture scope |
|---|---|---|---|
| node-oidc-provider 9.12.2 | All tested roles accepted | All tested roles accepted | RS384 enabled explicitly in its test-only `enabledJWA` subset. Discovery advertises token methods/algorithms but omits revocation/introspection authentication lists; those roles use trusted explicit metadata matching their private-key registrations. Opaque resource tokens are used for introspection/revocation. |
| Keycloak 26.7.4 | All tested roles accepted | Token, code, refresh and introspection accepted; revocation returns `invalid_client` for all three algorithms | Static public JWKS, `client-jwt` and exact registered algorithms in the disposable realm. All applicable authentication lists come from actual discovery. The pinned validator's accepted audience list omits the revocation endpoint. |

Revetsec preserves the actual revocation URL in endpoint audience mode. Applications using this Keycloak version should retain the default issuer audience. This qualified provider difference is covered by an integration regression; no token-URL substitution, retry or secret fallback is performed. These self-run local fixtures establish only the stated configurations; hosted providers and arbitrary deployments remain unproven.

### Selected comprehensive OIDF private-key profile

The pinned release-v5.3.1 comprehensive client plan is exercised with static registration, plain requests, code/query responses and RS256 private-key assertions using the default issuer audience. A fresh original JCA key pair supplies the signer; the suite receives only its public JWKS. The report requires the suite's actual assertion signature, claims, algorithm, type and replay checks against that registered projection. The Basic-authentication module is an upstream-mandated exception and is recorded separately. Signed UserInfo is configured as RS256; the invalid ES256 ID-token signature case explicitly enables ES256 to check signature rejection.

The plan declares 39 modules. Eleven are inapplicable to the selected variant; five applicable modules are explicitly outside the selected profile and remain `NOT_RUN`: WebFinger account/URL discovery, aggregated/distributed claims and UserInfo bearer tokens in request bodies. The other 23 modules run alongside all 37 inherited runs. Four unsigned-token rejections use the suite's documented skip disposition. Full comprehensive-plan support, certification and hosted-provider acceptance are not established by this profile. See [the exact profile and evidence checks](conformance/README.md).
