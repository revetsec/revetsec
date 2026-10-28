# Revetsec

### What Is It?

A zero-dependency Java library for OAuth 2.0 clients and resource servers, OpenID Connect relying parties, JOSE, SAML 2.0 service providers and SCIM 2.0 servers.

**Revetsec is pre-release.** It verifies signed JWTs against JSON Web Key Sets, provides bounded RSA signing, and includes OAuth 2.0 client and issuer operations, audience-checked JWT/introspection resource validation, an OpenID Connect relying party, SAML SP, SCIM server primitives, WebAuthn relying-party workflows, TOTP enrollment with one-use recovery codes, and password hashing. See [Status](#status) for current release gates.

Revetsec handles the application side of these protocols. It builds outbound requests, parses and validates what comes back, and returns an explicit outcome for expected success or rejection. TOTP storage and recovery-admission failures also have explicit outcomes; other infrastructure and configuration failures retain their documented exception boundaries. Your application keeps its own users, sessions, routes and storage.

Framework adapters for [Soklet](https://www.soklet.com) and the Servlet API are separate artifacts in their own repositories (see [Installation](#installation)).

[Unpublished runnable examples](examples/README.md) demonstrate OIDC sessions and a Soklet MCP resource server with application-owned storage and authorization decisions. Their local HTTPS/provider setup uses exact source pins and private build/trust directories.

### Why?

Adding single sign-on, API protection or user provisioning to a Java application usually means assembling several libraries, one per protocol, each with its own dependency tree, release cadence and advisory stream.

Revetsec aims to cover the common application-side needs of these protocols with one artifact and the JDK: one dependency, one version, and one place to report and track security issues.

It provides protocol-specific library APIs rather than one abstraction over every protocol, and it does not treat an OAuth token response as an authenticated identity.

### Design Goals

- Main focus: the application side of OAuth 2.0, OpenID Connect, SAML 2.0 and SCIM 2.0
- Zero compile or runtime dependencies: the JAR plus the JDK is enough, enforced by the build and visible in the published POM
- Secure defaults: every relaxation is a named compatibility mode that is off by default and observable
- Validated identities are produced only by validators, with no public constructors, builders or factories for them
- Framework-neutral and raw-input-first: the core parses raw query strings, form bodies and header values, and adapters only translate
- Immutability and thread safety, with injectable [`Clock`](https://docs.oracle.com/en/java/javase/27/docs/api/java.base/java/time/Clock.html), [`HttpClient`](https://docs.oracle.com/en/java/javase/27/docs/api/java.net.http/java/net/http/HttpClient.html) and observers for deterministic tests
- The common path for each protocol fits on one page of application code
- More test code than production code, at least as many negative tests as positive ones, and every security rule tested with a citation of its spec section or CVE
- Claims only with evidence that anyone can re-run

### Validation outcomes

Operations with several expected outcomes expose one immutable sealed result API. Success, absence, malformed input, checked provider denial and local validation rejection remain explicit where applicable. Optional return values mean only a value is present or absent; they never hide a parsing or validation outcome.

| Operation | Result entry point | Outcomes |
| --- | --- | --- |
| Access-token validation | [`AccessTokenValidator`](https://javadoc.revetsec.com/com/revetsec/oauth/AccessTokenValidator.html)`.validateResult` | `Succeeded` with [`VerifiedAccessToken`](https://javadoc.revetsec.com/com/revetsec/oauth/VerifiedAccessToken.html), credential `Rejected` with fixed reasons, or introspection `RejectedEndpoint` |
| JWT validation | [`JwtValidator`](https://javadoc.revetsec.com/com/revetsec/jose/JwtValidator.html)`.validateResult` | `Succeeded` with a checked [`Jwt`](https://javadoc.revetsec.com/com/revetsec/jose/Jwt.html), or `Rejected` with a fixed JOSE reason |
| Bearer header parsing | [`BearerToken`](https://javadoc.revetsec.com/com/revetsec/oauth/BearerToken.html)`.fromAuthorizationHeaderValuesResult` | `Absent`, `Present` with an unverified credential, or `Malformed` |
| Sealed application state | [`StateSealer`](https://javadoc.revetsec.com/com/revetsec/StateSealer.html)`.unsealResult` | `Succeeded` with authenticated plaintext, or an opaque `Rejected` |
| New password hash | [`PasswordHasher`](https://javadoc.revetsec.com/com/revetsec/password/PasswordHasher.html)`.hashResult` | `Succeeded` with a stored verifier, `Rejected`, or `Unavailable` |
| Password verification | [`PasswordHasher`](https://javadoc.revetsec.com/com/revetsec/password/PasswordHasher.html)`.verifyResult` | `Matched` with rehash advice, `NotMatched`, `Rejected`, or `Unavailable` |
| OAuth callback | [`OAuthClient`](https://javadoc.revetsec.com/com/revetsec/oauth/OAuthClient.html)`.completeAuthorizationResult` | `Succeeded`, `Denied`, `RejectedAuthorizationError`, `RejectedEndpoint`, local `Rejected`, or pending-store `Failed` |
| OIDC callback | [`OidcClient`](https://javadoc.revetsec.com/com/revetsec/oidc/OidcClient.html)`.completeAuthenticationResult` | `Succeeded`, `Denied`, checked authorization/endpoint rejection, local callback or ID-token rejection, or pending-store `Failed` |
| Pending transaction persistence | [`PendingAuthorization`](https://javadoc.revetsec.com/com/revetsec/oauth/PendingAuthorization.html)`.saveToResult` | `SAVED`, `ALREADY_PRESENT`, `CAPACITY_REFUSED`, `UNAVAILABLE`, or `INDETERMINATE`; redirect only after confirmed save |
| Callback parsing | [`AuthorizationResponse`](https://javadoc.revetsec.com/com/revetsec/oauth/AuthorizationResponse.html)`.fromQueryStringResult` / `fromFormBodyResult` | `Succeeded` with an untrusted callback, or fixed `Rejected` |
| Public-key document parsing | [`Jwks`](https://javadoc.revetsec.com/com/revetsec/jose/Jwks.html)`.fromJsonResult` | `Succeeded` with usable keys, or fixed structural `Rejected` |
| Metadata parsing | [`AuthorizationServerMetadata`](https://javadoc.revetsec.com/com/revetsec/oauth/AuthorizationServerMetadata.html)`.fromJsonResult` / [`OidcProviderMetadata`](https://javadoc.revetsec.com/com/revetsec/oidc/OidcProviderMetadata.html)`.fromJsonResult` | `Succeeded` with checked metadata, or fixed `Rejected` |
| Direct service token or OAuth refresh | [`OAuthClient`](https://javadoc.revetsec.com/com/revetsec/oauth/OAuthClient.html)`.requestClientCredentialsResult` / `refreshResult` | [`OAuthTokenRequestResult.Succeeded`](https://javadoc.revetsec.com/com/revetsec/oauth/OAuthTokenRequestResult.Succeeded.html) or fixed endpoint `Rejected` |
| Cached service token | [`ClientCredentialsTokenSource`](https://javadoc.revetsec.com/com/revetsec/oauth/ClientCredentialsTokenSource.html)`.getAccessTokenResult` | [`AccessTokenAcquisitionResult.Succeeded`](https://javadoc.revetsec.com/com/revetsec/oauth/AccessTokenAcquisitionResult.Succeeded.html) or fixed endpoint `Rejected` |
| Revocation | [`OAuthClient`](https://javadoc.revetsec.com/com/revetsec/oauth/OAuthClient.html)`.revokeResult` | [`OAuthRevocationResult.Succeeded`](https://javadoc.revetsec.com/com/revetsec/oauth/OAuthRevocationResult.Succeeded.html) or fixed endpoint `Rejected` |
| OIDC refresh | [`OidcClient`](https://javadoc.revetsec.com/com/revetsec/oidc/OidcClient.html)`.refreshResult` | [`OidcRefreshOutcome.Succeeded`](https://javadoc.revetsec.com/com/revetsec/oidc/OidcRefreshOutcome.Succeeded.html), local `Rejected`, or `RejectedEndpoint` |
| UserInfo | [`OidcClient`](https://javadoc.revetsec.com/com/revetsec/oidc/OidcClient.html)`.fetchUserInfoResult` | [`OidcUserInfoResult.Succeeded`](https://javadoc.revetsec.com/com/revetsec/oidc/OidcUserInfoResult.Succeeded.html), local `Rejected`, or `RejectedEndpoint` |
| Restored session reference | [`OidcSessionReference`](https://javadoc.revetsec.com/com/revetsec/oidc/OidcSessionReference.html)`.fromSerializedFormResult` / [`SamlSessionReference`](https://javadoc.revetsec.com/com/revetsec/saml/SamlSessionReference.html)`.fromSerializedFormResult`, or their sealed-form counterparts | A structural/session reference or a fixed rejection; no authenticated identity |

For example, an application can switch over JWT validation results:

```java
switch (validator.validateResult(compactJwt)) {
  case JwtValidationResult.Succeeded success ->
    useValidatedJwt(success.getJwt());
  case JwtValidationResult.Rejected rejection ->
    rejectRequest(rejection.getReason());
  default -> rejectRequest();
}
```

The application supplies the handling functions.
These hierarchies may gain variants, so keep a rejecting default in switches. Only successful validation releases a checked value;
expired or rejected tokens expose no identity or claims. Parsing a bearer header grants no permission. Sealed-state rejection exposes
no distinction between expiry, wrong context, unknown key or authentication failure. Result diagnostics redact their data.

Actual endpoint unavailability, malformed provider responses, transport, metadata and configuration failures retain their documented exception boundaries. Pending-store completion failures have fixed result variants. A checked callback `access_denied` yields `Denied`; other checked callback errors, including reported `server_error` and `temporarily_unavailable`, yield `RejectedAuthorizationError` with a fixed [`OAuthEndpointError`](https://javadoc.revetsec.com/com/revetsec/oauth/OAuthEndpointError.html). Endpoint client rejections carry only that fixed error and HTTP status. Completion result methods execute once and preserve atomic-store consumption,
the sealed-cookie replay boundary and observer behavior. The application clears pending cookies on every outcome and chooses generic
HTTP errors rather than reflecting detailed validation reasons to a remote caller.

### Design Non-Goals

- Operating a hosted identity service, OpenID Provider or SAML identity provider
- Implicit, hybrid and resource-owner-password flows, PKCE `plain`, and bearer tokens in query strings
- SAML Artifact binding, SOAP back-channel, ECP/PAOS, SAML 1.1 and WS-Federation
- RSA 1.5 and 3DES in XML Encryption, and unauthenticated AES-CBC decryption
- Sessions, user storage, routing, tenancy and persistence, which stay in your application
- Logging-framework integration, dependency injection, `ServiceLoader` discovery, Java serialization and reflection-based data binding

### Do Zero-Dependency Libraries Interest You?

Similarly-flavored commercially-friendly OSS libraries are available.

- [Soklet](https://www.soklet.com) - DI-friendly HTTP/1.1 server with support for virtual threads, Server-Sent Events, and Model Context Protocol
- [Pyranid](https://www.pyranid.com) - makes working with JDBC pleasant
- [Lokalized](https://www.lokalized.com) - natural-sounding translations (i18n) via expression language

### License

[Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0)

Attributions are kept in [`NOTICE`](NOTICE).

### Installation

Revetsec is a single JAR. JDK 17 or newer is required, with a minimum runtime of Java 17.0.3.

**Nothing has been published yet, including snapshots.** The version is `1.0.0-SNAPSHOT` until the first release. To try the current source, install it into your local Maven repository:

```shell
$ mvn -B -ntp -Dmaven.javadoc.skip=true install
```

#### Maven

```xml
<dependency>
  <groupId>com.revetsec</groupId>
  <artifactId>revetsec</artifactId>
  <version>1.0.0-SNAPSHOT</version>
</dependency>
```

#### Gradle

A Gradle build resolves a locally installed snapshot only when `mavenLocal()` is among its repositories.

```groovy
repositories {
  mavenLocal()
}

dependencies {
  implementation 'com.revetsec:revetsec:1.0.0-SNAPSHOT'
}
```

#### Framework adapters

Each adapter lives in its own repository, and its README lists its coordinates. An adapter declares Revetsec core and its framework API as `provided` dependencies, so your application declares both.

- [revetsec-soklet](https://github.com/revetsec/revetsec-soklet) for [Soklet](https://www.soklet.com) 4, requiring Java 21 or newer
- [revetsec-servlet-jakarta](https://github.com/revetsec/revetsec-servlet-jakarta) for the `jakarta.servlet` API
- [revetsec-servlet-javax](https://github.com/revetsec/revetsec-servlet-javax) for the legacy `javax.servlet` API

### Planned Scope

Every area below ships together in a single 1.0.0 release:

- OAuth 2.0 client
- App-integrated OAuth token issuance, with application-owned users, auth decisions and durable storage
- OAuth 2.0 resource server
- OpenID Connect relying party
- JOSE: JWS verification, bounded RSA signing, JWK and JWK Sets, and JWT validation
- SAML 2.0 service provider for Web Browser SSO, including encrypted assertions and front-channel Single Logout
- SCIM 2.0 server primitives
- WebAuthn relying-party registration, sign-in and account management
- TOTP authenticator enrollment, replay-protected verification and one-use recovery codes
- Argon2id password hashing with bounded work and explicit legacy verification

Each area gets its own section here, with application code, when it lands.

### TOTP and recovery codes

`TotpAuthenticator` provides confirmed enrollment, factor replacement/removal, replay-protected TOTP verification and one-use recovery-code batches. The application supplies durable opaque-record storage and an independent deployment recovery gate; accounts, authorization, primary authentication and sessions remain application-owned. Core stays at Java 17. See the [TOTP and recovery guide](docs/totp-recovery.md), [complete Soklet 4 integration](examples/totp-soklet/README.md), and unpublished [PostgreSQL durable-store fixture](examples/postgresql-pending-store/README.md#durable-totp-fixture).

### Password hashing

`PasswordHasher` creates Argon2id password verifiers, checks native stored forms, and optionally verifies selected bcrypt or PBKDF2 legacy records for migration. The application supplies a shared process-local work gate and owns account admission, password policy, credential-version compare-and-set, MFA and sessions. Optional pepper keys are separate from the credential database. See the [password hashing guide](docs/password-hashing.md).

### JOSE

`PublishedJwk` and `JwksPublisher` publish application-owned public verification keys without an OAuth authorization server. RSA (RS*/PS*), EC and Ed25519 keys, certificate chains, HTTP caching and Soklet/Servlet adapters are covered in the [standalone JWKS publication guide](docs/jwks-publication.md).

The [`JwtValidator`](https://javadoc.revetsec.com/com/revetsec/jose/JwtValidator.html) API validates a JWT signed with a public key, for one issuer, against a JSON Web Key Set. A [`RemoteJwksSource`](https://javadoc.revetsec.com/com/revetsec/jose/RemoteJwksSource.html) fetches your identity provider's key set on the first validation that needs it, on the calling thread, and caches it. Building either does no I/O.

```java
var keySource = RemoteJwksSource
  .withUri(URI.create("https://login.example.com/.well-known/jwks.json"))
  .build();

var validator = JwtValidator.withIssuer("https://login.example.com")
  .jwksSource(keySource)
  .expectedAudiences(Set.of("https://api.example.com"))
  .requiredClaims(Set.of("sub"))
  .build();

var result = validator.validateResult(token);
if (result instanceof JwtValidationResult.Succeeded success) {
  var jwt = success.getJwt();
  var subject = jwt.getClaims().getSubject().orElseThrow();
  // Apply application claim and permission checks to this validated JWT.
} else {
  // Reject the token; this outcome releases no checked claims.
}
```

Only the success variant releases the checked JWT. A rejection carries a fixed reason; remote key-source unavailability remains a [`JwksUnavailableException`](https://javadoc.revetsec.com/com/revetsec/jose/JwksUnavailableException.html) for the application error handler. Share one validator, and one key source, across threads. By default a token must be signed with RS256 and carry `iss`, `exp` and an expected audience, and its times are checked with 60 seconds of clock skew. `allowedAlgorithms` widens the algorithms (see [supported algorithms](docs/supported-algorithms.md)), and a [`JoseObserver`](https://javadoc.revetsec.com/com/revetsec/jose/JoseObserver.html) receives each validation, key-set fetch and skipped key. When key-set URLs come from your tenants, see "JSON Web Key Sets" in [SECURITY.md](SECURITY.md).

### OAuth client

The [`OAuthClient`](https://javadoc.revetsec.com/com/revetsec/oauth/OAuthClient.html) API supports authorization code with PKCE S256, client credentials, refresh, revocation and generated private-key assertions. It accepts static metadata or discovers an authorization server lazily. Browser completion checks the pending browser binding, state, callback route and issuer before token exchange. The [OAuth client guide](docs/oauth-client.md) covers cookie and store setup, concurrent replay, return destinations and the raw-token boundary.

For an OIDC sign-in example with an application-owned session and both query and form-post callbacks, start with the [barebones OIDC application](examples/barebones-oidc/README.md). It runs against a local test provider and rotates the browser session after successful authentication.

### OAuth authorization server

The `com.revetsec.oauth.server` package implements authorization, token issuance, refresh, revocation, introspection, metadata and JWKS operations. The application supplies registered clients, subject authentication, consent, grant policy, a durable atomic store, signing keys and the browser session. See the [application-contract guide](docs/oauth-server-application-contracts.md) and the [self-issued runnable example](examples/self-issued/README.md).

### RSA signing

The [`JwsSigner`](https://javadoc.revetsec.com/com/revetsec/jose/JwsSigner.html)`.fromRsaKeyPair(privateKey, publicKey, `[`JwsAlgorithm`](https://javadoc.revetsec.com/com/revetsec/jose/JwsAlgorithm.html)`.PS256)` creates a reusable signer with a checked public-key snapshot. It retains an application-owned private key without exporting it. Call `warmUp(remainingBudget)` for an explicit noncredential pair probe. Supply a typed [`JwtSigningHeader`](https://javadoc.revetsec.com/com/revetsec/jose/JwtSigningHeader.html) and [`JwtClaimsSet`](https://javadoc.revetsec.com/com/revetsec/jose/JwtClaimsSet.html) to sign a compact JWT without manual JSON serialization:

```java
var signer = JwsSigner.fromRsaKeyPair(
  privateKey, publicKey, JwsAlgorithm.PS256);
var now = Instant.now();
var claims = JwtClaimsSet.builder()
  .issuer("https://issuer.example.com")
  .subject("user-123")
  .audiences(List.of("https://api.example.com"))
  .issuedAt(now)
  .expiresAt(now.plusSeconds(300))
  .claim("role", "reader")
  .build();
var header = JwtSigningHeader.withType(JwtType.JWT)
  .keyId("key-1")
  .build();

var jwt = signer.fromHeaderAndClaims(header, claims);
```

The [`JwtType`](https://javadoc.revetsec.com/com/revetsec/jose/JwtType.html) enum supplies the protected header's `typ`; `alg` comes from the signer. The convenience method signs immediately with a two-second operation budget. Use `signer.withHeaderAndClaims(header, claims).remainingBudget(budget).build()` to override that budget; constructing the builder does not sign. The terminal `build()` signs and verifies the output before releasing the compact credential. The existing `toCompactSerialization(type, keyId, certificateSha256Thumbprint, claimsUtf8, remainingBudget)` remains available to sign an exact, bounded JSON object supplied as bytes.

PS256, RS256 and RS384 are supported. The optional 32-byte thumbprint is the SHA-256 digest of a DER certificate. The application supplies claims and remains responsible for their meaning. A checked JCA exception or provider [`RuntimeException`](https://docs.oracle.com/en/java/javase/27/docs/api/java.base/java/lang/RuntimeException.html), mismatched pair or exhausted budget produces a fixed [`JwsSigningException`](https://javadoc.revetsec.com/com/revetsec/jose/JwsSigningException.html); it emits no partial credential. Provider [`Error`](https://docs.oracle.com/en/java/javase/27/docs/api/java.base/java/lang/Error.html) values propagate after buffer cleanup, following the library’s unexpected-error boundary. JCA providers must cooperate with synchronous time budgets. See [algorithms and bounds](docs/supported-algorithms.md#bounded-rsa-signing-jwssigner). OAuth clients support private_key_jwt, and the issuer implements token issuance.

### Status

Revetsec is **pre-release**. The version is `1.0.0-SNAPSHOT`, and there is no compatibility promise before 1.0.0; see [COMPATIBILITY.md](COMPATIBILITY.md).

The repository includes shared foundations, JOSE, an OAuth client and issuer, an OpenID Connect relying party, resource-server validation, a SAML SP, SCIM server primitives and a WebAuthn relying party. The SAML SP's [RC-2 readiness gate](docs/reviews/rc-2-round-1.md#rc-2-closure--2026-10-14) closed on 2026-10-14; its [integration guide](docs/saml-sp.md) describes deployment contracts. SCIM's API was frozen on 2026-10-14; see its [server guide](docs/scim-server-primitives.md). Subsequent API changes still require consolidated review against the final release source.

On 2026-10-15, the local [WebAuthn browser example](examples/passkeys-soklet/README.md) passed registration, discoverable sign-in, account-pinned reauthentication and rejection after server-side credential removal with a Yubico Security Key C NFC over USB. WebAuthn's dedicated review and final release qualification remain open. The [PostgreSQL example](examples/postgresql-pending-store/README.md) also passed its full storage/Soklet application lanes on Java 17 and 27, including synthetic WebAuthn recovery checks, on one host and one authoritative primary. These observations retain their tested source and environment scope.

The application supplies users, permissions, sessions, routes and durable storage. The Soklet, Jakarta Servlet and javax Servlet adapters provide transport helpers across OAuth, bearer admission, issuer endpoints, SAML, SCIM and WebAuthn as documented in each adapter. Applications choose validators and make permission decisions.

Revetsec has not been independently audited. Its bounded security evidence is in [`docs/`](docs/): the [threat model](docs/threat-model.md), [interop matrix](COMPATIBILITY.md), [RC-1 local OAuth/OIDC qualification and Burp closeout](docs/pentest/2026-10-15-rc1-burp.md), [RC-2 review and closure](docs/reviews/rc-2-round-1.md), [SAML pentest notes](docs/pentest/2026-10-13.md), and [mutation ledger](docs/saml-mutation-triage-2026-10-11.md). [Fuzz evidence](fuzz/README.md) includes local runs and planted-defect checks. Other 1.0.0 release evidence is still being assembled.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

### Development Verification

With `JAVA_HOME` pointing at JDK 17 or newer:

```shell
$ mvn -B -ntp -Dmaven.javadoc.skip=true verify
```

[CONTRIBUTING.md](CONTRIBUTING.md) gives the local commands for each check in `ci.yml` that gates a pull request, and names the other workflows. The workflows in [`.github/workflows/`](.github/workflows/) remain the source of truth.

### Resource-server protocol helpers

The [`BearerToken`](https://javadoc.revetsec.com/com/revetsec/oauth/BearerToken.html)`.fromAuthorizationHeaderValuesResult(values)` operation parses raw Authorization fields into an **unverified** credential. Preserve duplicates: an empty list returns `Absent`; malformed or multiple values return `Malformed`, which the application can map to `invalid_request`. Only `Present` carries a credential. Other authentication schemes follow the same strict malformed-input policy. The credential has no public value getter. Parsing grants no identity or permission; pass the credential to a configured resource validator.

The [`BearerChallenge`](https://javadoc.revetsec.com/com/revetsec/oauth/BearerChallenge.html)`.builder().resourceMetadata(metadataUri).build().getHeaderValue()` supplies a bounded initial challenge with no error. Set a trusted realm, fixed error/description or required operation scopes as appropriate; the application chooses the HTTP status. At least one rendered parameter is required. [`ProtectedResourceMetadata`](https://javadoc.revetsec.com/com/revetsec/oauth/ProtectedResourceMetadata.html)`.withResource(resourceUri)` renders header-only bearer metadata and derives its well-known URI from raw path/query components, preserving the configured identifier. Both are pure helpers with HTTPS defaults and an explicit loopback HTTP option.

The [`AuthorizationResponse`](https://javadoc.revetsec.com/com/revetsec/oauth/AuthorizationResponse.html)`.fromFormBodyResult(body, contentTypeValues, rawQuery)` operation validates one bounded raw form Content-Type with absent/UTF-8 charset, then applies the existing duplicate and query/body channel checks. The result parser also accepts an explicit-charset overload. Transports that collapse identical physical header values need a trusted edge that rejects duplicate Authorization and Content-Type fields.

### Resource-server validation

The [`JwtAccessTokenValidator`](https://javadoc.revetsec.com/com/revetsec/oauth/JwtAccessTokenValidator.html)`.withIssuer(issuer).expectedAudiences(`[`Set`](https://docs.oracle.com/en/java/javase/27/docs/api/java.base/java/util/Set.html)`.of(resource)).build()` validates strict RFC 9068 JWT access tokens. It requires an access-token type, exact issuer, intended audience, valid signature, `exp`, `iat`, and nonempty `sub`, `client_id` and `jti`. Its public-key algorithm default is RS256. A supplied key source bypasses discovery; static keys perform no network I/O. Explicit untyped compatibility requires an additional claim and rejects identity-token claims; it does not grant permissions.

The [`TokenIntrospectionClient`](https://javadoc.revetsec.com/com/revetsec/oauth/TokenIntrospectionClient.html)`.withOAuthClient(confidentialClient).expectedAudiences(`[`Set`](https://docs.oracle.com/en/java/javase/27/docs/api/java.base/java/util/Set.html)`.of(resource)).build()` inherits the OAuth client's authentication, issuer, HTTP policy, clock and deadlines. Each validation sends one authenticated JSON introspection request. Active and inactive results are uncached; the response must identify the intended audience. Non-transient endpoint client errors return [`AccessTokenValidationResult.RejectedEndpoint`](https://javadoc.revetsec.com/com/revetsec/oauth/AccessTokenValidationResult.RejectedEndpoint.html), which carries no Bearer invalid-token error. Outages and malformed provider responses remain exceptions, with bounded endpoint-wide backoff and one recovery probe.

Both implement [`AccessTokenValidator`](https://javadoc.revetsec.com/com/revetsec/oauth/AccessTokenValidator.html) with one `validateResult` operation for sealed outcomes. Only `Succeeded.getAccessToken()` releases checked proof. [`VerifiedAccessToken`](https://javadoc.revetsec.com/com/revetsec/oauth/VerifiedAccessToken.html) contains checked claims, optional subject/client ID/expiry, audiences and scopes; it has no incoming-credential getter. Claims are sensitive explicit access. Empty scopes grant no permission, and application code still decides operation, tenant and object authorization.

Role-specific discovery needs only issuer/JWKS for JWT or issuer/introspection endpoint for introspection. The existing OAuth metadata parser still requires authorization and token endpoints. `warmUp()` performs discovery/key loading without validating a credential. Builds perform no I/O and start no threads.

Generated OAuth `private_key_jwt` authentication uses [`ClientAssertionSigningKey`](https://javadoc.revetsec.com/com/revetsec/oauth/ClientAssertionSigningKey.html) and a caller-thread [`ClientAssertionKeyProvider`](https://javadoc.revetsec.com/com/revetsec/oauth/ClientAssertionKeyProvider.html). See [the OAuth client guide](docs/oauth-client.md#private-key-client-assertions) for role metadata, audience compatibility and deadline rules. Hosted private-key qualification remains pending.

### Microsoft Entra issuer policy

OIDC clients can explicitly select the fixed public-cloud `common` or `organizations` v2.0 issuer policy with an application-owned allowed-tenant predicate. The engine verifies the token signature and the actual tenant/issuer/JWK binding before invoking that predicate. The authenticated account key remains the actual tenant issuer and subject. See [the issuer policy guide](docs/oidc-issuer-policy.md) for metadata, UserInfo and refresh behavior. Local synthetic tests cover this path; hosted Entra sign-in remains unproven.
