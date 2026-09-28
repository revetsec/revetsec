# Revetsec

### What Is It?

A zero-dependency Java library for OAuth 2.0 clients and resource servers, OpenID Connect relying parties, JOSE, SAML 2.0 service providers and SCIM 2.0 servers.

**Revetsec is pre-release.** So far it verifies signed JWTs against JSON Web Key Sets; the OAuth, OpenID Connect, SAML and SCIM areas do not exist yet. This README describes what it is being built to do; see [Status](#status) for what exists.

Revetsec handles the application side of these protocols. It builds outbound requests, parses and validates what comes back, and hands your code a validated result or an exception. Your application keeps its own users, sessions, routes and storage.

Framework adapters for [Soklet](https://www.soklet.com) and the Servlet API are separate artifacts in their own repositories (see [Installation](#installation)).

### Why?

Adding single sign-on, API protection or user provisioning to a Java application usually means assembling several libraries, one per protocol, each with its own dependency tree, release cadence and advisory stream.

Revetsec aims to cover the common application-side needs of these protocols with one artifact and the JDK: one dependency, one version, and one place to report and track security issues.

It is a library, not a framework or an identity server. It has protocol-specific APIs rather than one abstraction over every protocol, and it does not treat an OAuth token response as an authenticated identity.

### Design Goals

- Main focus: the application side of OAuth 2.0, OpenID Connect, SAML 2.0 and SCIM 2.0
- Zero compile or runtime dependencies: the JAR plus the JDK is enough, enforced by the build and visible in the published POM
- Secure defaults: every relaxation is a named compatibility mode that is off by default and observable
- Validated identities are produced only by validators, with no public constructors, builders or factories for them
- Framework-neutral and raw-input-first: the core parses raw query strings, form bodies and header values, and adapters only translate
- Immutability and thread safety, with injectable `Clock`, `HttpClient` and observers for deterministic tests
- The common path for each protocol fits on one page of application code
- More test code than production code, at least as many negative tests as positive ones, and every security rule tested with a citation of its spec section or CVE
- Claims only with evidence that anyone can re-run

### Design Non-Goals

- Acting as an OAuth authorization server, OpenID Provider or SAML identity provider
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

- [revetsec-soklet](https://github.com/revetsec/revetsec-soklet) for [Soklet](https://www.soklet.com)
- [revetsec-servlet-jakarta](https://github.com/revetsec/revetsec-servlet-jakarta) for the `jakarta.servlet` API
- [revetsec-servlet-javax](https://github.com/revetsec/revetsec-servlet-javax) for the legacy `javax.servlet` API

### Planned Scope

Every area below ships together in a single 1.0.0 release:

- OAuth 2.0 client
- OAuth 2.0 resource server
- OpenID Connect relying party
- JOSE: JWS verification, JWK and JWK Sets, and JWT validation
- SAML 2.0 service provider for Web Browser SSO, including encrypted assertions and front-channel Single Logout
- SCIM 2.0 server primitives

Each area gets its own section here, with application code, when it lands.

### JOSE

`JwtValidator` validates a JWT signed with a public key, for one issuer, against a JSON Web Key Set. A `RemoteJsonWebKeySource` fetches your identity provider's key set on the first validation that needs it, on the calling thread, and caches it. Building either does no I/O.

```java
RemoteJsonWebKeySource keySource = RemoteJsonWebKeySource
  .withUri(URI.create("https://login.example.com/.well-known/jwks.json"))
  .build();

JwtValidator validator = JwtValidator.withIssuer("https://login.example.com")
  .jsonWebKeySource(keySource)
  .expectedAudiences(Set.of("https://api.example.com"))
  .build();

try {
  Jwt jwt = validator.validate(token);
  String subject = jwt.getClaims().getSubject().orElseThrow();
  // The token is valid: signed by a key from the key set, for this issuer and audience, and not expired.
} catch (JoseException e) {
  // The token was refused. e.getReason() says why, such as EXPIRED or SIGNATURE_MISMATCH;
  // the message never contains the token.
} catch (JsonWebKeySetUnavailableException e) {
  // The key set could not be fetched. e.isTransient() says whether trying again later may help.
}
```

Share one validator, and one key source, across threads. By default a token must be signed with RS256 and carry `iss`, `exp` and an expected audience, and its times are checked with 60 seconds of clock skew. `allowedAlgorithms` widens the algorithms (see [supported algorithms](docs/supported-algorithms.md)), and a `JoseObserver` receives each validation, key-set fetch and skipped key. When key-set URLs come from your tenants, see "JSON Web Key Sets" in [SECURITY.md](SECURITY.md).

### Status

Revetsec is **pre-release**. The version is `1.0.0-SNAPSHOT`, and there is no compatibility promise before 1.0.0; see [COMPATIBILITY.md](COMPATIBILITY.md).

The repository holds the build, contract tests, CI configuration and documents (milestone M0), the shared foundations (milestone M1) and JOSE (milestone M2). The foundations are the exception root and error categories, `StateSealer` for sealing short-lived state with key rotation, an outbound URI policy with two presets, and the JSON value model, plus internal parsers and a bounded HTTP helper that the protocol areas use. JOSE is `JwtValidator` with static and remote JSON Web Key Sets, as above. No OAuth, OpenID Connect, SAML or SCIM code exists yet.

Revetsec has not been independently audited. Its security evidence is meant to be reproducible by anyone and will be listed in [`docs/`](docs/) as it is produced: conformance logs, the interop matrix, the threat model with its invariant-to-test map, review ledgers, penetration-test notes, and fuzz and mutation reports. So far the [threat model](docs/threat-model.md) maps the invariants of the foundations and JOSE to their tests, and [fuzz/README.md](fuzz/README.md) records local fuzzing runs and planted-defect checks for the fuzz targets; the rest does not exist yet.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

### Development Verification

With `JAVA_HOME` pointing at JDK 17 or newer:

```shell
$ mvn -B -ntp -Dmaven.javadoc.skip=true verify
```

[CONTRIBUTING.md](CONTRIBUTING.md) gives the local commands for each check in `ci.yml` that gates a pull request, and names the other workflows. The workflows in [`.github/workflows/`](.github/workflows/) remain the source of truth.
