# Revetsec examples

Build the public examples with Maven and launch the applications with Java.
The example projects and a small demo-key utility share an [examples parent POM](pom.xml), separate from the
core build. They are unpublished and do not deploy artifacts.

| Project | Demonstrates | Entry point |
| --- | --- | --- |
| [Barebones OIDC](barebones-oidc/README.md) | Browser sign-in and application-owned sessions | Executable JAR |
| [Playground](playground/README.md) | OIDC/SAML sessions, JWT/introspection MCP admission and SCIM routes | Executable JAR; separate SCIM main |
| [Self-issued MCP](self-issued/README.md) | Application-owned OAuth issuance, refresh, revocation and MCP permissions | Executable JAR |
| [Passkeys](passkeys-soklet/README.md) | Registration, discoverable sign-in, reauthentication and removal | Executable JAR behind an HTTPS edge |
| [TOTP and recovery](totp-soklet/README.md) | Enrollment, replacement, login, recovery and management | Injected application integration and Maven tests |
| [Password hashing](password-hashing/README.md) | Bounded Argon2id work, pepper and exact-version rehashing | Executable console JAR |
| [RSA/OIDC recipes](rsa-oidc/README.md) | Private-key client authentication and explicit Entra tenant decisions | Integration recipes and Maven tests |
| [Google/Apple with Soklet](provider-backend-tokens-soklet/README.md) | Common provider-token flows through bounded Soklet routes and current account policy | Injected Java 21 integration; trusted HTTPS/query-free edge required |
| [Local-first OIDC logout](rp-initiated-logout/README.md) | Authorized local session close, bounded provider preparation and correlated return | Common Java 17 application recipe and Maven tests |
| [OIDC logout with Soklet](rp-initiated-logout-soklet/README.md) | Shared logout workflow through bounded raw Soklet requests | Injected Java 21 integration; trusted HTTPS/query-free edge required |
| [Key import](key-import/README.md) | Bounded application-owned DER files and explicit pair checking | Executable console JAR |
| [Google/Apple backend tokens](provider-backend-tokens/README.md) | Request-bound provider tokens, local session rotation and current authorization | Common application recipe and Maven tests |
| [PostgreSQL stores](postgresql-pending-store/README.md) | Shared pending logins, metadata cache, issuer, SCIM, TOTP and WebAuthn storage | Store recipes; optional Docker failure tests |

The paired [Jakarta Servlet](https://github.com/revetsec/revetsec-servlet-jakarta/blob/main/docs/totp.md)
and [Javax Servlet](https://github.com/revetsec/revetsec-servlet-javax/blob/main/docs/totp.md)
TOTP cookbooks live with their adapters. Applications supply production accounts,
authorization, durable sessions/storage and coordinated recovery admission.

## Build with Maven

Use JDK 21 or newer for the full reactor and Soklet applications. Core-only
password, RSA, key-import, common logout and provider-token recipes retain Java 17 compatibility. Select the JDK with
`JAVA_HOME` and put its `bin` directory on `PATH` so Maven and Java agree.

Revetsec core 1.0.0, the Revetsec Soklet adapter 1.0.0 and Soklet 4.0.0 are
published Maven Central coordinates. Soklet's coordinates and artifact hashes
are recorded in [pins.json](pins.json). From the core repository root:

```sh
mvn -B -ntp -f examples/pom.xml verify
```

This runs the example tests and packages the applications. To build one project instead, use, for example:

```sh
mvn -B -ntp -f examples/pom.xml -pl passkeys-soklet -am verify
```

Maven manages compile, test and runtime dependencies. Each executable JAR has a
manifest entry point and uses its sibling `target/lib` directory. Keep that JAR
and `lib` together when moving an application. Annotation libraries are provided
at compile time, and JUnit stays in test scope; neither is a runtime dependency.
A build does not start Docker or contact a hosted identity provider. Some tests
bind disposable loopback listeners.

After supplying the selected project's environment configuration, launch it
from the core repository root:

```sh
java -jar examples/playground/target/playground-1.0.0.jar
```

Each project README describes its configuration. TOTP, RSA, logout and PostgreSQL are
integration recipes: their Maven build does not invent primary authentication,
application security or a database service.

## Optional verification tools

Python is not required to build or launch these Java applications. The optional
passkey TLS helper generates a disposable private CA and exact-DNS certificates
without changing global trust. The PostgreSQL Python runners coordinate Docker,
separate JVM races, outages, uncertain commits and restore tests. Those runners
are test tools, separate from the normal Maven build.

Additional source-pin, published-artifact, nullability and annotation-free runtime audits
live under [verification/examples](../verification/examples/README.md).
CI retains the exact adapter source pin and checksum-bound Central framework artifacts, including the explicit
[test-only adapter compatibility bridge](compatibility/soklet-shared-clock/README.md).
Revetsec has not been independently audited.

## Local provider and HTTPS

The [HTTPS recipe](../interop/local-https/README.md) creates a fresh two-day test CA and SAN-correct leaf without changing machine trust. Set the example origin to the configured HTTPS site; every backend listener binds IPv4 loopback. Cookies stay Secure and HttpOnly. For manual browsing, choose whether to trust the disposable CA yourself. Unattended checks use a private scoped CA store and normal hostname verification.

For the locked node-provider preset, copy its four source/package inputs to a private directory and run `npm ci --omit=dev --ignore-scripts` there. Start with:

```sh
TEST_RESOURCE_MODE=playground TEST_BIND_ADDRESS=127.0.0.1 PORT=9443 \
  ISSUER=https://localhost:9443 \
  TLS_CERT_FILE=/private/tls/localhost.crt TLS_KEY_FILE=/private/tls/localhost.key \
  TEST_CLIENT_REDIRECT_URIS=https://localhost:8443/oidc/callback,https://localhost:8445/callback \
  node /private/provider/server.js
```

This preset uses genuine provider issuance and public-client registration. It automatically logs in the synthetic `test-user` and grants requested scopes; expose it only on disposable loopback test systems. The fixed synthetic confidential client is `revetsec-test-client`, with basic-auth secret `test-only-client-secret-not-a-real-secret`; Inspector registers a separate public client. `TEST_PLAYGROUND_TOKEN_FORMAT=opaque` selects the introspection preset; default `jwt` selects strict resource JWTs. Restart the example and provider when changing preset: keys, grants and in-memory sessions reset. Never retain issued tokens or provider/browser state in source control.

The [Keycloak preset](providers/README.md) supplies another local OIDC/JWT/introspection provider. Hosted OIDC configuration is possible, but no hosted account compatibility is asserted from these local checks.

Create a private JVM truststore for the local provider, using the selected JDK's keytool:

```sh
/absolute/jdk/bin/keytool -importcert -noprompt -alias local-example-ca \
  -file /private/tls/ca.crt -keystore /private/tls/java-trust.p12 \
  -storetype PKCS12 -storepass changeit
```

`changeit` protects only a disposable public CA truststore. No installed JDK cacerts or user keychain is changed. Follow each project's environment configuration, start Caddy with the pinned recipe, then launch the packaged application:

```sh
java -Djavax.net.ssl.trustStore=/private/tls/java-trust.p12 \
  -Djavax.net.ssl.trustStorePassword=changeit \
  -jar examples/playground/target/playground-1.0.0.jar
```

Interrupt the app and provider and remove their private work/profile directories after use. Examples store no browser credentials in localStorage/sessionStorage. The transient inspection form is an explicit CSRF-protected demonstration and never becomes MCP bearer transport. Only allowlisted application-redacted fields from checked results are displayed.
