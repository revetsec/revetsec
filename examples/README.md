# Revetsec examples

Two unpublished Soklet projects use packaged core, adapter and framework artifacts. A separate [RSA/OIDC recipe project](rsa-oidc/README.md) uses the current authored core only, with private-key authentication and synthetic Entra captures:

| Project | Demonstrates | Soklet |
|---|---|---|
| [barebones-oidc](barebones-oidc/README.md) | OIDC login and an application-owned session | Pinned 4.0.0 |
| [playground](playground/README.md) | OIDC and SAML browser sessions, JWT/introspection MCP `whoami`, resource metadata, scope and application permissions, client credentials and transient inspection | Pinned 4.0.0 |

A separate [self-issued MCP Playground](self-issued/README.md) uses current core/helper sources for app-owned OAuth issuance and online MCP validation with bounded volatile sessions/storage. Its builder records the authored core/helper inputs separately from the packaged-example pins below.

The [Soklet passkey browser demo](passkeys-soklet/README.md) exercises registration, discoverable sign-in, account-pinned reauthentication and credential management with an explicitly selected volatile WebAuthn store and exact HTTPS DNS origin.

The [complete Soklet 4 TOTP integration](totp-soklet/README.md) shows enrollment, confirmation, replacement, TOTP login, recovery login, rotation, removal, cancellation and status with application-owned authorization, sessions, durable storage and recovery admission. Its isolated builder compiles against the current core and pinned Soklet JAR on Java 21 or newer. The examples CI job runs its boundary, lifecycle and loopback socket checks.

The paired [Jakarta Servlet](https://github.com/revetsec/revetsec-servlet-jakarta/blob/main/docs/totp.md) and [Javax Servlet](https://github.com/revetsec/revetsec-servlet-javax/blob/main/docs/totp.md) cookbooks live in their adapter repositories. Their Java 17 sources call core directly from application-owned routes, with disposable Tomcat 11 and 9 fixtures. They do not supply production primary authentication, durable sessions or a cross-host recovery gate.

The [Java 17 password hashing example](password-hashing/README.md) runs directly
against current core. It demonstrates bounded Argon2id work, an ephemeral pepper
key and exact-version compare-and-set rehashing without an HTTP adapter.

The standalone [PostgreSQL storage examples](postgresql-pending-store/README.md) show application-owned shared pending-authorization storage, an optional CIMD cache, an authoritative issuer store and a WebAuthn store, all using Pyranid. They are outside the core reactor and are not a managed database service.

The examples are outside the core reactor. `pins.json` records already-pushed core/helper revisions and the exact framework source. They do not publish artifacts. Revetsec has not been independently audited.

## Build

Use JDK 21 or newer for Soklet examples. The framework source build uses Corretto 21.0.11 so its JAR matches the recorded checksum.

Check out the revisions in `pins.json` for the adapter and Soklet framework. A core checkout with unchanged `pom.xml` and `src/main` relative to its recorded pin can supply the core artifact for a manual build. CI passes its exact run commit with `--core-revision` so the examples exercise the pushed core under test; the builder requires the source checkout to match that SHA and records it in the result. The builder copies these inputs into a new private directory and uses its own Maven repository. Optional `--repository-tail` is read-only; `--offline` requires cached build dependencies.

```sh
python3 examples/build.py --work /absolute/new/example-build \
  --maven /absolute/path/to/mvn --java-home /absolute/path/to/jdk \
  --core-source /absolute/core-checkout --adapter-source /absolute/adapter-checkout \
  --framework-source /absolute/pinned-soklet-checkout
```

The builder runs both example test suites and checks their runtime classpaths contain exactly the three declared dependency JARs. Provided annotation JARs are absent at runtime. It records commands, artifact checksums and exact source pins in the private result. The alternative `--framework-jar` accepts only the recorded source-built JAR checksum. Soklet applications require Java 21 or newer; CI checks them on JDK 21 and 27. The framework JAR is built with the exact Corretto version recorded in `pins.json` before those application lanes run. Core and the core-only RSA/OIDC recipes retain Java 17 compatibility.

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
python3 examples/run.py --build /absolute/example-build --example playground \
  --java-home /absolute/jdk --trust-store /private/tls/java-trust.p12
```

Interrupt the app and provider and remove their private work/profile directories after use. Examples store no browser credentials in localStorage/sessionStorage. The transient inspection form is an explicit CSRF-protected demonstration and never becomes MCP bearer transport. Only allowlisted application-redacted fields from checked results are displayed.
