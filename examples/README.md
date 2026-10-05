# Revetsec examples

Two unpublished Soklet projects use packaged core, adapter and framework artifacts. A separate [RSA/OIDC recipe project](rsa-oidc/README.md) uses the current authored core only, with private-key authentication and synthetic Entra captures:

| Project | Demonstrates | Soklet |
|---|---|---|
| [barebones-oidc](barebones-oidc/README.md) | OIDC login and an application-owned session | Official 3.5.1 |
| [playground](playground/README.md) | OIDC login, JWT/introspection MCP `whoami`, resource metadata, scope and application permissions, client credentials and transient inspection | Source-built 4.0.0 |

The examples are outside the core reactor. `pins.json` records already-pushed core/helper revisions and the exact framework source. They do not publish artifacts. Revetsec has not been independently audited.

## Build

Check out the revisions in `pins.json` for the adapter and Soklet framework. A core checkout with unchanged `pom.xml` and `src/main` relative to its pin can supply the core artifact. The builder checks these inputs, copies them into a new private directory and uses its own Maven repository. Optional `--repository-tail` is read-only; `--offline` requires cached build dependencies.

```sh
python3 examples/build.py --work /absolute/new/example-build \
  --maven /absolute/path/to/mvn --java-home /absolute/path/to/jdk \
  --core-source /absolute/core-checkout --adapter-source /absolute/adapter-checkout \
  --framework-source /absolute/pinned-soklet-checkout
```

The builder runs both example test suites and checks their runtime classpaths contain exactly the three declared dependency JARs. Provided annotation JARs are absent at runtime. It records commands, artifact checksums and exact source pins in the private result. The alternative `--framework-jar` accepts only the recorded source-built JAR checksum. Java 17 source compatibility is retained when tests run on later JDKs.

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
