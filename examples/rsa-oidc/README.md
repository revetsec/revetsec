# RSA client authentication and Entra login

Two compiled configuration recipes use only the packaged Revetsec core artifact. They can configure the `OidcClient` injected into a Soklet application's login handler. The application supplies registered keys, trusted callback configuration, tenant decisions, pending storage and sessions. These recipes do not issue OAuth tokens or implement an authorization server.

- [PrivateKeyClients](src/main/java/example/rsa/PrivateKeyClients.java) builds issuer-audience OAuth clients from trusted metadata and an application key provider. Its fixed-key helper takes an existing JCA key pair; it performs no key generation, loading, serialization or registration.
- [EntraLogin](src/main/java/example/rsa/EntraLogin.java) selects the fixed public-cloud common/organizations policy. Supply a fast, thread-safe tenant predicate. An authenticated tenant is eligible for application authorization; it is not itself a permission decision.

## Application configuration

For a provider registered for private-key authentication, supply `PrivateKeyClients.registeredKey(applicationKeyPair, JwsAlgorithm.PS256, registeredKeyId)` to `PrivateKeyClients.withMetadata(metadata, clientId, keyProvider)`, then build. Register the **public** key first. Persist and protect the private key in the application's own key system. For rotation, implement `ClientAssertionKeyProvider` to return one immutable `ClientAssertionSigningKey` snapshot with its matching registered identifier per call. Keep previously registered verification keys for the required overlap. Do not return separately rotated key and header fields.

Issuer audience is the default: `typ=client-authentication+jwt`, sole `aud` equal to the exact configured issuer. Every actual credential POST gets a fresh assertion and identifier; cache hits make no key call. RS256, RS384 and PS256 are available with no negotiation or fallback. Token and revocation method lists must name `private_key_jwt`; absent lists mean Basic. Present signing-algorithm lists must allow the selected algorithm. Configure introspection's own role lists or explicit out-of-band registration; token and ID-token algorithm lists do not authorize introspection. All asserted POST endpoints must share the issuer's origin. Do not copy metadata across providers or substitute a token URL for another role.

For a provider requiring endpoint compatibility, use `ClientAuthentication.withPrivateKeyJwt(keyProvider).audience(ClientAssertionAudience.TOKEN_ENDPOINT).build()`. The audience is the **actual** token, revocation or introspection POST URL and `typ=JWT`. Keycloak 26.7.4 rejects endpoint-audience revocation in our local registration; retain the default issuer audience for that version. No automatic retry or secret fallback is performed.

For Entra, pass the exact `https://login.microsoftonline.com/organizations/v2.0` or `https://login.microsoftonline.com/common/v2.0`, registered client ID and callback to `EntraLogin.withIssuer`. Keep an application-owned tenant allowlist and deny consumer accounts unless intended. Microsoft's documented private-key profile uses explicit endpoint compatibility, PS256 and the SHA-256 digest of the registered DER certificate: build `ClientAssertionSigningKey.withSigner(signer).certificateSha256Thumbprint(applicationCertificateDigest).build()`. The application supplies the digest and certificate enrollment. The local fixture instead registers a synthetic key ID; it is not a hosted certificate acceptance test. Hosted issuer-audience acceptance is also unproven.

At login, use `beginAuthentication`, save its pending record with a browser-specific secret binding in an atomic `PendingAuthorizationStore`, then complete through `completeAuthenticationResult` with the exact trusted callback URI. The [barebones Soklet example](../barebones-oidc/README.md) demonstrates the surrounding cookies, CSRF checks and application session rotation. Never derive issuer/callback/tenant routing from incoming headers or unsigned claims. A successful authentication gives the actual verified `(issuer, subject)` identity; persist that tuple, not email or the common issuer. Restored `OidcSessionReference` is comparison data, not proof. Another allowed tenant cannot replace the original during refresh. UserInfo requires the original associated authentication and a current tenant decision before Bearer disclosure. Follow the [issuer policy guide](../../docs/oidc-issuer-policy.md) for the remaining session contracts.

## Build and run the owned fixture

This example uses the current authored core source, including explicitly inventoried uncommitted changes. It leaves the older Soklet examples' pushed artifact pins intact. Use a new private work directory outside the core checkout:

```sh
python3 examples/rsa-oidc/build.py --work /absolute/new/rsa-example-build \
  --maven /absolute/path/to/mvn --java-home /absolute/path/to/jdk \
  --core-source /absolute/core-checkout --offline \
  --repository-tail /absolute/read-only/maven-cache
```

The builder copies Git-tracked and nonignored authored inputs, installs core into its own repository, creates a two-day SAN-correct disposable TLS store, compiles and tests the recipes, and audits every main/test reference signature for explicit JSpecify annotations. The example's runtime dependency list contains **only core**; annotations are provided and JUnit belongs only to the test runner. It then launches a separate Java process to run nine scenarios and write `CAPTURE.json`. Java 17 source compatibility is retained; CI runs on JDK 17 and 27.

The owned fixture binds IPv4 loopback and checks normal TLS hostname verification with its scoped trust store. JCA verifies outgoing assertions against fresh in-memory public RSA projections, including the PS256 parameters, role audiences, type, claims, lifetime and fresh identifiers. Three signing algorithms use issuer audience; PS256 also uses endpoint audience. Each scenario exercises client credentials/cache, refresh, introspection and revocation. Entra scenarios run PS256 endpoint assertions, template discovery and JWK issuer validation, login/UserInfo, tenant denial, forged signature, missing key issuer and refresh to another allowed tenant.

**Synthetic Entra routing:** a test-source-only `HttpClient` maps the exact configured Microsoft fixture paths to the owned local TLS listener. It never contacts Microsoft and must never be used in an application. The synthetic authorization code carries a generated nonce for fixture correlation; it is not a browser/provider PKCE acceptance test. Genuine PKCE/private-key provider qualification is separately covered by the integration fixtures. No hosted account, interactive browser or Microsoft-issued token is involved.

The capture writes only fixed case labels, checked booleans and aggregate counts. It contains no JWT, access/refresh token, private key, nonce, code, subject, tenant, cookie or session reference. Private TLS stores and runtime state stay in the work directory; do not upload them. Delete that directory after retaining the redacted JSON and selected test evidence. No system trust store or user keychain changes.

## Qualification limits

[The dated provider results](../../COMPATIBILITY.md#local-private-key-client-authentication-observed-2026-10-02) retain the Keycloak revocation deviation and node's explicit RS384/role registration settings. The selected comprehensive OIDF private-key profile runs 23 applicable modules alongside 37 inherited runs. Its five unsupported-profile modules remain `NOT_RUN`: WebFinger account/URL discovery, aggregated/distributed claims and UserInfo bearer request bodies. Eleven declarations do not apply to the selected variant; four unsigned-token rejection runs have documented skip outcomes. The upstream Basic module is recorded separately. These examples add no full-plan, certification or hosted-compatibility claim.

Revetsec has not been independently audited.
