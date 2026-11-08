# Private-key client authentication and Entra login

Two compiled configuration recipes use only the packaged Revetsec core artifact. They can configure the `OidcClient` injected into a Soklet application's login handler. The application supplies registered keys, trusted callback configuration, tenant decisions, pending storage and sessions. These recipes do not issue OAuth tokens or implement an authorization server.

- [PrivateKeyClients](src/main/java/example/rsa/PrivateKeyClients.java) builds issuer-audience OAuth clients from trusted metadata and an application key provider. Its sign-only helper takes an existing JCA key pair without generating, loading or exporting private keys. A separate registration value binds its checked public snapshot to a matching JWKS response publisher.
- [EntraLogin](src/main/java/example/rsa/EntraLogin.java) selects the fixed public-cloud common/organizations policy. Supply a fast, thread-safe tenant predicate. An authenticated tenant is eligible for application authorization; it is not itself a permission decision.

## Application configuration

For a provider registered for private-key authentication, choose the algorithm from trusted application configuration and construct a matching signing/publication snapshot:

```java
var registration = PrivateKeyClients.registration(
    applicationKeyPair, JwsAlgorithm.ES256, registeredKeyId);
var client = PrivateKeyClients.withMetadata(
    metadata, clientId, registration.getKeyProvider()).build();
// Host registration.getJwksPublisher().responseFor(method) at an approved
// public JWKS endpoint, or register that same public projection out of band.
```

`registration` selects the appropriate existing RSA, EC or Ed25519 signer and publishes the signer's immutable, structurally checked public snapshot with its exact algorithm and identifier. It performs public JSON serialization and ETag hashing; it does not register the key or start an HTTP server. Register the **public** key before using the client. Persist and protect the private key in the application's own key system. `registeredKey` remains a sign-only alternative when publication is managed separately. It supports eligible opaque/provider-owned private keys and typed or restricted PSS keys; joint `registration` retains the public JWKS API's refusal of typed/restricted PSS containers and does not flatten those restrictions. For rotation, implement `ClientAssertionKeyProvider` to return one immutable `ClientAssertionSigningKey` snapshot with its matching registered identifier per call. Keep previously registered verification keys for the required overlap. Do not return separately rotated key and header fields.

Issuer audience is the default: `typ=client-authentication+jwt`, sole `aud` equal to the exact configured issuer. Every actual credential POST gets a fresh assertion and identifier; cache hits make no key call. The helper explicitly accepts RS256, RS384, RS512, PS256, PS384, PS512, ES256 with P-256, ES384 with P-384 and fully specified `Ed25519`. It rejects symmetric algorithms, ES512 and legacy `EdDSA`, with no negotiation or fallback. An `EdDSA` metadata entry does not authorize an `Ed25519` assertion. Token and revocation method lists must name `private_key_jwt`; absent lists mean Basic. Present signing-algorithm lists must allow the exact selected wire algorithm. A metadata mismatch throws `OAuthConfigurationException` with `CLIENT_ASSERTION_ENDPOINT_MISMATCH` before a credential request; an actual private/public mismatch similarly refuses with `CLIENT_ASSERTION_KEY_PAIR_MISMATCH`. A factory that snapshots keys does not prove that a private key can sign; the actual operation must succeed and verify before the assertion is released. Configure introspection's own role lists or explicit out-of-band registration; token and ID-token algorithm lists do not authorize introspection. All asserted POST endpoints must share the issuer's origin. Do not copy metadata across providers or substitute a token URL for another role.

For a provider requiring endpoint compatibility, use `ClientAuthentication.withPrivateKeyJwt(keyProvider).audience(ClientAssertionAudience.TOKEN_ENDPOINT).build()`. The audience is the **actual** token, revocation or introspection POST URL and `typ=JWT`. Keycloak 26.7.4 rejects endpoint-audience revocation in our local registration; retain the default issuer audience for that version. No automatic retry or secret fallback is performed.

For Entra, pass the exact `https://login.microsoftonline.com/organizations/v2.0` or `https://login.microsoftonline.com/common/v2.0`, registered client ID and callback to `EntraLogin.withIssuer`. Keep an application-owned tenant allowlist and deny consumer accounts unless intended. Microsoft's documented private-key profile uses explicit endpoint compatibility, PS256 and the SHA-256 digest of the registered DER certificate: build `ClientAssertionSigningKey.withSigner(signer).certificateSha256Thumbprint(applicationCertificateDigest).build()`. The application supplies the digest and certificate enrollment. The local fixture instead registers a synthetic key ID; it is not a hosted certificate acceptance test. Hosted issuer-audience acceptance is also unproven.

At login, use `beginAuthentication`, save its pending record with a browser-specific secret binding in an atomic `PendingAuthorizationStore`, then complete through `completeAuthenticationResult` with the exact trusted callback URI. The [barebones Soklet example](../barebones-oidc/README.md) demonstrates the surrounding cookies, CSRF checks and application session rotation. Never derive issuer/callback/tenant routing from incoming headers or unsigned claims. A successful authentication gives the actual verified `(issuer, subject)` identity; persist that tuple, not email or the common issuer. Restored `OidcSessionReference` is comparison data, not proof. Another allowed tenant cannot replace the original during refresh. UserInfo requires the original associated authentication and a current tenant decision before Bearer disclosure. Follow the [issuer policy guide](../../docs/oidc-issuer-policy.md) for the remaining session contracts.

## Build and test

Install matching core sources using the [parent Maven instructions](../README.md#build-with-maven).
From the core repository root, run:

```sh
mvn -B -ntp -f examples/rsa-oidc/pom.xml verify
```

This module contains integration recipes, rather than a standalone application.
Maven runs the JUnit scenarios against an owned loopback HTTPS provider. The
tests create a two-day localhost certificate with the JDK's `keytool`, use a
private trust store and keep normal TLS hostname checks. They do not contact
Microsoft or another hosted provider and do not change machine trust.

The tests execute all nine selected algorithms with issuer and explicit endpoint audiences through token acquisition, refresh, introspection and revocation. A cache hit makes no additional key call. The owned HTTPS fixture fetches the actual application public JWKS response, reconstructs its verification key from public parameters and verifies each assertion using raw JCA. Its observed software profiles are SunRsaSign for RSA/PSS and SunEC for P-256/P-384/Ed25519 on Corretto 17, 21 and 27. The fixture checks fixed ECDSA/Ed25519 wire lengths, exact PSS parameters, fresh identifiers, role-specific audiences and the absence of private JWK fields. Metadata that permits only legacy EdDSA and mismatched private/public pairs produce no credential POST. Separate tests retain the local Entra tenant decisions. Synthetic Entra routing exists only in test sources;
it must never be used in an application. Supply your actual provider
configuration, key custody and tenant policy when adapting the recipes.

The runtime dependency is core alone. Annotation libraries are provided and
JUnit stays in test scope. Python is not required. Additional source/artifact
and redacted capture audits live in
[verification/examples](../../verification/examples/README.md).

## Qualification limits

[The dated provider results](../../COMPATIBILITY.md#local-private-key-client-authentication-observed-2026-10-02) retain the Keycloak revocation deviation and node's explicit RS384/role registration settings. The selected comprehensive OIDF private-key profile runs 23 applicable modules alongside 37 inherited runs. Its five unsupported-profile modules remain `NOT_RUN`: WebFinger account/URL discovery, aggregated/distributed claims and UserInfo bearer request bodies. Eleven declarations do not apply to the selected variant; four unsigned-token rejection runs have documented skip outcomes. The upstream Basic module is recorded separately. These examples add no full-plan, certification or hosted-compatibility claim. The expanded nine-algorithm matrix is an owned local software-provider profile; it does not show that hosted Microsoft, Keycloak, another OAuth provider or a hardware key accepts every algorithm. Provider ID-token signing in the fixture remains RSA/RS256, independent of the application client-assertion algorithm.

Revetsec has not been independently audited.
