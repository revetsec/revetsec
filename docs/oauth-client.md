# OAuth client guide

**Pre-release.** `com.revetsec.oauth` supplies authorization code with PKCE S256, client credentials, refresh and revocation. It returns raw credentials; a token response is never proof of who a user is. Use `OidcClient` for OpenID Connect identity validation.

## Browser authorization

Build one client per configured issuer and client ID. Configure the exact registered callback URI at startup. For more than one authorization server, use distinct callback routes, or require the RFC 9207 `iss` parameter with `issuerParameterPolicy(IssuerParameterPolicy.REQUIRED)`. Never derive the callback URI from `Host`, forwarded headers or callback parameters.

```java
URI callback = URI.create("https://app.example/oauth/google/callback");
OAuthClient client = OAuthClient.withIssuer("https://accounts.google.com")
    .clientId(clientId)
    .clientAuthentication(ClientAuthentication.fromClientSecretBasic(clientSecret))
    .redirectUri(callback)
    .build();

AuthorizationRedirect begin = client.beginAuthorization(
    AuthorizationRequestOptions.builder()
        .scopes(Set.of("openid", "email"))
        .applicationData(Map.of("returnTo", checkedReturnTo))
        .build());
String sealed = begin.getPendingAuthorization().toSealedForm(sealer, "google");
// Set the pending cookie, then redirect the browser to begin.getAuthorizationUri().
```

`checkedReturnTo` must come from an application allowlist, for example `Set.of("/account", "/dashboard")`. Check it before saving it and again after completion. A value such as `https://attacker.example/` must fail both checks. Authenticated application data is still untrusted as a redirect destination.

Use one stable, application-chosen `__Host-` cookie name per provider for the simple flow. A later login in another tab replaces that provider's cookie, so the earlier tab fails the state check. Optional same-provider concurrency may use at most three per-flow cookies; `begin.getPerFlowCookieName()` and `response.getPerFlowCookieName()` derive matching names. The suffix selects a cookie and provides no authentication.

The application sets and clears cookies. Set `Secure`, `HttpOnly`, `Path=/`, no `Domain`, and `SameSite=Lax` for query callbacks. Form-post callbacks need `SameSite=None; Secure`. Keep Max-Age no longer than the pending lifetime and the whole `Set-Cookie` field within 4,096 bytes. Clear the pending cookie on every callback, including failures. Keep sealing keys separate by application and environment and rotate them as described in [SECURITY.md](../SECURITY.md).

At the callback, parse the query or UTF-8 form body with `AuthorizationResponse`. Pass the cookie through `PendingAuthorizationSource.fromSealedForm(sealedCookie, sealer, "google")`. Call `completeAuthorization(response, source, callback)` with the fixed URI from trusted route configuration. It validates local state, browser binding, delivery mode, route and issuer before discovery or token I/O. The resulting `TokenResponse.getApplicationData()` contains the authenticated `returnTo` from this completed browser flow. It is empty for client-credentials and refresh calls.

## Replay and a shared store

A sealed cookie has no atomic replay memory. Two concurrent callbacks with the same valid cookie may each send a code-exchange POST, even if the application clears the cookie in its response. The authorization server should reject reuse of the same code, but cookie clearing alone does not ensure client-side single use.

When at-most-once exchange is required across concurrent callbacks, nodes or restarts, use a durable shared implementation of `PendingAuthorizationStore` whose `consume(browserBinding, state)` removes a record atomically. At begin, call `begin.getPendingAuthorization().saveTo(store, browserBinding)`; at completion, use `PendingAuthorizationSource.fromStore(store, browserBinding)`. The binding is a browser-specific secret, not a user ID. Revetsec checks its digest again after consume even if a custom store ignores the binding. `InMemoryPendingAuthorizationStore.fromDefaults()` is bounded and atomic within one process, but it cannot preserve a pending login across a restart or share it across nodes.

## Token and endpoint rules

Authorization code always uses a fresh S256 PKCE verifier. Metadata that explicitly omits S256 from its advertised methods is rejected. When the field is absent, ordinary OAuth proceeds; `requirePkceAdvertised(true)` requires the advertisement. This policy still depends on the authorization server actually enforcing PKCE when its metadata is silent.

The client refuses token and metadata redirects, enforces HTTPS endpoints and bounded request and response sizes, and never retries an authorization-code exchange, refresh or revocation automatically. `ClientCredentialsTokenSource` caches a service token, renews through a single caller and lets the application invalidate an exact rejected token instance. Keep the client secret, authorization code, state, verifier and tokens out of application logs. `toString()` methods redact them; explicit token getters return the credential to the caller.

Captured public metadata for Google, Apple and tenant-specific Microsoft Entra is under `src/test/resources/fixtures/`. Tenant-specific Entra issuers work with exact metadata comparison. The generic OAuth metadata parser remains exact. OIDC `common` and `organizations` discovery can use the explicit [fixed Entra issuer policy](oidc-issuer-policy.md); this does not loosen the generic OAuth parser. The offline Keycloak integration test covers confidential and public code flows, client credentials, refresh and revocation. A live GitHub token-endpoint probe has not been run because no OAuth app/client ID was provided; HTTP-200 error parsing uses a synthetic test response.

## Private-key client assertions

The application owns registration, private keys and rotation. Revetsec prepares a fresh signed assertion for each actual token, refresh, code, revocation or introspection POST:

```java
JwsSigner signer = JwsSigner.fromRsaKeyPair(privateKey, publicKey, JwsAlgorithm.PS256);
ClientAssertionSigningKey key = ClientAssertionSigningKey.withSigner(signer)
    .keyId(registeredKeyId)
    .build();
ClientAuthentication authentication = ClientAuthentication.fromPrivateKeyJwt(
    ClientAssertionKeyProvider.fromKey(key));
```

`ClientAssertionSigningKey` requires a key ID or exactly 32 bytes of SHA-256 certificate digest, optionally both. Its builder intentionally has no `fromSigner` convenience: the signer alone cannot satisfy the identifier requirement. A rotating `ClientAssertionKeyProvider` returns one immutable signer/header snapshot per POST on the caller's thread and must cooperate with its remaining budget. Builds, cached service tokens and waiting callers make no key callback. RSA signing accepts PS256, RS256 and RS384; the selected algorithm must match any applicable advertised role list. There is no negotiation or authentication fallback.

The default assertion has `typ=client-authentication+jwt`, sole `aud` equal to the exact configured issuer, `iss=sub=clientId`, whole-second `iat=nbf`, a 60-second `exp` and a fresh 32-byte random `jti`. `withPrivateKeyJwt(provider)` allows exact whole-second lifetime in [1, 300]. Explicit `audience(ClientAssertionAudience.TOKEN_ENDPOINT)` compatibility uses `typ=JWT` and the exact actual POST URI, including the revocation or introspection target and its query escaping. Every asserted POST must have the configured issuer's scheme, ASCII host and effective port; a present cross-origin token endpoint also fails introspection preparation.

Token and revocation metadata with absent authentication methods defaults to Basic and therefore cannot authorize private-key assertions. Configure or advertise `private_key_jwt` for each applicable role. Introspection-only explicit configuration may omit its method/algorithm lists; it needs no browser, token or JWKS discovery. An override of another introspection endpoint does not inherit that other endpoint's lists. The same endpoint retains its lists across host case, explicit default port and percent-escape hex case changes; its actual assertion audience still preserves the supplied URI string. Missing signing algorithms mean the explicitly configured signer represents an out-of-band registered credential; present empty or excluding lists fail closed. ID-token algorithms do not authorize client assertions.

The form contains `client_id`, the fixed `client_assertion_type` and `client_assertion`; no Basic header or `client_secret` is sent. Private-key client authentication cannot be used with HMAC ID tokens. Key and signing failures are fixed-message `OAuthConfigurationException` instances without application/provider causes. Deadline failures remain transport exceptions. None becomes an invalid-user result. A preparation failure fires `didFailClientAssertionPreparation` before the credential endpoint's HTTP lifecycle; expiry or deadline exhaustion after `willRequestEndpoint` fires only `didFailEndpoint`. No automatic assertion regeneration or retry occurs. The original operation deadline covers discovery, key selection, signing and transport; provider/JCA execution is cooperative. Do not log assertion bodies or explicit identifier/digest getters.

Local private-key checks cover Keycloak 26.7.4 and node-oidc-provider 9.12.2 with three algorithms, both audience modes and each POST role. Keycloak's endpoint audience mode rejects revocation because its accepted audience list omits that endpoint; use the default issuer mode for this provider version. Node's RS384 support is explicitly enabled in the test fixture. Its absent revocation/introspection authentication lists require trusted explicit settings matching registration. See [the dated provider results](../COMPATIBILITY.md#local-private-key-client-authentication-observed-2026-10-02). Hosted qualification remains unproven. The selected comprehensive OIDF private-key profile and its exclusions are recorded in [COMPATIBILITY.md](../COMPATIBILITY.md#selected-comprehensive-oidf-private-key-profile). [Compiled application recipes and redacted local captures](../examples/rsa-oidc/README.md) demonstrate registration, role metadata, cache behavior and explicit endpoint compatibility.
