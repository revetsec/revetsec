# OAuth client guide

**Pre-release.** `com.revetsec.oauth` supplies authorization code with PKCE S256, client credentials, refresh and revocation. It returns raw credentials; a token response is never proof of who a user is. OpenID Connect identity validation arrives separately.

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

Captured public metadata for Google, Apple and tenant-specific Microsoft Entra is under `src/test/resources/fixtures/`. Tenant-specific Entra issuers work with exact metadata comparison; `common` and `organizations` template issuers need the later multi-tenant policy. The offline Keycloak integration test covers confidential and public code flows, client credentials, refresh and revocation. A live GitHub token-endpoint probe has not been run because no OAuth app/client ID was provided; HTTP-200 error parsing uses a synthetic test response.
