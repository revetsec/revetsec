# OAuth client guide

**Pre-release.** `com.revetsec.oauth` supplies authorization code with PKCE S256, client credentials, refresh and revocation. It returns raw credentials; a token response is never proof of who a user is. Use [`OidcClient`](https://javadoc.revetsec.com/com/revetsec/oidc/OidcClient.html) for OpenID Connect identity validation.

## Browser authorization

Build one client per configured issuer and client ID. Configure the exact registered callback URI at startup. For more than one authorization server, use distinct callback routes, or require the RFC 9207 `iss` parameter with `issuerParameterPolicy(`[`IssuerParameterPolicy`](https://javadoc.revetsec.com/com/revetsec/oauth/IssuerParameterPolicy.html)`.REQUIRED)`. Never derive the callback URI from `Host`, forwarded headers or callback parameters.

```java
var callback = URI.create("https://app.example/oauth/google/callback");
// Share this thread-safe client across requests.
var client = OAuthClient.withIssuer("https://accounts.google.com")
  .clientId(clientId)
  .clientAuthentication(ClientAuthentication.fromClientSecretBasic(clientSecret))
  .redirectUri(callback)
  .build();

var begin = client.beginAuthorization(
  AuthorizationRequestOptions.builder()
    .scopes(Set.of("openid", "email"))
    .applicationData(Map.of("returnTo", checkedReturnTo))
    .build());
var sealed = begin.getPendingAuthorization().toSealedForm(sealer, "google");
// Set the pending cookie, then redirect the browser to begin.getAuthorizationUri().
```

The `checkedReturnTo` value must come from an application allowlist, for example [`Set`](https://docs.oracle.com/en/java/javase/27/docs/api/java.base/java/util/Set.html)`.of("/account", "/dashboard")`. Check it before saving it and again after completion. A value such as `https://attacker.example/` must fail both checks. Authenticated application data is still untrusted as a redirect destination.

Use one stable, application-chosen `__Host-` cookie name per provider for the simple flow. A later login in another tab replaces that provider's cookie, so the earlier tab fails the state check. Optional same-provider concurrency may use at most three per-flow cookies; `begin.getPerFlowCookieName()` and `response.getPerFlowCookieName()` derive matching names. The suffix selects a cookie and provides no authentication.

The application sets and clears cookies. Set `Secure`, `HttpOnly`, `Path=/`, no `Domain`, and `SameSite=Lax` for query callbacks. Form-post callbacks need `SameSite=None; Secure`. Keep Max-Age no longer than the pending lifetime and the whole `Set-Cookie` field within 4,096 bytes. Clear the pending cookie on every callback, including failures. Keep sealing keys separate by application and environment and rotate them as described in [SECURITY.md](../SECURITY.md).

At the callback, parse the query or UTF-8 form body with [`AuthorizationResponse`](https://javadoc.revetsec.com/com/revetsec/oauth/AuthorizationResponse.html). Pass the cookie through [`PendingAuthorizationSource`](https://javadoc.revetsec.com/com/revetsec/oauth/PendingAuthorizationSource.html)`.fromSealedForm(sealedCookie, sealer, "google")`. Parse with [`AuthorizationResponse`](https://javadoc.revetsec.com/com/revetsec/oauth/AuthorizationResponse.html)`.fromQueryStringResult` or `fromFormBodyResult`, release the callback only from [`AuthorizationResponseParseResult.Succeeded`](https://javadoc.revetsec.com/com/revetsec/oauth/AuthorizationResponseParseResult.Succeeded.html), then call `completeAuthorizationResult(response, source, callback)` with the fixed URI from trusted route configuration. It validates local state, browser binding, delivery mode, route and issuer before discovery or token I/O. Only [`AuthorizationCompletionResult.Succeeded`](https://javadoc.revetsec.com/com/revetsec/oauth/AuthorizationCompletionResult.Succeeded.html)`.getTokens()` releases a token response. Its `getApplicationData()` contains the authenticated `returnTo` from this completed browser flow. It is empty for client-credentials and refresh calls.

## Replay and a shared store

A sealed cookie has no atomic replay memory. Two concurrent callbacks with the same valid cookie may each send a code-exchange POST, even if the application clears the cookie in its response. The authorization server should reject reuse of the same code, but cookie clearing alone does not ensure client-side single use.

When at-most-once exchange is required across concurrent callbacks, nodes or restarts, use a durable shared implementation of [`PendingAuthorizationStore`](https://javadoc.revetsec.com/com/revetsec/oauth/PendingAuthorizationStore.html) whose `consume(browserBinding, state)` removes a record atomically. At begin, call `begin.getPendingAuthorization().saveToResult(store, browserBinding)` and redirect only when the outcome is [`PendingAuthorizationSaveResult`](https://javadoc.revetsec.com/com/revetsec/oauth/PendingAuthorizationSaveResult.html)`.SAVED`; collision, capacity refusal, unavailable storage and indeterminate persistence remain explicit outcomes. An indeterminate write may already have taken effect and must not be blindly retried; at completion, use [`PendingAuthorizationSource`](https://javadoc.revetsec.com/com/revetsec/oauth/PendingAuthorizationSource.html)`.fromStore(store, browserBinding)`. The binding is a browser-specific secret, not a user ID. Store-mode opaque records are plaintext JSON containing sensitive state, including PKCE verifier/nonce and application data. The store must protect their confidentiality and integrity and the raw browser binding, including remote transport and access controls. The binding digest is unkeyed comparison data, not a MAC: a malicious store can alter fields and recompute it. Revetsec validates structure and flow bindings but does not authenticate attacker-controlled storage. A sealed cookie has its separate authenticated type/context; do not infer those protections for the store path. Revetsec checks its digest again after consume even if a custom store ignores the binding. [`InMemoryPendingAuthorizationStore`](https://javadoc.revetsec.com/com/revetsec/oauth/InMemoryPendingAuthorizationStore.html)`.fromDefaults()` is bounded and atomic within one process, but it cannot preserve a pending login across a restart or share it across nodes.

The high-level store path takes [`BrowserBinding`](https://javadoc.revetsec.com/com/revetsec/BrowserBinding.html), not a raw `String`. Generate new values with `BrowserBinding.fresh()`. Restore an exact value with `fromTrustedPersistence` only after recovering it from application-controlled protected server state. A request cookie, query field or form value is an untrusted comparison candidate: compare it to the server-held value and pass the server-held carrier to Revetsec; never call `fromTrustedPersistence` merely to type request text. The broad carrier preserves exact nonempty values through 65,536 Java UTF-16 code units, while OAuth/OIDC still require their existing strict UTF-8 processing. The low-level `PendingAuthorizationStore` SPI remains raw `String` so existing backend lookup framing is unchanged.

This pre-1.0 tightening intentionally stops accepting well-formed OAuth/OIDC pending bindings over 65,536 code units that a sufficiently provisioned in-memory or custom store could previously accept. A deployment needs to expire, clear or rotate state only when such an oversized live pending attempt or retained server-session binding actually exists, then start a newly authorized flow. Do not retry a possibly consumed authorization code. No account, credential, reference PostgreSQL schema, key or codec migration follows.

## Token and endpoint rules

Authorization code always uses a fresh S256 PKCE verifier. Metadata that explicitly omits S256 from its advertised methods is rejected. When the field is absent, ordinary OAuth proceeds; `requirePkceAdvertised(true)` requires the advertisement. This policy still depends on the authorization server actually enforcing PKCE when its metadata is silent.

Direct client credentials and refresh use `requestClientCredentialsResult` and `refreshResult`; revocation uses `revokeResult`. Token, revocation and checked callback client rejections carry a fixed [`OAuthEndpointError`](https://javadoc.revetsec.com/com/revetsec/oauth/OAuthEndpointError.html) and, for endpoint rejections, the HTTP status. Every checked callback error remains a result, including a provider-reported temporary failure. Actual endpoint 429/5xx responses, malformed responses, metadata and transport failures remain exceptions.

The client refuses token and metadata redirects, enforces HTTPS endpoints and bounded request and response sizes, and never retries an authorization-code exchange, refresh or revocation automatically. The [`ClientCredentialsTokenSource`](https://javadoc.revetsec.com/com/revetsec/oauth/ClientCredentialsTokenSource.html)`.getAccessTokenResult()` operation returns a currently valid cached/renewed token or a fixed endpoint rejection. Renewal is coordinated through one caller, and rejections remain values through shared renewal and backoff. A still-valid prior token can remain available during failed early renewal; exact-instance invalidation prevents using that rejected token again. Keep the client secret, authorization code, state, verifier and tokens out of application logs. `toString()` methods redact them; explicit token getters return the credential to the caller.

Captured public metadata for Google, Apple and tenant-specific Microsoft Entra is under `src/test/resources/fixtures/`. Tenant-specific Entra issuers work with exact metadata comparison. The generic OAuth metadata parser remains exact. OIDC `common` and `organizations` discovery can use the explicit [fixed Entra issuer policy](oidc-issuer-policy.md); this does not loosen the generic OAuth parser. The offline Keycloak integration test covers confidential and public code flows, client credentials, refresh and revocation. A live GitHub token-endpoint probe has not been run because no OAuth app/client ID was provided; HTTP-200 error parsing uses a synthetic test response.

A discovery document whose issuer does not match the configured issuer throws a fixed `OAuthConfigurationException` with reason `ISSUER_MISMATCH`, including discovery during OAuth/OIDC completion and cached failure delivery. It is a provider/configuration failure. A mismatching issuer in the browser callback or saved flow remains a checked callback rejection. Direct metadata parse results keep their document-level mismatch reason; they do not classify a browser callback. These failures do not trigger another discovery candidate or a token POST.

`ClientCredentialsTokenSource.Builder.build()` requires a confidential client authentication strategy and rejects `none` with `IllegalArgumentException`. This local check makes no secret/key-provider call and performs no discovery or signing. Basic, POST and private-key strategies still depend on valid registration and compatible provider metadata at request time; construction does not prove remote capability.

Discovery coordinates concurrent callers and bounds refresh attempts. A caller interrupted or out of time before admission consumes no discovery attempt. Cancellation after a request starts retains that attempt charge but does not install shared failure backoff; cancelling a waiter leaves the leader running. Shared discovery failures preserve fixed reason/status data through fresh exceptions, without another caller's mutable diagnostics or transport cause.

## Private-key client assertions

The application owns registration, private keys and rotation. Revetsec prepares a fresh signed assertion for each actual token, refresh, code, revocation or introspection POST:

```java
// Share this thread-safe signer across requests.
var signer = JwsSigner.fromRsaKeyPair(privateKey, publicKey, JwsAlgorithm.PS256);
var key = ClientAssertionSigningKey.withSigner(signer)
  .keyId(registeredKeyId)
  .build();
var authentication = ClientAuthentication.fromPrivateKeyJwt(
  ClientAssertionKeyProvider.fromKey(key));
```

The [`ClientAssertionSigningKey`](https://javadoc.revetsec.com/com/revetsec/oauth/ClientAssertionSigningKey.html) configuration requires a key ID or exactly 32 bytes of SHA-256 certificate digest, optionally both. Its builder intentionally has no `fromSigner` convenience: the signer alone cannot satisfy the identifier requirement. A rotating [`ClientAssertionKeyProvider`](https://javadoc.revetsec.com/com/revetsec/oauth/ClientAssertionKeyProvider.html) returns one immutable signer/header snapshot per POST on the caller's thread and must cooperate with its remaining budget. Builds, cached service tokens and waiting callers make no key callback. Client assertions accept PS256, PS384, PS512, RS256, RS384, RS512, ES256/P-256 and ES384/P-384; the selected algorithm must match any applicable advertised role list. There is no negotiation or authentication fallback.

The default assertion has `typ=client-authentication+jwt`, sole `aud` equal to the exact configured issuer, `iss=sub=clientId`, whole-second `iat=nbf`, a 60-second `exp` and a fresh 32-byte random `jti`. `withPrivateKeyJwt(provider)` allows exact whole-second lifetime in [1, 300]. Explicit `audience(`[`ClientAssertionAudience`](https://javadoc.revetsec.com/com/revetsec/oauth/ClientAssertionAudience.html)`.TOKEN_ENDPOINT)` compatibility uses `typ=JWT` and the exact actual POST URI, including the revocation or introspection target and its query escaping. Every asserted POST must have the configured issuer's scheme, ASCII host and effective port; a present cross-origin token endpoint also fails introspection preparation.

Token and revocation metadata with absent authentication methods defaults to Basic and therefore cannot authorize private-key assertions. Configure or advertise `private_key_jwt` for each applicable role. Introspection-only explicit configuration may omit its method/algorithm lists; it needs no browser, token or JWKS discovery. An override of another introspection endpoint does not inherit that other endpoint's lists. The same endpoint retains its lists across host case, explicit default port and percent-escape hex case changes; its actual assertion audience still preserves the supplied URI string. Missing signing algorithms mean the explicitly configured signer represents an out-of-band registered credential; present empty or excluding lists fail closed. ID-token algorithms do not authorize client assertions.

The form contains `client_id`, the fixed `client_assertion_type` and `client_assertion`; no Basic header or `client_secret` is sent. Private-key client authentication cannot be used with HMAC ID tokens. Key and signing failures are fixed-message [`OAuthConfigurationException`](https://javadoc.revetsec.com/com/revetsec/oauth/OAuthConfigurationException.html) instances without application/provider causes. Deadline failures remain transport exceptions. None becomes an invalid-user result. A preparation failure fires `didFailClientAssertionPreparation` before the credential endpoint's HTTP lifecycle; expiry or deadline exhaustion after `willRequestEndpoint` fires only `didFailEndpoint`. No automatic assertion regeneration or retry occurs. The original operation deadline covers discovery, key selection, signing and transport; provider/JCA execution is cooperative. Do not log assertion bodies or explicit identifier/digest getters.

Local private-key checks cover Keycloak 26.7.4 and node-oidc-provider 9.12.2 with three algorithms, both audience modes and each POST role. Keycloak's endpoint audience mode rejects revocation because its accepted audience list omits that endpoint; use the default issuer mode for this provider version. Node's RS384 support is explicitly enabled in the test fixture. Its absent revocation/introspection authentication lists require trusted explicit settings matching registration. See [the dated provider results](../COMPATIBILITY.md#local-private-key-client-authentication-observed-2026-10-02). Hosted qualification remains unproven. The selected comprehensive OIDF private-key profile and its exclusions are recorded in [COMPATIBILITY.md](../COMPATIBILITY.md#selected-comprehensive-oidf-private-key-profile). [Compiled application recipes and redacted local captures](../examples/rsa-oidc/README.md) demonstrate registration, role metadata, cache behavior and explicit endpoint compatibility.

## RP-Initiated Logout

The [logout guide](oidc-logout.md) covers explicit credential-hint retention, local POST/CSRF authorization and session termination, trusted end-session configuration, save-before-browser delivery and correlation-only returns. Logout has separate pending state; it neither replaces the original continuity reference nor creates authentication from a returned state.

## Provider error links

`AuthorizationResponse.getErrorUri()` exposes parsed, untrusted provider error data. Absolute URI syntax does not authorize its scheme, host or navigation. Core neither fetches nor follows it and supplies no automatic browser redirect. Keep it as diagnostic data; an application that deliberately offers a link must use its own exact HTTPS destination allowlist, reject user information and unexpected ports/paths/fragments, and escape output. A valid callback or pending-state match does not establish this link as trusted.

OIDC applications configure ordered request preferences separately from local ACR acceptance and preserve that acceptance through refresh. See [OIDC flow assurance and version-2 session references](oidc-flow-assurance.md), including the required reauthentication for version-1 stored references. Token revocation composes explicitly through this OAuth client; it remains distinct from local session invalidation and provider logout.
