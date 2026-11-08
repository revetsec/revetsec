# OIDC request preferences and flow assurance

Use `OidcClient.Builder.requiredAcrValues(Set<String>)` for the complete local acceptance set and `acrPreferences(List<String>)` for ordered `acr_values` request preferences. `OidcAuthenticationOptions.Builder` offers the same complete per-login overrides. Preference values are distinct, nonempty visible-ASCII strings. They preserve order and are copied; a preference does not establish assurance or require the provider to return that claim.

```java
OidcAuthenticationOptions options = OidcAuthenticationOptions.builder()
    .acrPreferences(List.of("urn:example:phishing-resistant", "urn:example:mfa"))
    .requiredAcrValues(Set.of("urn:example:phishing-resistant", "urn:example:mfa"))
    .build();
```

The strings are examples; select values from the application's actual provider registration and assurance policy. Request preferences have the ordered semantics in [OIDC Core 3.1.2.1](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest). Local acceptance is an additional library policy: a nonempty required set refuses a missing or unlisted ID-token `acr`. A preference-only request imposes no such requirement.

Null preference configuration restores inheritance/default derivation. An explicit empty per-login list omits `acr_values` while preserving the effective acceptance set. With no explicit preference list, the effective acceptance set is emitted in lexical order for deterministic output; that set expresses no caller-supplied priority. A per-login empty required set intentionally removes the client's default ACR acceptance requirement. Set both overrides when a different request preference and acceptance policy are needed for one flow.

## Preserve the login policy through refresh

A genuine successful login records its effective required set in `OidcAuthentication.getSessionReference()`. `getRequiredAcrValues()` returns the immutable saved policy, including an intentional empty set. Every returned refresh ID token is validated against it, even when a new client instance has different login defaults. A refresh without an ID token supplies no new identity or assurance and retains the original reference. Refresh does not establish a new authentication event or reapply the original login authentication-age window; the application owns current session age and authorization. [OIDC Core 12.2](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse) specifies original-event continuity.

Changing defaults affects new logins. If a policy change must invalidate earlier sessions, apply an explicit application session-generation/fence policy and require authentication again. Do not infer a stronger authentication from a new token, preference order or successful refresh.

## Version-2 storage migration

Session-reference JSON now has exactly `v`, `client_id`, `claims`, `nonce_digest` and `required_acr_values`, with `v=2`. The required set is a sorted unique string array. Existing complete 64 KiB UTF-8 limits, trusted-storage obligations and authenticated sealer type/context still apply. The policy participates in original-reference comparison; it is comparison data, never proof of identity.

Version 1 does not record the original per-flow acceptance set. Parsing refuses it, including old sealed references and references embedded in old logout hints. Before deploying this format, clear those stored references/hints and require authentication again. There is no automatic inference from new defaults or an observed ACR, format rewrite or reseal upgrade. Do not use parse-only data to create identity, a local session or a logout hint. Protect plaintext reference storage's integrity, confidentiality and access, or use the typed authenticated sealing API.

## Compose revocation deliberately

Token revocation uses a separately configured `OAuthClient.revokeResult`, with the same trusted issuer, client registration and selected client authentication. The application chooses the actual refresh/access credential and token-type hint, and handles the explicit result or infrastructure exception. A successful revocation response may also mean the token was already unknown; it does not prove local sessions or every provider session ended.

Local session invalidation, token revocation and [RP-initiated logout](oidc-logout.md) are separate application decisions. Bound them under the application's budget, close local authority as required, and never automatically retry an uncertain credential-bearing endpoint call or restore a closed session because a provider step failed. This release adds no separate OIDC revocation facade.
