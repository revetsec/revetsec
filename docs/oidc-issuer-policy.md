# OIDC issuer policy

Exact issuer comparison is the default. `OidcIssuerPolicy.exactInstance()` and a null `OidcClient.Builder.issuerPolicy` setter select that default. The ordinary two-argument OAuth and OIDC metadata parsers remain exact.

## Fixed Microsoft Entra multi-tenant policy

```java
OidcIssuerPolicy policy = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(
    tenantId -> permittedTenantIds.contains(tenantId));
OidcClient client = OidcClient.withIssuer(
        "https://login.microsoftonline.com/organizations/v2.0")
    .issuerPolicy(policy)
    .clientId(clientId)
    .redirectUri(registeredCallbackUri)
    .build();
```

Only the exact public-cloud `https://login.microsoftonline.com/common/v2.0` and `https://login.microsoftonline.com/organizations/v2.0` configured issuers are supported. Selected discovery accepts only the exact advertised `https://login.microsoftonline.com/{tenantid}/v2.0` template. `getIssuer()` retains configured trust; `getAdvertisedIssuer()` preserves the received template. An exact client refuses metadata that needs this relaxation. Sovereign clouds, v1, B2C, External ID and arbitrary issuer templates are outside this policy.

The engine verifies the actual JOSE signature before reading tenant claims. It requires a lowercase GUID `tid`, its exact tenant-specific v2.0 `iss`, and the actual verifying JWK's `issuer` equal to that issuer or the one allowed template. Missing key issuer fails. Ordinary OIDC audience, authorized-party, nonce, time, hash, authentication-age and confirmation checks still apply. Only then does the app predicate receive the authenticated tenant GUID, before identity or endpoint credentials are released. HMAC ID tokens cannot use this policy.

The predicate is trusted application code: make it fast and thread-safe. It runs on the caller's thread, with no executor or preemption; late results are discarded using the original deadline and current clock. False yields `TENANT_NOT_ALLOWED`. A throwing predicate yields fixed `ISSUER_POLICY_UNAVAILABLE` configuration failure without its cause or message. Consumer accounts use the same tenant rule; deny the consumer tenant unless intended. Share a common key source only with the same policy instance, since separate predicates cannot be proven equivalent.

## Callback, UserInfo and refresh

Callback `iss` remains bound to the pending configured issuer before code exchange. It never chooses a tenant endpoint or invokes the tenant predicate. Captured Entra metadata does not advertise callback issuer support; a future inconsistent callback issuer fails closed.

UserInfo requires an original verified authentication associated with this client, then rechecks the app's current tenant decision before Bearer disclosure. JSON subject must match. Signed UserInfo uses that verified tenant issuer and subject, checks the actual verifying key issuer, and permits missing `tid` only under this verified binding; a present `tid` must match. The original authentication is also required by the overload that uses refreshed access tokens.

Restored `OidcSessionReference` values are comparison data, never identity proof. Local refresh preflight checks only the stored exact tenant issuer shape and client ID, with no tenant predicate on restored data and no tenant routing. A returned ID token must newly pass signature/key/tenant/predicate checks and all original issuer, subject, audience-set, authorized-party, issued-at, authentication-time and nonce continuity rules. Another allowed tenant cannot replace the original. Refresh without an ID token creates no new identity and performs no predicate call.

## Evidence

Local synthetic TLS flows and independent JDK-signed test tokens exercise these paths. Hosted Entra acceptance is unproven; no account or live capture was used. Enabling this OIDC policy does not qualify private-key client assertions against a hosted provider.

[Compiled Entra configuration and redacted synthetic capture recipes](../examples/rsa-oidc/README.md) demonstrate application tenant decisions, signature/key issuer checks, UserInfo and refresh continuity. Their test-only local routing does not establish hosted acceptance.

Revetsec has not been independently audited.
