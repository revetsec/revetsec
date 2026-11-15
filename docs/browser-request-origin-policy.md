# Browser request-origin policy

`BrowserRequestOriginPolicy` applies one stateless request-origin decision to browser-facing HTTP routes. It is an
admission layer, not a complete CSRF defense: applications still validate the trusted host/routing context, bind
sessions, use synchronizer or action tokens where appropriate, and authorize the requested state change.

Configure exact canonical origins once. HTTPS is required unless the named loopback-development option is enabled;
wildcards, paths, user information, fragments, explicit default ports and values derived from `Host` or `Forwarded`
are refused.

```java
BrowserRequestOriginPolicy policy = BrowserRequestOriginPolicy
        .withAllowedOrigins(Set.of(URI.create("https://app.example")))
        .build();

BrowserRequestOriginResult result = policy.checkResult(
        method, secFetchSiteOccurrences, originOccurrences);
if (!(result instanceof BrowserRequestOriginResult.Allowed)) {
    // Refuse before changing application state.
}
```

For unsafe methods, a valid `Sec-Fetch-Site: same-origin` or `none` is sufficient when `Origin` is absent, opaque or
exactly configured. That deliberately admits the observed same-origin `Origin: null` case produced by a
`Referrer-Policy: no-referrer` page, while a contradictory concrete origin still rejects. `same-site`, `cross-site`,
an absent fetch-site value, or an unknown syntactically valid future value requires an exact configured `Origin`.
Duplicate or malformed values reject. When both metadata headers are absent, the default is rejection; the named
`allowMissingMetadata` option is only for a deliberately mixed browser/non-browser endpoint, and its distinct
`MISSING_METADATA_COMPATIBILITY` basis makes the relaxation observable without logging submitted values.

Safe `GET`, `HEAD` and `OPTIONS` methods are admitted before metadata inspection. Do not use a safe method for a
state-changing operation. `Origin: null` is otherwise rejected unless valid same-origin or user-initiated fetch-site
metadata already establishes the browser context.

The Soklet, Jakarta Servlet and javax Servlet artifacts provide extraction helpers. They install no route or filter.
Keep binding-specific cross-site protocol callbacks outside this policy: SAML POST bindings and OIDC `form_post`
callbacks rely on their signed message or exact pending-state/browser binding. Cookie-free bearer/token, SCIM and
back-channel endpoints use their own authentication and admission contracts.

