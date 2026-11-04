# Barebones OIDC

Use JDK 21 or newer for this Soklet application. Revetsec core retains Java 17 compatibility.

Build with [the Maven build](../README.md#build-with-maven), then configure trusted process values:

```sh
export APP_ORIGIN=https://localhost:8445
export APP_UPSTREAM_PORT=8082
export OIDC_ISSUER=https://localhost:9443
export OIDC_CLIENT_ID=revetsec-test-client
export OIDC_CLIENT_SECRET=test-only-client-secret-not-a-real-secret
export OIDC_RESPONSE_MODE=query
```

The node preset also supports `OIDC_RESPONSE_MODE=form_post`. Configure the [HTTPS edge](../../interop/local-https/README.md) for localhost:8445 to proxy 127.0.0.1:8082 with the external Host preserved, then launch the application with the scoped provider truststore described in the parent README:

```sh
java -Djavax.net.ssl.trustStore=/private/tls/java-trust.p12 \
  -Djavax.net.ssl.trustStorePassword=changeit \
  -jar examples/barebones-oidc/target/revetsec-barebones-oidc-1.0.0-SNAPSHOT.jar
```

The callback is exactly `https://localhost:8445/callback`. A public client omits `OIDC_CLIENT_SECRET`; its registration must use `token_endpoint_auth_method=none`.

The application uses `OidcClient` and the thin Soklet callback/redirect helpers. It owns bounded atomic pending transactions and bounded expiring sessions, source/browser binding, rotating `__Host-` cookies, CSRF and exact Origin/Host policy. Replay against its atomic pending store rejects locally before another code POST. The checked identity is pseudonymized with a fresh per-process HMAC key. Tokens, cookies and raw claims are never rendered or logged.

All listener addresses are explicit IPv4 loopback. Only trusted startup configuration supplies the issuer, callback and origin. Tests include synthetic genuine signatures, query/form_post, wrong issuer/audience/nonce/expiry, binding/raw-input rejection, concurrent completion, session rotation, caps and infrastructure failures. This is application example code; it does not add session storage or authorization policy to core.

## Browser session admission

Anonymous home, unknown-route and callback reads do not allocate sessions or set a session cookie. The home page offers Start local session; an explicit same-origin `POST /session` with the fixed `begin=1` form creates a session and redirects home. The POST requires exact Host/Origin and one form Content-Type, and refuses query parameters, discarded/oversized input and extra form fields. It does not begin authentication. Sign-in and sign-out retain their session-bound CSRF checks.

The launcher selects 128 sessions (constructor range 1–1024) plus a 262,144-byte content charge: 512 bytes per session plus the checked identity's UTF-8 bytes. Admission rejects with a fixed 503 at either cap and never evicts live sessions. Sessions expire absolutely thirty minutes after creation or successful authentication rotation; reads and bootstrap reuse do not renew them. Request-time cleanup releases session charges and pending bindings, and clock regression expires affected sessions. Reads still work at capacity. Deliberate bootstrap traffic can exhaust this local allowance; a deployment supplies trusted edge admission and rate limits.
