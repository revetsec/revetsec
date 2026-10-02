# Barebones OIDC

Build with [the example builder](../README.md), then configure trusted process values:

```sh
export APP_ORIGIN=https://localhost:8445
export APP_UPSTREAM_PORT=8082
export OIDC_ISSUER=https://localhost:9443
export OIDC_CLIENT_ID=revetsec-test-client
export OIDC_CLIENT_SECRET=test-only-client-secret-not-a-real-secret
export OIDC_RESPONSE_MODE=query
```

The node preset also supports `OIDC_RESPONSE_MODE=form_post`. Configure the [HTTPS edge](../../interop/local-https/README.md) for localhost:8445 to proxy 127.0.0.1:8082 with the external Host preserved, then run `examples/run.py --example barebones-oidc` as described in the parent README. The callback is exactly `https://localhost:8445/callback`. A public client omits `OIDC_CLIENT_SECRET`; its registration must use `token_endpoint_auth_method=none`.

The application uses `OidcClient` and the thin Soklet callback/redirect helpers. It owns bounded atomic pending transactions and bounded expiring sessions, source/browser binding, rotating `__Host-` cookies, CSRF and exact Origin/Host policy. Replay against its atomic pending store rejects locally before another code POST. The checked identity is pseudonymized with a fresh per-process HMAC key. Tokens, cookies and raw claims are never rendered or logged.

All listener addresses are explicit IPv4 loopback. Only trusted startup configuration supplies the issuer, callback and origin. Tests include synthetic genuine signatures, query/form_post, wrong issuer/audience/nonce/expiry, binding/raw-input rejection, concurrent completion, session rotation, caps and infrastructure failures. This is application example code; it does not add session storage or authorization policy to core.
