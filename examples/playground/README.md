# Revetsec Playground — initial scenarios

Build with [the example builder](../README.md), start the local provider and [HTTPS edge](../../interop/local-https/README.md), and configure:

```sh
export PLAYGROUND_ORIGIN=https://localhost:8443
export PLAYGROUND_ISSUER=https://localhost:9443
export PLAYGROUND_CLIENT_ID=revetsec-test-client
export PLAYGROUND_SECRET_REFERENCE=env:PLAYGROUND_CLIENT_SECRET
export PLAYGROUND_CLIENT_SECRET=test-only-client-secret-not-a-real-secret
export PLAYGROUND_PROBE_CLIENT_ID=revetsec-test-client
export PLAYGROUND_PROBE_SECRET_REFERENCE=env:PLAYGROUND_CLIENT_SECRET
export PLAYGROUND_VALIDATION=jwt
```

Run `examples/run.py --example playground` as described in the parent README. Frontend HTTP binds 127.0.0.1:8080 and MCP binds 127.0.0.1:8081. The trusted resource is `https://localhost:8443/mcp`, metadata is `https://localhost:8443/.well-known/oauth-protected-resource/mcp`, and OIDC callback is `https://localhost:8443/oidc/callback`. The edge preserves the frontend Host and uses the exact backend MCP Host; applications never derive security identities from forwarded headers.

The initial UI includes OIDC login/session, configured validator strategy, checked redacted results, client-credentials probing and transient token inspection. Secret references are `env:NAME`, `file:/absolute/path`, or `none` for a public OIDC client. Provider configuration, probes and inspection require the application session, exact Origin and CSRF token. Raw credentials are not stored in browser storage, echoed or logged. Before validation, only explicitly unverified allowlisted algorithm/type labels may be shown; claim displays require completed validation.

`PLAYGROUND_VALIDATION=introspection` with the node provider's `TEST_PLAYGROUND_TOKEN_FORMAT=opaque` uses fresh audience-checked JSON introspection on every admission. The JWT preset uses strict RFC 9068 tokens. Provider infrastructure failures map to unavailable rather than invalid credentials. The app authorizes every MCP operation: discovery/catalog operations need `mcp:discover`; only the registered `whoami` tool with permitted local/self arguments needs `mcp:whoami`. Other operations, tenant and object selections are denied. Notifications receive the corresponding transport status without a JSON-RPC response body.

Set `PLAYGROUND_REPLAY_JOURNAL=true` only for the local synthetic replay demonstrations. Atomic-store replay and sealed-cookie replay are distinct: atomic consumption rejects locally before another code POST; sealed cookies have no cross-request at-most-once guarantee, so the provider's single-use-code rejection can decide a replay. The opt-in server journal preserves normal pending/browser validation, holds at most one transaction per session and expires at the original deadline. It is not a callback/token export feature.

The [locked Inspector checks](../../interop/inspector-auth/README.md) preserve the released-client recovery regression separately from this endpoint's normal OAuth/tool flow. A generic policy denial remains a denial. The natural framework capabilities are retained; subscriptions are not enabled by default. Later SAML, SCIM and self-issuing OAuth scenarios are added at their milestones.
