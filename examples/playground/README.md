# Revetsec Playground — local protocol scenarios

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

The UI includes OIDC and optional SAML sign-in, configured resource validation, checked redacted results, client-credentials probing and transient token inspection. OIDC secret references are `env:NAME`, `file:/absolute/path`, or `none` for a public client. Provider configuration, probes and inspection require the application session, exact Origin and CSRF token. Raw credentials are not stored in browser storage, echoed or logged. Before validation, only explicitly unverified allowlisted algorithm/type labels may be shown; claim displays require completed validation.

## SAML service provider

SAML is disabled unless a trusted operator supplies local IdP metadata and the SP's signing key and certificate. The app never fetches an IdP URL or accepts a browser-selected IdP. Configure one approved connection before starting the Playground:

```sh
export PLAYGROUND_SAML_METADATA_FILE=/absolute/path/to/approved-idp-metadata.xml
export PLAYGROUND_SAML_IDP_ENTITY_ID=https://idp.example.test/
export PLAYGROUND_SAML_CONNECTION_ID=local-example-idp
export PLAYGROUND_SAML_SIGNING_KEY_FILE=/absolute/path/to/sp-signing-key.pem
export PLAYGROUND_SAML_SIGNING_CERT_FILE=/absolute/path/to/sp-signing-cert.pem
# Optional, if this IdP encrypts assertions or NameIDs; configure both together:
export PLAYGROUND_SAML_DECRYPTION_KEY_FILE=/absolute/path/to/sp-decryption-key.pem
export PLAYGROUND_SAML_DECRYPTION_CERT_FILE=/absolute/path/to/sp-decryption-cert.pem
```

The local HTTPS edge routes `/saml/*` to the Playground HTTP listener while preserving the public Host. The SP entity ID and metadata URL are `https://localhost:8443/saml/metadata` with the default origin; ACS is `/saml/acs`, and Redirect-binding logout is `/saml/slo`. Browser login uses the IdP's Redirect SSO endpoint and receives an HTTP-POST response at the ACS.

For a local round trip with the [scripted IdP](../../interop/scripted-idp/README.md), use a **different HTTPS origin** for the IdP and keep its fixture keys in a private, disposable directory. Set its `/control/config` `base_url` to that browser-reachable origin. Request `/metadata?now=<current-UTC-instant>` using its trusted test CA, save the returned XML to the approved metadata file, and set `PLAYGROUND_SAML_IDP_ENTITY_ID=https://idp.scripted-idp.test/`. Start the Playground with the SAML environment above. Then register the Playground's `/saml/metadata` XML through the IdP's `/control/sps`, passing exact `entity_id`, `acs_url`, `slo_url`, `signing_certificate_pem`, `metadata_xml`, and `require_signed_requests: true`. Arm one `/control/armed/sso` response using the current clock before clicking **Begin SAML login**. Arm `/control/armed/slo` before clicking **Begin SAML logout**. The scripted IdP's [sandboxed browser probe](../../interop/scripted-idp/playground_browser_probe.mjs) also checks both logout directions and `SessionIndex` matching. The scripted IdP is test tooling; its keys are disposable fixtures. The app reads trusted IdP metadata only at startup, so restart it after changing the file.

The app checks `Parsed`/`Rejected`/`Unavailable` metadata results at startup, scopes accounts by its own connection ID, and requires a stable checked subject key before creating a local account. It stores a redacted account view and SAML session reference in its bounded in-memory browser sessions. Sealed pending cookies use `Secure`, `HttpOnly`, `SameSite=None` and the app session's browser binding. Logout ends local access when begun; a verified IdP-initiated LogoutRequest ends only sessions whose connection, full NameID and any supplied SessionIndex match. The malformed ACS button is one safe binding rejection demonstration; the scripted IdP and core tests hold the broader adversarial matrix.

The [Keycloak browser probe](../../interop/keycloak/README.md) also exercises this app with an independent IdP. Chromium can send `Origin: null` on Keycloak's automatic SAML form POST; the Playground accepts that value only at `/saml/acs`, after which its pending browser binding and SAML checks still decide the result. Other browser forms retain exact Origin and CSRF checks.

This example has one-node replay and account storage. A distributed application supplies shared atomic replay/pending storage and durable account/session storage; see the [SAML integration guide](../../docs/saml-sp.md). The SAML flow does not issue OAuth tokens or change MCP bearer admission.

`PLAYGROUND_VALIDATION=introspection` with the node provider's `TEST_PLAYGROUND_TOKEN_FORMAT=opaque` uses fresh audience-checked JSON introspection on every admission. The JWT preset uses strict RFC 9068 tokens. Provider infrastructure failures map to unavailable rather than invalid credentials. The app authorizes every MCP operation: discovery/catalog operations need `mcp:discover`; only the registered `whoami` tool with permitted local/self arguments needs `mcp:whoami`. Other operations, tenant and object selections are denied. Notifications receive the corresponding transport status without a JSON-RPC response body.

Set `PLAYGROUND_REPLAY_JOURNAL=true` only for the local synthetic replay demonstrations. Atomic-store replay and sealed-cookie replay are distinct: atomic consumption rejects locally before another code POST; sealed cookies have no cross-request at-most-once guarantee, so the provider's single-use-code rejection can decide a replay. The opt-in server journal preserves normal pending/browser validation, holds at most one transaction per session and expires at the original deadline. It is not a callback/token export feature.

The [locked Inspector checks](../../interop/inspector-auth/README.md) preserve the released-client recovery regression separately from this endpoint's normal OAuth/tool flow. A generic policy denial remains a denial. The natural framework capabilities are retained; subscriptions are not enabled by default. Later SCIM and self-issuing OAuth scenarios are separate milestone work.
