# Revetsec Playground — local protocol scenarios

Use JDK 21 or newer for this Soklet application. Revetsec core retains Java 17 compatibility.

Build with [the Maven build](../README.md#build-with-maven), start the local provider and [HTTPS edge](../../interop/local-https/README.md), and configure:

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

Launch the application with the scoped provider truststore described in the parent README:

```sh
java -Djavax.net.ssl.trustStore=/private/tls/java-trust.p12 \
  -Djavax.net.ssl.trustStorePassword=changeit \
  -jar examples/playground/target/playground-1.0.0.jar
```

Frontend HTTP binds 127.0.0.1:8080 and MCP binds 127.0.0.1:8081. The trusted resource is `https://localhost:8443/mcp`, metadata is `https://localhost:8443/.well-known/oauth-protected-resource/mcp`, and OIDC callback is `https://localhost:8443/oidc/callback`. The edge preserves the frontend Host and uses the exact backend MCP Host; applications never derive security identities from forwarded headers.

The UI includes OIDC and optional SAML sign-in, configured resource validation, checked redacted results, client-credentials probing and transient token inspection. OIDC secret references are `env:NAME`, `file:/absolute/path`, or `none` for a public client. Provider configuration, probes and inspection require the application session, exact Origin and CSRF token. Raw credentials are not stored in browser storage, echoed or logged. Before validation, only explicitly unverified allowlisted algorithm/type labels may be shown; claim displays require completed validation.

## SAML service provider

The Playground acts as a SAML service provider (SP). SAML is disabled unless a trusted operator supplies local identity provider (IdP) metadata and the SP's signing key and certificate. The app never fetches an IdP URL or accepts a browser-selected IdP. Configure one approved connection before starting the Playground:

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

Select `PLAYGROUND_SAML_LOGOUT_BINDING=post` at trusted startup to use HTTP-POST logout. The default remains `redirect`. The POST profile requires a POST SLO service in the approved IdP metadata; it publishes the SP POST service at the same fixed `/saml/slo` route. It renders the core-prepared, signed form with a fresh CSP nonce and a form-action restricted to the configured IdP origin. The browser submits that form; the application never accepts a request-selected IdP, action or transport fallback. A POST return is bound to the saved POST attempt, and a Redirect return cannot complete it. Both configured profiles keep signed IdP-initiated logout and full NameID/SessionIndex matching.

Local SAML logout closes the current session's authentication authority before provider preparation and cancels any SAML/OIDC pending login or replay journal on that object. A closed browser marker is retained only to correlate the pending SLO return: ordinary session lookup and final authentication rotation reject it. A fresh explicit bootstrap creates a new object. An IdP logout of a known SAML session applies the same cancellation; already validated callbacks must still pass the final generation/object comparison. SAML identity and its session reference are published together, so a logout observes either the old session or the complete new one. These are bounded single-process application rules, not a global SessionIndex blacklist or durable cross-host revocation service.

At `/saml/acs` and an enabled POST `/saml/slo`, a singleton opaque `Origin: null` is only an auxiliary browser carrier allowance. It grants no IdP trust: signatures, trusted connection, saved browser/pending correlation for returns, exact transaction/freshness and full session matching for IdP requests still decide the result. Hostile/multiple origins and wrong signatures remain denied. A pending SLO result never restores application authentication or proves provider-wide logout.

The optional [POST-SLO socket qualifier](../../verification/playground-post-slo/README.md) checks this application using genuine JCA-signed synthetic IdP messages, actual Soklet HTTP, protected application controls and deterministic cancellation schedules. Its source/runtime-bound receipts retain exact artifacts. HTTP fixture Origins are not TLS/browser evidence; full formal tools, actual TLS/proxy/browser profile, positive encrypted provider interoperability and final merged-artifact qualification remain separately scoped.

The app checks `Parsed`/`Rejected`/`Unavailable` metadata results at startup, scopes accounts by its own connection ID, and requires a stable checked subject key before creating a local account. It stores a redacted account view and SAML session reference in its bounded in-memory browser sessions. Sealed pending cookies use `Secure`, `HttpOnly`, `SameSite=None` and the app session's browser binding. Logout ends local access when begun; a verified IdP-initiated LogoutRequest ends only sessions whose connection, full NameID and any supplied SessionIndex match. The malformed ACS button is one safe binding rejection demonstration; the scripted IdP and core tests hold the broader adversarial matrix.

The [Keycloak browser probe](../../interop/keycloak/README.md) exercises this app with a separate IdP. Its cited capture predates POST-SLO application support and keeps its original source scope. Chromium can send `Origin: null` on an automatic SAML form POST; this version accepts that carrier at `/saml/acs` and at enabled POST `/saml/slo`, while the mandatory SAML signature and browser/session correlation checks still decide the result. Other browser forms retain exact Origin and CSRF checks.

Invalid logout callbacks preserve a live pending flow and its browser cookie, so a later valid IdP response can still complete. Verified terminal statuses and attempt expiry clear the flow. Unavailable or indeterminate callbacks release no provider outcome and never restore local access.

This example has one-node replay and account storage. A distributed application supplies shared atomic replay/pending storage and durable account/session storage; see the [SAML integration guide](../../docs/saml-sp.md). The SAML flow does not issue OAuth tokens or change MCP bearer admission.

`PLAYGROUND_VALIDATION=introspection` with the node provider's `TEST_PLAYGROUND_TOKEN_FORMAT=opaque` uses fresh audience-checked JSON introspection on every admission. The JWT preset uses strict RFC 9068 tokens. Provider infrastructure failures map to unavailable rather than invalid credentials. The app authorizes every MCP operation: discovery/catalog operations need `mcp:discover`; only the registered `whoami` tool with permitted local/self arguments needs `mcp:whoami`. Other operations, tenant and object selections are denied. Notifications receive the corresponding transport status without a JSON-RPC response body.

Set `PLAYGROUND_REPLAY_JOURNAL=true` only for the local synthetic replay demonstrations. Atomic-store replay and sealed-cookie replay are distinct: atomic consumption rejects locally before another code POST; sealed cookies have no cross-request at-most-once guarantee, so the provider's single-use-code rejection can decide a replay. The opt-in server journal preserves normal pending/browser validation, holds at most one transaction per session and expires at the original deadline. It is not a callback/token export feature.

The [locked Inspector checks](../../interop/inspector-auth/README.md) preserve the released-client recovery regression separately from this endpoint's normal OAuth/tool flow. A generic policy denial remains a denial. The natural framework capabilities are retained; subscriptions are not enabled by default. Later SCIM and self-issuing OAuth scenarios are separate milestone work.

## SCIM provisioning

Register private service-client credentials to enable the restrictive SCIM directory: alpha administrator (`SCIM_BEARER_TOKEN`), limited provisioner (`SCIM_ALPHA_LIMITED_TOKEN`) or reader (`SCIM_ALPHA_READER_TOKEN`), and optional beta administrator/reader (`SCIM_BETA_BEARER_TOKEN`, `SCIM_BETA_READER_TOKEN`). Roles and tenants come from explicit startup registration. Use `example.playground.ScimDirectoryPlayground` for the same standalone policy. See [the service-client recipe](../../docs/scim-restrictive-service-clients.md) for canonical tenant paths, field/query rules, password and work bounds, the HTTPS edge and volatile-state limits. The separate `ScimPlayground` entrypoint retains the earlier administrative interoperability fixture and its registered Enterprise User extension; [interop/scim](../../interop/scim/README.md) remains scoped to that fixture.

## Browser session admission

Static assets, metadata and `GET /api/session` are allocation-free. Without a session, status returns `sessionAvailable: false` and an empty CSRF value. Start local session sends an explicit same-origin `POST /api/session` with only `begin=1`; it requires exact Host/Origin and one form Content-Type and rejects query parameters or discarded/oversized input. The UI enables protected controls after admission. This step creates no identity; configuration, probes and authentication controls still require the session-bound CSRF token.

The launcher selects 128 sessions (constructor range 1–256), with a default 8,388,608-byte content budget charging 65,536 bytes per entry. The store refuses new admission with a fixed 503 at either limit and preserves every live session. Absolute expiry is ten minutes after creation or authentication rotation, with request-time cleanup; status reads and bootstrap reuse never renew it. Anonymous status remains readable at capacity. These are single-process example limits. Trusted edge admission/rate limits remain necessary against deliberate session creation, and distributed deployments supply their own shared session/admission infrastructure.
