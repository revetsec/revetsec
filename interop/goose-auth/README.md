# Goose released-client preflight (unpublished)

The separate [real self-issued workflow](workflow/README.md) exercises this released profile with a real browser, scope step-up, tools and an expired stored-auth reconnect. The synthetic preflight below retains its own scope.

This selects **Goose 1.57.0, Linux ARM64, its shipped `mcp-probe` command and the `2025-11-25` protocol profile** for the next real self-issued qualification attempt. The command is hidden from top-level help but included in the unmodified published binary. It creates a normal Goose Agent/extension-manager session without a model provider. The probe script selects a supported protocol and ordinary list/call operations; it supplies no credentials, OAuth result, client ID override or raw protocol headers.

This fixture exercises a **synthetic loopback HTTP issuer/server**. It does not run Revetsec, launch a real browser, fetch CIMD from the synthetic issuer, qualify TLS, or establish full released-client interoperability. Every receipt keeps `fullClientWorkflowQualified: false`, `realIssuerExercised: false` and `releaseQualification: OPEN`. Existing VS Code blocker receipts retain their scope.

## Inputs and execution

Prepare a new directory containing only `goose`, extracted from the official archive in `pins.json`. Verify the archive against its published SHA-256 before extraction. The runner verifies the exact executable and dated live CIMD capture. Use the already cached, digest-pinned Linux ARM64 runtime image; the runner never pulls an image. Docker and Python are required; no client is installed into host application or configuration paths.

```sh
python3 interop/goose-auth/run-preflight.py \
  --client /absolute/private/goose-runtime \
  --output /absolute/new/private/goose-preflight
```

The four cases run sequentially in one disposable network-none container, as uid1001 with all capabilities dropped, a process/memory bound and read-only client/fixture mounts. No host profiles, keychain, trust store or credential environment is mounted. A new temporary Goose root and file secret store are removed after every case. Synthetic authorization URLs, codes, tokens and their hashes are absent from receipts and raw output is discarded.

The transport control requires actual initialize completion, a synthetic tool list/call and the negotiated version header on subsequent requests. The callback control observes Goose's real authorization URL and waits for its supported two-second callback timeout. The code/refresh controls drive a synthetic redirect through the client's real native listener and withhold the corresponding token response until the client disconnects. The synthetic driver follows its own issuer redirect in place of a browser; this is a deadline/binding calibration, not browser authorization evidence. The built-in automatic-callback shortcut stays unset. No normal client request is rewritten.

`RUN.json`, matching `junit.xml` and `evidence/RESULT.json` preserve immutable pins, structural bindings, bounded timings and cleanup. A local PASS means the selected client contract was observed. An unexpected version, absent header, missing PKCE/resource/actual redirect binding, missing refresh value, wrong deadline, qualification overclaim, artifact drift or failed cleanup fails the preflight.

## Selected client contract

The built-in CIMD identity is `https://goose-docs.ai/oauth/client-metadata.json`. The dated live HTTP-200 document matches the release source and has `Cache-Control: max-age=600`; it declares code/refresh, public-client authentication and port-less IP-loopback callback paths. Revetsec requires its separate explicit IP-loopback policy. Localhost any-port and custom schemes are unnecessary for this profile. The live public document is a capture, not a guarantee of future publisher content.

Goose binds an ephemeral `127.0.0.1` port at `/oauth_callback`; the supported `GOOSE_OAUTH_CALLBACK_PORT` can select a fixture-owned fixed port later. Its default browser callback wait is 300 seconds, separately configurable through `GOOSE_OAUTH_CALLBACK_TIMEOUT_SECONDS`. The selected SDK applies a 30-second OAuth HTTP request deadline to code exchange and refresh; the preflight measures both disconnects. This is Goose evidence and does not verify the separately reviewed Claude limits.

Goose and its locked `rmcp` SDK refresh when fewer than 30 seconds remain. The existing example's 120-second lifetime exceeds that window; no lifetime option or refresh grace is added. The normal MCP operation timeout/cancellation path and transport recovery controls are distinct from OAuth HTTP deadlines. Their full real-server behavior remains a later acceptance gate.

## Checks and next gate

```sh
python3 -m unittest discover -s interop/goose-auth -p 'test_*.py' -v
```

Acceptance calibrations include missing/contradictory proof and qualification-scope negatives. The accompanying planning receipt binds the official release/locked SDK source inspection, binary, live document and focused current-library document-admission probe. No production code changes are required for this selection.

Next, use this exact released profile against exact packaged Revetsec artifacts with a real sandboxed browser and private normal TLS validation. Require discovery, login/consent, actual native callback, bound code exchange, MCP catalog/tool completion, real expiry/refresh, protected use afterward, controlled metadata latency and cleanup. Keep CIMD freshness, default-off loopback policies, PKCE, actual-return/resource binding and single-use rotation. Do not count this synthetic suite as that workflow or introduce header injection, client patches or preloaded credentials to obtain a pass.
