# Goose real self-issued workflow (unpublished)

This fixture runs unmodified released Goose 1.57.0 (Linux ARM64), its shipped account-free `mcp-probe` command and explicit `2025-11-25` protocol selection against exact packaged self-issued/core/Soklet artifacts. A real sandboxed Chromium browser performs local demo login, consent and the native callback. Goose owns resource/issuer discovery, its built-in CIMD identity, S256/code exchange, scope step-up, credential storage, refresh and all MCP calls.

The selected recovery is **stored-auth reconnect after actual expiry**: one command completes tool use; the fixture waits 121.5 seconds beyond that command's completion; another unmodified command uses the same private Goose root and performs refresh before protected tool use. The example's two-minute lifetime and clocks are unchanged. `expires_in` can be 119 or 120 after elapsed-time rounding. This profile does not establish recovery of an in-flight request in a continuously running client, GUI/model-driven Goose operation or the default modern protocol profile.

## Inputs

Use `workflow-pins.json` and the already prepared public client/runtime from the [synthetic preflight](../README.md). Verify the official client archive before extracting `goose`; the workflow checks the executable hash. Prepare the Java/Caddy/public system-CA/seccomp inputs described by the [VS Code fixture](../../vscode-auth/README.md), with the exact digests in the workflow pins. No images are pulled during execution.

Supply four current-source JARs and their `{ "name": "filename.jar", "sha256": "..." }` manifest from the [exact-source example build](../../../examples/self-issued/README.md). Keep its source inventories and test/runtime receipts. `--source` supplies the exact unchanged pinned process/CDP/browser helpers from that build. Every run needs a fresh issuer port and output directory.

```sh
python3 interop/goose-auth/workflow/run.py \
  --source /absolute/exact/core-source \
  --runtime /absolute/private/runtime \
  --client /absolute/private/goose-runtime \
  --app /absolute/private/app \
  --app-manifest /absolute/private/app-manifest.json \
  --output /absolute/new/private/workflow \
  --port 37511
```

Repeat with `--metadata-delay-ms 1000` and a different new issuer port/output. The metadata server replays the unchanged dated Goose publisher document with its captured `max-age=600` policy. Each code redemption and refresh must perform its own anonymous, unconditional fresh-200 metadata fetch despite that warm cache window. Timings use the observer's monotonic clock and compare local credential round trips to the separately established 30-second Goose OAuth HTTP deadline. This is controlled local latency, not an internet-origin or Claude timeout measurement.

## Client, browser and server behavior

The probe script contains only supported protocol selection and ordinary tool-list/call steps. There is no preloaded OAuth result, client-ID override, custom authorization header or injected protocol header. The first `whoami` request challenges the discovery-only grant. Goose performs fresh browser consent and a second bound code exchange for the expanded scopes, then retries successfully. Both invocations must list the catalog, return a checked local identity result and receive the application's normal other-tenant denial. Identity text and its hash are never persisted.

`BROWSER` points to an ordinary disposable opener that passes the client's original authorization URL through a private Unix socket to Chromium, unchanged. The client uses its supported fixed callback-port setting at `http://127.0.0.1:33419/oauth_callback`. Real form submissions perform demo login and consent; the browser follows the issuer's code/state/issuer redirect. No synthetic issuer or callback driver from the preflight is used here. The built-in automatic-callback shortcut remains unset.

Each invocation owns a network-none namespace. Its sole preparer adds public-form and IPv6 loopback aliases; application/client/browser processes run uid1001 with all capabilities dropped. Client/runtime/app/helper mounts are read-only. A disposable CA is trusted only in private Java/NSS stores and a container-local public CA bundle. Normal chain, SNI and hostname checks remain enabled. Host trust, profiles and keychain are untouched. No provider/model account is used.

`RUN.json`, matching `junit.xml` and the child `evidence/RESULT.json` retain source/artifact pins, structural bindings, code/refresh timings, expected scope challenge, tool outcomes, expiry and cleanup. PASS qualifies this selected local released-command workflow. `fullClientWorkflowQualified` refers to that explicit `qualificationScope`; `releaseQualification` stays OPEN for broader gates. Failed or preparation runs retain their original status and identity. Raw logs, credential/cookie values or hashes, OAuth URLs, identity partitions, browser profiles and private TLS never enter durable receipts.

## Calibrations and scope

```sh
python3 -m unittest discover -s interop/goose-auth/workflow -p 'test_*.py' -v
```

`acceptance-reference.json` is sanitized structural test input from a preparation run, not a qualification receipt. Tests reject missing or contradictory binding, browser, scope, expiry, current-refresh, header, metadata, timing and cleanup proofs. Run `wire-check.mjs` as uid1001 in the pinned network-none browser image with this directory mounted read-only at `/suite` to calibrate observer forwarding, argument classification, redaction and bounds with synthetic secrets. The observer preserves application bodies/headers; the TLS edge performs ordinary reverse-proxy framing.

This selected local result does not close broader RC/security/coverage gates, qualified durable/shared-clock exit, other clients/profiles or real-client request cancellation and transport-loss recovery. The example retains volatile demo stores. The scoped remaining-risk ledger must preserve those limits.


The current application first presents its ordinary explicit browser-session bootstrap. The fixture submits that original same-origin POST form once, preserves its original authorization query, and observes the accepted Secure/HttpOnly session cookie before login. The resulting server redirect resumes that same authorization; it is distinguished from the two new authorization URLs opened by the unmodified Goose client. No callback, credential, client header or authorization URL is injected or rewritten. Missing, duplicate, foreign-origin, wrong-body or unbound bootstrap proof fails the current qualification. The sanitized acceptance reference remains structural test input, never a workflow receipt.
