# VS Code CIMD transport checkpoint (unpublished)

This fixture runs the pinned, unmodified Linux ARM64 VS Code release in `pins.json` against exact packaged self-issued example/core/Soklet-helper artifacts. It supplies a disposable VS Code extension that registers a server through the public MCP definition API and opens the ordinary server picker. A sandboxed browser performs the application's local demo login and consent. The released client owns discovery, its built-in CIMD identity, native callback, S256/code exchange and refresh. No model/provider account is supplied.

**This is a blocker reproducer, not completed released-client qualification.** The current client negotiates MCP `2025-11-25`, then omits `MCP-Protocol-Version` on `notifications/initialized`. The selected endpoint rejects it with 400. The pinned Soklet adapter explicitly refuses the headerless fallback revision `2025-03-26`. Successful OAuth milestones cannot establish MCP catalog/tool or full recovery interoperability. The runner stops at this rejection. An unexpected advance fails this checkpoint and requires a new qualification plan; it is not an automatic pass.

A `REPRODUCED` receipt means the exact blocker and its preceding OAuth milestones were observed and cleaned up. Every receipt keeps `fullClientWorkflowQualified: false` and `releaseQualification: OPEN`. Earlier exploratory failed runs retain their own status and identities. No client code, headers, OAuth result or credential state is patched or injected. The separate compatibility tests compare the same notification with supported explicit version headers and check that enabling the unsupported revision is refused.

## Prepared inputs

Use a new private workspace and already cached immutable images from `pins.json`. Runs never pull images or contact external services. Prepare:

- `client/`: extract the official release archive from `pins.json` after verifying its published SHA-256. The complete extracted tree must match the recorded tree identity; keep the Microsoft release/license files. The runner mounts it read-only.
- `runtime/java/`: `/opt/java/openjdk/` from the pinned cached Temurin 21 image; preserve files and symlinks. The runner verifies the full tree.
- `runtime/caddy`: `/usr/bin/caddy` from the pinned Caddy image.
- `runtime/system-ca.crt`: the public `/etc/ssl/certs/ca-certificates.crt` from the pinned browser image.
- `runtime/seccomp.json`: the existing derived [browser sandbox profile](../inspector-auth/linux/README.md). Its digest must match the pin; no sandbox-disable flag is used.
- `app/` and `app-manifest.json`: four packaged JARs from the [exact-source example build](../../examples/self-issued/README.md): self-issued example, core, Revetsec Soklet adapter and Soklet 4.0.0. The manifest is an array of `{ "name": "filename.jar", "sha256": "..." }` rows. Keep the build's source inventories, checks and artifact receipt alongside the run.
- `source/`: the exact core input from that build, supplying the pinned process/CDP/browser helpers. Keep its complete source inventory.

Extract public runtime inputs only through owned stopped containers, then remove those containers. Do not copy another container's application state, credentials or trust files. Docker, Python and OpenSSL are required. The fixed synthetic metadata document is the unmodified dated VS Code capture; this is not a live production-origin metadata fetch or a claim of hostname ownership.

## Run

Use a never-used issuer port for every invocation and a new output directory:

```sh
python3 interop/vscode-auth/run.py \
  --source /absolute/exact/core-source \
  --runtime /absolute/private/runtime \
  --client /absolute/private/VSCode-linux-arm64 \
  --app /absolute/private/app \
  --app-manifest /absolute/private/app-manifest.json \
  --output /absolute/new/private/checkpoint \
  --port 37421
```

Repeat separately with `--metadata-delay-ms 1000` and another new port/output to measure a controlled one-second metadata delay. Token round-trip and its own metadata-fetch durations use the observer's monotonic clock. Samples cover completed code/refresh requests preceding the transport failure. They are local measurements against a replayed document, not internet latency or expired-token recovery evidence. The reviewed Claude timeouts are not relabeled as VS Code timeouts. The inspected pinned code/refresh exchange methods supply no separate fixed deadline; their caller/transport cancellation and platform limits remain open in this checkpoint.

The example retains its ordinary two-minute access lifetime and selected protocol revisions. The pinned client treats tokens within five minutes of expiry as needing refresh, so it eagerly refreshes these short-lived demo tokens. This is recorded, not suppressed. A future full-flow target/profile must resolve lifetime and protocol compatibility before qualification. No extra March-2025 protocol support, lifetime option or refresh-grace behavior is added by this fixture.

## Isolation and evidence

Each invocation owns a network-none namespace with a public-form `8.8.8.8/32` loopback alias for the CIMD peer. Only its namespace preparer receives NET_ADMIN; application/client/browser processes remain uid1001 with zero effective capabilities. All runtime/application/client/source mounts are read-only. There is no external route or published host port.

A private CA is trusted only in the disposable Java/NSS stores and a container-local CA bundle, using supported VS Code system-certificate settings. TLS chain, SNI and hostname checks remain enabled. The client/browser use explicit local hostname mapping so both reach the IPv6 TLS edge while the app retains its IPv4 listener. Host trust and desktop profiles remain untouched. A new VS Code profile selects custom dialogs and its supported external-browser command; its original authorization URL travels only over a private Unix socket and opens unchanged. `focus.py` uses the owned process's X11 window identity inside Xvfb. No host desktop is accessed.

`RUN.json`, `junit.xml` and `evidence/RESULT.json` contain fixed structural facts, immutable inputs, local prerequisites, observed OAuth bindings, token/metadata timings and the transport blocker. Request/response bytes pass unchanged. Credentials, their hashes, raw logs, cookie values, identity partitions, browser profiles and TLS private keys never enter durable receipts. Private state and all owned child processes/containers are removed on success, unexpected behavior, error or timeout. A private failure diagnostic retains only bounded fixed error-code categories.

## Calibrations

```sh
python3 -m unittest discover -s interop/vscode-auth -p 'test_*.py' -v
```

The acceptance tests reject missing or contradictory discovery, browser, redirect/PKCE/resource, refresh rotation, freshness, TLS/header, timing and cleanup proofs. `wire-check.mjs`, run as uid1001 in the pinned network-none browser image with this directory read-only at `/suite`, uses synthetic secrets to check byte transparency, redaction, malformed responses and request/event bounds. The driver is checked against the release's shipped public `vscode.d.ts`, using `extension/api-check.d.ts` only for its small Node I/O surface. No runtime dependencies are installed into the client.

The example's own tests cover supported explicit legacy notifications, rejection of absent/unknown versions, authentication, and the pinned adapter's explicit March-revision refusal. These checks do not close RC-1/RC-AS, M12, durable storage, qualified shared-clock exit, live-origin latency or independent review.
