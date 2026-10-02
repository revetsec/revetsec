# Released Inspector generic 403 recovery diagnostic

This isolated diagnostic runs unmodified released `@modelcontextprotocol/inspector@2.9.0` against a bounded Node loopback responder. It tests whether a valid static bearer credential plus a generic policy 403 response without `WWW-Authenticate` triggers unintended OAuth recovery. It uses no Revetsec implementation or application tool call and does not qualify a real application host.

## Locked client

From `interop/inspector-auth/client`, install with `npm ci --ignore-scripts --no-audit --no-fund` using the committed exact `package-lock.json`. Do not install globally or rebuild/patch the released client. `client/pins.json` records exact package/lock hashes, official npm integrity, release commit, runtime and the installed tree identity. The runner checks those pins before and after execution. Optional platform dependencies make the installed-tree pin platform-specific; a different environment needs a separately recorded complete tree identity, with the same exact lock and released package integrity.

Run the recorded Node executable/version:

```sh
node interop/inspector-auth/run.mjs \
  --dependencies /absolute/path/to/interop/inspector-auth/client \
  --browser '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' \
  --work-dir /absolute/path/to/new/private-diagnostic-run
node --test interop/inspector-auth/fixture-self-test.mjs interop/inspector-auth/runner-self-test.mjs
```

The work directory must be new and outside sources (or under target). Each row creates a fresh read-only memory-store configuration, private browser profile and disposable credential. No user profile, keychain, OAuth account or shared installation state is used. Browser interception allows only the local Inspector origin; its exact optional font request is denied and counted. Every metadata/registration recovery attempt stops at the local responder.

## Five cases

| Case | Intended difference | Interpretation |
| --- | --- | --- |
| no-subscription | No list-change advertisement | Causal control: no subscription or OAuth recovery |
| jsonrpc-200-control | Identical error body, HTTP/200 | Causal control: retries may remain; OAuth must not occur |
| policy-403 | Generic403 without auth challenge | Observe whether the released client attempts recovery |
| policy-403-throw | Explicit insufficient-scope throw setting | Test the supported setting separately |
| policy-403-no-refresh | Explicit automatic refresh disabled | Test the supported setting separately |

The controls identify the cause; their capability/status differences are not changes to an actual application's access policy. The underlying SDK and Inspector subscription paths remain unmodified. All cases authenticate discovery and exactly two tools-list calls, then observe the same six seconds. No tool is invoked.

`REPRODUCED_WITH_CONTROLS` means both causal controls pass and all three policy 403 variants reproduce unintended recovery. It is a diagnostic outcome, not a passing host result. `NOT_REPRODUCED_WITH_CONTROLS` requires the same controls and unchanged 403 responses with zero recovery in every policy row. `MIXED_WITH_CONTROLS` retains differing observations. Missing/invalid traffic, isolation, lifecycle or identity facts remain `FAILED`. hostQualification and candidateEvidence are always false.

## Bounds and evidence

Requests/responses cap at 64 KiB, total requests 64, connections 32, exchange 10 seconds. Host/browser bounds 60/45 seconds, startup/catalog 10 seconds, observation 6 seconds, disconnect 5 seconds. Child output caps 1 MiB and is never persisted. Graceful exit 3 seconds has independent 2 secondTERM/KILL fallbacks. Cancellation stops scheduling further cases. Closure consumes only the exact expected CDP_CLOSED condition; other protocol errors remain failures.

The receipt retains only fixed labels, booleans, bounded counts and static source/dependency/browser/config identities. It excludes live credentials, token hashes, private bodies, request IDs, browser storage and arbitrary host/browser diagnostics. A gap-free combined request sequence requires every OAuth attempt to follow the first denied subscription. Each process must close and each private session must be removed before final identity checks.

The harness is adapted from the focused September 19 Inspector auth-recovery fixture and its shared CDP/process/config helpers. Historical diagnostic outcomes and failed attempts remain private evidence; no unrelated app/source inventory is included. This is implementation verification, with no independent review or audit claim. Normal Playground OAuth/tool-call verification is separate; success there does not close this generic 403 recovery item.
