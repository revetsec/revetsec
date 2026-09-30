# Local OIDF RP suite

Unpublished tooling for the actual Revetsec OIDC client. Self-run test results are the only claim; Revetsec has not been independently audited.

The four pinned plans run 37 modules: Basic (14), Config (6), Form Post Basic (14), and Refresh (3). Each module has a fresh client; the two-login key-rotation module reuses that client and key cache. Discovery-only modules stop at their defined discovery/JWKS boundary. Code flows use generated PKCE/nonce, sealed browser-bound pending state and a fixed registered callback. The small HTML parser is specific to the pinned suite's form template; it never visits the callback.

## Run

Requires Docker Compose, JDK 17 or newer, Maven, Python 3, OpenSSL and curl. Set `JAVA_HOME`; core is installed into a temporary isolated Maven repository. This module is never published and adds no dependency to the core artifact.

```sh
python3 -m unittest discover -s conformance -p 'test_*.py'
python3 conformance/run.py --pull-images --output /tmp/revetsec-oidf-run
```

`--pull-images` explicitly fetches the three digest-pinned images. Omit it to use cached images only. For cached Maven dependencies, use `--offline --repository-tail /path/to/maven/cache`; `--maven /path/to/mvn` selects Maven. Choose a fresh output directory for every run. The runner uses a unique Compose project, publishes only 127.0.0.1:8443 and :8444, asserts those bindings, and removes its containers/network/anonymous volumes even on failure. Those two host ports must be available. A killed runner can be cleaned up using the project name in `startup.log` with `docker compose -p <name> -f conformance/compose.yml down -v` and a valid `REVETSEC_OIDF_TLS_DIR` pointing at the temporary certificate directory.

A fresh short-lived SAN-correct certificate is mounted into the pinned proxy. The Java client trusts only that certificate and retains TLS/hostname verification. Its local hosts file resolves the suite name to loopback without public DNS. No hosted account, real user or production secret is used. All configuration and credentials are disposable test values. Treat raw logs/exports as sensitive test data; do not point this harness at a live provider.

## Gate and evidence

`plans.json` fixes the release, source commit and ordered module lists. The live `/api/server` must match release-v5.3.1 / 440eec8. The three image references are OCI digest pins in `compose.yml` and `run.py`; the suite pin supports Linux amd64 and arm64.

The driver exercises Revetsec's real discovery, authorization, ID-token, UserInfo and refresh APIs. It records a fixed exception reason, including the JOSE reason, for negative cases. An unrelated transport/harness failure never passes. The runner checks the complete 37-module inventory, suite terminal/result fields, RP outcomes, matching final/outcome/raw-log evidence, and valid ZIP exports. Every `FAILED`, `INTERRUPTED`, unexpected skip, warning or review finding fails.

Three runs of `oidcc-client-test-idtoken-sig-none` finish as `SKIPPED`: the RP rejects `alg: none`, and this exact suite module permits that outcome. The report requires the matching rejection and the suite's explicit skip message and writes `dispositions.json`. Ambiguous missing-kid keys are rejected with `AMBIGUOUS_KEY`, one of the two behaviors that module permits. No other skip/warning/review is allowlisted.

Only the harness's injected sources for key-rotation modules use a one-second unknown-key refresh cooldown. The second login waits for that cooldown and reuses the original client/cache. Core defaults stay at 30 seconds. All signing algorithms remain at Revetsec's RS256 default.

The output contains exact image inspections, server metadata, created/final plans, each module's raw logs/final state/RP result, raw plan ZIP exports, skip dispositions, build/driver/container/teardown logs and the public test certificate. The generated private key and isolated Maven repository are deleted. The CI job uploads evidence on both success and failure; a remote check is confirmed only after a pushed run succeeds.

[OIDF RP instructions](https://openid.net/certification/connect_rp_testing/) · [Pinned source](https://gitlab.com/openid/conformance-suite/-/tree/440eec8bac7b12b7389d7ca9cbc459b53507a443)
