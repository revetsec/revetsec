# Independent SCIM qualification

`run.py` starts the actual compiled `example.playground.ScimPlayground` Soklet
routes, then runs **scim2-tester 0.5.2** and the production outbound
`SCIMUserClient`/`SCIMGroupClient` from **authentik 2026.8.3**. It does not use
authentik's inbound SCIM source as evidence. The authentik client runs in its
official image with real Django models, property mappings and a disposable
PostgreSQL database. It writes, updates, deactivates and deletes users; creates,
renames and deletes a group; adds and removes members; and checks unchanged
syncs do not write. The qualified client uses authentik's explicit **AWS**
compatibility mode (`aws`). Its production client disables PATCH in that mode
and uses ordinary SCIM POST/GET/PUT/DELETE, including membership changes. The
server uses the documented extension-root profile and enforces required schema
and attribute validation. Method metadata and the selected
mode are recorded; this does not qualify an AWS account or AWS service. This is
a client integration fixture, not an authentik UI or
asynchronous worker scheduling qualification.

Authentik 2026.8.3's default mode has an unresolved upstream defect: group
rename constructs a PatchRequest then serializes with `exclude_unset=True`,
omitting the required top-level PatchOp `schemas`. The unchanged production
client reached the real routes and received strict SCIM 400 `invalidSyntax`.
`authentik-default-shape.py` reproduces the missing field using
the pinned upstream serializer and records only keys and a production-source
digest. See the [exact official client source](https://github.com/goauthentik/authentik/blob/e5a0d2f7572cb776eee7a3e9355937ce38973761/authentik/providers/scim/clients/groups.py#L198).
No default-mode interoperability success is claimed, no request is rewritten,
and required schema validation remains enabled. The AWS mode is an explicit
qualified alternative, and nightly evidence validation rejects any mode mismatch.

All values are synthetic. No hosted Microsoft/Okta/Entra account was exercised
by this tooling, and no hosted compatibility claim follows from it. The
Playground's documented ASCII identity and in-memory transaction profile is
the tested application profile. Group members reference existing Users or
Groups, with resource kind and `$ref` checked against the same authoritative
state. Remove inbound references before deleting a referenced resource. A durable store and account
matching policy remain application responsibilities.

The tester also has a pinned default data-fixture defect: its extension-root
ADD/REPLACE checks serialize an extension as a standalone SCIM object, placing
a nested `schemas` field inside the Enterprise extension value. That is not an
Enterprise attribute, and the server rejects it. Every qualification
run preserves the complete unconfigured result in `tester-default.json` with
those two ERROR rows. It then uses the supported client model/provider
registration API to derive an Enterprise model from the **discovered** schema
and exclude only its inherited `schemas` serializer field. All discovered
schema facets and all upstream check algorithms remain active. The configured
profile's full result is separate in `tester.json`; emitted HTTP requests are
never rewritten. The default defects must match both exact check identities
and captured nested-field shapes. Any extra or unexplained default error, or
any configured-profile error, fails qualification. This qualifies the explicit
configured profile; it does not claim the stock tester completed without errors.

The official releases, container manifest digests, license scopes and dated
advisory checks are in `pins.json` and `python-pins.json`. The tester's full
transitive Python closure is exact-version and artifact-checksum locked in
`requirements.txt`. Container pulls always include the digest, including Java,
Caddy and PostgreSQL. Pin metadata alone is not interoperability evidence.
The source for the [tester](https://github.com/python-scim/scim2-tester) and
[authentik outbound provider](https://docs.goauthentik.io/add-secure-apps/providers/scim/)
is independent of Revetsec. Authentik's September 2026 published advisories are
patched in 2026.8.2; the selected release is 2026.8.3. This dated review does
not promise that future advisories or dependency vulnerabilities cannot arise.

Build current core, the Soklet adapter and the unpublished Playground according
to `examples/README.md`. Use a task-private Python environment:

```sh
python3 -m venv /private/tmp/revetsec-scim-tester
/private/tmp/revetsec-scim-tester/bin/python -m pip install --require-hashes -r interop/scim/requirements.txt
python3 interop/scim/run.py \
  --classes examples/playground/target/classes \
  --class-path-file examples/playground/target/runtime-classpath.txt \
  --python /private/tmp/revetsec-scim-tester/bin/python \
  --output /private/tmp/revetsec-scim-qualification
```

The output directory must be new. The application class path contains the
actual built classes and runtime JARs; the report hashes their bytes. Docker
uses a unique internal network. Only the TLS edge additionally joins a separate
publication bridge and is published on a random loopback port. Docker 29 does
not allocate published host ports to internal-only networks. The application,
database and authentik have no host-published port. Images are pulled before
creating the networks. The official Caddy binary requires its declared
NET_BIND_SERVICE file capability in the container's bounding set; all other
capabilities are dropped from the edge. No Docker socket
is mounted, no global trust store is changed, and all containers, the private
networks, the application image, certificate keys and ephemeral secrets are
removed on exit. The database exists only in tmpfs. Interrupted processes may
need cleanup of resources with the reported `revetsec-scim-` prefix.

The two-day task CA signs a leaf with `localhost`, `scim-target` and `127.0.0.1`
SANs. The Python tester trusts only that CA; authentik receives
`REQUESTS_CA_BUNDLE` for that run and keeps certificate verification enabled.
Positive scoped trust, negative default trust and negative foreign hostname
controls are mandatory. There are no hostname bypass flags. Outcome reads have
a 20-second deadline and 100-ms bounded polling; each authentik HTTP request
has a five-second connection and twenty-second response timeout. This fixture
does not assume propagation from a fixed sleep.

Both complete tester profiles run against discovered User and Group schemas.
ERROR, CRITICAL, DEVIATION or a missing required test category in the configured
profile fails qualification; only the two documented default
fixture defects have the explicit disposition above.
SKIPPED and optional ACCEPTABLE outcomes remain explicit in `tester.json`;
they are not rewritten as successes. Raw tester debug bodies and bearer values
are excluded from evidence. `authentik.json` records required outcomes and
method/status/path traffic metadata with synthetic resource IDs replaced by
placeholders. `qualification.json` binds those outcomes to application artifact
bytes, tool pins and, in CI, the GitHub run, attempt, event and source SHA.
An optional `--diagnostic-request-directory` captures at most three failing
synthetic extension/Group bodies, each at most 64 KiB and containing no password
field. It is a private reproduction aid and is not enabled in CI. Ordinary
receipts retain only redacted shapes in `tester-default-wire-errors.json` and
`tester-wire-errors.json`.
Aggregate POST `/scim/v2/.search` is an optional unsupported operation. The
fixture returns a SCIM 501, and the pinned upstream tester records an explicit
SKIPPED outcome. Resource-specific POST `/Users/.search` and `/Groups/.search`
remain supported and are covered by the application tests.

`.github/workflows/scim-interop.yml` runs tester-only qualification on relevant
pull requests (`run.py --mode tester`), and both clients on scheduled/manual
runs. The outbound nightly result is advisory, not a new PR-required status.
Nightly CI is ongoing coverage with no minimum-duration or consecutive-run
release gate. The workflow and M12 empty-body bridge repair are pushed. The exact
adapter source guard and checkout revision are kept together; after a reviewed
adapter update is pushed, refresh both. The pinned source also includes the
API-freeze documentation for overflow handling and host-owned response headers.
A configured schedule is not evidence that a particular run passed.
Collect the authoritative GitHub REST workflow-run history, including failures
and skips, and download each matching run's qualification artifact to
`<evidence-directory>/<run-id>/qualification.json`. Then run:

```sh
python3 interop/scim/soak.py --runs-json scheduled-workflow-runs.json \
  --evidence-directory downloaded-artifacts --output soak-result.json
```

The checker reports each scheduled run and validates its complete required
outcomes, matching event/run/attempt/SHA, artifact/tool hashes and selected
client modes. Its overall result reflects the latest scheduled run. A single
successful run can pass; pin changes, successful reruns and calendar gaps do
not impose a release waiting period. Age is reported for visibility. Failures
and missing or mismatched receipts remain explicit. Manual runs remain separate
from scheduled history. Use authoritative history rather than a success-only
list. `test_scripts.py` checks provenance and exact upstream-defect dispositions.
This ongoing coverage does not replace owner API freeze, external review,
penetration testing or the complete release assurance matrix.

The local qualification on 2026-10-13 completed both clients on the actual
containerized Soklet routes: default tester **129 SUCCESS / 2 optional SKIPPED /
2 identified fixture ERROR**, configured tester **131 SUCCESS / 2 optional
SKIPPED / zero ERROR**, and authentik AWS mode **eight required outcomes / 22
actual HTTP calls**. The skipped checks are the unsupported optional aggregate
search, for User and Group. The default tester and authentik default-mode
defects remain explicit. These are local runs, separate from nightly CI history.
Exact artifact/tooling hashes, reports, failed attempt history and dispositions
are preserved in the private M12 evidence record rather than copied into source.
