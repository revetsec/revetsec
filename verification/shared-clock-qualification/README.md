# Focused shared-clock qualification

This unpublished fixture contributes focused current-source evidence for the shared-clock change. It adds no runtime library API. Use its native runner only with the explicitly owned disposable PostgreSQL resources it creates; it has no arbitrary deployment target option.

The current-source join binds one exact core artifact, current test/helper inputs, consumer/API/Javadoc evidence, retained fuzz inputs and calibrated production-source guard mutations. Reuse requires an exact dependency and source comparison. A changed test tree does not inherit a prior whole-suite pass merely because the production JAR is unchanged. Each mutation has a passing original control and a named assertion that detects the changed guard.

The native lane measures the actual current TOTP, WebAuthn and issuer adapters with 8 and 16 actors. Distinct quota buckets, independent keys sharing a bucket, and a single contested entity have separate outcomes and latency records. Held-lock controls and actual PostgreSQL blocker observations distinguish progress from serialization. Root/namespace fingerprints and per-key/version/quota observations check the write set. Direct SPI transactions exercise backend structure; the separate engine/service receipts establish their own behavior. These measurements do not establish issuer policy/signing latency or a complete service workload certificate.

```sh
python3 verification/shared-clock-qualification/run_postgres.py \
  --output /absolute/fresh-owned-output \
  --java-home /absolute/jdk17-or21-home
```

The runner checks its cached PostgreSQL image and pinned artifacts without pulling an image. It removes its owned containers, volumes, networks and protected runtime files on success or failure. Results retain structural assertions, tool/source identities, generated schedule seeds, blocker relationships and timings; they exclude credentials, raw authentication records and secret material.

The 95-group evidence inventory records applicable lanes and unresolved requirements separately. Scripted authority time supports functional tests. Approved UTC accuracy, witness custody, platform/device durability, worker continuity and complete applicable profile evidence remain prerequisites for a qualified shared deployment. Local A/B evidence and partial one-host C evidence cannot pass an unavailable lane or qualify cross-host D. The source checkpoint does not close SCP-11/SCG-07 while those dependencies remain missing.

See the [store contract](../../docs/shared-clock-stores.md), [witness fixture](../shared-clock/README.md), [PostgreSQL primitives](../shared-clock-postgresql/README.md) and [closed migration/restore fixture](../shared-clock-migration/README.md).
