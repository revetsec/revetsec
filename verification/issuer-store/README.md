# PostgreSQL issuer storage with Pyranid

This unpublished fixture implements the schema-2 admitted-time issuer SPI on one PostgreSQL primary using pinned Pyranid 4.7.0. Revetsec core acquires no database dependency. Applications own access, keys, TLS, pools, capacity, witness/recovery admission, migration and operating procedures.

`PostgresStore` wraps `FixtureIssuerStore`, a private source copy of the application example adapter. The shared `IssuerPg*` lock/transaction/escrow helpers preserve the bounded protocol. All ordinary calls hold shared physical admission and sorted strongest-mode logical entity locks, including absences; changed entry buckets follow. Fresh root activation takes exclusive admission first. There is no namespace mutex, global normal count/sum, cleanup, transaction retry or worker-selected healthy time. The authority uses a separate explicit `authorityNow`/`authorityMode` fixture input; `now` controls only the worker Clock.

Reads return coherent `Available(key, entry-or-absence, observation)`, `Fenced` or `Unavailable`. Timed writes compare complete versions/admission, sample fresh authority after all waits, check lower/upper bounds, then capacity and atomic data/quota changes. Exact retention seconds/nanos preserve the permanent sentinel. The root registry makes established root loss unavailable rather than fresh absence. Its contents are not an external recovery witness. A clock/error-only profile transition with matching current authority/recovery retains coherent data admission with unavailable time, permitting only the narrow fence path. Timed writes stay fenced; authority/recovery mismatch, missing root/activation and uncertain reads do not receive this downgrade.

Pyranid owns transaction lifecycle and public post-transaction completion. Known COMMITTED retains required timing even after local deadline/cleanup failure. Uncertain acknowledgement after possible DML is UNKNOWN, never an automatic retry. Empty barriers and failed transactions do no hidden writes. Private `Probe` hooks only interrupt this fixture's SQL/lifecycle phases, never run security callbacks inside a transaction.

Existing issuer/subject epoch revocation uses only the exact `FENCE_ONLY` shape. Current authority/recovery admission is mandatory; UTC and worker health are omitted solely for this path. The service takes its fresh minimum issuer-root acknowledgement read. Raw initialization/reseal preserve contextual factual receipts; finite reseal uses full original retention.

Build the core in a private Maven repository, then package this standalone module. The runner accepts existing exact JARs and a cached PostgreSQL image; it uses `--pull=never`, unique owned resources and loopback credentials. It records structural checks and hashes, omitting rows, credentials and SQL payloads:

```sh
python3 verification/issuer-store/run.py \
  --java-home /absolute/jdk --core-jar /absolute/revetsec.jar \
  --fixture-jar /absolute/issuer-store.jar --pyranid-jar /absolute/pyranid.jar \
  --driver-jar /absolute/postgresql.jar --output /absolute/new-receipt
```

`StoreContract` and `RecordingStore` capture genuine public engine transactions; they do not construct restricted authority. The process runner exercises rollback, complete exact predicates, barriers, separate-JVM code/refresh races, wire acknowledgement loss, process/primary interruption, restart, worker-health refusal and missing established roots. `--recovery` adds the separately bounded logical archive exercise in [RECOVERY.md](RECOVERY.md). The selected source-bound SCP-08 lane is [run_issuer.py](../../examples/postgresql-pending-store/run_issuer.py).

These local scripted-authority fixtures do not establish approved UTC/source accuracy, live witness ownership, Linux device/filesystem durability, worker elapsed/rate assumptions, real old-writer quarantine, retained legacy migration or a combined-family profile. Cross-host/HA, physical/PITR recovery, deployment activation, browser/independent-client and release assurance remain open. Historical evidence retains its original source and scope.
