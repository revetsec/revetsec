# PostgreSQL issuer storage with Pyranid

An **unpublished application fixture** implementing `OAuthAuthorizationServerStore` with [Pyranid](https://www.pyranid.com)4.7.0 and PostgreSQL18.4. These dependencies belong to this standalone module. Revetsec's library artifact and runtime dependencies are unchanged. Nothing in this module is installed or deployed by its build, or included in the library reactor.

This is a starting point for application storage integration and a reusable contract exercise. Applications still own database access, capacity, credentials, TLS, pools, keys, migrations, operating procedures and recovery. It is not a shipped database backend.

## What Pyranid does

`PostgresStore` uses `Database.transaction(READ_COMMITTED, ...)` and public `useRawConnection(...)` for the exact opaque SQL transport. Pyranid owns acquisition, transaction lifecycle, rollback and connection cleanup. Its public post-transaction `TransactionResult` is mapped as follows:

| Outcome | Store behavior |
|---|---|
| COMMITTED after all predicates/writes | Return COMMITTED, then permit the engine to release its response. |
| Predicate mismatch with successful rollback | Return CONFLICT; zero effects. |
| IN_DOUBT | Return UNKNOWN; no retry or success response. |
| Other failure | Throw a fixed, redacted infrastructure error; never return absence. |

The fixture uses no `transactionWithRetry`. A cleanup error following known COMMITTED still has that known result. No signing, grant-policy, client, HTTP, observer or other application security callback runs inside a SQL transaction. The `Probe` interruption points exist only for this harness's SQL fault/crash tests.

## Atomic storage boundary

Every read and complete commit first locks the one permanent `issuer_mutex` row. After that lock, READ COMMITTED queries see current primary state; all fixture writers use that same lock. ABSENT and exact opaque versions are checked together, before any mutation. Zero-mutation read-set barriers use the same transaction. Capacity failure rolls back instead of evicting anything. Retention seconds/nanos preserve the whole Instant, including permanent sentinel values, without squeezing them into a SQL timestamp. No TTL cleanup or cache is provided.

This deliberately simple global lock serializes all namespaces. It is a correctness fixture, not a throughput design. A production implementation can use namespace locks with equivalent absence/read-set guarantees and provision its own bounded pool. Connect, driver network, statement and mutex waits share a cooperative operation deadline; connection setup rounds the driver's connect timeout up to whole seconds. No library can forcibly interrupt arbitrary application code.

The tested boundary is **one authoritative PostgreSQL primary, a persisted Docker volume, and independent JVM callers on one host**. `fsync`, `full_page_writes`, and synchronous COMMIT are required and checked. With `--recovery`, the fixture also exercises authentic logical backup restoration and an application-owned recovery gate; see [RECOVERY.md](RECOVERY.md). There is no replica, failover, cross-host, physical/PITR or storage-device power-loss qualification. Operator SQL, migrations and maintenance must participate in the same locking/fencing contract. Never reopen an authentic restored snapshot merely because sealed records validate; restore needs a separate administrative fence and key lifecycle procedure.

## Run

Build the core into a private Maven repository, then build this standalone module with `mvn -f verification/issuer-store/pom.xml package`. Use Java17 or newer. For an offline run, pre-cache the pinned image and artifact versions; the runner always uses `--pull=never`.

```sh
python3 verification/issuer-store/run.py \
  --java-home /absolute/path/to/jdk \
  --core-jar /absolute/path/to/revetsec-1.0.0-SNAPSHOT.jar \
  --fixture-jar /absolute/path/to/issuer-store-1.0.0-SNAPSHOT.jar \
  --pyranid-jar /absolute/path/to/pyranid-4.7.0.jar \
  --driver-jar /absolute/path/to/postgresql-42.7.13.jar \
  --output /absolute/path/to/new/evidence-directory
```

The runner requires Docker access and loopback sockets. It creates uniquely named owned network/container/volume resources and kills **only those resources and its own caller processes**. The PostgreSQL container publishes a password-protected random fixed loopback port. It never downloads images or calls an external service. Test credentials, keys and tokens live in a temporary private directory, are omitted from evidence, and are deleted on completion. Interrupting the runner forcibly may require cleanup of its uniquely named `revetsec-store-*` resources.

Checks cover complete rollback, exact predicates and retention, condition-only barriers, capacity refusal, separate-JVM code and refresh races, full-family invalidation, actual PostgreSQL connection loss before/after writing COMMIT, caller/database SIGKILL before/after durable acknowledgement, established restart with retained keys, backward clock rejection, an already-built engine observing another engine's issuer fence, and missing permanent fences. The optional `--recovery` checks additionally cover authentic rollback of revocation, administrative issuer fencing before admission, UNKNOWN/crash reconciliation under exclusive management ownership, old-generation isolation, nanosecond high-water and sealing-key migration of permanent records. JSON and JUnit XML retain structural outcomes, source/artifact hashes and boundary limitations. Database/driver diagnostics, SQL, rows and credential responses are not archived.

`StoreContract` and `RecordingStore` exercise only public engine-generated transactions. To qualify another backend, supply an application implementation to the recording wrapper, construct `IssuerFixture` with it, and supply backend-specific partial-write failure controls to `StoreContract.run`. Adapt the process orchestration to the actual backend and its deployment contract too. Passing the in-process checks alone does not prove durability or multi-node behavior.

## Design references

The lock/snapshot reasoning follows PostgreSQL18 [READ COMMITTED](https://www.postgresql.org/docs/18/transaction-iso.html#XACT-READ-COMMITTED) and [row locking](https://www.postgresql.org/docs/18/explicit-locking.html#LOCKING-ROWS). The commit boundary follows its [WAL settings](https://www.postgresql.org/docs/18/runtime-config-wal.html). Pyranid4.7.0's public transaction APIs are used without changes to Pyranid. The runner pins its published JAR SHA256 and the cached driver/image identities.
