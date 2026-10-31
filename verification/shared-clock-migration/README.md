# Closed shared-clock migration and restore fixture

This unpublished administrative fixture converts retained TOTP, WebAuthn and issuer records while ordinary admission is closed. It uses the restricted legacy transformers from the selected core artifact. It adds no library migration API, background migration, normal read promotion or automatic recovery path.

Use only an explicitly owned disposable PostgreSQL fixture. The runner creates its own database resources and removes them after the checks. It never supplies a procedure or authority for changing another deployment. Its scripted UTC capture tests control behavior; it does not establish approved source accuracy, platform durability, worker continuity or a qualified shared deployment.

## Closed procedure

The external journal is outside authentication backups, under a protected directory with a live exclusive owner. It pins the migration identity, source recovery generation, target admission, formats, old-writer fence, roots, complete inventory, key/capacity policy, exact prepared batches and eventual activation commitment. Missing or substituted external state closes the procedure; an authentication row or restored in-database marker cannot recreate it.

| Phase | Required work |
|---|---|
| `CLOSED` | Stop/drain owned writers, disable ordinary cleanup and establish actual SQL role/session exclusion. Persist the external intent before changing authentication rows. |
| `INVENTORIED` | Enumerate the complete declared native scope through bounded administrative pages; authenticate every retained row and required root. Include old epochs, consumed state, charges, revoked ownership and permanent fences. |
| `PREPARED` | Pin target admission and exact floors/minima. Prepare new versions and ciphertext, authenticate the target through the current decoder, compare complete semantic commitments and check keys, row limits and all assigned capacity buckets. |
| `REWRITING` | Apply at most eight replacements with at most sixteen exact row predicates per atomic batch, under the current closed intent and writer/recovery fence. Keep ordinary traffic closed between batches. |
| `VERIFIED` | Reinventory the entire target; reject leftovers, unlisted rows, mismatched semantics, unresolved outcomes or inconsistent quotas. Persist the target activation commitment externally. |
| `ACTIVE` | Recheck the external generation, writer fence, target commitment and deployment capabilities before structural activation. Current timed admission has its own health/floor requirements. |

Phases are monotone for one intent. After any target-format write, old writers cannot resume. A restore requires explicit closed recovery with fresh external admission; it cannot reverse the migration or authorize a fresh namespace. Restarting a process does not turn an incomplete rewrite into a completed one.

## Fit and outcome rules

Every row has an explicit private fit disposition: `FIT`, `WAIT_RETENTION`, `BLOCKED_DEPENDENCY`, `CORRUPT` or `UNSUPPORTED`. Missing keys or incomplete authority/inventory evidence are dependencies. Authenticated malformed state is corrupt. Permanent or hard-cap non-fit stays unsupported. No condition permits truncating state, refunding charges, dropping tombstones, extending lifetime, lowering floors or increasing a cap automatically.

`WAIT_RETENTION` leaves durable closed intent without retaining a long SQL transaction. Only a fresh privileged administrative observation from the same reserved witness projection and current closed migration intent can authorize cleanup at authenticated **full retention**. Credential expiry, worker time and database wall time cannot authorize it. Permanent state is never eligible. Cleanup is bounded, exact and atomic, with the same uncertain-outcome rules, followed by complete reinventory and capacity reconciliation.

Before dispatch, persist the exact old/new versions and ciphertext commitments for the whole batch. `UNKNOWN` never advances progress or generates fresh replacement bytes. Under current exclusive control, definitively settle the backend transaction, then compare every affected row: all exact new state establishes commitment; all exact old state plus definitive transaction settlement permits the same prepared batch to be resubmitted. Unsettled, mixed, missing or third-state data stays closed. A matching plaintext, one representative row or later clock sample cannot settle a batch.

The codec lane authenticates retained expired legacy envelopes only through the restricted migration path and preserves their original expiry. Normal decoders still reject legacy formats and do not acquire an expiry bypass. All old opening keys remain required until complete transformation, independent verification, activation and the declared backup/restore key policy permit retirement. Ordinary runtime key-count limits remain unchanged.

## Evidence boundary

The codec helpers run against one exact selected core JAR. Three old codec producers run separately against the source-bound frozen artifact. A frozen old WebAuthn adapter writer holds actual direct/pooled SQL sessions across quarantine. Native checks use the actual family authentication tables, real transactions, uncertain acknowledgements and authentic authentication-data backup/restore while the external journal remains current. Results contain fixed assertions, counts, artifact/source identities and cleanup facts. Protected temporary row/key/prepared-plan/backup files are not routine evidence exports.

The native administrative profile is bounded to 128 retained rows and 6 MiB of SQL sealed-form bytes, with native pages of at most 32 rows. These are explicit fixture limits. Exceeding administrative inventory capability blocks completion; it is not proof that the data exceeds a library hard limit. The target records are authenticated by the current family decoders. Normal deployment traffic remains closed pending the complete admitted witness/backend profile.

## Legacy schema and current-adapter join

`run_adapter_join.py` extends the structural rehearsal from the actual frozen legacy schemas. Its initial WebAuthn table has only `expires_at`, without target expiry or size columns. The old adapter rounds finite retention upward to a database microsecond. The closed inspector authenticates the original envelope and obtains its exact seconds/nanoseconds, complete opening-key inventory and semantic commitment without creating replacement bytes. The raw source timestamp remains part of the exact source predicate; it cannot supply expiry authority. Expired retained records remain part of the inventory.

The protected schema journal binds the full source catalog, rows, roots, epochs, capacity identities and sequence configuration. Before the first authentication rewrite, a rollback-only target-schema preflight checks the fixed prepared target against current constraints, capacity and version headroom. Staging, backfill and final installation settle uncertain outcomes against the complete expected state. Final installation applies the current namespace/admission metadata, root and epoch registries, exact retention and size fields, constraints, 256-bucket reservations and sequence continuation in place. It preserves established identities and caps; no reset or cap increase repairs a failed fit.

Current adapters stay closed while either the migration or schema intent is pending or inconsistent. After both are durably settled, the disposable runner exercises the actual current TOTP, WebAuthn and issuer adapters and public maintenance/query operations against the migrated rows. Each admission checks the protected intents, current SQL metadata, recovery ownership and a fresh witness observation. A drain barrier covers operations already holding a recovery permit before restore. Scripted advancing source and worker channels support these functional checks; they do not qualify real UTC capture, worker continuity or platform durability.

The migration component can be exercised before the real admitted witness and complete shared backend/profile certificates exist. That component result does not close the qualified migration/restore gate, establish a real-data fit report, activate a deployment or grant release approval. See the [store/consumer contract](../../docs/shared-clock-stores.md), [witness fixture](../shared-clock/README.md) and [PostgreSQL primitives](../shared-clock-postgresql/README.md).

## Run the selected local fixture

From the core checkout, with the source-bound frozen old inputs and selected core artifact retained in the sibling private planning records:

```sh
python3 verification/shared-clock-migration/run_postgres.py \
  --output /absolute/fresh-owned-output \
  --java-home /absolute/jdk17-or21-home
```

The runner verifies its pinned cached PostgreSQL image and artifacts, uses no image pull or external service request, and creates unique owned database resources. Repeat with the other supported JDK and a separate fresh output directory. Its result records the actual assertions, exact inputs and cleanup outcomes. The local frozen-input layout and hashes are deliberate; this fixture is not an arbitrary-target migration command.

Run the legacy schema/backfill and current-adapter join with its own fresh output directory:

```sh
python3 verification/shared-clock-migration/run_adapter_join.py \
  --output /absolute/fresh-owned-adapter-output \
  --java-home /absolute/jdk17-or21-home
```

Both runners own and remove their disposable PostgreSQL resources and protected temporary runtime files. The earlier structural result and the adapter-join result have separate evidence boundaries; neither grants deployment migration or release approval.
