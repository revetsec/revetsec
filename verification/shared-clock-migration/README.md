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

The issuer target cap, declared legacy cap and sealer cap must each be integers within `1024..16384` before narrowing to Java `int` or producing decisions. An explicit target-record cap adjustment is allowed only within that range, before `PREPARED`, followed by fresh complete codec preflight and quota preparation. Changing configuration does not make an earlier refusal report usable. This does not raise an established namespace entry/byte cap during schema installation. A finite record that exceeds the selected target budget but fits the hard maximum can receive `WAIT_RETENTION`; a target above the hard maximum receives `UNSUPPORTED`, with no cleanup permission from that report. An authorized later retention/format resolution remains separate.

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
  --java-home /absolute/jdk17-or21-home \
  --repository /absolute/offline-maven-repository
```

Both runners own and remove their disposable PostgreSQL resources and protected temporary runtime files. The earlier structural result and the adapter-join result have separate evidence boundaries; neither grants deployment migration or release approval.

For current-source MIG-06 qualification, pass an explicit existing `--core-jar` and its exact `--core-sha256`, plus `--repository` for the existing offline annotation dependencies. Omitting these options retains the hash-checked canonical API-BIND29/Performance42 artifact pin that supports the live probe; there is no automatic selection of a cached replacement. Add `--capacity-preflight` to `run_postgres.py` for the five current-codec/controller capacity cases against real native tables. They check refusal before writes, repeated preflight after a permitted `16383 → 16384` record-cap adjustment, hard-limit refusal and TOTP quotas based on reserved K64 bytes rather than current short-key output.

Add `--rotation-key-id-length 64` to `run_adapter_join.py` to exercise the current public maintenance operations with the longest supported runtime key ID. The TOTP reseal checks actual SQL size, unchanged reservation and bucket usage/limit, and exact use of the previously reserved bytes. Source checks in `test_capacity_preflight.py` also cover invalid and wrapping capacity values, exact fit and all-family short/long-key semantic preservation. The fixture's `ACTIVE` phase still leaves normal timed admission separately closed; these are disposable component receipts, not approved UTC/witness/platform or release certificates.

## Closed-inventory completeness (MIG-07)

The administrative controller rejects duplicate physical addresses even when their transport handles differ, handle aliases for distinct addresses, and families outside the pinned intent. The complete codec join also binds every row to its declared family scope and requires one exact, ordered source result per input. Duplicate roots cannot select an arbitrary first match. Missing or corrupt roots, unavailable opening keys and invalid authenticated old payloads cannot produce a usable complete preparation.

Both native collectors compare each family's enumerated row count with an independent count taken before materialization. Their SQL pages contain at most 32 rows in explicit `C` key order, with strictly advancing unique keys; root declarations must cover every selected family. The 128-row/6-MiB administrative bounds remain in place. The controller still requests pages of at most 16 rows, and normal store SPI limits are unchanged. Exceeding the administrative profile blocks completion.

`INVENTORIED` pins the closed physical catalogue; it does not grant authentication, cleanup, initialization or ordinary read/promotion authority. The subsequent complete restricted-codec report must authenticate every retained row and dependency before `PREPARED`. A refusal leaves protected preparation state, native authentication data, quotas and transaction dispatch unchanged.

Add `--inventory-preflight` to `run_postgres.py` for the owned native root, address, opening-key, omission and administrative-bound controls, including a genuine 64-row frozen-old fixture with 47 issuer rows crossing both page sizes. Add the same flag to `run_adapter_join.py` for omitted/duplicated legacy-schema pages in all three families and incomplete root declarations before schema preparation. Both retain their existing writer-exclusion, outcome, restore and cleanup controls. `test_inventory_preflight.py` supplies the current-source regressions and codec controls; full deployment C qualification remains separate.

## Crash/restart boundaries (MIG-08)

An owner with a lost journal-file acknowledgement keeps ordinary reads closed. Explicit `reconcile_persistence` uses a private, exact-file, journal-instance and thread-bound read context to inspect native state without acknowledging the file first. That context cannot apply mutations, install quotas, activate or invalidate restore. Source inventory is checked in full; prepared batches use whole-set definitive evidence. A pending activation may be definitively old or new without advancing its phase during file acknowledgement; an `ACTIVE` file requires the complete committed target. Cleanup reconciliation preserves the exact remaining permanent set and still requires separate reinventory.

Schema plans saved as `SOURCE_PREPARED` or `CURRENT_PREPARED` can resume their exact persisted statements. Current-schema resumption requires the original preflight configuration and does not generate another target. Schema reconciliation observes the entire native outcome before acknowledging an uncertain file; a failed native check keeps normal reads and runtime admission closed. Discovering a phase after process restart supplies neither healthy time nor permission for partially migrated serving traffic.

Add `--crash-restart` to `run_postgres.py` for fresh-process recoveries at metadata and native dispatch/commit boundaries, a process-group kill of an actual worker/JVM blocked in PostgreSQL, and same-owner lost-acknowledgement reconciliation. The runner checks the end of the native transaction, exact plans, authentic all-family records, quota state and old-role exclusion. Add the same flag to `run_adapter_join.py` for lost acknowledgements in all six schema phases, followed by exact native settlement and the existing current-adapter controls.

`test_crash_restart.py` supplies the focused regressions. `test_process_crash.py` adds 390 actual child-process deaths and fresh-owner restarts over six file/acknowledgement boundaries, every bounded model batch, definitive no-effect, activation, restore invalidation, cleanup and schema phases. These file-only probes use a scripted data model; the cleanup model starts with an already authorized finite batch. They do not provide SQL atomicity, cleanup-time authority or filesystem/device power-loss qualification. Real witness/full-retention controls and disposable PostgreSQL evidence remain separate. Normal store APIs, caps and ordinary read/write paths are unchanged.

## Whole-batch UNKNOWN reconciliation (MIG-09)

A saved rewrite batch must match the exact pinned preparation slice, batch identity and mutation count. Explicit retry after definitive `NO_EFFECT` reuses those bytes. Cleanup remains bound to the pinned finite inventory and requires its own fresh authority observation. Duplicate native addresses and aliased handles are invalid predicates. Neither a later budget/SQL clock read nor authentic alternate ciphertext with equal semantics is a transaction receipt.

A native observation covers every ordered predicate under the closed control-row barrier and checks that the original transaction has ended. A present row with a conflicting SQL kind is a third state, including during deletion reconciliation; it cannot be filtered into apparent absence. Size, TOTP epoch/reservation and WebAuthn expiry projections must agree with the exact expected physical state. An unresolved transaction takes precedence over row classification.

The legacy-schema observer recognizes old bytes only when address, handle, version, ciphertext and physical timestamp match the protected original projection. For that exact old WebAuthn row, finite retention comes from the authenticated pinned envelope rather than nullable staged target columns or database time. Target rows must carry truthful target size and exact retention. Old TOTP reservation staging and unchanged legacy timestamps are checked separately.

Add `--unknown-reconciliation` to `run_postgres.py` for each family's all-old, all-new, mixed, missing, third, authentic alternate-ciphertext and reordered-observation cases, plus an actually in-flight advisory-lock-blocked transaction. It also tests a present conflicting-kind row after uncertain cleanup. Add the same flag to `run_adapter_join.py` for precommit and postcommit response loss in each of its four bounded batches, proving exact retry and settlement through old schema projections and opening the complete current target in a separate verification pass. Both runners retain their normal native, writer-fence, schema, restore and resource-cleanup checks. `test_unknown_reconciliation.py` supplies the bounded predicate/guard/deletion matrix and controller regressions. These are closed administrative component checks; approved UTC, witness ownership, host durability and full profile qualification remain open.

## Restore, old writers and clock identity (MIG-10)

The native restore close requires an already durable external invalidation and its exact saved fresh recovery generation. It cannot substitute another generation or dispatch ahead of that invalidation. Closed SQL admission binds both target authority and recovery identifiers. Transaction predicates recheck retired roles, login/superuser/bypass flags, membership, live sessions, and effective table and column privileges together with the native control row. The fixture still requires exclusive owned administration and an external drain barrier; SQL role/catalog checks do not establish custody against concurrent deployment administrators.

Add `--restore-fencing` to `run_postgres.py` for authentic old rows and in-snapshot control-marker restores at prepared, partial rewrite, verified and active boundaries. New owners and old direct/pooled binaries remain closed. Isolated role-login, column-grant and membership plants test prebuilt SQL transaction predicates before any data change. A reserved scripted witness rotates its clock generation while keeping authority/recovery admission: exact all-family native bytes, versions, addresses, metadata, quotas and semantic facts authenticated by a separate observer remain unchanged. This is an identity invariant, not a serving-profile clock-rotation procedure or trusted-time qualification.

Add the same flag to `run_adapter_join.py` to capture actual legacy authentication snapshots before staging/target writes, including the original six-column WebAuthn table and SQL marker. Restore one before activation and another after current-schema/public runtime operations. External invalidation and current services refuse both; old direct/pooled binary login remains fenced. A column-grant plant closes runtime admission. Protected snapshots stay container-private and are removed with owned resources. `test_restore_fencing.py` and `test_clock_generation_identity.py` supply the focused controller/native and genuine current-codec controls. Full C still requires the approved UTC/witness/worker/durability/profile join.

## Exact floors and restart catchup (MIG-11)

A successful fit report must include its exact floor and match the authenticated carrier retention. Once PREPARED, the protected journal pins the complete inventory, root, quota/capacity/key and decision commitments/count through rewriting, verification, activation and restore invalidation. A CAS cannot replace that preparation to lower a floor or select another source/epoch. The existing independent key commitment check still rejects raw protected-file substitution. This adds no journal fields or normal decoder acceptance.

`test_floor_catchup.py` exercises report/pin regressions and genuine frozen-old signed/common-boundary minima, distinct future entity floors, and dirty TOTP account/root history. The old TOTP grammar remains unchanged: negative/out-of-common-range or invalid subsidiary timestamps refuse conversion with original bytes intact. WebAuthn and issuer signed minima can be transformed exactly while timed admission remains closed. No maximum with current time can erase an incompatible old floor. Additional current-core temporal engine cases check immutable L and relevant F separately at the largest lower bound minus/equal/plus one nanosecond, without query writes.

Add `--floor-catchup` to `run_postgres.py` for all-family native closed transformations with negative/upper/future WA/issuer minima (valid independent TOTP history), genuine future ceremony/access floors, and a dirty TOTP history refusing before preparation. Complete current-codec verification preserves every source floor, retention and semantic commitment. A reserved scripted witness observes expiry without any auth row or root write; after a new owner/boot/generation, an earlier checked capture and a center equal to the durable prior ceiling cannot publish healthy time. Catchup of the entire error interval keeps all three families beyond the observed expiry while exact native data, floors, roots, epochs and quota state remain unchanged. This is component evidence, not real UTC/platform/worker continuity or serving-profile qualification. The existing legacy-schema/current-adapter rehearsal remains a separate current-source join.

## Expired envelopes and retained cleanup (MIG-12)

Authenticated reports bind kind to a recognized native address and permanence to exact carrier retention. Cleanup admits only the five finite issuer authorization kinds. Its existing batch identity commits the complete authenticated WAIT_RETENTION report and migration ID; that exact object is now persisted as a content-addressed plan and verified on settlement/retry. Pending cleanup metadata cannot repoint its batch/count. This adds no journal fields or changed batch-ID algorithm.

An earlier pending cleanup intent without the bound report remains closed. Explicit private `bind_cleanup_plan(original_decisions, deadline)` can persist only the exact original report whose commitment reproduces the saved batch, after current closed-control checks. It dispatches nothing, supplies no time and acknowledges no outcome. Whole-batch settlement and a fresh privileged administrative observation remain separate. No scan, report regeneration, blind retry or automatic legacy promotion supplies authority. Process models now save this complete preauthorized plan; they still do not establish witness time.

Add `--retention-maintenance` to `run_postgres.py` for raw DB-time pause controls, unhealthy source/boot and invalidated migration, all-family permanent-state cleanup refusal, old-intent exact-report binding across real pre/postcommit loss, complete reinventory/capacity reconciliation and non-eviction under a refused capacity plan. Only full authenticated retention can delete the selected finite nonfit row; permanent facts stay exact.

Add the same flag to `run_adapter_join.py` to seed one genuine frozen-old USED issuer code whose credential expires before admitted authority time while its outer retention remains future. Actual public maintenance reseals it; independent current decoding preserves the complete payload, floor and original retention. Restricted before/after audits run only behind the exclusive drain barrier with the runtime authority channel closed, the SQL writer role disabled and its sessions drained. Closing authority while advancing the raw worker by 100 years denies services and leaves all retained data intact. Core tests separately cover real spent-credential rejection, retained maintenance before/equal/after full retention, unhealthy/fast/broken-clock refusal, and old/new encrypted expiry boundaries for issuer/WA contexts and all retained status vectors. Ordinary decoders and ceremony reseal scope are unchanged; no expiry grace or new credential admission follows from migration or maintenance. All database operations remain disposable components; real UTC/witness/worker/durability/profile qualification remains open.

## SC-BOUND-04 current-adapter contention component

Add `--capacity-contention` to `run_adapter_join.py` to execute the TOTP,
WebAuthn and issuer engines through the current public adapters in separate JVMs.
The component holds unrelated entity, bucket and namespace locks, observes actual
PostgreSQL waiting, and requires unrelated work to commit before release. It also
exercises reverse-order multi-lock acquisition and emits the SQL trace used to
check the signed advisory-lock ordering. The result records the exact
`scBound04Assertions` and `crossJvmAdapterSqlTraces` counts and keeps all 256
capacity counters tied to the authenticated retained inventory.

This closes only the disposable current-adapter component that was absent from
the earlier source-boundary record. Its witness and time are scripted, and the
fixture supplies neither a latency SLO nor an approved deployment, durability,
worker-continuity or restore profile. The runner therefore keeps `qualified`
false; this component must not be reported as a lane-B, full lane-C or whole
`SC-BOUND-04` pass.

## CAP-10 isolated adapter atomicity

`run_atomicity.py` compiles the three current reference adapters and their private
helpers with `--release 17 -proc:none -Xlint:all -Werror`, using a caller-selected
core JAR with an explicit SHA-256 and the preserved pinned dependencies. Run with
`--output <new-private-directory> --java-home <jdk-home> --core-jar <jar>
--core-sha256 <sha256>`. Docker must already have the exact pinned image cached.
The runner owns a new loopback-published container, network and volume; it removes
them and the protected credential directory even after assertion failure.

Its 31 native SPI scenarios use isolated schemas, scripted observations and
structural opaque values. They exercise mixed multi-key writes, merged bucket
cancellation at actual assigned capacity, positive/zero/negative net deltas,
entry/byte refusal, rollback after actual first data/quota DML, a physically
committed transaction with a lost acknowledgement, abrupt worker death before
commit and after commit before receipt, and a final abrupt primary restart.
A separate Python inventory oracle checks exact data, versions, expiry/retention,
metadata and all 256 quota rows per scenario. TOTP SQL Base64 wraps the ASCII core
wire; the oracle checks both layers and computes K64 reservation with separate Python arithmetic.
TOTP has no delete operation: negative deltas are byte-shrinking replacements.
WebAuthn deletes only ceremonies and issuer deletes only interactions. Sequence
allocation itself may advance on rollback; it is outside the data/quota atom.

The worker's JDBC wrappers inject faults only after delegated SQL or COMMIT;
worker crashes use `Runtime.halt`, and primary restart kills only the owned
container. No successful outcome is inferred from a receipt alone. These are SPI
mechanics, not authenticated engine flows, production role/RLS qualification,
serving activation, migration/restore authority, trusted UTC or device-durability
qualification. The test role has no schema/role/cluster administration; fixture
setup grants table privileges without claiming the full application privilege
profile. `--adapter-sources` and `--family` support isolated defect calibration;
a calibration failure receives no successful case credit.
