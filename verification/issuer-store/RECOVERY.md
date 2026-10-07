# Established issuer recovery

This module exercises real PostgreSQL18 custom logical archives with `pg_dump -Fc` and atomic `pg_restore --single-transaction --exit-on-error`. It restores authentic encrypted rows, exact opaque versions and retention values into its owned database. Signing and sealing keys remain in the application's private directory outside the database snapshot. Add `--recovery` to the runner command in [README.md](README.md) to include these checks.

## Why the application must coordinate recovery

An authentic old snapshot can contain a previously revoked grant and the permanent fences from before revocation. Encryption authenticates those bytes; it cannot establish that the snapshot is the latest state. `warmUp()` cannot establish that either. The exercise deliberately bypasses a closed application gate to demonstrate that a revoked token is active again immediately after restore. This bypass is a trusted diagnostic fixture command, never a request route.

`revokeAllGrants()` advances the permanent issuer epoch using an authentic conditional store transaction. After restoring a complete consistent ledger, it invalidates retained interactions, unused codes, grants, refresh families and online token status. Credentials created after the snapshot have no restored authoritative records. New authorization can start after recovery. An established namespace must not be repaired with `initializeFreshIssuer()` or replacement keys: that operation requires an operator assertion that the namespace has never been used or restored.

## Operator sequence

1. Close every issuer and resource route, stop background mutation, drain in-flight work, and isolate old deployment writers. Fence or terminate old nodes before changing the store. Verify this across all serving nodes.
2. Persist a recovery intent and new deployment generation in a trusted control plane outside the restored database. Keep admission CLOSED. Record the authoritative permanent issuer version before the fence attempt; protect this intent from rollback too.
3. Restore a complete consistent authoritative store and its required key material. Check storage, namespace, key publication/lifecycle, clock and connectivity. Retain the established issuer string, signing keys and decrypt keys for all retained records, including permanent fences.
4. With traffic still drained and writers isolated, call the genuine public `revokeAllGrants()` once. Known success permits the remaining recovery checks. UNKNOWN is not permission to reopen or automatically retry this non-idempotent operation.
5. Reconcile uncertainty against the authoritative primary and the external intent under exclusive management ownership. Only a definitive outcome permits continuation. If rollback is definitively established, an operator may authorize a new fence attempt. If commit is established, do not repeat it. Ambiguous or unavailable state keeps admission CLOSED.
6. Verify the fence, required keys and online validation, then publish LIVE for the new generation. Old generations remain isolated. Begin new authorization; all restored outstanding credentials stay invalid. Offline JWT consumers have a stale acceptance window and require their own recovery/traffic procedure.

The fixture's UNKNOWN reconciliation compares an opaque issuer version before and after an isolated management operation, together with actual primary state. No other management writer runs. In a production deployment, competing writers, lossy failover or external-intent rollback invalidate that inference; the application must provide an authoritative outcome/receipt protocol or keep traffic closed. No engine/provider retry is added.

## Demonstrated local gate

`DeploymentGate` accepts only an exact bounded `LIVE <expected generation>` file; absent, malformed, symlink and wrong generation values fail closed. The trusted coordinator writes it by file fsync, atomic replace and directory fsync. Both this gate and the recovery intent are outside the SQL archive. A fresh JVM must supply its expected generation. An already-built old-generation engine is rejected after recovery; uncertain/crashed coordinators leave CLOSED state for a fresh JVM.

This file is a **one-host admission demonstration**. Its before/after request checks cannot atomically drain requests, stop a response already being released, fence database writers or coordinate multiple hosts. The fixture pauses old callers before route/store admission and completes all other callers before restoration. Production must supply routing isolation, an authoritative distributed control plane and a drain/lease mechanism appropriate to its deployment. Revetsec retains the protocol/fence logic; the application owns this operational boundary.

## Clocks and sealing keys

A fresh node behind the durable nanosecond high-water fails unavailable without mutation; forward revocation advances that high-water. Unrepresentable operation times at the permanent sentinel reject before commit. Loss of a sealing key and premature retirement of an old decrypt key fail corrupt rather than recreating permanent state.

For rotation, first deploy overlapping decrypt key rings everywhere. Select the new active key while retaining the old verification/decrypt key. Use public `resealStoreEntry(key)` authenticated CAS maintenance for **every retained record**, including permanent issuer and subject fences. Preserve key/kind/retention; reconcile conflicts or UNKNOWN authoritatively. Retire the old decrypt key only after complete migration and writer/key rollout verification. All still-required archived snapshots need their corresponding keys and the same fenced restore procedure. An old-only node cannot read the migrated permanent state. Resealing does not mint authority or revoke grants.

## Evidence boundary

Real logical restoration, retained keys, multiple independent JVMs and one durable authoritative primary on one host are covered. Physical/PITR backups, roles/global objects, cross-host control planes, HA/failover, device power loss, HSM reconstruction and independent browser/client assurance remain separate work. Snapshot/key/credential/SQL/row bytes stay in owned ephemeral resources and are destroyed; evidence contains only structural checks and source/artifact hashes.

The tooling follows PostgreSQL18 [pg_dump](https://www.postgresql.org/docs/18/app-pgdump.html), [pg_restore](https://www.postgresql.org/docs/18/app-pgrestore.html) and [SQL dump backup](https://www.postgresql.org/docs/18/backup-dump.html) documentation. This small owned logical archive exercise does not choose a production backup strategy for an application.
