# Sealing-key inventory, rotation and recovery

A `StateSealer` key protects every typed value sealed with that key. Browser cookies are only part of the inventory: durable TOTP, WebAuthn and OAuth issuer records can outlive every browser session. This procedure concerns sealing keys; [issuer JWT signing-key publication](oauth-server-key-lifecycle.md) is a separate lifecycle.

## Inventory before promotion

Maintain an application-owned, bounded administrative inventory of exact storage addresses, namespaces/RP IDs/recovery epochs, versions, record kinds, sealing key IDs, authenticated retention, reservation sizes and migration/recovery admission identities. Include retained historical epochs, tombstones and backups that may be restored. Public credential listing is not a complete store inventory. Key IDs, address digests and counts are not authentication of a record; verify the complete contextual envelope through the owning engine/closed maintenance machinery.

| Family | Required durable inventory |
| --- | --- |
| TOTP | Permanent `NAMESPACE_STATE` and every `ACCOUNT_STATE`, including factors, recovery generations/consumption, used steps, pending enrollment and rate charges inside account records. |
| WebAuthn | Permanent `NAMESPACE_CLOCK`, `ACCOUNT_FENCE`, `ACCOUNT_CREDENTIAL_INDEX` and `CREDENTIAL`, including disabled fences, empty indexes and revoked-credential ownership tombstones. Also account for finite `CEREMONY` records through their full retention; privileged raw reseal refuses ceremonies. |
| OAuth issuer | Permanent `ISSUER_STATE` and `SUBJECT_STATE`; retained `INTERACTION`, `CODE`, `GRANT`, `ACCESS_TOKEN` and `REFRESH_TOKEN` rows, including consumed/revoked/reuse evidence after credential expiry. |
| Application/protocol storage | Application values, pending cookies, persisted references/hints, metadata caches and any other configured sealed forms. Apply each format's original purpose, context, size and retention rules. |

Do not use credential expiry, an empty active-credential list, SQL row counts or the absence of recent traffic as proof that an opening key is unused. Permanent records never age out solely because a rotation is old. Retention timestamps are not permission to delete permanent kinds.

## Stage, reseal, verify, retire

1. Create a fresh application-owned key and unique ID. Deploy it as an opening/verification key to every reader before any writer promotes it. Preserve the old opening keys and their exact IDs. A sealer holds one active key and at most 16 verification keys; plan overlapping rotations within that limit.
2. Promote the new active key across writers. Fence or drain old writers that can still emit the old key. Capacity preflight must include the complete retained inventory, framing, SQL encoding and reserved key-ID growth; promotion is not a capacity waiver.
3. Reseal the authoritative inventory with the owning timed operation: `TotpAuthenticator.resealStoreEntryResult`, `WebAuthnRelyingParty.resealStoreEntry` or `OAuthAuthorizationServer.resealStoreEntry`. Preserve the original payload, authority/recovery binding, exact floor, credential expiry, full retention, permanent fences and all replay/charge facts. A reseal changes encryption and version, not identity, authorization or lifetime. Do not replace a permanent row with absence to make it fit.
4. Settle every conditional conflict and uncertain outcome through fresh authorized inventory under the recovery contract. `Indeterminate`/`UNKNOWN` is not permission to retry a credential operation. Known `COMMITTED` remains factual even if normal output was withheld; `ReconciliationRequired` creates no new proof. The raw WebAuthn/issuer receipts are effect acknowledgements, not traffic-readiness approval. No failed, missing or unreadable row counts as successfully migrated.
5. Perform complete new inventory and verification after writers are fenced or their output is proven to use the new key. Verify current versions, authenticated key/context/kind, semantic facts, floors/retention and capacity accounting. Include tombstones and historical scopes. Expiring forms may be allowed to reach their original full retention, with admitted cleanup where supported; never invent an extended lifetime by reissuing pending state.
6. Retire an old opening key only after that complete evidence shows no retained value or authorized restore can depend on it, and no old writer/in-flight operation can reintroduce it. Keep it in separately controlled recovery custody if an authorized backup still needs it, without re-enabling unsafe serving acceptance. A partial scan or elapsed browser-cookie lifetime is insufficient.

The library supplies neither an inventory scanner nor a distributed key-retirement controller. The [store contract](shared-clock-stores.md), [closed migration/restore fixture](../verification/shared-clock-migration/README.md) and application recovery gate define the component boundaries. Actual deployment time, writer fencing, durability and restore qualification remain application obligations.

## Compromise and old backups

If a sealing key may have been disclosed, its holder may decrypt and forge affected records of every type. Close affected serving/recovery admission and fence writers before reconciling the incident. Remove the compromised key from serving acceptance and use fresh trusted key material. Do not keep accepting it to obtain a convenient overlap, and do not treat a newly sealed copy of attacker-forgeable old content as restored trust.

Removing an opening key can strand permanent data, not just interrupt a login. If no copy/key trusted through a separate custody path remains, TOTP seeds, recovery state or other encrypted records may be unrecoverable. Re-enrollment, credential/session revocation and account recovery require independent current application authority; the compromised record or an earlier proof cannot authorize its own replacement. Preserve ownership/disable/replay fences and recovery-generation rules. Keep forensic or backup keys outside serving configuration under explicit custody.

Restore the database and its required key inventory only under closed recovery admission. An older snapshot can contain old-key rows, smaller floors, stale writers and obsolete capacity declarations. Reconcile the exact retained state, external recovery/witness identity and old-writer exclusion before reopening. Never delete fences, reset time, synthesize a fresh empty namespace or reuse a retired ID for new material to make an old backup appear current.

Public `StateSealer.unsealResult` returns `StateUnsealResult.Rejected` for an invalid, expired or unavailable-key value. Stateful services report their documented invalid-state/unavailable outcomes, or fail before normal output; key removal never means a durable row was absent. These failure paths must keep application traffic closed when authoritative state cannot be established.
