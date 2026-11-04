# Shared-clock store and consumer contracts

The unpublished [closed migration/restore fixture](../verification/shared-clock-migration/README.md) supplies bounded administrative inventory, exact prepared batches and disposable PostgreSQL rehearsal. Its structural activation remains separate from timed admission. It does not qualify an actual deployment, establish a real-data fit report or authorize migration of another target.

Its adapter-join lane starts from the actual legacy schemas, obtains exact WebAuthn retention from authenticated payloads, and preflights the fixed target against current schema and capacity constraints before rewriting authentication rows. It installs the full current metadata, registries, reservations and sequence continuation under a separate protected schema intent. Actual current adapters run only after both intents settle and fresh witness admission succeeds. These scripted disposable checks complete the source integration checkpoint; real witness and platform qualification remain required.

The current pre-1.0 source switches TOTP, WebAuthn and the OAuth issuer together. Applications must update their stores, wrappers, examples and result handling together. Existing persisted records require the selected closed migration procedure before activation; compiling the new API does not migrate a namespace or permit mixed old/new writers.

This document describes the joined source contract. Local fixture checks do not establish approved UTC accuracy, witness ownership, platform durability, old-writer exclusion or a production shared-store profile. The bounded volatile stores remain process-local examples.

The unpublished [focused qualification fixture](../verification/shared-clock-qualification/README.md) joins current source/test identities and records separate native measurements for distinct buckets, bucket collisions and the same entity. Its scripted backend evidence and production-source guard calibrations contribute bounded assertions; they do not replace the required real witness/platform profile or close missing case lanes.

## Store observations and receipts

Stores return data or confirmed absence together with one coherent `StoreTimeObservation`. `Fenced` and `Unavailable` never report absence. `StoreAdmission` binds the authority and recovery generation; healthy observations also identify the admitted clock generation and time profile. Constructing these carriers validates transport syntax and bounds. It does not establish that the source is trusted or that a deployment is ready.

The engine creates temporal conditions under the original operation budget. The lower bound includes admitted time, the immutable namespace/issuer minimum and relevant authenticated entity floors; an applicable original expiry supplies the exclusive upper bound. A backend checks exact predicates and admission, obtains fresh authority time after relevant lock waits, checks lower then upper bound, checks capacity and atomically commits. Worker clocks check health; they do not supply a healthy authority fallback or advance the durable minimum.

`TotpStoreCommitReceipt`, `WebAuthnStoreCommitReceipt` and `OAuthStoreCommitReceipt` preserve factual commit outcomes. Required validation timing and optional completion timing have different roles. Missing completion does not erase known commitment. Only valid final service evidence may allow normal output; an unknown mutation never becomes known committed through a later matching-looking read. A receipt factory does not authenticate a user, authorize a retry or open traffic.

Issuer transactions explicitly distinguish `TIMED` from `FENCE_ONLY`. Only existing issuer/subject emergency epoch revocation may use the latter. It preserves authority binding, incarnation, minimum, entity floors and permanent retention under current recovery admission, without healthy UTC or clock generation. Initialization, token revocation HTTP, grant revocation, issuance, status and reseal remain timed.

## Explicit result handling

All these mutation families add a restricted, payload-free `ReconciliationRequired` leaf:

| TOTP and recovery | WebAuthn |
|---|---|
| `TotpEnrollmentRequestResult` | `WebAuthnRegistrationRequestResult` |
| `TotpEnrollmentResult` | `WebAuthnAuthenticationRequestResult` |
| `TotpVerificationResult` | `WebAuthnRegistrationResult` |
| `RecoveryCodeUseResult` | `WebAuthnAuthenticationResult` |
| `RecoveryCodeRotationResult` | `WebAuthnCredentialRemovalResult` |
| `TotpFactorRemovalResult` | `WebAuthnAccountDisableResult` |
| `TotpEnrollmentCancellationResult` | — |
| `TotpNamespaceInitializationResult` | — |
| `TotpStoreResealResult` | — |

Handle each new branch deliberately in trusted application logic. `ReconciliationRequired` means the requested transition is known committed but its ordinary output cannot be released. `Indeterminate` means a relevant mutation is uncertain. Neither contains a proof, setup URI, recovery plaintext, credential or operation token. They may share a generic private/no-store 503 response, without a cookie, redirect, commit detail or `Retry-After`; keep the distinction in the already-authorized account, ceremony or management context.

Only the documented success variant releases its restricted payload. Existing rejection, throttling and unavailability variants keep their own meaning. A rejecting default protects against future unknown variants; it does not replace the explicit reconciliation branch. Never turn infrastructure or reconciliation into authentication success, ordinary invalid credentials, a charge refund or an automatic repeated mutation.

A committed recovery-code rotation whose plaintext was withheld cannot retrieve or re-emit that batch on retry. A later rotation needs fresh management approval and is a new operation. TOTP `ATTEMPT_INCOMPLETE` preserves a confirmed charge when verification or settlement is definitely incomplete. `TIME_AUTHORITY_UNAVAILABLE` and `CLOCK_HEALTH_UNCONFIRMED` identify their respective unavailable conditions without blaming a submitted credential. Pure TOTP status and WebAuthn credential listing retain their query variants and perform no hidden clock/cleanup writes.

The issuer exposes the same distinction through fixed, nontransient store exceptions: `COMMIT_CONFIRMED_NOT_ADMITTED` versus `COMMIT_OUTCOME_UNKNOWN`. Both have the generic HTTP boundary `503` and `{"error":"server_error"}`, no-store headers, no redirect or credential and no `Retry-After`. No underlying diagnostic or commit fact belongs in the remote response. Terminal observer hooks describe the processing checkpoint before their callback runs. A final pure release guard may withhold return after a delayed hook, without a second terminal event.

## Raw maintenance is factual acknowledgement

Three raw methods return contextual receipts:

- `OAuthAuthorizationServer.initializeFreshIssuer()`;
- `OAuthAuthorizationServer.resealStoreEntry(key)`;
- `WebAuthnRelyingParty.resealStoreEntry(key)`.

Inspect the receipt as an effect acknowledgement. A late known `COMMITTED` remains committed; `UNKNOWN` stays uncertain. Neither result establishes current traffic/readiness admission. Confirm readiness through a fresh admitted operation and the deployment's external recovery/activation procedure. These raw methods have no mandatory postcommit service-admission read and release no authentication or credential payload.

Issuer finite reseal can maintain credential-expired retained replay state strictly before its original full retention. It preserves the original payload, expiry, floor and retention and refuses at retention equality. WebAuthn raw reseal remains permanent-only and refuses ceremonies. Neither path becomes `FENCE_ONLY` during a UTC outage. TOTP initialization/reseal remain service-result families, with their normal final-admission requirement.

## WebAuthn tentative enrollment and permanent account state

Browser and provider claims also follow the [selected extension policy and dated target matrix](webauthn-browser-compatibility.md).
Current source accepts explicitly configured canonical HTTPS origins on the RP host or its
dot-delimited subdomains, with exact origin/port membership and the original RP-ID hash. Update
all readers before enabling child-origin pending records; the WAR2 format is unchanged, while
older readers reject those origins. Existing ceremonies retain their sealed origin snapshot.
Broader SR-5 browser/provider qualification remains required. The store-time transition does not
widen browser extension parsing.

Beginning registration commits an expiring ceremony, not a permanent account fence or credential
index. Its snapshot still predicates the account fence and index, including confirmed absence,
so a concurrent disable can prevent the begin commit. A namespace may establish its one permanent
clock root at this point; that root is shared rather than added per abandoned account handle.

The first successful registration completion inserts the active account fence, credential and
index together with ceremony consumption in one compare-and-commit. All absent/present predicates
are rechecked by the store. Competing first completions can retry only after a definite no-effect
conflict, then preserve the established active fence and update the index without losing another
credential. An index without its fence is inconsistent and cannot initialize a new active fence.
Authentication and account-pinned reauthentication still require an existing active fence.

Authorized account disable can establish a permanent disabled fence even before any credential
exists. A disable winning the completion race prevents credential creation; a later disable of a
committed enrollment remains effective. The API does not reopen disabled accounts. Permanent
fences, indexes, credentials and revoked-ID tombstones are never expired or evicted by this change.

Abandoned begins retain only their finite ceremonies plus any shared namespace root. Reads and
no-effect refusals do not reclaim them. The application must rate-limit enrollment and supply
explicit admitted ceremony maintenance where supported by its backend; retained ceremonies can
still exhaust capacity. The volatile in-memory example has no automatic maintenance. Completion
needs capacity for the additional permanent records and can refuse atomically while leaving the
pending ceremony unconsumed. Reconcile unknown or late committed outcomes before retrying or
releasing proof, under the existing recovery contract.

WAR2 payloads, key kinds and store APIs are unchanged. Existing active fences created by older
begins remain permanent: their bytes do not distinguish an abandoned account from retained
authoritative account state. This fix prevents new per-account leakage; it does not authorize
bulk deletion of historical active fences. Inventory and review any historical cleanup under an
application-owned closed procedure, preserving disabled fences, revocation proof and recovery
admission. All writers must adopt the deferred-establishment behavior before relying on its
capacity profile; older writers can still create permanent rows during begin.

## WebAuthn terminal account disable and traffic admission

`disableAccountResult(handle)` is terminal for the selected credential namespace, RP ID and
account handle. It can create the permanent disabled fence before enrollment or replace an
active fence. The API supplies no account-enable transition. New registration and account-pinned
reauthentication reject; pending registration, sign-in and reauthentication completions enforce
the disabled fence. Discoverable sign-in begin does not yet know an account and can still prepare
a browser request; it cannot complete authentication for the disabled account.

Reopening `WebAuthnRecoveryGate` traffic admission means that deployment recovery checks permit
operations to run again. It does not change an account fence. Rebuilding the relying party,
repeating disable or resealing under a new key also leaves the account disabled. A repeated
confirmed disable is a timed predicate barrier, without rewriting an already disabled fence.
Do not delete/reset a permanent fence or change identifiers as an account-enable shortcut;
retained disable and ownership/revocation evidence remains authoritative.

Disable retains credentials and indexes; authorized listing, credential removal and permanent
record reseal remain available when recovery admission permits them. Removal retains its revoked
ID tombstone. Applications still own account authorization, sessions and sensitive-action state.
Disable neither terminates existing application sessions nor retroactively revokes a verification
fact already returned to the caller; the host must enforce its own current account/session policy.

`Indeterminate` reports an unknown effect, not permission to reopen the account or automatically
retry. Reconcile through authorized fresh operations under the store/recovery contract before
resuming dependent actions. `ReconciliationRequired` retains a known committed terminal disable
whose normal output failed admission. Restoring traffic admission does not undo that effect.
These are current behavior and documentation/conformance clarifications, not a new enable feature
or runtime transition. Production restore/witness admission and application session revocation
remain separate responsibilities.

## WebAuthn persisted addresses and revoked-credential reseal

Credential removal retains a permanent ownership/revocation tombstone at the original credential
address and removes its ID from the active account index. Listing active credentials therefore
cannot supply a complete key-rotation inventory. Preserve and enumerate exact persistence
addresses, including tombstones, under application-owned bounded administrative inventory.

`WebAuthnStoreKey.fromStoredForm(storedAddress)` reconstructs a typed address without requiring a
credential-ID preimage or rehashing the stored digest. It accepts only the existing canonical
`wa1` format, at most 583 ASCII characters, with the existing printable namespace/canonical RP
rules, exact kind spelling and unpadded canonical Base64url components. Identifier digests must
be 32 bytes; namespace-clock addresses must use their one canonical empty-identifier digest.
Malformed, padded, aliased or oversized forms reject with fixed errors that omit the address.
`getStorageKey()` returns the same exact persistence spelling, and diagnostics remain redacted.

Reconstruction validates syntax only. An address supplies no account permission, authenticated
record, recovery admission or verification proof. Keep administrative inventory separate from
browser input and never log these sensitive addresses. The relying party still rejects foreign
namespace/RP and ceremony keys before store access; same-scope rows must pass sealed key/payload
binding, permanent retention, admitted time and recovery checks. All five kinds round-trip for
storage use, but short-lived ceremony rows remain ineligible for privileged raw reseal.

During rotation, deploy the opening-key overlap to all readers, then reseal every permanent row
with the new active key using the existing timed compare-and-commit operation. This includes
namespace roots, account fences, indexes, active credentials and revoked-credential tombstones.
Retain old opening keys until the complete inventory is verified. Reconcile unknown effects
under the existing recovery contract; one matching row is not a replacement acknowledgement.
Reseal preserves the payload, permanent retention, entity/root floor and revoked state; it does
not reinsert a credential into the active index, delete ownership evidence or permit ID reuse.

This is one additive pre-1.0 value factory. Storage addresses, WAR2 payloads, key kinds, store SPIs,
receipts and numerical limits are unchanged. It adds no inventory iterator or production scanner;
the host still owns bounded enumeration, key retirement, authorization, restore/witness admission
and real backend qualification. Historical addresses need no wire-format migration.

## WebAuthn sealing capacity changes

`StateSealer.maximumSealedLength` bounds each newly emitted WebAuthn record chunk. Historical WebAuthn record opening uses the fixed 16,384-character chunk ceiling of the WAR framing format. Lowering the emission setting, including reverting an earlier increase, therefore does not make otherwise valid larger historical chunks unreadable. This is specific to typed WebAuthn record opening: public application-state opening, general internal unseal operations and issuer record opening keep their configured caps.

The normal reader still requires WAR2, the exact addressed store key and chunk context, valid authentication, coherent encrypted retention, valid payloads and admitted floors. Its existing limits remain 262,144 framed bytes, 256 chunks, 16,384 characters per sealed chunk and 110,000 decoded payload bytes. An oversized frame is rejected before chunk authentication. Reading a WAR1 record for migration still requires the explicit closed migration intent; normal WebAuthn operations do not promote WAR1.

Before lowering an emission limit:

1. Upgrade all readers to the compatible implementation. Older binaries may still reject historical chunks above their own configured cap; an unchanged wire format does not repair those readers.
2. Retain every required opening key. The length setting supplies no new key, credential validity, account authority or recovery admission. Do not use a lower length cap to revoke credentials; use the authorized account or credential management operations.
3. Inventory retained records and rehearse replacement sizes against the backend's actual per-record and aggregate quotas. Smaller chunks add framing and cryptographic overhead, so a resealed frame can occupy more store bytes. The fixed frame/chunk/plaintext bounds and backend quotas remain enforced; no limit is raised to force a migration to fit.
4. Use normal admitted reads and the existing privileged permanent-record reseal API when changing sealing keys or rewriting the inventory. Confirm each contextual receipt and reconcile uncertain outcomes under the recovery contract. Resealing preserves the original payload, authority binding, entity/root floor and encrypted retention; it emits chunks under the current cap and does not extend lifetime or reset permanent state. Ceremonies remain excluded from privileged raw reseal.
5. Verify the completed inventory before retiring an opening key. Keep restore admission closed when durable recovery state is uncertain. A sealing-cap change alone requires no WAR schema migration and supplies no restore or UTC qualification.

## API inventory and compatibility

The shared-clock delta adds 15 store declarations and 15 service leaves. The new store types have 56 source-declared public methods; the `Purpose` enum also has Java's two generated `values`/`valueOf` methods. Existing types add seven getters and 17 enum constants. There are 11 selected public contract signature replacements plus the two required concrete `InMemoryTotpStore.compareAndCommit` and `InMemoryWebAuthnStore.compareAndCommit` return replacements: 13 binary replacements in total. The issuer transaction factory also changes at package access.

The two forced-public bridge declarations are internal. The separate rules and crypto/migration support classes remain internal too. No public signature exposes them; they are outside the compatibility boundary. No new builder, proof factory, key kind, public clock callback or generic recovery controller is added.

Use one recorded core/adapter artifact set when qualifying applications. The source/consumer acceptance of this delta does not substitute for release-owner approval, retained-data migration or shared-profile qualification. See the [TOTP guide](totp-recovery.md), [issuer application contract](oauth-server-application-contracts.md), [WebAuthn source contract](reviews/rc-wa-public-api-contract-2026-10-16.md) and [compatibility policy](../COMPATIBILITY.md).
