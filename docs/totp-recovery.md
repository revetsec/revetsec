# TOTP enrollment and recovery codes

**All-family source join — 2026-10-30:** use the [shared-clock store and consumer contract](shared-clock-stores.md) with the matching core and adapter artifacts. Its explicit reconciliation, factual raw-receipt and final-admission rules apply alongside this guide. Historical review and release approvals remain bound to their original artifacts; live profile, migration and release-owner acceptance remain separate.

`com.revetsec.totp` provides authenticator enrollment, confirmation, replay-protected TOTP verification, one-use recovery codes, replacement and removal. Core requires Java 17. The [complete Soklet 4 integration](../examples/totp-soklet/README.md) requires Java 21 and uses Soklet's default response marshaler. The paired [Jakarta Servlet](https://github.com/revetsec/revetsec-servlet-jakarta/blob/main/docs/totp.md) and [Javax Servlet](https://github.com/revetsec/revetsec-servlet-javax/blob/main/docs/totp.md) cookbooks show the same application-owned boundary on Java 17, with compilable recipes and disposable Tomcat fixtures. They call core directly; no dedicated Servlet TOTP adapter API is needed.

The application owns account identity, authorization, primary authentication, sessions, CSRF, network admission, UI, durable storage and the deployment recovery controller. A successful library result proves a confirmed credential transition; it does not prove that a browser session or application transaction committed. TOTP codes are not phishing resistant.

## Configure one immutable authenticator

```java
StateSealer sealer = StateSealer.withActiveKey(currentSealingKey)
    .verificationKeys(List.of(previousSealingKey))
    .build();

TotpAuthenticator totp = TotpAuthenticator.withIssuer("Example")
    .credentialNamespace("production-accounts")
    .recoveryEpoch(deploymentRecoveryEpoch)
    .store(applicationTotpStore)
    .stateSealer(sealer)
    .recoveryGate(applicationRecoveryGate)
    .clock(Clock.systemUTC())
    .build();
```

These configuration values and collaborators are application supplied. The issuer is trusted authenticator display text, not an OAuth issuer URL. Stable account IDs distinguish tenants and accounts; an email label is display text rather than storage identity. Building performs no I/O and starts no background threads. The authenticator is safe to share. Configuration is immutable; replace instances for configuration/key changes while preserving authoritative state.

The recovery epoch is an opaque, never-reused generation identifier maintained outside the database being restored. Ordinary deployments and sealing-key rotation retain it. Every participating node uses the same active epoch and coordinated gate/store policy.

For a newly provisioned epoch, explicitly call `initializeNamespaceResult()` while the external controller permits initialization. Handle `Initialized`, `AlreadyInitialized`, `Unavailable`, `Indeterminate` and `ReconciliationRequired`. Confirm initialization under the recovery controller before opening ordinary traffic. Ordinary operations never recreate a missing namespace fence. The backend changes the namespace activation state from `NEW` to `ACTIVATED` atomically with its initial namespace record. Once activated, a missing record is infrastructure failure.

## Profile and limits

| Setting | Behavior |
| --- | --- |
| Authenticator profile | HMAC-SHA1, six ASCII digits, 30-second Unix-epoch steps |
| Enrollment secret | 20 random bytes, unpadded Base32 provisioning |
| Clock tolerance | Previous, current and next step; no automatic drift expansion |
| Pending enrollment | Five minutes; one pending enrollment per account |
| Active factors | One per account |
| Recovery batch | Ten random 128-bit codes from separate draws |
| Recovery presentation | 26 Crockford Base32 symbols with readable grouping |
| Shared account admission | Five failed or unsettled attempts within a rolling five minutes, shared by confirmation, TOTP and recovery; in-flight reservations count |
| TOTP guessing budget | Ten failed or unsettled six-digit attempts within a rolling 24 hours, shared by confirmation and verification; in-flight reservations count |
| Operation budget | Five seconds by default across admission, storage, sealing and verification |

The store supplies admitted authority time from a source separate from the worker clock. The authenticated namespace minimum and each account's durable floor constrain that time; ordinary authentication advances only the affected account floor. The namespace root stays stable. Core checks the worker's whole causal offset interval against the admitted five-second bound, the original monotonic operation budget, and the bounded time between the final authority read and result release. An unavailable authority, a future floor or unconfirmed worker health refuses the operation without a worker-time fallback. Status is a pure query and never writes clock housekeeping. A store authority must remain nondecreasing, including across observations used only by queries and admitted clock generations.

An expired, unsettled or uncertain attempt reservation remains conservatively charged for its applicable window. Malformed submitted codes of at most 128 characters count as attempts; longer inputs are rejected before recovery-gate or store access. A confirmed success removes only its own reservation, not earlier failures. A full short ledger also blocks beginning enrollment, although beginning enrollment creates no attempt charge. Beginning another enrollment, replacing or removing a factor, and rebuilding the authenticator do not reset either admission ledger. Recovery-code consumption remains subject to the shared five-minute budget but does not spend or wait for the 24-hour six-digit TOTP budget; a legitimate recovery path remains available after the short cooldown. When both budgets apply, `Throttled` reports the later expiry. Applications still add trusted-edge, global and primary-login admission controls; the per-account limits cannot prevent distributed account probing or establish an account-existence oracle.

The TOTP algorithm and once-only acceptance follow [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.html). Provisioning follows the [authenticator key URI format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format). The code remains a `String` to preserve leading zeros. Recovery input has its own bounded ASCII parser; Unicode lookalikes and ambiguous symbols are rejected.

## Enrollment and management

```java
TotpEnrollmentOptions options = TotpEnrollmentOptions.withAccountId(accountId)
    .accountName("alice@example.com")
    .build();

TotpEnrollmentRequestResult result =
    totp.beginEnrollmentResult(options, browserBinding);
```

The app obtains `accountId`, label and unpredictable `browserBinding` from approved server-side state. Replacement is explicit: add `.replacingFactorId(expectedFactorId)` from the authorized management snapshot. Starting replacement leaves the existing factor and recovery batch usable. Confirmation atomically consumes the pending enrollment, installs the new factor and recovery batch, and initializes the accepted-step high-water mark.

Only `Prepared` releases a `TotpEnrollment`. Its enrollment ID, future factor ID and expiry can be retained against the approved browser session before releasing the setup secret. `getProvisioningUri()` and `getManualEntryKey()` deliberately expose secrets. Render QR codes locally with application-owned code. Do not send provisioning data to a third-party QR service, log it, persist it in browser storage or include it in telemetry. There is no accessor for retrieving an active factor's secret later.

```java
TotpEnrollmentResult confirmation = totp.confirmEnrollmentResult(
    accountId, enrollmentId, submittedCode, browserBinding);
```

`Succeeded` releases the factor and new `RecoveryCodes`. Plaintext recovery codes are available only from a confirmed enrollment or rotation result and are not retrievable from storage. Repeated getters on that immutable result can return the same values; the API cannot enforce single Java getter access. Deliver these responses with `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, escaped rendering and no third-party assets.

Management uses exact server-owned generations:

```java
totp.rotateRecoveryCodesResult(accountId, expectedFactorId, expectedBatchId);
totp.removeFactorResult(accountId, expectedFactorId);
totp.cancelEnrollmentResult(accountId, enrollmentId, browserBinding);
totp.getStatusResult(accountId);
```

Each requires application authorization. Factor/batch IDs and builder options are not authorization proofs. Use fresh action-specific approval or an explicitly approved recovery path. Rotation invalidates the entire old batch in one commit. Removal clears active factor, recovery batch and pending enrollment while advancing a permanent account fence. A delayed request cannot modify a later factor or recovery batch.

Status exposes active-factor metadata, pending enrollment/future-factor IDs and expiry, recovery batch ID and remaining-code count. It exposes neither TOTP secrets nor recovery plaintext. An account can have a retained record with no active factor after removal.

## Verification and application completion

```java
TotpVerificationResult result = totp.verifyResult(
    accountId, submittedCode, pendingLoginBinding);

RecoveryCodeUseResult recovery = totp.consumeRecoveryCodeResult(
    accountId, submittedRecoveryCode, pendingLoginBinding);
```

The server-owned operation binding identifies the current pending login or approved reauthentication action. The application gives primary-authenticated pending logins a short fixed expiry, does not extend it after code failures, and rejects expired or previously consumed state at both code admission and session completion. A successful result echoes the binding for the application's comparison. This is orchestration: an OTP is not cryptographically bound to a browser, purpose or site.

A TOTP success commits the accepted step before releasing `TotpVerification`; the same or any older step cannot succeed again. If several permitted steps happen to generate the same code, reject ambiguity rather than selecting a newer step around replay protection. Factor replacement/removal races participate in the same atomic predicates.

Recovery consumption atomically removes exactly one verifier and returns `RecoveryCodeUse`, a distinct method with the remaining-code count. It leaves the TOTP factor and other codes unchanged. Application policy may use it as a login fallback or, as in the example, create a restricted recovery session to replace the lost factor. It is not proof of current authenticator possession.

The application must recheck account state, proof account/operation binding and epoch, atomically consume the current primary-authenticated pending login, and rotate session/CSRF state. Hold an outer recovery permit through that transaction, or enforce a coordinated application epoch fence in the same transaction. Reading the epoch and later creating a session leaves a race. Sessions and management approvals carry the epoch and become unusable when recovery advances it.

## Results and uncertain writes

| Operation | Outcomes |
| --- | --- |
| Begin enrollment | `Prepared`, `Rejected`, `Throttled`, `Unavailable`, `Indeterminate`, `ReconciliationRequired` |
| Confirm, TOTP verify, recovery consume | `Succeeded`, `Rejected`, `Throttled`, `Unavailable`, `Indeterminate`, `ReconciliationRequired` |
| Rotate, remove, cancel | `Succeeded`, `Rejected`, `Unavailable`, `Indeterminate`, `ReconciliationRequired` |
| Status | `Present`, `Absent`, `Unavailable` |
| Initialize namespace | `Initialized`, `AlreadyInitialized`, `Unavailable`, `Indeterminate`, `ReconciliationRequired` |
| Reseal record | `Resealed`, `AlreadyCurrent`, `Absent`, `Unavailable`, `Indeterminate`, `ReconciliationRequired` |

Collapse credential-specific rejections into a generic remote error. `Throttled` carries a bounded retry duration. `Unavailable` means infrastructure failed without uncertain effects from a relevant mutation. `ATTEMPT_INCOMPLETE` specifically means an attempt charge is confirmed but the requested verification or settlement is definitely incomplete; keep that charge and do not reserve or refund automatically. `TIME_AUTHORITY_UNAVAILABLE` covers unavailable admitted time and time before the required minimum or floor. `CLOCK_HEALTH_UNCONFIRMED` covers unconfirmed worker offset, elapsed continuity or result-release timing. Pure status failures return `Unavailable` and never create an authentication proof.

`Indeterminate` means a relevant mutation may have committed. `ReconciliationRequired` means the requested transition is known committed, but its ordinary success, proof or secret cannot be released after the final admission checks. Both are payload-free and release no proof, setup URI or new recovery plaintext. Trusted application logic must distinguish them, even when both map to the same no-store HTTP 503 without `Retry-After`. Never retry the original mutation automatically or turn a later matching-looking snapshot into authentication success.

After uncertain or confirmed-but-withheld verification/recovery use, leave the pending login restricted and require a fresh code or approved alternate path. After a begin result requiring reconciliation, use authorized status to find/cancel the pending enrollment or wait for expiry; its secret cannot be retrieved. After confirmation or rotation requiring reconciliation, compare factor/batch state under fresh management approval and rotate again if the plaintext batch was lost. Status can reconcile management state, never reconstruct a verification proof. HTTP delivery and application transactions remain separate: a code may be consumed without a session being created.

## Durable backend contract

`TotpStore` accepts bounded-budget `read(Set<TotpStoreKey>, Duration)` and `compareAndCommit(TotpStoreWrite, Duration)` callbacks. The commit callback returns `TotpStoreCommitReceipt`, whose status describes the effect and whose committed timing records factual validation and optional completion observations. It stores opaque permanent records; core owns record grammar and transitions.

- A read returns one complete immutable authoritative snapshot with explicit presence or absence for every requested key and an admitted time observation. Unavailable time still carries admission metadata; it supplies no invented timestamp.
- Each commit compares every observed version/absence, admission and clock generation, and its engine-created temporal condition under the final transaction locks, then applies every mutation or none. Even a write with no mutations checks all predicates. Validation samples fresh authority time after waiting; it is not a durable-commit timestamp.
- The active recovery epoch is checked inside the same read/commit transaction. An earlier epoch lookup is insufficient.
- Preserve opaque addresses, fresh random versions and sealed bytes exactly. No version reuse, partial writes, eviction, read-replica snapshots or record TTLs.
- Only confirmed `CONFLICT` permits a bounded reread/recalculation of the same uncommitted transition within the original shrinking deadline. `UNKNOWN` is never retried automatically. `FENCED`, capacity refusal, `TIME_UNAVAILABLE`, `TIME_BEFORE_FLOOR` and `TIME_EXPIRED` guarantee no changes for that callback; they cannot erase an earlier committed charge or requested transition. Lost commit acknowledgement is `UNKNOWN`.
- A known committed receipt remains committed if its optional completion observation is absent. Before normal output, core reads the stable root again, checks the original generation/profile, floors and finite expiry, and checks the original budget and permit through release. A failed final check withholds normal output without changing the known effect.
- Store callbacks obey the remaining budget and preserve interruption. Application transactions do not wrap library calls; the backend callback owns its own bounded atomic work.

`ACCOUNT_STATE` aggregates the account generation/fence, active secret, used-step high-water mark, pending enrollment, recovery verifiers, both admission ledgers and monotone account floor. `NAMESPACE_STATE` retains namespace identity, admitted authority binding, immutable minimum and protocol fences. Both are permanent. Nested enrollment/attempt data expires through authenticated core transitions. A factor removal retains the account record, fence, floor and admission history.

Normal reads and writes use TTR3. TTR1/TTR2 are accepted only by the restricted closed-migration decoder with explicit external intent and an authenticated legacy namespace root. Migration preserves the exact legacy namespace minimum and account floors, replay marks, generations, ledgers and expiry; TTR1's combined attempt history is conservatively retained in the TOTP ledger. Close and drain old writers, admit the authority and recovery generation, convert and verify the complete retained population, then reopen. Oversized or unsupported retained records keep migration closed; do not evict, truncate or reset them. Older binaries cannot read TTR3 and must never run concurrently against a converted population. The private codecs and fixture do not establish a qualified deployment migration procedure.

`TotpStoreRecord.fromStoredForm(key, version, sealedBytes)` rehydrates an untrusted opaque carrier, with defensive copying and bounded representation validation. It grants no trust. Core authenticates exact address, namespace, epoch, kind, version and contents before use. A malformed record, unsupported format or missing sealing key is infrastructure unavailability, never absence or an invalid user code.

No store fallback is selected implicitly. `InMemoryTotpStore` is explicitly bounded, single-process and volatile; it cannot protect an established account against restart or backup rollback. The unpublished [PostgreSQL TOTP fixture](../examples/postgresql-pending-store/README.md#durable-totp-fixture) shows one application-owned `TotpStore` with a separate recovery gate and controller. Its test-only application store also demonstrates pending-login and session completion under a held recovery permit. It is a local qualification recipe, not a shipped backend, production session implementation or production recovery controller. Deployments still own their durable backend, key lifecycle and cross-host admission design.

## Sealing-key rotation and restore

Durable TOTP records use an internal typed sealing format with no expiry. The expiring public `StateSealer.seal(...)` API remains for short-lived application state. Never use a very long public-state lifetime as a substitute for durable record sealing. Sealed records bind their complete address and fresh version, so copying ciphertext to another account or version is rejected.

For normal rotation, distribute the new opening key to all nodes, promote it while retaining the old opening key, stop old writers from sealing with the old key, and enumerate/reseal all records using `resealStoreEntryResult(key)`. Enumeration is application owned, outside the authentication SPI. Resealing preserves every semantic field, performs an exact compare-and-commit, and never resets replay marks, generations, attempts or expiry. Reconcile uncertain outcomes before retirement. Key IDs always identify the same immutable material. Permanent records and retained backups require an explicit retirement policy; token/cookie expiry is insufficient.

`TotpRecoveryGate.acquire(context, remainingBudget)` returns a caller-thread permit or null when external recovery/key state cannot be confirmed. Context identifies the actual namespace, epoch, sealing-key IDs and initialization/operation purpose. The permit spans storage, cryptography, reservations, commit and the final result decision. It is current through release, deadline bounded and idempotently closed. Distributed gates must fence stale lease holders; store transactions separately enforce the epoch.

If acquisition returns null or throws, its implementation must release any lock, lease or admission count it acquired before returning control. Core can close only a permit that was actually returned. A stranded partial acquisition can prevent the recovery controller from draining outstanding work.

Before restoring authoritative storage, durably close admission outside that storage, drain all nodes and fence outstanding writers/transactions. Restore while closed. Provision a fresh never-reused epoch with an empty namespace generation, invalidate earlier sessions and approvals, initialize explicitly and then reopen. Old TOTP factors and recovery codes stay unusable; require application-approved recovery and reenrollment. Merely resealing restored records or overwriting their epoch cannot reconstruct lost consumption/removal history.

The local PostgreSQL fixture makes that sequence concrete. Its controller atomically changes an external file marker to `CLOSED` before taking an exclusive operation lock, which waits for live permits. While that restore lease remains held, the runner restores a real PostgreSQL logical backup, including test application sessions, pending logins and approval markers, and calls the store's transactional `provisionRecoveryEpoch(newEpoch, remainingBudget)`. Only after the database is fenced does the controller publish the fresh epoch in `INITIALIZING` mode and release the lease. A new authenticator explicitly initializes the fresh namespace root; the controller changes the marker to `OPEN` only after confirmation. The test application's read and completion transactions lock the authoritative namespace row and compare the current epoch, so restored old sessions, pending logins and approval markers stay rejected even if their rows reappear. During the closed interval, neither application state nor restored core records can grant a session or release proof or provisioning material. Old-epoch core reads and commits also return `FENCED` after the transactional epoch switch, including condition-only writes made from a pre-recovery snapshot.

The fixture also checks application admission before a valid code is consumed, a confirmed rotation of the primary cookie and CSRF token, a restricted recovery-code session, application COMMIT uncertainty, and a one-winner completion race after two distinct recovery codes have been consumed. A paused proof lets the controller close admission before application completion; another pause crosses the pending-login deadline and rejects completion despite a valid proof. After a fresh-epoch factor removal and reenrollment, a pending login pinned to the removed factor rejects a valid proof from the replacement factor. Those pauses test the proof-to-completion boundary. A separate pause after the final application session `INSERT` proves the PostgreSQL namespace row remains locked inside an in-flight SQL transaction. The controller closes admission and waits for that transaction and its outer permit to end; the probe withholds the new cookie and CSRF after the SQL commit. This is one-host fixture evidence, not a production recovery-controller qualification. Its primary-authenticated pending login and session-linked approval marker are synthetic. They do not supply production primary authentication, action-bound one-use management approvals or a complete session/CSRF policy.

That marker and lock are one-host test machinery. The key check binds the configured sealing-key IDs to digests of their actual material, but neither a local file nor the one-primary probe establishes cross-host recovery durability, replica failover, power-loss durability or production session fencing. A database backup can also restore its own epoch-history rows, so freshness must be retained outside that backup. The shared-clock candidate adds an external reserved time ceiling and database admission/interlock checks; approved UTC accuracy, filesystem durability, worker elapsed assumptions and the complete deployment profile remain unqualified. Neither application expiry checks nor the candidate clock profile authorize an unannounced backup rollback within the active epoch.

**Absence after recovery must not downgrade a protected account to password-only login.** Preserve the application's MFA requirement outside the restored factor generation, or require conservative recovery for every affected account. A static marker cannot detect an unannounced rollback within its existing epoch. Every authoritative restore must pass through the recovery controller.
