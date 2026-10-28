# RC-SEC selected core API candidate — 2026-10-16

**Status:** source-bound inventory and contract review of the uncommitted Java 17
password-hashing and TOTP/recovery core. This is a candidate boundary, not the
owner's 1.0.0 API freeze, an independent cryptographic review, or approval of a
production durable store or recovery controller.

## Exported declarations

`com.revetsec.password` has 15 public top-level types:

| Role | Types |
| --- | --- |
| Configuration and operations | `Argon2idParameters`, `PasswordHasher`, `PasswordWorkGate`, `PasswordVerificationLimits` |
| Results and values | `PasswordHash`, `PasswordHashResult`, `PasswordVerificationResult`, `PasswordRejectionReason`, `PasswordUnavailableReason` |
| Optional pepper lifecycle | `PasswordPepperKey`, `PasswordPepperSnapshot`, `PasswordPepperSnapshotResult`, `PasswordPepperSource` |
| Explicit legacy selectors | `LegacyPasswordPreparation`, `Pbkdf2Hmac` |

`com.revetsec.totp` has 33 public top-level types:

| Role | Types |
| --- | --- |
| Configuration and operations | `TotpAuthenticator`, `TotpEnrollmentOptions`, `InMemoryTotpStore` |
| Enrollment, use and management values | `TotpEnrollment`, `TotpPendingEnrollment`, `TotpFactor`, `TotpStatus`, `TotpVerification`, `RecoveryCodeUse`, `RecoveryCodes`, `TotpAuthenticationMethod` |
| Operation results and reasons | `TotpEnrollmentRequestResult`, `TotpEnrollmentResult`, `TotpEnrollmentCancellationResult`, `TotpVerificationResult`, `RecoveryCodeUseResult`, `RecoveryCodeRotationResult`, `TotpFactorRemovalResult`, `TotpStatusResult`, `TotpNamespaceInitializationResult`, `TotpStoreResealResult`, `TotpRejectionReason`, `TotpUnavailableReason` |
| Authoritative storage | `TotpStore`, `TotpStoreKey`, `TotpStoreRecord`, `TotpStoreEntry`, `TotpStoreSnapshot`, `TotpStoreReadResult`, `TotpStoreWrite`, `TotpStoreCommitResult` |
| External recovery admission | `TotpRecoveryGate`, `TotpRecoveryContext` |

The nested sealed-result variants and builders are also public API. The
[compatibility ledger](../../COMPATIBILITY.md) defines `public` and `protected`
declarations in these packages as the compatibility boundary.

## Operation and result boundary

| Component | Entry points and proof-bearing result |
| --- | --- |
| New password hash | `PasswordHasher.hashResult(char[])` returns a verifier only through `PasswordHashResult.Succeeded`; the application still must persist it. |
| Native password verification | `verifyResult(char[], String)` returns a local match only through `PasswordVerificationResult.Matched`; rehash advice is neither a write nor a login. |
| Explicit migration | `verifyLegacyBcryptResult(...)` and `verifyLegacyPbkdf2Result(...)` require trusted account provenance to select the method; a match recommends Argon2id rehash. |
| TOTP setup | `beginEnrollmentResult(...)`, `confirmEnrollmentResult(...)`, `cancelEnrollmentResult(...)`; only `Prepared` releases a setup secret, and only confirmed enrollment `Succeeded` releases active factor and fresh plaintext recovery codes. |
| TOTP/recovery use | `verifyResult(...)` and `consumeRecoveryCodeResult(...)` release distinct TOTP or recovery-method proofs only after confirmed atomic consumption. |
| TOTP management | `rotateRecoveryCodesResult(...)`, `removeFactorResult(...)`, `getStatusResult(...)`; status releases metadata but no secret or authentication proof. |
| Durable lifecycle | `initializeNamespaceResult()` and `resealStoreEntryResult(...)` require exact external recovery admission and do not grant login authority. |

Password hashing and verification use complete success/match, `Rejected`, and
`Unavailable` paths. TOTP mutations additionally expose `Indeterminate` after
a possible unacknowledged commit; neither it nor `Unavailable` releases proof,
setup secret or newly issued recovery codes. `Throttled` is a separate code
admission result. The application owns account authorization, credential-version
compare-and-set, browser/session completion, MFA policy and recovery approval.
No OAuth authorization server or HTTP framework adapter is required.

## Bounded configuration and state contracts

| Boundary | Current candidate |
| --- | --- |
| Password input | Default maximum 1,024 input UTF-16 code units, 4,096 normalized UTF-8 bytes and 512 stored-form characters. New hashes use 16-byte random salts and 32-byte tags. |
| Argon2id and work | `Argon2idParameters.withCosts(memoryKiB, passes, lanes)` allows 19,456–262,144 KiB with at least two passes, or at least 47,104 KiB with one pass, and 1–8 lanes. `PasswordWorkGate` bounds process memory and concurrent calls without waiting or starting workers. Verification caps apply before KDF allocation. |
| Legacy verification | bcrypt is verify-only with an explicit 4–16 log-round ceiling and no 72-byte truncation. PBKDF2 is verify-only with an explicit maximum of at most 2,000,000 iterations, bounded salt/tag lengths and trusted schema fields. Both require historical character preparation. |
| Pepper | Optional snapshots contain one active key and at most 15 retained keys. A 1–64-character ASCII ID names one 32-byte secret; one operation uses one coherent snapshot. Missing keys fail closed. |
| TOTP profile | Six ASCII digits, 30-second HMAC-SHA1 steps, previous/current/next-step tolerance, 20-byte random enrollment secret and five-minute pending enrollment. One active factor and one pending enrollment per account. |
| Recovery and guessing | Ten random 128-bit recovery codes per batch. A five-failed-or-unsettled-attempt rolling five-minute ledger covers confirmation, TOTP and recovery; a second ten-attempt rolling 24-hour ledger covers six-digit attempts. Code strings longer than 128 characters are rejected before admission or storage. |
| Operation budget | One shrinking TOTP deadline defaults to five seconds and permits 100 milliseconds to 30 seconds. Account IDs are at most 1,024 UTF-8 bytes; namespace and recovery epoch are visible ASCII strings of at most 128 characters. |
| Store SPI | A read covers 1–16 exact addresses in one namespace/epoch with explicit presence or absence. Compare-and-commit checks every snapshot predicate and active epoch transactionally, then applies at most 16 insertions/replacements or none. No record TTL, eviction, delete or version reuse. Only definite `CONFLICT` is retryable within the original deadline; `UNKNOWN` never is. |
| Recovery gate | A caller-thread permit spans storage, crypto and result decision, plus any nested application completion transaction. Failed acquisition releases partial claims. A controller closes admission, drains and fences writers, provisions a fresh never-reused epoch outside restored state, then reopens. |

The [password guide](../password-hashing.md) and [TOTP guide](../totp-recovery.md)
give the detailed caller and backend obligations. The TOTP store and gate are
application SPIs; the bounded `InMemoryTotpStore` is volatile and does not
qualify a durable deployment.

## Contract-audit result and remaining gates

`PublicApiContractTests` and the exported-signature check previously omitted
`com.revetsec.password` because it was missing from
`ContractSupport.EXPORTED_PACKAGES`. This review added it and a sentinel that
keeps both selected security packages in the audit. The expanded checks found
and fixed one naming violation (`Argon2idParameters.of(...)` became
`withCosts(...)`) and four missing `@Immutable` enum markers. The full suite
then exposed password getters and builder setters that did not follow the
existing boxed-value and nullable-property convention. Those declarations now
use boxed accessors; nullable limit setters restore their finite defaults;
`workGate(null)` clears a required dependency so `build()` fails; and
`pepperSource(null)` clears the optional policy. The per-item pepper-key adder
became `retainedKeys(List)`, which atomically replaces the complete retained
set and accepts null to restore an empty set. The instance factories now use
`PasswordVerificationLimits.fromDefaults()` and
`PasswordPepperSource.fromSnapshot(...)`.

The focused Java 17 builder-conventions, public API, package-dependency,
source-policy and password tests pass; the Java 17 standalone password example
compiles with `-Xlint:all -Werror` and runs. These checks cover exported type
shape, nullability, thread safety, package layering and public references to
internal types. The full Java 17 suite subsequently passed with 19,076 tests,
zero failures/errors and one skip on these final declarations.

`com.revetsec.webauthn` was absent from the exported-package audit at this
checkpoint. The later [WebAuthn source-contract audit](rc-wa-public-api-contract-2026-10-16.md)
adds it and resolves the findings it exposed. That audit does not complete the
separate RC-WA API freeze. This password/TOTP review did not change WebAuthn source.

The selected password/TOTP API remains a freeze **candidate**. RC-SEC still
needs external review of the Argon2id/BLAKE2b translation, production workload
sizing, application session/epoch-fence and cross-host recovery qualification,
and remaining selected-scope assurance decisions. The one-host PostgreSQL fixture
now exercises durable key promotion, resealing and retirement, but local tests
cannot replace production host measurements, a distributed recovery controller,
or hosted CI on pushed source.
