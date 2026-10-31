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

## API inventory and compatibility

The shared-clock delta adds 15 store declarations and 15 service leaves. The new store types have 56 source-declared public methods; the `Purpose` enum also has Java's two generated `values`/`valueOf` methods. Existing types add seven getters and 17 enum constants. There are 11 selected public contract signature replacements plus the two required concrete `InMemoryTotpStore.compareAndCommit` and `InMemoryWebAuthnStore.compareAndCommit` return replacements: 13 binary replacements in total. The issuer transaction factory also changes at package access.

The two forced-public bridge declarations are internal. The separate rules and crypto/migration support classes remain internal too. No public signature exposes them; they are outside the compatibility boundary. No new builder, proof factory, key kind, public clock callback or generic recovery controller is added.

Use one recorded core/adapter artifact set when qualifying applications. The source/consumer acceptance of this delta does not substitute for release-owner approval, retained-data migration or shared-profile qualification. See the [TOTP guide](totp-recovery.md), [issuer application contract](oauth-server-application-contracts.md), [WebAuthn source contract](reviews/rc-wa-public-api-contract-2026-10-16.md) and [compatibility policy](../COMPATIBILITY.md).
