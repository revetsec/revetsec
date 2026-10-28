/*
 * Copyright 2026 Revetware LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.revetsec.totp;

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.StrictUtf8;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import javax.annotation.concurrent.NotThreadSafe;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

/**
 * Standalone TOTP enrollment, once-only verification and recovery codes. Applications own account
 * authorization, primary authentication, sessions, CSRF, network admission, durable storage and
 * recovery administration. TOTP is not phishing resistant. Configuration is immutable and building
 * performs no storage, gate, cryptographic-provider or network work.
 * <p>
 * The fixed profile is HMAC-SHA1, six digits and 30-second Unix-epoch steps, accepting the previous,
 * current or next step exactly once. Five failed or unsettled attempts per account in five minutes
 * are shared by confirmation, TOTP and recovery codes. Six-digit confirmation and verification
 * also share a durable limit of ten failed or unsettled attempts per rolling 24 hours. Recovery
 * codes have 128 bits of entropy and remain subject to the five-minute shared limit, so they can
 * provide fallback after that cooldown. Malformed submitted codes of at most 128 characters count
 * as attempts; longer inputs are rejected before recovery admission or storage access. A successful
 * attempt removes only its own reservations; earlier failed or unsettled attempts remain charged
 * until their respective windows expire.
 * A confirmed factor has ten random 128-bit recovery codes from separate draws. Pending enrollment
 * lasts five minutes; starting replacement leaves the old factor active until confirmation commits.
 * <p>
 * Only confirmed, timely, recovery-admitted operations release proofs or secrets. Unknown writes
 * are never retried automatically. An indeterminate verification cannot be reconciled into a login;
 * require a fresh code. Status can reconcile management generations but never reveals secret material.
 * Instances are safe to share across threads with thread-safe application dependencies.
 * @since 1.0.0
 */
@ThreadSafe
public final class TotpAuthenticator {
    private final @NonNull TotpEngine engine;
    private final @NonNull String namespace;
    private final @NonNull String recoveryEpoch;
    private TotpAuthenticator(@NonNull TotpEngine engine, @NonNull String namespace, @NonNull String recoveryEpoch) {
        this.engine = engine; this.namespace = namespace; this.recoveryEpoch = recoveryEpoch;
    }
    /** Starts configuration with a trusted authenticator display issuer, not an OAuth issuer URL.
     * @param issuer well-formed display issuer, 1–128 characters, without colons or controls
     * @return a builder
     * @since 1.0.0 */
    public static @NonNull Builder withIssuer(@NonNull String issuer) { return new Builder(issuer); }
    /** Returns the configured credential namespace.
     * @return the namespace
     * @since 1.0.0 */
    public @NonNull String getCredentialNamespace() { return this.namespace; }
    /** Returns the fixed external recovery generation.
     * @return the recovery epoch
     * @since 1.0.0 */
    public @NonNull String getRecoveryEpoch() { return this.recoveryEpoch; }
    /** Persist a browser-bound pending secret before releasing provisioning information. Management authorization is application-owned.
     * @param options approved account, display label and optional exact replacement generation
     * @param browserBinding unpredictable server-owned browser binding
     * @return the canonical operation outcome
     * @since 1.0.0 */
    @CheckReturnValue
    public @NonNull TotpEnrollmentRequestResult beginEnrollmentResult(@NonNull TotpEnrollmentOptions options, @NonNull String browserBinding) {
        Objects.requireNonNull(options); account(options.getAccountId()); binding(browserBinding);
        TotpEngine.Result result = this.engine.execute(new TotpEngine.Command(TotpEngine.Action.BEGIN,
                options.getAccountId(), "", "", browserBinding, options, null));
        return switch (result.status) {
            case SUCCEEDED -> TotpEnrollmentRequestResult.prepared(Objects.requireNonNull(result.enrollment));
            case REJECTED -> TotpEnrollmentRequestResult.rejected(result.rejection);
            case THROTTLED -> TotpEnrollmentRequestResult.throttled(result.retryAfter);
            case UNAVAILABLE -> TotpEnrollmentRequestResult.unavailable(result.unavailable);
            case INDETERMINATE -> TotpEnrollmentRequestResult.indeterminate();
            default -> throw new IllegalStateException("Unexpected TOTP operation outcome");
        };
    }
    /** Atomically consumes pending enrollment, activates the factor, consumes its confirmation step and installs recovery verifiers.
     * @param accountId approved stable account identifier
     * @param enrollmentId pending enrollment identifier
     * @param code submitted six ASCII digits, preserving leading zeros
     * @param browserBinding the original server-owned browser binding
     * @return the canonical operation outcome
     * @since 1.0.0 */
    @CheckReturnValue
    public @NonNull TotpEnrollmentResult confirmEnrollmentResult(@NonNull String accountId, @NonNull String enrollmentId, @NonNull String code, @NonNull String browserBinding) {
        account(accountId); binding(browserBinding); Objects.requireNonNull(enrollmentId); Objects.requireNonNull(code);
        if (enrollmentId.length() > 128 || code.length() > 128) return TotpEnrollmentResult.rejected(TotpRejectionReason.INVALID_CODE);
        TotpEngine.Result result = execute(TotpEngine.Action.CONFIRM, accountId, enrollmentId, code, browserBinding);
        return switch (result.status) {
            case SUCCEEDED -> TotpEnrollmentResult.succeeded(Objects.requireNonNull(result.factor), Objects.requireNonNull(result.codes));
            case REJECTED -> TotpEnrollmentResult.rejected(result.rejection);
            case THROTTLED -> TotpEnrollmentResult.throttled(result.retryAfter);
            case UNAVAILABLE -> TotpEnrollmentResult.unavailable(result.unavailable);
            case INDETERMINATE -> TotpEnrollmentResult.indeterminate();
            default -> throw new IllegalStateException("Unexpected TOTP operation outcome");
        };
    }
    /** Verifies one code and commits replay consumption before releasing a TOTP proof. The application must atomically complete its current bound operation under recovery admission.
     * @param accountId approved stable account identifier
     * @param code submitted six ASCII digits
     * @param operationBinding server-owned pending login or approved action binding
     * @return the canonical operation outcome
     * @since 1.0.0 */
    @CheckReturnValue
    public @NonNull TotpVerificationResult verifyResult(@NonNull String accountId, @NonNull String code, @NonNull String operationBinding) {
        account(accountId); binding(operationBinding); Objects.requireNonNull(code);
        if (code.length() > 128) return TotpVerificationResult.rejected(TotpRejectionReason.INVALID_CODE);
        TotpEngine.Result result = execute(TotpEngine.Action.VERIFY, accountId, "", code, operationBinding);
        return switch (result.status) {
            case SUCCEEDED -> TotpVerificationResult.succeeded(Objects.requireNonNull(result.verification));
            case REJECTED -> TotpVerificationResult.rejected(result.rejection);
            case THROTTLED -> TotpVerificationResult.throttled(result.retryAfter);
            case UNAVAILABLE -> TotpVerificationResult.unavailable(result.unavailable);
            case INDETERMINATE -> TotpVerificationResult.indeterminate();
            default -> throw new IllegalStateException("Unexpected TOTP operation outcome");
        };
    }
    /** Atomically consumes one recovery code and releases distinct recovery-method provenance. It does not prove current TOTP possession.
     * @param accountId approved stable account identifier
     * @param recoveryCode submitted recovery code, accepting ASCII case folding and hyphens
     * @param operationBinding server-owned pending login or recovery action binding
     * @return the canonical operation outcome
     * @since 1.0.0 */
    @CheckReturnValue
    public @NonNull RecoveryCodeUseResult consumeRecoveryCodeResult(@NonNull String accountId, @NonNull String recoveryCode, @NonNull String operationBinding) {
        account(accountId); binding(operationBinding); Objects.requireNonNull(recoveryCode);
        if (recoveryCode.length() > 128) return RecoveryCodeUseResult.rejected(TotpRejectionReason.INVALID_CODE);
        TotpEngine.Result result = execute(TotpEngine.Action.RECOVERY, accountId, "", recoveryCode, operationBinding);
        return switch (result.status) {
            case SUCCEEDED -> RecoveryCodeUseResult.succeeded(Objects.requireNonNull(result.recoveryUse));
            case REJECTED -> RecoveryCodeUseResult.rejected(result.rejection);
            case THROTTLED -> RecoveryCodeUseResult.throttled(result.retryAfter);
            case UNAVAILABLE -> RecoveryCodeUseResult.unavailable(result.unavailable);
            case INDETERMINATE -> RecoveryCodeUseResult.indeterminate();
            default -> throw new IllegalStateException("Unexpected TOTP operation outcome");
        };
    }
    /** Replaces the entire recovery batch only for the exact approved factor and batch generations. New plaintext is released only after a confirmed commit.
     * @param accountId approved stable account identifier
     * @param expectedFactorId current factor generation from the authorized management context
     * @param expectedBatchId current recovery batch from that same context
     * @return the canonical operation outcome
     * @since 1.0.0 */
    @CheckReturnValue
    public @NonNull RecoveryCodeRotationResult rotateRecoveryCodesResult(@NonNull String accountId, @NonNull String expectedFactorId, @NonNull String expectedBatchId) {
        account(accountId); identifier(expectedFactorId); identifier(expectedBatchId);
        TotpEngine.Result result = execute(TotpEngine.Action.ROTATE, accountId, expectedFactorId, expectedBatchId, "");
        return switch (result.status) {
            case SUCCEEDED -> RecoveryCodeRotationResult.succeeded(Objects.requireNonNull(result.codes));
            case REJECTED -> RecoveryCodeRotationResult.rejected(result.rejection);
            case UNAVAILABLE -> RecoveryCodeRotationResult.unavailable(result.unavailable);
            case INDETERMINATE -> RecoveryCodeRotationResult.indeterminate();
            default -> throw new IllegalStateException("Unexpected TOTP operation outcome");
        };
    }
    /** Removes the exact approved factor, pending enrollment and recovery batch while retaining permanent account and admission fences.
     * @param accountId approved stable account identifier
     * @param expectedFactorId current factor generation from the approved management context
     * @return the canonical operation outcome
     * @since 1.0.0 */
    @CheckReturnValue
    public @NonNull TotpFactorRemovalResult removeFactorResult(@NonNull String accountId, @NonNull String expectedFactorId) {
        account(accountId); identifier(expectedFactorId);
        TotpEngine.Result result = execute(TotpEngine.Action.REMOVE, accountId, expectedFactorId, "", "");
        return switch (result.status) {
            case SUCCEEDED -> TotpFactorRemovalResult.succeeded();
            case REJECTED -> TotpFactorRemovalResult.rejected(result.rejection);
            case UNAVAILABLE -> TotpFactorRemovalResult.unavailable(result.unavailable);
            case INDETERMINATE -> TotpFactorRemovalResult.indeterminate();
            default -> throw new IllegalStateException("Unexpected TOTP operation outcome");
        };
    }
    /** Cancels only the named browser-bound pending enrollment, preserving the active factor and attempt accounting.
     * @param accountId approved stable account identifier
     * @param enrollmentId approved pending enrollment identifier
     * @param browserBinding original server-owned browser binding
     * @return the canonical operation outcome
     * @since 1.0.0 */
    @CheckReturnValue
    public @NonNull TotpEnrollmentCancellationResult cancelEnrollmentResult(@NonNull String accountId, @NonNull String enrollmentId, @NonNull String browserBinding) {
        account(accountId); identifier(enrollmentId); binding(browserBinding);
        TotpEngine.Result result = execute(TotpEngine.Action.CANCEL, accountId, enrollmentId, "", browserBinding);
        return switch (result.status) {
            case SUCCEEDED -> TotpEnrollmentCancellationResult.succeeded();
            case REJECTED -> TotpEnrollmentCancellationResult.rejected(result.rejection);
            case UNAVAILABLE -> TotpEnrollmentCancellationResult.unavailable(result.unavailable);
            case INDETERMINATE -> TotpEnrollmentCancellationResult.indeterminate();
            default -> throw new IllegalStateException("Unexpected TOTP operation outcome");
        };
    }
    /** Reads active and pending generations and recovery counts without exposing secrets. Absence never authorizes a password-only fallback after namespace recovery.
     * @param accountId authorized stable account identifier
     * @return the canonical operation outcome
     * @since 1.0.0 */
    @CheckReturnValue
    public @NonNull TotpStatusResult getStatusResult(@NonNull String accountId) {
        account(accountId);
        TotpEngine.Result result = execute(TotpEngine.Action.STATUS, accountId, "", "", "");
        return switch (result.status) {
            case SUCCEEDED -> TotpStatusResult.present(Objects.requireNonNull(result.accountStatus));
            case ABSENT -> TotpStatusResult.absent();
            case UNAVAILABLE -> TotpStatusResult.unavailable(result.unavailable);
            default -> TotpStatusResult.unavailable(result.unavailable);
        };
    }
    /** Initializes only a newly provisioned recovery generation under an explicit initialization permit. Normal operations never recreate a missing namespace root.
     * @return the canonical operation outcome
     * @since 1.0.0 */
    @CheckReturnValue
    public @NonNull TotpNamespaceInitializationResult initializeNamespaceResult() {
        TotpEngine.Result result = execute(TotpEngine.Action.INITIALIZE, null, "", "", "");
        return switch (result.status) {
            case SUCCEEDED -> TotpNamespaceInitializationResult.initialized();
            case ALREADY_CURRENT -> TotpNamespaceInitializationResult.alreadyInitialized();
            case UNAVAILABLE -> TotpNamespaceInitializationResult.unavailable(result.unavailable);
            case INDETERMINATE -> TotpNamespaceInitializationResult.indeterminate();
            default -> throw new IllegalStateException("Unexpected TOTP operation outcome");
        };
    }
    /** Authenticates and reseals one permanent record with the active key under exact row and namespace predicates, preserving all semantic state and deadlines.
     * @param key application-authorized maintenance address within this configured scope
     * @return the canonical operation outcome
     * @since 1.0.0 */
    @CheckReturnValue
    public @NonNull TotpStoreResealResult resealStoreEntryResult(@NonNull TotpStoreKey key) {
        Objects.requireNonNull(key);
        if (!key.getCredentialNamespace().equals(this.namespace) || !key.getRecoveryEpoch().equals(this.recoveryEpoch))
            throw new IllegalArgumentException("Foreign TOTP maintenance scope");
        TotpEngine.Result result = this.engine.execute(new TotpEngine.Command(TotpEngine.Action.RESEAL,
                null, "", "", "", null, key));
        return switch (result.status) {
            case SUCCEEDED -> TotpStoreResealResult.resealed();
            case ALREADY_CURRENT -> TotpStoreResealResult.alreadyCurrent();
            case ABSENT -> TotpStoreResealResult.absent();
            case UNAVAILABLE -> TotpStoreResealResult.unavailable(result.unavailable);
            case INDETERMINATE -> TotpStoreResealResult.indeterminate();
            default -> throw new IllegalStateException("Unexpected TOTP operation outcome");
        };
    }
    private TotpEngine.@NonNull Result execute(TotpEngine.@NonNull Action action, @Nullable String accountId,
            @NonNull String first, @NonNull String second, @NonNull String third) {
        return this.engine.execute(new TotpEngine.Command(action, accountId, first, second, third, null, null));
    }
    private void account(@NonNull String accountId) { TotpStoreKey.validateAccount(accountId); }
    private static void identifier(@NonNull String value) {
        Objects.requireNonNull(value);
        if (value.isEmpty() || value.length() > 1024 || !StrictUtf8.isWellFormed(value))
            throw new IllegalArgumentException("Invalid TOTP identifier");
    }
    private static void binding(@NonNull String value) { identifier(value); }
    /** Redacts application configuration and identifiers.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "TotpAuthenticator{configuration=<redacted>}"; }

    /** Caller-thread configuration builder. Required dependencies have no permissive defaults.
     * @since 1.0.0 */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Builder {
        private final @NonNull String issuer;
        private @Nullable String namespace;
        private @Nullable String epoch;
        private @Nullable TotpStore store;
        private @Nullable StateSealer sealer;
        private @Nullable TotpRecoveryGate gate;
        private @NonNull Clock clock = Clock.systemUTC();
        private @NonNull Duration timeout = Duration.ofSeconds(5);
        private Builder(@NonNull String issuer) {
            Objects.requireNonNull(issuer);
            if (issuer.isEmpty() || issuer.length() > 128 || !StrictUtf8.isWellFormed(issuer))
                throw new IllegalArgumentException("Invalid TOTP issuer");
            for (int i = 0; i < issuer.length(); i++)
                if (issuer.charAt(i) == ':' || Character.isISOControl(issuer.charAt(i)))
                    throw new IllegalArgumentException("Invalid TOTP issuer");
            this.issuer = issuer;
        }
        /** Sets the stable account storage namespace.
         * @param credentialNamespace visible ASCII namespace, 1–128 characters; null clears this required setting
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder credentialNamespace(@Nullable String credentialNamespace) {
            if (credentialNamespace != null) TotpStoreKey.validateScope(credentialNamespace); this.namespace = credentialNamespace; return this;
        }
        /** Sets the externally durable, never-reused recovery generation.
         * @param recoveryEpoch visible ASCII epoch, 1–128 characters; null clears this required setting
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder recoveryEpoch(@Nullable String recoveryEpoch) {
            if (recoveryEpoch != null) TotpStoreKey.validateScope(recoveryEpoch); this.epoch = recoveryEpoch; return this;
        }
        /** Sets authoritative storage with atomic recovery fencing.
         * @param store application-owned thread-safe store; null clears this required setting
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder store(@Nullable TotpStore store) { this.store = store; return this; }
        /** Sets immutable sealing-key configuration for typed permanent records.
         * @param stateSealer the sealer; null clears this required setting. Retain old opening keys until records are migrated
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder stateSealer(@Nullable StateSealer stateSealer) { this.sealer = stateSealer; return this; }
        /** Sets externally durable deployment/recovery admission.
         * @param recoveryGate application-owned thread-safe gate; null clears this required setting
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder recoveryGate(@Nullable TotpRecoveryGate recoveryGate) { this.gate = recoveryGate; return this; }
        /** Sets the UTC instant source; persisted observed time limits backward movement.
         * @param clock the clock, or null for the system UTC clock
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder clock(@Nullable Clock clock) { this.clock = clock == null ? Clock.systemUTC() : clock; return this; }
        /** Sets one shrinking caller-thread deadline for admission, crypto, storage and conflict retries.
         * @param operationTimeout from 100 milliseconds to 30 seconds, or null for five seconds
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder operationTimeout(@Nullable Duration operationTimeout) {
            Duration timeout = operationTimeout == null ? Duration.ofSeconds(5) : operationTimeout;
            if (timeout.compareTo(Duration.ofMillis(100)) < 0 || timeout.compareTo(Duration.ofSeconds(30)) > 0)
                throw new IllegalArgumentException("Invalid TOTP operation timeout");
            this.timeout = timeout; return this;
        }
        /** Checks configuration without admission, storage, cryptographic-provider calls or thread startup.
         * @return the immutable authenticator
         * @since 1.0.0 */
        public @NonNull TotpAuthenticator build() {
            String ns = Objects.requireNonNull(this.namespace, "credentialNamespace");
            String recoveryEpoch = Objects.requireNonNull(this.epoch, "recoveryEpoch");
            return new TotpAuthenticator(new TotpEngine(this.issuer, ns, recoveryEpoch,
                    Objects.requireNonNull(this.store, "store"), Objects.requireNonNull(this.sealer, "stateSealer"),
                    Objects.requireNonNull(this.gate, "recoveryGate"), this.clock, this.timeout), ns, recoveryEpoch);
        }
        /** Redacts builder contents.
         * @return a fixed description
         * @since 1.0.0 */
        @Override public @NonNull String toString() { return "TotpAuthenticator.Builder{configuration=<redacted>}"; }
    }
}
