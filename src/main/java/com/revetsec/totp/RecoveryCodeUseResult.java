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

import org.jspecify.annotations.NonNull;
import com.google.errorprone.annotations.CheckReturnValue;
import javax.annotation.concurrent.Immutable;
import java.time.Duration;

import static java.util.Objects.requireNonNull;

/** Recovery-code consumption; only Succeeded carries committed recovery-method proof.
 * @since 1.0.0 */
@Immutable
public abstract sealed class RecoveryCodeUseResult permits
        RecoveryCodeUseResult.Succeeded, RecoveryCodeUseResult.Rejected, RecoveryCodeUseResult.Throttled, RecoveryCodeUseResult.Unavailable, RecoveryCodeUseResult.Indeterminate, RecoveryCodeUseResult.ReconciliationRequired {
    private static final @NonNull Indeterminate INDETERMINATE = new Indeterminate();
    private static final @NonNull ReconciliationRequired RECONCILIATION_REQUIRED = new ReconciliationRequired();

    RecoveryCodeUseResult() { }
    static @NonNull RecoveryCodeUseResult succeeded(@NonNull RecoveryCodeUse use) {
        return new Succeeded(use);
    }
    static @NonNull RecoveryCodeUseResult rejected(@NonNull TotpRejectionReason reason) {
        return new Rejected(reason);
    }
    static @NonNull RecoveryCodeUseResult throttled(@NonNull Duration retryAfter) {
        return new Throttled(retryAfter);
    }
    static @NonNull RecoveryCodeUseResult unavailable(@NonNull TotpUnavailableReason reason) {
        return new Unavailable(reason);
    }
    static @NonNull RecoveryCodeUseResult indeterminate() {
        return INDETERMINATE;
    }
    @CheckReturnValue
    static @NonNull RecoveryCodeUseResult reconciliationRequired() {
        return RECONCILIATION_REQUIRED;
    }
    static @NonNull RecoveryCodeUseResult unavailable() {
        return unavailable(TotpUnavailableReason.DEPENDENCY_UNAVAILABLE);
    }

    /** Redacts all account, binding and secret data.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public final @NonNull String toString() { return "RecoveryCodeUseResult{<redacted>}"; }

    /** The requested transition was definitely committed under current admission.
     * @since 1.0.0 */
    @Immutable
    public static final class Succeeded extends RecoveryCodeUseResult {
        private final @NonNull RecoveryCodeUse use;
        private Succeeded(@NonNull RecoveryCodeUse use) {
            this.use = requireNonNull(use);
        }
        /** Returns the use.
         * @return use
         * @since 1.0.0 */
        public @NonNull RecoveryCodeUse getUse() { return this.use; }
    }

    /** Fixed input, policy or generation rejection; no proof is released.
     * @since 1.0.0 */
    @Immutable
    public static final class Rejected extends RecoveryCodeUseResult {
        private final @NonNull TotpRejectionReason reason;
        private Rejected(@NonNull TotpRejectionReason reason) {
            this.reason = requireNonNull(reason);
        }
        /** Returns the reason.
         * @return reason
         * @since 1.0.0 */
        public @NonNull TotpRejectionReason getReason() { return this.reason; }
    }

    /** The durable shared account admission limit prevented this attempt.
     * @since 1.0.0 */
    @Immutable
    public static final class Throttled extends RecoveryCodeUseResult {
        private final @NonNull Duration retryAfter;
        private Throttled(@NonNull Duration retryAfter) {
            this.retryAfter = requireNonNull(retryAfter);
            if (retryAfter.isNegative()) throw new IllegalArgumentException("Negative retry duration");
        }
        /** Returns the retryAfter.
         * @return retryAfter
         * @since 1.0.0 */
        public @NonNull Duration getRetryAfter() { return this.retryAfter; }
    }

    /** Infrastructure or recovery admission was unavailable; no success is established.
     * @since 1.0.0 */
    @Immutable
    public static final class Unavailable extends RecoveryCodeUseResult {
        private final @NonNull TotpUnavailableReason reason;
        private Unavailable(@NonNull TotpUnavailableReason reason) {
            this.reason = requireNonNull(reason);
        }
        /** Returns the reason.
         * @return reason
         * @since 1.0.0 */
        public @NonNull TotpUnavailableReason getReason() { return this.reason; }
    }

    /** A write may have occurred; reconcile management state and never infer authentication success.
     * @since 1.0.0 */
    @Immutable
    public static final class Indeterminate extends RecoveryCodeUseResult {
        private Indeterminate() { }
    }

    /** The requested transition is known committed, but normal output could not be admitted.
     * No proof, secret or operation detail is released.
     * @since 1.0.0 */
    @Immutable
    public static final class ReconciliationRequired extends RecoveryCodeUseResult {
        private ReconciliationRequired() { }
    }
}
