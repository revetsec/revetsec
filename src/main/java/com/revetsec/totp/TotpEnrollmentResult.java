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

/** Enrollment confirmation and atomic activation of a factor and recovery batch.
 * @since 1.0.0 */
@Immutable
public abstract sealed class TotpEnrollmentResult permits
        TotpEnrollmentResult.Succeeded, TotpEnrollmentResult.Rejected, TotpEnrollmentResult.Throttled, TotpEnrollmentResult.Unavailable, TotpEnrollmentResult.Indeterminate, TotpEnrollmentResult.ReconciliationRequired {
    private static final @NonNull Indeterminate INDETERMINATE = new Indeterminate();
    private static final @NonNull ReconciliationRequired RECONCILIATION_REQUIRED = new ReconciliationRequired();

    TotpEnrollmentResult() { }
    static @NonNull TotpEnrollmentResult succeeded(@NonNull TotpFactor factor, @NonNull RecoveryCodes recoveryCodes) {
        return new Succeeded(factor, recoveryCodes);
    }
    static @NonNull TotpEnrollmentResult rejected(@NonNull TotpRejectionReason reason) {
        return new Rejected(reason);
    }
    static @NonNull TotpEnrollmentResult throttled(@NonNull Duration retryAfter) {
        return new Throttled(retryAfter);
    }
    static @NonNull TotpEnrollmentResult unavailable(@NonNull TotpUnavailableReason reason) {
        return new Unavailable(reason);
    }
    static @NonNull TotpEnrollmentResult indeterminate() {
        return INDETERMINATE;
    }
    @CheckReturnValue
    static @NonNull TotpEnrollmentResult reconciliationRequired() {
        return RECONCILIATION_REQUIRED;
    }
    static @NonNull TotpEnrollmentResult unavailable() {
        return unavailable(TotpUnavailableReason.DEPENDENCY_UNAVAILABLE);
    }

    /** Redacts all account, binding and secret data.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public final @NonNull String toString() { return "TotpEnrollmentResult{<redacted>}"; }

    /** The requested transition was definitely committed under current admission.
     * @since 1.0.0 */
    @Immutable
    public static final class Succeeded extends TotpEnrollmentResult {
        private final @NonNull TotpFactor factor;
        private final @NonNull RecoveryCodes recoveryCodes;
        private Succeeded(@NonNull TotpFactor factor, @NonNull RecoveryCodes recoveryCodes) {
            this.factor = requireNonNull(factor);
            this.recoveryCodes = requireNonNull(recoveryCodes);
        }
        /** Returns the factor.
         * @return factor
         * @since 1.0.0 */
        public @NonNull TotpFactor getFactor() { return this.factor; }
        /** Returns the recoveryCodes.
         * @return recoveryCodes
         * @since 1.0.0 */
        public @NonNull RecoveryCodes getRecoveryCodes() { return this.recoveryCodes; }
    }

    /** Fixed input, policy or generation rejection; no proof is released.
     * @since 1.0.0 */
    @Immutable
    public static final class Rejected extends TotpEnrollmentResult {
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
    public static final class Throttled extends TotpEnrollmentResult {
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
    public static final class Unavailable extends TotpEnrollmentResult {
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
    public static final class Indeterminate extends TotpEnrollmentResult {
        private Indeterminate() { }
    }

    /** The requested transition is known committed, but normal output could not be admitted.
     * No proof, secret or operation detail is released.
     * @since 1.0.0 */
    @Immutable
    public static final class ReconciliationRequired extends TotpEnrollmentResult {
        private ReconciliationRequired() { }
    }
}
