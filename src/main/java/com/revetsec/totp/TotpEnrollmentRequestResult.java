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
import javax.annotation.concurrent.Immutable;
import java.time.Duration;

import static java.util.Objects.requireNonNull;

/** Pending enrollment preparation; provisioning material appears only after a confirmed commit.
 * @since 1.0.0 */
@Immutable
public abstract sealed class TotpEnrollmentRequestResult permits
        TotpEnrollmentRequestResult.Prepared, TotpEnrollmentRequestResult.Rejected, TotpEnrollmentRequestResult.Throttled, TotpEnrollmentRequestResult.Unavailable, TotpEnrollmentRequestResult.Indeterminate {
    private static final @NonNull Indeterminate INDETERMINATE = new Indeterminate();

    TotpEnrollmentRequestResult() { }
    static @NonNull TotpEnrollmentRequestResult prepared(@NonNull TotpEnrollment enrollment) {
        return new Prepared(enrollment);
    }
    static @NonNull TotpEnrollmentRequestResult rejected(@NonNull TotpRejectionReason reason) {
        return new Rejected(reason);
    }
    static @NonNull TotpEnrollmentRequestResult throttled(@NonNull Duration retryAfter) {
        return new Throttled(retryAfter);
    }
    static @NonNull TotpEnrollmentRequestResult unavailable(@NonNull TotpUnavailableReason reason) {
        return new Unavailable(reason);
    }
    static @NonNull TotpEnrollmentRequestResult indeterminate() {
        return INDETERMINATE;
    }
    static @NonNull TotpEnrollmentRequestResult unavailable() {
        return unavailable(TotpUnavailableReason.DEPENDENCY_UNAVAILABLE);
    }

    /** Redacts all account, binding and secret data.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public final @NonNull String toString() { return "TotpEnrollmentRequestResult{<redacted>}"; }

    /** Provisioning material whose pending record was definitely committed.
     * @since 1.0.0 */
    @Immutable
    public static final class Prepared extends TotpEnrollmentRequestResult {
        private final @NonNull TotpEnrollment enrollment;
        private Prepared(@NonNull TotpEnrollment enrollment) {
            this.enrollment = requireNonNull(enrollment);
        }
        /** Returns the enrollment.
         * @return enrollment
         * @since 1.0.0 */
        public @NonNull TotpEnrollment getEnrollment() { return this.enrollment; }
    }

    /** Fixed input, policy or generation rejection; no proof is released.
     * @since 1.0.0 */
    @Immutable
    public static final class Rejected extends TotpEnrollmentRequestResult {
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
    public static final class Throttled extends TotpEnrollmentRequestResult {
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
    public static final class Unavailable extends TotpEnrollmentRequestResult {
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
    public static final class Indeterminate extends TotpEnrollmentRequestResult {
        private Indeterminate() { }
    }
}
