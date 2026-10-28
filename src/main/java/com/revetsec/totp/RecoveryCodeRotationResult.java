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

import static java.util.Objects.requireNonNull;

/** Atomic recovery-code batch replacement for an approved current factor and batch.
 * @since 1.0.0 */
@Immutable
public abstract sealed class RecoveryCodeRotationResult permits
        RecoveryCodeRotationResult.Succeeded, RecoveryCodeRotationResult.Rejected, RecoveryCodeRotationResult.Unavailable, RecoveryCodeRotationResult.Indeterminate {
    private static final @NonNull Indeterminate INDETERMINATE = new Indeterminate();

    RecoveryCodeRotationResult() { }
    static @NonNull RecoveryCodeRotationResult succeeded(@NonNull RecoveryCodes recoveryCodes) {
        return new Succeeded(recoveryCodes);
    }
    static @NonNull RecoveryCodeRotationResult rejected(@NonNull TotpRejectionReason reason) {
        return new Rejected(reason);
    }
    static @NonNull RecoveryCodeRotationResult unavailable(@NonNull TotpUnavailableReason reason) {
        return new Unavailable(reason);
    }
    static @NonNull RecoveryCodeRotationResult indeterminate() {
        return INDETERMINATE;
    }
    static @NonNull RecoveryCodeRotationResult unavailable() {
        return unavailable(TotpUnavailableReason.DEPENDENCY_UNAVAILABLE);
    }

    /** Redacts all account, binding and secret data.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public final @NonNull String toString() { return "RecoveryCodeRotationResult{<redacted>}"; }

    /** The requested transition was definitely committed under current admission.
     * @since 1.0.0 */
    @Immutable
    public static final class Succeeded extends RecoveryCodeRotationResult {
        private final @NonNull RecoveryCodes recoveryCodes;
        private Succeeded(@NonNull RecoveryCodes recoveryCodes) {
            this.recoveryCodes = requireNonNull(recoveryCodes);
        }
        /** Returns the recoveryCodes.
         * @return recoveryCodes
         * @since 1.0.0 */
        public @NonNull RecoveryCodes getRecoveryCodes() { return this.recoveryCodes; }
    }

    /** Fixed input, policy or generation rejection; no proof is released.
     * @since 1.0.0 */
    @Immutable
    public static final class Rejected extends RecoveryCodeRotationResult {
        private final @NonNull TotpRejectionReason reason;
        private Rejected(@NonNull TotpRejectionReason reason) {
            this.reason = requireNonNull(reason);
        }
        /** Returns the reason.
         * @return reason
         * @since 1.0.0 */
        public @NonNull TotpRejectionReason getReason() { return this.reason; }
    }

    /** Infrastructure or recovery admission was unavailable; no success is established.
     * @since 1.0.0 */
    @Immutable
    public static final class Unavailable extends RecoveryCodeRotationResult {
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
    public static final class Indeterminate extends RecoveryCodeRotationResult {
        private Indeterminate() { }
    }
}
