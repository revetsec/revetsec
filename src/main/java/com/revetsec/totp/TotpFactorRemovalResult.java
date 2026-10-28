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

/** Atomic factor removal that retains permanent account and namespace fences.
 * @since 1.0.0 */
@Immutable
public abstract sealed class TotpFactorRemovalResult permits
        TotpFactorRemovalResult.Succeeded, TotpFactorRemovalResult.Rejected, TotpFactorRemovalResult.Unavailable, TotpFactorRemovalResult.Indeterminate {
    private static final @NonNull Succeeded SUCCEEDED = new Succeeded();
    private static final @NonNull Indeterminate INDETERMINATE = new Indeterminate();

    TotpFactorRemovalResult() { }
    static @NonNull TotpFactorRemovalResult succeeded() {
        return SUCCEEDED;
    }
    static @NonNull TotpFactorRemovalResult rejected(@NonNull TotpRejectionReason reason) {
        return new Rejected(reason);
    }
    static @NonNull TotpFactorRemovalResult unavailable(@NonNull TotpUnavailableReason reason) {
        return new Unavailable(reason);
    }
    static @NonNull TotpFactorRemovalResult indeterminate() {
        return INDETERMINATE;
    }
    static @NonNull TotpFactorRemovalResult unavailable() {
        return unavailable(TotpUnavailableReason.DEPENDENCY_UNAVAILABLE);
    }

    /** Redacts all account, binding and secret data.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public final @NonNull String toString() { return "TotpFactorRemovalResult{<redacted>}"; }

    /** The requested transition was definitely committed under current admission.
     * @since 1.0.0 */
    @Immutable
    public static final class Succeeded extends TotpFactorRemovalResult {
        private Succeeded() { }
    }

    /** Fixed input, policy or generation rejection; no proof is released.
     * @since 1.0.0 */
    @Immutable
    public static final class Rejected extends TotpFactorRemovalResult {
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
    public static final class Unavailable extends TotpFactorRemovalResult {
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
    public static final class Indeterminate extends TotpFactorRemovalResult {
        private Indeterminate() { }
    }
}
