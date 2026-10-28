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

/** Authoritative non-secret status; absence never authorizes an application to downgrade MFA.
 * @since 1.0.0 */
@Immutable
public abstract sealed class TotpStatusResult permits
        TotpStatusResult.Present, TotpStatusResult.Absent, TotpStatusResult.Unavailable {
    private static final @NonNull Absent ABSENT = new Absent();

    TotpStatusResult() { }
    static @NonNull TotpStatusResult present(@NonNull TotpStatus status) {
        return new Present(status);
    }
    static @NonNull TotpStatusResult absent() {
        return ABSENT;
    }
    static @NonNull TotpStatusResult unavailable(@NonNull TotpUnavailableReason reason) {
        return new Unavailable(reason);
    }
    static @NonNull TotpStatusResult unavailable() {
        return unavailable(TotpUnavailableReason.DEPENDENCY_UNAVAILABLE);
    }

    /** Redacts all account, binding and secret data.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public final @NonNull String toString() { return "TotpStatusResult{<redacted>}"; }

    /** An authoritative status read; this is not identity proof.
     * @since 1.0.0 */
    @Immutable
    public static final class Present extends TotpStatusResult {
        private final @NonNull TotpStatus status;
        private Present(@NonNull TotpStatus status) {
            this.status = requireNonNull(status);
        }
        /** Returns the status.
         * @return status
         * @since 1.0.0 */
        public @NonNull TotpStatus getStatus() { return this.status; }
    }

    /** The account has no record in this epoch; application MFA requirements still apply.
     * @since 1.0.0 */
    @Immutable
    public static final class Absent extends TotpStatusResult {
        private Absent() { }
    }

    /** Infrastructure or recovery admission was unavailable; no success is established.
     * @since 1.0.0 */
    @Immutable
    public static final class Unavailable extends TotpStatusResult {
        private final @NonNull TotpUnavailableReason reason;
        private Unavailable(@NonNull TotpUnavailableReason reason) {
            this.reason = requireNonNull(reason);
        }
        /** Returns the reason.
         * @return reason
         * @since 1.0.0 */
        public @NonNull TotpUnavailableReason getReason() { return this.reason; }
    }
}
