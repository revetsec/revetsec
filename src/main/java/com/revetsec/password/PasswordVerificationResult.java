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
package com.revetsec.password;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;

import static java.util.Objects.requireNonNull;

/** Complete local password-verification result. Only {@link Matched} proves that the submitted
 * password matches the selected stored verifier; the application still owns account admission,
 * credential-version checks, and the remaining login flow.
 * @since 1.0.0 */
@Immutable
public abstract sealed class PasswordVerificationResult permits PasswordVerificationResult.Matched,
        PasswordVerificationResult.NotMatched, PasswordVerificationResult.Rejected,
        PasswordVerificationResult.Unavailable {
    private static final @NonNull NotMatched NOT_MATCHED = new NotMatched();
    PasswordVerificationResult() { }

    static @NonNull PasswordVerificationResult matched(boolean rehashRecommended) { return new Matched(rehashRecommended); }
    static @NonNull PasswordVerificationResult notMatched() { return NOT_MATCHED; }
    static @NonNull PasswordVerificationResult rejected(@NonNull PasswordRejectionReason reason) { return new Rejected(reason); }
    static @NonNull PasswordVerificationResult unavailable(@NonNull PasswordUnavailableReason reason) { return new Unavailable(reason); }

    /** @return a fixed redacted description
     * @since 1.0.0 */
    @Override public final @NonNull String toString() { return "PasswordVerificationResult{<redacted>}"; }

    /** The submitted complete password matched the selected stored verifier.
     * @since 1.0.0 */
    @Immutable
    public static final class Matched extends PasswordVerificationResult {
        private final boolean rehashRecommended;
        private Matched(boolean rehashRecommended) { this.rehashRecommended = rehashRecommended; }
        /** Whether the application should generate a current-policy hash and atomically replace
         * the exact current credential. This method does not perform or establish a write.
         * @return whether an upgrade is recommended
         * @since 1.0.0 */
        public @NonNull Boolean isRehashRecommended() { return rehashRecommended; }
    }

    /** The submitted password did not match.
     * @since 1.0.0 */
    @Immutable
    public static final class NotMatched extends PasswordVerificationResult {
        private NotMatched() { }
    }

    /** An input or stored verifier was invalid or unsupported under this operation.
     * @since 1.0.0 */
    @Immutable
    public static final class Rejected extends PasswordVerificationResult {
        private final @NonNull PasswordRejectionReason reason;
        private Rejected(@NonNull PasswordRejectionReason reason) { this.reason = requireNonNull(reason); }
        /** Returns the reason this input was rejected.
         * @return fixed rejection reason
         * @since 1.0.0 */
        public @NonNull PasswordRejectionReason getReason() { return reason; }
    }

    /** Work or a required dependency was unavailable; no password match was established.
     * @since 1.0.0 */
    @Immutable
    public static final class Unavailable extends PasswordVerificationResult {
        private final @NonNull PasswordUnavailableReason reason;
        private Unavailable(@NonNull PasswordUnavailableReason reason) { this.reason = requireNonNull(reason); }
        /** Returns the reason verification was unavailable.
         * @return fixed unavailability reason
         * @since 1.0.0 */
        public @NonNull PasswordUnavailableReason getReason() { return reason; }
    }
}
