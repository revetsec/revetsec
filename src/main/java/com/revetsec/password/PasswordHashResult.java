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

/** Complete result of generating a new password hash.
 * @since 1.0.0 */
@Immutable
public abstract sealed class PasswordHashResult permits PasswordHashResult.Succeeded,
        PasswordHashResult.Rejected, PasswordHashResult.Unavailable {
    PasswordHashResult() { }

    static @NonNull PasswordHashResult succeeded(@NonNull PasswordHash hash) { return new Succeeded(hash); }
    static @NonNull PasswordHashResult rejected(@NonNull PasswordRejectionReason reason) { return new Rejected(reason); }
    static @NonNull PasswordHashResult unavailable(@NonNull PasswordUnavailableReason reason) { return new Unavailable(reason); }

    /** @return a fixed redacted description
     * @since 1.0.0 */
    @Override public final @NonNull String toString() { return "PasswordHashResult{<redacted>}"; }

    /** A new hash is ready for application-owned persistence.
     * @since 1.0.0 */
    @Immutable
    public static final class Succeeded extends PasswordHashResult {
        private final @NonNull PasswordHash passwordHash;
        private Succeeded(@NonNull PasswordHash passwordHash) { this.passwordHash = requireNonNull(passwordHash); }
        /** Returns the generated password hash.
         * @return the generated hash
         * @since 1.0.0 */
        public @NonNull PasswordHash getPasswordHash() { return passwordHash; }
    }

    /** Input was refused without hashing.
     * @since 1.0.0 */
    @Immutable
    public static final class Rejected extends PasswordHashResult {
        private final @NonNull PasswordRejectionReason reason;
        private Rejected(@NonNull PasswordRejectionReason reason) { this.reason = requireNonNull(reason); }
        /** Returns the reason this input was rejected.
         * @return fixed rejection reason
         * @since 1.0.0 */
        public @NonNull PasswordRejectionReason getReason() { return reason; }
    }

    /** Work or a required dependency was unavailable; no hash was generated.
     * @since 1.0.0 */
    @Immutable
    public static final class Unavailable extends PasswordHashResult {
        private final @NonNull PasswordUnavailableReason reason;
        private Unavailable(@NonNull PasswordUnavailableReason reason) { this.reason = requireNonNull(reason); }
        /** Returns the reason hashing was unavailable.
         * @return fixed unavailability reason
         * @since 1.0.0 */
        public @NonNull PasswordUnavailableReason getReason() { return reason; }
    }
}
