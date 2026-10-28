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

import com.revetsec.json.JsonString;
import com.google.errorprone.annotations.CheckReturnValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/** Application-approved account and display information for initial or replacement enrollment.
 * @since 1.0.0 */
@Immutable
public final class TotpEnrollmentOptions {
    private final @NonNull String accountId;
    private final @NonNull String accountName;
    private final @Nullable String replacingFactorId;

    private TotpEnrollmentOptions(@NonNull String accountId, @NonNull String accountName,
            @Nullable String replacingFactorId) {
        this.accountId = accountId;
        this.accountName = accountName;
        this.replacingFactorId = replacingFactorId;
    }

    /** Starts enrollment options for an application-approved account.
     * @param accountId stable nonempty, well-formed account identifier, at most 1024 UTF-8 bytes
     * @return a builder
     * @since 1.0.0 */
    public static @NonNull Builder withAccountId(@NonNull String accountId) {
        return new Builder(accountId);
    }

    /** Returns the application-approved account identifier.
     * @return account identifier
     * @since 1.0.0 */
    public @NonNull String getAccountId() { return this.accountId; }

    /** Returns the authenticator display name, which does not establish identity.
     * @return account display name
     * @since 1.0.0 */
    public @NonNull String getAccountName() { return this.accountName; }

    /** Returns the explicitly approved factor generation to replace.
     * @return current factor generation, or empty for initial enrollment
     * @since 1.0.0 */
    public @NonNull Optional<@NonNull String> getReplacingFactorId() {
        return Optional.ofNullable(this.replacingFactorId);
    }

    /** Redacts account and generation information.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "TotpEnrollmentOptions{<redacted>}"; }

    /** One caller-thread enrollment builder.
     * @since 1.0.0 */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Builder {
        private final @NonNull String accountId;
        private @Nullable String accountName;
        private @Nullable String replacingFactorId;
        private Builder(@NonNull String accountId) {
            requireNonNull(accountId);
            if (accountId.isEmpty() || accountId.length() > 1024)
                throw new IllegalArgumentException("Invalid TOTP account identifier");
            JsonString.fromValue(accountId);
            if (accountId.getBytes(StandardCharsets.UTF_8).length > 1024)
                throw new IllegalArgumentException("Invalid TOTP account identifier");
            this.accountId = accountId;
        }

        /** Sets the display name shown by the authenticator application.
         * @param accountName display name of at most 256 code points, without colons or controls; null clears this required setting
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder accountName(@Nullable String accountName) {
            if (accountName == null) { this.accountName = null; return this; }
            bounded(accountName, 256);
            if (accountName.indexOf(':') >= 0)
                throw new IllegalArgumentException("Invalid TOTP account display name");
            this.accountName = accountName;
            return this;
        }

        /** Approves replacement of an exact current factor generation.
         * Starting replacement preserves the active factor until confirmation commits.
         * @param factorId current factor generation, or null for initial enrollment
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder replacingFactorId(@Nullable String factorId) {
            this.replacingFactorId = factorId == null ? null : bounded(factorId, 1024);
            return this;
        }

        /** Builds immutable options; an account display name is required.
         * @return enrollment options
         * @since 1.0.0 */
        public @NonNull TotpEnrollmentOptions build() {
            return new TotpEnrollmentOptions(this.accountId,
                    requireNonNull(this.accountName, "accountName"), this.replacingFactorId);
        }

        /** Redacts builder contents.
         * @return a fixed description
         * @since 1.0.0 */
        @Override public @NonNull String toString() { return "TotpEnrollmentOptions.Builder{<redacted>}"; }
    }

    private static @NonNull String bounded(@NonNull String value, int maximumPoints) {
        requireNonNull(value);
        if (value.isEmpty() || value.length() > maximumPoints * 2)
            throw new IllegalArgumentException("Invalid TOTP enrollment option");
        JsonString.fromValue(value);
        if (value.codePointCount(0, value.length()) > maximumPoints)
            throw new IllegalArgumentException("Invalid TOTP enrollment option");
        for (int offset = 0; offset < value.length();) {
            int point = value.codePointAt(offset);
            if (Character.isISOControl(point))
                throw new IllegalArgumentException("Invalid TOTP enrollment option");
            offset += Character.charCount(point);
        }
        return value;
    }
}
