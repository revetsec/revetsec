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

import com.google.errorprone.annotations.CheckReturnValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;

/** Input and stored-cost ceilings applied before expensive password work.
 * @since 1.0.0 */
@Immutable
public final class PasswordVerificationLimits {
    private static final int DEFAULT_MAXIMUM_STORED_FORM_CHARS = 512;
    private static final int DEFAULT_MAXIMUM_PASSWORD_CHARS = 1_024;
    private static final int DEFAULT_MAXIMUM_PASSWORD_UTF8_BYTES = 4_096;
    private static final int DEFAULT_MAXIMUM_ARGON2ID_MEMORY_KIB = 131_072;
    private static final int DEFAULT_MAXIMUM_ARGON2ID_PASSES = 6;
    private static final int DEFAULT_MAXIMUM_ARGON2ID_LANES = 8;
    private final int maximumStoredFormChars;
    private final int maximumPasswordChars;
    private final int maximumPasswordUtf8Bytes;
    private final int maximumArgon2idMemoryKiB;
    private final int maximumArgon2idPasses;
    private final int maximumArgon2idLanes;

    private PasswordVerificationLimits(@NonNull Builder builder) {
        this.maximumStoredFormChars = builder.maximumStoredFormChars;
        this.maximumPasswordChars = builder.maximumPasswordChars;
        this.maximumPasswordUtf8Bytes = builder.maximumPasswordUtf8Bytes;
        this.maximumArgon2idMemoryKiB = builder.maximumArgon2idMemoryKiB;
        this.maximumArgon2idPasses = builder.maximumArgon2idPasses;
        this.maximumArgon2idLanes = builder.maximumArgon2idLanes;
    }

    /** Conservative verification ceilings suitable for initial configuration.
     * @return the limits
     * @since 1.0.0 */
    public static @NonNull PasswordVerificationLimits fromDefaults() { return new Builder().build(); }

    /** Starts a builder from conservative limits.
     * @return the builder
     * @since 1.0.0 */
    public static @NonNull Builder builder() { return new Builder(); }

    /** Returns the stored-form length limit.
     * @return maximum stored-form characters
     * @since 1.0.0 */
    public @NonNull Integer getMaximumStoredFormChars() { return maximumStoredFormChars; }

    /** Returns the input length limit before normalization.
     * @return maximum input UTF-16 code units before normalization
     * @since 1.0.0 */
    public @NonNull Integer getMaximumPasswordChars() { return maximumPasswordChars; }

    /** Returns the password byte length limit after normalization.
     * @return maximum normalized UTF-8 bytes
     * @since 1.0.0 */
    public @NonNull Integer getMaximumPasswordUtf8Bytes() { return maximumPasswordUtf8Bytes; }

    /** Returns the maximum accepted Argon2id memory cost.
     * @return maximum Argon2id verification memory in KiB
     * @since 1.0.0 */
    public @NonNull Integer getMaximumArgon2idMemoryKiB() { return maximumArgon2idMemoryKiB; }

    /** Returns the maximum accepted Argon2id time cost.
     * @return maximum Argon2id verification passes
     * @since 1.0.0 */
    public @NonNull Integer getMaximumArgon2idPasses() { return maximumArgon2idPasses; }

    /** Returns the maximum accepted Argon2id parallelism.
     * @return maximum Argon2id verification lanes
     * @since 1.0.0 */
    public @NonNull Integer getMaximumArgon2idLanes() { return maximumArgon2idLanes; }

    /** Mutable construction helper; no cryptographic or provider work runs during construction.
     * @since 1.0.0 */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Builder {
        private int maximumStoredFormChars = DEFAULT_MAXIMUM_STORED_FORM_CHARS;
        private int maximumPasswordChars = DEFAULT_MAXIMUM_PASSWORD_CHARS;
        private int maximumPasswordUtf8Bytes = DEFAULT_MAXIMUM_PASSWORD_UTF8_BYTES;
        private int maximumArgon2idMemoryKiB = DEFAULT_MAXIMUM_ARGON2ID_MEMORY_KIB;
        private int maximumArgon2idPasses = DEFAULT_MAXIMUM_ARGON2ID_PASSES;
        private int maximumArgon2idLanes = DEFAULT_MAXIMUM_ARGON2ID_LANES;

        private Builder() { }

        /** Sets the stored-form length limit.
         * @param value maximum stored-form characters, or null to restore the default
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder maximumStoredFormChars(@Nullable Integer value) {
            maximumStoredFormChars = value == null ? DEFAULT_MAXIMUM_STORED_FORM_CHARS : value; return this;
        }

        /** Sets the input length limit before normalization.
         * @param value maximum input UTF-16 code units, or null to restore the default
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder maximumPasswordChars(@Nullable Integer value) {
            maximumPasswordChars = value == null ? DEFAULT_MAXIMUM_PASSWORD_CHARS : value; return this;
        }

        /** Sets the password byte length limit after normalization.
         * @param value maximum normalized UTF-8 bytes, or null to restore the default
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder maximumPasswordUtf8Bytes(@Nullable Integer value) {
            maximumPasswordUtf8Bytes = value == null ? DEFAULT_MAXIMUM_PASSWORD_UTF8_BYTES : value; return this;
        }

        /** Sets the maximum accepted Argon2id memory cost.
         * @param value maximum Argon2id verification memory in KiB, or null to restore the default
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder maximumArgon2idMemoryKiB(@Nullable Integer value) {
            maximumArgon2idMemoryKiB = value == null ? DEFAULT_MAXIMUM_ARGON2ID_MEMORY_KIB : value; return this;
        }

        /** Sets the maximum accepted Argon2id time cost.
         * @param value maximum Argon2id verification passes, or null to restore the default
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder maximumArgon2idPasses(@Nullable Integer value) {
            maximumArgon2idPasses = value == null ? DEFAULT_MAXIMUM_ARGON2ID_PASSES : value; return this;
        }

        /** Sets the maximum accepted Argon2id parallelism.
         * @param value maximum Argon2id verification lanes, or null to restore the default
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder maximumArgon2idLanes(@Nullable Integer value) {
            maximumArgon2idLanes = value == null ? DEFAULT_MAXIMUM_ARGON2ID_LANES : value; return this;
        }

        /** Validates the ceilings without performing I/O or allocating KDF memory.
         * @return immutable limits
         * @since 1.0.0 */
        public @NonNull PasswordVerificationLimits build() {
            // A native form with a 64-character pepper key ID is at most 184 characters.
            if (maximumStoredFormChars < 192 || maximumStoredFormChars > 4_096
                    || maximumPasswordChars < 64 || maximumPasswordChars > 16_384
                    || maximumPasswordUtf8Bytes < 256 || maximumPasswordUtf8Bytes > 65_536
                    || maximumArgon2idMemoryKiB < 19_456 || maximumArgon2idMemoryKiB > 262_144
                    || maximumArgon2idPasses < 2 || maximumArgon2idPasses > 10
                    || maximumArgon2idLanes < 1 || maximumArgon2idLanes > 8) {
                throw new IllegalArgumentException("Invalid password verification limits");
            }
            return new PasswordVerificationLimits(this);
        }
    }
}
