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

package com.revetsec.webauthn;

import com.google.errorprone.annotations.CheckReturnValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.time.Duration;

/** Bounded parser, ceremony and store-operation settings for a WebAuthn relying party.
 * Values are application-selected, while Revetsec enforces the protocol bounds.
 * @since 1.0.0 */
@Immutable
public final class WebAuthnSettings {
    private static final int DEFAULT_BODY = 64 * 1_024;
    private static final int DEFAULT_CLIENT_DATA = 8 * 1_024;
    private static final int DEFAULT_ATTESTATION = 16 * 1_024;
    private static final int DEFAULT_AUTHENTICATOR_DATA = 8 * 1_024;
    private static final int DEFAULT_EXCLUSIONS = 64;
    private static final @NonNull Duration DEFAULT_LIFETIME = Duration.ofMinutes(5);
    private static final @NonNull Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);

    private final int maximumResponseBodyBytes;
    private final int maximumClientDataJsonBytes;
    private final int maximumAttestationObjectBytes;
    private final int maximumAuthenticatorDataBytes;
    private final int maximumExcludedCredentials;
    private final @NonNull Duration ceremonyLifetime;
    private final @NonNull Duration operationTimeout;

    private WebAuthnSettings(@NonNull Builder builder) {
        this.maximumResponseBodyBytes = builder.maximumResponseBodyBytes;
        this.maximumClientDataJsonBytes = builder.maximumClientDataJsonBytes;
        this.maximumAttestationObjectBytes = builder.maximumAttestationObjectBytes;
        this.maximumAuthenticatorDataBytes = builder.maximumAuthenticatorDataBytes;
        this.maximumExcludedCredentials = builder.maximumExcludedCredentials;
        this.ceremonyLifetime = builder.ceremonyLifetime;
        this.operationTimeout = builder.operationTimeout;
    }

    /** Starts a settings builder with the selected profile defaults.
     * @return builder
     * @since 1.0.0 */
    @CheckReturnValue public static @NonNull Builder builder() { return new Builder(); }
    /** Returns the raw completion body limit.
     * @return maximum raw completion body bytes
     * @since 1.0.0 */
    public int getMaximumResponseBodyBytes() { return this.maximumResponseBodyBytes; }
    /** Returns the decoded client data limit.
     * @return maximum decoded clientDataJSON bytes
     * @since 1.0.0 */
    public int getMaximumClientDataJsonBytes() { return this.maximumClientDataJsonBytes; }
    /** Returns the decoded attestation object limit.
     * @return maximum decoded attestationObject bytes
     * @since 1.0.0 */
    public int getMaximumAttestationObjectBytes() { return this.maximumAttestationObjectBytes; }
    /** Returns the decoded authenticator data limit.
     * @return maximum decoded authenticatorData bytes
     * @since 1.0.0 */
    public int getMaximumAuthenticatorDataBytes() { return this.maximumAuthenticatorDataBytes; }
    /** Returns the active credential exclusion limit.
     * @return maximum active credential IDs admitted before enrollment is refused
     * @since 1.0.0 */
    public int getMaximumExcludedCredentials() { return this.maximumExcludedCredentials; }
    /** Returns the validity duration of a ceremony.
     * @return ceremony validity duration
     * @since 1.0.0 */
    public @NonNull Duration getCeremonyLifetime() { return this.ceremonyLifetime; }
    /** Returns the caller-thread operation budget.
     * @return caller-thread operation budget
     * @since 1.0.0 */
    public @NonNull Duration getOperationTimeout() { return this.operationTimeout; }
    /** Redacts configuration details.
     * @return fixed description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "WebAuthnSettings{<redacted>}"; }

    /** One caller-thread settings builder. Passing null to a setter restores its default.
     * @since 1.0.0 */
    @NotThreadSafe public static final class Builder {
        private int maximumResponseBodyBytes = DEFAULT_BODY;
        private int maximumClientDataJsonBytes = DEFAULT_CLIENT_DATA;
        private int maximumAttestationObjectBytes = DEFAULT_ATTESTATION;
        private int maximumAuthenticatorDataBytes = DEFAULT_AUTHENTICATOR_DATA;
        private int maximumExcludedCredentials = DEFAULT_EXCLUSIONS;
        private @NonNull Duration ceremonyLifetime = DEFAULT_LIFETIME;
        private @NonNull Duration operationTimeout = DEFAULT_TIMEOUT;
        private Builder() { }

        /** Sets the raw completion body limit.
         * @param value byte limit, 1 through 262144, or null for default
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder maximumResponseBodyBytes(@Nullable Integer value) {
            this.maximumResponseBodyBytes = bounded(value, DEFAULT_BODY, 1, 256 * 1_024);
            return this;
        }
        /** Sets the decoded client data limit.
         * @param value byte limit, 1 through 16384, or null for default
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder maximumClientDataJsonBytes(@Nullable Integer value) {
            this.maximumClientDataJsonBytes = bounded(value, DEFAULT_CLIENT_DATA, 1, 16 * 1_024);
            return this;
        }
        /** Sets the decoded attestation object limit.
         * @param value byte limit, 1 through 65536, or null for default
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder maximumAttestationObjectBytes(@Nullable Integer value) {
            this.maximumAttestationObjectBytes = bounded(value, DEFAULT_ATTESTATION, 1, 64 * 1_024);
            return this;
        }
        /** Sets the decoded authenticator data limit.
         * @param value byte limit, 37 through 32768, or null for default
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder maximumAuthenticatorDataBytes(@Nullable Integer value) {
            this.maximumAuthenticatorDataBytes = bounded(value, DEFAULT_AUTHENTICATOR_DATA, 37, 32 * 1_024);
            return this;
        }
        /** Sets the active credential exclusion limit.
         * @param value enrollment exclusion limit, 1 through 64, or null for default
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder maximumExcludedCredentials(@Nullable Integer value) {
            this.maximumExcludedCredentials = bounded(value, DEFAULT_EXCLUSIONS, 1, 64);
            return this;
        }
        /** Sets the ceremony validity duration.
         * @param value 30 seconds through 10 minutes, or null for default
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder ceremonyLifetime(@Nullable Duration value) {
            this.ceremonyLifetime = bounded(value, DEFAULT_LIFETIME,
                    Duration.ofSeconds(30), Duration.ofMinutes(10));
            return this;
        }
        /** Sets the caller-thread operation budget.
         * @param value 100 milliseconds through 30 seconds, or null for default
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder operationTimeout(@Nullable Duration value) {
            this.operationTimeout = bounded(value, DEFAULT_TIMEOUT,
                    Duration.ofMillis(100), Duration.ofSeconds(30));
            return this;
        }
        /** Builds a stable settings snapshot.
         * @return immutable settings
         * @since 1.0.0 */
        @CheckReturnValue public @NonNull WebAuthnSettings build() { return new WebAuthnSettings(this); }
        /** @return fixed description
         * @since 1.0.0 */
        @Override public @NonNull String toString() { return "WebAuthnSettings.Builder{<redacted>}"; }
    }

    private static int bounded(@Nullable Integer value, int defaultValue, int minimum, int maximum) {
        if (value == null) return defaultValue;
        if (value < minimum || value > maximum) throw new IllegalArgumentException("Invalid WebAuthn limit");
        return value;
    }

    private static @NonNull Duration bounded(@Nullable Duration value, @NonNull Duration defaultValue,
            @NonNull Duration minimum, @NonNull Duration maximum) {
        if (value == null) return defaultValue;
        if (value.compareTo(minimum) < 0 || value.compareTo(maximum) > 0)
            throw new IllegalArgumentException("Invalid WebAuthn duration");
        return value;
    }
}
