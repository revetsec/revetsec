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
package com.revetsec.saml;

import com.google.errorprone.annotations.CheckReturnValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.net.URI;
import java.nio.CharBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Optional policy on an SP-initiated AuthnRequest. The options are sealed into pending state and
 * checked again at completion. Application data is an opaque local hint, never a RelayState URL.
 *
 * @since 1.0.0
 */
@Immutable
public final class SamlAuthenticationRequestOptions {
    private final boolean forceAuthn;
    private final boolean passive;
    private final @NonNull List<@NonNull String> contextClassRefs;
    private final @Nullable String applicationData;

    private SamlAuthenticationRequestOptions(@NonNull Builder builder) {
        this.forceAuthn = builder.forceAuthn;
        this.passive = builder.passive;
        this.contextClassRefs = List.copyOf(builder.contextClassRefs);
        this.applicationData = builder.applicationData;
    }

    /**
     * Starts optional request-policy configuration.
     *
     * @return a request-options builder
     * @since 1.0.0
     */
    public static @NonNull Builder builder() { return new Builder(); }

    /**
     * Reports whether fresh authentication was requested.
     *
     * @return true when the IdP must freshly authenticate the principal
     * @since 1.0.0
     */
    public @NonNull Boolean isForceAuthn() { return forceAuthn; }
    /**
     * Reports whether noninteractive authentication was requested.
     *
     * @return true when the IdP must not visibly interact with the principal
     * @since 1.0.0
     */
    public @NonNull Boolean isPassive() { return passive; }
    /**
     * Returns the exact requested authentication context classes.
     *
     * @return exact accepted authentication context class URIs
     * @since 1.0.0
     */
    public @NonNull List<@NonNull String> getRequestedAuthnContextClassRefs() { return contextClassRefs; }
    /**
     * Returns the application-owned local hint.
     *
     * @return application-owned local hint, if supplied
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getApplicationData() { return Optional.ofNullable(applicationData); }

    /** @return redacted description @since 1.0.0 */
    @Override public @NonNull String toString() {
        return "SamlAuthenticationRequestOptions{<redacted>}";
    }

    /**
     * Mutable options builder.
     * @since 1.0.0
     */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Builder {
        private boolean forceAuthn;
        private boolean passive;
        private @NonNull List<@NonNull String> contextClassRefs = List.of();
        private @Nullable String applicationData;
        private Builder() { }

        /**
         * Requests a fresh authentication; null restores false.
         * @param value policy value or null
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder forceAuthn(@Nullable Boolean value) {
            forceAuthn = value != null && value;
            return this;
        }

        /**
         * Requests noninteractive authentication; null restores false.
         * @param value policy value or null
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder passive(@Nullable Boolean value) {
            passive = value != null && value;
            return this;
        }

        /**
         * Requests exact authentication context classes. Empty or null restores no restriction.
         * @param values absolute class URIs
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder requestedAuthnContextClassRefs(@Nullable List<@NonNull String> values) {
            if (values == null || values.isEmpty()) { contextClassRefs = List.of(); return this; }
            if (values.size() > 8) throw new IllegalArgumentException("Too many SAML authentication contexts");
            for (String value : values) {
                Objects.requireNonNull(value);
                if (value.isEmpty() || value.length() > 512) throw new IllegalArgumentException("Invalid SAML context");
                try { if (!URI.create(value).isAbsolute()) throw new IllegalArgumentException("Invalid SAML context"); }
                catch (IllegalArgumentException exception) { throw new IllegalArgumentException("Invalid SAML context"); }
            }
            contextClassRefs = List.copyOf(values);
            return this;
        }

        /**
         * Carries an opaque local hint in sealed pending state; null clears it.
         * @param value local hint, or null
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder applicationData(@Nullable String value) {
            if (value != null) {
                try {
                    if (StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                            .onUnmappableCharacter(CodingErrorAction.REPORT)
                            .encode(CharBuffer.wrap(value)).remaining() > 512)
                        throw new IllegalArgumentException("SAML application data is too long");
                } catch (java.nio.charset.CharacterCodingException exception) {
                    throw new IllegalArgumentException("Invalid SAML application data");
                }
            }
            applicationData = value;
            return this;
        }

        /**
         * Creates immutable options.
         * @return request options
         * @since 1.0.0
         */
        public @NonNull SamlAuthenticationRequestOptions build() {
            if (forceAuthn && passive) throw new IllegalArgumentException("Conflicting SAML request options");
            return new SamlAuthenticationRequestOptions(this);
        }
    }
}
