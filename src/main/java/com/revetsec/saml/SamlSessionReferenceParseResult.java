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

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;

import static java.util.Objects.requireNonNull;

/**
 * The outcome of opening or parsing a SAML logout continuity reference. Successful parsing does not authenticate
 * an identity. Rejections release no reference, submitted value or sealed-state failure details.
 * A later release may add variants; consuming switches should include a rejecting default branch.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public abstract sealed class SamlSessionReferenceParseResult permits SamlSessionReferenceParseResult.Succeeded,
        SamlSessionReferenceParseResult.Rejected, SamlSessionReferenceParseResult.RejectedSealedState {
    SamlSessionReferenceParseResult() { }

    static @NonNull SamlSessionReferenceParseResult fromReference(@NonNull SamlSessionReference reference) {
        return new Succeeded(requireNonNull(reference));
    }
    static @NonNull SamlSessionReferenceParseResult fromRejection() { return new Rejected(); }
    static @NonNull SamlSessionReferenceParseResult fromSealedStateRejection() { return new RejectedSealedState(); }

    /**
     * Returns the outcome kind with all continuity and storage data redacted.
     * @return redacted description
     * @since 1.0.0
     */
    @Override public final @NonNull String toString() {
        return "SamlSessionReferenceParseResult{outcome=" + getClass().getSimpleName() + ", data=<redacted>}";
    }

    /**
     * A structurally parsed continuity reference, not authenticated identity.
     * @author <a href="https://www.revetkn.com">Mark Allen</a>
     * @since 1.0.0
     */
    @Immutable
    public static final class Succeeded extends SamlSessionReferenceParseResult {
        private final @NonNull SamlSessionReference reference;
        private Succeeded(@NonNull SamlSessionReference reference) { this.reference = reference; }
        /**
         * Returns the parsed logout continuity reference.
         * @return reference, never identity proof
         * @since 1.0.0
         */
        public @NonNull SamlSessionReference getReference() { return this.reference; }
    }

    /**
     * The supplied or opened reference has invalid structure.
     * @author <a href="https://www.revetkn.com">Mark Allen</a>
     * @since 1.0.0
     */
    @Immutable
    public static final class Rejected extends SamlSessionReferenceParseResult {
        private Rejected() { }
        /**
         * Returns the fixed invalid-reference reason.
         * @return rejection reason
         * @since 1.0.0
         */
        public @NonNull Reason getReason() { return Reason.INVALID_REFERENCE; }
    }

    /**
     * The sealed state did not authenticate for this type, context, keys or lifetime. Invalid and expired values
     * have the same outcome; no cryptographic failure step or plaintext is exposed.
     * @author <a href="https://www.revetkn.com">Mark Allen</a>
     * @since 1.0.0
     */
    @Immutable
    public static final class RejectedSealedState extends SamlSessionReferenceParseResult {
        private RejectedSealedState() { }
        /**
         * Returns the fixed sealed-state rejection reason.
         * @return rejection reason
         * @since 1.0.0
         */
        public @NonNull Reason getReason() { return Reason.INVALID_SEALED_STATE; }
    }

    /**
     * Fixed storage rejection categories containing no supplied data.
     * @author <a href="https://www.revetkn.com">Mark Allen</a>
     * @since 1.0.0
     */
    @Immutable
    public enum Reason {
        /** The supplied or opened continuity reference has invalid structure. */ INVALID_REFERENCE,
        /** The sealed value could not be opened; no failure step is disclosed. */ INVALID_SEALED_STATE
    }
}
