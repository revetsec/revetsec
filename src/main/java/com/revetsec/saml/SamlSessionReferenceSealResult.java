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

/**
 * The outcome of sealing SAML logout continuity fields. Only {@link Succeeded} carries a
 * storage value. Size and provider failures expose no reference, plaintext or provider details.
 * A later release may add variants; consumers should reject unknown outcomes.
 *
 * @since 1.0.0
 */
@Immutable
public sealed interface SamlSessionReferenceSealResult permits SamlSessionReferenceSealResult.Succeeded,
        SamlSessionReferenceSealResult.TooLarge, SamlSessionReferenceSealResult.Unavailable {
    /**
     * A reference sealed for the requested application context and expiry.
     *
     * @since 1.0.0
     */
    @Immutable
    final class Succeeded implements SamlSessionReferenceSealResult {
        private final @NonNull String sealedForm;
        Succeeded(@NonNull String sealedForm) { this.sealedForm = sealedForm; }
        /**
         * Returns the sealed continuity reference, which contains personal data when opened.
         *
         * @return opaque sealed storage form
         * @since 1.0.0
         */
        public @NonNull String getSealedForm() { return sealedForm; }
        /**
         * Redacts the sealed value.
         * @return redacted outcome
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "SamlSessionReferenceSealResult.Succeeded{<redacted>}"; }
    }

    /**
     * The complete reference cannot fit the sealer's configured output limit. No encryption
     * was attempted. Use trusted server-side storage or decline session creation if logout
     * continuity is required; do not truncate the reference.
     *
     * @since 1.0.0
     */
    @Immutable
    enum TooLarge implements SamlSessionReferenceSealResult {
        /** The fixed size-refusal outcome. @since 1.0.0 */
        INSTANCE;
        /**
         * Returns the fixed outcome without reference data.
         * @return fixed outcome description
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "SamlSessionReferenceSealResult.TooLarge"; }
    }

    /**
     * The cryptographic provider could not produce a sealed value. No value is available
     * to persist or return to the browser.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Unavailable implements SamlSessionReferenceSealResult {
        /** The fixed provider-unavailable outcome. @since 1.0.0 */
        INSTANCE;
        /**
         * Returns the fixed outcome without provider or reference data.
         * @return fixed outcome description
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "SamlSessionReferenceSealResult.Unavailable"; }
    }
}
