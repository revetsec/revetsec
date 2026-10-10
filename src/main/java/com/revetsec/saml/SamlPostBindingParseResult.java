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
 * The outcome of parsing the SAML HTTP-POST binding. Accepted bytes are still untrusted.
 *
 * @since 1.0.0
 */
@Immutable
public sealed interface SamlPostBindingParseResult permits SamlPostBindingParseResult.Parsed,
        SamlPostBindingParseResult.Rejected {
    /**
     * An opaque message whose XML has not yet been parsed or verified.
     *
     * @since 1.0.0
     */
    @Immutable
    final class Parsed implements SamlPostBindingParseResult {
        private final @NonNull SamlPostBindingMessage message;
        Parsed(@NonNull SamlPostBindingMessage message) { this.message = message; }
        /**
         * Returns the opaque untrusted message.
         *
         * @return the message
         * @since 1.0.0
         */
        public @NonNull SamlPostBindingMessage getMessage() { return message; }
        @Override public @NonNull String toString() { return "SamlPostBindingParseResult.Parsed{<untrusted>}"; }
    }

    /**
     * A fixed local rejection; no portion of the submitted message is included.
     *
     * @since 1.0.0
     */
    @Immutable
    final class Rejected implements SamlPostBindingParseResult {
        private final @NonNull Reason reason;
        Rejected(@NonNull Reason reason) { this.reason = reason; }
        /**
         * Returns a fixed binding rejection reason.
         *
         * @return the reason
         * @since 1.0.0
         */
        public @NonNull Reason getReason() { return reason; }
        @Override public @NonNull String toString() { return "SamlPostBindingParseResult.Rejected{" + reason + "}"; }
    }

    /**
     * Bounded input and framing failures.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Reason {
        /** The form body is empty or exceeds its cap. */ BODY_SIZE,
        /** The Content-Type fields are missing, repeated or unsupported. */ CONTENT_TYPE,
        /** The query string conflicts with the POST binding. */ QUERY,
        /** Required parameters are missing, repeated or unexpected. */ PARAMETERS,
        /** A form component is not valid UTF-8 or percent encoding. */ FORM_ENCODING,
        /** RelayState exceeds the binding cap. */ RELAY_STATE_SIZE,
        /** SAMLResponse is not strict Base64. */ BASE64,
        /** Decoded XML is empty or exceeds its cap. */ XML_SIZE
    }
}
