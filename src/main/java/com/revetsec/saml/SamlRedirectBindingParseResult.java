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
 * Result of bounded raw-query HTTP-Redirect binding parsing.
 *
 * @since 1.0.0
 */
@Immutable
public sealed interface SamlRedirectBindingParseResult permits
        SamlRedirectBindingParseResult.Parsed, SamlRedirectBindingParseResult.Rejected {
    /**
     * A parsed but not yet verified Redirect message.
     *
     * @since 1.0.0
     */
    @Immutable
    final class Parsed implements SamlRedirectBindingParseResult {
        private final @NonNull SamlRedirectBindingMessage message;
        Parsed(@NonNull SamlRedirectBindingMessage message) { this.message = message; }
        /**
         * Returns the message for signature and semantic validation.
         *
         * @return unverified message
         * @since 1.0.0
         */
        public @NonNull SamlRedirectBindingMessage getMessage() { return message; }
    }
    /**
     * Malformed, duplicate, oversized or unsigned query input.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Rejected implements SamlRedirectBindingParseResult {
        /** No message is released. */ INSTANCE
    }
}
