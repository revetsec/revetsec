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
import java.net.URI;

/**
 * A prepared SP-initiated login, a configuration rejection, or an unavailable signing/time source.
 * Only {@link Prepared} can be sent to the browser.
 *
 * @since 1.0.0
 */
@Immutable
public sealed interface SamlAuthenticationRequestResult permits SamlAuthenticationRequestResult.Prepared,
        SamlAuthenticationRequestResult.PostPrepared, SamlAuthenticationRequestResult.Rejected,
        SamlAuthenticationRequestResult.Unavailable {
    /**
     * A Redirect-binding request and the pending state that must accompany the browser.
     *
     * @since 1.0.0
     */
    @Immutable
    final class Prepared implements SamlAuthenticationRequestResult {
        private final @NonNull URI redirectUri;
        private final @NonNull PendingSamlAuthentication pending;
        Prepared(@NonNull URI redirectUri, @NonNull PendingSamlAuthentication pending) {
            this.redirectUri = redirectUri;
            this.pending = pending;
        }
        /**
         * Returns the IdP redirect URI.
         *
         * @return URI
         * @since 1.0.0
         */
        public @NonNull URI getRedirectUri() { return redirectUri; }
        /**
         * Returns the pending state for this request.
         *
         * @return pending login
         * @since 1.0.0
         */
        public @NonNull PendingSamlAuthentication getPendingAuthentication() { return pending; }
        /**
         * Redacts the request and state.
         *
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "SamlAuthenticationRequestResult.Prepared{<redacted>}"; }
    }

    /**
     * A POST-binding request and its browser pending state.
     *
     * @since 1.0.0
     */
    @Immutable
    final class PostPrepared implements SamlAuthenticationRequestResult {
        private final @NonNull SamlPostForm form;
        private final @NonNull PendingSamlAuthentication pending;
        PostPrepared(@NonNull SamlPostForm form, @NonNull PendingSamlAuthentication pending) {
            this.form = form;
            this.pending = pending;
        }
        /**
         * Returns the IdP-bound form.
         *
         * @return form
         * @since 1.0.0
         */
        public @NonNull SamlPostForm getPostForm() { return form; }
        /**
         * Returns the pending login state.
         *
         * @return pending state
         * @since 1.0.0
         */
        public @NonNull PendingSamlAuthentication getPendingAuthentication() { return pending; }
        /**
         * Redacts the request.
         *
         * @return redacted description
         * @since 1.0.0
         */
        @Override public @NonNull String toString() {
            return "SamlAuthenticationRequestResult.PostPrepared{<redacted>}";
        }
    }

    /**
     * A local configuration rejection discovered when preparing a request.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Rejected implements SamlAuthenticationRequestResult {
        /** The IdP requires signing, but the SP cannot prepare a valid request. */ CONFIGURATION
    }

    /**
     * The time, randomness or signing capability was unavailable.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Unavailable implements SamlAuthenticationRequestResult {
        /** The operation could not produce a request. */ INSTANCE
    }
}
