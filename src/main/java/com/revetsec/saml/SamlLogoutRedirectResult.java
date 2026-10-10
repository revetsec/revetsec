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
 * Result of preparing a signed outbound logout Redirect.
 *
 * @since 1.0.0
 */
@Immutable
public sealed interface SamlLogoutRedirectResult permits SamlLogoutRedirectResult.Prepared,
        SamlLogoutRedirectResult.Rejected, SamlLogoutRedirectResult.Unavailable {
    /**
     * A browser Redirect with pending state to retain until the response.
     *
     * @since 1.0.0
     */
    @Immutable
    final class Prepared implements SamlLogoutRedirectResult {
        private final @NonNull URI redirectUri;
        private final @NonNull PendingSamlLogout pending;
        Prepared(@NonNull URI redirectUri, @NonNull PendingSamlLogout pending) {
            this.redirectUri = redirectUri;
            this.pending = pending;
        }
        /**
         * Returns the signed IdP Redirect.
         *
         * @return URI
         * @since 1.0.0
         */
        public @NonNull URI getRedirectUri() { return redirectUri; }
        /**
         * Returns pending logout state.
         *
         * @return pending state
         * @since 1.0.0
         */
        public @NonNull PendingSamlLogout getPendingLogout() { return pending; }
    }
    /**
     * Session or connection configuration is incompatible.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Rejected implements SamlLogoutRedirectResult {
        /** No Redirect was prepared. */ CONFIGURATION
    }
    /**
     * Randomness, clock or signing failed.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Unavailable implements SamlLogoutRedirectResult {
        /** No Redirect was prepared. */ INSTANCE
    }
}
