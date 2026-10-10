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
 * Preparation result for a signed response to an IdP-initiated logout request.
 *
 * @since 1.0.0
 */
@Immutable
public sealed interface SamlLogoutResponseRedirectResult permits
        SamlLogoutResponseRedirectResult.Prepared, SamlLogoutResponseRedirectResult.Rejected,
        SamlLogoutResponseRedirectResult.Unavailable {
    /**
     * A signed LogoutResponse Redirect.
     *
     * @since 1.0.0
     */
    @Immutable
    final class Prepared implements SamlLogoutResponseRedirectResult {
        private final @NonNull URI redirectUri;
        Prepared(@NonNull URI redirectUri) { this.redirectUri = redirectUri; }
        /**
         * Returns the signed IdP Redirect.
         *
         * @return URI
         * @since 1.0.0
         */
        public @NonNull URI getRedirectUri() { return redirectUri; }
    }
    /**
     * Request or IdP connection did not match this SP.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Rejected implements SamlLogoutResponseRedirectResult {
        /** No response was prepared. */ INSTANCE
    }
    /**
     * Clock, randomness or signing failed.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Unavailable implements SamlLogoutResponseRedirectResult {
        /** No response was prepared. */ INSTANCE
    }
}
