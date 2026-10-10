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
 * Result of a signed IdP-initiated LogoutRequest.
 *
 * @since 1.0.0
 */
@Immutable
public sealed interface SamlLogoutRequestResult permits SamlLogoutRequestResult.Accepted,
        SamlLogoutRequestResult.Rejected, SamlLogoutRequestResult.Unavailable,
        SamlLogoutRequestResult.Indeterminate {
    /**
     * A checked request that the application can use to locate sessions.
     *
     * @since 1.0.0
     */
    @Immutable
    final class Accepted implements SamlLogoutRequestResult {
        private final @NonNull SamlLogoutRequest request;
        Accepted(@NonNull SamlLogoutRequest request) { this.request = request; }
        /**
         * Returns the validated logout request.
         *
         * @return request
         * @since 1.0.0
         */
        public @NonNull SamlLogoutRequest getRequest() { return request; }
    }
    /**
     * A malformed, untrusted, expired or replayed request.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Rejected implements SamlLogoutRequestResult {
        /** No session data is released. */ INSTANCE
    }
    /**
     * A required local capability or replay store was unavailable.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Unavailable implements SamlLogoutRequestResult {
        /** No session data is released. */ INSTANCE
    }
    /**
     * The replay write outcome is uncertain.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Indeterminate implements SamlLogoutRequestResult {
        /** Reconciliation is required. */ INSTANCE
    }
}
