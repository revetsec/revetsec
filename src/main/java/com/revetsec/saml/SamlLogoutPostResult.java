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
 * Result of preparing a signed outbound logout POST form.
 *
 * @since 1.0.0
 */
@Immutable
public sealed interface SamlLogoutPostResult permits SamlLogoutPostResult.Prepared,
        SamlLogoutPostResult.Rejected, SamlLogoutPostResult.Unavailable {
    /**
     * A browser POST form with pending state to retain until the response.
     *
     * @since 1.0.0
     */
    @Immutable
    final class Prepared implements SamlLogoutPostResult {
        private final @NonNull SamlPostForm postForm;
        private final @NonNull PendingSamlLogout pending;
        Prepared(@NonNull SamlPostForm postForm, @NonNull PendingSamlLogout pending) {
            this.postForm = postForm;
            this.pending = pending;
        }
        /**
         * Returns the signed IdP POST form.
         *
         * @return prepared form
         * @since 1.0.0
         */
        public @NonNull SamlPostForm getPostForm() { return postForm; }
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
    enum Rejected implements SamlLogoutPostResult {
        /** No POST form was prepared. */ CONFIGURATION
    }
    /**
     * Randomness, clock or signing failed.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Unavailable implements SamlLogoutPostResult {
        /** No POST form was prepared. */ INSTANCE
    }
}
