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
 * Result of locally parsing application-supplied IdP metadata. Parsing does not approve trust.
 *
 * @since 1.0.0
 */
@Immutable
public sealed interface SamlIdentityProviderMetadataResult permits
        SamlIdentityProviderMetadataResult.Parsed, SamlIdentityProviderMetadataResult.Rejected,
        SamlIdentityProviderMetadataResult.Unavailable {
    /**
     * One selected, structurally checked IdP descriptor.
     *
     * @since 1.0.0
     */
    @Immutable
    final class Parsed implements SamlIdentityProviderMetadataResult {
        private final @NonNull SamlIdentityProviderMetadata metadata;
        Parsed(@NonNull SamlIdentityProviderMetadata metadata) { this.metadata = metadata; }
        /**
         * Returns the checked metadata fields.
         *
         * @return metadata
         * @since 1.0.0
         */
        public @NonNull SamlIdentityProviderMetadata getMetadata() { return metadata; }
    }

    /**
     * Input was malformed, expired or unsupported.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Rejected implements SamlIdentityProviderMetadataResult {
        /** No trusted metadata is returned. */ INSTANCE
    }

    /**
     * The local parser or certificate provider was unavailable.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Unavailable implements SamlIdentityProviderMetadataResult {
        /** No trusted metadata is returned. */ INSTANCE
    }
}
