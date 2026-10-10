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
 * Result of producing SP metadata. Only generated metadata is publishable.
 *
 * @since 1.0.0
 */
@Immutable
public sealed interface SamlServiceProviderMetadataResult permits
        SamlServiceProviderMetadataResult.Generated, SamlServiceProviderMetadataResult.Rejected,
        SamlServiceProviderMetadataResult.Unavailable {
    /**
     * Complete XML metadata from a configured signing credential.
     *
     * @since 1.0.0
     */
    @Immutable
    final class Generated implements SamlServiceProviderMetadataResult {
        private final @NonNull String xml;
        Generated(@NonNull String xml) { this.xml = xml; }
        /**
         * Returns complete UTF-8 XML text for publication.
         *
         * @return metadata XML
         * @since 1.0.0
         */
        public @NonNull String getXml() { return xml; }
    }
    /**
     * The SP lacks a publishable signing credential or has unsupported features.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Rejected implements SamlServiceProviderMetadataResult {
        /** No metadata was produced. */ CONFIGURATION
    }
    /**
     * XML or certificate encoding was unavailable.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Unavailable implements SamlServiceProviderMetadataResult {
        /** No metadata was produced. */ INSTANCE
    }
}
