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
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;

/**
 * Stable subject identifier derived from a persistent NameID. Applications key an account by
 * the pair (IdP connection ID, this subject key); this value alone is not a tenant namespace.
 *
 * @since 1.0.0
 */
@Immutable
public final class SamlSubjectKey {
    private final @NonNull String stableString;

    private SamlSubjectKey(@NonNull String stableString) { this.stableString = stableString; }

    static @NonNull SamlSubjectKey fromPersistentNameId(@NonNull SamlNameId nameId) {
        if (!nameId.persistent()) throw new IllegalArgumentException("NameID is not persistent");
        StringBuilder encoded = new StringBuilder("saml-nameid-v1:");
        add(encoded, nameId.rawFormat());
        add(encoded, nameId.getValue());
        add(encoded, nameId.rawNameQualifier());
        add(encoded, nameId.rawSpNameQualifier());
        return new SamlSubjectKey(encoded.toString());
    }

    static @NonNull SamlSubjectKey fromScopedIdentifier(@NonNull String kind, @NonNull String value) {
        StringBuilder encoded = new StringBuilder("saml-scoped-id-v1:");
        add(encoded, kind);
        add(encoded, value);
        return new SamlSubjectKey(encoded.toString());
    }

    private static void add(@NonNull StringBuilder builder, @Nullable String value) {
        if (value == null) builder.append("-1:");
        else builder.append(value.length()).append(':').append(value);
    }

    /**
     * Returns a length-prefixed stable encoding. Treat this as personal data.
     *
     * @return the stable subject key
     * @since 1.0.0
     */
    public @NonNull String toStableString() { return stableString; }

    /**
     * Redacts the subject key.
     *
     * @return redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "SamlSubjectKey{<redacted>}"; }
}
