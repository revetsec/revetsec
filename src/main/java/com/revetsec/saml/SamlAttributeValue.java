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
import java.util.Optional;

/**
 * One checked SAML AttributeValue. XML with unrecognized element content, nilled values,
 * and values declared with a non-string schema type are retained as {@link Kind#COMPLEX}
 * without exposing a flattened string or an untrusted DOM node.
 *
 * @since 1.0.0
 */
@Immutable
public final class SamlAttributeValue {
    /**
     * The supported shape of this value.
     *
     * @since 1.0.0
     */
    @Immutable
    public enum Kind {
        /** An element-free text value. @since 1.0.0 */
        TEXT,
        /** A nested SAML NameID. @since 1.0.0 */
        NAME_ID,
        /** Element content whose shape is not mapped to a scalar. @since 1.0.0 */
        COMPLEX
    }

    private final @NonNull Kind kind;
    private final @Nullable String text;
    private final @Nullable SamlNameId nameId;

    private SamlAttributeValue(@NonNull Kind kind, @Nullable String text, @Nullable SamlNameId nameId) {
        this.kind = kind;
        this.text = text;
        this.nameId = nameId;
    }

    static @NonNull SamlAttributeValue text(@NonNull String value) {
        return new SamlAttributeValue(Kind.TEXT, value, null);
    }

    static @NonNull SamlAttributeValue nameId(@NonNull SamlNameId value) {
        return new SamlAttributeValue(Kind.NAME_ID, null, value);
    }

    static @NonNull SamlAttributeValue complex() {
        return new SamlAttributeValue(Kind.COMPLEX, null, null);
    }

    /**
     * Reports whether this value is text, a nested NameID, or opaque complex content.
     *
     * @return the value shape
     * @since 1.0.0
     */
    public @NonNull Kind getKind() { return kind; }

    /**
     * Reads a scalar value without flattening nested XML.
     *
     * @return text only for an element-free, non-nilled string value
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getText() { return Optional.ofNullable(text); }

    /**
     * Reads a recognized nested NameID with its qualifiers.
     *
     * @return a nested SAML NameID when it is the sole well-formed child
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull SamlNameId> getNameId() { return Optional.ofNullable(nameId); }

    /**
     * @return a redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "SamlAttributeValue{" + kind + ", <redacted>}"; }
}
