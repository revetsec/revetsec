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
 * A validated NameID with its identity-significant qualifiers. The value alone is not a stable
 * cross-tenant account key. Transient and unspecified formats never yield a {@link SamlSubjectKey}.
 *
 * @since 1.0.0
 */
@Immutable
public final class SamlNameId {
    static final String PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    static final String TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

    private final @NonNull String value;
    private final @Nullable String format;
    private final @Nullable String nameQualifier;
    private final @Nullable String spNameQualifier;

    SamlNameId(@NonNull String value, @Nullable String format, @Nullable String nameQualifier,
            @Nullable String spNameQualifier) {
        this.value = value;
        this.format = format;
        this.nameQualifier = nameQualifier;
        this.spNameQualifier = spNameQualifier;
    }

    /**
     * Returns the validated NameID text.
     *
     * @return value
     * @since 1.0.0
     */
    public @NonNull String getValue() { return value; }
    /**
     * Returns the format URI when present.
     *
     * @return optional format
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getFormat() { return Optional.ofNullable(format); }
    /**
     * Returns the NameQualifier when present.
     *
     * @return optional qualifier
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getNameQualifier() { return Optional.ofNullable(nameQualifier); }
    /**
     * Returns the SPNameQualifier when present.
     *
     * @return optional qualifier
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getSpNameQualifier() { return Optional.ofNullable(spNameQualifier); }
    /**
     * Reports whether the format explicitly marks this identifier transient.
     *
     * @return true for transient
     * @since 1.0.0
     */
    public @NonNull Boolean isTransient() { return TRANSIENT.equals(format); }
    /**
     * Redacts the subject.
     *
     * @return redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "SamlNameId{<redacted>}"; }

    boolean persistent() { return PERSISTENT.equals(format); }
    @Nullable String rawFormat() { return format; }
    @Nullable String rawNameQualifier() { return nameQualifier; }
    @Nullable String rawSpNameQualifier() { return spNameQualifier; }
}
