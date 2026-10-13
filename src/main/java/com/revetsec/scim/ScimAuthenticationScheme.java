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

package com.revetsec.scim;

import com.google.errorprone.annotations.CheckReturnValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.net.URI;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Immutable description of an application authentication scheme; it performs no authentication.
 * Specification and documentation links are trusted bounded HTTP(S) URIs and are never fetched.
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimAuthenticationScheme {
    private final @NonNull String type;
    private final @NonNull String name;
    private final @NonNull String description;
    private final boolean primary;
    private final @Nullable URI specUri;
    private final @Nullable URI documentationUri;

    private ScimAuthenticationScheme(@NonNull Builder builder) {
        if (builder.name == null || builder.description == null)
            throw new IllegalStateException("A SCIM authentication scheme requires name and description.");
        type = builder.type;
        name = builder.name;
        description = builder.description;
        primary = Boolean.TRUE.equals(builder.primary);
        specUri = builder.specUri;
        documentationUri = builder.documentationUri;
    }

    /**
     * Starts a standard authentication scheme with its exact SCIM type spelling.
     * @param type oauth, oauth2, oauthbearertoken, httpbasic or httpdigest
     * @return a new builder
     * @since 1.0.0
     */
    public static @NonNull Builder withType(@NonNull String type) {
        ScimSchemas.requireName(Objects.requireNonNull(type));
        if (!Set.of("oauth", "oauth2", "oauthbearertoken", "httpbasic", "httpdigest").contains(type))
            throw new IllegalArgumentException("Unsupported standard SCIM authentication scheme type.");
        return new Builder(type);
    }

    /**
     * Returns the exact standard scheme type.
     * @return the exact standard scheme type
     * @since 1.0.0
     */
    public @NonNull String getType() { return type; }

    /**
     * Returns the human-readable scheme name.
     * @return the human-readable scheme name
     * @since 1.0.0
     */
    public @NonNull String getName() { return name; }

    /**
     * Returns the scheme description.
     * @return the scheme description
     * @since 1.0.0
     */
    public @NonNull String getDescription() { return description; }

    /**
     * Returns whether this is the preferred scheme.
     * @return whether this is the preferred scheme
     * @since 1.0.0
     */
    public @NonNull Boolean isPrimary() { return primary; }

    /**
     * Returns the optional specification URI.
     * @return the optional specification URI
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull URI> getSpecUri() { return Optional.ofNullable(specUri); }

    /**
     * Returns the optional documentation URI.
     * @return the optional documentation URI
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull URI> getDocumentationUri() { return Optional.ofNullable(documentationUri); }

    /**
     * Compares all scheme description characteristics.
     * @param other the comparison value
     * @return whether descriptions are equal
     * @since 1.0.0
     */
    @Override public boolean equals(@Nullable Object other) {
        return this == other || other instanceof ScimAuthenticationScheme value && primary == value.primary
                && type.equals(value.type) && name.equals(value.name) && description.equals(value.description)
                && Objects.equals(specUri, value.specUri) && Objects.equals(documentationUri, value.documentationUri);
    }

    /**
     * Returns the scheme description hash.
     * @return the description hash
     * @since 1.0.0
     */
    @Override public int hashCode() { return Objects.hash(type, name, description, primary, specUri, documentationUri); }

    /**
     * Returns a fixed redacted description.
     * @return a fixed redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "ScimAuthenticationScheme{<redacted>}"; }

    /**
     * Mutable, non-thread-safe authentication-scheme description configuration.
     * @since 1.0.0
     */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Builder {
        private final @NonNull String type;
        private @Nullable String name;
        private @Nullable String description;
        private @Nullable Boolean primary;
        private @Nullable URI specUri;
        private @Nullable URI documentationUri;
        private Builder(@NonNull String type) { this.type = type; }

        /**
         * Sets name; null restores unset.
         * @param value the setting, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder name(@Nullable String value) { name = value == null ? null : ScimSchemas.requireName(value); return this; }

        /**
         * Sets description; null restores unset.
         * @param value the setting, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder description(@Nullable String value) { description = value == null ? null : ScimSchemas.requireText(value, true); return this; }

        /**
         * Sets primary; null restores false.
         * @param value the setting, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder primary(@Nullable Boolean value) { primary = value; return this; }

        /**
         * Sets specUri; null restores absent.
         * @param value the setting, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder specUri(@Nullable URI value) { specUri = value == null ? null : ScimSchemas.requireDocumentationUri(value); return this; }

        /**
         * Sets documentationUri; null restores absent.
         * @param value the setting, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder documentationUri(@Nullable URI value) { documentationUri = value == null ? null : ScimSchemas.requireDocumentationUri(value); return this; }

        /**
         * Validates required descriptions and creates an immutable scheme.
         * @return the authentication-scheme description
         * @since 1.0.0
         */
        public @NonNull ScimAuthenticationScheme build() { return new ScimAuthenticationScheme(this); }
    }
}
