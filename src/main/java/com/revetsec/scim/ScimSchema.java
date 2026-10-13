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
import com.revetsec.internal.json.AsciiCase;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable SCIM schema registration. Schema identifiers are bounded absolute URI strings;
 * they are never fetched. Application schemas cannot override common resource attributes.
 *
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimSchema {
    private final @NonNull String id;
    private final @NonNull String name;
    private final @Nullable String description;
    private final @NonNull List<@NonNull ScimAttributeDefinition> attributes;
    private final boolean discovery;

    private ScimSchema(@NonNull Builder builder, boolean discovery) {
        if (builder.name == null)
            throw new IllegalStateException("A SCIM schema requires a name.");
        id = builder.id;
        name = builder.name;
        description = builder.description;
        attributes = builder.attributes;
        this.discovery = discovery;
        ScimSchemas.requireDistinctAttributes(attributes);
        int count = 0;
        for (ScimAttributeDefinition definition : attributes) {
            count += definition.definitionCount();
            if (!discovery) {
                if (ScimSchemas.isCommonName(definition.getName()) || AsciiCase.fold(definition.getName()).equals("$ref"))
                    throw new IllegalArgumentException("Application schemas cannot override common SCIM attributes.");
                for (ScimAttributeDefinition child : definition.getSubAttributes())
                    if (child.getType() == ScimAttributeType.COMPLEX)
                        throw new IllegalArgumentException("Nested complex application SCIM attributes are unsupported.");
            }
        }
        ScimSchemas.requireDefinitionCount(count);
    }

    /**
     * Starts an application schema with its required absolute URI identifier.
     * @param id the required schema identifier
     * @return a new builder
     * @since 1.0.0
     */
    public static @NonNull Builder withId(@NonNull String id) { return new Builder(ScimSchemas.requireSchemaId(id)); }

    /**
     * Returns the schema URI identifier.
     * @return the schema URI identifier
     * @since 1.0.0
     */
    public @NonNull String getId() { return id; }

    /**
     * Returns the human-readable schema name.
     * @return the human-readable schema name
     * @since 1.0.0
     */
    public @NonNull String getName() { return name; }

    /**
     * Returns the optional schema description.
     * @return the optional schema description
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getDescription() { return Optional.ofNullable(description); }

    /**
     * Returns the immutable schema-specific definitions. Common resource definitions are inherited.
     * @return the immutable schema-specific definitions
     * @since 1.0.0
     */
    public @NonNull List<@NonNull ScimAttributeDefinition> getAttributes() { return attributes; }

    /**
     * Returns the shared standard User schema, with reviewed RFC corrections.
     * @return the standard schema
     * @since 1.0.0
     */
    public static @NonNull ScimSchema userInstance() { return ScimSchemas.user(); }

    /**
     * Returns the shared standard Group schema, with reviewed RFC corrections.
     * @return the standard schema
     * @since 1.0.0
     */
    public static @NonNull ScimSchema groupInstance() { return ScimSchemas.group(); }

    /**
     * Returns the shared standard Enterprise User extension schema, with reviewed RFC corrections.
     * @return the standard schema
     * @since 1.0.0
     */
    public static @NonNull ScimSchema enterpriseUserInstance() { return ScimSchemas.enterpriseUser(); }

    /**
     * Returns the shared standard ServiceProviderConfig discovery schema, with reviewed RFC corrections.
     * @return the standard schema
     * @since 1.0.0
     */
    public static @NonNull ScimSchema serviceProviderConfigInstance() { return ScimSchemas.serviceProviderConfig(); }

    /**
     * Returns the shared standard ResourceType discovery schema, with reviewed RFC corrections.
     * @return the standard schema
     * @since 1.0.0
     */
    public static @NonNull ScimSchema resourceTypeInstance() { return ScimSchemas.resourceType(); }

    /**
     * Returns the shared standard Schema discovery schema, with reviewed RFC corrections.
     * @return the standard schema
     * @since 1.0.0
     */
    public static @NonNull ScimSchema schemaInstance() { return ScimSchemas.schema(); }

    /**
     * Compares semantic schema registrations, folding the schema identifier.
     * @param other the comparison value
     * @return whether registrations have equal characteristics
     * @since 1.0.0
     */
    @Override public boolean equals(@Nullable Object other) {
        return this == other || other instanceof ScimSchema schema && discovery == schema.discovery
                && AsciiCase.fold(id).equals(AsciiCase.fold(schema.id)) && name.equals(schema.name)
                && Objects.equals(description, schema.description) && attributes.equals(schema.attributes);
    }

    /**
     * Returns the semantic registration hash.
     * @return the semantic hash
     * @since 1.0.0
     */
    @Override public int hashCode() { return Objects.hash(AsciiCase.fold(id), name, description, attributes, discovery); }

    /**
     * Returns a fixed redacted description.
     * @return a fixed redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "ScimSchema{<redacted>}"; }

    boolean isDiscovery() { return discovery; }
    static @NonNull ScimSchema fromDiscovery(@NonNull Builder builder) { return new ScimSchema(builder, true); }

    /**
     * Mutable, non-thread-safe schema configuration. Null restores the stated default.
     * @since 1.0.0
     */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Builder {
        private final @NonNull String id;
        private @Nullable String name;
        private @Nullable String description;
        private @NonNull List<@NonNull ScimAttributeDefinition> attributes = List.of();
        private Builder(@NonNull String id) { this.id = id; }

        /**
         * Sets the required schema name; null restores unset.
         * @param value the name, or null to restore unset
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder name(@Nullable String value) {
            name = value == null ? null : ScimSchemas.requireName(value); return this;
        }

        /**
         * Sets the optional description; null restores absent.
         * @param value the description, or null to restore absent
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder description(@Nullable String value) {
            description = value == null ? null : ScimSchemas.requireText(value, false); return this;
        }

        /**
         * Replaces and snapshots the complete bounded definition list; null restores empty.
         * @param value definitions, or null to restore empty
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder attributes(@Nullable List<@NonNull ScimAttributeDefinition> value) {
            attributes = value == null ? List.of() : ScimSchemas.attributes(value); return this;
        }

        /**
         * Checks application-resource characteristics and creates an immutable schema.
         * @return the schema
         * @since 1.0.0
         */
        public @NonNull ScimSchema build() { return new ScimSchema(this, false); }
    }
}
