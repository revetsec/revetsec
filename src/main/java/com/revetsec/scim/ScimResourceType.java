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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable application-resource registration. Endpoints are authority-free absolute paths
 * beneath the trusted service-provider base URI, without traversal, query or fragment.
 *
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimResourceType {
    private final @NonNull String name;
    private final @Nullable String id;
    private final @Nullable String description;
    private final @NonNull String endpoint;
    private final @NonNull ScimSchema schema;
    private final @NonNull List<@NonNull ScimSchemaExtension> schemaExtensions;
    private final boolean patchResponseNoContent;
    private final int definitionCount;
    private final boolean standardGroupSchema;
    private final boolean standardUserSchema;
    private final @Nullable String standardEnterpriseManagerPath;
    private final @Nullable String standardEnterpriseManagerValuePath;

    private ScimResourceType(@NonNull Builder builder) { this(builder, false); }

    private ScimResourceType(@NonNull Builder builder, boolean allowDiscovery) {
        if (builder.endpoint == null || builder.schema == null)
            throw new IllegalStateException("A SCIM resource type requires an endpoint and core schema.");
        name = builder.name;
        id = builder.id;
        description = builder.description;
        endpoint = builder.endpoint;
        ScimSchema configured = builder.schema;
        ScimSchema builtinGroup = ScimSchema.groupInstance();
        ScimSchema builtinUser = ScimSchema.userInstance();
        // Prove every trusted builtin facet once. Equivalent rebuilt definitions
        // use builtin attribute spellings throughout binding, storage and typed views.
        standardGroupSchema = configured.equals(builtinGroup);
        standardUserSchema = configured.equals(builtinUser);
        schema = standardGroupSchema ? canonicalBuiltin(configured, builtinGroup)
                : standardUserSchema ? canonicalBuiltin(configured, builtinUser) : configured;
        if (schema.isDiscovery() && !allowDiscovery)
            throw new IllegalArgumentException("Discovery schemas cannot define application resource types.");
        List<ScimSchemaExtension> extensions = new ArrayList<>();
        ScimSchema builtinEnterprise = ScimSchema.enterpriseUserInstance();
        String managerPath = null;
        for (ScimSchemaExtension extension : builder.schemaExtensions) {
            ScimSchema extensionSchema = extension.getSchema();
            if (extensionSchema.equals(builtinEnterprise)) {
                ScimSchema canonical = canonicalBuiltin(extensionSchema, builtinEnterprise);
                extensions.add(ScimSchemaExtension.fromSchema(canonical, extension.isRequired()));
                managerPath = canonical.getId() + ":manager";
            } else extensions.add(extension);
        }
        schemaExtensions = List.copyOf(extensions);
        standardEnterpriseManagerPath = managerPath;
        standardEnterpriseManagerValuePath = managerPath == null ? null : managerPath + ".value";
        patchResponseNoContent = Boolean.TRUE.equals(builder.patchResponseNoContent);
        int definitions = ScimSchemas.commonDefinitionCount();
        for (ScimAttributeDefinition attribute : schema.getAttributes()) definitions += attribute.definitionCount();
        java.util.HashSet<@NonNull String> ids = new java.util.HashSet<>();
        ids.add(AsciiCase.fold(schema.getId()));
        for (ScimSchemaExtension extension : schemaExtensions) {
            if (!ids.add(AsciiCase.fold(extension.getSchema().getId())))
                throw new IllegalArgumentException("Duplicate SCIM schema registration.");
            for (ScimAttributeDefinition attribute : extension.getSchema().getAttributes())
                definitions += attribute.definitionCount();
        }
        ScimSchemas.requireDefinitionCount(definitions);
        definitionCount = definitions;
    }

    int definitionCount() { return definitionCount; }
    boolean hasStandardGroupSchema() { return standardGroupSchema; }
    boolean hasStandardUserSchema() { return standardUserSchema; }
    boolean isStandardEnterpriseManagerPath(@NonNull String path) { return path.equals(standardEnterpriseManagerPath); }
    boolean isStandardEnterpriseManagerValuePath(@NonNull String path) { return path.equals(standardEnterpriseManagerValuePath); }

    @SuppressWarnings("ReferenceEquality") // Preserve builtin singleton optional fast paths; rebuilt schemas remain distinct.
    private static @NonNull ScimSchema canonicalBuiltin(@NonNull ScimSchema configured, @NonNull ScimSchema builtin) {
        // The caller has already proved complete semantic equality, including all facets.
        return configured == builtin ? configured
                : ScimSchema.withId(configured.getId()).name(configured.getName())
                        .description(configured.getDescription().orElse(null))
                        .attributes(builtin.getAttributes()).build();
    }

    static @NonNull ScimResourceType discovery(@NonNull ScimSchema schema, @NonNull String name,
            @NonNull String endpoint) {
        if (!schema.isDiscovery())
            throw new IllegalArgumentException("Internal discovery registration requires a discovery schema.");
        return new ScimResourceType(withName(name).schema(schema).endpoint(endpoint), true);
    }

    /**
     * Starts a resource type with its required bounded token name.
     * @param name the resource type name
     * @return a new builder
     * @since 1.0.0
     */
    public static @NonNull Builder withName(@NonNull String name) {
        return new Builder(ScimSchemas.requireName(name));
    }

    /**
     * Returns the standard User registration with optional Enterprise extension and PATCH 200.
     * @return the shared User resource type
     * @since 1.0.0
     */
    public static @NonNull ScimResourceType userInstance() { return Defaults.USER; }

    /**
     * Returns the standard Group registration with PATCH 204.
     * @return the shared Group resource type
     * @since 1.0.0
     */
    public static @NonNull ScimResourceType groupInstance() { return Defaults.GROUP; }

    /**
     * Returns the resource type name.
     * @return the resource type name
     * @since 1.0.0
     */
    public @NonNull String getName() { return name; }

    /**
     * Returns the optional trusted discovery identifier.
     * @return the optional trusted discovery identifier
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getId() { return Optional.ofNullable(id); }

    /**
     * Returns the optional description.
     * @return the optional description
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getDescription() { return Optional.ofNullable(description); }

    /**
     * Returns the bounded endpoint path.
     * @return the bounded endpoint path
     * @since 1.0.0
     */
    public @NonNull String getEndpoint() { return endpoint; }

    /**
     * Returns the core schema.
     * An equal rebuilt standard User or Group retains its configured identifier, name and
     * description and uses the builtin attribute spellings.
     * @return the core schema
     * @since 1.0.0
     */
    public @NonNull ScimSchema getSchema() { return schema; }

    /**
     * Returns the immutable extension registrations. An equal rebuilt Enterprise User
     * extension retains its configured identifier, name, description and required
     * characteristic and uses the builtin attribute spellings.
     * @return the immutable extension registrations
     * @since 1.0.0
     */
    public @NonNull List<@NonNull ScimSchemaExtension> getSchemaExtensions() { return schemaExtensions; }

    /**
     * Returns whether an unprojected PATCH response uses 204.
     * @return whether an unprojected PATCH response uses 204
     * @since 1.0.0
     */
    public @NonNull Boolean isPatchResponseNoContent() { return patchResponseNoContent; }

    /**
     * Compares complete semantic registrations. An equal name alone is insufficient.
     * @param other the comparison value
     * @return whether all registration characteristics are equal
     * @since 1.0.0
     */
    @Override public boolean equals(@Nullable Object other) {
        return this == other || other instanceof ScimResourceType value
                && name.equals(value.name) && Objects.equals(id, value.id)
                && Objects.equals(description, value.description) && endpoint.equals(value.endpoint)
                && schema.equals(value.schema) && schemaExtensions.equals(value.schemaExtensions)
                && patchResponseNoContent == value.patchResponseNoContent;
    }

    /**
     * Returns the complete semantic registration hash.
     * @return the semantic hash
     * @since 1.0.0
     */
    @Override public int hashCode() {
        return Objects.hash(name, id, description, endpoint, schema, schemaExtensions,
                patchResponseNoContent);
    }

    /**
     * Returns a fixed redacted description.
     * @return a fixed redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "ScimResourceType{<redacted>}"; }

    private static final class Defaults {
        private static final @NonNull ScimResourceType USER = withName("User").id("User").endpoint("/Users")
                .schema(ScimSchema.userInstance()).schemaExtensions(List.of(
                        ScimSchemaExtension.fromSchema(ScimSchema.enterpriseUserInstance(), false))).build();
        private static final @NonNull ScimResourceType GROUP = withName("Group").id("Group").endpoint("/Groups")
                .schema(ScimSchema.groupInstance()).patchResponseNoContent(true).build();
        private Defaults() {}
    }

    /**
     * Mutable, non-thread-safe complete resource-type configuration.
     * Null restores absent, unset, empty or false according to the property.
     * @since 1.0.0
     */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Builder {
        private final @NonNull String name;
        private @Nullable String id;
        private @Nullable String description;
        private @Nullable String endpoint;
        private @Nullable ScimSchema schema;
        private @NonNull List<@NonNull ScimSchemaExtension> schemaExtensions = List.of();
        private @Nullable Boolean patchResponseNoContent;
        private Builder(@NonNull String name) { this.name = name; }

        /**
         * Sets id; null restores absent.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder id(@Nullable String value) { id = value == null ? null : ScimSchemas.requireIdentifier(value); return this; }

        /**
         * Sets description; null restores absent.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder description(@Nullable String value) { description = value == null ? null : ScimSchemas.requireText(value, false); return this; }

        /**
         * Sets endpoint; null restores unset.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder endpoint(@Nullable String value) { endpoint = value == null ? null : ScimSchemas.requireEndpoint(value); return this; }

        /**
         * Sets schema; null restores unset.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder schema(@Nullable ScimSchema value) { schema = value; return this; }

        /**
         * Sets schemaExtensions; null restores empty.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder schemaExtensions(@Nullable List<@NonNull ScimSchemaExtension> value) { schemaExtensions = value == null ? List.of() : ScimSchemas.extensions(value); return this; }

        /**
         * Sets patchResponseNoContent; null restores false.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder patchResponseNoContent(@Nullable Boolean value) { patchResponseNoContent = value; return this; }

        /**
         * Validates endpoint, schemas and aggregate bounds and creates an immutable registration.
         * @return the resource type
         * @since 1.0.0
         */
        public @NonNull ScimResourceType build() { return new ScimResourceType(this); }
    }
}
