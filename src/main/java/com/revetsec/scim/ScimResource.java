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
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.revetsec.json.*;
import com.revetsec.internal.json.AsciiCase;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import static java.util.Objects.requireNonNull;

/** Immutable schema-normalized application data. Intentional getters expose provisioning data;
 * diagnostics never expose it. Trusted construction is not request provenance or authorization.
 *
     * @since 1.0.0
 */
@Immutable
public final class ScimResource {
    private final @NonNull ScimResourceType resourceType;
    private final @NonNull JsonObject document;
    private final @Nullable Object semanticContext;
    private final long constructionWorkUnits;
    private ScimResource(@NonNull ScimResourceType type, @NonNull JsonObject document,
            @Nullable Object context, long constructionWorkUnits) {
        this.resourceType = type; this.document = document; this.semanticContext = context;
        this.constructionWorkUnits = constructionWorkUnits;
    }
    static @NonNull ScimResource parsed(@NonNull ScimResourceType type, @NonNull JsonObject document, @NonNull Object context) {
        return parsed(type, document, context, ScimLimits.fromDefaults().getMaximumWorkUnits());
    }
    static @NonNull ScimResource parsed(@NonNull ScimResourceType type, @NonNull JsonObject document,
            @NonNull Object context, long workUnits) {
        return new ScimResource(type, document, context, workUnits);
    }
    @Nullable Object getSemanticContext() { return semanticContext; }
    /** Starts trusted data construction.
     * @param resourceType the schema registration
     * @return a builder
     * @since 1.0.0 */
    @CheckReturnValue public static @NonNull Builder withResourceType(@NonNull ScimResourceType resourceType) { return new Builder(requireNonNull(resourceType)); }
    /** Starts trusted data copying.
     * @return a copier
     * @since 1.0.0 */
    @CheckReturnValue public @NonNull Copier copy() { return new Copier(this); }
    /** Returns the resource type.
     * @return the resource type
     * @since 1.0.0 */
    public @NonNull ScimResourceType getResourceType() { return resourceType; }
    /** Intentionally exposes the immutable normalized document, including transient write-only data.
     *
     * @return the document
     * @since 1.0.0 */
    public @NonNull JsonObject getDocument() { return document; }
    /** Finds a registered attribute or subattribute. Multi-valued subattributes return an array.
     *
     * @param path the path
     * @return the assigned value, when present
     * @since 1.0.0 */
    public @NonNull Optional<@NonNull JsonValue> find(@NonNull ScimAttributePath path) {
        requireNonNull(path);
        Optional<ScimAttributePath> bound = ScimSchemas.canonicalPath(resourceType, path);
        if (bound.isEmpty()) return Optional.empty();
        ScimAttributePath canonical = bound.orElseThrow();
        JsonObject container = document;
        if (canonical.getSchemaId().isPresent() && !AsciiCase.fold(canonical.getSchemaId().orElseThrow()).equals(AsciiCase.fold(resourceType.getSchema().getId()))) {
            Optional<JsonObject> extension = getExtension(canonical.getSchemaId().orElseThrow());
            if (extension.isEmpty()) return Optional.empty();
            container = extension.orElseThrow();
        }
        Optional<JsonValue> value = container.find(canonical.getAttributeName());
        if (canonical.getSubAttributeName().isEmpty() || value.isEmpty()) return value;
        String sub = canonical.getSubAttributeName().orElseThrow();
        JsonValue assigned = value.orElseThrow();
        if (assigned instanceof JsonObject object) return object.find(sub);
        if (assigned instanceof JsonArray array) {
            List<JsonValue> found = new ArrayList<>();
            for (JsonValue element : array.getElements()) if (element instanceof JsonObject object) object.find(sub).ifPresent(found::add);
            return found.isEmpty() ? Optional.empty() : Optional.of(JsonArray.fromElements(found));
        }
        return Optional.empty();
    }
    /** Finds a registered extension without fetching its identifier.
     * @param schemaId the schema identifier
     * @return the extension
     * @since 1.0.0 */
    public @NonNull Optional<@NonNull JsonObject> getExtension(@NonNull String schemaId) {
        requireNonNull(schemaId);
        for (ScimSchemaExtension extension : resourceType.getSchemaExtensions()) if (AsciiCase.fold(extension.getSchema().getId()).equals(AsciiCase.fold(schemaId))) {
            JsonValue value = document.getMembers().get(extension.getSchema().getId());
            return value instanceof JsonObject object ? Optional.of(object) : Optional.empty();
        }
        return Optional.empty();
    }
    /** Returns the server-assigned identifier.
     * @return the identifier
     * @since 1.0.0 */
    public @NonNull Optional<@NonNull String> getId() { return document.findString("id"); }
    /** Returns the client identifier.
     * @return the identifier
     * @since 1.0.0 */
    public @NonNull Optional<@NonNull String> getExternalId() { return document.findString("externalId"); }
    /** Returns the version entity tag.
     * @return the version
     * @since 1.0.0 */
    public @NonNull Optional<@NonNull String> getVersion() { return metaString("version"); }
    /** Returns the server-assigned location without fetching it.
     * @return the location
     * @since 1.0.0 */
    public @NonNull Optional<@NonNull URI> getLocation() { return metaString("location").map(URI::create); }
    /** Returns the creation instant; fractional seconds beyond nanosecond precision are truncated.
     * @return the instant
     * @since 1.0.0 */
    public @NonNull Optional<@NonNull Instant> getCreated() { return metaString("created").map(ScimResourceValidation::instant); }
    /** Returns the last modification instant; fractional seconds beyond nanosecond precision are truncated.
     * @return the instant
     * @since 1.0.0 */
    public @NonNull Optional<@NonNull Instant> getLastModified() { return metaString("lastModified").map(ScimResourceValidation::instant); }
    private @NonNull Optional<@NonNull String> metaString(@NonNull String name) {
        JsonValue meta = document.getMembers().get("meta");
        return meta instanceof JsonObject object ? object.findString(name) : Optional.empty();
    }
    /** Returns a fixed redacted description.
     * @return the description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "ScimResource{document=<redacted>}"; }
    /** Trusted document construction; invalid data is a programming error.
     * @since 1.0.0 */
    @NotThreadSafe @CheckReturnValue public static final class Builder {
        private final @NonNull ScimResourceType type;
        private @Nullable JsonObject document;
        private @Nullable ScimLimits limits;
        private Builder(@NonNull ScimResourceType type) { this.type = type; }
        /** Replaces the entire document; null restores unset.
     * @param value the document
     * @return this builder
     * @since 1.0.0 */
        @CanIgnoreReturnValue public @NonNull Builder document(@Nullable JsonObject value) { document = value; return this; }
        /** Uses the provider's configured processing limits for trusted construction.
         * @param value processing limits; null restores defaults
         * @return this builder
         * @since 1.0.0 */
        @CanIgnoreReturnValue public @NonNull Builder limits(@Nullable ScimLimits value) { limits = value; return this; }
        /** Validates and normalizes trusted data.
     * @return the immutable resource
     * @since 1.0.0 */
        public @NonNull ScimResource build() {
            if (document == null) throw new IllegalStateException("A resource document is required.");
            return trusted(type, document, null, budget(limits));
        }
        /** Returns a fixed redacted description.
     * @return the description
     * @since 1.0.0 */
        @Override public @NonNull String toString() { return "ScimResource.Builder{document=<redacted>}"; }
    }
    /** Trusted copying; null restores the source document.
     * @since 1.0.0 */
    @NotThreadSafe @CheckReturnValue public static final class Copier {
        private final @NonNull ScimResource source;
        private @Nullable JsonObject document;
        private @Nullable ScimLimits limits;
        private Copier(@NonNull ScimResource source) { this.source = source; }
        /** Replaces the entire document; null restores the source.
     * @param value the document
     * @return this copier
     * @since 1.0.0 */
        @CanIgnoreReturnValue public @NonNull Copier document(@Nullable JsonObject value) { document = value; return this; }
        /** Overrides the source resource's processing limit for this copy.
         * @param value processing limits; null uses the source limit
         * @return this copier
         * @since 1.0.0 */
        @CanIgnoreReturnValue public @NonNull Copier limits(@Nullable ScimLimits value) { limits = value; return this; }
        /** Validates the replacement trusted data.
     * @return the immutable resource
     * @since 1.0.0 */
        public @NonNull ScimResource finish() { return trusted(source.resourceType,
                document == null ? source.document : document, source.semanticContext,
                limits == null ? source.constructionWorkUnits : budget(limits)); }
        /** Returns a fixed redacted description.
     * @return the description
     * @since 1.0.0 */
        @Override public @NonNull String toString() { return "ScimResource.Copier{document=<redacted>}"; }
    }
    private static long budget(@Nullable ScimLimits limits) {
        return (limits == null ? ScimLimits.fromDefaults() : limits).getMaximumWorkUnits();
    }
    private static @NonNull ScimResource trusted(@NonNull ScimResourceType type,
            @NonNull JsonObject document, @Nullable Object context, long workUnits) {
        ScimResourceValidation validation = new ScimResourceValidation(type, null,
                ScimCompatibility.strictInstance(), new ScimWork(workUnits), false);
        JsonObject normalized = validation.normalize(document);
        if (normalized == null) {
            if (validation.error() == ScimError.requestTooLargeInstance())
                throw new ScimResourceWorkLimitException();
            throw new IllegalArgumentException("The resource document violates its registered schema.");
        }
        return new ScimResource(type, normalized, context, workUnits);
    }
}
