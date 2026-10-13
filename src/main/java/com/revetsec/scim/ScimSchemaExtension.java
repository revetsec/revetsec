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
import java.util.Objects;

/**
 * Immutable registration of a required or optional application-resource schema extension.
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimSchemaExtension {
    private final @NonNull ScimSchema schema;
    private final boolean required;
    private ScimSchemaExtension(@NonNull ScimSchema schema, boolean required) {
        this.schema = schema; this.required = required;
        if (schema.isDiscovery())
            throw new IllegalArgumentException("Discovery schemas cannot extend application resources.");
    }

    /**
     * Registers a schema extension with an explicit required characteristic.
     * @param schema the required extension schema
     * @param required whether the extension is required
     * @return the immutable registration
     * @since 1.0.0
     */
    public static @NonNull ScimSchemaExtension fromSchema(@NonNull ScimSchema schema, @NonNull Boolean required) {
        return new ScimSchemaExtension(Objects.requireNonNull(schema), Objects.requireNonNull(required));
    }

    /**
     * Returns the registered schema.
     * @return the registered schema
     * @since 1.0.0
     */
    public @NonNull ScimSchema getSchema() { return schema; }

    /**
     * Returns whether the extension is required.
     * @return whether the extension is required
     * @since 1.0.0
     */
    public @NonNull Boolean isRequired() { return required; }

    /**
     * Compares extension schema and required characteristics.
     * @param other the comparison value
     * @return whether the extensions are equal
     * @since 1.0.0
     */
    @Override public boolean equals(@Nullable Object other) {
        return this == other || other instanceof ScimSchemaExtension value
                && required == value.required && schema.equals(value.schema);
    }

    /**
     * Returns the semantic registration hash.
     * @return the semantic hash
     * @since 1.0.0
     */
    @Override public int hashCode() { return Objects.hash(schema, required); }

    /**
     * Returns a fixed redacted description.
     * @return a fixed redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "ScimSchemaExtension{<redacted>}"; }
}
