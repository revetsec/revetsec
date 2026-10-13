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
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * Immutable, explicitly selected SCIM compatibility features. Presets are configuration only;
 * no feature is inferred from User-Agent, credentials, payload, or earlier traffic.
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimCompatibility {
    private final @NonNull Set<@NonNull ScimCompatibilityFeature> features;
    private ScimCompatibility(@NonNull Builder builder) { features = builder.features; }

    /**
     * Starts strict configuration with no enabled features.
     * @return a new builder
     * @since 1.0.0
     */
    public static @NonNull Builder builder() { return new Builder(); }

    /**
     * Returns strict configuration with no enabled compatibility relaxations.
     * @return the shared strict snapshot
     * @since 1.0.0
     */
    public static @NonNull ScimCompatibility strictInstance() { return Defaults.STRICT; }

    /**
     * Returns the exact reviewed Microsoft Entra ID feature set. Scalar Enterprise manager
     * values and dropping unknown attributes remain disabled.
     * @return the shared Microsoft Entra ID snapshot
     * @since 1.0.0
     */
    public static @NonNull ScimCompatibility microsoftEntraIdInstance() { return Defaults.ENTRA; }

    /**
     * Returns the reviewed Okta feature set: operation-name casing and identical PATCH id echo.
     * @return the shared Okta snapshot
     * @since 1.0.0
     */
    public static @NonNull ScimCompatibility oktaInstance() { return Defaults.OKTA; }

    /**
     * Returns the complete immutable selected feature set.
     * @return the immutable feature set
     * @since 1.0.0
     */
    public @NonNull Set<@NonNull ScimCompatibilityFeature> getFeatures() { return features; }

    /**
     * Compares the selected features.
     * @param other the comparison value
     * @return whether selected feature sets are equal
     * @since 1.0.0
     */
    @Override public boolean equals(@Nullable Object other) {
        return this == other || other instanceof ScimCompatibility value && features.equals(value.features);
    }

    /**
     * Returns the selected-feature hash.
     * @return the selected-feature hash
     * @since 1.0.0
     */
    @Override public int hashCode() { return features.hashCode(); }

    /**
     * Returns a bounded description containing only the number of selected fixed features.
     * @return a bounded configuration description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "ScimCompatibility{features=" + features.size() + "}"; }

    private static final class Defaults {
        private static final @NonNull ScimCompatibility STRICT = builder().build();
        private static final @NonNull ScimCompatibility ENTRA = builder().features(Set.of(
                ScimCompatibilityFeature.PATCH_OPERATION_NAME_CASE_INSENSITIVE,
                ScimCompatibilityFeature.BOOLEAN_STRINGS,
                ScimCompatibilityFeature.PATCH_REMOVE_WITH_VALUE,
                ScimCompatibilityFeature.PATCH_VALUE_PATH_UPSERT,
                ScimCompatibilityFeature.PATCH_VALUE_OBJECT_ATTRIBUTE_PATHS,
                ScimCompatibilityFeature.FILTER_VALUE_PATH_SUB_ATTRIBUTE_COMPARISON,
                ScimCompatibilityFeature.INFER_MISSING_EXTENSION_SCHEMAS,
                ScimCompatibilityFeature.IGNORE_UNDECLARED_SCHEMA_URIS)).build();
        private static final @NonNull ScimCompatibility OKTA = builder().features(Set.of(
                ScimCompatibilityFeature.PATCH_OPERATION_NAME_CASE_INSENSITIVE,
                ScimCompatibilityFeature.PATCH_READ_ONLY_ID_ECHO)).build();
        private Defaults() {}
    }

    /**
     * Mutable, non-thread-safe complete feature-set configuration.
     * @since 1.0.0
     */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Builder {
        private @NonNull Set<@NonNull ScimCompatibilityFeature> features = Set.of();
        private Builder() {}

        /**
         * Replaces and snapshots all features; null restores the empty strict set.
         * @param value the feature set, or null for strict behavior
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder features(@Nullable Set<@NonNull ScimCompatibilityFeature> value) {
            if (value == null || value.isEmpty()) features = Set.of();
            else {
                if (value.size() > ScimCompatibilityFeature.values().length)
                    throw new IllegalArgumentException("SCIM compatibility feature count exceeds its inventory.");
                features = Collections.unmodifiableSet(EnumSet.copyOf(value));
            }
            return this;
        }

        /**
         * Creates an immutable complete feature snapshot without callbacks.
         * @return selected compatibility configuration
         * @since 1.0.0
         */
        public @NonNull ScimCompatibility build() { return new ScimCompatibility(this); }
    }
}
