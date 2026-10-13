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
import com.revetsec.internal.Limits;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.*;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;

/** Immutable SCIM operation budgets. Each original operation uses one work budget.
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimLimits {
    private final int maximumBodyBytes;
    private final int maximumPatchOperations;
    private final int maximumJsonNodes;
    private final int maximumRawQueryBytes;
    private final int maximumQueryParameters;
    private final int maximumParameterCharacters;
    private final int maximumProjectionPaths;
    private final int maximumPageSize;
    private final int maximumCursorCharacters;
    private final int maximumConditionalHeaderBytes;
    private final int maximumConditionalTags;
    private final int maximumResponseHeaderBytes;
    private final int maximumResponseBytes;
    private final int maximumWorkUnits;
    private final @NonNull ScimFilterLimits filterLimits;

    private ScimLimits(@NonNull Builder b) {
        maximumBodyBytes =
                Limits.SCIM_BODY_SIZE.require(
                        b.maximumBodyBytes == null
                                ? Limits.SCIM_BODY_SIZE.getDefaultIntValue()
                                : b.maximumBodyBytes);
        maximumPatchOperations =
                Limits.SCIM_PATCH_OPERATIONS.require(
                        b.maximumPatchOperations == null
                                ? Limits.SCIM_PATCH_OPERATIONS.getDefaultIntValue()
                                : b.maximumPatchOperations);
        maximumJsonNodes =
                Limits.SCIM_JSON_NODES.require(
                        b.maximumJsonNodes == null
                                ? Limits.SCIM_JSON_NODES.getDefaultIntValue()
                                : b.maximumJsonNodes);
        maximumRawQueryBytes =
                Limits.SCIM_RAW_QUERY_BYTES.require(
                        b.maximumRawQueryBytes == null
                                ? Limits.SCIM_RAW_QUERY_BYTES.getDefaultIntValue()
                                : b.maximumRawQueryBytes);
        maximumQueryParameters =
                Limits.SCIM_QUERY_PARAMETERS.require(
                        b.maximumQueryParameters == null
                                ? Limits.SCIM_QUERY_PARAMETERS.getDefaultIntValue()
                                : b.maximumQueryParameters);
        maximumParameterCharacters =
                Limits.SCIM_PARAMETER_CHARACTERS.require(
                        b.maximumParameterCharacters == null
                                ? Limits.SCIM_PARAMETER_CHARACTERS.getDefaultIntValue()
                                : b.maximumParameterCharacters);
        maximumProjectionPaths =
                Limits.SCIM_PROJECTION_PATHS.require(
                        b.maximumProjectionPaths == null
                                ? Limits.SCIM_PROJECTION_PATHS.getDefaultIntValue()
                                : b.maximumProjectionPaths);
        maximumPageSize =
                Limits.SCIM_PAGE_SIZE.require(
                        b.maximumPageSize == null
                                ? Limits.SCIM_PAGE_SIZE.getDefaultIntValue()
                                : b.maximumPageSize);
        maximumCursorCharacters =
                Limits.SCIM_CURSOR_CHARACTERS.require(
                        b.maximumCursorCharacters == null
                                ? Limits.SCIM_CURSOR_CHARACTERS.getDefaultIntValue()
                                : b.maximumCursorCharacters);
        maximumConditionalHeaderBytes =
                Limits.SCIM_CONDITIONAL_HEADER_BYTES.require(
                        b.maximumConditionalHeaderBytes == null
                                ? Limits.SCIM_CONDITIONAL_HEADER_BYTES.getDefaultIntValue()
                                : b.maximumConditionalHeaderBytes);
        maximumConditionalTags =
                Limits.SCIM_CONDITIONAL_TAGS.require(
                        b.maximumConditionalTags == null
                                ? Limits.SCIM_CONDITIONAL_TAGS.getDefaultIntValue()
                                : b.maximumConditionalTags);
        maximumResponseHeaderBytes =
                Limits.SCIM_RESPONSE_HEADER_BYTES.require(
                        b.maximumResponseHeaderBytes == null
                                ? Limits.SCIM_RESPONSE_HEADER_BYTES.getDefaultIntValue()
                                : b.maximumResponseHeaderBytes);
        maximumResponseBytes =
                Limits.SCIM_RESPONSE_BYTES.require(
                        b.maximumResponseBytes == null
                                ? Limits.SCIM_RESPONSE_BYTES.getDefaultIntValue()
                                : b.maximumResponseBytes);
        maximumWorkUnits =
                Limits.SCIM_WORK_UNITS.require(
                        b.maximumWorkUnits == null
                                ? Limits.SCIM_WORK_UNITS.getDefaultIntValue()
                                : b.maximumWorkUnits);
        filterLimits = b.filterLimits == null ? ScimFilterLimits.defaultInstance() : b.filterLimits;
    }

    /** Starts budget configuration.
     * @return a fresh builder
     * @since 1.0.0
     */
    public static @NonNull Builder builder() {
        return new Builder();
    }

    /** Creates a default snapshot.
     * @return defaults
     * @since 1.0.0
     */
    public static @NonNull ScimLimits fromDefaults() {
        return builder().build();
    }

    /** Returns the maximumBodyBytes budget.
     * @return configured inclusive bound
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumBodyBytes() {
        return maximumBodyBytes;
    }

    /** Returns the maximumPatchOperations budget.
     * @return configured inclusive bound
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumPatchOperations() {
        return maximumPatchOperations;
    }

    /** Returns the maximumJsonNodes budget.
     * @return configured inclusive bound
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumJsonNodes() {
        return maximumJsonNodes;
    }

    /** Returns the maximumRawQueryBytes budget.
     * @return configured inclusive bound
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumRawQueryBytes() {
        return maximumRawQueryBytes;
    }

    /** Returns the maximumQueryParameters budget.
     * @return configured inclusive bound
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumQueryParameters() {
        return maximumQueryParameters;
    }

    /** Returns the maximumParameterCharacters budget.
     * @return configured inclusive bound
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumParameterCharacters() {
        return maximumParameterCharacters;
    }

    /** Returns the maximumProjectionPaths budget.
     * @return configured inclusive bound
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumProjectionPaths() {
        return maximumProjectionPaths;
    }

    /** Returns the maximumPageSize budget.
     * @return configured inclusive bound
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumPageSize() {
        return maximumPageSize;
    }

    /** Returns the maximumCursorCharacters budget.
     * @return configured inclusive bound
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumCursorCharacters() {
        return maximumCursorCharacters;
    }

    /** Returns the maximumConditionalHeaderBytes budget.
     * @return configured inclusive bound
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumConditionalHeaderBytes() {
        return maximumConditionalHeaderBytes;
    }

    /** Returns the maximumConditionalTags budget.
     * @return configured inclusive bound
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumConditionalTags() {
        return maximumConditionalTags;
    }

    /** Returns the maximumResponseHeaderBytes budget.
     * @return configured inclusive bound
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumResponseHeaderBytes() {
        return maximumResponseHeaderBytes;
    }

    /** Returns the maximumResponseBytes budget.
     * @return configured inclusive bound
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumResponseBytes() {
        return maximumResponseBytes;
    }

    /** Returns the maximumWorkUnits budget.
     * @return configured inclusive bound
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumWorkUnits() {
        return maximumWorkUnits;
    }

    /** Returns the filter budget snapshot.
     * @return filter limits
     * @since 1.0.0
     */
    public @NonNull ScimFilterLimits getFilterLimits() {
        return filterLimits;
    }

    /** Returns a fixed description.
     * @return diagnostic
     * @since 1.0.0
     */
    @Override
    public @NonNull String toString() {
        return "ScimLimits{bounded}";
    }

    /** Mutable complete budget configuration; null restores each default.
     * @since 1.0.0
     */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Builder {
        private Builder() {}

        private @Nullable Integer maximumBodyBytes;

        /** Replaces the maximumBodyBytes setting.
         * @param value bound or null for default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumBodyBytes(@Nullable Integer value) {
            maximumBodyBytes = value;
            return this;
        }

        private @Nullable Integer maximumPatchOperations;

        /** Replaces the maximumPatchOperations setting.
         * @param value bound or null for default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumPatchOperations(@Nullable Integer value) {
            maximumPatchOperations = value;
            return this;
        }

        private @Nullable Integer maximumJsonNodes;

        /** Replaces the maximumJsonNodes setting.
         * @param value bound or null for default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumJsonNodes(@Nullable Integer value) {
            maximumJsonNodes = value;
            return this;
        }

        private @Nullable Integer maximumRawQueryBytes;

        /** Replaces the maximumRawQueryBytes setting.
         * @param value bound or null for default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumRawQueryBytes(@Nullable Integer value) {
            maximumRawQueryBytes = value;
            return this;
        }

        private @Nullable Integer maximumQueryParameters;

        /** Replaces the maximumQueryParameters setting.
         * @param value bound or null for default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumQueryParameters(@Nullable Integer value) {
            maximumQueryParameters = value;
            return this;
        }

        private @Nullable Integer maximumParameterCharacters;

        /** Replaces the maximumParameterCharacters setting.
         * @param value bound or null for default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumParameterCharacters(@Nullable Integer value) {
            maximumParameterCharacters = value;
            return this;
        }

        private @Nullable Integer maximumProjectionPaths;

        /** Replaces the maximumProjectionPaths setting.
         * @param value bound or null for default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumProjectionPaths(@Nullable Integer value) {
            maximumProjectionPaths = value;
            return this;
        }

        private @Nullable Integer maximumPageSize;

        /** Replaces the maximumPageSize setting.
         * @param value bound or null for default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumPageSize(@Nullable Integer value) {
            maximumPageSize = value;
            return this;
        }

        private @Nullable Integer maximumCursorCharacters;

        /** Replaces the maximumCursorCharacters setting.
         * @param value bound or null for default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumCursorCharacters(@Nullable Integer value) {
            maximumCursorCharacters = value;
            return this;
        }

        private @Nullable Integer maximumConditionalHeaderBytes;

        /** Replaces the maximumConditionalHeaderBytes setting.
         * @param value bound or null for default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumConditionalHeaderBytes(@Nullable Integer value) {
            maximumConditionalHeaderBytes = value;
            return this;
        }

        private @Nullable Integer maximumConditionalTags;

        /** Replaces the maximumConditionalTags setting.
         * @param value bound or null for default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumConditionalTags(@Nullable Integer value) {
            maximumConditionalTags = value;
            return this;
        }

        private @Nullable Integer maximumResponseHeaderBytes;

        /** Replaces the maximumResponseHeaderBytes setting.
         * @param value bound or null for default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumResponseHeaderBytes(@Nullable Integer value) {
            maximumResponseHeaderBytes = value;
            return this;
        }

        private @Nullable Integer maximumResponseBytes;

        /** Replaces the maximumResponseBytes setting.
         * @param value bound or null for default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumResponseBytes(@Nullable Integer value) {
            maximumResponseBytes = value;
            return this;
        }

        private @Nullable Integer maximumWorkUnits;

        /** Replaces the maximumWorkUnits setting.
         * @param value bound or null for default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumWorkUnits(@Nullable Integer value) {
            maximumWorkUnits = value;
            return this;
        }

        private @Nullable ScimFilterLimits filterLimits;

        /** Replaces all filter limits.
         * @param value snapshot or null for defaults
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder filterLimits(@Nullable ScimFilterLimits value) {
            filterLimits = value;
            return this;
        }

        /** Validates all budgets before use.
         * @return immutable limits
         * @since 1.0.0
         */
        public @NonNull ScimLimits build() {
            return new ScimLimits(this);
        }
    }
}
