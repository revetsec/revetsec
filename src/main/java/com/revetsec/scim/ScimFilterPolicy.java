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

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * An immutable declaration of supported filter shapes. Defaults deny every shape. Syntax is checked
 * at construction; registering a policy with a service provider later binds its paths to a schema
 * and checks complete normalized filters. Possessing this configuration does not approve a filter.
 *
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimFilterPolicy {
    private static final @NonNull ScimFilterPolicy REJECT_ALL = new Builder().build();

    private final @NonNull Map<@NonNull String, @NonNull Set<@NonNull ScimComparisonOperator>> allowedComparisons;
    private final @NonNull Set<@NonNull String> allowedPresence;
    private final @NonNull Map<@NonNull String, @NonNull ScimFilterPolicy> allowedValuePaths;
    private final @NonNull Set<@NonNull ScimLogicalOperator> allowedLogicalOperators;
    private final int maximumComparisons;

    private ScimFilterPolicy(@NonNull Builder builder) {
        validatePaths(builder.allowedComparisons.keySet(), false);
        validatePaths(builder.allowedPresence, false);
        validatePaths(builder.allowedValuePaths.keySet(), true);
        validateGraph(builder.allowedComparisons.size(), builder.allowedPresence.size(), builder.allowedValuePaths);
        maximumComparisons = Limits.SCIM_FILTER_COMPARISONS.require(builder.maximumComparisons == null
                ? Limits.SCIM_FILTER_COMPARISONS.getDefaultIntValue() : builder.maximumComparisons);
        allowedComparisons = builder.allowedComparisons;
        allowedPresence = builder.allowedPresence;
        allowedValuePaths = builder.allowedValuePaths;
        allowedLogicalOperators = builder.allowedLogicalOperators;
    }

    /**
     * Starts complete policy configuration with every filter shape denied.
     * @return a new builder
     * @since 1.0.0
     */
    public static @NonNull Builder builder() { return new Builder(); }

    /**
     * Returns the fixed policy that explicitly denies filtering.
     * @return the rejection policy
     * @since 1.0.0
     */
    public static @NonNull ScimFilterPolicy rejectAllInstance() { return REJECT_ALL; }

    /**
     * Returns the immutable configured path-to-comparison-operator snapshot.
     * @return configured comparison shapes
     * @since 1.0.0
     */
    public @NonNull Map<@NonNull String, @NonNull Set<@NonNull ScimComparisonOperator>> getAllowedComparisons() {
        return allowedComparisons;
    }

    /**
     * Returns immutable configured presence paths.
     *
     * @return immutable configured presence paths
     * @since 1.0.0
     */
    public @NonNull Set<@NonNull String> getAllowedPresence() { return allowedPresence; }
    /**
     * Returns immutable configured ValuePath policies.
     *
     * @return immutable configured ValuePath policies
     * @since 1.0.0
     */
    public @NonNull Map<@NonNull String, @NonNull ScimFilterPolicy> getAllowedValuePaths() { return allowedValuePaths; }
    /**
     * Returns immutable configured logical operators.
     *
     * @return immutable configured logical operators
     * @since 1.0.0
     */
    public @NonNull Set<@NonNull ScimLogicalOperator> getAllowedLogicalOperators() { return allowedLogicalOperators; }
    /**
     * Returns maximum comparisons across a complete filter.
     *
     * @return maximum comparisons across a complete filter
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumComparisons() { return maximumComparisons; }

    /**
     * Returns a fixed redacted description.
     *
     * @return a fixed redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "ScimFilterPolicy{<redacted>}"; }

    private static void requireEntryBound(int size) {
        if (size > Limits.SCIM_FILTER_NODES.getCap())
            throw new IllegalArgumentException("SCIM filter policy exceeds its entry bound.");
    }

    private static void validatePaths(@NonNull Set<@NonNull String> paths, boolean valuePath) {
        Set<ScimAttributePath> unique = new HashSet<>();
        for (String expression : paths) {
            ScimAttributePathParseResult result = ScimAttributePath.fromExpressionResult(expression);
            if (!(result instanceof ScimAttributePathParseResult.Succeeded succeeded))
                throw new IllegalArgumentException("SCIM filter policy contains an invalid attribute path.");
            ScimAttributePath path = succeeded.getAttributePath();
            if (!unique.add(path))
                throw new IllegalArgumentException("SCIM filter policy contains equivalent attribute paths.");
            if (valuePath && path.getSubAttributeName().isPresent())
                throw new IllegalArgumentException("SCIM ValuePath policy requires a top-level attribute path.");
        }
    }

    private static void validateGraph(int comparisonPaths, int presencePaths,
            @NonNull Map<@NonNull String, @NonNull ScimFilterPolicy> children) {
        requireEntryBound(children.size());
        IdentityHashMap<ScimFilterPolicy, Boolean> active = new IdentityHashMap<>();
        // Count repeated DAG occurrences as work: sharing a child cannot evade aggregate bounds.
        int[] counts = {1, comparisonPaths + presencePaths + children.size()};
        requireEntryBound(counts[1]);
        for (ScimFilterPolicy child : children.values())
            visitPolicy(Objects.requireNonNull(child), 2, active, counts);
    }

    private static void visitPolicy(@NonNull ScimFilterPolicy policy, int depth,
            @NonNull IdentityHashMap<@NonNull ScimFilterPolicy, @NonNull Boolean> active, int @NonNull [] counts) {
        if (depth > Limits.SCIM_FILTER_DEPTH.getCap() || ++counts[0] > Limits.SCIM_FILTER_NODES.getCap())
            throw new IllegalArgumentException("SCIM filter policy graph exceeds its structural bounds.");
        counts[1] += policy.allowedComparisons.size() + policy.allowedPresence.size() + policy.allowedValuePaths.size();
        requireEntryBound(counts[1]);
        if (active.put(policy, Boolean.TRUE) != null)
            throw new IllegalArgumentException("SCIM filter policy graph contains a cycle.");
        for (ScimFilterPolicy child : policy.allowedValuePaths.values())
            visitPolicy(child, depth + 1, active, counts);
        active.remove(policy);
    }

    /**
     * Mutable, non-thread-safe policy configuration. Setters replace complete snapshots. Null
     * clears collections and restores the registered comparison-count default.
     *
     * @since 1.0.0
     */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Builder {
        private @NonNull Map<@NonNull String, @NonNull Set<@NonNull ScimComparisonOperator>> allowedComparisons = Map.of();
        private @NonNull Set<@NonNull String> allowedPresence = Set.of();
        private @NonNull Map<@NonNull String, @NonNull ScimFilterPolicy> allowedValuePaths = Map.of();
        private @NonNull Set<@NonNull ScimLogicalOperator> allowedLogicalOperators = Set.of();
        private @Nullable Integer maximumComparisons;

        private Builder() { }

        /**
         * Replaces supported comparison shapes with a deep immutable collection snapshot.
         * @param value complete comparison map, or null to deny comparisons
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder allowedComparisons(
                @Nullable Map<@NonNull String, @NonNull Set<@NonNull ScimComparisonOperator>> value) {
            if (value == null) { allowedComparisons = Map.of(); return this; }
            requireEntryBound(value.size());
            Map<String, Set<ScimComparisonOperator>> copy = new LinkedHashMap<>();
            for (Map.Entry<String, Set<ScimComparisonOperator>> entry : value.entrySet()) {
                String path = Objects.requireNonNull(entry.getKey());
                Set<ScimComparisonOperator> operators = Objects.requireNonNull(entry.getValue());
                requireEntryBound(operators.size());
                EnumSet<ScimComparisonOperator> operatorCopy = EnumSet.noneOf(ScimComparisonOperator.class);
                for (ScimComparisonOperator operator : operators)
                    operatorCopy.add(Objects.requireNonNull(operator));
                copy.put(path, Collections.unmodifiableSet(operatorCopy));
            }
            allowedComparisons = Collections.unmodifiableMap(copy);
            return this;
        }

        /**
         * Replaces supported presence paths with an immutable snapshot.
         * @param value complete path set, or null to deny presence
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder allowedPresence(@Nullable Set<@NonNull String> value) {
            if (value == null) { allowedPresence = Set.of(); return this; }
            requireEntryBound(value.size());
            Set<String> copy = new LinkedHashSet<>();
            for (String path : value) copy.add(Objects.requireNonNull(path));
            allowedPresence = Collections.unmodifiableSet(copy);
            return this;
        }

        /**
         * Replaces supported ValuePath policies after checking finite acyclic graph bounds.
         * @param value complete path-to-policy map, or null to deny ValuePath
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder allowedValuePaths(
                @Nullable Map<@NonNull String, @NonNull ScimFilterPolicy> value) {
            if (value == null) { allowedValuePaths = Map.of(); return this; }
            validateGraph(0, 0, value);
            Map<String, ScimFilterPolicy> copy = new LinkedHashMap<>();
            for (Map.Entry<String, ScimFilterPolicy> entry : value.entrySet())
                copy.put(Objects.requireNonNull(entry.getKey()), Objects.requireNonNull(entry.getValue()));
            allowedValuePaths = Collections.unmodifiableMap(copy);
            return this;
        }

        /**
         * Replaces supported logical operators with an immutable snapshot.
         * @param value complete operator set, or null to deny logical operators
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder allowedLogicalOperators(@Nullable Set<@NonNull ScimLogicalOperator> value) {
            if (value == null) { allowedLogicalOperators = Set.of(); return this; }
            requireEntryBound(value.size());
            EnumSet<ScimLogicalOperator> copy = EnumSet.noneOf(ScimLogicalOperator.class);
            for (ScimLogicalOperator operator : value) copy.add(Objects.requireNonNull(operator));
            allowedLogicalOperators = Collections.unmodifiableSet(copy);
            return this;
        }

        /**
         * Sets the comparison-count limit: default 32, inclusive range 1–128. The filter's node
         * limit provides an additional bound when a complete filter is checked.
         * @param value the limit, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumComparisons(@Nullable Integer value) {
            maximumComparisons = value; return this;
        }

        /**
         * Checks path syntax and graph bounds and creates a complete immutable snapshot. Schema
         * registration and normalized-filter approval are later service-provider operations.
         * @return filter policy
         * @since 1.0.0
         */
        public @NonNull ScimFilterPolicy build() { return new ScimFilterPolicy(this); }
    }
}
