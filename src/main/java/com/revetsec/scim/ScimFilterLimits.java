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
import com.revetsec.internal.Limit;
import com.revetsec.internal.Limits;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;

/**
 * Immutable allocation and structural limits for SCIM filter syntax. Character counts use UTF-16
 * code units. All limits are finite; literal length must not exceed expression length.
 *
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimFilterLimits {
    private static final @NonNull ScimFilterLimits DEFAULT = new Builder().build();
    private final int maximumExpressionCharacters;
    private final int maximumDepth;
    private final int maximumNodes;
    private final int maximumLiteralCharacters;
    private final int maximumNumberCharacters;
    private final int maximumNumberExponentMagnitude;

    private ScimFilterLimits(@NonNull Builder builder) {
        maximumExpressionCharacters = resolve(builder.maximumExpressionCharacters, Limits.SCIM_FILTER_LENGTH);
        maximumDepth = resolve(builder.maximumDepth, Limits.SCIM_FILTER_DEPTH);
        maximumNodes = resolve(builder.maximumNodes, Limits.SCIM_FILTER_NODES);
        maximumLiteralCharacters = resolve(builder.maximumLiteralCharacters, Limits.SCIM_FILTER_LITERAL_LENGTH);
        maximumNumberCharacters = resolve(builder.maximumNumberCharacters, Limits.SCIM_FILTER_NUMBER_LENGTH);
        maximumNumberExponentMagnitude = resolve(builder.maximumNumberExponentMagnitude,
                Limits.SCIM_FILTER_NUMBER_EXPONENT_MAGNITUDE);
        if (maximumLiteralCharacters > maximumExpressionCharacters)
            throw new IllegalArgumentException("SCIM filter literal length must not exceed expression length.");
    }

    /**
     * Starts limit configuration with the registered defaults.
     *
     * @return a new builder
     * @since 1.0.0
     */
    public static @NonNull Builder builder() {
        return new Builder();
    }

    /**
     * Returns the shared immutable default filter limits.
     *
     * @return the shared default filter limits
     * @since 1.0.0
     */
    public static @NonNull ScimFilterLimits defaultInstance() {
        return DEFAULT;
    }

    /**
     * Returns maximum expression UTF-16 units.
     *
     * @return maximum expression UTF-16 units
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumExpressionCharacters() { return maximumExpressionCharacters; }
    /**
     * Returns maximum AST depth.
     *
     * @return maximum AST depth
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumDepth() { return maximumDepth; }
    /**
     * Returns maximum AST nodes.
     *
     * @return maximum AST nodes
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumNodes() { return maximumNodes; }
    /**
     * Returns maximum decoded string-literal UTF-16 units.
     *
     * @return maximum decoded string-literal UTF-16 units
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumLiteralCharacters() { return maximumLiteralCharacters; }
    /**
     * Returns maximum number-literal UTF-16 units.
     *
     * @return maximum number-literal UTF-16 units
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumNumberCharacters() { return maximumNumberCharacters; }
    /**
     * Returns maximum magnitude of a number literal's exponent.
     *
     * @return maximum magnitude of a number literal's exponent
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumNumberExponentMagnitude() { return maximumNumberExponentMagnitude; }

    /**
     * Returns a bounded description of the configured limits.
     *
     * @return a bounded description of the configured limits
     * @since 1.0.0
     */
    @Override public @NonNull String toString() {
        return "ScimFilterLimits{expression=" + maximumExpressionCharacters + ", depth=" + maximumDepth
                + ", nodes=" + maximumNodes + ", literal=" + maximumLiteralCharacters + ", number="
                + maximumNumberCharacters + ", exponent=" + maximumNumberExponentMagnitude + "}";
    }

    private static int resolve(@Nullable Integer value, @NonNull Limit limit) {
        return limit.require(value == null ? limit.getDefaultIntValue() : value);
    }

    /**
     * Mutable, non-thread-safe filter-limit configuration. Null restores the registered default.
     *
     * @since 1.0.0
     */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Builder {
        private @Nullable Integer maximumExpressionCharacters;
        private @Nullable Integer maximumDepth;
        private @Nullable Integer maximumNodes;
        private @Nullable Integer maximumLiteralCharacters;
        private @Nullable Integer maximumNumberCharacters;
        private @Nullable Integer maximumNumberExponentMagnitude;

        private Builder() { }

        /**
         * Sets the expression limit: default 4,096, range 256–65,536 UTF-16 units.
         * @param value the limit, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumExpressionCharacters(@Nullable Integer value) {
            maximumExpressionCharacters = value; return this;
        }

        /**
         * Sets the AST depth limit: default 16, range 4–64 levels.
         * @param value the limit, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumDepth(@Nullable Integer value) {
            maximumDepth = value; return this;
        }

        /**
         * Sets the AST node limit: default 128, range 8–4,096.
         * @param value the limit, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumNodes(@Nullable Integer value) {
            maximumNodes = value; return this;
        }

        /**
         * Sets the decoded literal limit: default 2,048, range 1–16,384 UTF-16 units, within the expression limit.
         * @param value the limit, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumLiteralCharacters(@Nullable Integer value) {
            maximumLiteralCharacters = value; return this;
        }

        /**
         * Sets the number-text limit: default 64, range 1–256 UTF-16 units.
         * @param value the limit, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumNumberCharacters(@Nullable Integer value) {
            maximumNumberCharacters = value; return this;
        }

        /**
         * Sets the exponent-magnitude limit: default 1,000, range 0–10,000.
         * @param value the limit, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumNumberExponentMagnitude(@Nullable Integer value) {
            maximumNumberExponentMagnitude = value; return this;
        }

        /**
         * Checks all registered bounds and creates an immutable snapshot.
         * @return filter limits
         * @since 1.0.0
         */
        public @NonNull ScimFilterLimits build() { return new ScimFilterLimits(this); }
    }
}
