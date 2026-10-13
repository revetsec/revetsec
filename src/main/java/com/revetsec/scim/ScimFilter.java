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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.google.errorprone.annotations.CheckReturnValue;
import javax.annotation.concurrent.Immutable;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * A bounded immutable SCIM filter syntax tree (RFC 7644 section 3.4.2.2).
 * AND and OR are ordered, flattened n-ary nodes. NOT binds more tightly than
 * AND, which binds more tightly than OR. ValuePath predicates describe one
 * array element and cannot contain another ValuePath.
 * <p>
 * A successful syntax parse does not bind paths to schemas, validate attribute
 * types, approve a filter policy, or authorize query execution. Applications
 * must perform those checks before using a tree to select resources.
 * <p>
 * Equality is structural, with the path's ASCII case-insensitive equality and
 * numeric-value literal equality. Explicit serialization contains the complete
 * filter and may expose personal data; every diagnostic toString redacts it.
 *
 * @since 1.0.0
 */
@Immutable
public sealed interface ScimFilter permits ScimFilter.And, ScimFilter.Or, ScimFilter.Not,
        ScimFilter.Comparison, ScimFilter.Present, ScimFilter.ValuePath {
    /**
     * Parses filter syntax under the shared immutable default limits.
     *
     * @param expression untrusted filter expression
     * @return success or a fixed rejection with a UTF-16 expression offset
     * @throws NullPointerException if expression is null
     * @since 1.0.0
     */
    @CheckReturnValue
    static @NonNull ScimFilterParseResult fromExpressionResult(@NonNull String expression) {
        return fromExpressionResult(expression, ScimFilterLimits.defaultInstance());
    }

    /**
     * Parses filter syntax directly into a result, without exception-driven
     * handling of malformed input. Bounds apply before recursive stack growth,
     * AST construction and literal/number allocation. Depth covers retained AST
     * levels as well as transient grouping/NOT/ValuePath nesting; nodes count
     * the retained flattened tree, rather than discarded parentheses.
     *
     * @param expression untrusted filter expression
     * @param limits immutable limits
     * @return syntax success or a fixed rejection with a UTF-16 expression offset
     * @throws NullPointerException if either argument is null
     * @since 1.0.0
     */
    @CheckReturnValue
    static @NonNull ScimFilterParseResult fromExpressionResult(
            @NonNull String expression, @NonNull ScimFilterLimits limits) {
        return new ScimFilterParser(requireNonNull(expression), requireNonNull(limits)).parse();
    }

    /**
     * Dispatches this node to a Java 17 visitor. The visitor controls traversal.
     *
     * @param visitor visitor
     * @param <R> nonnull result type
     * @return the visitor's result
     * @throws NullPointerException if visitor or its result is null
     * @since 1.0.0
     */
    @CheckReturnValue
    <R extends @NonNull Object> @NonNull R accept(@NonNull ScimFilterVisitor<@NonNull R> visitor);

    /**
     * Emits a canonical filter with lowercase operators and minimal grouping.
     * Strings use JSON escapes; numeric exponent notation remains compact and
     * never expands an exponent into zeros. The output contains personal data.
     *
     * @return round-trippable SCIM syntax
     * @since 1.0.0
     */
    @CheckReturnValue
    @NonNull String toScimString();

    /** An ordered flattened conjunction.
     * @since 1.0.0
     */
    @Immutable
    final class And implements ScimFilter {
        private final @NonNull List<@NonNull ScimFilter> operands;
        And(@NonNull List<@NonNull ScimFilter> operands) { this.operands = List.copyOf(operands); }

        /** Returns ordered conjunction operands.
         * @return immutable operands
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull List<@NonNull ScimFilter> getOperands() { return this.operands; }
        /** Dispatches this node.
         * @param visitor visitor
         * @param <R> result type
         * @return result
         * @since 1.0.0
         */
        @Override @CheckReturnValue
        public <R extends @NonNull Object> @NonNull R accept(@NonNull ScimFilterVisitor<@NonNull R> visitor) {
            return requireNonNull(requireNonNull(visitor).visitAnd(this));
        }
        /** Emits filter data.
         * @return canonical syntax
         * @since 1.0.0
         */
        @Override @CheckReturnValue public @NonNull String toScimString() { return ScimFilterRendering.render(this); }
        /** Compares ordered structure.
         * @param other candidate
         * @return equality
         * @since 1.0.0
         */
        @Override public boolean equals(@Nullable Object other) {
            return this == other || other instanceof And filter && this.operands.equals(filter.operands);
        }
        /** Returns the structural hash.
         * @return hash
         * @since 1.0.0
         */
        @Override public int hashCode() { return 31 * this.operands.hashCode(); }
        /** Redacts filter data.
         * @return redacted description
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "ScimFilter.And{operands=<redacted>}"; }
    }

    /** An ordered flattened disjunction.
     * @since 1.0.0
     */
    @Immutable
    final class Or implements ScimFilter {
        private final @NonNull List<@NonNull ScimFilter> operands;
        Or(@NonNull List<@NonNull ScimFilter> operands) { this.operands = List.copyOf(operands); }

        /** Returns ordered disjunction operands.
         * @return immutable operands
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull List<@NonNull ScimFilter> getOperands() { return this.operands; }
        /** Dispatches this node.
         * @param visitor visitor
         * @param <R> result type
         * @return result
         * @since 1.0.0
         */
        @Override @CheckReturnValue
        public <R extends @NonNull Object> @NonNull R accept(@NonNull ScimFilterVisitor<@NonNull R> visitor) {
            return requireNonNull(requireNonNull(visitor).visitOr(this));
        }
        /** Emits filter data.
         * @return canonical syntax
         * @since 1.0.0
         */
        @Override @CheckReturnValue public @NonNull String toScimString() { return ScimFilterRendering.render(this); }
        /** Compares ordered structure.
         * @param other candidate
         * @return equality
         * @since 1.0.0
         */
        @Override public boolean equals(@Nullable Object other) {
            return this == other || other instanceof Or filter && this.operands.equals(filter.operands);
        }
        /** Returns the structural hash.
         * @return hash
         * @since 1.0.0
         */
        @Override public int hashCode() { return 37 * this.operands.hashCode(); }
        /** Redacts filter data.
         * @return redacted description
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "ScimFilter.Or{operands=<redacted>}"; }
    }

    /** Negation of a grouped predicate.
     * @since 1.0.0
     */
    @Immutable
    final class Not implements ScimFilter {
        private final @NonNull ScimFilter operand;
        Not(@NonNull ScimFilter operand) {
            this.operand = requireNonNull(operand);
        }

        /** Returns the operand.
         * @return operand
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull ScimFilter getOperand() { return this.operand; }

        /** Dispatches this node.
         * @param visitor visitor
         * @param <R> result type
         * @return result
         * @since 1.0.0
         */
        @Override @CheckReturnValue
        public <R extends @NonNull Object> @NonNull R accept(@NonNull ScimFilterVisitor<@NonNull R> visitor) {
            return requireNonNull(requireNonNull(visitor).visitNot(this));
        }
        /** Emits filter data.
         * @return canonical syntax
         * @since 1.0.0
         */
        @Override @CheckReturnValue public @NonNull String toScimString() { return ScimFilterRendering.render(this); }
        /** Compares structure.
         * @param other candidate
         * @return equality
         * @since 1.0.0
         */
        @Override public boolean equals(@Nullable Object other) {
            return this == other || other instanceof Not filter
                    && this.operand.equals(filter.operand);
        }
        /** Returns the structural hash.
         * @return hash
         * @since 1.0.0
         */
        @Override public int hashCode() { return this.operand.hashCode(); }
        /** Redacts filter data.
         * @return redacted description
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "ScimFilter.Not{filter=<redacted>}"; }
    }

    /** An attribute comparison with a JSON literal.
     * @since 1.0.0
     */
    @Immutable
    final class Comparison implements ScimFilter {
        private final @NonNull ScimAttributePath attributePath;
        private final @NonNull ScimComparisonOperator operator;
        private final @NonNull ScimFilterValue value;
        Comparison(@NonNull ScimAttributePath attributePath, @NonNull ScimComparisonOperator operator, @NonNull ScimFilterValue value) {
            this.attributePath = requireNonNull(attributePath);
            this.operator = requireNonNull(operator);
            this.value = requireNonNull(value);
        }

        /** Returns the attributePath.
         * @return attributePath
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull ScimAttributePath getAttributePath() { return this.attributePath; }
        /** Returns the operator.
         * @return operator
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull ScimComparisonOperator getOperator() { return this.operator; }
        /** Returns the value.
         * @return value
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull ScimFilterValue getValue() { return this.value; }

        /** Dispatches this node.
         * @param visitor visitor
         * @param <R> result type
         * @return result
         * @since 1.0.0
         */
        @Override @CheckReturnValue
        public <R extends @NonNull Object> @NonNull R accept(@NonNull ScimFilterVisitor<@NonNull R> visitor) {
            return requireNonNull(requireNonNull(visitor).visitComparison(this));
        }
        /** Emits filter data.
         * @return canonical syntax
         * @since 1.0.0
         */
        @Override @CheckReturnValue public @NonNull String toScimString() { return ScimFilterRendering.render(this); }
        /** Compares structure.
         * @param other candidate
         * @return equality
         * @since 1.0.0
         */
        @Override public boolean equals(@Nullable Object other) {
            return this == other || other instanceof Comparison filter
                    && this.attributePath.equals(filter.attributePath) && this.operator.equals(filter.operator) && this.value.equals(filter.value);
        }
        /** Returns the structural hash.
         * @return hash
         * @since 1.0.0
         */
        @Override public int hashCode() { return (31 * (31 * this.attributePath.hashCode() + this.operator.hashCode()) + this.value.hashCode()); }
        /** Redacts filter data.
         * @return redacted description
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "ScimFilter.Comparison{filter=<redacted>}"; }
    }

    /** An attribute presence test.
     * @since 1.0.0
     */
    @Immutable
    final class Present implements ScimFilter {
        private final @NonNull ScimAttributePath attributePath;
        Present(@NonNull ScimAttributePath attributePath) {
            this.attributePath = requireNonNull(attributePath);
        }

        /** Returns the attributePath.
         * @return attributePath
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull ScimAttributePath getAttributePath() { return this.attributePath; }

        /** Dispatches this node.
         * @param visitor visitor
         * @param <R> result type
         * @return result
         * @since 1.0.0
         */
        @Override @CheckReturnValue
        public <R extends @NonNull Object> @NonNull R accept(@NonNull ScimFilterVisitor<@NonNull R> visitor) {
            return requireNonNull(requireNonNull(visitor).visitPresent(this));
        }
        /** Emits filter data.
         * @return canonical syntax
         * @since 1.0.0
         */
        @Override @CheckReturnValue public @NonNull String toScimString() { return ScimFilterRendering.render(this); }
        /** Compares structure.
         * @param other candidate
         * @return equality
         * @since 1.0.0
         */
        @Override public boolean equals(@Nullable Object other) {
            return this == other || other instanceof Present filter
                    && this.attributePath.equals(filter.attributePath);
        }
        /** Returns the structural hash.
         * @return hash
         * @since 1.0.0
         */
        @Override public int hashCode() { return this.attributePath.hashCode(); }
        /** Redacts filter data.
         * @return redacted description
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "ScimFilter.Present{filter=<redacted>}"; }
    }

    /** A predicate whose relative paths refer to the same array element.
     * @since 1.0.0
     */
    @Immutable
    final class ValuePath implements ScimFilter {
        private final @NonNull ScimAttributePath attributePath;
        private final @NonNull ScimFilter filter;
        ValuePath(@NonNull ScimAttributePath attributePath, @NonNull ScimFilter filter) {
            this.attributePath = requireNonNull(attributePath);
            this.filter = requireNonNull(filter);
        }

        /** Returns the attributePath.
         * @return attributePath
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull ScimAttributePath getAttributePath() { return this.attributePath; }
        /** Returns the filter.
         * @return filter
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull ScimFilter getFilter() { return this.filter; }

        /** Dispatches this node.
         * @param visitor visitor
         * @param <R> result type
         * @return result
         * @since 1.0.0
         */
        @Override @CheckReturnValue
        public <R extends @NonNull Object> @NonNull R accept(@NonNull ScimFilterVisitor<@NonNull R> visitor) {
            return requireNonNull(requireNonNull(visitor).visitValuePath(this));
        }
        /** Emits filter data.
         * @return canonical syntax
         * @since 1.0.0
         */
        @Override @CheckReturnValue public @NonNull String toScimString() { return ScimFilterRendering.render(this); }
        /** Compares structure.
         * @param other candidate
         * @return equality
         * @since 1.0.0
         */
        @Override public boolean equals(@Nullable Object other) {
            return this == other || other instanceof ValuePath filter
                    && this.attributePath.equals(filter.attributePath) && this.filter.equals(filter.filter);
        }
        /** Returns the structural hash.
         * @return hash
         * @since 1.0.0
         */
        @Override public int hashCode() { return (31 * this.attributePath.hashCode() + this.filter.hashCode()); }
        /** Redacts filter data.
         * @return redacted description
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "ScimFilter.ValuePath{filter=<redacted>}"; }
    }
}
