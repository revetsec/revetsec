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
import java.math.BigDecimal;

import static java.util.Objects.requireNonNull;

/**
 * A SCIM comparison literal: JSON string, number, boolean or null. Construction
 * is restricted to bounded parsing. Strings compare exactly; numbers compare
 * by numeric value. Diagnostic rendering always redacts content.
 * The four permitted literal kinds are stable within a major version and may be matched exhaustively.
 *
 * @since 1.0.0
 */
@Immutable
public sealed interface ScimFilterValue permits ScimFilterValue.StringValue,
        ScimFilterValue.NumberValue, ScimFilterValue.BooleanValue, ScimFilterValue.NullValue {
    /** A well-formed UTF-16 string literal.
     * @since 1.0.0
     */
    @Immutable
    final class StringValue implements ScimFilterValue {
        private final @NonNull String value;
        StringValue(@NonNull String value) { this.value = requireNonNull(value); }

        /** Returns the decoded literal, which may contain personal data.
         * @return value
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull String getValue() { return this.value; }

        /** Compares literal content exactly.
         * @param other candidate
         * @return equality
         * @since 1.0.0
         */
        @Override public boolean equals(@Nullable Object other) {
            return this == other || other instanceof StringValue literal && this.value.equals(literal.value);
        }
        /** Returns the value hash.
         * @return hash
         * @since 1.0.0
         */
        @Override public int hashCode() { return this.value.hashCode(); }
        /** Redacts content.
         * @return redacted description
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "ScimFilterValue.StringValue{value=<redacted>}"; }
    }

    /** A bounded exact decimal literal.
     * @since 1.0.0
     */
    @Immutable
    final class NumberValue implements ScimFilterValue {
        private final @NonNull BigDecimal value;
        private final @NonNull String expression;
        private final int hashCode;
        NumberValue(@NonNull BigDecimal value, @NonNull String expression) {
            this.value = requireNonNull(value);
            this.expression = requireNonNull(expression);
            // Numeric equality has the same correctly rounded double; no exponent expansion.
            this.hashCode = Double.hashCode(value.doubleValue());
        }

        /** Returns the exact literal value without expanding exponent notation.
         * @return value
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull BigDecimal getValue() { return this.value; }

        @NonNull String expression() { return this.expression; }

        /** Compares numeric value, ignoring scale.
         * @param other candidate
         * @return equality
         * @since 1.0.0
         */
        @Override public boolean equals(@Nullable Object other) {
            return this == other || other instanceof NumberValue literal
                    && this.hashCode == literal.hashCode && this.value.compareTo(literal.value) == 0;
        }
        /** Returns a hash consistent with numeric equality.
         * @return hash
         * @since 1.0.0
         */
        @Override public int hashCode() { return this.hashCode; }
        /** Redacts content.
         * @return redacted description
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "ScimFilterValue.NumberValue{value=<redacted>}"; }
    }

    /** A JSON boolean literal.
     * @since 1.0.0
     */
    @Immutable
    final class BooleanValue implements ScimFilterValue {
        private final boolean value;
        BooleanValue(boolean value) { this.value = value; }

        /** Returns the boolean literal.
         * @return value
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Boolean getValue() { return this.value; }

        /** Compares boolean value.
         * @param other candidate
         * @return equality
         * @since 1.0.0
         */
        @Override public boolean equals(@Nullable Object other) {
            return this == other || other instanceof BooleanValue literal && this.value == literal.value;
        }
        /** Returns the value hash.
         * @return hash
         * @since 1.0.0
         */
        @Override public int hashCode() { return Boolean.hashCode(this.value); }
        /** Redacts content.
         * @return redacted description
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "ScimFilterValue.BooleanValue{value=<redacted>}"; }
    }

    /** JSON null, with no nullable payload.
     * @since 1.0.0
     */
    @Immutable
    final class NullValue implements ScimFilterValue {
        NullValue() {}
        /** Compares null literals.
         * @param other candidate
         * @return equality
         * @since 1.0.0
         */
        @Override public boolean equals(@Nullable Object other) { return other instanceof NullValue; }
        /** Returns a fixed hash.
         * @return hash
         * @since 1.0.0
         */
        @Override public int hashCode() { return 0; }
        /** Redacts content.
         * @return redacted description
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "ScimFilterValue.NullValue{value=<redacted>}"; }
    }
}
