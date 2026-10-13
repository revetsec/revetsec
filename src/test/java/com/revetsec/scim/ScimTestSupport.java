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
import org.junit.jupiter.api.Assertions;

import java.math.BigDecimal;
import java.util.List;

/** Independent expected graphs, deliberately separate from the public AST and serializer. */
final class ScimTestSupport {
    private ScimTestSupport() {}

    sealed interface Expected permits Comparison, Present, And, Or, Not, ValuePath {}
    record Comparison(@NonNull String path, @NonNull ScimComparisonOperator operator,
                      @NonNull Object value) implements Expected {}
    record Present(@NonNull String path) implements Expected {}
    record And(@NonNull List<@NonNull Expected> operands) implements Expected {}
    record Or(@NonNull List<@NonNull Expected> operands) implements Expected {}
    record Not(@NonNull Expected operand) implements Expected {}
    record ValuePath(@NonNull String path, @NonNull Expected filter) implements Expected {}
    enum Null { VALUE }

    static @NonNull Expected c(@NonNull String path, @NonNull ScimComparisonOperator operator,
                              @NonNull Object value) { return new Comparison(path, operator, value); }
    static @NonNull Expected p(@NonNull String path) { return new Present(path); }
    static @NonNull Expected a(@NonNull Expected @NonNull ... operands) { return new And(List.of(operands)); }
    static @NonNull Expected o(@NonNull Expected @NonNull ... operands) { return new Or(List.of(operands)); }
    static @NonNull Expected n(@NonNull Expected operand) { return new Not(operand); }
    static @NonNull Expected v(@NonNull String path, @NonNull Expected filter) { return new ValuePath(path, filter); }

    static @NonNull ScimFilter parse(@NonNull String expression) {
        return Assertions.assertInstanceOf(ScimFilterParseResult.Succeeded.class,
                ScimFilter.fromExpressionResult(expression), expression).getFilter();
    }

    static @NonNull ScimFilter parse(@NonNull String expression, @NonNull ScimFilterLimits limits) {
        return Assertions.assertInstanceOf(ScimFilterParseResult.Succeeded.class,
                ScimFilter.fromExpressionResult(expression, limits), expression).getFilter();
    }

    static @NonNull ScimError reject(@NonNull String expression) {
        return reject(expression, ScimFilterLimits.defaultInstance());
    }

    static @NonNull ScimError reject(@NonNull String expression, @NonNull ScimFilterLimits limits) {
        ScimError error = Assertions.assertInstanceOf(ScimFilterParseResult.Rejected.class,
                ScimFilter.fromExpressionResult(expression, limits), expression).getError();
        Assertions.assertEquals(400, error.getStatusCode());
        Assertions.assertEquals(ScimErrorType.INVALID_FILTER, error.getErrorType().orElseThrow());
        int offset = error.getExpressionOffset().orElseThrow();
        Assertions.assertTrue(offset >= 0 && offset <= expression.length(), "bounded UTF-16 expression offset");
        return error;
    }

    static void assertGraph(@NonNull Expected expected, @NonNull ScimFilter actual) {
        if (expected instanceof Comparison comparison) {
            ScimFilter.Comparison node = Assertions.assertInstanceOf(ScimFilter.Comparison.class, actual);
            Assertions.assertEquals(comparison.path(), node.getAttributePath().toScimString());
            Assertions.assertEquals(comparison.operator(), node.getOperator());
            Object value = comparison.value();
            if (value instanceof String string) {
                Assertions.assertEquals(string, Assertions.assertInstanceOf(ScimFilterValue.StringValue.class,
                        node.getValue()).getValue());
            } else if (value instanceof BigDecimal number) {
                Assertions.assertEquals(0, number.compareTo(Assertions.assertInstanceOf(
                        ScimFilterValue.NumberValue.class, node.getValue()).getValue()));
            } else if (value instanceof Boolean bool) {
                Assertions.assertEquals(bool, Assertions.assertInstanceOf(ScimFilterValue.BooleanValue.class,
                        node.getValue()).getValue());
            } else {
                Assertions.assertEquals(Null.VALUE, value);
                Assertions.assertInstanceOf(ScimFilterValue.NullValue.class, node.getValue());
            }
        } else if (expected instanceof Present present) {
            Assertions.assertEquals(present.path(), Assertions.assertInstanceOf(ScimFilter.Present.class,
                    actual).getAttributePath().toScimString());
        } else if (expected instanceof And and) {
            assertOperands(and.operands(), Assertions.assertInstanceOf(ScimFilter.And.class, actual).getOperands());
        } else if (expected instanceof Or or) {
            assertOperands(or.operands(), Assertions.assertInstanceOf(ScimFilter.Or.class, actual).getOperands());
        } else if (expected instanceof Not not) {
            assertGraph(not.operand(), Assertions.assertInstanceOf(ScimFilter.Not.class, actual).getOperand());
        } else if (expected instanceof ValuePath valuePath) {
            ScimFilter.ValuePath node = Assertions.assertInstanceOf(ScimFilter.ValuePath.class, actual);
            Assertions.assertEquals(valuePath.path(), node.getAttributePath().toScimString());
            assertGraph(valuePath.filter(), node.getFilter());
        }
    }

    private static void assertOperands(@NonNull List<@NonNull Expected> expected,
                                       @NonNull List<@NonNull ScimFilter> actual) {
        Assertions.assertEquals(expected.size(), actual.size());
        for (int index = 0; index < expected.size(); ++index) assertGraph(expected.get(index), actual.get(index));
    }

    /** Compares graphs directly, never using equality or serialized output as the oracle. */
    static void assertSameGraph(@NonNull ScimFilter expected, @NonNull ScimFilter actual) {
        Assertions.assertEquals(expected.getClass(), actual.getClass());
        if (expected instanceof ScimFilter.Comparison left) {
            ScimFilter.Comparison right = Assertions.assertInstanceOf(ScimFilter.Comparison.class, actual);
            assertPath(left.getAttributePath(), right.getAttributePath());
            Assertions.assertEquals(left.getOperator(), right.getOperator());
            Assertions.assertEquals(left.getValue().getClass(), right.getValue().getClass());
            if (left.getValue() instanceof ScimFilterValue.StringValue string) {
                Assertions.assertEquals(string.getValue(),
                        Assertions.assertInstanceOf(ScimFilterValue.StringValue.class, right.getValue()).getValue());
            } else if (left.getValue() instanceof ScimFilterValue.NumberValue number) {
                Assertions.assertEquals(0, number.getValue().compareTo(
                        Assertions.assertInstanceOf(ScimFilterValue.NumberValue.class, right.getValue()).getValue()));
            } else if (left.getValue() instanceof ScimFilterValue.BooleanValue bool) {
                Assertions.assertEquals(bool.getValue(),
                        Assertions.assertInstanceOf(ScimFilterValue.BooleanValue.class, right.getValue()).getValue());
            }
        } else if (expected instanceof ScimFilter.Present left) {
            assertPath(left.getAttributePath(), Assertions.assertInstanceOf(ScimFilter.Present.class, actual)
                    .getAttributePath());
        } else if (expected instanceof ScimFilter.And left) {
            compareOperands(left.getOperands(), Assertions.assertInstanceOf(ScimFilter.And.class, actual).getOperands());
        } else if (expected instanceof ScimFilter.Or left) {
            compareOperands(left.getOperands(), Assertions.assertInstanceOf(ScimFilter.Or.class, actual).getOperands());
        } else if (expected instanceof ScimFilter.Not left) {
            assertSameGraph(left.getOperand(), Assertions.assertInstanceOf(ScimFilter.Not.class, actual).getOperand());
        } else if (expected instanceof ScimFilter.ValuePath left) {
            ScimFilter.ValuePath right = Assertions.assertInstanceOf(ScimFilter.ValuePath.class, actual);
            assertPath(left.getAttributePath(), right.getAttributePath());
            assertSameGraph(left.getFilter(), right.getFilter());
        }
    }

    private static void compareOperands(@NonNull List<@NonNull ScimFilter> expected,
                                        @NonNull List<@NonNull ScimFilter> actual) {
        Assertions.assertEquals(expected.size(), actual.size());
        for (int index = 0; index < expected.size(); ++index) assertSameGraph(expected.get(index), actual.get(index));
    }

    private static void assertPath(@NonNull ScimAttributePath expected, @NonNull ScimAttributePath actual) {
        Assertions.assertEquals(expected.getSchemaId(), actual.getSchemaId());
        Assertions.assertEquals(expected.getAttributeName(), actual.getAttributeName());
        Assertions.assertEquals(expected.getSubAttributeName(), actual.getSubAttributeName());
    }
}
