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
package com.revetsec.differential;

import com.revetsec.scim.*;
import com.unboundid.scim2.common.Path;
import com.unboundid.scim2.common.exceptions.BadRequestException;
import com.unboundid.scim2.common.filters.Filter;
import com.unboundid.scim2.common.filters.FilterType;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.exc.JsonNodeException;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** Independent parser/typed-AST comparisons only: no evaluator, policy, authorization or storage oracle. */
final class ScimFilterComparatorTests {
    private record Attribute(String schema, List<String> elements) { }
    private record Literal(String type, Object value) { }
    private record Node(String kind, Attribute path, Literal literal, List<Node> children) { }

    @TestFactory Stream<DynamicTest> sharedGrammarProducesTheSameTypedTree() {
        List<String> expressions = new ArrayList<>();
        for (String path : List.of("userName", "name.givenName", "$ref",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department")) {
            for (String operator : List.of("eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le"))
                for (String value : List.of("\"a+b%20é\"", "\"line\\n\\t\\\"\\\\\\uD83D\\uDE00\"", "1.25", "1e3", "true", "false", "null"))
                    expressions.add(path + " " + operator + " " + value);
            expressions.add(path + " pr");
        }
        expressions.addAll(List.of(
                "USERNAME EQ \"a\"", "active eQ true", "userName Pr", "name.givenName Ne null",
                "userName eq \"a\" and active eq true or userName eq \"b\"",
                "userName eq \"a\" or active eq true and userName eq \"b\"",
                "(userName eq \"a\" or active eq true) and userName eq \"b\"",
                "userName eq \"a\" and (active eq true and userName eq \"b\")",
                "(userName eq \"a\" and active eq true) and userName eq \"b\"",
                "userName eq \"a\" or (active eq true or userName eq \"b\")",
                "not(userName eq \"a\" or active eq true)", "not(not(active eq false))",
                "emails[type eq \"work\" and value co \"@example.test\"]",
                "emails[(type eq \"work\" or type eq \"home\") and not(value eq null)]",
                "emails[primary eq true] or phoneNumbers[type pr]",
                "emails[type eq \"work\"] and emails[value sw \"a\"]",
                "  ( userName eq \"a\" )  ", "active eq null", "number ge -0", "number lt -1.25e2"));
        return java.util.stream.IntStream.range(0, expressions.size()).mapToObj(index ->
                DynamicTest.dynamicTest("shared typed AST " + index, () -> {
                    String expression = expressions.get(index);
                    ScimFilter ours = core(expression);
                    Filter independent = Filter.fromString(expression);
                    assertEquals(project(independent), project(ours), expression);
                }));
    }

    @TestFactory Stream<DynamicTest> sharedMalformedGrammarIsRejectedByBothParsers() {
        List<String> invalid = List.of("", " ", "userName", "userName eq", "userName eq \"unterminated",
                "userName eq \"\\q\"", "userName eq +1",
                "userName eq 01", "userName eq .5", "userName eq 1.", "userName eq 1e", "userName eq True",
                "userName eq undefined", "userName xx \"a\"", "userName pr 1", "and userName pr",
                "userName pr or", "userName pr and and active pr", "(userName pr", "userName pr)",
                "not userName eq \"a\"", "not not(userName pr)", "emails[]",
                "emails[value eq \"a\"]junk", "emails[aliases[value eq \"a\"]]", "userName eq \"a\" userName eq \"b\"");
        return java.util.stream.IntStream.range(0, invalid.size()).mapToObj(index ->
                DynamicTest.dynamicTest("shared malformed grammar " + index, () -> {
                    String expression = invalid.get(index);
                    assertInstanceOf(ScimFilterParseResult.Rejected.class, ScimFilter.fromExpressionResult(expression), expression);
                    assertThrows(BadRequestException.class, () -> Filter.fromString(expression), expression);
                }));
    }

    @Test void documentedGrammarDifferencesRemainExact() throws BadRequestException {
        // One row per deliberate/observed profile difference. New divergence must get a reviewed disposition.
        for (String expression : List.of("userName eq \"\\uD800\"", "name.givenName.other eq 1",
                "userName eq \"a\"or userName eq \"b\"", "emails[value eq \"a\"")) {
            assertInstanceOf(ScimFilterParseResult.Rejected.class, ScimFilter.fromExpressionResult(expression));
            assertNotNull(Filter.fromString(expression));
        }
        for (String expression : List.of("https://[2001:db8::1]/schema:attr eq \"a\"", "userName\teq\t\"a\"")) {
            assertInstanceOf(ScimFilterParseResult.Succeeded.class, ScimFilter.fromExpressionResult(expression));
            assertThrows(BadRequestException.class, () -> Filter.fromString(expression));
        }
        String grouped = "(".repeat(17) + "userName pr" + ")".repeat(17);
        assertInstanceOf(ScimFilterParseResult.Rejected.class, ScimFilter.fromExpressionResult(grouped));
        assertNotNull(Filter.fromString(grouped));
    }

    @Test void documentedIndependentNonScalarLiteralFaultsAreExact() {
        for (String expression : List.of("userName eq [1]", "userName eq {}")) {
            assertInstanceOf(ScimFilterParseResult.Rejected.class, ScimFilter.fromExpressionResult(expression));
            assertThrows(ClassCastException.class, () -> Filter.fromString(expression));
        }
    }

    @Test void documentedIndependentDecimalPrecisionLossIsNotSilentlyNormalizedAway() throws BadRequestException {
        String expression = "number eq 0.123456789012345678901234";
        Node ours = project(core(expression));
        Node independent = project(Filter.fromString(expression));
        assertEquals(new BigDecimal("0.123456789012345678901234"), ours.literal().value());
        assertEquals(new BigDecimal("0.12345678901234568"), independent.literal().value());
        assertNotEquals(ours, independent);
        for (String exponent : List.of("1e309", "1e1000")) {
            String numeric = "number eq " + exponent;
            assertEquals(new BigDecimal(exponent), project(core(numeric)).literal().value());
            JsonNode overflow = Filter.fromString(numeric).getComparisonValue();
            assertEquals(Double.POSITIVE_INFINITY, overflow.numberValue().doubleValue());
            assertThrows(JsonNodeException.class, overflow::decimalValue);
        }
    }

    @Test void typedProjectionDetectsPlantedPrecedenceAndLiteralDefects() throws BadRequestException {
        // Negative controls ensure the comparator can fail on structural and typed-value disagreement.
        Node independent = project(Filter.fromString("a eq 1 or b eq 2 and c eq 3"));
        assertNotEquals(independent, project(core("(a eq 1 or b eq 2) and c eq 3")));
        assertNotEquals(project(Filter.fromString("a eq true")), project(core("a eq \"true\"")));
        assertNotEquals(project(Filter.fromString("a eq 1")), project(core("a eq 2")));
        assertNotEquals(project(Filter.fromString("emails[type eq \"work\" and value eq \"a\"]")),
                project(core("emails[type eq \"work\"] and emails[value eq \"a\"]")));
    }

    private static ScimFilter core(String expression) {
        return assertInstanceOf(ScimFilterParseResult.Succeeded.class,
                ScimFilter.fromExpressionResult(expression), expression).getFilter();
    }
    private static Node project(ScimFilter filter) {
        if (filter instanceof ScimFilter.And and) return combined("and", and.getOperands().stream().map(ScimFilterComparatorTests::project).toList());
        if (filter instanceof ScimFilter.Or or) return combined("or", or.getOperands().stream().map(ScimFilterComparatorTests::project).toList());
        if (filter instanceof ScimFilter.Not not) return new Node("not", null, null, List.of(project(not.getOperand())));
        if (filter instanceof ScimFilter.Present present) return new Node("pr", path(present.getAttributePath()), null, List.of());
        if (filter instanceof ScimFilter.ValuePath valuePath) return new Node("valuePath", path(valuePath.getAttributePath()), null, List.of(project(valuePath.getFilter())));
        ScimFilter.Comparison comparison = (ScimFilter.Comparison) filter;
        return new Node(comparison.getOperator().name().toLowerCase(Locale.ROOT), path(comparison.getAttributePath()), literal(comparison.getValue()), List.of());
    }
    private static Node project(Filter filter) {
        FilterType type = filter.getFilterType();
        if (type == FilterType.AND || type == FilterType.OR)
            return combined(type.getStringValue(), filter.getCombinedFilters().stream().map(ScimFilterComparatorTests::project).toList());
        if (type == FilterType.NOT) return new Node("not", null, null, List.of(project(filter.getInvertedFilter())));
        if (type == FilterType.COMPLEX_VALUE) return new Node("valuePath", path(filter.getAttributePath()), null, List.of(project(filter.getValueFilter())));
        if (type == FilterType.PRESENT) return new Node("pr", path(filter.getAttributePath()), null, List.of());
        return new Node(type.getStringValue(), path(filter.getAttributePath()), literal(filter.getComparisonValue()), List.of());
    }
    private static Node combined(String kind, List<Node> input) {
        List<Node> children = new ArrayList<>();
        for (Node node : input) {
            if (kind.equals(node.kind())) children.addAll(node.children());
            else children.add(node);
        }
        return new Node(kind, null, null, List.copyOf(children));
    }
    private static Attribute path(ScimAttributePath path) {
        List<String> elements = new ArrayList<>(); elements.add(fold(path.getAttributeName()));
        path.getSubAttributeName().ifPresent(value -> elements.add(fold(value)));
        return new Attribute(fold(path.getSchemaId().orElse("")), List.copyOf(elements));
    }
    private static Attribute path(Path path) {
        List<String> elements = new ArrayList<>();
        for (int index = 0; index < path.size(); ++index) {
            assertNull(path.getElement(index).getValueFilter(), "unexpected embedded path filter");
            elements.add(fold(path.getElement(index).getAttribute()));
        }
        return new Attribute(path.getSchemaUrn() == null ? "" : fold(path.getSchemaUrn()), List.copyOf(elements));
    }
    private static String fold(String value) {
        StringBuilder folded = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); ++index) {
            char ch = value.charAt(index); folded.append(ch >= 'A' && ch <= 'Z' ? (char) (ch + 32) : ch);
        }
        return folded.toString();
    }
    private static Literal literal(ScimFilterValue value) {
        if (value instanceof ScimFilterValue.StringValue string) return new Literal("string", string.getValue());
        if (value instanceof ScimFilterValue.NumberValue number) return new Literal("number", number.getValue().stripTrailingZeros());
        if (value instanceof ScimFilterValue.BooleanValue bool) return new Literal("boolean", bool.getValue());
        return new Literal("null", null);
    }
    private static Literal literal(JsonNode value) {
        if (value.isString()) return new Literal("string", value.stringValue());
        if (value.isNumber()) return new Literal("number", value.decimalValue().stripTrailingZeros());
        if (value.isBoolean()) return new Literal("boolean", value.booleanValue());
        assertTrue(value.isNull(), "unexpected comparison literal type"); return new Literal("null", null);
    }
}
