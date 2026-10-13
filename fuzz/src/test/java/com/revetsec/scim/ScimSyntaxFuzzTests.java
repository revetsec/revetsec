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

import com.code_intelligence.jazzer.junit.FuzzTest;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Assertions;

import javax.annotation.concurrent.ThreadSafe;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.List;

/**
 * Total bounded syntax over UTF-8 text and raw UTF-16 units (including malformed surrogates).
 * These targets assert structural and round-trip properties; independent RFC grammar acceptance
 * and exact AST oracles remain in the core ScimFilterGrammarTests/ScimAttributePathTests.
 * Curated seeds and their primary-source provenance are recorded beside the seed manifest.
 * Checks cover INV-M1 (syntax structure), INV-G4 (bounded work), INV-M7 (fixed errors),
 * and INV-M8 (ASCII attribute names). Parsing grants no schema or query permission.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class ScimSyntaxFuzzTests {
    private static final @NonNull List<@NonNull ScimFilterLimits> PROFILES = List.of(
            ScimFilterLimits.defaultInstance(),
            ScimFilterLimits.builder().maximumExpressionCharacters(256).maximumLiteralCharacters(4)
                    .maximumDepth(4).maximumNodes(8).maximumNumberCharacters(4)
                    .maximumNumberExponentMagnitude(2).build(),
            ScimFilterLimits.builder().maximumExpressionCharacters(65_536).maximumLiteralCharacters(16_384)
                    .maximumDepth(64).maximumNodes(4_096).maximumNumberCharacters(256)
                    .maximumNumberExponentMagnitude(10_000).build());

    /** Unexpected throwables are findings; accepted syntax obeys all supplied budgets. */
    @FuzzTest(maxDuration = "5m")
    public void rawFiltersRemainBoundedAndRoundTrip(byte @NonNull [] input) {
        for (String expression : List.of(new String(input, StandardCharsets.UTF_8), rawUnits(input))) {
            for (ScimFilterLimits limits : PROFILES) {
                ScimFilterParseResult result = ScimFilter.fromExpressionResult(expression, limits);
                if (result instanceof ScimFilterParseResult.Rejected rejected) {
                    fixedError(rejected.getError(), ScimError.invalidFilterInstance(), expression.length());
                    continue;
                }
                ScimFilter filter = Assertions.assertInstanceOf(ScimFilterParseResult.Succeeded.class, result).getFilter();
                Assertions.assertTrue(expression.length() <= limits.getMaximumExpressionCharacters());
                boundedGraph(filter, limits);
                String serialized = filter.toScimString();
                Assertions.assertTrue(serialized.length() <= expression.length(), "Canonical syntax must not grow");
                ScimFilter reparsed = Assertions.assertInstanceOf(ScimFilterParseResult.Succeeded.class,
                        ScimFilter.fromExpressionResult(serialized, limits)).getFilter();
                sameGraph(filter, reparsed);
                Assertions.assertEquals(serialized, reparsed.toScimString());
            }
        }
    }

    /** Path successes retain their exact parts and spelling; failures carry fixed, bounded metadata. */
    @FuzzTest(maxDuration = "5m")
    public void rawPathsRemainBoundedAndRoundTrip(byte @NonNull [] input) {
        for (String expression : List.of(new String(input, StandardCharsets.UTF_8), rawUnits(input))) {
            ScimAttributePathParseResult result = ScimAttributePath.fromExpressionResult(expression);
            if (result instanceof ScimAttributePathParseResult.Rejected rejected) {
                fixedError(rejected.getError(), ScimError.invalidPathInstance(), expression.length());
                continue;
            }
            ScimAttributePath path = Assertions.assertInstanceOf(ScimAttributePathParseResult.Succeeded.class, result)
                    .getAttributePath();
            boundedPath(path);
            Assertions.assertEquals(expression, path.toScimString());
            ScimAttributePath reparsed = Assertions.assertInstanceOf(ScimAttributePathParseResult.Succeeded.class,
                    ScimAttributePath.fromExpressionResult(path.toScimString())).getAttributePath();
            samePath(path, reparsed);
            Assertions.assertEquals(path, reparsed);
            Assertions.assertEquals(path.hashCode(), reparsed.hashCode());
        }
    }

    private static @NonNull String rawUnits(byte @NonNull [] input) {
        char[] characters = new char[(input.length + 1) / 2];
        for (int index = 0; index < characters.length; ++index) {
            int first = input[index * 2] & 255;
            int second = index * 2 + 1 < input.length ? input[index * 2 + 1] & 255 : 0;
            characters[index] = (char) ((first << 8) | second);
        }
        return new String(characters);
    }

    private static void fixedError(@NonNull ScimError actual, @NonNull ScimError fixed, int length) {
        Assertions.assertEquals(fixed.getStatusCode(), actual.getStatusCode());
        Assertions.assertEquals(fixed.getErrorType(), actual.getErrorType());
        Assertions.assertEquals(fixed.getDetail(), actual.getDetail());
        Assertions.assertEquals(fixed.toString(), actual.toString());
        int offset = actual.getExpressionOffset().orElseThrow();
        Assertions.assertTrue(offset >= 0 && offset <= length);
    }

    private static void boundedPath(@NonNull ScimAttributePath path) {
        Assertions.assertTrue(validName(path.getAttributeName()));
        path.getSubAttributeName().ifPresent(name -> Assertions.assertTrue(validName(name)));
        path.getSchemaId().ifPresent(schema -> {
            Assertions.assertTrue(schema.length() <= 2_048);
            for (int index = 0; index < schema.length(); ++index) {
                char character = schema.charAt(index);
                Assertions.assertTrue(character > 32 && character < 127);
            }
        });
    }

    private static boolean validName(@NonNull String value) {
        if (value.length() > 128 || value.isEmpty()) return false;
        if (value.equals("$ref") || value.equals("$REF") || value.equals("$Ref") || value.equals("$rEf")
                || value.equals("$reF") || value.equals("$REf") || value.equals("$rEF") || value.equals("$ReF")) return true;
        char first = value.charAt(0);
        if (!alpha(first)) return false;
        for (int index = 1; index < value.length(); ++index) {
            char character = value.charAt(index);
            if (!alpha(character) && !(character >= '0' && character <= '9') && character != '_' && character != '-') return false;
        }
        return true;
    }

    private static boolean alpha(char character) {
        return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z');
    }

    private static void scalarUnicode(@NonNull String value) {
        for (int index = 0; index < value.length(); ++index) {
            char character = value.charAt(index);
            if (Character.isHighSurrogate(character)) {
                Assertions.assertTrue(index + 1 < value.length());
                Assertions.assertTrue(Character.isLowSurrogate(value.charAt(++index)));
            } else Assertions.assertFalse(Character.isLowSurrogate(character));
        }
    }

    private static void boundedGraph(@NonNull ScimFilter root, @NonNull ScimFilterLimits limits) {
        ArrayDeque<ScimFilter> filters = new ArrayDeque<>();
        ArrayDeque<Integer> depths = new ArrayDeque<>();
        ArrayDeque<Boolean> inValuePaths = new ArrayDeque<>();
        filters.add(root); depths.add(1); inValuePaths.add(false);
        int nodes = 0;
        while (!filters.isEmpty()) {
            ScimFilter filter = filters.remove();
            int depth = depths.remove();
            boolean inValuePath = inValuePaths.remove();
            Assertions.assertTrue(++nodes <= limits.getMaximumNodes());
            Assertions.assertTrue(depth <= limits.getMaximumDepth());
            List<ScimFilter> children = List.of();
            if (filter instanceof ScimFilter.And and) {
                children = and.getOperands();
                Assertions.assertTrue(children.size() >= 2);
                for (ScimFilter child : children) Assertions.assertFalse(child instanceof ScimFilter.And);
            } else if (filter instanceof ScimFilter.Or or) {
                children = or.getOperands();
                Assertions.assertTrue(children.size() >= 2);
                for (ScimFilter child : children) Assertions.assertFalse(child instanceof ScimFilter.Or);
            } else if (filter instanceof ScimFilter.Not not) children = List.of(not.getOperand());
            else if (filter instanceof ScimFilter.ValuePath valuePath) {
                Assertions.assertFalse(inValuePath);
                boundedPath(valuePath.getAttributePath());
                inValuePath = true;
                children = List.of(valuePath.getFilter());
            } else if (filter instanceof ScimFilter.Present present) boundedPath(present.getAttributePath());
            else if (filter instanceof ScimFilter.Comparison comparison) {
                boundedPath(comparison.getAttributePath());
                ScimFilterValue value = comparison.getValue();
                if (value instanceof ScimFilterValue.StringValue string) {
                    Assertions.assertTrue(string.getValue().length() <= limits.getMaximumLiteralCharacters());
                    scalarUnicode(string.getValue());
                } else if (value instanceof ScimFilterValue.NumberValue number) {
                    Assertions.assertTrue(number.getValue().precision() <= limits.getMaximumNumberCharacters());
                    Assertions.assertTrue(Math.abs((long) number.getValue().scale())
                            <= limits.getMaximumNumberExponentMagnitude() + limits.getMaximumNumberCharacters());
                } else Assertions.assertTrue(value instanceof ScimFilterValue.BooleanValue || value instanceof ScimFilterValue.NullValue);
            }
            for (ScimFilter child : children) {
                filters.add(child); depths.add(depth + 1); inValuePaths.add(inValuePath);
            }
        }
    }

    private static void sameGraph(@NonNull ScimFilter expected, @NonNull ScimFilter actual) {
        ArrayDeque<ScimFilter> left = new ArrayDeque<>();
        ArrayDeque<ScimFilter> right = new ArrayDeque<>();
        left.add(expected); right.add(actual);
        while (!left.isEmpty()) {
            ScimFilter first = left.remove();
            ScimFilter second = right.remove();
            Assertions.assertEquals(first.getClass(), second.getClass());
            List<ScimFilter> firstChildren = List.of(), secondChildren = List.of();
            if (first instanceof ScimFilter.And and) {
                firstChildren = and.getOperands();
                secondChildren = Assertions.assertInstanceOf(ScimFilter.And.class, second).getOperands();
            } else if (first instanceof ScimFilter.Or or) {
                firstChildren = or.getOperands();
                secondChildren = Assertions.assertInstanceOf(ScimFilter.Or.class, second).getOperands();
            } else if (first instanceof ScimFilter.Not not) {
                firstChildren = List.of(not.getOperand());
                secondChildren = List.of(Assertions.assertInstanceOf(ScimFilter.Not.class, second).getOperand());
            } else if (first instanceof ScimFilter.ValuePath valuePath) {
                ScimFilter.ValuePath other = Assertions.assertInstanceOf(ScimFilter.ValuePath.class, second);
                samePath(valuePath.getAttributePath(), other.getAttributePath());
                firstChildren = List.of(valuePath.getFilter()); secondChildren = List.of(other.getFilter());
            } else if (first instanceof ScimFilter.Present present) {
                samePath(present.getAttributePath(), Assertions.assertInstanceOf(ScimFilter.Present.class, second).getAttributePath());
            } else if (first instanceof ScimFilter.Comparison comparison) {
                ScimFilter.Comparison other = Assertions.assertInstanceOf(ScimFilter.Comparison.class, second);
                samePath(comparison.getAttributePath(), other.getAttributePath());
                Assertions.assertEquals(comparison.getOperator(), other.getOperator());
                Assertions.assertEquals(comparison.getValue().getClass(), other.getValue().getClass());
                if (comparison.getValue() instanceof ScimFilterValue.StringValue string) {
                    Assertions.assertEquals(string.getValue(), Assertions.assertInstanceOf(ScimFilterValue.StringValue.class,
                            other.getValue()).getValue());
                } else if (comparison.getValue() instanceof ScimFilterValue.NumberValue number) {
                    Assertions.assertEquals(0, number.getValue().compareTo(Assertions.assertInstanceOf(ScimFilterValue.NumberValue.class,
                            other.getValue()).getValue()));
                } else if (comparison.getValue() instanceof ScimFilterValue.BooleanValue bool) {
                    Assertions.assertEquals(bool.getValue(), Assertions.assertInstanceOf(ScimFilterValue.BooleanValue.class,
                            other.getValue()).getValue());
                }
            }
            Assertions.assertEquals(firstChildren.size(), secondChildren.size());
            left.addAll(firstChildren); right.addAll(secondChildren);
        }
        Assertions.assertTrue(right.isEmpty());
    }

    private static void samePath(@NonNull ScimAttributePath expected, @NonNull ScimAttributePath actual) {
        Assertions.assertEquals(expected.getSchemaId(), actual.getSchemaId());
        Assertions.assertEquals(expected.getAttributeName(), actual.getAttributeName());
        Assertions.assertEquals(expected.getSubAttributeName(), actual.getSubAttributeName());
    }
}
