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
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static com.revetsec.scim.ScimTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

final class ScimFilterBoundaryTests {
    @Test void expressionBudgetCountsUtf16UnitsAtTheExactLimit() {
        ScimFilterLimits limits = ScimFilterLimits.builder().maximumExpressionCharacters(256)
                .maximumLiteralCharacters(256).build();
        String exact = "a eq \"" + "x".repeat(249) + "\"";
        assertEquals(256, exact.length());
        parse(exact, limits);
        reject(exact + " ", limits);
        reject(" ".repeat(257), limits);
    }

    @Test void literalBudgetCountsDecodedUtf16RatherThanEscapeBytes() {
        ScimFilterLimits limits = ScimFilterLimits.builder().maximumLiteralCharacters(4).build();
        parse("a eq \"abcd\"", limits);
        parse("a eq \"\\u0061\\u0062\\u0063\\u0064\"", limits);
        parse("a eq \"😀😀\"", limits);
        parse("a eq \"\\ud83d\\ude00\\ud83d\\ude00\"", limits);
        reject("a eq \"abcde\"", limits);
        reject("a eq \"\\u0061\\u0062\\u0063\\u0064\\u0065\"", limits);
        reject("a eq \"😀😀x\"", limits);
    }

    @Test void numericLexicalAndExponentBudgetsAreIndependent() {
        ScimFilterLimits fourCharacters = ScimFilterLimits.builder().maximumNumberCharacters(4).build();
        parse("a eq 1234", fourCharacters);
        parse("a eq -123", fourCharacters);
        parse("a eq 1e+2", fourCharacters);
        reject("a eq 12345", fourCharacters);
        reject("a eq 1e+20", fourCharacters);
        ScimFilterLimits exponent = ScimFilterLimits.builder().maximumNumberExponentMagnitude(2).build();
        parse("a eq 999", exponent);
        parse("a eq 1e2", exponent);
        parse("a eq 1e-2", exponent);
        reject("a eq 1e3", exponent);
        reject("a eq 1e-3", exponent);
        ScimFilterLimits noExponent = ScimFilterLimits.builder().maximumNumberExponentMagnitude(0).build();
        parse("a eq 999", noExponent);
        parse("a eq 1e0", noExponent);
        reject("a eq 1e1", noExponent);
        reject("a eq 1e-1", noExponent);
    }

    @Test void literalNumberAndExponentHardCapsHaveExactParseBoundaries() {
        ScimFilterLimits limits = ScimFilterLimits.builder().maximumExpressionCharacters(65_536)
                .maximumLiteralCharacters(16_384).maximumNumberCharacters(256)
                .maximumNumberExponentMagnitude(10_000).build();
        parse("a eq \"" + "x".repeat(16_384) + "\"", limits);
        reject("a eq \"" + "x".repeat(16_385) + "\"", limits);
        parse("a eq " + "9".repeat(256), limits);
        reject("a eq " + "9".repeat(257), limits);
        parse("a eq 1e10000", limits);
        parse("a eq 1e-10000", limits);
        reject("a eq 1e10001", limits);
        reject("a eq 1e-10001", limits);
    }

    @Test void nodeBudgetCountsRetainedNaryNodesAndAllValuePathChildren() {
        ScimFilterLimits limits = ScimFilterLimits.builder().maximumNodes(8).build();
        ScimFilter.And exact = assertInstanceOf(ScimFilter.And.class, parse(chain(7, "and"), limits));
        assertEquals(7, exact.getOperands().size());
        reject(chain(8, "and"), limits);
        ScimFilter.Or alternative = assertInstanceOf(ScimFilter.Or.class, parse(chain(7, "or"), limits));
        assertEquals(7, alternative.getOperands().size());
        reject(chain(8, "or"), limits);
        parse("members[" + chain(6, "and") + "]", limits);
        reject("members[" + chain(7, "and") + "]", limits);
    }

    @Test void astDepthAndRedundantGroupingAreBoundedIndependently() {
        ScimFilterLimits limits = ScimFilterLimits.builder().maximumDepth(4).build();
        parse("not(".repeat(3) + "a pr" + ")".repeat(3), limits);
        reject("not(".repeat(4) + "a pr" + ")".repeat(4), limits);
        parse("(".repeat(4) + "a pr" + ")".repeat(4), limits);
        reject("(".repeat(5) + "a pr" + ")".repeat(5), limits);
        parse("members[not(a pr and b pr)]", limits);
        reject("not(members[not(a pr and b pr)])", limits);
    }

    @Test void longFlatAndDeepInputsRejectWithoutUnboundedRecursion() {
        ScimFilterLimits expanded = ScimFilterLimits.builder().maximumExpressionCharacters(65_536)
                .maximumDepth(64).maximumNodes(4_096).build();
        ScimFilter.And flat = assertInstanceOf(ScimFilter.And.class, parse(chain(200, "and"), expanded));
        assertEquals(200, flat.getOperands().size());
        assertEquals(4_095, assertInstanceOf(ScimFilter.And.class, parse(chain(4_095, "and"), expanded)).getOperands().size());
        reject(chain(4_096, "and"), expanded);
        reject("(".repeat(30_000) + "a pr" + ")".repeat(30_000), expanded);
        reject("not(".repeat(10_000) + "a pr" + ")".repeat(10_000), expanded);
        reject("(".repeat(100_000) + "a pr" + ")".repeat(100_000));
        reject("a eq 1e" + "9".repeat(10_000), expanded);
        reject("a eq \"" + "\\u0061".repeat(10_000) + "\"", expanded);
    }

    @Test void errorOffsetsAreExactUtf16PositionsAndDetailsRemainFixed() {
        record Bad(@NonNull String expression, int offset) {}
        List<Bad> malformed = List.of(new Bad("", 0), new Bad("   ", 3), new Bad("a eq", 4),
                new Bad("not a pr", 4), new Bad("a regex 1", 2), new Bad("a eq +1", 5),
                new Bad("a eq true junk", 10), new Bad("a eq \"unfinished", 16),
                new Bad("(a pr", 5), new Bad("a[b[c pr]]", 3), new Bad("a eq \"😀\" junk", 10));
        String detail = ScimError.invalidFilterInstance().getDetail();
        for (Bad bad : malformed) {
            ScimError error = reject(bad.expression());
            assertEquals(bad.offset(), error.getExpressionOffset().orElseThrow(), bad.expression());
            assertEquals(detail, error.getDetail(), "Offset and input never enter the fixed wire detail");
        }
        String secret = "scim-private-value-7bed0ee2";
        ScimError error = reject("name eq \"" + secret + "\" junk");
        assertFalse(error.toString().contains(secret));
        assertFalse(error.getDetail().contains(secret));
    }

    private static @NonNull String chain(int count, @NonNull String operator) {
        return IntStream.range(0, count).mapToObj(index -> "a" + index + " pr")
                .collect(Collectors.joining(" " + operator + " "));
    }
}
