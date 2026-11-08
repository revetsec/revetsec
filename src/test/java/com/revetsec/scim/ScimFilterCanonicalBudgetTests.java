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

import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

final class ScimFilterCanonicalBudgetTests {
    private static final String URN = "urn:revetsec:test:canonical-budget";
    private static final ScimResourceType TYPE = ScimResourceType.withName("Budget").endpoint("/Budgets")
            .schema(ScimSchema.withId(URN).name("Budget").attributes(List.of(
                    ScimAttributeDefinition.withName("text").build(),
                    ScimAttributeDefinition.withName("flag").type(ScimAttributeType.BOOLEAN).build(),
                    ScimAttributeDefinition.withName("number").type(ScimAttributeType.DECIMAL).build(),
                    ScimAttributeDefinition.withName("hidden").returned(ScimReturned.NEVER).build(),
                    ScimAttributeDefinition.withName("tags").type(ScimAttributeType.COMPLEX).multiValued(true)
                            .subAttributes(List.of(ScimAttributeDefinition.withName("value").build())).build())).build()).build();
    private static final ScimFilterPolicy POLICY = ScimFilterPolicy.builder()
            .allowedComparisons(Map.of("text", Set.of(ScimComparisonOperator.EQ), "tags.value", Set.of(ScimComparisonOperator.EQ),
                    "flag", Set.of(ScimComparisonOperator.EQ), "number", Set.of(ScimComparisonOperator.EQ)))
            .allowedPresence(Set.of("text", "flag", "tags"))
            .allowedLogicalOperators(EnumSet.allOf(ScimLogicalOperator.class))
            .allowedValuePaths(Map.of("tags", ScimFilterPolicy.builder()
                    .allowedComparisons(Map.of("value", Set.of(ScimComparisonOperator.EQ)))
                    .allowedLogicalOperators(EnumSet.allOf(ScimLogicalOperator.class)).build())).build();
    private static final ScimCompatibility STRICT = ScimCompatibility.builder().build();

    @TestFactory @NonNull Stream<@NonNull DynamicTest> acceptedCompactExpressionsSurviveCanonicalGrowth() {
        return Stream.of(256, 4096, 16384).flatMap(cap -> Stream.of("comparison", "and", "or", "not")
                .flatMap(shape -> Stream.of(false, true).map(bound -> DynamicTest.dynamicTest(
                        "cap=" + cap + " shape=" + shape + " bound=" + bound, () -> {
            String prefix = shape.equals("not") ? "not(tags eq \"" : "tags eq \"";
            String suffix = shape.equals("not") ? "\")" : shape.equals("and") ? "\" and flag eq true"
                    : shape.equals("or") ? "\" or flag eq false" : "\"";
            String literal = "a".repeat(cap - prefix.length() - suffix.length());
            String source = prefix + literal + suffix;
            assertEquals(cap, source.length());
            var provider = provider(limits(cap), POLICY, STRICT, new AtomicInteger(), 4_000_000);
            ScimFilter tree = bound ? approved(provider, source) : syntax(source);
            if (bound) assertTrue(tree.toScimString().length() > cap, "binding must grow the accepted source");
            var result = assertInstanceOf(ScimFilterEvaluationResult.Succeeded.class,
                    ScimFilterEvaluator.fromServiceProvider(provider).evaluateResult(resource(literal), tree));
            assertEquals(!shape.equals("not"), result.isMatched());
        }))));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> normalizedValuePathComparisonKeepsTheAcceptedSource() {
        return Stream.of(256, 4096, 16384).map(cap -> DynamicTest.dynamicTest("ValuePath cap=" + cap, () -> {
            var compatibility = ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.FILTER_VALUE_PATH_SUB_ATTRIBUTE_COMPARISON)).build();
            var provider = provider(limits(cap), POLICY, compatibility, new AtomicInteger(), 4_000_000);
            String prefix = "tags[value eq \"";
            String suffix = "\"].value eq \"a\"";
            String literal = "a".repeat(cap - prefix.length() - suffix.length());
            String source = prefix + literal + suffix;
            ScimFilter tree = approved(provider, source);
            assertEquals(cap, source.length());
            assertTrue(tree.toScimString().length() > cap);
            assertFalse(assertInstanceOf(ScimFilterEvaluationResult.Succeeded.class,
                    ScimFilterEvaluator.fromServiceProvider(provider).evaluateResult(resource(literal), tree)).isMatched());
        }));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> everyRootKindKeepsTheReceivingRawExpressionCap() {
        return Stream.of("text eq \"a\"", "text eq \"a\" and flag eq true", "text eq \"a\" or flag eq false",
                "not(text eq \"z\")", "text pr", "tags[value eq \"a\"]").flatMap(expression -> Stream.of(false, true)
                .map(bound -> DynamicTest.dynamicTest("foreign root=" + expression + " bound=" + bound, () -> {
            String source = expression + " ".repeat(257 - expression.length());
            var high = provider(limits(512), POLICY, STRICT, new AtomicInteger(), 4_000_000);
            var calls = new AtomicInteger();
            var low = provider(limits(256), POLICY, STRICT, calls, 4_000_000);
            ScimFilter tree = bound ? approved(high, source) : syntax(source);
            assertTrue(tree.toScimString().length() < 256);
            assertInvalid(low, resource("a"), tree);
            assertEquals(0, calls.get());
        })));
    }

    @Test void rawNumberBudgetCannotBeBypassedByNumericCanonicalization() {
        var source = provider(limits(256), POLICY, STRICT, new AtomicInteger(), 4_000_000);
        var receivingLimits = ScimFilterLimits.builder().maximumNumberCharacters(4).build();
        var receiving = provider(receivingLimits, POLICY, STRICT, new AtomicInteger(), 4_000_000);
        ScimFilter tree = approved(source, "number eq 1e+000000000001");
        assertEquals("number eq 1E1", tree.toScimString());
        assertInvalid(receiving, resource("a"), tree);
    }

    @Test void normalizedCompatibilityDoesNotGrantPermissionToAStrictReceiver() {
        var permissive = ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.BOOLEAN_STRINGS)).build();
        var high = provider(limits(256), POLICY, permissive, new AtomicInteger(), 4_000_000);
        var strict = provider(limits(256), POLICY, STRICT, new AtomicInteger(), 4_000_000);
        ScimFilter tree = approved(high, "flag eq \"true\"");
        assertEquals("flag eq true", tree.toScimString());
        assertInvalid(strict, resource("a"), tree);
        assertTrue(assertInstanceOf(ScimFilterEvaluationResult.Succeeded.class,
                ScimFilterEvaluator.fromServiceProvider(high).evaluateResult(resource("a"), tree)).isMatched());
    }

    @Test void approvedGetAndSearchFiltersRetainTheirAcceptedSourceBudget() {
        var provider = provider(limits(256), POLICY, STRICT, new AtomicInteger(), 4_000_000);
        String literal = "a".repeat(246);
        String source = "tags eq \"" + literal + "\"";
        assertEquals(256, source.length());
        var query = assertInstanceOf(ScimQueryParseResult.Succeeded.class, provider.parseQueryResult(TYPE,
                "filter=" + URLEncoder.encode(source, StandardCharsets.UTF_8))).getQuery();
        assertTrue(assertInstanceOf(ScimFilterEvaluationResult.Succeeded.class,
                ScimFilterEvaluator.fromServiceProvider(provider).evaluateResult(resource(literal), query.getFilter().orElseThrow())).isMatched());
        var body = JsonObject.builder().put("schemas", JsonArray.fromElements(List.of(com.revetsec.json.JsonString.fromValue("urn:ietf:params:scim:api:messages:2.0:SearchRequest"))))
                .put("filter", source).build();
        var search = assertInstanceOf(ScimQueryParseResult.Succeeded.class, provider.parseSearchRequestResult(TYPE,
                List.of("application/scim+json"), body.toJson().getBytes(StandardCharsets.UTF_8))).getQuery();
        assertTrue(assertInstanceOf(ScimFilterEvaluationResult.Succeeded.class,
                ScimFilterEvaluator.fromServiceProvider(provider).evaluateResult(resource(literal), search.getFilter().orElseThrow())).isMatched());
    }

    @Test void maximumExpressionCanBeComposedOfSeveralMaximumBoundedLiterals() {
        int cap = 65536;
        StringBuilder source = new StringBuilder();
        int totalLiteral = cap - 4 * "tags eq \"\"".length() - 3 * " or ".length();
        String first = "";
        for (int i = 0; i < 4; i++) {
            if (i > 0) source.append(" or ");
            String literal = "a".repeat(totalLiteral / 4 + (i < totalLiteral % 4 ? 1 : 0));
            if (i == 0) first = literal;
            source.append("tags eq \"").append(literal).append('"');
        }
        assertEquals(cap, source.length());
        var provider = provider(limits(cap), POLICY, STRICT, new AtomicInteger(), 4_000_000);
        ScimFilter tree = approved(provider, source.toString());
        assertTrue(tree.toScimString().length() > cap);
        assertTrue(assertInstanceOf(ScimFilterEvaluationResult.Succeeded.class,
                ScimFilterEvaluator.fromServiceProvider(provider).evaluateResult(resource(first), tree)).isMatched());
    }

    @Test void reapprovalAndSchemaBindingAreNeverSkippedForAnOriginBearingTree() {
        var high = provider(limits(256), POLICY, STRICT, new AtomicInteger(), 4_000_000);
        ScimFilter tree = approved(high, "text eq \"a\"");
        var calls = new AtomicInteger();
        var denied = provider(limits(256), ScimFilterPolicy.rejectAllInstance(), STRICT, calls, 4_000_000);
        assertInvalid(denied, resource("a"), tree);
        assertEquals(0, calls.get());
        assertInvalid(high, resource("a"), syntax("unknown eq \"a\""));
        assertInvalid(high, resource("a"), syntax("hidden eq \"private\""));
        assertInvalid(high, resource("a"), syntax("flag eq \"true\""));
    }

    @Test void structuralLiteralAndWorkLimitsStillPrecedeMatching() {
        var calls = new AtomicInteger();
        var shortLiteral = ScimFilterLimits.builder().maximumLiteralCharacters(1).build();
        assertInvalid(provider(shortLiteral, POLICY, STRICT, calls, 4_000_000), resource("a"), syntax("text eq \"aa\""));
        var shallow = ScimFilterLimits.builder().maximumDepth(4).build();
        assertInvalid(provider(shallow, POLICY, STRICT, calls, 4_000_000), resource("a"), syntax("not(not(not(not(text pr))))"));
        var fewNodes = ScimFilterLimits.builder().maximumNodes(8).build();
        assertInvalid(provider(fewNodes, POLICY, STRICT, calls, 4_000_000), resource("a"),
                syntax(String.join(" or ", java.util.Collections.nCopies(8, "text pr"))));
        assertEquals(0, calls.get());
        String literal = "a".repeat(15000);
        var workLimited = provider(limits(16384), POLICY, STRICT, calls, 10000);
        var rejected = assertInstanceOf(ScimFilterEvaluationResult.Rejected.class,
                ScimFilterEvaluator.fromServiceProvider(workLimited).evaluateResult(resource(literal), syntax("text eq \"" + literal + "\"")));
        assertSame(ScimError.requestTooLargeInstance(), rejected.getError());
        assertEquals(0, calls.get());
    }

    @Test void transientGroupingDepthIsStillAReceivingParserLimit() {
        var receiving = provider(ScimFilterLimits.builder().maximumDepth(4).build(), POLICY, STRICT, new AtomicInteger(), 4_000_000);
        ScimFilter tree = syntax("(((((text pr)))))");
        assertEquals("text pr", tree.toScimString());
        assertInvalid(receiving, resource("a"), tree);
    }

    @Test void extractedSubtreesUseTheBoundedCanonicalFallback() {
        var receiving = provider(limits(256), POLICY, STRICT, new AtomicInteger(), 4_000_000);
        ScimFilter.Or small = assertInstanceOf(ScimFilter.Or.class, syntax("text eq \"a\" or flag eq false"));
        assertTrue(assertInstanceOf(ScimFilterEvaluationResult.Succeeded.class,
                ScimFilterEvaluator.fromServiceProvider(receiving).evaluateResult(resource("a"), small.getOperands().get(0))).isMatched());
        String compact = "tags eq \"" + "a".repeat(247) + "\"";
        ScimFilter.Or large = assertInstanceOf(ScimFilter.Or.class, syntax(compact + " or flag eq false"));
        assertEquals(257, large.getOperands().get(0).toScimString().length());
        ScimError refusal = assertInvalid(receiving, resource("a"), large.getOperands().get(0));
        assertTrue(refusal.getExpressionOffset().isEmpty(), "fallback size refusal occurs before canonical reparse");
    }

    @Test void provenanceDoesNotChangeEqualityHashRenderingOrRedaction() {
        for (String source : List.of("text eq \"a\"", "text eq \"a\" and flag eq true", "text eq \"a\" or flag eq false",
                "not(text eq \"a\")", "text pr", "tags[value eq \"a\"]")) {
            ScimFilter first = syntax(source);
            ScimFilter second = syntax(" " + source + " ");
            assertEquals(first, second);
            assertEquals(first.hashCode(), second.hashCode());
            assertEquals(first.toScimString(), second.toScimString());
            assertFalse(first.toString().contains(source));
            assertEquals(first, syntax(first.toScimString()));
        }
    }

    private static @NonNull ScimFilterLimits limits(int cap) {
        return ScimFilterLimits.builder().maximumExpressionCharacters(cap).maximumLiteralCharacters(Math.min(cap, 16384)).build();
    }
    private static @NonNull ScimServiceProvider provider(@NonNull ScimFilterLimits filterLimits, @NonNull ScimFilterPolicy policy,
            @NonNull ScimCompatibility compatibility, @NonNull AtomicInteger calls, int work) {
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(TYPE)).limits(ScimLimits.builder().filterLimits(filterLimits).maximumWorkUnits(work).build())
                .compatibility(compatibility).filterPolicies(Map.of(TYPE, policy))
                .serviceProviderConfig(ScimServiceProviderConfig.builder().filterSupported(true).build())
                .stringMatching((path, definition, operator, left, right) -> {
                    calls.incrementAndGet(); return ScimStringMatchResult.fromMatched(left.equals(right));
                }).build();
    }
    private static @NonNull ScimResource resource(@NonNull String text) {
        return ScimResource.withResourceType(TYPE).document(JsonObject.builder().put("schemas", JsonArray.fromElements(List.of(com.revetsec.json.JsonString.fromValue(URN))))
                .put("text", text).put("flag", true).put("number", com.revetsec.json.JsonNumber.fromValue(java.math.BigDecimal.TEN))
                .put("tags", JsonArray.fromElements(List.of(JsonObject.builder().put("value", text).build()))).build()).build();
    }
    private static @NonNull ScimFilter syntax(@NonNull String source) {
        var limits = ScimFilterLimits.builder().maximumExpressionCharacters(65536).maximumLiteralCharacters(16384).build();
        return assertInstanceOf(ScimFilterParseResult.Succeeded.class, ScimFilter.fromExpressionResult(source, limits)).getFilter();
    }
    private static @NonNull ScimFilter approved(@NonNull ScimServiceProvider provider, @NonNull String source) {
        return assertInstanceOf(ScimFilterParseResult.Succeeded.class, provider.parseFilterResult(TYPE, source)).getFilter();
    }
    private static @NonNull ScimError assertInvalid(@NonNull ScimServiceProvider provider, @NonNull ScimResource resource, @NonNull ScimFilter tree) {
        ScimError error = assertInstanceOf(ScimFilterEvaluationResult.Rejected.class,
                ScimFilterEvaluator.fromServiceProvider(provider).evaluateResult(resource, tree)).getError();
        assertEquals(ScimError.invalidFilterInstance().getErrorType(), error.getErrorType());
        assertEquals(400, error.getStatusCode());
        return error;
    }
}
