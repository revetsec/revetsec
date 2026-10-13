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

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;

import static org.junit.jupiter.api.Assertions.*;

final class ScimFilterConfigurationTests {
    @Test void filterLimitsHaveFrozenDefaultsAndNullRestoresEveryDefault() {
        ScimFilterLimits defaults = ScimFilterLimits.defaultInstance();
        assertSame(defaults, ScimFilterLimits.defaultInstance());
        assertNotSame(defaults, ScimFilterLimits.builder().build());
        assertLimits(defaults, 4_096, 16, 128, 2_048, 64, 1_000);
        ScimFilterLimits.Builder builder = ScimFilterLimits.builder().maximumExpressionCharacters(8_192)
                .maximumDepth(32).maximumNodes(256).maximumLiteralCharacters(4_096)
                .maximumNumberCharacters(128).maximumNumberExponentMagnitude(2_000);
        ScimFilterLimits before = builder.build();
        assertLimits(before, 8_192, 32, 256, 4_096, 128, 2_000);
        assertSame(builder, builder.maximumExpressionCharacters(null));
        assertSame(builder, builder.maximumDepth(null));
        assertSame(builder, builder.maximumNodes(null));
        assertSame(builder, builder.maximumLiteralCharacters(null));
        assertSame(builder, builder.maximumNumberCharacters(null));
        assertSame(builder, builder.maximumNumberExponentMagnitude(null));
        assertLimits(builder.build(), 4_096, 16, 128, 2_048, 64, 1_000);
        assertLimits(before, 8_192, 32, 256, 4_096, 128, 2_000);
    }

    @Test void configurableLimitsAcceptEndpointsAndRejectOutsideRanges() {
        assertLimits(ScimFilterLimits.builder().maximumExpressionCharacters(256).maximumDepth(4)
                .maximumNodes(8).maximumLiteralCharacters(1).maximumNumberCharacters(1)
                .maximumNumberExponentMagnitude(0).build(), 256, 4, 8, 1, 1, 0);
        assertLimits(ScimFilterLimits.builder().maximumExpressionCharacters(65_536).maximumDepth(64)
                .maximumNodes(4_096).maximumLiteralCharacters(16_384).maximumNumberCharacters(256)
                .maximumNumberExponentMagnitude(10_000).build(), 65_536, 64, 4_096, 16_384, 256, 10_000);
        Set<@NonNull UnaryOperator<ScimFilterLimits.@NonNull Builder>> changes = Set.of(
                builder -> builder.maximumExpressionCharacters(255), builder -> builder.maximumExpressionCharacters(65_537),
                builder -> builder.maximumDepth(3), builder -> builder.maximumDepth(65),
                builder -> builder.maximumNodes(7), builder -> builder.maximumNodes(4_097),
                builder -> builder.maximumLiteralCharacters(0), builder -> builder.maximumLiteralCharacters(16_385),
                builder -> builder.maximumNumberCharacters(0), builder -> builder.maximumNumberCharacters(257),
                builder -> builder.maximumNumberExponentMagnitude(-1), builder -> builder.maximumNumberExponentMagnitude(10_001));
        for (UnaryOperator<ScimFilterLimits.@NonNull Builder> change : changes) {
            assertThrows(IllegalArgumentException.class, () -> change.apply(ScimFilterLimits.builder()).build());
        }
        assertThrows(IllegalArgumentException.class, () -> ScimFilterLimits.builder()
                .maximumExpressionCharacters(256).maximumLiteralCharacters(257).build());
    }

    @Test void policyDefaultsAndNullResetRejectAllPermissions() {
        assertRejectAll(ScimFilterPolicy.builder().build());
        assertRejectAll(ScimFilterPolicy.rejectAllInstance());
        assertSame(ScimFilterPolicy.rejectAllInstance(), ScimFilterPolicy.rejectAllInstance());
        ScimFilterPolicy.Builder builder = ScimFilterPolicy.builder()
                .allowedComparisons(Map.of("userName", Set.of(ScimComparisonOperator.EQ)))
                .allowedPresence(Set.of("title"))
                .allowedValuePaths(Map.of("members", ScimFilterPolicy.rejectAllInstance()))
                .allowedLogicalOperators(Set.of(ScimLogicalOperator.AND)).maximumComparisons(64);
        ScimFilterPolicy prior = builder.build();
        assertSame(builder, builder.allowedComparisons(null));
        assertSame(builder, builder.allowedPresence(null));
        assertSame(builder, builder.allowedValuePaths(null));
        assertSame(builder, builder.allowedLogicalOperators(null));
        assertSame(builder, builder.maximumComparisons(null));
        assertRejectAll(builder.build());
        assertEquals(64, prior.getMaximumComparisons());
        assertFalse(prior.getAllowedComparisons().isEmpty());
    }

    @Test void policyCapturesDefensiveSnapshotsAndReturnsImmutableNestedCollections() {
        Set<ScimComparisonOperator> comparisons = new HashSet<>(Set.of(ScimComparisonOperator.EQ));
        Map<String, Set<ScimComparisonOperator>> attributes = new LinkedHashMap<>();
        attributes.put("userName", comparisons);
        Set<String> presence = new LinkedHashSet<>(Set.of("title"));
        Map<String, ScimFilterPolicy> valuePaths = new LinkedHashMap<>();
        valuePaths.put("members", ScimFilterPolicy.rejectAllInstance());
        Set<ScimLogicalOperator> logical = new HashSet<>(Set.of(ScimLogicalOperator.AND));
        ScimFilterPolicy.Builder builder = ScimFilterPolicy.builder().allowedComparisons(attributes)
                .allowedPresence(presence).allowedValuePaths(valuePaths).allowedLogicalOperators(logical);
        ScimFilterPolicy policy = builder.build();
        comparisons.add(ScimComparisonOperator.CO);
        attributes.clear();
        presence.clear();
        valuePaths.clear();
        logical.clear();
        assertEquals(Set.of(ScimComparisonOperator.EQ), policy.getAllowedComparisons().values().iterator().next());
        assertEquals(1, policy.getAllowedPresence().size());
        assertEquals(1, policy.getAllowedValuePaths().size());
        assertEquals(Set.of(ScimLogicalOperator.AND), policy.getAllowedLogicalOperators());
        assertEquals(policy.getAllowedComparisons(), builder.build().getAllowedComparisons());
        assertThrows(UnsupportedOperationException.class, () -> policy.getAllowedComparisons().clear());
        assertThrows(UnsupportedOperationException.class,
                () -> policy.getAllowedComparisons().values().iterator().next().clear());
        assertThrows(UnsupportedOperationException.class, () -> policy.getAllowedPresence().clear());
        assertThrows(UnsupportedOperationException.class, () -> policy.getAllowedValuePaths().clear());
        assertThrows(UnsupportedOperationException.class, () -> policy.getAllowedLogicalOperators().clear());
    }

    @Test void policyRejectsMalformedAmbiguousAndSubattributeValuePathKeys() {
        assertThrows(IllegalArgumentException.class, () -> ScimFilterPolicy.builder()
                .allowedComparisons(Map.of("a.b.c", Set.of(ScimComparisonOperator.EQ))).build());
        assertThrows(IllegalArgumentException.class, () -> ScimFilterPolicy.builder().allowedPresence(Set.of(" bad")).build());
        assertThrows(IllegalArgumentException.class, () -> ScimFilterPolicy.builder()
                .allowedComparisons(Map.of("Name", Set.of(ScimComparisonOperator.EQ),
                        "name", Set.of(ScimComparisonOperator.CO))).build());
        assertThrows(IllegalArgumentException.class, () -> ScimFilterPolicy.builder().allowedPresence(Set.of("Name", "name")).build());
        assertThrows(IllegalArgumentException.class, () -> ScimFilterPolicy.builder()
                .allowedValuePaths(Map.of("members.value", ScimFilterPolicy.rejectAllInstance())).build());
        assertThrows(IllegalArgumentException.class, () -> ScimFilterPolicy.builder()
                .allowedValuePaths(Map.of("Members", ScimFilterPolicy.rejectAllInstance(),
                        "members", ScimFilterPolicy.rejectAllInstance())).build());
        assertThrows(IllegalArgumentException.class, () -> ScimFilterPolicy.builder().maximumComparisons(0).build());
        assertThrows(IllegalArgumentException.class, () -> ScimFilterPolicy.builder().maximumComparisons(129).build());
        assertEquals(1, ScimFilterPolicy.builder().maximumComparisons(1).build().getMaximumComparisons());
        assertEquals(128, ScimFilterPolicy.builder().maximumComparisons(128).build().getMaximumComparisons());
    }

    @Test void nestedPolicyDepthAndConfigurationWorkHaveFiniteExactCaps() {
        ScimFilterPolicy nested = ScimFilterPolicy.builder().build();
        for (int depth = 2; depth <= 64; ++depth) {
            nested = ScimFilterPolicy.builder().allowedValuePaths(Map.of("members", nested)).build();
        }
        ScimFilterPolicy atCap = nested;
        assertThrows(IllegalArgumentException.class,
                () -> ScimFilterPolicy.builder().allowedValuePaths(Map.of("members", atCap)).build());
        Set<String> paths = new LinkedHashSet<>();
        Map<String, ScimFilterPolicy> children = new LinkedHashMap<>();
        for (int index = 0; index < 4_095; ++index) {
            paths.add("a" + index);
            children.put("a" + index, ScimFilterPolicy.rejectAllInstance());
        }
        assertEquals(4_095, ScimFilterPolicy.builder().allowedValuePaths(children).build()
                .getAllowedValuePaths().size());
        paths.add("a4095");
        assertEquals(4_096, ScimFilterPolicy.builder().allowedPresence(paths).build().getAllowedPresence().size());
        children.put("a4095", ScimFilterPolicy.rejectAllInstance());
        assertThrows(IllegalArgumentException.class, () -> ScimFilterPolicy.builder().allowedValuePaths(children).build());
        paths.add("a4096");
        assertThrows(IllegalArgumentException.class, () -> ScimFilterPolicy.builder().allowedPresence(paths).build());
    }

    private static void assertLimits(@NonNull ScimFilterLimits limits, int expression, int depth, int nodes,
                                     int literal, int number, int exponent) {
        assertEquals(expression, limits.getMaximumExpressionCharacters());
        assertEquals(depth, limits.getMaximumDepth());
        assertEquals(nodes, limits.getMaximumNodes());
        assertEquals(literal, limits.getMaximumLiteralCharacters());
        assertEquals(number, limits.getMaximumNumberCharacters());
        assertEquals(exponent, limits.getMaximumNumberExponentMagnitude());
    }

    private static void assertRejectAll(@NonNull ScimFilterPolicy policy) {
        assertTrue(policy.getAllowedComparisons().isEmpty());
        assertTrue(policy.getAllowedPresence().isEmpty());
        assertTrue(policy.getAllowedValuePaths().isEmpty());
        assertTrue(policy.getAllowedLogicalOperators().isEmpty());
        assertEquals(32, policy.getMaximumComparisons());
    }
}
