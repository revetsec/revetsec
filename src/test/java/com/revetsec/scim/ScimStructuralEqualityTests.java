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

import org.junit.jupiter.api.Test;
import org.jspecify.annotations.NonNull;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Structural equality laws and explicit semantic cases, independent of AST construction algorithms. */
class ScimStructuralEqualityTests {
    @Test
    void conjunctionsCompareFlattenedOrderedOperands() {
        equal(filter("a pr and (b pr and c pr)"), filter("A PR and B pr and C pr"));
        unequal(filter("a pr and b pr"), filter("b pr and a pr"));
        unequal(filter("a pr and b pr"), filter("a pr and c pr"));
        unequal(filter("a pr and b pr"), filter("a pr or b pr"));
    }

    @Test
    void disjunctionsCompareFlattenedOrderedOperands() {
        equal(filter("a pr or (b pr or c pr)"), filter("A PR or B pr or C pr"));
        unequal(filter("a pr or b pr"), filter("b pr or a pr"));
        unequal(filter("a pr or b pr"), filter("a pr or c pr"));
        unequal(filter("a pr or b pr"), filter("a pr and b pr"));
    }

    @Test
    void negationComparesItsCompleteOperand() {
        equal(filter("not(a pr)"), filter("NOT(A PR)"));
        unequal(filter("not(a pr)"), filter("not(b pr)"));
        unequal(filter("not(a pr)"), filter("a pr"));
        unequal(filter("not(a pr)"), filter("not(not(a pr))"));
    }

    @Test
    void comparisonsIncludePathOperatorAndExactLiteralSemantics() {
        equal(filter("userName eq 1"), filter("USERNAME EQ 1.0"));
        equal(filter("userName eq 1.0"), filter("userName eq 1e0"));
        equal(filter("urn:example:User:userName eq 1"), filter("URN:EXAMPLE:USER:USERNAME EQ 1.0"));
        unequal(filter("userName eq 1"), filter("userName ne 1"));
        unequal(filter("userName eq 1"), filter("displayName eq 1"));
        unequal(filter("userName eq 1"), filter("userName eq 2"));
        unequal(filter("userName eq 1"), filter("userName eq \"1\""));
        unequal(filter("userName eq 1"), filter("userName pr"));
    }

    @Test
    void presenceComparesStructuralPath() {
        equal(filter("name.familyName pr"), filter("NAME.FAMILYNAME PR"));
        unequal(filter("name.familyName pr"), filter("name.givenName pr"));
        unequal(filter("name.familyName pr"), filter("name.familyName eq null"));
    }

    @Test
    void valuePathsCompareOuterPathAndWholeSameElementPredicate() {
        equal(filter("emails[type eq \"work\" and value co \"a\"]"),
                filter("EMAILS[TYPE EQ \"work\" and VALUE CO \"a\"]"));
        unequal(filter("emails[type eq \"work\"]"), filter("phones[type eq \"work\"]"));
        unequal(filter("emails[type eq \"work\"]"), filter("emails[type eq \"home\"]"));
        unequal(filter("emails[type eq \"work\" and value pr]"), filter("emails[type eq \"work\" or value pr]"));
        unequal(filter("emails[type eq \"work\"]"), filter("emails.type eq \"work\""));
    }

    @Test
    void allFourLiteralKindsHaveValueEqualityAndHashContracts() {
        equal(value("\"a\""), value("\"\\u0061\""));
        unequal(value("\"a\""), value("\"A\""));
        unequal(value("\"1\""), value("1"));

        equal(value("1"), value("1.0"));
        equal(value("1.0"), value("1e0"));
        equal(value("-0"), value("0.0e0"));
        unequal(value("1"), value("2"));
        // Integers beyond binary64 precision remain distinct exact decimal values.
        unequal(value("9007199254740992"), value("9007199254740993"));
        // Distinct tiny decimal values remain distinct even below binary64's range.
        unequal(value("1e-900"), value("1e-901"));
        unequal(value("1"), value("true"));

        equal(value("true"), value("true"));
        unequal(value("true"), value("false"));
        unequal(value("true"), value("1"));

        equal(value("null"), value("null"));
        unequal(value("null"), value("\"null\""));
    }

    @Test
    void diagnosticsDoNotEmitFilterOrLiteralContent() {
        String marker = "SENSITIVE_PERSONAL_MARKER_781359";
        for (ScimFilter tree : representativeKinds(marker)) {
            assertTrue(tree.toString().contains("<redacted>"));
            assertFalse(tree.toString().contains(marker));
            assertTrue(tree.toScimString().contains(marker));
            if (tree instanceof ScimFilter.Comparison comparison)
                assertFalse(comparison.getValue().toString().contains(marker));
        }
        for (String expression : List.of("\"" + marker + "\"", "987654321", "true", "null")) {
            String diagnostic = value(expression).toString();
            assertTrue(diagnostic.contains("<redacted>"));
            assertFalse(diagnostic.contains(marker));
            assertFalse(diagnostic.contains("987654321"));
        }
        var succeeded = ScimFilter.fromExpressionResult("a eq \"" + marker + "\"");
        var rejected = ScimFilter.fromExpressionResult("a eq \"" + marker);
        assertFalse(succeeded.toString().contains(marker));
        assertFalse(rejected.toString().contains(marker));
        assertTrue(succeeded.toString().contains("<redacted>"));
        assertTrue(rejected.toString().contains("<redacted>"));
        String limits = ScimFilterLimits.defaultInstance().toString();
        assertTrue(limits.contains("ScimFilterLimits"));
        assertFalse(limits.contains(marker));
    }

    @Test
    // Intentional API misuse verifies the documented runtime rejection alongside static null checking.
    @SuppressWarnings("NullAway")
    void everyNodeRejectsDocumentedNullVisitorArgumentAndResult() {
        ScimFilterVisitor<String> visitor = new NullReturningVisitor();
        for (ScimFilter tree : representativeKinds("marker")) {
            assertThrows(NullPointerException.class, () -> tree.accept(null));
            assertThrows(NullPointerException.class, () -> tree.accept(visitor));
        }
    }

    private static @NonNull List<@NonNull ScimFilter> representativeKinds(@NonNull String marker) {
        String literal = "\"" + marker + "\"";
        return List.of(filter("a eq " + literal + " and b pr"), filter("a eq " + literal + " or b pr"),
                filter("not(a eq " + literal + ")"), filter("a eq " + literal),
                filter(marker + " pr"), filter("emails[value eq " + literal + "]"));
    }

    private static @NonNull ScimFilter filter(@NonNull String expression) {
        return assertInstanceOf(ScimFilterParseResult.Succeeded.class,
                ScimFilter.fromExpressionResult(expression)).getFilter();
    }

    private static @NonNull ScimFilterValue value(@NonNull String literal) {
        return assertInstanceOf(ScimFilter.Comparison.class, filter("a eq " + literal)).getValue();
    }

    // The equals(null) contract itself is the behavior under test.
    @SuppressWarnings("EqualsNull")
    private static void equal(@NonNull Object first, @NonNull Object second) {
        assertEquals(first, second);
        assertEquals(second, first);
        assertEquals(first.hashCode(), second.hashCode());
        assertTrue(first.equals(first));
        assertTrue(second.equals(second));
        assertFalse(first.equals(null));
        assertFalse(second.equals(null));
        assertFalse(first.equals(new Object()));
        assertFalse(second.equals(new Object()));
    }

    private static void unequal(@NonNull Object first, @NonNull Object second) {
        assertNotEquals(first, second);
        assertNotEquals(second, first);
    }

    // Deliberately faulty application callbacks exercise the documented runtime contract.
    @SuppressWarnings("NullAway")
    private static final class NullReturningVisitor implements ScimFilterVisitor<String> {
        @Override public @NonNull String visitAnd(ScimFilter.@NonNull And filter) { return null; }
        @Override public @NonNull String visitOr(ScimFilter.@NonNull Or filter) { return null; }
        @Override public @NonNull String visitNot(ScimFilter.@NonNull Not filter) { return null; }
        @Override public @NonNull String visitComparison(ScimFilter.@NonNull Comparison filter) { return null; }
        @Override public @NonNull String visitPresent(ScimFilter.@NonNull Present filter) { return null; }
        @Override public @NonNull String visitValuePath(ScimFilter.@NonNull ValuePath filter) { return null; }
    }
}
