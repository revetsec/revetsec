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

import static com.revetsec.scim.ScimTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

final class ScimFilterSerializationTests {
    @Test void canonicalEmissionHasIndependentExpectedStringsAndPreservesGraph() {
        record Fixture(@NonNull String source, @NonNull String emitted) {}
        List<Fixture> fixtures = List.of(
                new Fixture(" \tUsername EQ \"x\" \n", "Username eq \"x\""),
                new Fixture("(((a PR)))", "a pr"),
                new Fixture("(a pr and b pr) and c pr", "a pr and b pr and c pr"),
                new Fixture("a pr or (b pr and c pr)", "a pr or b pr and c pr"),
                new Fixture("(a pr or b pr) and c pr", "(a pr or b pr) and c pr"),
                new Fixture("not(a pr or b pr)", "not(a pr or b pr)"),
                new Fixture("members[(value eq \"x\") AND NOT(type PR)]", "members[value eq \"x\" and not(type pr)]"),
                new Fixture("a eq 1e3", "a eq 1E3"),
                new Fixture("a eq 1e+00003", "a eq 1E3"),
                new Fixture("a eq 1e-6", "a eq 1E-6"),
                new Fixture("a eq -0.00", "a eq -0.00"),
                new Fixture("a eq true or b eq false or c eq null", "a eq true or b eq false or c eq null"),
                new Fixture("a eq \"\\u00e9\\ud83d\\ude00\\/\\\"\\\\\\n\"", "a eq \"é😀/\\\"\\\\\\n\""));
        for (Fixture fixture : fixtures) {
            ScimFilter filter = parse(fixture.source());
            assertEquals(fixture.emitted(), filter.toScimString(), fixture.source());
            assertSameGraph(filter, parse(fixture.emitted()));
            assertEquals(fixture.emitted(), parse(fixture.emitted()).toScimString());
        }
    }

    @Test void visitorDispatchesEveryKindAndKeepsOrderAndTypedValues() {
        ScimFilter filter = parse("not(a pr) and (b eq 3 or members[value eq \"x\"]) and active eq true and gone eq null");
        assertEquals("AND(NOT(PRESENT(a)),OR(COMP(b,EQ,NUMBER:3),VALUEPATH(members,COMP(value,EQ,STRING:x))),"
                + "COMP(active,EQ,BOOLEAN:true),COMP(gone,EQ,NULL))", filter.accept(new GraphVisitor()));
    }

    @Test void diagnosticsNeverExposeLiteralOrSchemaContents() {
        String secret = "scim-private-value-12c5f54b";
        ScimFilter filter = parse("urn:example:" + secret + ":name eq \"" + secret
                + "\" and number eq 12345678901234567890 and members[value eq \"" + secret + "\"]");
        assertFalse(filter.toString().contains(secret));
        assertFalse(filter.toString().contains("12345678901234567890"));
        assertTrue(filter.toScimString().contains(secret), "Explicit data serialization retains the literal");
        inspectRedaction(filter, secret);
    }

    @Test void logicalOperandCollectionsAreImmutable() {
        ScimFilter.And and = assertInstanceOf(ScimFilter.And.class, parse("a pr and b pr"));
        ScimFilter.Or or = assertInstanceOf(ScimFilter.Or.class, parse("a pr or b pr"));
        assertThrows(UnsupportedOperationException.class, () -> and.getOperands().clear());
        assertThrows(UnsupportedOperationException.class, () -> or.getOperands().add(parse("c pr")));
        assertEquals("a pr and b pr", and.toScimString());
        assertEquals("a pr or b pr", or.toScimString());
    }

    private static void inspectRedaction(@NonNull ScimFilter filter, @NonNull String secret) {
        assertFalse(filter.toString().contains(secret));
        if (filter instanceof ScimFilter.Comparison comparison) {
            assertFalse(comparison.getValue().toString().contains(secret));
            assertFalse(comparison.getAttributePath().toString().contains(secret));
        } else if (filter instanceof ScimFilter.And and) {
            for (ScimFilter operand : and.getOperands()) inspectRedaction(operand, secret);
        } else if (filter instanceof ScimFilter.Or or) {
            for (ScimFilter operand : or.getOperands()) inspectRedaction(operand, secret);
        } else if (filter instanceof ScimFilter.Not not) {
            inspectRedaction(not.getOperand(), secret);
        } else if (filter instanceof ScimFilter.ValuePath valuePath) {
            inspectRedaction(valuePath.getFilter(), secret);
        }
    }

    private static final class GraphVisitor implements ScimFilterVisitor<@NonNull String> {
        @Override public @NonNull String visitAnd(ScimFilter.@NonNull And filter) {
            return "AND(" + children(filter.getOperands()) + ")";
        }
        @Override public @NonNull String visitOr(ScimFilter.@NonNull Or filter) {
            return "OR(" + children(filter.getOperands()) + ")";
        }
        @Override public @NonNull String visitNot(ScimFilter.@NonNull Not filter) {
            return "NOT(" + filter.getOperand().accept(this) + ")";
        }
        @Override public @NonNull String visitComparison(ScimFilter.@NonNull Comparison filter) {
            ScimFilterValue value = filter.getValue();
            String typed;
            if (value instanceof ScimFilterValue.StringValue string) typed = "STRING:" + string.getValue();
            else if (value instanceof ScimFilterValue.NumberValue number) typed = "NUMBER:" + number.getValue();
            else if (value instanceof ScimFilterValue.BooleanValue bool) typed = "BOOLEAN:" + bool.getValue();
            else typed = "NULL";
            return "COMP(" + filter.getAttributePath().toScimString() + "," + filter.getOperator() + "," + typed + ")";
        }
        @Override public @NonNull String visitPresent(ScimFilter.@NonNull Present filter) {
            return "PRESENT(" + filter.getAttributePath().toScimString() + ")";
        }
        @Override public @NonNull String visitValuePath(ScimFilter.@NonNull ValuePath filter) {
            return "VALUEPATH(" + filter.getAttributePath().toScimString() + "," + filter.getFilter().accept(this) + ")";
        }
        private @NonNull String children(@NonNull List<@NonNull ScimFilter> children) {
            return children.stream().map(child -> child.accept(this)).collect(Collectors.joining(","));
        }
    }
}
