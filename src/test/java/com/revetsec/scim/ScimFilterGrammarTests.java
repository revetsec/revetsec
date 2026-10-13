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
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.math.BigDecimal;
import java.util.List;
import java.util.stream.Stream;

import static com.revetsec.scim.ScimComparisonOperator.*;
import static com.revetsec.scim.ScimTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Expected grammar and graphs are hand-authored from RFC 7644 section 3.4.2.2 Figures 1/2,
 * RFC 7644 errata 7319/4690/7322, and the approved bounded syntax profile.
 * Figure 2 contains 17 examples; the obsolete research F01 count of 18 is not copied.
 */
final class ScimFilterGrammarTests {
    record Fixture(@NonNull String expression, @NonNull Expected expected) {}

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> rfcFigureTwoHasTheExpectedSeventeenGraphs() {
        String time = "2011-05-13T04:42:34Z";
        Expected employee = c("userType", EQ, "Employee");
        Expected domains = o(c("emails", CO, "example.com"), c("emails.value", CO, "example.org"));
        Expected workEmail = v("emails", a(c("type", EQ, "work"), c("value", CO, "@example.com")));
        List<Fixture> fixtures = List.of(
                new Fixture("userName eq \"bjensen\"", c("userName", EQ, "bjensen")),
                new Fixture("name.familyName co \"O'Malley\"", c("name.familyName", CO, "O'Malley")),
                new Fixture("userName sw \"J\"", c("userName", SW, "J")),
                new Fixture("urn:ietf:params:scim:schemas:core:2.0:User:userName sw \"J\"",
                        c("urn:ietf:params:scim:schemas:core:2.0:User:userName", SW, "J")),
                new Fixture("title pr", p("title")),
                new Fixture("meta.lastModified gt \"" + time + "\"", c("meta.lastModified", GT, time)),
                new Fixture("meta.lastModified ge \"" + time + "\"", c("meta.lastModified", GE, time)),
                new Fixture("meta.lastModified lt \"" + time + "\"", c("meta.lastModified", LT, time)),
                new Fixture("meta.lastModified le \"" + time + "\"", c("meta.lastModified", LE, time)),
                new Fixture("title pr and userType eq \"Employee\"", a(p("title"), employee)),
                new Fixture("title pr or userType eq \"Intern\"", o(p("title"), c("userType", EQ, "Intern"))),
                new Fixture("schemas eq \"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User\"",
                        c("schemas", EQ, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")),
                new Fixture("userType eq \"Employee\" and (emails co \"example.com\" or emails.value co \"example.org\")",
                        a(employee, domains)),
                new Fixture("userType ne \"Employee\" and not (emails co \"example.com\" or emails.value co \"example.org\")",
                        a(c("userType", NE, "Employee"), n(domains))),
                new Fixture("userType eq \"Employee\" and (emails.type eq \"work\")",
                        a(employee, c("emails.type", EQ, "work"))),
                new Fixture("userType eq \"Employee\" and emails[type eq \"work\" and value co \"@example.com\"]",
                        a(employee, workEmail)),
                new Fixture("emails[type eq \"work\" and value co \"@example.com\"] or ims[type eq \"xmpp\" and value co \"@foo.com\"]",
                        o(workEmail, v("ims", a(c("type", EQ, "xmpp"), c("value", CO, "@foo.com"))))));
        assertEquals(17, fixtures.size());
        return fixtures.stream().map(fixture -> DynamicTest.dynamicTest(fixture.expression(), () -> {
            ScimFilter filter = parse(fixture.expression());
            assertGraph(fixture.expected(), filter);
            assertSameGraph(filter, parse(filter.toScimString()));
        }));
    }

    @Test void precedenceAndGroupingPreserveExactOperandOrder() {
        Expected x = c("a", EQ, new BigDecimal("1"));
        Expected y = c("b", EQ, new BigDecimal("2"));
        Expected z = c("c", EQ, new BigDecimal("3"));
        assertGraph(o(x, a(y, z)), parse("a eq 1 or b eq 2 and c eq 3"));
        assertGraph(a(o(x, y), z), parse("(a eq 1 or b eq 2) and c eq 3"));
        assertGraph(a(n(p("a")), p("b")), parse("not (a pr) and b pr"));
        assertGraph(n(o(p("a"), a(p("b"), p("c")))), parse("not(a pr or b pr and c pr)"));
        assertGraph(o(a(p("a"), p("b")), a(p("c"), p("d"))), parse("a pr and b pr or c pr and d pr"));
    }

    @Test void adjacentLogicalNodesFlattenThroughGroupingWithoutReordering() {
        assertGraph(a(p("a"), p("b"), p("c"), p("d")), parse("(a pr and b pr) and (c pr and d pr)"));
        assertGraph(o(p("a"), p("b"), p("c"), p("d")), parse("a pr or (b pr or (c pr or d pr))"));
        assertGraph(a(p("a"), o(p("b"), p("c")), p("d")), parse("a pr and (b pr or c pr) and d pr"));
    }

    @Test void keywordsAreContextualAttributeNamesAndOperatorsFoldAsciiOnly() {
        for (String attribute : List.of("and", "or", "not", "eq", "pr", "true", "false", "null")) {
            assertGraph(c(attribute, EQ, "x"), parse(attribute + " eq \"x\""));
            assertGraph(p(attribute), parse(attribute + " pr"));
        }
        assertGraph(a(c("Username", EQ, "john"), n(p("title"))), parse("Username Eq \"john\" AnD NoT(title PR)"));
        for (String expression : List.of("a eK \"x\"", "İ pr", "a PRé", "a ｅｑ 1")) reject(expression);
    }

    @Test void valuePathHoldsOneRelativePredicateAndSupportsLogicalGroups() {
        assertGraph(v("emails", o(c("type", EQ, "work"), a(c("type", EQ, "home"), c("value", EW, "@x.com")))),
                parse("emails[type eq \"work\" or (type eq \"home\" and value ew \"@x.com\")]"));
        assertGraph(v("members", n(a(p("value"), p("type")))), parse("members[not(value pr and type pr)]"));
        assertGraph(v("members", p("$ref")), parse("members[$ref pr]"));
        assertGraph(v("members", c("$REF", EQ, "https://example.test/Users/123")),
                parse("members[$REF eq \"https://example.test/Users/123\"]"));
        for (String expression : List.of("emails[type pr and x[y eq 1]]", "emails[not(x[y pr])]",
                "emails[x[y pr] or type pr]", "emails[]", "emails[type pr].value", "members[$other pr]")) reject(expression);
    }

    @Test void comparisonOperatorsAndTypedValuesAreSyntaxOnly() {
        for (ScimComparisonOperator operator : ScimComparisonOperator.values()) {
            String wire = switch (operator) {
                case EQ -> "eq"; case NE -> "ne"; case CO -> "co"; case SW -> "sw"; case EW -> "ew";
                case GT -> "gt"; case LT -> "lt"; case GE -> "ge"; case LE -> "le";
            };
            assertGraph(c("active", operator, true), parse("active " + wire + " true"));
        }
        assertGraph(c("a", EQ, false), parse("a eq false"));
        assertGraph(c("a", EQ, Null.VALUE), parse("a eq null"));
        for (String bad : List.of("True", "FALSE", "Null", "User", "undefined", "TRUE")) reject("a eq " + bad);
    }

    @Test void uriPathsCannotBeConfusedWithValuePathBracketsOrDots() {
        assertGraph(c("https://[2001:db8::1]:8443/schemas/2.0/User:manager.$ref", EQ, "x"),
                parse("https://[2001:db8::1]:8443/schemas/2.0/User:manager.$ref eq \"x\""));
        assertGraph(v("https://schemas.example.test/v2/User:members", p("value")),
                parse("https://schemas.example.test/v2/User:members[value pr]"));
        assertGraph(v("https://example.com:emails", c("type", EQ, "work")),
                parse("https://example.com:emails[type eq \"work\"]"));
        assertGraph(v("https://[::1]:emails", c("type", EQ, "work")),
                parse("https://[::1]:emails[type eq \"work\"]"));
        assertGraph(c("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value", EQ, "x"),
                parse("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value eq \"x\""));
        assertGraph(p("members.$REF"), parse("members.$REF pr"));
    }

    @Test void approvedWhitespaceIsAcceptedOnlyBetweenTokens() {
        assertGraph(a(c("userName", EQ, "x"), p("title")), parse(" \t\r\n\fuserName\teq\r\n\"x\"\fand\ttitle\rpr \n"));
        assertGraph(n(p("a")), parse("not \f\n(a pr)"));
        for (String expression : List.of("userName eq\"x\"", "a\u000bpr", "a\u00a0pr", "a\u2003pr",
                "a eq 1and b pr", "a prand b pr", "a pr or(b pr)", "a eq 1 or\"x\"")) reject(expression);
    }

    @Test void invalidSyntaxIsAlwaysARejection() {
        for (String expression : List.of("", " \n", "a", "a eq", "a eq 1 b", "a pr 1", "a regex \"x\"",
                "not a pr", "a pr and", "or a pr", "a pr or or b pr", "(a pr", "a pr)", "[]",
                "a.[b pr]", "a[pr]", "a eq [1]", "a eq {}", "a eq 'x'", "a eq \"x\";", "( )")) {
            reject(expression);
        }
    }

    @Test void stringEscapesAndSupplementaryUnicodeDecodeStrictly() {
        assertGraph(c("a", EQ, "\"\\/\b\f\n\r\té😀"), parse("a eq \"\\\"\\\\\\/\\b\\f\\n\\r\\t\\u00e9\\ud83d\\ude00\""));
        assertGraph(c("a", EQ, "é😀O'Malley"), parse("a eq \"é😀O'Malley\""));
        assertGraph(c("a", EQ, "\u0000\u001f"), parse("a eq \"\\u0000\\u001f\""));
        for (String literal : List.of("\"\\ud83d\"", "\"\\ude00\"", "\"\\ud83dA\"", "\"\\ude00\\ud83d\"",
                "\"\\ud83d\\u0041\"", "\"\\u123\"", "\"\\u12xz\"", "\"\\x20\"", "\"\\v\"",
                "\"line\nfeed\"", "\"\u0000\"", "\"\ud83d\"", "\"\ude00\"", "\"unfinished", "\"\\")) reject("a eq " + literal);
    }

    @Test void numbersUseTheJsonGrammarAndBoundedExponents() {
        for (String number : List.of("0", "-0", "1", "-1", "1.5", "-0.0", "1e3", "2E+4", "9e-4", "0.001")) {
            assertGraph(c("a", EQ, new BigDecimal(number)), parse("a eq " + number));
        }
        for (String number : List.of("01", "-01", "+1", ".5", "-.5", "1.", "1e", "1e+", "1e-",
                "NaN", "Infinity", "1_000", "0x1", "1e1001", "1e-1001", "1e999999999999999999")) reject("a eq " + number);
        parse("a eq 1e1000");
        parse("a eq 1e-1000");
    }
}
