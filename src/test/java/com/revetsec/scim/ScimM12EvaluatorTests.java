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

import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseResult;
import com.revetsec.json.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

/** Independent authored verdict matrix; no production evaluator or PATCH matcher supplies expectations. */
class ScimM12EvaluatorTests {
    private static final @NonNull String URN="urn:revetsec:test:scim:evaluator";
    private static final @NonNull ScimAttributeDefinition TEXT=ScimAttributeDefinition.withName("text").build();
    private static final @NonNull ScimAttributeDefinition TAGS=ScimAttributeDefinition.withName("tags").multiValued(true).build();
    private static final @NonNull ScimAttributeDefinition ROWS=ScimAttributeDefinition.withName("rows").type(ScimAttributeType.COMPLEX)
            .multiValued(true).subAttributes(List.of(ScimAttributeDefinition.withName("value").build(),
                    ScimAttributeDefinition.withName("type").build(),ScimAttributeDefinition.withName("primary").type(ScimAttributeType.BOOLEAN).build())).build();
    private static final @NonNull ScimResourceType TYPE=ScimResourceType.withName("Fixture").endpoint("/Fixtures")
            .schema(ScimSchema.withId(URN).name("Fixture").attributes(List.of(TEXT,TAGS,ROWS,
                    ScimAttributeDefinition.withName("flag").type(ScimAttributeType.BOOLEAN).build(),
                    ScimAttributeDefinition.withName("number").type(ScimAttributeType.DECIMAL).build(),
                    ScimAttributeDefinition.withName("integer").type(ScimAttributeType.INTEGER).build(),
                    ScimAttributeDefinition.withName("date").type(ScimAttributeType.DATE_TIME).build(),
                    ScimAttributeDefinition.withName("binary").type(ScimAttributeType.BINARY).build(),
                    ScimAttributeDefinition.withName("link").type(ScimAttributeType.REFERENCE).build(),
                    ScimAttributeDefinition.withName("hidden").returned(ScimReturned.NEVER).build())).build()).build();
    private static final @NonNull Set<@NonNull ScimComparisonOperator> ORDER=EnumSet.of(ScimComparisonOperator.EQ,ScimComparisonOperator.NE,
            ScimComparisonOperator.GT,ScimComparisonOperator.GE,ScimComparisonOperator.LT,ScimComparisonOperator.LE);
    private static final @NonNull Set<@NonNull ScimLogicalOperator> LOGIC=EnumSet.allOf(ScimLogicalOperator.class);
    private static final @NonNull ScimFilterPolicy POLICY=ScimFilterPolicy.builder()
            .allowedComparisons(Map.of("text",EnumSet.allOf(ScimComparisonOperator.class),"tags",ORDER,"rows.value",ORDER,
                    "flag",Set.of(ScimComparisonOperator.EQ,ScimComparisonOperator.NE),"number",ORDER,"integer",ORDER,
                    "date",ORDER,"binary",Set.of(ScimComparisonOperator.EQ,ScimComparisonOperator.NE),"link",EnumSet.allOf(ScimComparisonOperator.class)))
            .allowedPresence(Set.of("text","tags","rows","rows.value","flag","number","date","binary","link"))
            .allowedLogicalOperators(LOGIC).allowedValuePaths(Map.of("rows",ScimFilterPolicy.builder()
                    .allowedComparisons(Map.of("value",ORDER,"type",ORDER,"primary",Set.of(ScimComparisonOperator.EQ,ScimComparisonOperator.NE)))
                    .allowedPresence(Set.of("value","type","primary")).allowedLogicalOperators(LOGIC).build())).build();
    private static final @NonNull ScimStringMatching EXACT=(path,definition,operator,left,right) -> {
        int order=left.compareTo(right);
        return ScimStringMatchResult.fromMatched(switch(operator) {
            case EQ -> order == 0; case NE -> order != 0; case CO -> left.contains(right);
            case SW -> left.startsWith(right); case EW -> left.endsWith(right); case GT -> order > 0;
            case GE -> order >= 0; case LT -> order < 0; case LE -> order <= 0;
        });
    };
    private static @NonNull ScimServiceProvider provider() { return provider(EXACT,null,null,POLICY); }
    private static @NonNull ScimServiceProvider provider(@NonNull ScimStringMatching matching,@Nullable ScimObserver observer,
            @Nullable ScimLimits limits,@NonNull ScimFilterPolicy policy) {
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(TYPE)).stringMatching(matching).observer(observer).limits(limits)
                .filterPolicies(Map.of(TYPE,policy)).serviceProviderConfig(ScimServiceProviderConfig.builder().filterSupported(true).build()).build();
    }
    private static @NonNull JsonObject object(@NonNull String text) {
        return assertInstanceOf(JsonObject.class,assertInstanceOf(JsonParseResult.Succeeded.class,
                JsonCodec.parseResult(text.getBytes(StandardCharsets.UTF_8),JsonLimits.scim(100000,10000))).getDocument().getValue());
    }
    private static @NonNull ScimResource resource(@NonNull String members) {
        return ScimResource.withResourceType(TYPE).document(object("{\"schemas\":[\""+URN+"\"]"+members+"}")).build();
    }
    private static @NonNull ScimFilter filter(@NonNull String expression) {
        return assertInstanceOf(ScimFilterParseResult.Succeeded.class,ScimFilter.fromExpressionResult(expression)).getFilter();
    }
    private static boolean matched(@NonNull ScimFilterEvaluator evaluator,@NonNull ScimResource resource,@NonNull String expression) {
        return assertInstanceOf(ScimFilterEvaluationResult.Succeeded.class,evaluator.evaluateResult(resource,filter(expression)),expression).isMatched();
    }
    private static @NonNull ScimError rejected(@NonNull ScimFilterEvaluator evaluator,@NonNull ScimResource resource,@NonNull String expression) {
        return assertInstanceOf(ScimFilterEvaluationResult.Rejected.class,evaluator.evaluateResult(resource,filter(expression)),expression).getError();
    }

    private record TruthRow(@NonNull String members,boolean eqNull,boolean neNull,boolean eqA,boolean neA,boolean present,boolean notEqA) {}
    @Test void independentScalarNullEmptyAndAbsentMatrix() {
        ScimFilterEvaluator evaluator=ScimFilterEvaluator.fromServiceProvider(provider());
        for (TruthRow row:List.of(
                new TruthRow("",true,false,false,true,false,true),
                new TruthRow(",\"text\":null",true,false,false,true,false,true),
                new TruthRow(",\"text\":\"\"",false,true,false,true,false,true),
                new TruthRow(",\"text\":\"a\"",false,true,true,false,true,false),
                new TruthRow(",\"text\":\"b\"",false,true,false,true,true,true))) {
            ScimResource current=resource(row.members());
            assertEquals(row.eqNull(),matched(evaluator,current,"text eq null"),row.members());
            assertEquals(row.neNull(),matched(evaluator,current,"text ne null"),row.members());
            assertEquals(row.eqA(),matched(evaluator,current,"text eq \"a\""),row.members());
            assertEquals(row.neA(),matched(evaluator,current,"text ne \"a\""),row.members());
            assertEquals(row.present(),matched(evaluator,current,"text pr"),row.members());
            assertEquals(row.notEqA(),matched(evaluator,current,"not(text eq \"a\")"),row.members());
            for (String operator:List.of("co","sw","ew","gt","ge","lt","le"))
                if (row.eqNull()) assertFalse(matched(evaluator,current,"text "+operator+" \"a\""));
        }
    }
    @Test void independentMultiValueAnyElementNeIsDifferentFromNotEq() {
        ScimFilterEvaluator evaluator=ScimFilterEvaluator.fromServiceProvider(provider());
        for (TruthRow row:List.of(
                new TruthRow("",true,false,false,true,false,true),
                new TruthRow(",\"tags\":null",true,false,false,true,false,true),
                new TruthRow(",\"tags\":[]",true,false,false,true,false,true),
                new TruthRow(",\"tags\":[\"\"]",false,true,false,true,false,true),
                new TruthRow(",\"tags\":[\"a\"]",false,true,true,false,true,false),
                new TruthRow(",\"tags\":[\"a\",\"b\"]",false,true,true,true,true,false),
                new TruthRow(",\"tags\":[\"a\",\"a\"]",false,true,true,false,true,false),
                new TruthRow(",\"tags\":[\"b\",\"c\"]",false,true,false,true,true,true))) {
            ScimResource current=resource(row.members());
            assertEquals(row.eqNull(),matched(evaluator,current,"tags eq null"),row.members());
            assertEquals(row.neNull(),matched(evaluator,current,"tags ne null"),row.members());
            assertEquals(row.eqA(),matched(evaluator,current,"tags eq \"a\""),row.members());
            assertEquals(row.neA(),matched(evaluator,current,"tags ne \"a\""),row.members());
            assertEquals(row.present(),matched(evaluator,current,"tags pr"),row.members());
            assertEquals(row.notEqA(),matched(evaluator,current,"not(tags eq \"a\")"),row.members());
        }
    }
    @Test void valuePathRequiresOneElementAndFlatSubattributesRetainMissingValues() {
        ScimFilterEvaluator evaluator=ScimFilterEvaluator.fromServiceProvider(provider());
        ScimResource split=resource(",\"rows\":[{\"value\":\"a\",\"type\":\"home\"},{\"value\":\"b\",\"type\":\"work\"}]");
        assertFalse(matched(evaluator,split,"rows[type eq \"work\" and value eq \"a\"]"));
        assertTrue(matched(evaluator,split,"rows[type eq \"work\" and value eq \"b\"]"));
        assertTrue(matched(evaluator,split,"rows.value eq \"a\" and rows.value ne \"a\""));
        assertFalse(matched(evaluator,split,"not(rows.value eq \"a\")"));
        ScimResource partlyMissing=resource(",\"rows\":[{\"value\":\"a\"},{\"type\":\"work\"}]");
        assertTrue(matched(evaluator,partlyMissing,"rows.value eq null"));
        assertTrue(matched(evaluator,partlyMissing,"rows.value ne null"));
        assertTrue(matched(evaluator,partlyMissing,"rows[value eq null and type eq \"work\"]"));
        assertTrue(matched(evaluator,partlyMissing,"rows.value ne \"a\""));
        assertFalse(matched(evaluator,resource(",\"rows\":[{}, {\"value\":\"\"}]"),"rows pr"));
        assertTrue(matched(evaluator,resource(",\"rows\":[{\"primary\":false}]"),"rows pr"));
        for (ScimResource unassigned:List.of(resource(""),resource(",\"rows\":[]"))) {
            assertFalse(matched(evaluator,unassigned,"rows[value eq \"a\"]"));
            assertTrue(matched(evaluator,unassigned,"rows.value eq null"));
            assertFalse(matched(evaluator,unassigned,"rows.value ne null"));
        }
    }
    @Test void scalarComplexChildPathsPreserveMissingAndAssignedValues() {
        ScimResourceType user=ScimResourceType.userInstance();
        ScimServiceProvider provider=ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(user)).stringMatching(EXACT)
                .filterPolicies(Map.of(user,ScimFilterPolicy.builder().allowedComparisons(Map.of("name.givenName",ORDER))
                        .allowedPresence(Set.of("name.givenName")).build()))
                .serviceProviderConfig(ScimServiceProviderConfig.builder().filterSupported(true).build()).build();
        ScimFilterEvaluator evaluator=ScimFilterEvaluator.fromServiceProvider(provider);
        for (JsonObject document:List.of(
                JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(user.getSchema().getId())))).put("userName","fixture").build(),
                JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(user.getSchema().getId())))).put("userName","fixture").put("name",JsonObject.emptyInstance()).build())) {
            ScimResource unassigned=ScimResource.withResourceType(user).document(document).build();
            assertTrue(matched(evaluator,unassigned,"name.givenName eq null"));
            assertFalse(matched(evaluator,unassigned,"name.givenName ne null"));
            assertFalse(matched(evaluator,unassigned,"name.givenName pr"));
        }
        ScimResource assigned=ScimResource.withResourceType(user).document(JsonObject.builder()
                .put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(user.getSchema().getId())))).put("userName","fixture")
                .put("name",JsonObject.builder().put("givenName","Alice").build()).build()).build();
        assertTrue(matched(evaluator,assigned,"name.givenName eq \"Alice\""));
        assertFalse(matched(evaluator,assigned,"name.givenName eq \"Bob\""));
        assertTrue(matched(evaluator,assigned,"name.givenName pr"));
    }
    @Test void typedValuesUseCoreSemanticsWithoutStringCallbacks() {
        AtomicInteger calls=new AtomicInteger();
        ScimFilterEvaluator evaluator=ScimFilterEvaluator.fromServiceProvider(provider((path,definition,operator,left,right) -> {
            calls.incrementAndGet(); return ScimStringMatchResult.unsupportedInstance();
        },null,null,POLICY));
        ScimResource current=resource(",\"flag\":false,\"number\":1.00,\"integer\":100,\"date\":\"2000-01-01T00:00:00.123400Z\",\"binary\":\"Zg==\",\"link\":\"../Users/A\"");
        for (String expression:List.of("flag eq false","number eq 1e0","number ge 1","number le 1","integer gt 99",
                "integer lt 101","date eq \"1999-12-31T19:00:00.1234-05:00\"","date gt \"1999-12-31T00:00:00Z\"",
                "binary eq \"Zg\"","link eq \"../Users/A\"","link ne \"../Users/a\"","link co \"Users\"",
                "link sw \"../\"","link ew \"/A\"","number pr","flag pr"))
            assertTrue(matched(evaluator,current,expression),expression);
        assertFalse(matched(evaluator,current,"link eq \"../Users/a\""));
        assertSame(ScimError.invalidFilterInstance(),rejected(evaluator,current,"date eq \"2000-01-01T00:00:00\""));
        assertEquals(0,calls.get());
    }
    @Test void authoredTypedOrderingAndLogicalTruthTablesIncludeNegativeVerdicts() {
        ScimFilterEvaluator evaluator=ScimFilterEvaluator.fromServiceProvider(provider());
        List<String> operators=List.of("eq","ne","gt","ge","lt","le");
        List<List<Boolean>> expected=List.of(List.of(false,true,false,false,true,true),
                List.of(true,false,false,true,false,true),List.of(false,true,true,true,false,false));
        for (int row=0;row<3;row++) {
            ScimResource current=resource(",\"number\":"+(row-1)+",\"date\":\"2000-01-01T0"+(row+1)+":00:00Z\"");
            for (int column=0;column<operators.size();column++) {
                String operator=operators.get(column);
                assertEquals(expected.get(row).get(column),matched(evaluator,current,"number "+operator+" 0"));
                assertEquals(expected.get(row).get(column),matched(evaluator,current,"date "+operator+" \"2000-01-01T02:00:00Z\""));
            }
        }
        for (boolean value:List.of(false,true)) {
            ScimResource current=resource(",\"flag\":"+value+",\"binary\":\""+(value ? "Zg==" : "Zw==")+"\"");
            assertEquals(value,matched(evaluator,current,"flag eq true"));
            assertEquals(!value,matched(evaluator,current,"flag ne true"));
            assertEquals(value,matched(evaluator,current,"binary eq \"Zg==\""));
            assertEquals(!value,matched(evaluator,current,"binary ne \"Zg==\""));
        }
        ScimResource current=resource(",\"flag\":false,\"number\":1,\"text\":\"a\"");
        List<String> clauses=List.of("flag eq true","text eq \"a\"");
        List<List<Boolean>> or=List.of(List.of(false,true),List.of(true,true));
        List<List<Boolean>> and=List.of(List.of(false,false),List.of(false,true));
        for (int left=0;left<2;left++) for (int right=0;right<2;right++) {
            assertEquals(or.get(left).get(right),matched(evaluator,current,clauses.get(left)+" or "+clauses.get(right)));
            assertEquals(and.get(left).get(right),matched(evaluator,current,clauses.get(left)+" and "+clauses.get(right)));
        }
    }
    private record DatePair(@NonNull String stored,@NonNull String sameInstant) {}
    @Test void authoredCalendarPairsCoverOffsetMinutesLeapCenturiesAndNoYearZero() {
        ScimFilterEvaluator evaluator=ScimFilterEvaluator.fromServiceProvider(provider());
        for (DatePair pair:List.of(
                new DatePair("2000-01-01T00:00:00+05:30","1999-12-31T18:30:00Z"),
                new DatePair("2000-01-01T00:00:00-05:45","2000-01-01T05:45:00Z"),
                new DatePair("2000-03-01T00:15:00+00:30","2000-02-29T23:45:00Z"),
                new DatePair("1900-03-01T00:15:00+00:30","1900-02-28T23:45:00Z"),
                new DatePair("1000-03-01T00:15:00+00:30","1000-02-28T23:45:00Z"),
                new DatePair("2000-02-29T23:45:00-00:30","2000-03-01T00:15:00Z"),
                new DatePair("1900-02-28T23:45:00-00:30","1900-03-01T00:15:00Z"),
                new DatePair("2004-02-28T23:45:00-00:30","2004-02-29T00:15:00Z"),
                new DatePair("2004-03-01T00:15:00+00:30","2004-02-29T23:45:00Z"),
                new DatePair("2000-01-01T00:00:00.900","2000-01-01T00:00:00.9"),
                new DatePair("2001-01-01T00:00:00+01:00","2000-12-31T23:00:00Z"),
                new DatePair("1998-12-31T23:00:00-01:00","1999-01-01T00:00:00Z"),
                new DatePair("-0001-03-01T00:15:00+00:30","-0001-02-29T23:45:00Z"),
                new DatePair("-0002-03-01T00:15:00+00:30","-0002-02-28T23:45:00Z"),
                new DatePair("0001-01-01T00:30:00+01:00","-0001-12-31T23:30:00Z"),
                new DatePair("-0001-12-31T23:30:00-01:00","0001-01-01T00:30:00Z"),
                new DatePair("10000-01-01T00:00:00+01:00","9999-12-31T23:00:00Z"),
                new DatePair("-10000-12-31T23:00:00-01:00","-9999-01-01T00:00:00Z"),
                new DatePair("-9999-01-01T00:00:00+01:00","-10000-12-31T23:00:00Z"))) {
            ScimResource current=resource(",\"date\":"+JsonString.fromValue(pair.stored()).toJson());
            assertTrue(matched(evaluator,current,"date eq "+JsonString.fromValue(pair.sameInstant()).toJson()),pair.toString());
            assertFalse(matched(evaluator,current,"date ne "+JsonString.fromValue(pair.sameInstant()).toJson()),pair.toString());
        }
        for (DatePair pair:List.of(new DatePair("-10000-01-01T00:00:00Z","-9999-01-01T00:00:00Z"),
                new DatePair("-0002-01-01T00:00:00Z","-0001-01-01T00:00:00Z"),
                new DatePair("-0001-01-01T00:00:00Z","0001-01-01T00:00:00Z"))) {
            ScimResource current=resource(",\"date\":"+JsonString.fromValue(pair.stored()).toJson());
            assertTrue(matched(evaluator,current,"date lt "+JsonString.fromValue(pair.sameInstant()).toJson()));
            assertFalse(matched(evaluator,current,"date ge "+JsonString.fromValue(pair.sameInstant()).toJson()));
        }
    }
    @Test void evaluatorAndEveryResultBranchHaveFixedExactDiagnostics() {
        ScimFilterEvaluator evaluator=ScimFilterEvaluator.fromServiceProvider(provider());
        ScimResource current=resource(",\"text\":\"private-personal-data\"");
        assertEquals("ScimFilterEvaluator{<redacted>}",evaluator.toString());
        assertEquals("ScimFilterEvaluationResult.Succeeded{<redacted>}",evaluator.evaluateResult(current,filter("text pr")).toString());
        assertEquals("ScimFilterEvaluationResult.Succeeded{<redacted>}",evaluator.evaluateResult(current,filter("text eq \"other-private-data\"")).toString());
        assertEquals("ScimFilterEvaluationResult.Rejected{<redacted>}",evaluator.evaluateResult(current,filter("hidden pr")).toString());
    }
    @SuppressWarnings("NullAway") // Deliberate null arguments verify the public programmer-misuse boundary.
    @Test void wholeTreeIsReboundUnderReceivingPolicyAndDisabledCapabilitiesReject() {
        ScimServiceProvider p=provider();
        ScimFilterEvaluator evaluator=ScimFilterEvaluator.fromServiceProvider(p);
        ScimResource current=resource(",\"text\":\"a\",\"flag\":true");
        for (String expression:List.of("hidden pr","missing eq null","text eq 1","flag gt true"))
            assertSame(ScimError.invalidFilterInstance(),rejected(evaluator,current,expression));
        ScimFilter foreign=assertInstanceOf(ScimFilterParseResult.Succeeded.class,p.parseFilterResult(TYPE,"text eq \"a\" or flag eq true")).getFilter();
        ScimServiceProvider narrow=provider(EXACT,null,null,ScimFilterPolicy.builder().allowedComparisons(Map.of("text",ORDER)).build());
        assertInstanceOf(ScimFilterEvaluationResult.Rejected.class,ScimFilterEvaluator.fromServiceProvider(narrow).evaluateResult(current,foreign));
        ScimServiceProvider disabled=ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(TYPE)).stringMatching(EXACT).filterPolicies(Map.of(TYPE,POLICY)).build();
        assertSame(ScimError.forbiddenInstance(),rejected(ScimFilterEvaluator.fromServiceProvider(disabled),current,"text eq \"a\""));
        ScimResource parsed=assertInstanceOf(ScimResourceParseResult.Succeeded.class,p.parseResourceResult(TYPE,
                ("{\"schemas\":[\""+URN+"\"],\"text\":\"a\"}").getBytes(StandardCharsets.UTF_8))).getResource();
        assertSame(ScimError.invalidValueInstance(),rejected(ScimFilterEvaluator.fromServiceProvider(provider()),parsed,"text eq \"a\""));
        assertTrue(matched(ScimFilterEvaluator.fromServiceProvider(p.copy().baseUri(URI.create("https://other.invalid/scim/")).finish()),parsed,"text eq \"a\""));
        assertThrows(IllegalArgumentException.class,() -> ScimFilterEvaluator.fromServiceProvider(ScimServiceProvider.builder()
                .baseUri(URI.create("https://example.invalid/scim/")).resourceTypes(List.of(TYPE)).build()));
        assertThrows(NullPointerException.class,() -> ScimFilterEvaluator.fromServiceProvider(null));
        assertThrows(NullPointerException.class,() -> evaluator.evaluateResult(null,foreign));
        assertThrows(NullPointerException.class,() -> evaluator.evaluateResult(current,null));
    }
    @Test void everyLogicalClauseAndArrayElementCanRejectUnsupportedMatching() {
        AtomicInteger calls=new AtomicInteger();
        ScimFilterEvaluator evaluator=ScimFilterEvaluator.fromServiceProvider(provider((path,definition,operator,left,right) -> {
            calls.incrementAndGet(); return left.equals("unsupported") ? ScimStringMatchResult.unsupportedInstance() : EXACT.match(path,definition,operator,left,right);
        },null,null,POLICY));
        ScimResource current=resource(",\"text\":\"unsupported\",\"flag\":true,\"tags\":[\"a\",\"unsupported\"]");
        for (String expression:List.of("flag eq false and text eq \"a\"","flag eq true or text eq \"a\"",
                "not(flag eq false and text eq \"a\")","tags eq \"a\""))
            assertSame(ScimError.invalidFilterInstance(),rejected(evaluator,current,expression));
        assertEquals(5,calls.get());
        ScimResource elements=resource(",\"rows\":[{\"value\":\"a\"},{\"value\":\"unsupported\"}]");
        assertSame(ScimError.invalidFilterInstance(),rejected(evaluator,elements,"rows[value eq \"a\"]"));
    }
    @SuppressWarnings("NullAway") // Deliberately violate the application SPI's nonnull return contract.
    @Test void applicationFaultsAreFixedAndObserverEventsAreRedactedWhileFatalErrorsEscape() {
        List<String> events=new ArrayList<>();
        ScimObserver observer=new ScimObserver() {
            @Override public void willProcess(@NonNull Operation operation) { events.add("will:"+operation); }
            @Override public void didProcess(@NonNull Operation operation,@NonNull Outcome outcome) { events.add("did:"+outcome); }
            @Override public void didFailToProcess(@NonNull Operation operation) { events.add("fail:"+operation); }
        };
        for (ScimStringMatching matching:List.<ScimStringMatching>of(
                (path,definition,operator,left,right) -> { throw new IllegalStateException("secret-fixture"); },
                (path,definition,operator,left,right) -> { throw new AssertionError("secret-fixture"); },
                (path,definition,operator,left,right) -> null)) {
            events.clear();
            ScimFilterEvaluator evaluator=ScimFilterEvaluator.fromServiceProvider(provider(matching,observer,null,POLICY));
            ScimFilterEvaluationResult outcome=evaluator.evaluateResult(resource(",\"text\":\"secret-fixture\""),filter("text eq \"private-literal\""));
            assertSame(ScimError.internalErrorInstance(),assertInstanceOf(ScimFilterEvaluationResult.Rejected.class,outcome).getError());
            assertEquals(List.of("will:FILTER_EVALUATE","fail:FILTER_EVALUATE"),events);
            assertFalse(outcome.toString().contains("secret"));
            assertFalse(evaluator.toString().contains("secret"));
        }
        ScimFilterEvaluator fatal=ScimFilterEvaluator.fromServiceProvider(provider((path,definition,operator,left,right) -> {
            throw new OutOfMemoryError("fixture");
        },null,null,POLICY));
        assertThrows(OutOfMemoryError.class,() -> fatal.evaluateResult(resource(",\"text\":\"a\""),filter("text eq \"a\"")));
        events.clear();
        assertFalse(matched(ScimFilterEvaluator.fromServiceProvider(provider(EXACT,observer,null,POLICY)),resource(""),"text eq \"a\""));
        assertEquals(List.of("will:FILTER_EVALUATE","did:SUCCEEDED"),events);
    }
    @Test void checkedMatcherInterruptionIsContainedWithoutLosingTheThreadFlag() {
        boolean previouslyInterrupted=Thread.interrupted();
        List<String> events=new ArrayList<>();
        ScimObserver observer=new ScimObserver() {
            @Override public void willProcess(@NonNull Operation operation) { events.add("will:"+operation); }
            @Override public void didProcess(@NonNull Operation operation,@NonNull Outcome outcome) { events.add("did:"+outcome); }
            @Override public void didFailToProcess(@NonNull Operation operation) { events.add("fail:"+operation); }
        };
        try {
            ScimFilterEvaluator evaluator=ScimFilterEvaluator.fromServiceProvider(provider((path,definition,operator,left,right) ->
                    ScimM12EvaluatorTests.<RuntimeException>throwUnchecked(new InterruptedException("private-matcher-data")),observer,null,POLICY));
            assertSame(ScimError.internalErrorInstance(),rejected(evaluator,resource(",\"text\":\"a\""),"text eq \"a\""));
            assertTrue(Thread.currentThread().isInterrupted());
            assertEquals(List.of("will:FILTER_EVALUATE","fail:FILTER_EVALUATE"),events);
        } finally {
            Thread.interrupted();
            if (previouslyInterrupted) Thread.currentThread().interrupt();
        }
    }
    @SuppressWarnings("unchecked")
    private static <E extends @NonNull Throwable> @NonNull ScimStringMatchResult throwUnchecked(@NonNull Throwable failure) throws E {
        throw (E)failure;
    }
    @Test void sharedWorkBudgetChargesAllArrayScansAndCallbacksAcrossClauses() {
        AtomicInteger calls=new AtomicInteger();
        ScimLimits limits=ScimLimits.builder().maximumWorkUnits(10000).build();
        ScimFilterEvaluator evaluator=ScimFilterEvaluator.fromServiceProvider(provider((path,definition,operator,left,right) -> {
            calls.incrementAndGet(); return EXACT.match(path,definition,operator,left,right);
        },null,limits,POLICY));
        List<JsonValue> elements=new ArrayList<>();
        for (int index=0;index<2000;index++) elements.add(JsonString.fromValue("a"));
        ScimResource current=ScimResource.withResourceType(TYPE).document(JsonObject.builder()
                .put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(URN))))
                .put("tags",JsonArray.fromElements(elements)).build()).build();
        assertTrue(matched(evaluator,current,"tags eq \"a\""));
        assertEquals(2000,calls.get(),"Successful any-element matching still checks the remaining elements");
        calls.set(0);
        assertSame(ScimError.requestTooLargeInstance(),rejected(evaluator,current,"tags eq \"a\" or tags eq \"a\""));
        assertTrue(calls.get() > 2000 && calls.get() < 4000,"One budget spans both clauses and every callback");
    }
    @Test void largeTrustedResourcesRejectAtOneBudgetAndFirstUnsupportedValueKeepsItsError() {
        List<String> events=new ArrayList<>();
        ScimObserver observer=new ScimObserver() {
            @Override public void didProcess(@NonNull Operation operation,@NonNull Outcome outcome) { events.add(outcome.name()); }
            @Override public void didFailToProcess(@NonNull Operation operation) { fail("An ordinary evaluator rejection is not an application fault"); }
        };
        AtomicInteger calls=new AtomicInteger();
        ScimLimits limits=ScimLimits.builder().maximumWorkUnits(10000).build();
        ScimResource current=ScimResource.withResourceType(TYPE).document(JsonObject.builder()
                .put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(URN))))
                .put("tags",JsonArray.fromElements(java.util.Collections.nCopies(50000,JsonString.fromValue("a"))))
                .put("rows",JsonArray.fromElements(java.util.Collections.nCopies(50000,JsonObject.builder().put("value","a").build())))
                .build()).build();
        JsonObject original=current.getDocument();
        ScimFilterEvaluator bounded=ScimFilterEvaluator.fromServiceProvider(provider((path,definition,operator,left,right) -> {
            calls.incrementAndGet(); return EXACT.match(path,definition,operator,left,right);
        },observer,limits,POLICY));
        for (String expression:List.of("tags eq \"b\"","tags pr","rows.value eq \"b\"","rows[value eq \"b\"]","rows pr")) {
            calls.set(0);
            assertSame(ScimError.requestTooLargeInstance(),rejected(bounded,current,expression));
            assertTrue(calls.get() < 10000,"Callbacks remain within the shared operation budget");
            assertSame(original,current.getDocument());
        }
        ScimFilterEvaluator unsupported=ScimFilterEvaluator.fromServiceProvider(provider((path,definition,operator,left,right) -> {
            calls.incrementAndGet(); return ScimStringMatchResult.unsupportedInstance();
        },observer,limits,POLICY));
        for (String expression:List.of("tags eq \"b\"","rows.value eq \"b\"","rows[value eq \"b\"]",
                "tags eq \"b\" and text eq \"a\"","tags eq \"b\" or text eq \"a\"")) {
            calls.set(0);
            assertSame(ScimError.invalidFilterInstance(),rejected(unsupported,current,expression));
            assertEquals(1,calls.get(),"A terminal unsupported value preserves the first rejection");
        }
        assertEquals(java.util.Collections.nCopies(10,"REJECTED"),events);
    }
    @Test void receivingSyntaxLimitsApplyBeforeRenderingAndRebindingForeignTrees() {
        ScimResource current=resource(",\"text\":\"a\"");
        ScimFilterLimits filterLimits=ScimFilterLimits.builder().maximumLiteralCharacters(2).build();
        ScimFilterEvaluator evaluator=ScimFilterEvaluator.fromServiceProvider(provider(EXACT,null,
                ScimLimits.builder().filterLimits(filterLimits).build(),POLICY));
        assertSame(ScimError.invalidFilterInstance(),rejected(evaluator,current,"text eq \"long-fixture\""));
        ScimFilterLimits shallow=ScimFilterLimits.builder().maximumDepth(4).build();
        ScimFilterEvaluator shallowEvaluator=ScimFilterEvaluator.fromServiceProvider(provider(EXACT,null,
                ScimLimits.builder().filterLimits(shallow).build(),POLICY));
        assertSame(ScimError.invalidFilterInstance(),rejected(shallowEvaluator,current,"not(not(not(not(text eq \"a\"))))"));
        ScimFilterLimits nodes=ScimFilterLimits.builder().maximumNodes(8).build();
        ScimFilterEvaluator fewNodes=ScimFilterEvaluator.fromServiceProvider(provider(EXACT,null,
                ScimLimits.builder().filterLimits(nodes).build(),POLICY));
        assertSame(ScimError.invalidFilterInstance(),rejected(fewNodes,current,String.join(" or ",java.util.Collections.nCopies(8,"text eq \"a\""))));
        ScimFilterLimits numbers=ScimFilterLimits.builder().maximumNumberCharacters(4).maximumNumberExponentMagnitude(2).build();
        ScimFilterEvaluator boundedNumbers=ScimFilterEvaluator.fromServiceProvider(provider(EXACT,null,
                ScimLimits.builder().filterLimits(numbers).build(),POLICY));
        assertSame(ScimError.invalidFilterInstance(),rejected(boundedNumbers,current,"number eq 12345"));
        assertEquals(ScimErrorType.INVALID_FILTER,rejected(boundedNumbers,current,"number eq 1e3").getErrorType().orElseThrow());
        ScimFilterLimits expression=ScimFilterLimits.builder().maximumExpressionCharacters(256).maximumLiteralCharacters(256).build();
        ScimFilterEvaluator boundedExpression=ScimFilterEvaluator.fromServiceProvider(provider(EXACT,null,
                ScimLimits.builder().filterLimits(expression).build(),POLICY));
        assertSame(ScimError.invalidFilterInstance(),rejected(boundedExpression,current,"text eq \""+"x".repeat(249)+"\""));
        assertFalse(matched(ScimFilterEvaluator.fromServiceProvider(provider()),current,"(text eq \"x\" or text eq \"y\") and flag eq false"));
        assertFalse(matched(ScimFilterEvaluator.fromServiceProvider(provider()),current,"text eq \"\\\"\\\\\\b\\f\\n\\r\\t\\u0000\""));
    }

    @Test void canonicalExtensionPathsAndComplexPresenceKeepHiddenDataOutOfFiltering() {
        ScimAttributeDefinition rows=ScimAttributeDefinition.withName("rows").type(ScimAttributeType.COMPLEX).multiValued(true)
                .subAttributes(List.of(ScimAttributeDefinition.withName("label").build(),
                        ScimAttributeDefinition.withName("score").type(ScimAttributeType.INTEGER).build(),
                        ScimAttributeDefinition.withName("secret").returned(ScimReturned.NEVER).build())).build();
        ScimSchema base=ScimSchema.withId("urn:example:evaluator:base").name("Complex").attributes(List.of(rows)).build();
        ScimSchema extension=ScimSchema.withId("urn:example:evaluator:extension").name("Extra")
                .attributes(List.of(ScimAttributeDefinition.withName("label").build(),rows)).build();
        ScimResourceType type=ScimResourceType.withName("Complex").endpoint("/Complex").schema(base)
                .schemaExtensions(List.of(ScimSchemaExtension.fromSchema(extension,false))).build();
        ScimFilterPolicy policy=ScimFilterPolicy.builder().allowedComparisons(Map.of(extension.getId()+":label",ORDER))
                .allowedPresence(Set.of("rows",extension.getId()+":label"))
                .allowedValuePaths(Map.of("rows",ScimFilterPolicy.builder().allowedPresence(Set.of("label"))
                        .allowedComparisons(Map.of("label",ORDER,"score",ORDER)).build(),extension.getId()+":rows",
                        ScimFilterPolicy.builder().allowedComparisons(Map.of("label",ORDER)).build())).build();
        List<String> paths=new ArrayList<>();
        ScimServiceProvider p=ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(type)).filterPolicies(Map.of(type,policy))
                .serviceProviderConfig(ScimServiceProviderConfig.builder().filterSupported(true).build())
                .stringMatching((path,definition,operator,left,right) -> { paths.add(path.toScimString()); return EXACT.match(path,definition,operator,left,right); }).build();
        ScimFilterEvaluator evaluator=ScimFilterEvaluator.fromServiceProvider(p);
        ScimResource hidden=ScimResource.withResourceType(type).document(JsonObject.builder()
                .put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(base.getId()))))
                .put("rows",JsonArray.fromElements(List.of(JsonObject.builder().put("secret","private").build()))).build()).build();
        assertFalse(matched(evaluator,hidden,"rows pr"));
        assertFalse(matched(evaluator,hidden,"rows[label pr]"));
        assertTrue(matched(evaluator,hidden,extension.getId()+":label eq null"));
        assertFalse(matched(evaluator,hidden,extension.getId()+":label pr"));
        assertFalse(matched(evaluator,hidden,extension.getId()+":rows[label eq \"a\"]"));
        ScimResource visible=ScimResource.withResourceType(type).document(JsonObject.builder()
                .put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(base.getId()),JsonString.fromValue(extension.getId()))))
                .put(extension.getId(),JsonObject.builder().put("label","a")
                        .put("rows",JsonArray.fromElements(List.of(JsonObject.builder().put("label","a").build()))).build())
                .put("rows",JsonArray.fromElements(List.of(JsonObject.builder().put("label","a").put("score",2L).build()))).build()).build();
        assertTrue(matched(evaluator,visible,extension.getId()+":LABEL eq " + JsonString.fromValue("a").toJson()));
        assertEquals(List.of(extension.getId()+":label"),paths);
        assertTrue(matched(evaluator,visible,"rows[label pr]"));
        assertTrue(matched(evaluator,visible,"rows[score ge 1]"));
        assertTrue(matched(evaluator,visible,"rows[label eq " + JsonString.fromValue("a").toJson()+"]"));
        assertEquals(List.of(extension.getId()+":label","rows.label"),paths);
        assertTrue(matched(evaluator,visible,extension.getId()+":rows[label eq \"a\"]"));
        assertEquals(List.of(extension.getId()+":label","rows.label",extension.getId()+":rows.label"),paths);
    }

    @Test void strategyReceivesCanonicalDefinitionsAndExactGroupMembershipIdsRemainCoreOwned() {
        List<String> paths=new ArrayList<>();
        ScimFilterEvaluator evaluator=ScimFilterEvaluator.fromServiceProvider(provider((path,definition,operator,left,right) -> {
            paths.add(path.toScimString());
            assertEquals(path.getSubAttributeName().orElse(path.getAttributeName()),definition.getName());
            return EXACT.match(path,definition,operator,left,right);
        },null,null,POLICY));
        ScimResource current=resource(",\"text\":\"a\",\"rows\":[{\"value\":\"a\"}]");
        assertTrue(matched(evaluator,current,"TEXT eq \"a\""));
        assertTrue(matched(evaluator,current,"rows[VALUE eq \"a\"]"));
        assertEquals(List.of("text","rows.value"),paths);
        ScimResourceType group=ScimResourceType.groupInstance();
        ScimFilterPolicy policy=ScimFilterPolicy.builder().allowedComparisons(Map.of("members.value",ORDER))
                .allowedValuePaths(Map.of("members",ScimFilterPolicy.builder().allowedComparisons(Map.of("value",ORDER)).build())).build();
        ScimServiceProvider p=ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(group)).filterPolicies(Map.of(group,policy))
                .serviceProviderConfig(ScimServiceProviderConfig.builder().filterSupported(true).build())
                .stringMatching((path,definition,operator,left,right) -> { fail("Exact standard Group IDs must bypass application collation"); return ScimStringMatchResult.unsupportedInstance(); }).build();
        ScimResource members=ScimResource.withResourceType(group).document(JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(group.getSchema().getId()))))
                .put("displayName","fixture").put("members",JsonArray.fromElements(List.of(JsonObject.builder().put("value","A").build()))).build()).build();
        assertTrue(matched(ScimFilterEvaluator.fromServiceProvider(p),members,"members[value eq \"A\"]"));
        assertFalse(matched(ScimFilterEvaluator.fromServiceProvider(p),members,"members.value eq \"a\""));
    }
}
