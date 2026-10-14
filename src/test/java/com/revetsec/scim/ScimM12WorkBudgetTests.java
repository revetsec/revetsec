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

import com.revetsec.json.*;
import org.junit.jupiter.api.Test;
import org.jspecify.annotations.NonNull;
import java.math.BigDecimal;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

/** Typed evaluation receives the original request budget remaining after earlier stages. */
class ScimM12WorkBudgetTests {
    private static final @NonNull String URN="urn:example:m12:mutation-budget";
    private static final @NonNull ScimResourceType TYPE=ScimResourceType.withName("Budget").endpoint("/Budgets")
            .schema(ScimSchema.withId(URN).name("Budget").attributes(List.of(
                    ScimAttributeDefinition.withName("text").build(),
                    ScimAttributeDefinition.withName("link").type(ScimAttributeType.REFERENCE).build(),
                    ScimAttributeDefinition.withName("number").type(ScimAttributeType.DECIMAL).build(),
                    ScimAttributeDefinition.withName("rows").type(ScimAttributeType.COMPLEX).multiValued(true)
                            .subAttributes(List.of(ScimAttributeDefinition.withName("longchildname").build())).build())).build()).build();
    private static @NonNull ScimFilter filter(@NonNull String text) {
        return assertInstanceOf(ScimFilterParseResult.Succeeded.class,ScimFilter.fromExpressionResult(text)).getFilter();
    }
    private static @NonNull ScimResource resource(@NonNull String key,@NonNull JsonValue value) {
        return ScimResource.withResourceType(TYPE).document(JsonObject.builder()
                .put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(URN)))).put(key,value).build()).build();
    }
    private static void tooLarge(@NonNull ScimFilterEvaluationResult result) {
        assertSame(ScimError.requestTooLargeInstance(),assertInstanceOf(ScimFilterEvaluationResult.Rejected.class,result).getError());
    }
    @Test void exhaustedStringChargeDoesNotInvokeApplicationStrategy() {
        ScimResource current=resource("text",JsonString.fromValue("a"));
        ScimFilter bound=filter("text eq \"a\"");
        boolean sawRejection=false, sawSuccess=false;
        for (int remaining=0;remaining<=128;remaining++) {
            AtomicInteger calls=new AtomicInteger();
            ScimFilterEvaluationResult result=ScimFilterEvaluation.evaluate(current,bound,
                    (path,definition,operator,left,right) -> {calls.incrementAndGet();return ScimStringMatchResult.fromMatched(true);},
                    new ScimWork(remaining));
            if (result instanceof ScimFilterEvaluationResult.Rejected) {
                tooLarge(result); sawRejection=true;
                assertEquals(0,calls.get(),"No callback begins after budget exhaustion; remaining="+remaining);
            } else {
                sawSuccess=true;
                assertTrue(assertInstanceOf(ScimFilterEvaluationResult.Succeeded.class,result).isMatched());
                assertEquals(1,calls.get());
            }
        }
        assertTrue(sawRejection && sawSuccess,"The sweep includes exhausted and sufficient remaining budgets");
    }
    @Test void containsAndNumericComparisonsChargeTheirCoreWorkBeforeProducingAVerdict() {
        ScimStringMatching unexpected=(path,definition,operator,left,right) -> {fail("Core-owned typed comparison must bypass SPI");return ScimStringMatchResult.unsupportedInstance();};
        tooLarge(ScimFilterEvaluation.evaluate(resource("link",JsonString.fromValue("../"+"a".repeat(500))),
                filter("link co \""+"a".repeat(100)+"\""),unexpected,new ScimWork(10000)));
        String stored="9".repeat(4000), literal="8".repeat(250);
        ScimFilter numeric=assertInstanceOf(ScimFilterParseResult.Succeeded.class,ScimFilter.fromExpressionResult(
                "number eq "+literal,ScimFilterLimits.builder().maximumNumberCharacters(256).build())).getFilter();
        tooLarge(ScimFilterEvaluation.evaluate(resource("number",JsonNumber.fromValue(new BigDecimal(stored))),
                numeric,unexpected,new ScimWork(4000)));
    }
    @Test void longCanonicalValuePathChildrenRetainACompleteMatchedVerdict() {
        ScimResource current=resource("rows",JsonArray.fromElements(List.of(JsonObject.builder().put("longchildname","a").build())));
        ScimFilterEvaluationResult result=ScimFilterEvaluation.evaluate(current,filter("rows[longchildname eq \"a\"]"),
                (path,definition,operator,left,right) -> {assertEquals("rows.longchildname",path.toScimString());return ScimStringMatchResult.fromMatched(left.equals(right));},new ScimWork(1000000));
        assertTrue(assertInstanceOf(ScimFilterEvaluationResult.Succeeded.class,result).isMatched());
    }
}
