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
import com.revetsec.json.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Arbitrary foreign trees and an independent authored default-null/any-element truth model. */
@ThreadSafe
public final class ScimM12FuzzTests {
    private static final @NonNull String URN="urn:example:scim:fuzz:evaluation";
    private static final @NonNull ScimResourceType TYPE=ScimResourceType.withName("Evaluation").endpoint("/Evaluations")
            .schema(ScimSchema.withId(URN).name("Evaluation").attributes(List.of(
                    ScimAttributeDefinition.withName("text").build(),
                    ScimAttributeDefinition.withName("tags").multiValued(true).build(),
                    ScimAttributeDefinition.withName("date").type(ScimAttributeType.DATE_TIME).build(),
                    ScimAttributeDefinition.withName("number").type(ScimAttributeType.DECIMAL).build(),
                    ScimAttributeDefinition.withName("link").type(ScimAttributeType.REFERENCE).build(),
                    ScimAttributeDefinition.withName("rows").type(ScimAttributeType.COMPLEX).multiValued(true)
                            .subAttributes(List.of(ScimAttributeDefinition.withName("value").build(),ScimAttributeDefinition.withName("type").build())).build())).build()).build();
    private static final @NonNull Set<@NonNull ScimComparisonOperator> ALL=EnumSet.allOf(ScimComparisonOperator.class);
    private static final @NonNull ScimFilterPolicy POLICY=ScimFilterPolicy.builder()
            .allowedComparisons(Map.of("text",ALL,"tags",ALL,"date",EnumSet.of(ScimComparisonOperator.EQ,ScimComparisonOperator.NE,
                    ScimComparisonOperator.GT,ScimComparisonOperator.GE,ScimComparisonOperator.LT,ScimComparisonOperator.LE),"number",EnumSet.of(ScimComparisonOperator.EQ,ScimComparisonOperator.NE,
                    ScimComparisonOperator.GT,ScimComparisonOperator.GE,ScimComparisonOperator.LT,ScimComparisonOperator.LE),"link",ALL,"rows.value",ALL))
            .allowedPresence(Set.of("text","tags","rows","rows.value","date","number","link"))
            .allowedLogicalOperators(EnumSet.allOf(ScimLogicalOperator.class))
            .allowedValuePaths(Map.of("rows",ScimFilterPolicy.builder().allowedComparisons(Map.of("value",ALL,"type",ALL))
                    .allowedPresence(Set.of("value","type")).allowedLogicalOperators(EnumSet.allOf(ScimLogicalOperator.class)).build())).build();
    private static final @NonNull ScimStringMatching ASCII=(path,definition,operator,left,right) ->
            ScimStringMatchResult.fromMatched(switch(operator) {
                case EQ -> left.equals(right); case NE -> !left.equals(right); case CO -> left.contains(right);
                case SW -> left.startsWith(right); case EW -> left.endsWith(right); case GT -> left.compareTo(right)>0;
                case GE -> left.compareTo(right)>=0; case LT -> left.compareTo(right)<0; case LE -> left.compareTo(right)<=0;
            });
    private static final @NonNull ScimFilterEvaluator EVALUATOR=ScimFilterEvaluator.fromServiceProvider(provider(POLICY,ScimLimits.fromDefaults()));
    private static final @NonNull List<@NonNull ScimFilterEvaluator> RECEIVERS=List.of(EVALUATOR,
            ScimFilterEvaluator.fromServiceProvider(provider(ScimFilterPolicy.builder().allowedComparisons(Map.of("text",Set.of(ScimComparisonOperator.EQ))).build(),
                    ScimLimits.builder().maximumWorkUnits(10000).filterLimits(ScimFilterLimits.builder()
                            .maximumExpressionCharacters(256).maximumLiteralCharacters(16).maximumDepth(4).maximumNodes(8).build()).build())));
    private static final @NonNull ScimResourceType REBUILT_GROUP=ScimResourceType.withName("Group").endpoint("/Groups")
            .schema(ScimM12FuzzFixtures.rebuiltGroup()).build();
    private static final @NonNull ScimFilterEvaluator GROUP_EVALUATOR=ScimFilterEvaluator.fromServiceProvider(ScimServiceProvider.builder()
            .baseUri(URI.create("https://example.invalid/scim/")).resourceTypes(List.of(REBUILT_GROUP))
            .filterPolicies(Map.of(REBUILT_GROUP,ScimFilterPolicy.builder().allowedComparisons(Map.of("members.value",Set.of(ScimComparisonOperator.EQ)))
                    .allowedValuePaths(Map.of("members",ScimFilterPolicy.builder().allowedComparisons(Map.of("value",Set.of(ScimComparisonOperator.EQ))).build())).build()))
            .stringMatching((path,definition,operator,left,right) -> { Assertions.fail("Opaque standard Group IDs must bypass collation"); return ScimStringMatchResult.unsupportedInstance(); })
            .serviceProviderConfig(ScimServiceProviderConfig.builder().filterSupported(true).build()).build());
    private static final @NonNull ScimResource FIXTURE=ScimResource.withResourceType(TYPE).document(document()
            .put("text","a").put("tags",JsonArray.fromElements(List.of(JsonString.fromValue("a"),JsonString.fromValue("b"),JsonString.fromValue(""))))
            .put("rows",JsonArray.fromElements(List.of(JsonObject.builder().put("value","a").put("type","home").build(),
                    JsonObject.builder().put("value","b").put("type","work").build(),JsonObject.builder().put("type","missing").build())))
            .put("date","2000-01-01T00:00:00Z").put("number",1L).put("link","../Users/A").build()).build();
    private static @NonNull ScimServiceProvider provider(@NonNull ScimFilterPolicy policy,@NonNull ScimLimits limits) {
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(TYPE)).stringMatching(ASCII).limits(limits).filterPolicies(Map.of(TYPE,policy))
                .serviceProviderConfig(ScimServiceProviderConfig.builder().filterSupported(true).build()).build();
    }
    private static JsonObject.@NonNull Builder document() {
        return JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(URN))));
    }

    /** Neither arbitrary syntax nor an assigned/unassigned matrix can cause partial success or implicit policy grants. */
    @FuzzTest(maxDuration="5m")
    public void evaluationsRebindPoliciesAndAgreeWithIndependentNullModel(byte @NonNull [] input) {
        for (String expression:List.of(new String(input,StandardCharsets.UTF_8),rawUnits(input))) {
            ScimFilterParseResult parsed=ScimFilter.fromExpressionResult(expression);
            if (parsed instanceof ScimFilterParseResult.Succeeded success) {
                for (ScimFilterEvaluator receiver:RECEIVERS) {
                    ScimFilterEvaluationResult result=receiver.evaluateResult(FIXTURE,success.getFilter());
                    if (result instanceof ScimFilterEvaluationResult.Rejected rejected) fixed(rejected.getError());
                    else Assertions.assertNotNull(((ScimFilterEvaluationResult.Succeeded)result).isMatched());
                }
            }
        }
        // Structured synthetic data reaches evaluation on every input, even when raw syntax rejects.
        int mode=at(input,0)%4;
        String scalar=mode == 0 ? null : mode == 1 ? "" : mode == 2 ? "a" : "b";
        int count=at(input,1)%9;
        List<String> tags=new ArrayList<>();
        List<JsonValue> values=new ArrayList<>();
        for (int index=0;index<count;index++) {
            String value=switch(at(input,index+2)%3) { case 0 -> ""; case 1 -> "a"; default -> "b"; };
            tags.add(value); values.add(JsonString.fromValue(value));
        }
        JsonObject.Builder body=document().put("tags",JsonArray.fromElements(values));
        if (scalar != null) body.put("text",scalar);
        ScimResource resource=ScimResource.withResourceType(TYPE).document(body.build()).build();
        JsonObject before=resource.getDocument();
        check(resource,"text eq null",scalar == null);
        check(resource,"text ne null",scalar != null);
        check(resource,"text eq \"a\"","a".equals(scalar));
        check(resource,"text ne \"a\"",!"a".equals(scalar));
        check(resource,"text pr",scalar != null && !scalar.isEmpty());
        boolean equal=false,unequal=tags.isEmpty(),present=false;
        for (String value:tags) {
            if (value.equals("a")) equal=true;
            else unequal=true;
            if (!value.isEmpty()) present=true;
        }
        check(resource,"tags eq null",tags.isEmpty());
        check(resource,"tags ne null",!tags.isEmpty());
        check(resource,"tags eq \"a\"",equal);
        check(resource,"tags ne \"a\"",unequal);
        check(resource,"not(tags eq \"a\")",!equal);
        check(resource,"tags pr",present);
        Assertions.assertSame(before,resource.getDocument());
        String id=at(input,2)%2 == 0 ? "A" : "a";
        String requested=at(input,3)%2 == 0 ? "A" : "a";
        ScimResource group=ScimResource.withResourceType(REBUILT_GROUP).document(JsonObject.builder()
                .put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(REBUILT_GROUP.getSchema().getId()))))
                .put("displayName","fixture").put("members",JsonArray.fromElements(List.of(JsonObject.builder().put("value",id).build()))).build()).build();
        for (String expression:List.of("members.value eq "+JsonString.fromValue(requested).toJson(),
                "members[value eq "+JsonString.fromValue(requested).toJson()+"]")) {
            ScimFilter filter=Assertions.assertInstanceOf(ScimFilterParseResult.Succeeded.class,ScimFilter.fromExpressionResult(expression)).getFilter();
            boolean actual=Assertions.assertInstanceOf(ScimFilterEvaluationResult.Succeeded.class,GROUP_EVALUATOR.evaluateResult(group,filter)).isMatched();
            Assertions.assertEquals(id.equals(requested),actual,expression);
        }
    }
    private static void check(@NonNull ScimResource resource,@NonNull String expression,boolean expected) {
        ScimFilter filter=Assertions.assertInstanceOf(ScimFilterParseResult.Succeeded.class,ScimFilter.fromExpressionResult(expression)).getFilter();
        boolean actual=Assertions.assertInstanceOf(ScimFilterEvaluationResult.Succeeded.class,EVALUATOR.evaluateResult(resource,filter)).isMatched();
        Assertions.assertEquals(expected,actual,expression);
    }
    private static int at(byte @NonNull [] input,int index) { return index < input.length ? input[index]&255 : 0; }
    private static @NonNull String rawUnits(byte @NonNull [] input) {
        char[] characters=new char[(input.length+1)/2];
        for(int index=0;index<characters.length;index++) characters[index]=(char)((at(input,index*2)<<8)|at(input,index*2+1));
        return new String(characters);
    }
    private static void fixed(@NonNull ScimError error) {
        Assertions.assertNotSame(ScimError.internalErrorInstance(),error);
        Assertions.assertTrue(Set.of(400,403,413).contains(error.getStatusCode()));
        Assertions.assertTrue(error.getDetail().length()<128);
    }
}
