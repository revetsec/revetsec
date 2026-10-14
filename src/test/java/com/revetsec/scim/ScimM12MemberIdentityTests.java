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
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

/** Opaque identity controls use authored verdicts and an ordered storage model. */
class ScimM12MemberIdentityTests {
    private static final @NonNull ScimFilterPolicy POLICY=ScimFilterPolicy.builder()
            .allowedComparisons(Map.of("members.value",Set.of(ScimComparisonOperator.EQ,ScimComparisonOperator.NE)))
            .allowedValuePaths(Map.of("members",ScimFilterPolicy.builder()
                    .allowedComparisons(Map.of("value",Set.of(ScimComparisonOperator.EQ,ScimComparisonOperator.NE))).build())).build();
    private static @NonNull ScimAttributeDefinition rebuilt(@NonNull ScimAttributeDefinition original,boolean upperNames) {
        List<ScimAttributeDefinition> children=new ArrayList<>();
        for (ScimAttributeDefinition child:original.getSubAttributes()) children.add(rebuilt(child,upperNames));
        return ScimAttributeDefinition.withName(upperNames ? original.getName().toUpperCase(java.util.Locale.ROOT) : original.getName()).type(original.getType())
                .description(original.getDescription().orElse(null)).multiValued(original.isMultiValued())
                .required(original.isRequired()).caseExact(original.isCaseExact()).mutability(original.getMutability())
                .returned(original.getReturned()).uniqueness(original.getUniqueness()).canonicalValues(original.getCanonicalValues())
                .referenceTypes(original.getReferenceTypes()).subAttributes(children).build();
    }
    private static @NonNull ScimSchema rebuiltGroup(@NonNull String id) { return rebuiltGroup(id,false); }
    private static @NonNull ScimSchema rebuiltGroup(@NonNull String id,boolean upperNames) {
        ScimSchema standard=ScimSchema.groupInstance();
        List<ScimAttributeDefinition> attributes=new ArrayList<>();
        for (ScimAttributeDefinition definition:standard.getAttributes()) attributes.add(rebuilt(definition,upperNames));
        return ScimSchema.withId(id).name(standard.getName()).description(standard.getDescription().orElse(null))
                .attributes(attributes).build();
    }
    private static @NonNull ScimResourceType type(@NonNull ScimSchema schema) {
        return ScimResourceType.withName("DirectoryGroup").endpoint("/DirectoryGroups").schema(schema).build();
    }
    private static @NonNull ScimServiceProvider provider(@NonNull ScimResourceType type,@NonNull AtomicInteger callbacks) {
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(type)).filterPolicies(Map.of(type,POLICY))
                .serviceProviderConfig(ScimServiceProviderConfig.builder().filterSupported(true).patchSupported(true).build())
                .stringMatching((path,definition,operator,left,right) -> {
                    callbacks.incrementAndGet();
                    boolean equal=left.equalsIgnoreCase(right);
                    return ScimStringMatchResult.fromMatched(operator == ScimComparisonOperator.NE ? !equal : equal);
                }).build();
    }
    private static @NonNull ScimResource resource(@NonNull ScimResourceType type,@NonNull List<@NonNull JsonValue> members) {
        return ScimResource.withResourceType(type).document(JsonObject.builder()
                .put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(type.getSchema().getId()))))
                .put("id","group-1").put("displayName","Example").put("members",JsonArray.fromElements(members)).build()).build();
    }
    private static boolean matched(@NonNull ScimServiceProvider provider,@NonNull ScimResource current,@NonNull String expression) {
        ScimFilter filter=assertInstanceOf(ScimFilterParseResult.Succeeded.class,ScimFilter.fromExpressionResult(expression)).getFilter();
        return assertInstanceOf(ScimFilterEvaluationResult.Succeeded.class,
                ScimFilterEvaluator.fromServiceProvider(provider).evaluateResult(current,filter)).isMatched();
    }
    private static @NonNull ScimPatchRequest patch(@NonNull ScimServiceProvider provider,@NonNull ScimResourceType type,
            @NonNull String operations) {
        byte[] body=("{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\"Operations\":["+operations+"]}")
                .getBytes(StandardCharsets.UTF_8);
        return assertInstanceOf(ScimPatchParseResult.Succeeded.class,provider.parsePatchRequestResult(type,body)).getPatchRequest();
    }
    private static @NonNull String remove(@NonNull String id) {
        return JsonObject.builder().put("op","remove").put("path","members[value eq \""+id+"\"]").build().toJson();
    }
    private static @NonNull ScimPatchResult apply(@NonNull ScimServiceProvider provider,@NonNull ScimResource current,@NonNull ScimPatchRequest patch) {
        return assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,provider.applyPatchResult(current,patch)).getPatchResult();
    }
    @Test void equalRebuiltDefinitionsAndCaseFoldedSchemaIdsKeepOpaqueMemberIdsExact() {
        ScimSchema standard=ScimSchema.groupInstance();
        for (ScimSchema schema:List.of(standard,rebuiltGroup(standard.getId()),rebuiltGroup(standard.getId().toUpperCase(java.util.Locale.ROOT)),
                rebuiltGroup(standard.getId().toUpperCase(java.util.Locale.ROOT),true))) {
            assertEquals(standard,schema);
            ScimResourceType type=type(schema);
            assertEquals(schema,type.getSchema());
            assertEquals(schema.getId(),type.getSchema().getId());
            assertEquals(schema.getName(),type.getSchema().getName());
            assertEquals(schema.getDescription(),type.getSchema().getDescription());
            assertEquals(standard.getAttributes().stream().map(ScimAttributeDefinition::getName).toList(),
                    type.getSchema().getAttributes().stream().map(ScimAttributeDefinition::getName).toList());
            AtomicInteger callbacks=new AtomicInteger();
            ScimServiceProvider provider=provider(type,callbacks);
            ScimResource current=resource(type,List.of(JsonObject.builder().put("value","A").build()));
            assertEquals("A",ScimGroup.fromResource(current).getMembers().get(0).findString("value").orElseThrow());
            for (String expression:List.of("members.value eq \"A\"","members[value eq \"A\"]","members.value ne \"a\""))
                assertTrue(matched(provider,current,expression),expression);
            for (String expression:List.of("members.value eq \"a\"","members[value eq \"a\"]","members.value ne \"A\""))
                assertFalse(matched(provider,current,expression),expression);
            assertEquals(0,callbacks.get(),"Opaque Group identity bypasses application collation");
        }
    }
    @Test void sameUriWithAlteredFacetsRejectsAndCustomCloneRetainsApplicationMatching() {
        ScimSchema standard=ScimSchema.groupInstance();
        List<ScimAttributeDefinition> altered=new ArrayList<>(standard.getAttributes());
        ScimAttributeDefinition first=altered.get(0);
        altered.set(0,ScimAttributeDefinition.withName(first.getName()).type(first.getType())
                .description(first.getDescription().orElse(null)).required(first.isRequired()).caseExact(!first.isCaseExact()).build());
        for (ScimSchema schema:List.of(
                ScimSchema.withId(standard.getId()).name("Altered").description(standard.getDescription().orElse(null)).attributes(standard.getAttributes()).build(),
                ScimSchema.withId(standard.getId()).name(standard.getName()).description("Altered").attributes(standard.getAttributes()).build(),
                ScimSchema.withId(standard.getId()).name(standard.getName()).description(standard.getDescription().orElse(null)).attributes(altered).build())) {
            assertNotEquals(standard,schema);
            ScimResourceType type=type(schema);
            assertThrows(IllegalArgumentException.class,() -> provider(type,new AtomicInteger()));
        }
        for (boolean upperNames:List.of(false,true)) {
            ScimSchema customSchema=rebuiltGroup("urn:example:custom:group",upperNames);
            ScimResourceType custom=type(customSchema);
            assertSame(customSchema,custom.getSchema(),"Custom registrations keep their configured definitions");
            AtomicInteger calls=new AtomicInteger();
            ScimServiceProvider provider=provider(custom,calls);
            ScimResource current=resource(custom,List.of(JsonObject.builder().put("value","A").build()));
            assertTrue(matched(provider,current,"members.value eq \"a\""));
            assertTrue(matched(provider,current,"members[value eq \"a\"]"));
            assertEquals(2,calls.get(),"A custom schema cannot obtain the builtin opaque-ID exception");
            assertInstanceOf(ScimMembershipPatchResult.RequiresFullEvaluation.class,provider.reduceMembershipPatchResult(
                    patch(provider,custom,remove("a"))));
        }
    }
    @Test void fullEngineRebuiltFallbackAndSingletonReductionAgreeWithoutLosingOrderOrMetadata() {
        ScimSchema standard=ScimSchema.groupInstance();
        JsonObject a=JsonObject.builder().put("value","A").put("display","Saved A").put("type","User").build();
        JsonObject b=JsonObject.builder().put("value","B").put("display","Saved B").build();
        JsonObject lower=JsonObject.builder().put("value","a").build();
        String operations=remove("a")+","
                +"{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"a\"},{\"value\":\"A\"}]},"
                +"{\"op\":\"replace\",\"path\":\"members\",\"value\":[{\"value\":\"B\"},{\"value\":\"a\"}]},"
                +remove("a")+","
                +"{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"a\"}]}";
        List<JsonValue> expected=List.of(b,lower);
        int fixtureIndex=0;
        for (ScimSchema schema:List.of(standard,rebuiltGroup(standard.getId()),rebuiltGroup(standard.getId().toUpperCase(java.util.Locale.ROOT),true))) {
            ScimResourceType type=type(schema);
            AtomicInteger calls=new AtomicInteger();
            ScimServiceProvider provider=provider(type,calls);
            ScimResource current=resource(type,List.of(a,b));
            ScimPatchRequest request=patch(provider,type,operations);
            ScimMembershipPatchResult reduced=provider.reduceMembershipPatchResult(request);
            if (fixtureIndex++ == 0) {
                ScimMembershipPatch instructions=assertInstanceOf(ScimMembershipPatchResult.Reduced.class,reduced).getMembershipPatch();
                assertEquals(expected,executeStorageModel(List.of(a,b),instructions));
            } else assertInstanceOf(ScimMembershipPatchResult.RequiresFullEvaluation.class,reduced);
            ScimPatchResult result=apply(provider,current,request);
            assertEquals(JsonArray.fromElements(expected),result.getResource().getDocument().find("members").orElseThrow());
            assertEquals(JsonArray.fromElements(List.of(a,b)),current.getDocument().find("members").orElseThrow());
            assertEquals(0,calls.get());
            ScimPatchResult exactRemoval=apply(provider,current,patch(provider,type,remove("A")));
            assertEquals(JsonArray.fromElements(List.of(b)),exactRemoval.getResource().getDocument().find("members").orElseThrow());
            assertEquals(current.getId(),exactRemoval.getResource().getId());
            ScimPatchRequest wrongCase=patch(provider,type,remove("a"));
            assertFalse(apply(provider,current,wrongCase).isModified());
            ScimPatchRequest forged=patch(provider,type,"{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"A\",\"display\":\"Forged\"}]}");
            assertSame(ScimError.mutabilityInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,
                    provider.applyPatchResult(current,forged)).getError());
            ScimPatchResult cleared=apply(provider,current,patch(provider,type,"{\"op\":\"remove\",\"path\":\"members\"}"));
            assertTrue(cleared.getResource().getDocument().find("members").isEmpty());
        }
    }
    private static @NonNull List<@NonNull JsonValue> executeStorageModel(@NonNull List<@NonNull JsonValue> initial,
            @NonNull ScimMembershipPatch instructions) {
        List<JsonValue> stored=new ArrayList<>(initial);
        int index=0;
        for (ScimMembershipPatch.Step step:instructions.getSteps()) {
            assertEquals(index++,step.getOperationIndex());
            if (step.getKind() == ScimMembershipPatch.Kind.REMOVE_IDS)
                stored.removeIf(value -> step.getValues().contains(((JsonObject)value).findString("value").orElseThrow()));
            else if (step.getKind() == ScimMembershipPatch.Kind.CLEAR) stored.clear();
            else {
                List<JsonValue> next=step.getKind() == ScimMembershipPatch.Kind.REPLACE_IDS ? new ArrayList<>() : stored;
                for (String id:step.getValues()) {
                    JsonValue existing=null;
                    for (JsonValue value:stored) if (((JsonObject)value).findString("value").orElseThrow().equals(id)) { existing=value; break; }
                    if (next.stream().noneMatch(value -> ((JsonObject)value).findString("value").orElseThrow().equals(id)))
                        next.add(existing == null ? JsonObject.builder().put("value",id).build() : existing);
                }
                stored=next;
            }
        }
        return stored;
    }
    @Test void putMembershipReconciliationPreservesExactIdsAndMetadataAcrossAcceptedSchemaSpellings() {
        ScimSchema standard=ScimSchema.groupInstance();
        JsonObject a=JsonObject.builder().put("value","A").put("display","Saved A").put("type","User").put("$ref","../Users/A").build();
        JsonObject b=JsonObject.builder().put("value","B").put("display","Saved B").put("type","Group").put("$ref","../Groups/B").build();
        JsonObject lower=JsonObject.builder().put("value","a").build();
        for (ScimSchema schema:List.of(standard,rebuiltGroup(standard.getId()),rebuiltGroup(standard.getId().toUpperCase(java.util.Locale.ROOT)),
                rebuiltGroup(standard.getId().toUpperCase(java.util.Locale.ROOT),true))) {
            ScimResourceType type=type(schema);
            ScimServiceProvider provider=provider(type,new AtomicInteger());
            JsonObject document=resource(type,List.of(a,b)).getDocument();
            Map<String,JsonValue> stored=new java.util.LinkedHashMap<>(document.getMembers());
            stored.put("meta",JsonObject.builder().put("version","W/\"saved\"").put("resourceType",type.getName()).build());
            ScimResource current=ScimResource.withResourceType(type).document(JsonObject.fromMembers(stored)).build();
            JsonObject body=JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(schema.getId()))))
                    .put("displayName","Renamed").put("id","attempted-change").build();
            List<List<JsonValue>> requested=List.of(List.of(JsonObject.builder().put("value","B").put("display","Forged").build(),
                    JsonObject.builder().put("value","a").put("display","Forged").build()),List.of(b,a),List.of());
            List<List<JsonValue>> expected=List.of(List.of(b,lower),List.of(b,a),List.of());
            for (int index=0;index<requested.size();index++) {
                Map<String,JsonValue> requestedBody=new java.util.LinkedHashMap<>(body.getMembers());
                requestedBody.put("members",JsonArray.fromElements(requested.get(index)));
                JsonObject replacement=JsonObject.fromMembers(requestedBody);
                ScimResource replaced=assertInstanceOf(ScimResourceParseResult.Succeeded.class,provider.parseReplacementResult(type,current,
                        replacement.toJson().getBytes(StandardCharsets.UTF_8))).getResource();
                assertEquals(JsonArray.fromElements(expected.get(index)),replaced.getDocument().find("members").orElseThrow());
                assertEquals(current.getId(),replaced.getId());
                assertEquals(current.getVersion(),replaced.getVersion());
                assertEquals(document.find("members"),current.getDocument().find("members"));
            }
            ScimResource omitted=assertInstanceOf(ScimResourceParseResult.Succeeded.class,provider.parseReplacementResult(type,current,
                    JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(schema.getId()))))
                            .put("displayName","Renamed").build().toJson().getBytes(StandardCharsets.UTF_8))).getResource();
            assertTrue(omitted.getDocument().find("members").isEmpty());
        }
    }
    @Test void standardGroupMemberIdLexicalRulesAlsoApplyToFoldedSchemaUrisWhileCustomStringsRemainCustom() {
        ScimSchema standard=ScimSchema.groupInstance();
        for (ScimSchema schema:List.of(standard,rebuiltGroup(standard.getId()),rebuiltGroup(standard.getId().toUpperCase(java.util.Locale.ROOT)),
                rebuiltGroup(standard.getId().toUpperCase(java.util.Locale.ROOT),true))) {
            ScimResourceType type=type(schema);
            ScimServiceProvider provider=provider(type,new AtomicInteger());
            for (String id:List.of("bulkId:temporary","BULKID","id\nbreak","id\u007fbreak")) {
                JsonObject body=JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(schema.getId()))))
                        .put("displayName","Fixture").put("members",JsonArray.fromElements(List.of(JsonObject.builder().put("value",id).build()))).build();
                assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimResourceParseResult.Rejected.class,
                        provider.parseResourceResult(type,body.toJson().getBytes(StandardCharsets.UTF_8))).getError(),id);
            }
        }
        ScimResourceType custom=type(rebuiltGroup("urn:example:custom:group"));
        ScimServiceProvider provider=provider(custom,new AtomicInteger());
        JsonObject body=JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(custom.getSchema().getId()))))
                .put("displayName","Fixture").put("members",JsonArray.fromElements(List.of(JsonObject.builder().put("value","bulkId:temporary").build()))).build();
        ScimResource resource=assertInstanceOf(ScimResourceParseResult.Succeeded.class,provider.parseResourceResult(custom,body.toJson().getBytes(StandardCharsets.UTF_8))).getResource();
        JsonArray members=assertInstanceOf(JsonArray.class,resource.getDocument().find("members").orElseThrow());
        assertEquals("bulkId:temporary",assertInstanceOf(JsonObject.class,members.getElements().get(0)).findString("value").orElseThrow());
    }
}
