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

import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonNull;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/** Public-surface, independent security/specification verdicts for the SCIM RC-3 candidate. */
class ScimRc3SecurityTests {
    private static final @NonNull ScimResourceType USER=ScimResourceType.userInstance();
    private static final @NonNull String PATCH="urn:ietf:params:scim:api:messages:2.0:PatchOp";
    private static final @NonNull ScimStringMatching EXACT=(path,definition,operator,left,right) -> {
        int order=left.compareTo(right);
        return ScimStringMatchResult.fromMatched(switch(operator) {
            case EQ -> order == 0; case NE -> order != 0; case GT -> order > 0;
            case GE -> order >= 0; case LT -> order < 0; case LE -> order <= 0;
            case CO -> left.contains(right); case SW -> left.startsWith(right); case EW -> left.endsWith(right);
        });
    };
    private static @NonNull ScimServiceProvider provider() {
        ScimFilterPolicy children=ScimFilterPolicy.builder().allowedComparisons(Map.of("value",Set.of(ScimComparisonOperator.EQ,ScimComparisonOperator.NE)))
                .allowedPresence(Set.of("value")).allowedLogicalOperators(EnumSet.allOf(ScimLogicalOperator.class)).build();
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(USER)).stringMatching(EXACT)
                .serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).filterSupported(true).build())
                .filterPolicies(Map.of(USER,ScimFilterPolicy.builder().allowedValuePaths(Map.of("emails",children)).build())).build();
    }
    private static @NonNull ScimResource user(@NonNull JsonObject email) {
        return ScimResource.withResourceType(USER).document(JsonObject.builder()
                .put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(USER.getSchema().getId()))))
                .put("id","account").put("userName","subject").put("emails",JsonArray.fromElements(List.of(email))).build()).build();
    }
    private static @NonNull ScimPatchResult remove(@NonNull ScimServiceProvider provider,@NonNull ScimResource current,@NonNull String predicate) {
        String operation="{\"schemas\":[\""+PATCH+"\"],\"Operations\":[{\"op\":\"remove\",\"path\":\"emails["+predicate.replace("\\","\\\\").replace("\"","\\\"")+ "]\"}]}";
        ScimPatchRequest request=assertInstanceOf(ScimPatchParseResult.Succeeded.class,
                provider.parsePatchRequestResult(USER,operation.getBytes(StandardCharsets.UTF_8))).getPatchRequest();
        return assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,provider.applyPatchResult(current,request)).getPatchResult();
    }
    private static boolean evaluates(@NonNull ScimServiceProvider provider,@NonNull ScimResource current,@NonNull String predicate) {
        ScimFilter filter=assertInstanceOf(ScimFilterParseResult.Succeeded.class,
                ScimFilter.fromExpressionResult("emails["+predicate+"]")).getFilter();
        return assertInstanceOf(ScimFilterEvaluationResult.Succeeded.class,
                ScimFilterEvaluator.fromServiceProvider(provider).evaluateResult(current,filter)).isMatched();
    }
    private static void row(@NonNull JsonObject email,@NonNull String predicate,boolean expected) {
        ScimServiceProvider provider=provider(); ScimResource current=user(email);
        // The expected Boolean is hand-enumerated; neither production evaluator nor matcher supplies it.
        assertEquals(expected,evaluates(provider,current,predicate),"query selector: "+predicate);
        assertEquals(expected,remove(provider,current,predicate).isModified(),"PATCH selector: "+predicate);
    }
    @Test void patchNeOnAnAbsentValueMatchesTheApprovedNullTruthTable() {
        row(JsonObject.builder().put("type","work").build(),"value ne \"a\"",true);
    }
    @Test void patchEqNullDoesNotSelectAnAssignedEmptyString() {
        row(JsonObject.builder().put("value","").build(),"value eq null",false);
    }
    @Test void patchEmptyStringComparisonsKeepAssignedValueSemantics() {
        row(JsonObject.builder().put("value","").build(),"value eq \"\"",true);
        row(JsonObject.builder().put("value","").build(),"value ne null",true);
        row(JsonObject.builder().put("value","").build(),"value ne \"a\"",true);
    }
    @Test void assignedAndAbsentSelectorControlsPassIndependently() {
        for (String value:List.of("a","b")) {
            JsonObject email=JsonObject.builder().put("value",value).build();
            row(email,"value eq null",false); row(email,"value ne null",true); row(email,"value pr",true);
            row(email,"value eq \"a\"",value.equals("a")); row(email,"value ne \"a\"",!value.equals("a"));
        }
        JsonObject absent=JsonObject.builder().put("type","work").build();
        row(absent,"value eq null",true); row(absent,"value ne null",false); row(absent,"value eq \"a\"",false); row(absent,"value pr",false);
        row(JsonObject.builder().put("value","").build(),"value pr",false);
    }

    private static final @NonNull ScimResourceType CUSTOM=ScimResourceType.withName("Qualification").endpoint("/Qualifications")
            .schema(ScimSchema.withId("urn:rc3:security").name("Qualification").attributes(List.of(
                    ScimAttributeDefinition.withName("rows").type(ScimAttributeType.COMPLEX).multiValued(true)
                            .subAttributes(List.of(ScimAttributeDefinition.withName("tags").multiValued(true).build(),
                                    ScimAttributeDefinition.withName("marker").build())).build(),
                    ScimAttributeDefinition.withName("secret").mutability(ScimMutability.WRITE_ONLY).returned(ScimReturned.NEVER).build(),
                    ScimAttributeDefinition.withName("requested").returned(ScimReturned.REQUEST).build(),
                    ScimAttributeDefinition.withName("normal").build())).build()).build();
    private static @NonNull ScimServiceProvider customProvider(@NonNull ScimStringMatching matching) {
        ScimFilterPolicy child=ScimFilterPolicy.builder().allowedComparisons(Map.of("tags",EnumSet.allOf(ScimComparisonOperator.class),
                        "marker",EnumSet.allOf(ScimComparisonOperator.class)))
                .allowedPresence(Set.of("tags")).allowedLogicalOperators(EnumSet.allOf(ScimLogicalOperator.class)).build();
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(CUSTOM)).stringMatching(matching)
                .serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).filterSupported(true).build())
                .filterPolicies(Map.of(CUSTOM,ScimFilterPolicy.builder().allowedValuePaths(Map.of("rows",child)).build())).build();
    }
    private static @NonNull ScimResource custom(@NonNull JsonObject row) {
        return ScimResource.withResourceType(CUSTOM).document(JsonObject.builder()
                .put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(CUSTOM.getSchema().getId()))))
                .put("id","resource").put("normal","public-value").put("secret","private-never-value")
                .put("requested","private-requested-value").put("rows",JsonArray.fromElements(List.of(row))).build()).build();
    }
    private static @NonNull ScimPatchRequest patch(@NonNull ScimServiceProvider p,@NonNull ScimResourceType type,@NonNull String operations) {
        String input="{\"schemas\":[\""+PATCH+"\"],\"Operations\":["+operations+"]}";
        return assertInstanceOf(ScimPatchParseResult.Succeeded.class,p.parsePatchRequestResult(type,input.getBytes(StandardCharsets.UTF_8))).getPatchRequest();
    }
    private static @NonNull ScimPatchResult customRemove(@NonNull ScimServiceProvider p,@NonNull ScimResource current,@NonNull String predicate) {
        String encoded=predicate.replace("\\","\\\\").replace("\"","\\\"");
        return assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,p.applyPatchResult(current,
                patch(p,CUSTOM,"{\"op\":\"remove\",\"path\":\"rows["+encoded+"]\"}"))).getPatchResult();
    }
    private static void customRow(@NonNull JsonObject row,@NonNull String predicate,boolean expected) {
        ScimServiceProvider p=customProvider(EXACT); ScimResource current=custom(row);
        ScimFilter filter=assertInstanceOf(ScimFilterParseResult.Succeeded.class,ScimFilter.fromExpressionResult("rows["+predicate+"]")).getFilter();
        assertEquals(expected,assertInstanceOf(ScimFilterEvaluationResult.Succeeded.class,
                ScimFilterEvaluator.fromServiceProvider(p).evaluateResult(current,filter)).isMatched(),"query: "+predicate);
        assertEquals(expected,customRemove(p,current,predicate).isModified(),"PATCH: "+predicate);
    }
    private static @NonNull JsonObject tags(@NonNull String @NonNull ... values) {
        List<JsonValue> elements=new ArrayList<>(); for(String value:values) elements.add(JsonString.fromValue(value));
        return JsonObject.builder().put("marker","row").put("tags",JsonArray.fromElements(elements)).build();
    }
    @Test void primitiveArrayPresenceInspectsItsValues() {
        customRow(tags(""),"tags pr",false); customRow(tags(),"tags pr",false);
        customRow(tags("","a"),"tags pr",true); customRow(tags("a"),"tags pr",true);
    }
    @Test void primitiveArrayAbsentAndEmptyStringComparisonMatrix() {
        for(JsonObject row:List.of(tags(),JsonObject.builder().put("marker","row").build(),
                JsonObject.builder().put("marker","row").put("tags",JsonNull.defaultInstance()).build())) {
            customRow(row,"tags eq null",true); customRow(row,"tags ne null",false);
            customRow(row,"tags eq \"a\"",false); customRow(row,"tags ne \"a\"",true); customRow(row,"tags pr",false);
        }
        customRow(tags(""),"tags eq null",false); customRow(tags(""),"tags ne null",true);
        customRow(tags(""),"tags eq \"\"",true); customRow(tags(""),"tags ne \"a\"",true);
    }
    @Test void primitiveArrayAnyElementNeDiffersFromWholePredicateNot() {
        customRow(tags("a","b"),"tags eq \"a\"",true);
        customRow(tags("a","b"),"tags ne \"a\"",true);
        customRow(tags("a","b"),"not(tags eq \"a\")",false);
        customRow(tags("a","a"),"tags ne \"a\"",false);
    }
    @Test void unsupportedHealthyNonLeadingLogicalClausesStillReject() {
        ScimServiceProvider p=customProvider((path,definition,operator,left,right) -> path.getSubAttributeName().orElse("").equals("marker")
                ? ScimStringMatchResult.unsupportedInstance() : EXACT.match(path,definition,operator,left,right));
        ScimResource current=custom(tags("a"));
        for(String predicate:List.of("tags eq \"a\" or marker eq \"row\"","tags eq \"b\" and marker eq \"row\"")) {
            String encoded=predicate.replace("\"","\\\"");
            ScimPatchRequest request=patch(p,CUSTOM,"{\"op\":\"remove\",\"path\":\"rows["+encoded+"]\"}");
            assertSame(ScimError.invalidFilterInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,p.applyPatchResult(current,request)).getError());
        }
    }
    @Test void terminalSelectorRejectionStopsApplicationCallbacks() {
        AtomicInteger calls=new AtomicInteger();
        ScimServiceProvider p=customProvider((path,definition,operator,left,right) -> {
            calls.incrementAndGet(); return ScimStringMatchResult.unsupportedInstance();
        });
        ScimResource current=custom(tags("a","b","c"));
        ScimPatchRequest request=patch(p,CUSTOM,"{\"op\":\"remove\",\"path\":\"rows[tags eq \\\"a\\\" or marker eq \\\"row\\\"]\"}");
        assertInstanceOf(ScimPatchApplicationResult.Rejected.class,p.applyPatchResult(current,request));
        assertEquals(1,calls.get());
        JsonArray rows=assertInstanceOf(JsonArray.class,current.getDocument().find("rows").orElseThrow());
        JsonObject row=assertInstanceOf(JsonObject.class,rows.getElements().get(0));
        JsonArray values=assertInstanceOf(JsonArray.class,row.find("tags").orElseThrow());
        assertEquals(List.of("a","b","c"),values.getElements().stream()
                .map(value -> assertInstanceOf(JsonString.class,value).getValue()).toList());
    }
    private static @NonNull ScimAttributeSelection selection(@NonNull ScimServiceProvider p,@NonNull ScimResourceType type,@NonNull String raw) {
        return assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class,p.parseAttributeSelectionResult(type,raw)).getAttributeSelection();
    }
    private static @NonNull String body(@NonNull ScimResponseResult response) {
        return new String(assertInstanceOf(ScimResponseResult.Prepared.class,response).getResponse().toHttpBodyWithPersonalData(),StandardCharsets.UTF_8);
    }
    @Test void everyProjectionContextStripsNeverAndDoesNotInventWriteProvenance() {
        ScimServiceProvider p=customProvider(EXACT); ScimResource current=custom(tags("a"));
        for(String raw:List.of("","attributes=secret","attributes=requested","attributes=normal","excludedAttributes=id")) {
            ScimAttributeSelection selected=selection(p,CUSTOM,raw);
            String get=body(p.resourceResponseResult(current,selected));
            String write=body(p.replacementResponseResult(current,Set.of(),selected));
            assertFalse(get.contains("private-never-value")); assertFalse(write.contains("private-never-value"));
            assertEquals(raw.equals("attributes=requested"),get.contains("private-requested-value"));
            assertEquals(raw.equals("attributes=requested"),write.contains("private-requested-value"));
            assertTrue(get.contains("\"id\":\"resource\""));
        }
        ScimAttributePath supplied=assertInstanceOf(ScimAttributePathParseResult.Succeeded.class,ScimAttributePath.fromExpressionResult("requested")).getAttributePath();
        assertTrue(body(p.replacementResponseResult(current,Set.of(supplied),selection(p,CUSTOM,""))).contains("private-requested-value"));
        assertFalse(body(p.resourceResponseResult(current,selection(p,CUSTOM,""))).contains("private-requested-value"));
    }
    @Test void relaxedPatchCannotBeAppliedUnderStrictProviderProof() {
        ScimServiceProvider strict=provider(); ScimServiceProvider relaxed=strict.copy().compatibility(ScimCompatibility.microsoftEntraIdInstance()).finish();
        ScimPatchRequest request=patch(relaxed,USER,"{\"op\":\"Replace\",\"path\":\"active\",\"value\":\"false\"}");
        ScimResource current=user(JsonObject.builder().put("value","a").build());
        assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,relaxed.applyPatchResult(current,request));
        assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,strict.applyPatchResult(current,request)).getError());
        assertInstanceOf(ScimPatchParseResult.Rejected.class,strict.parsePatchRequestResult(USER,
                ("{\"schemas\":[\""+PATCH+"\"],\"Operations\":[{\"op\":\"Replace\",\"path\":\"active\",\"value\":\"false\"}]}").getBytes(StandardCharsets.UTF_8)));
    }
    @Test void independentProviderSelectionAndParsedResourceProofsAreRejected() {
        ScimServiceProvider one=provider(); ScimServiceProvider two=provider();
        ScimResource trusted=user(JsonObject.builder().put("value","a").build());
        assertInstanceOf(ScimResponseResult.Rejected.class,one.resourceResponseResult(trusted,selection(two,USER,"")));
        String create="{\"schemas\":[\""+USER.getSchema().getId()+"\"],\"userName\":\"subject\"}";
        ScimResource parsed=assertInstanceOf(ScimResourceParseResult.Succeeded.class,one.parseResourceResult(USER,create.getBytes(StandardCharsets.UTF_8))).getResource();
        ScimPatchRequest request=patch(two,USER,"{\"op\":\"replace\",\"path\":\"active\",\"value\":true}");
        assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,two.applyPatchResult(parsed,request)).getError());
    }
    @Test void unknownFilterClausesCannotTurnIntoBroadQueries() {
        ScimServiceProvider p=provider();
        for(String expression:List.of("userName eq \"subject\"","emails[value eq \"a\"] or userName eq \"subject\"",
                "password pr","emails[value eq \"a\" and password pr]")) {
            assertInstanceOf(ScimFilterParseResult.Rejected.class,p.parseFilterResult(USER,expression));
        }
        assertInstanceOf(ScimFilterParseResult.Succeeded.class,p.parseFilterResult(USER,"emails[value eq \"a\"]"));
    }
    @Test void rawQueryHeaderAndBodyErrorsKeepSyntheticSecretsOutOfDiagnostics() {
        ScimServiceProvider p=provider(); String secret="rc3-sensitive-marker";
        List<ScimError> errors=List.of(
                assertInstanceOf(ScimQueryParseResult.Rejected.class,p.parseQueryResult(USER,"filter="+secret+"%G0")).getError(),
                assertInstanceOf(ScimResourceParseResult.Rejected.class,p.parseResourceResult(USER,("{\"userName\":\""+secret+"\",\"UserName\":\"x\"}").getBytes(StandardCharsets.UTF_8))).getError(),
                assertInstanceOf(ScimContentTypeResult.Rejected.class,p.validateContentTypeResult(List.of("application/scim+json; x="+secret))).getError(),
                assertInstanceOf(ScimPatchParseResult.Rejected.class,p.parsePatchRequestResult(USER,("{\"schemas\":[\""+PATCH+"\"],\"Operations\":[{\"op\":\"remove\",\"path\":\"emails\",\"value\":\""+secret+"\"}]}").getBytes(StandardCharsets.UTF_8))).getError());
        for(ScimError error:errors) {
            assertFalse(error.toString().contains(secret)); assertFalse(error.getDetail().contains(secret));
            String rendered=new String(p.errorResponse(error).toHttpBodyWithPersonalData(),StandardCharsets.UTF_8);
            assertFalse(rendered.contains(secret)); assertTrue(rendered.contains("\"status\":\""));
        }
    }
    @Test void preconditionsUseExactOpaqueVersionsAndRejectMalformedLists() {
        ScimServiceProvider p=provider(); ScimResource current=user(JsonObject.builder().put("value","a").build());
        JsonObject.Builder document=JsonObject.builder(); current.getDocument().getMembers().forEach(document::put);
        current=current.copy().document(document.put("meta",JsonObject.builder().put("version","W/\"Abc\"").build()).build()).finish();
        assertInstanceOf(ScimIfMatchResult.Satisfied.class,p.checkIfMatchResult(List.of("\"Abc\""),current));
        assertInstanceOf(ScimIfMatchResult.Satisfied.class,p.checkIfMatchResult(List.of("W/\"Abc\""),current));
        assertSame(ScimError.preconditionFailedInstance(),assertInstanceOf(ScimIfMatchResult.Rejected.class,p.checkIfMatchResult(List.of("W/\"abc\""),current)).getError());
        for(String raw:List.of("*, \"Abc\"","W/Abc","\"Abc\" junk","\"Abc\"\r\nInjected: true","w/\"Abc\""))
            assertInstanceOf(ScimIfMatchResult.Rejected.class,p.checkIfMatchResult(List.of(raw),current));
        assertInstanceOf(ScimIfNoneMatchResult.NotModified.class,p.checkIfNoneMatchResult(List.of("\"other\"","\"Abc\""),current));
        ScimResponse response=assertInstanceOf(ScimResponseResult.Prepared.class,p.notModifiedResponseResult(current)).getResponse();
        assertEquals(304,response.getStatusCode()); assertEquals(0,response.toHttpBodyWithPersonalData().length);
        assertEquals(List.of("W/\"Abc\""),response.getHeaders().get("ETag"));
    }
    @Test void identifierLocationAlwaysEncodesOneSegmentAndRejectsReservedIds() {
        ScimServiceProvider p=provider();
        assertEquals("https://example.invalid/scim/Users/%2E%2E%2Fadmin%3Fowner%3D1%23fragment",
                p.resourceLocationFor(USER,"../admin?owner=1#fragment").toASCIIString());
        for(String id:List.of("","bulkId-internal","case-BULKID-internal","a\r\nHeader","unpaired\uD800","unpaired\uDC00"))
            assertThrows(IllegalArgumentException.class,()->p.resourceLocationFor(USER,id));
    }

    @Test void acceptedOpaqueIdentifiersWithSpacesPrepareConsistentLocations() {
        ScimServiceProvider p=provider();
        for(String id:List.of("a b"," leading","trailing "," ")) {
            JsonObject document=JsonObject.builder()
                    .put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(USER.getSchema().getId()))))
                    .put("id",id).put("userName","subject").build();
            ScimResource current=ScimResource.withResourceType(USER).document(document).build();
            assertEquals(id,current.getId().orElseThrow());
            String expected="https://example.invalid/scim/Users/"+id.replace(" ","%20");
            assertEquals(expected,p.resourceLocationFor(USER,id).toASCIIString());
            ScimResponse created=assertInstanceOf(ScimResponseResult.Prepared.class,
                    p.createdResponseResult(current,Set.of(),selection(p,USER,""))).getResponse();
            assertEquals(List.of(expected),created.getHeaders().get("Location"));
            String output=new String(created.toHttpBodyWithPersonalData(),StandardCharsets.UTF_8);
            assertTrue(output.contains("\"location\":\""+expected+"\""));
        }
    }

    @Test void latePatchFailureCannotPublishAnEarlierDraft() {
        ScimServiceProvider p=provider(); ScimResource current=user(JsonObject.builder().put("value","a").build());
        JsonObject before=current.getDocument();
        ScimPatchRequest request=patch(p,USER,"{\"op\":\"replace\",\"path\":\"active\",\"value\":false},"
                +"{\"op\":\"replace\",\"path\":\"id\",\"value\":\"attacker\"}");
        assertSame(ScimError.mutabilityInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,
                p.applyPatchResult(current,request)).getError());
        assertSame(before,current.getDocument()); assertTrue(current.getDocument().find("active").isEmpty());
        assertEquals("account",current.getId().orElseThrow());
    }
    @Test void noOpRetainsAttemptedPrivilegePathsWithoutCreatingEffectiveChanges() {
        ScimServiceProvider p=provider(); ScimResource current=user(JsonObject.builder().put("value","a").build());
        ScimPatchRequest request=patch(p,USER,"{\"op\":\"replace\",\"path\":\"roles\",\"value\":[{\"value\":\"admin\"}]},"
                +"{\"op\":\"remove\",\"path\":\"roles\"}");
        ScimPatchResult result=assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,p.applyPatchResult(current,request)).getPatchResult();
        assertFalse(result.isModified()); assertSame(current,result.getResource());
        Set<String> paths=result.getRequestedAttributePaths().stream().map(ScimAttributePath::toScimString).collect(java.util.stream.Collectors.toSet());
        assertTrue(paths.containsAll(Set.of("roles","roles.value"))); assertTrue(result.getModifiedAttributePaths().isEmpty());
    }
    @Test void primarySideEffectsAppearInEffectivePaths() {
        ScimServiceProvider p=provider();
        ScimResource current=ScimResource.withResourceType(USER).document(JsonObject.builder()
                .put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(USER.getSchema().getId()))))
                .put("id","account").put("userName","subject").put("emails",JsonArray.fromElements(List.of(
                        JsonObject.builder().put("value","a").put("type","work").put("primary",true).build(),
                        JsonObject.builder().put("value","b").put("type","home").build()))).build()).build();
        ScimPatchRequest request=patch(p,USER,"{\"op\":\"replace\",\"path\":\"emails[value eq \\\"b\\\"].primary\",\"value\":true}");
        ScimPatchResult result=assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,p.applyPatchResult(current,request)).getPatchResult();
        Set<String> paths=result.getModifiedAttributePaths().stream().map(ScimAttributePath::toScimString).collect(java.util.stream.Collectors.toSet());
        assertTrue(paths.containsAll(Set.of("emails","emails.primary")));
        JsonArray emails=assertInstanceOf(JsonArray.class,result.getResource().getDocument().find("emails").orElseThrow());
        assertFalse(assertInstanceOf(JsonObject.class,emails.getElements().get(0)).findBoolean("primary").orElseThrow());
        assertTrue(assertInstanceOf(JsonObject.class,emails.getElements().get(1)).findBoolean("primary").orElseThrow());
    }

    @Test void resourceIdentifierLengthBoundaryAgreesWithLocationPreparation() {
        ScimServiceProvider p=provider(); String exact=" ".repeat(1024);
        JsonObject document=JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(USER.getSchema().getId()))))
                .put("id",exact).put("userName","subject").build();
        ScimResource current=ScimResource.withResourceType(USER).document(document).build();
        assertEquals(exact,current.getId().orElseThrow());
        assertEquals("https://example.invalid/scim/Users/"+"%20".repeat(1024),p.resourceLocationFor(USER,exact).toASCIIString());
        String excessive=exact+" ";
        assertThrows(IllegalArgumentException.class,()->p.resourceLocationFor(USER,excessive));
        JsonObject tooLong=JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(USER.getSchema().getId()))))
                .put("id",excessive).put("userName","subject").build();
        assertThrows(IllegalArgumentException.class,()->ScimResource.withResourceType(USER).document(tooLong).build());
    }
}
