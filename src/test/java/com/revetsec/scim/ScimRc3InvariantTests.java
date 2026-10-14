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
import java.util.List;
import java.util.Map;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

/** Public security contracts tied to INV-M1..M10 and disposable defect-recall controls. */
class ScimRc3InvariantTests {
    private static final @NonNull ScimResourceType USER=ScimResourceType.userInstance();
    private static final @NonNull ScimResourceType GROUP=ScimResourceType.groupInstance();
    private static final @NonNull String PATCH="urn:ietf:params:scim:api:messages:2.0:PatchOp";
    private static byte @NonNull [] bytes(@NonNull String text) { return text.getBytes(StandardCharsets.UTF_8); }
    private static @NonNull ScimFilterPolicy policy() {
        return ScimFilterPolicy.builder().allowedComparisons(Map.of("userName",Set.of(ScimComparisonOperator.EQ)))
                .allowedValuePaths(Map.of("emails",ScimFilterPolicy.builder()
                        .allowedComparisons(Map.of("type",Set.of(ScimComparisonOperator.EQ),"value",Set.of(ScimComparisonOperator.EQ)))
                        .allowedLogicalOperators(Set.of(ScimLogicalOperator.AND)).build())).build();
    }
    private static @NonNull ScimServiceProvider provider() {
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(USER,GROUP)).filterPolicies(Map.of(USER,policy(),GROUP,ScimFilterPolicy.rejectAllInstance()))
                .serviceProviderConfig(ScimServiceProviderConfig.builder().filterSupported(true).sortSupported(true).patchSupported(true).build())
                .stringMatching((path,definition,operator,left,right) -> ScimStringMatchResult.fromMatched(
                        operator == ScimComparisonOperator.NE ? !left.equals(right) : left.equals(right))).build();
    }
    private static @NonNull JsonObject userDocument() {
        return JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(USER.getSchema().getId()))))
                .put("id","server-id").put("userName","synthetic").build();
    }
    private static @NonNull ScimPatchParseResult parsePatch(@NonNull ScimServiceProvider provider,@NonNull ScimResourceType type,@NonNull String ops) {
        return provider.parsePatchRequestResult(type,bytes("{\"schemas\":[\""+PATCH+"\"],\"Operations\":["+ops+"]}"));
    }
    private static @NonNull ScimAttributeSelection selection(@NonNull ScimServiceProvider provider,@NonNull String query) {
        return assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class,provider.parseAttributeSelectionResult(USER,query)).getAttributeSelection();
    }
    @Test void invM1GrammarPrecedenceAndWireIntegerLexemesStayDistinct() {
        ScimFilter filter=assertInstanceOf(ScimFilterParseResult.Succeeded.class,
                ScimFilter.fromExpressionResult("a eq 1 or b eq 2 and c eq 3")).getFilter();
        ScimFilter.Or or=assertInstanceOf(ScimFilter.Or.class,filter);
        assertEquals(2,or.getOperands().size()); assertInstanceOf(ScimFilter.And.class,or.getOperands().get(1));
        assertInstanceOf(ScimFilterParseResult.Rejected.class,ScimFilter.fromExpressionResult("rows[a eq 1 and child[b eq 2]]"));
        ScimSchema schema=ScimSchema.withId("urn:example:rc3:integer").name("Integer")
                .attributes(List.of(ScimAttributeDefinition.withName("counter").type(ScimAttributeType.INTEGER).build())).build();
        ScimResourceType type=ScimResourceType.withName("Integer").endpoint("/Integers").schema(schema).build();
        ScimServiceProvider provider=ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(type)).build();
        for (String lexical:List.of("1.0","1e0")) assertInstanceOf(ScimResourceParseResult.Rejected.class,
                provider.parseResourceResult(type,bytes("{\"schemas\":[\""+schema.getId()+"\"],\"counter\":"+lexical+"}")));
    }
    @Test void invM2StrictRemoveValueAndLateFailureCannotPublishMembershipChanges() {
        ScimServiceProvider provider=provider();
        ScimResource current=ScimResource.withResourceType(GROUP).document(JsonObject.builder()
                .put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(GROUP.getSchema().getId()))))
                .put("id","group-id").put("displayName","Group").put("members",JsonArray.fromElements(List.of(
                        JsonObject.builder().put("value","one").build()))).build()).build();
        JsonObject before=current.getDocument();
        assertInstanceOf(ScimPatchParseResult.Rejected.class,parsePatch(provider,GROUP,
                "{\"op\":\"remove\",\"path\":\"members\",\"value\":[{\"value\":\"one\"}]}"));
        ScimPatchRequest patch=assertInstanceOf(ScimPatchParseResult.Succeeded.class,parsePatch(provider,GROUP,
                "{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"two\"}]},"
                        +"{\"op\":\"replace\",\"path\":\"id\",\"value\":\"forged\"}")).getPatchRequest();
        assertInstanceOf(ScimPatchApplicationResult.Rejected.class,provider.applyPatchResult(current,patch));
        assertSame(before,current.getDocument()); assertEquals("one",ScimGroup.fromResource(current).getMembers().get(0).findString("value").orElseThrow());
    }
    @Test void invM3ReadOnlyServerIdDoesNotBecomeAnExternalIdentityMapping() {
        ScimServiceProvider provider=provider();
        ScimResource parsed=assertInstanceOf(ScimResourceParseResult.Succeeded.class,provider.parseResourceResult(USER,
                bytes("{\"schemas\":[\""+USER.getSchema().getId()+"\"],\"userName\":\"synthetic\",\"id\":\"forged\",\"externalId\":\"opaque-external\"}"))).getResource();
        assertTrue(parsed.getId().isEmpty()); assertEquals("opaque-external",parsed.getExternalId().orElseThrow());
    }
    @Test void invM4NeverValuesCannotEnterResponsesFiltersOrSorts() {
        ScimServiceProvider provider=provider(); Map<String,JsonValue> fields=new java.util.LinkedHashMap<>(userDocument().getMembers());
        fields.put("password",JsonString.fromValue("private-credential"));
        ScimResource resource=ScimResource.withResourceType(USER).document(JsonObject.fromMembers(fields)).build();
        ScimResponse response=assertInstanceOf(ScimResponseResult.Prepared.class,
                provider.resourceResponseResult(resource,selection(provider,"attributes=password,userName"))).getResponse();
        String wire=new String(response.toHttpBodyWithPersonalData(),StandardCharsets.UTF_8);
        assertFalse(wire.contains("password")); assertFalse(wire.contains("private-credential"));
        assertInstanceOf(ScimFilterParseResult.Rejected.class,provider.parseFilterResult(USER,"password eq \"private-credential\""));
        assertInstanceOf(ScimQueryParseResult.Rejected.class,provider.parseQueryResult(USER,"sortBy=password"));
    }
    @Test void invM5UnknownSchemasAttributesAndCaseDuplicatesReject() {
        ScimServiceProvider provider=provider(); String prefix="{\"schemas\":[\""+USER.getSchema().getId()+"\"],\"userName\":\"synthetic\"";
        for (String suffix:List.of(",\"USERNAME\":\"other\"}",",\"userName\":\"other\"}",",\"admin\":true}"))
            assertInstanceOf(ScimResourceParseResult.Rejected.class,provider.parseResourceResult(USER,bytes(prefix+suffix)));
        assertInstanceOf(ScimResourceParseResult.Rejected.class,provider.parseResourceResult(USER,
                bytes("{\"schemas\":[\"urn:example:foreign\"],\"userName\":\"synthetic\"}")));
    }
    @Test void invM6PagingCapsAndUnsupportedSortHaveExplicitOutcomes() {
        ScimServiceProvider provider=provider();
        ScimQuery zero=assertInstanceOf(ScimQueryParseResult.Succeeded.class,provider.parseQueryResult(USER,"startIndex=0&count=-1")).getQuery();
        assertEquals(1L,zero.getStartIndex().orElseThrow()); assertEquals(0,zero.getCount());
        assertEquals(1000,assertInstanceOf(ScimQueryParseResult.Succeeded.class,provider.parseQueryResult(USER,"count=99999")).getQuery().getCount());
        ScimServiceProvider noSort=ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(USER)).filterPolicies(Map.of(USER,policy()))
                .serviceProviderConfig(ScimServiceProviderConfig.builder().filterSupported(true).build()).build();
        assertInstanceOf(ScimQueryParseResult.Rejected.class,noSort.parseQueryResult(USER,"sortBy=userName"));
    }
    @Test void invM7ErrorsAreFixedStringStatusWithoutRequestData() {
        ScimServiceProvider provider=provider();
        ScimError error=assertInstanceOf(ScimResourceParseResult.Rejected.class,provider.parseResourceResult(USER,bytes("private-request-data"))).getError();
        String wire=new String(provider.errorResponse(error).toHttpBodyWithPersonalData(),StandardCharsets.UTF_8);
        assertTrue(wire.contains("\"status\":\"400\"")); assertTrue(wire.contains("\"detail\":"));
        assertFalse(wire.contains("private-request-data")); assertFalse(error.toString().contains("private-request-data"));
    }
    @Test void invM8AsciiNamesAndCollidingValuesRemainUnambiguous() {
        ScimServiceProvider provider=provider();
        assertInstanceOf(ScimFilterParseResult.Succeeded.class,provider.parseFilterResult(USER,"USERNAME EQ \"synthetic\""));
        assertInstanceOf(ScimFilterParseResult.Rejected.class,provider.parseFilterResult(USER,"userNáme eq \"synthetic\""));
        assertEquals(JsonString.fromValue("Aa").hashCode(),JsonString.fromValue("BB").hashCode());
        Map<String,JsonValue> fields=new java.util.LinkedHashMap<>(userDocument().getMembers());
        fields.put("emails",JsonArray.fromElements(List.of(JsonObject.builder().put("value","Aa").build(),JsonObject.builder().put("value","BB").build())));
        ScimResource current=ScimResource.withResourceType(USER).document(JsonObject.fromMembers(fields)).build();
        ScimPatchRequest patch=assertInstanceOf(ScimPatchParseResult.Succeeded.class,parsePatch(provider,USER,
                "{\"op\":\"remove\",\"path\":\"emails[value eq \\\"BB\\\"]\"}")).getPatchRequest();
        ScimResource changed=assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,provider.applyPatchResult(current,patch)).getPatchResult().getResource();
        assertEquals(List.of(JsonObject.builder().put("value","Aa").build()),ScimUser.fromResource(changed).getEmails());
    }
    @Test void invM9DuplicatePrimaryValuesRejectBeforePublishingACandidate() {
        assertInstanceOf(ScimResourceParseResult.Rejected.class,provider().parseResourceResult(USER,
                bytes("{\"schemas\":[\""+USER.getSchema().getId()+"\"],\"userName\":\"synthetic\",\"emails\":[{\"value\":\"a\",\"primary\":true},{\"value\":\"b\",\"primary\":true}]}")));
    }
    @Test void invM10DefaultDenySameElementAndFormDecodingCannotBroadenAQuery() {
        ScimServiceProvider provider=provider();
        assertInstanceOf(ScimQueryParseResult.Rejected.class,provider.parseQueryResult(USER,"filter=userName+co+%22synthetic%22"));
        ScimQuery query=assertInstanceOf(ScimQueryParseResult.Succeeded.class,provider.parseQueryResult(USER,"filter=userName+eq+%22a%2Bb%22")).getQuery();
        ScimFilter.Comparison comparison=assertInstanceOf(ScimFilter.Comparison.class,query.getFilter().orElseThrow());
        assertEquals("a+b",assertInstanceOf(ScimFilterValue.StringValue.class,comparison.getValue()).getValue());
        Map<String,JsonValue> fields=new java.util.LinkedHashMap<>(userDocument().getMembers());
        fields.put("emails",JsonArray.fromElements(List.of(JsonObject.builder().put("type","work").put("value","work@example.invalid").build(),
                JsonObject.builder().put("type","home").put("value","home@example.invalid").build())));
        ScimResource current=ScimResource.withResourceType(USER).document(JsonObject.fromMembers(fields)).build();
        ScimFilter sameElement=assertInstanceOf(ScimFilterParseResult.Succeeded.class,provider.parseFilterResult(USER,
                "emails[type eq \"work\" and value eq \"home@example.invalid\"]")).getFilter();
        assertFalse(assertInstanceOf(ScimFilterEvaluationResult.Succeeded.class,
                ScimFilterEvaluator.fromServiceProvider(provider).evaluateResult(current,sameElement)).isMatched());
    }
}
