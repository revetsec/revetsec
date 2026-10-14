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
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

/** Independent public contracts selected from RC-3 mutation survivors. */
class ScimRc3MutationTests {
    private static final @NonNull ScimResourceType USER=ScimResourceType.userInstance();
    private static final @NonNull ScimResourceType GROUP=ScimResourceType.groupInstance();
    private static final @NonNull String USER_URI=ScimSchema.userInstance().getId();
    private static final @NonNull ScimStringMatching MATCH=(path,definition,operator,left,right) -> ScimStringMatchResult.fromMatched(left.equals(right));
    private static byte @NonNull [] bytes(@NonNull String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static @NonNull ScimServiceProvider provider() {
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(USER)).serviceProviderConfig(ScimServiceProviderConfig.builder()
                .patchSupported(true).filterSupported(true).build())
                .filterPolicies(Map.of(USER,ScimFilterPolicy.builder().allowedPresence(Set.of("userName"))
                        .allowedComparisons(Map.of("userName",Set.of(ScimComparisonOperator.EQ))).build()))
                .stringMatching(MATCH).build();
    }
    private static @NonNull ScimAttributePath path(@NonNull String text) {
        return assertInstanceOf(ScimAttributePathParseResult.Succeeded.class,ScimAttributePath.fromExpressionResult(text)).getAttributePath();
    }
    private static @NonNull ScimFilter parsed(@NonNull String text) {
        return assertInstanceOf(ScimFilterParseResult.Succeeded.class,ScimFilter.fromExpressionResult(text)).getFilter();
    }
    @SuppressWarnings("ReferenceEquality") // The two local fixtures deliberately use builtin singleton identities.
    private static @NonNull JsonObject document(@NonNull ScimResourceType type,@NonNull String id) {
        return JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(type.getSchema().getId()))))
                .put("id",id).put(type==USER?"userName":"displayName","name")
                .put("meta",JsonObject.builder().put("version","W/\"v\"").build()).build();
    }
    private static @NonNull ScimResource resource(@NonNull ScimResourceType type) {
        return ScimResource.withResourceType(type).document(document(type,"id")).build();
    }

    @Test void everyFacadeEntryRejectsAnUnregisteredTrustedTypeBeforeProcessing() {
        ScimServiceProvider p=provider();ScimResource foreign=resource(GROUP);byte[] body=bytes("{}");
        assertThrows(IllegalArgumentException.class,()->p.parseFilterResult(GROUP,"displayName pr"));
        assertThrows(IllegalArgumentException.class,()->p.parseQueryResult(GROUP,""));
        assertThrows(IllegalArgumentException.class,()->p.parseAttributeSelectionResult(GROUP,""));
        assertThrows(IllegalArgumentException.class,()->p.parseSearchRequestResult(GROUP,body));
        assertThrows(IllegalArgumentException.class,()->p.parseSearchRequestResult(GROUP,List.of("application/scim+json"),body));
        assertThrows(IllegalArgumentException.class,()->p.parseResourceResult(GROUP,body));
        assertThrows(IllegalArgumentException.class,()->p.parseResourceResult(GROUP,List.of("application/scim+json"),body));
        assertThrows(IllegalArgumentException.class,()->p.parseReplacementResult(GROUP,foreign,body));
        assertThrows(IllegalArgumentException.class,()->p.parseReplacementResult(GROUP,foreign,List.of("application/scim+json"),body));
        assertThrows(IllegalArgumentException.class,()->p.parsePatchRequestResult(GROUP,body));
        assertThrows(IllegalArgumentException.class,()->p.parsePatchRequestResult(GROUP,List.of("application/scim+json"),body));
        assertThrows(IllegalArgumentException.class,()->p.checkIfMatchResult(List.of(),foreign));
        assertThrows(IllegalArgumentException.class,()->p.checkIfNoneMatchResult(List.of(),foreign));
        assertThrows(IllegalArgumentException.class,()->p.notModifiedResponseResult(foreign));
        assertThrows(IllegalArgumentException.class,()->p.resourceLocationFor(GROUP,"id"));
        ScimServiceProvider other=ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(GROUP)).serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).build()).stringMatching(MATCH).build();
        ScimPatchRequest patch=assertInstanceOf(ScimPatchParseResult.Succeeded.class,other.parsePatchRequestResult(GROUP,
                bytes("{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\"Operations\":[{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"other\"}]}"))).getPatchRequest();
        assertThrows(IllegalArgumentException.class,()->p.applyPatchResult(foreign,patch));
        ScimAttributeSelection selection=assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class,p.parseAttributeSelectionResult(USER,"")).getAttributeSelection();
        assertThrows(IllegalArgumentException.class,()->p.resourceResponseResult(foreign,selection));
    }

    @Test void resourceLocationEscapesOpaqueSegmentsAndKeepsAlphabetBoundaries() {
        String id="AZaz09-._~!#$%&'()*+,/:;=?@[\\]^`{|}é😀";
        assertEquals("https://example.invalid/scim/Users/AZaz09-%2E_~%21%23%24%25%26%27%28%29%2A%2B%2C%2F%3A%3B%3D%3F%40%5B%5C%5D%5E%60%7B%7C%7D%C3%A9%F0%9F%98%80",
                provider().resourceLocationFor(USER,id).toASCIIString());
    }

    @Test void rawAndPercentEncodedUnicodeQueriesRetainTheExactDecodedLiteral() {
        ScimServiceProvider p=provider();
        for (String literal:List.of("\u007f","\u0080","\u07ff","\u0800","\uffff","\ud800\udc00","\udbff\udfff","é😀")) {
            ScimQuery q=assertInstanceOf(ScimQueryParseResult.Succeeded.class,p.parseQueryResult(USER,"filter=userName+eq+%22"+literal+"%22")).getQuery();
            assertEquals(literal,assertInstanceOf(ScimFilterValue.StringValue.class,assertInstanceOf(ScimFilter.Comparison.class,q.getFilter().orElseThrow()).getValue()).getValue());
        }
        for (String escaped:List.of("%7f","%C2%80","%DF%BF","%E0%A0%80","%EF%BF%BF","%F0%90%80%80","%F4%8F%BF%BF"))
            assertInstanceOf(ScimQueryParseResult.Succeeded.class,p.parseQueryResult(USER,"filter=userName+eq+%22"+escaped+"%22"));
    }

    @Test void hexadecimalEscapesAndSurrogateBoundaryPairsRoundTripTheirExactValues() {
        for (String hex:List.of("000A","000F","00AF","00af","FFFF","ffff","D800\\uDC00","DBFF\\uDFFF")) {
            String expression="a eq \"\\u"+hex+"\"";
            ScimFilter filter=parsed(expression);String decoded=assertInstanceOf(ScimFilterValue.StringValue.class,assertInstanceOf(ScimFilter.Comparison.class,filter).getValue()).getValue();
            String expected=switch(hex){case "000A"->"\n";case "000F"->"\u000f";case "00AF","00af"->"\u00af";case "FFFF","ffff"->"\uffff";case "D800\\uDC00"->"\ud800\udc00";default->"\udbff\udfff";};
            assertEquals(expected,decoded);assertEquals(filter,parsed(filter.toScimString()));
        }
        for(String hex:List.of("D800","DBFF","DC00","DFFF","D800\\uDBFF","DBFF\\uE000","000G","00g0","FFF/"))
            assertInstanceOf(ScimFilterParseResult.Rejected.class,ScimFilter.fromExpressionResult("a eq \"\\u"+hex+"\""));
        for(char unit:new char[]{0,1,15,31,32,127,128}) {
            ScimFilter filter=parsed("a eq \"\\u"+String.format("%04x",(int)unit)+"\"");
            assertEquals(String.valueOf(unit),assertInstanceOf(ScimFilterValue.StringValue.class,assertInstanceOf(ScimFilter.Comparison.class,parsed(filter.toScimString())).getValue()).getValue());
        }
        for(String name:List.of("a","z","A","Z","azAZ09_-","A.a","z.Z")) assertInstanceOf(ScimFilterParseResult.Succeeded.class,ScimFilter.fromExpressionResult(name+" pr"));
        for(String name:List.of("`","{","@","[","0","a.`","a.{","a.@","a.[")) assertInstanceOf(ScimFilterParseResult.Rejected.class,ScimFilter.fromExpressionResult(name+" pr"));
    }

    @Test void allBase64AlphabetAndTailBitsUseAnIndependentJdkEncodingOracle() {
        String urn="urn:example:rc3:binary";
        ScimResourceType type=ScimResourceType.withName("Binary").endpoint("/Binary")
                .schema(ScimSchema.withId(urn).name("Binary").attributes(List.of(ScimAttributeDefinition.withName("binary").type(ScimAttributeType.BINARY).build())).build()).build();
        ScimServiceProvider p=ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/")).resourceTypes(List.of(type)).build();
        for(int value=0;value<256;value++) for(int size:List.of(1,2,3)) {
            byte[] raw=new byte[size];for(int at=0;at<size;at++)raw[at]=(byte)(value+at);
            String encoded=Base64.getEncoder().encodeToString(raw);
            for(String variant:List.of(encoded,encoded.replace("=",""))) assertInstanceOf(ScimResourceParseResult.Succeeded.class,p.parseResourceResult(type,
                    bytes("{\"schemas\":[\""+urn+"\"],\"binary\":\""+variant+"\"}")),variant);
        }
        for(String invalid:List.of("AB","AB==","AAF","AAF=","AA+","AA/","AA9","AAz","A","=","AAA==","AA===","AA-_","AA@A","AA[A","AA`A","AA{A","AA:A"))
            assertInstanceOf(ScimResourceParseResult.Rejected.class,p.parseResourceResult(type,bytes("{\"schemas\":[\""+urn+"\"],\"binary\":\""+invalid+"\"}")),invalid);
    }

    @Test void assignedMetaInstantsPreserveFractionsOffsetsAndBceEpoch() {
        for(String text:List.of("2026-10-14T12:00:00.1+00:30","2026-10-14T12:00:00.123456-01:15","2026-10-14T12:00:00.123456789Z")) {
            JsonObject document=JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(USER_URI))))
                    .put("userName","a").put("meta",JsonObject.builder().put("created",text).put("lastModified",text).build()).build();
            ScimResource value=ScimResource.withResourceType(USER).document(document).build();
            assertEquals(java.time.OffsetDateTime.parse(text).toInstant(),value.getCreated().orElseThrow());
            assertEquals(java.time.OffsetDateTime.parse(text).toInstant(),value.getLastModified().orElseThrow());
        }
        JsonObject document=JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(USER_URI))))
                .put("userName","a").put("meta",JsonObject.builder().put("created","-0001-01-01T00:00:00Z").build()).build();
        assertEquals(Instant.parse("0000-01-01T00:00:00Z"),ScimResource.withResourceType(USER).document(document).build().getCreated().orElseThrow());
    }

    @Test void errorBodiesRetainFixedScimTypeAndStringStatus() {
        ScimServiceProvider p=provider();
        ScimError[] errors={ScimError.invalidFilterInstance(),ScimError.tooManyInstance(),ScimError.mutabilityInstance(),ScimError.invalidValueInstance(),ScimError.invalidSyntaxInstance(),ScimError.invalidPathInstance(),ScimError.noTargetInstance()};
        for(ScimError error:errors) {
            String body=new String(p.errorResponse(error).toHttpBodyWithPersonalData(),StandardCharsets.UTF_8);
            assertTrue(body.contains("\"status\":\""+error.getStatusCode()+"\""));
            assertTrue(body.contains("\"scimType\":\""+error.getErrorType().orElseThrow().getValue()+"\""));
            assertTrue(body.contains("\"detail\":\""+error.getDetail()+"\""));
        }
    }

    @Test void allOpaqueTagBoundaryOctetsAreAcceptedAndForbiddenOctetsReject() {
        ScimServiceProvider p=provider();
        for(char ch:new char[]{0x21,0x23,0x7e,0x80,0xff}) {
            String tag="\""+ch+"\"";JsonObject d=JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(USER_URI))))
                    .put("id","i").put("userName","a").put("meta",JsonObject.builder().put("version",tag).build()).build();
            ScimResource value=ScimResource.withResourceType(USER).document(d).build();
            assertInstanceOf(ScimIfMatchResult.Satisfied.class,p.checkIfMatchResult(List.of(tag),value));
            assertInstanceOf(ScimIfNoneMatchResult.NotModified.class,p.checkIfNoneMatchResult(List.of(tag),value));
        }
        for(char ch:new char[]{0x1f,0x22,0x7f,0x100}) {
            String tag="\""+ch+"\"";assertInstanceOf(ScimIfMatchResult.Rejected.class,p.checkIfMatchResult(List.of(tag),resource(USER)));
        }
        for(String suffix:List.of("0","9","a","z","A","Z")) assertInstanceOf(ScimContentTypeResult.Accepted.class,p.validateContentTypeResult(List.of("application/scim+json;charset="+suffix)));
    }

    @Test void cursorAlphabetEndpointsAndMoreResultsFlagAgreeWithWireFraming() {
        ScimServiceProvider p=ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/")).resourceTypes(List.of(USER))
                .serviceProviderConfig(ScimServiceProviderConfig.builder().pagination(ScimPaginationConfig.builder().cursorSupported(true)
                        .cursorTimeout(Duration.ofMinutes(1)).build()).build()).build();
        ScimQuery q=assertInstanceOf(ScimQueryParseResult.Succeeded.class,p.parseQueryResult(USER,"cursor=AZaz09-_.~&count=1")).getQuery();
        assertEquals("AZaz09-_.~",q.getCursor().orElseThrow());
        ScimListPage page=ScimListPage.withQuery(q).resources(List.of(resource(USER))).nextCursor("AZaz09-_.~").moreResultsAvailable(true).build();
        assertTrue(page.isMoreResultsAvailable());
        assertTrue(new String(assertInstanceOf(ScimResponseResult.Prepared.class,p.listResponseResult(page)).getResponse().toHttpBodyWithPersonalData(),StandardCharsets.UTF_8).contains("\"nextCursor\":\"AZaz09-_.~\""));
        for(String invalid:List.of("@","[","`","{","/",":","é")) assertInstanceOf(ScimQueryParseResult.Rejected.class,p.parseQueryResult(USER,"cursor="+invalid));
    }

    @Test void retainedFilterPolicyMapMatchesTheConfiguredRules() {
        ScimServiceProvider p=provider();assertEquals(Set.of(USER),p.getFilterPolicies().keySet());
        assertEquals(Set.of(ScimComparisonOperator.EQ),java.util.Objects.requireNonNull(p.getFilterPolicies().get(USER)).getAllowedComparisons().get("userName"));
        assertThrows(UnsupportedOperationException.class,()->p.getFilterPolicies().clear());
    }
    @Test void boundedPercentScansAndConditionalCommaScansCompleteWithinADeadline() {
        assertTimeoutPreemptively(Duration.ofSeconds(2),()-> {
            assertInstanceOf(ScimQueryParseResult.Succeeded.class,provider().parseQueryResult(USER,"ignored=%20%7f"));
            assertInstanceOf(ScimAttributePathParseResult.Succeeded.class,ScimAttributePath.fromExpressionResult("https://example.invalid/%20:x"));
            assertSame(ScimError.preconditionFailedInstance(),assertInstanceOf(ScimIfMatchResult.Rejected.class,
                    provider().checkIfMatchResult(List.of("\"a\", \"b\""),resource(USER))).getError());
            assertInstanceOf(ScimContentTypeResult.Accepted.class,provider().validateContentTypeResult(List.of("application/scim+json;charset=\"UTF-8\"")));
        });
    }

    @Test void boundedLargeAndExponentResponsePreparationCompletesWithinADeadline() {
        assertTimeoutPreemptively(Duration.ofSeconds(2),()-> {
            String urn="urn:example:rc3:output";
            ScimResourceType type=ScimResourceType.withName("Output").endpoint("/Outputs").schema(ScimSchema.withId(urn).name("Output")
                    .attributes(List.of(ScimAttributeDefinition.withName("number").type(ScimAttributeType.DECIMAL).build(),ScimAttributeDefinition.withName("text").build())).build()).build();
            ScimServiceProvider p=ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/")).resourceTypes(List.of(type)).build();
            ScimAttributeSelection selection=assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class,p.parseAttributeSelectionResult(type,"")).getAttributeSelection();
            for(String numeric:List.of("1E+12","1.23E+100","0.1","1.1","0.0000001")) {
                JsonObject d=JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(urn)))).put("id","i")
                        .put("number",JsonNumber.fromValue(new java.math.BigDecimal(numeric))).put("text","x".repeat(1024)).build();
                String body=new String(assertInstanceOf(ScimResponseResult.Prepared.class,p.resourceResponseResult(ScimResource.withResourceType(type).document(d).build(),selection)).getResponse().toHttpBodyWithPersonalData(),StandardCharsets.UTF_8);
                assertTrue(body.contains("\"number\":"+new java.math.BigDecimal(numeric)));assertTrue(body.contains("x".repeat(1024)));
            }
        });
    }

    @Test void independentFlattenedShapeCountsEnforceNodeAndDepthCaps() {
        String mixed="not((a pr or b pr) and (c pr or d pr) and (e pr or f pr))";
        assertInstanceOf(ScimFilterParseResult.Succeeded.class,ScimFilter.fromExpressionResult(mixed,ScimFilterLimits.builder().maximumNodes(11).maximumDepth(4).build()));
        assertInstanceOf(ScimFilterParseResult.Rejected.class,ScimFilter.fromExpressionResult(mixed,ScimFilterLimits.builder().maximumNodes(10).maximumDepth(4).build()));
        assertInstanceOf(ScimFilterParseResult.Rejected.class,ScimFilter.fromExpressionResult("not("+mixed+")",ScimFilterLimits.builder().maximumNodes(12).maximumDepth(4).build()));
        String flat="(a pr and b pr) and (c pr and d pr) and (e pr and f pr) and (g pr and h pr)";
        ScimFilter.And tree=assertInstanceOf(ScimFilter.And.class,assertInstanceOf(ScimFilterParseResult.Succeeded.class,
                ScimFilter.fromExpressionResult(flat,ScimFilterLimits.builder().maximumNodes(9).maximumDepth(4).build())).getFilter());
        assertEquals(8,tree.getOperands().size());
        assertInstanceOf(ScimFilterParseResult.Rejected.class,ScimFilter.fromExpressionResult(flat,ScimFilterLimits.builder().maximumNodes(8).maximumDepth(4).build()));
        assertInstanceOf(ScimFilterParseResult.Succeeded.class,ScimFilter.fromExpressionResult("rows["+mixed+"]",ScimFilterLimits.builder().maximumNodes(12).maximumDepth(5).build()));
        assertInstanceOf(ScimFilterParseResult.Rejected.class,ScimFilter.fromExpressionResult("rows["+mixed+"]",ScimFilterLimits.builder().maximumNodes(11).maximumDepth(5).build()));
    }

    @Test void receivingExpressionGuardRejectsBeforeSerializationBeyondEveryIndependentBound() {
        ScimFilterLimits size=ScimFilterLimits.builder().maximumExpressionCharacters(256).maximumLiteralCharacters(256).build();
        String exact="text eq \""+"a".repeat(246)+"\"";
        assertEquals(256,exact.length());
        assertEquals(exact,ScimFilterEvaluation.expression(parsed(exact),size,new ScimWork(1000000)));
        assertNull(ScimFilterEvaluation.expression(parsed("text eq \""+"a".repeat(247)+"\""),size,new ScimWork(1000000)));
        ScimFilterLimits literal=ScimFilterLimits.builder().maximumLiteralCharacters(2).build();
        assertEquals("text eq \"ab\"",ScimFilterEvaluation.expression(parsed("text eq \"ab\""),literal,new ScimWork(1000000)));
        assertNull(ScimFilterEvaluation.expression(parsed("text eq \"abc\""),literal,new ScimWork(1000000)));
        ScimFilterLimits number=ScimFilterLimits.builder().maximumNumberCharacters(4).build();
        assertEquals("number eq 1234",ScimFilterEvaluation.expression(parsed("number eq 1234"),number,new ScimWork(1000000)));
        assertNull(ScimFilterEvaluation.expression(parsed("number eq 12345"),number,new ScimWork(1000000)));
        ScimFilterLimits nodes=ScimFilterLimits.builder().maximumNodes(8).build();
        assertNotNull(ScimFilterEvaluation.expression(parsed(String.join(" or ",java.util.Collections.nCopies(7,"text pr"))),nodes,new ScimWork(1000000)));
        assertNull(ScimFilterEvaluation.expression(parsed(String.join(" or ",java.util.Collections.nCopies(8,"text pr"))),nodes,new ScimWork(1000000)));
        ScimFilterLimits depth=ScimFilterLimits.builder().maximumDepth(4).build();
        assertNotNull(ScimFilterEvaluation.expression(parsed("not(not(not(text pr)))"),depth,new ScimWork(1000000)));
        assertNull(ScimFilterEvaluation.expression(parsed("not(not(not(not(text pr))))"),depth,new ScimWork(1000000)));
        assertNotNull(ScimFilterEvaluation.expression(parsed("rows[not(not(value pr))]"),depth,new ScimWork(1000000)));
        assertNull(ScimFilterEvaluation.expression(parsed("rows[not(not(not(value pr)))]"),depth,new ScimWork(1000000)));
        String operands="longertitle pr or "+String.join(" or ",java.util.Collections.nCopies(22,"text pr"));
        assertEquals(256,operands.length());assertNotNull(ScimFilterEvaluation.expression(parsed(operands),size,new ScimWork(1000000)));
        assertNull(ScimFilterEvaluation.expression(parsed(String.join(" or ",java.util.Collections.nCopies(24,"text pr"))),size,new ScimWork(1000000)));
    }

    @Test void expressionGuardNeverPublishesAStringAfterItsOriginalWorkBudgetFails() {
        for(String text:List.of("text pr","rows.value eq \"a\"","urn:example:extra:label eq \"a\"","rows[value eq \"a\"]","text eq \"a\" or text eq \"b\"")) {
            ScimFilter tree=parsed(text);boolean accepted=false;
            for(int remaining=0;remaining<150;remaining++) {
                ScimWork work=new ScimWork(remaining);String expression=ScimFilterEvaluation.expression(tree,ScimFilterLimits.defaultInstance(),work);
                if(work.wasExceeded())assertNull(expression,text+" remaining "+remaining);
                if(expression!=null){accepted=true;assertEquals(text,expression);}
            }
            assertTrue(accepted);
        }
    }

    @Test void requestReturnedComplexProjectionPreservesAlwaysChildrenWithoutLeakingSiblings() {
        List<ScimAttributeDefinition> children=List.of(ScimAttributeDefinition.withName("value").build(),
                ScimAttributeDefinition.withName("always").returned(ScimReturned.ALWAYS).build(),
                ScimAttributeDefinition.withName("requested").returned(ScimReturned.REQUEST).build(),
                ScimAttributeDefinition.withName("secret").returned(ScimReturned.NEVER).build());
        String urn="urn:example:rc3:projection";
        ScimResourceType type=ScimResourceType.withName("Projection").endpoint("/Projections").schema(ScimSchema.withId(urn).name("Projection")
                .attributes(List.of(ScimAttributeDefinition.withName("contact").type(ScimAttributeType.COMPLEX).returned(ScimReturned.REQUEST).subAttributes(children).build(),
                        ScimAttributeDefinition.withName("contacts").type(ScimAttributeType.COMPLEX).multiValued(true).returned(ScimReturned.REQUEST).subAttributes(children).build())).build()).build();
        ScimServiceProvider p=ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/")).resourceTypes(List.of(type)).build();
        JsonObject child=JsonObject.builder().put("value","VISIBLE_DEFAULT").put("always","VISIBLE_ALWAYS").put("requested","VISIBLE_REQUESTED").put("secret","PRIVATE_SECRET").build();
        ScimResource current=ScimResource.withResourceType(type).document(JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(urn))))
                .put("id","i").put("contact",child).put("contacts",JsonArray.fromElements(List.of(child,JsonObject.emptyInstance()))).build()).build();
        for(String query:List.of("","excludedAttributes=contact,contacts")) {
            ScimAttributeSelection selected=assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class,p.parseAttributeSelectionResult(type,query)).getAttributeSelection();
            String body=new String(assertInstanceOf(ScimResponseResult.Prepared.class,p.resourceResponseResult(current,selected)).getResponse().toHttpBodyWithPersonalData(),StandardCharsets.UTF_8);
            assertTrue(body.contains("VISIBLE_ALWAYS"));assertFalse(body.contains("VISIBLE_DEFAULT"));assertFalse(body.contains("VISIBLE_REQUESTED"));assertFalse(body.contains("PRIVATE_SECRET"));
        }
        ScimAttributeSelection selected=assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class,p.parseAttributeSelectionResult(type,"attributes=contact.requested,contacts.requested")).getAttributeSelection();
        String selectedBody=new String(assertInstanceOf(ScimResponseResult.Prepared.class,p.resourceResponseResult(current,selected)).getResponse().toHttpBodyWithPersonalData(),StandardCharsets.UTF_8);
        assertTrue(selectedBody.contains("VISIBLE_REQUESTED"));assertFalse(selectedBody.contains("VISIBLE_DEFAULT"));assertFalse(selectedBody.contains("PRIVATE_SECRET"));
        ScimAttributeSelection all=assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class,p.parseAttributeSelectionResult(type,"")).getAttributeSelection();
        String write=new String(assertInstanceOf(ScimResponseResult.Prepared.class,p.replacementResponseResult(current,Set.of(path("contact.requested"),path("contacts.requested")),all)).getResponse().toHttpBodyWithPersonalData(),StandardCharsets.UTF_8);
        assertTrue(write.contains("VISIBLE_DEFAULT"));assertTrue(write.contains("VISIBLE_REQUESTED"));assertFalse(write.contains("PRIVATE_SECRET"));
    }

    @Test void discoveryPreservesApplicationMetadataAndTypedReferenceDeclarations() {
        String urn="urn:example:rc3:discovery";
        ScimSchema schema=ScimSchema.withId(urn).name("DiscoveryProbe").description("SCHEMA_DESCRIPTION")
                .attributes(List.of(ScimAttributeDefinition.withName("reference").type(ScimAttributeType.REFERENCE).referenceTypes(Set.of("User","external")).build())).build();
        ScimResourceType type=ScimResourceType.withName("DiscoveryProbe").id("DISCOVERY_ID").description("TYPE_DESCRIPTION").endpoint("/DiscoveryProbes").schema(schema).build();
        ScimServiceProvider p=ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/")).resourceTypes(List.of(type)).build();
        String schemaBody=new String(assertInstanceOf(ScimResponseResult.Prepared.class,p.schemaResponseResult(urn,"")).getResponse().toHttpBodyWithPersonalData(),StandardCharsets.UTF_8);
        assertTrue(schemaBody.contains("SCHEMA_DESCRIPTION"));assertTrue(schemaBody.contains("\"referenceTypes\""));assertTrue(schemaBody.contains("\"external\""));
        String typeBody=new String(assertInstanceOf(ScimResponseResult.Prepared.class,p.resourceTypeResponseResult("DiscoveryProbe","")).getResponse().toHttpBodyWithPersonalData(),StandardCharsets.UTF_8);
        assertTrue(typeBody.contains("\"id\":\"DISCOVERY_ID\""));assertTrue(typeBody.contains("TYPE_DESCRIPTION"));
    }

    @Test void exactProviderConfigurationBoundariesPreserveAllAcceptedEntries() {
        String prefix="https://example.invalid/";
        URI maximum=URI.create(prefix+"a".repeat(2047-prefix.length())+"/");
        assertEquals(2048,maximum.toASCIIString().length());
        assertEquals(maximum,ScimServiceProvider.builder().baseUri(maximum).resourceTypes(List.of(USER)).build().getBaseUri());
        assertThrows(IllegalArgumentException.class,()->ScimServiceProvider.builder().baseUri(URI.create(prefix+"a".repeat(2048-prefix.length()))).resourceTypes(List.of(USER)).build());
        assertEquals("a".repeat(128),ScimAttributeDefinition.withName("a".repeat(128)).build().getName());
        List<ScimResourceType> types=new ArrayList<>();Map<ScimResourceType,ScimFilterPolicy> policies=new java.util.LinkedHashMap<>();
        for(int index=0;index<32;index++) {
            ScimResourceType type=ScimResourceType.withName("Type"+index).endpoint("/Types"+index).schema(ScimSchema.withId("urn:example:rc3:config:"+index).name("Type"+index).build()).build();
            types.add(type);policies.put(type,ScimFilterPolicy.rejectAllInstance());
        }
        ScimServiceProvider p=ScimServiceProvider.builder().baseUri(URI.create(prefix)).resourceTypes(types).filterPolicies(policies).build();
        assertEquals(32,p.getResourceTypes().size());assertEquals(32,p.getFilterPolicies().size());
        List<ScimResourceType> tooMany=new ArrayList<>(types);tooMany.add(USER);
        assertThrows(IllegalArgumentException.class,()->ScimServiceProvider.builder().resourceTypes(tooMany));
        Map<ScimResourceType,ScimFilterPolicy> tooManyPolicies=new java.util.LinkedHashMap<>(policies);tooManyPolicies.put(USER,ScimFilterPolicy.rejectAllInstance());
        assertThrows(IllegalArgumentException.class,()->ScimServiceProvider.builder().filterPolicies(tooManyPolicies));
        List<ScimSchemaExtension> extensions=new ArrayList<>();
        for(int index=0;index<16;index++) extensions.add(ScimSchemaExtension.fromSchema(ScimSchema.withId("urn:example:rc3:extra:"+index).name("Extra"+index).build(),false));
        ScimResourceType type=ScimResourceType.withName("Extended").endpoint("/Extended").schema(ScimSchema.withId("urn:example:rc3:extended").name("Extended").build()).schemaExtensions(extensions).build();
        assertEquals(16,type.getSchemaExtensions().size());
        assertInstanceOf(ScimResourceParseResult.Succeeded.class,ScimServiceProvider.builder().baseUri(URI.create(prefix)).resourceTypes(List.of(type)).build()
                .parseResourceResult(type,bytes("{\"schemas\":[\"urn:example:rc3:extended\"]}")));
    }

    @Test void aggregateSchemaAndPolicyDefinitionsCannotEvadeTheConfigurationCaps() {
        List<ScimAttributeDefinition> children=new ArrayList<>();
        for(int index=0;index<1023;index++)children.add(ScimAttributeDefinition.withName("a"+index).build());
        ScimAttributeDefinition exact=ScimAttributeDefinition.withName("complex").type(ScimAttributeType.COMPLEX).subAttributes(children).build();
        assertEquals(1023,exact.getSubAttributes().size());
        children.add(ScimAttributeDefinition.withName("a1023").build());
        assertThrows(IllegalArgumentException.class,()->ScimAttributeDefinition.withName("complex").type(ScimAttributeType.COMPLEX).subAttributes(children).build());
        Map<String,Set<ScimComparisonOperator>> comparisons=new java.util.LinkedHashMap<>();Set<String> presence=new java.util.LinkedHashSet<>();
        for(int index=0;index<2048;index++){comparisons.put("a"+index,Set.of(ScimComparisonOperator.EQ));presence.add("b"+index);}
        assertEquals(2048,ScimFilterPolicy.builder().allowedComparisons(comparisons).allowedPresence(presence).build().getAllowedComparisons().size());
        presence.add("extra");assertThrows(IllegalArgumentException.class,()->ScimFilterPolicy.builder().allowedComparisons(comparisons).allowedPresence(presence).build());
        Map<String,Set<ScimComparisonOperator>> smaller=new java.util.LinkedHashMap<>(comparisons);smaller.remove("a2047");
        ScimFilterPolicy shared=ScimFilterPolicy.builder().allowedComparisons(smaller).build();
        assertEquals(2,ScimFilterPolicy.builder().allowedValuePaths(Map.of("x",shared,"y",shared)).build().getAllowedValuePaths().size());
        ScimFilterPolicy oversized=ScimFilterPolicy.builder().allowedComparisons(comparisons).build();
        assertThrows(IllegalArgumentException.class,()->ScimFilterPolicy.builder().allowedValuePaths(Map.of("x",oversized,"y",oversized)).build());
    }

    @Test void registeredUriGrammarRetainsEscapesPortsIpFutureAndPreciseFailurePositions() {
        for(String schema:List.of("https://exa%AFmple.invalid/%AF?key=%af#%Fa","https://[vF.x]:9009/schema","https://u%AF@[vA.x]:0/profile","urn:a:b?query#fragment")) {
            String expression=schema+":a";
            assertEquals(schema,path(expression).getSchemaId().orElseThrow());
            assertEquals(expression+" pr",parsed(expression+" pr").toScimString());
        }
        Map<String,Integer> failures=Map.ofEntries(
                Map.entry("a.",2),Map.entry("urn:x:a.",8),Map.entry("urn:x:a!",7),Map.entry("a:0",1),Map.entry("urn::",5),
                Map.entry("https://[bad]/:a",8),Map.entry("https://example.invalid:a:path",24),Map.entry("https://exa%mple.invalid/:a",11),
                Map.entry("https://example.invalid/%gg:a",24),Map.entry("https://example.invalid/%2:a",24),
                Map.entry("https://u%G0@host:a",9),Map.entry("https://u@v@host:a",11));
        for(Map.Entry<String,Integer> entry:failures.entrySet()) {
            ScimError error=assertInstanceOf(ScimAttributePathParseResult.Rejected.class,ScimAttributePath.fromExpressionResult(entry.getKey())).getError();
            assertEquals(entry.getValue(),error.getExpressionOffset().orElseThrow(),entry.getKey());
            assertSame(ScimErrorType.INVALID_PATH,error.getErrorType().orElseThrow());
        }
    }

    @Test void emptyCustomSchemasStillRejectInvalidDeclarationsAndIgnoredDuplicateObjects() {
        String urn="urn:example:rc3:empty";
        ScimResourceType type=ScimResourceType.withName("Empty").endpoint("/Empty").schema(ScimSchema.withId(urn).name("Empty").build()).build();
        ScimServiceProvider p=ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/")).resourceTypes(List.of(type)).build();
        for(String schemas:List.of("[]","[7]","[\"relative\"]","[\""+urn+"\",\""+urn.toUpperCase(java.util.Locale.ROOT)+"\"]","[\"urn:example:unregistered\"]"))
            assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimResourceParseResult.Rejected.class,p.parseResourceResult(type,bytes("{\"schemas\":"+schemas+"}"))).getError());
        ScimServiceProvider ignored=ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/")).resourceTypes(List.of(type))
                .compatibility(ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.IGNORE_UNKNOWN_ATTRIBUTES)).build()).build();
        assertSame(ScimError.invalidSyntaxInstance(),assertInstanceOf(ScimResourceParseResult.Rejected.class,ignored.parseResourceResult(type,
                bytes("{\"schemas\":[\""+urn+"\"],\"ignored\":{\"a\":1,\"A\":2}}"))).getError());
        assertInstanceOf(ScimResourceParseResult.Succeeded.class,ignored.parseResourceResult(type,bytes("{\"schemas\":[\""+urn+"\"],\"ignored\":{\"a\":1}}")));
    }

    @Test void fullLengthMalformedExpressionRetainsTheHardCapFailureOffset() {
        ScimFilterLimits limits=ScimFilterLimits.builder().maximumExpressionCharacters(65536).build();
        ScimError error=assertInstanceOf(ScimFilterParseResult.Rejected.class,ScimFilter.fromExpressionResult(" ".repeat(65536),limits)).getError();
        assertEquals(65536,error.getExpressionOffset().orElseThrow());
        assertEquals(ScimError.invalidFilterInstance().getDetail(),error.getDetail());
    }

    @Test void validZeroHashKeysRemainUsableAcrossPathsAndCompositeFilters() {
        // Fixed legal ASCII fixtures reach zero-hash cases without asserting a hash formula.
        ScimAttributePath key=path("aoffckzd");
        Map<ScimAttributePath,String> paths=new java.util.HashMap<>();paths.put(key,"found");
        assertEquals("found",paths.get(path("aoffckzd")));
        for(String text:List.of("aoffckzd pr","not(aoffckzd pr)","aoffckzd eq \"value\"",
                "aoffckzd[value pr]","aoffckzd pr and aoffckyd pr","aoffckzd pr or aoffckyd pr")) {
            Map<ScimFilter,String> filters=new java.util.HashMap<>();filters.put(parsed(text),"found");
            assertEquals("found",filters.get(parsed(text)),text);
        }
    }

}
