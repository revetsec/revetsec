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

import static org.junit.jupiter.api.Assertions.*;

import com.revetsec.json.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Public operation boundaries, provenance, response policy and strategy faults. */
class ScimM11ProviderTests {
    private static final @NonNull ScimResourceType USER = ScimResourceType.userInstance();
    private static final @NonNull ScimResourceType GROUP = ScimResourceType.groupInstance();
    private static final @NonNull String PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
    private static final @NonNull ScimStringMatching EXACT = (path, definition, operator, value, literal) ->
            ScimStringMatchResult.fromMatched(operator == ScimComparisonOperator.EQ ? value.equals(literal)
                    : operator == ScimComparisonOperator.NE ? !value.equals(literal) : false);

    private static @NonNull ScimServiceProvider provider() { return provider(EXACT, null); }
    private static @NonNull ScimServiceProvider provider(@NonNull ScimStringMatching matching, @Nullable ScimObserver observer) {
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.test/scim/"))
                .resourceTypes(List.of(USER, GROUP)).stringMatching(matching).observer(observer)
                .serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).build()).build();
    }
    private static byte @NonNull [] bytes(@NonNull String text) { return text.getBytes(StandardCharsets.UTF_8); }
    private static @NonNull ScimPatchRequest patch(@NonNull ScimServiceProvider p, @NonNull ScimResourceType type, @NonNull String operations) {
        return assertInstanceOf(ScimPatchParseResult.Succeeded.class, p.parsePatchRequestResult(type,
                bytes("{\"schemas\":[\"" + PATCH + "\"],\"Operations\":[" + operations + "]}"))).getPatchRequest();
    }
    private static @NonNull ScimResource resource(@NonNull ScimResourceType type) {
        JsonObject.Builder body = JsonObject.builder().put("schemas", JsonArray.fromElements(List.of(JsonString.fromValue(type.getSchema().getId()))))
                .put("id", "fixture-id").put("displayName", "before")
                .put("meta", JsonObject.builder().put("version", "W/\"v1\"")
                        .put("lastModified", "2026-10-13T00:00:00Z").build());
        if (type.getSchema().getId().equals(USER.getSchema().getId())) body.put("userName", "fixture").put("emails", JsonArray.fromElements(List.of(
                JsonObject.builder().put("value", "one@example.test").put("type", "work").build())));
        else body.put("members", JsonArray.fromElements(List.of(JsonObject.builder().put("value", "one").put("display", "kept-metadata").build())));
        return ScimResource.withResourceType(type).document(body.build()).build();
    }
    private static @NonNull ScimAttributeSelection selection(@NonNull ScimServiceProvider p, @NonNull ScimResourceType type, @NonNull String raw) {
        return assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class,p.parseAttributeSelectionResult(type,raw)).getAttributeSelection();
    }
    private static @NonNull ScimResponse prepared(@NonNull ScimResponseResult result) {
        return assertInstanceOf(ScimResponseResult.Prepared.class,result).getResponse();
    }

    @Test void patchCapabilityAndMediaTypeAreEnforcedWithoutCollectionFilterPermission() {
        ScimServiceProvider p=provider();
        assertFalse(p.getServiceProviderConfig().isFilterSupported());
        ScimPatchRequest request=patch(p,USER,"{\"op\":\"replace\",\"path\":\"emails[type eq \\\"work\\\"].value\",\"value\":\"two@example.test\"}");
        assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,p.applyPatchResult(resource(USER),request));
        ScimServiceProvider disabled=ScimServiceProvider.builder().baseUri(URI.create("https://example.test/scim/"))
                .resourceTypes(List.of(USER,GROUP)).build();
        assertSame(ScimError.forbiddenInstance(),assertInstanceOf(ScimPatchParseResult.Rejected.class,
                disabled.parsePatchRequestResult(USER,bytes("{}"))).getError());
        assertSame(ScimError.forbiddenInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,
                disabled.applyPatchResult(resource(USER),request)).getError());
        assertSame(ScimError.forbiddenInstance(),assertInstanceOf(ScimMembershipPatchResult.Rejected.class,
                disabled.reduceMembershipPatchResult(request)).getError());
        for(List<String> headers:List.of(List.of("text/plain"),List.of("application/scim+json","application/json")))
            assertSame(ScimError.unsupportedMediaTypeInstance(),assertInstanceOf(ScimPatchParseResult.Rejected.class,
                    p.parsePatchRequestResult(USER,headers,bytes("{}"))).getError());
        assertInstanceOf(ScimPatchParseResult.Succeeded.class,p.parsePatchRequestResult(USER,List.of("application/json; charset=\"UTF-8\""),
                bytes("{\"schemas\":[\""+PATCH+"\"],\"Operations\":[{\"op\":\"replace\",\"path\":\"active\",\"value\":true}]}")));
    }

    @Test void parsedPatchCannotCrossRegistrationOrCompatibilityButBaseCopiesRetainIt() {
        ScimServiceProvider p=provider();
        ScimPatchRequest request=patch(p,USER,"{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"after\"}");
        ScimResource current=resource(USER);
        assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,p.copy().baseUri(URI.create("https://other.test/scim/")).finish().applyPatchResult(current,request));
        ScimServiceProvider foreign=provider();
        assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,
                foreign.applyPatchResult(current,request)).getError());
        assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimMembershipPatchResult.Rejected.class,
                foreign.reduceMembershipPatchResult(request)).getError());
        ScimServiceProvider relaxed=p.copy().compatibility(ScimCompatibility.microsoftEntraIdInstance()).finish();
        assertInstanceOf(ScimPatchApplicationResult.Rejected.class,relaxed.applyPatchResult(current,request));
        ScimPatchRequest rebound=patch(relaxed,USER,"{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"after\"}");
        assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,relaxed.applyPatchResult(current,rebound));
        assertInstanceOf(ScimPatchApplicationResult.Rejected.class,p.applyPatchResult(resource(GROUP),request));
        ScimResource parsed=assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,relaxed.applyPatchResult(current,rebound)).getPatchResult().getResource();
        assertInstanceOf(ScimResponseResult.Rejected.class,p.patchResponseResult(parsed,Set.of(),selection(p,USER,"")));
    }

    @Test void patchResponseUsesTypeDefaultAndEitherExplicitProjectionForcesBody() {
        ScimServiceProvider p=provider();
        for(ScimResourceType type:List.of(USER,GROUP)) {
            ScimResource current=resource(type);
            ScimResponse defaultResponse=prepared(p.patchResponseResult(current,Set.of(),selection(p,type,"")));
            assertEquals(type.getSchema().getId().equals(GROUP.getSchema().getId())?204:200,defaultResponse.getStatusCode());
            assertEquals(List.of("W/\"v1\""),defaultResponse.getHeaders().get("ETag"));
            assertEquals(List.of("private, no-store"),defaultResponse.getHeaders().get("Cache-Control"));
            if(type.getSchema().getId().equals(GROUP.getSchema().getId())) {
                assertEquals(0,defaultResponse.toHttpBodyWithPersonalData().length);
                assertFalse(defaultResponse.getHeaders().containsKey("Content-Type"));
            }
            for(String raw:List.of("attributes=displayName","excludedAttributes=displayName")) {
                ScimResponse response=prepared(p.patchResponseResult(current,Set.of(),selection(p,type,raw)));
                assertEquals(200,response.getStatusCode());
                assertTrue(response.toHttpBodyWithPersonalData().length>0);
            }
        }
        ScimAttributePath invalid=assertInstanceOf(ScimAttributePathParseResult.Succeeded.class,
                ScimAttributePath.fromExpressionResult("unknown")).getAttributePath();
        assertInstanceOf(ScimResponseResult.Rejected.class,p.patchResponseResult(resource(GROUP),Set.of(invalid),selection(p,GROUP,"")));
        assertInstanceOf(ScimResponseResult.Rejected.class,p.patchResponseResult(resource(GROUP),Set.of(),selection(provider(),GROUP,"")));
    }

    @Test void noOpRetainsAuthoritativeMetadataAndRequestedAuthorizationPaths() {
        ScimServiceProvider p=provider();ScimResource current=resource(USER);
        ScimPatchRequest request=patch(p,USER,"{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"before\"}");
        ScimPatchResult result=assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,p.applyPatchResult(current,request)).getPatchResult();
        assertFalse(result.isModified());assertTrue(result.getModifiedAttributePaths().isEmpty());
        assertEquals(current.getDocument(),result.getResource().getDocument());
        assertEquals(current.getVersion(),result.getResource().getVersion());
        assertEquals(Set.of("displayName"),result.getRequestedAttributePaths().stream().map(ScimAttributePath::toScimString).collect(java.util.stream.Collectors.toSet()));
    }

    @Test void strategyUnsupportedRejectsAndUnexpectedFaultUsesOneFailureLifecycle() {
        RecordingObserver observer=new RecordingObserver();
        ScimServiceProvider unsupported=provider((path,definition,operator,value,literal)->ScimStringMatchResult.unsupportedInstance(),observer);
        ScimResource current=resource(USER);
        ScimPatchRequest request=patch(unsupported,USER,"{\"op\":\"replace\",\"path\":\"emails[type eq \\\"work\\\"].value\",\"value\":\"changed\"}");
        observer.events.clear();
        assertInstanceOf(ScimPatchApplicationResult.Rejected.class,unsupported.applyPatchResult(current,request));
        assertEquals(List.of("will:PATCH_APPLY","did:PATCH_APPLY:REJECTED"),observer.events);
        assertEquals("before",current.getDocument().findString("displayName").orElseThrow());
        ScimServiceProvider broken=provider((path,definition,operator,value,literal)->{throw new IllegalStateException("fixture-sensitive-exception");},observer);
        request=patch(broken,USER,"{\"op\":\"replace\",\"path\":\"emails[type eq \\\"work\\\"].value\",\"value\":\"changed\"}");
        observer.events.clear();
        assertSame(ScimError.internalErrorInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,broken.applyPatchResult(current,request)).getError());
        assertEquals(List.of("will:PATCH_APPLY","fail:PATCH_APPLY"),observer.events);
    }

    @Test void successfulOperationsAndFallbackHaveOneObserverTerminalEvent() {
        RecordingObserver observer=new RecordingObserver();ScimServiceProvider p=provider(EXACT,observer);
        ScimPatchRequest request=patch(p,GROUP,"{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"two\"}]}");
        assertEquals(List.of("will:PATCH_PARSE","did:PATCH_PARSE:SUCCEEDED"),observer.events);
        observer.events.clear();
        assertInstanceOf(ScimMembershipPatchResult.Reduced.class,p.reduceMembershipPatchResult(request));
        assertEquals(List.of("will:MEMBERSHIP_REDUCE","did:MEMBERSHIP_REDUCE:SUCCEEDED"),observer.events);
        observer.events.clear();
        assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,p.applyPatchResult(resource(GROUP),request));
        assertEquals(List.of("will:PATCH_APPLY","did:PATCH_APPLY:SUCCEEDED"),observer.events);
        request=patch(p,GROUP,"{\"op\":\"remove\",\"path\":\"members[display eq \\\"kept-metadata\\\"]\"}");
        observer.events.clear();
        assertInstanceOf(ScimMembershipPatchResult.RequiresFullEvaluation.class,p.reduceMembershipPatchResult(request));
        assertEquals(List.of("will:MEMBERSHIP_REDUCE","did:MEMBERSHIP_REDUCE:REQUIRES_FULL_EVALUATION"),observer.events);
        observer.events.clear();
        prepared(p.patchResponseResult(resource(GROUP),Set.of(),selection(p,GROUP,"")));
        assertEquals(List.of("will:ATTRIBUTE_SELECTION","did:ATTRIBUTE_SELECTION:SUCCEEDED","will:RESPONSE_PREPARE","did:RESPONSE_PREPARE:PREPARED"),observer.events);
    }

    @Test void transportErrorsAndQuotaErrorsAreFixedBeforePublishingAnyRequest() {
        ScimServiceProvider p=provider();
        for(byte[] body:List.of(bytes("{broken"),new byte[0],bytes("[]"))) {
            assertInstanceOf(ScimPatchParseResult.Rejected.class,p.parsePatchRequestResult(USER,body));
            assertInstanceOf(ScimPatchParseResult.Rejected.class,p.parsePatchRequestResult(USER,List.of("application/scim+json"),body));
        }
        ScimServiceProvider bounded=ScimServiceProvider.builder().baseUri(URI.create("https://example.test/scim/"))
                .resourceTypes(List.of(USER,GROUP)).stringMatching(EXACT)
                .limits(ScimLimits.builder().maximumWorkUnits(10_000).maximumBodyBytes(16_384).build())
                .serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).build()).build();
        assertSame(ScimError.requestTooLargeInstance(),assertInstanceOf(ScimPatchParseResult.Rejected.class,
                bounded.parsePatchRequestResult(USER,List.of("x".repeat(6_000)),bytes("{}"))).getError());
        assertSame(ScimError.requestTooLargeInstance(),assertInstanceOf(ScimPatchParseResult.Rejected.class,
                bounded.parsePatchRequestResult(USER,new byte[16_385])).getError());
        assertSame(ScimError.requestTooLargeInstance(),assertInstanceOf(ScimPatchParseResult.Rejected.class,
                bounded.parsePatchRequestResult(USER,List.of("application/scim+json"),new byte[16_385])).getError());
    }

    @Test void patchCarriersAndFixedErrorsDoNotRevealLiteralOrResourceValuesInDiagnostics() {
        ScimServiceProvider p=provider();String secret="fixture-private-literal-319";
        ScimPatchRequest request=patch(p,USER,"{\"op\":\"replace\",\"path\":\"password\",\"value\":\""+secret+"\"}");
        ScimPatchApplicationResult outcome=p.applyPatchResult(resource(USER),request);
        ScimPatchResult result=assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,outcome).getPatchResult();
        assertFalse(request.toString().contains(secret));assertFalse(request.getOperations().get(0).toString().contains(secret));
        assertFalse(outcome.toString().contains(secret));assertFalse(result.toString().contains(secret));
        assertEquals(secret,result.getResource().getDocument().findString("password").orElseThrow());
        ScimResponse rendered=prepared(p.patchResponseResult(result.getResource(),result.getSuppliedAttributePaths(),selection(p,USER,"")));
        assertFalse(new String(rendered.toHttpBodyWithPersonalData(),StandardCharsets.UTF_8).contains(secret));
        ScimPatchApplicationResult rejected=p.applyPatchResult(resource(GROUP),request);
        assertFalse(rejected.toString().contains(secret));
        ScimPatchRequest metadata=patch(p,GROUP,"{\"op\":\"remove\",\"path\":\"members[display eq \\\""+secret+"\\\"]\"}");
        ScimMembershipPatchResult fallback=p.reduceMembershipPatchResult(metadata);
        assertFalse(assertInstanceOf(ScimMembershipPatchResult.RequiresFullEvaluation.class,fallback).toString().contains(secret));
    }

    private static final class RecordingObserver implements ScimObserver {
        private final @NonNull List<@NonNull String> events=new ArrayList<>();
        @Override public void willProcess(ScimObserver.@NonNull Operation op) {events.add("will:"+op);}
        @Override public void didProcess(ScimObserver.@NonNull Operation op,ScimObserver.@NonNull Outcome outcome) {events.add("did:"+op+":"+outcome);}
        @Override public void didFailToProcess(ScimObserver.@NonNull Operation op) {events.add("fail:"+op);}
    }
}
