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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.revetsec.json.*;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Assertions;
import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

/** Bounded PatchOp wire grammar and atomic ordered mutation properties, using authored synthetic values. */
@ThreadSafe
public final class ScimM11FuzzTests {
    private static final @NonNull String PATCH="urn:ietf:params:scim:api:messages:2.0:PatchOp";
    private static final @NonNull ScimResourceType USER=ScimResourceType.userInstance();
    private static final @NonNull ScimResourceType GROUP=ScimResourceType.groupInstance();
    private static final @NonNull ScimResourceType COUNTER=ScimResourceType.withName("Counter").endpoint("/Counters")
            .schema(ScimSchema.withId("urn:example:scim:fuzz:counter").name("Counter")
                    .attributes(List.of(ScimAttributeDefinition.withName("counter").type(ScimAttributeType.INTEGER).build())).build()).build();
    private static final @NonNull ScimLimits LIMITS=ScimLimits.builder().maximumBodyBytes(16384).maximumJsonNodes(1000)
            .maximumPatchOperations(16).maximumWorkUnits(100000).maximumResponseBytes(8192).build();
    private static final @NonNull List<@NonNull ScimServiceProvider> PROVIDERS=List.of(
            provider(ScimCompatibility.strictInstance()),provider(ScimCompatibility.microsoftEntraIdInstance()),provider(ScimCompatibility.oktaInstance()));
    private static final @NonNull List<@NonNull ScimResource> RESOURCES=List.of(resource(USER),resource(GROUP),resource(COUNTER));
    private static @NonNull ScimServiceProvider provider(@NonNull ScimCompatibility compatibility) {
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.test/scim/"))
                .resourceTypes(List.of(USER,GROUP,COUNTER)).limits(LIMITS).compatibility(compatibility)
                .stringMatching((path,definition,operator,value,literal)->ScimStringMatchResult.fromMatched(switch(operator) {
                    case EQ -> value.equals(literal); case NE -> !value.equals(literal);
                    case CO -> value.contains(literal); case SW -> value.startsWith(literal); case EW -> value.endsWith(literal);
                    case GT -> value.compareTo(literal)>0; case GE -> value.compareTo(literal)>=0;
                    case LT -> value.compareTo(literal)<0; case LE -> value.compareTo(literal)<=0;
                })).serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).build()).build();
    }
    private static @NonNull ScimResource resource(@NonNull ScimResourceType type) {
        JsonObject.Builder object=JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(type.getSchema().getId()))))
                .put("id","existing-id").put("meta",JsonObject.builder().put("version","W/\"fuzz\"")
                        .put("lastModified","2026-10-13T00:00:00Z").build());
        if(type==USER) object.put("userName","existing").put("emails",JsonArray.fromElements(List.of(
                JsonObject.builder().put("value","one@example.test").put("type","work").put("primary",true).build())));
        else if(type==GROUP) object.put("displayName","existing").put("members",JsonArray.fromElements(List.of(
                JsonObject.builder().put("value","one").put("display","retained-metadata").build())));
        else object.put("counter",0L);
        return ScimResource.withResourceType(type).document(object.build()).build();
    }
    /** Arbitrary materialized PATCH bodies have fixed outcomes and never mutate the current snapshot. */
    @FuzzTest(maxDuration="5m")
    public void rawPatchBodiesStayBoundedAndAtomic(byte @NonNull [] input) {
        for(ScimServiceProvider provider:PROVIDERS) for(ScimResource current:RESOURCES) {
            JsonObject before=current.getDocument();
            ScimPatchParseResult parsed=provider.parsePatchRequestResult(current.getResourceType(),List.of("application/scim+json"),input);
            if(parsed instanceof ScimPatchParseResult.Rejected rejected) fixed(rejected.getError());
            else {
                ScimPatchRequest request=((ScimPatchParseResult.Succeeded)parsed).getPatchRequest();
                Assertions.assertTrue(!request.getOperations().isEmpty() && request.getOperations().size()<=16);
                Assertions.assertSame(current.getResourceType(),request.getResourceType());
                Assertions.assertFalse(request.toString().contains("retained-metadata"));
                ScimPatchApplicationResult result=provider.applyPatchResult(current,request);
                if(result instanceof ScimPatchApplicationResult.Rejected rejected) fixed(rejected.getError());
                else {
                    ScimPatchResult applied=((ScimPatchApplicationResult.Succeeded)result).getPatchResult();
                    Assertions.assertEquals("existing-id",applied.getResource().getId().orElseThrow());
                    Assertions.assertEquals("W/\"fuzz\"",applied.getResource().getVersion().orElseThrow());
                    Assertions.assertEquals(current.getLastModified(),applied.getResource().getLastModified());
                    Assertions.assertEquals(request.getRequestedAttributePaths(),applied.getRequestedAttributePaths());
                    Assertions.assertEquals(request.getSuppliedAttributePaths(),applied.getSuppliedAttributePaths());
                }
                ScimMembershipPatchResult reduced=provider.reduceMembershipPatchResult(request);
                if(reduced instanceof ScimMembershipPatchResult.Rejected rejected) fixed(rejected.getError());
            }
            Assertions.assertSame(before,current.getDocument());
        }
    }
    /** A forbidden final operation cannot publish an earlier Group membership update. */
    @FuzzTest(maxDuration="5m")
    public void lateFailurePreservesMembershipAndMetadata(@NonNull FuzzedDataProvider data) {
        String member="fixture-"+java.util.HexFormat.of().formatHex(data.consumeBytes(16));
        JsonObject addition=JsonObject.builder().put("op","add").put("path","members")
                .put("value",JsonArray.fromElements(List.of(JsonObject.builder().put("value",member).build()))).build();
        JsonObject failure=JsonObject.builder().put("op","replace").put("path","id").put("value","forbidden-id").build();
        byte[] body=JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(PATCH))))
                .put("Operations",JsonArray.fromElements(List.of(addition,failure))).build().toJson().getBytes(StandardCharsets.UTF_8);
        ScimResource current=RESOURCES.get(1); JsonObject before=current.getDocument();
        for(ScimServiceProvider provider:PROVIDERS) {
            ScimPatchRequest request=Assertions.assertInstanceOf(ScimPatchParseResult.Succeeded.class,provider.parsePatchRequestResult(GROUP,body)).getPatchRequest();
            ScimError error=Assertions.assertInstanceOf(ScimPatchApplicationResult.Rejected.class,provider.applyPatchResult(current,request)).getError();
            Assertions.assertSame(ScimError.mutabilityInstance(),error);
            Assertions.assertSame(before,current.getDocument());
            Assertions.assertEquals("retained-metadata",((JsonArray)current.getDocument().getMembers().get("members")).getElements().stream()
                    .map(value->(JsonObject)value).findFirst().orElseThrow().findString("display").orElseThrow());
        }
    }
    private static void fixed(@NonNull ScimError error) {
        Assertions.assertNotSame(ScimError.internalErrorInstance(),error);
        Assertions.assertTrue(Set.of(400,403,413,415).contains(error.getStatusCode()));
        Assertions.assertFalse(error.toString().contains("retained-metadata"));
        Assertions.assertTrue(error.getDetail().length()<128);
    }
}
