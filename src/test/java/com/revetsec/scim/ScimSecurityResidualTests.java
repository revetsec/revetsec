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
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

final class ScimSecurityResidualTests {
    private static final String PATCH="urn:ietf:params:scim:api:messages:2.0:PatchOp";
    private static final ScimStringMatching EXACT=(path,definition,op,left,right) -> ScimStringMatchResult.fromMatched(left.equals(right));
    private static @NonNull ScimServiceProvider provider(@NonNull ScimResourceType type,@NonNull ScimCompatibility compatibility) {
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
            .resourceTypes(List.of(type)).compatibility(compatibility).stringMatching(EXACT)
            .serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).build()).build();
    }
    private static @NonNull ScimResource resource(@NonNull ScimResourceType type,@NonNull JsonObject values) {
        var fields=new LinkedHashMap<String,JsonValue>(values.getMembers());
        var schemas=new ArrayList<JsonValue>();schemas.add(JsonString.fromValue(type.getSchema().getId()));
        for(var extension:type.getSchemaExtensions()) if(values.getMembers().containsKey(extension.getSchema().getId())) schemas.add(JsonString.fromValue(extension.getSchema().getId()));
        fields.put("schemas",JsonArray.fromElements(schemas));
        return ScimResource.withResourceType(type).document(JsonObject.fromMembers(fields)).build();
    }
    private static @NonNull ScimPatchParseResult parse(@NonNull ScimServiceProvider provider,@NonNull ScimResourceType type,
            @NonNull String kind,@Nullable String path,@NonNull JsonValue value) {
        var op=JsonObject.builder().put("op",kind).put("value",value);if(path!=null)op.put("path",path);
        var body=JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(PATCH))))
            .put("Operations",JsonArray.fromElements(List.of(op.build()))).build().toJson().getBytes(StandardCharsets.UTF_8);
        return provider.parsePatchRequestResult(type,body);
    }
    private static @NonNull ScimPatchRequest request(@NonNull ScimPatchParseResult parsed) {
        return assertInstanceOf(ScimPatchParseResult.Succeeded.class,parsed).getPatchRequest();
    }
    private static @NonNull ScimPatchResult applied(@NonNull ScimServiceProvider provider,@NonNull ScimResource old,@NonNull ScimPatchRequest request) {
        return assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,provider.applyPatchResult(old,request)).getPatchResult();
    }
    private static @NonNull JsonArray member(@NonNull String id,@NonNull JsonValue display) {
        return JsonArray.fromElements(List.of(JsonObject.builder().put("value",id).put("display",display).build()));
    }
    private static @NonNull ScimResource group() {
        return resource(ScimResourceType.groupInstance(),JsonObject.builder().put("displayName","group")
            .put("members",JsonArray.fromElements(List.of(JsonObject.builder().put("value","a").put("type","User").put("display","Saved").build()))).build());
    }
    @TestFactory @NonNull List<@NonNull DynamicTest> oktaMemberObjectDisplayIsIgnoredWithoutWritingServerMetadata() {
        var tests=new ArrayList<DynamicTest>();for(String op:List.of("add","replace"))for(boolean existing:List.of(false,true))
            tests.add(DynamicTest.dynamicTest(op+"/existing="+existing,()->{
                var type=ScimResourceType.groupInstance();var p=provider(type,ScimCompatibility.oktaInstance());var old=group();
                var req=request(parse(p,type,op,"members",member(existing?"a":"b",JsonString.fromValue("Supplied"))));
                var result=applied(p,old,req);var output=assertInstanceOf(JsonArray.class,result.getResource().getDocument().getMembers().get("members"));
                var target=output.getElements().stream().map(JsonObject.class::cast).filter(v->v.find("value").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow().equals(existing?"a":"b")).findFirst().orElseThrow();
                assertEquals(existing?JsonString.fromValue("Saved"):null,target.getMembers().get("display"));
                assertTrue(req.getSuppliedAttributePaths().stream().anyMatch(v->v.toScimString().equals("members.display")));
                assertFalse(result.getModifiedAttributePaths().stream().anyMatch(v->v.toScimString().equals("members.display"))&&existing);
                assertEquals("Saved",assertInstanceOf(JsonString.class,assertInstanceOf(JsonObject.class,assertInstanceOf(JsonArray.class,old.getDocument().getMembers().get("members")).getElements().get(0)).getMembers().get("display")).getValue());
            }));return tests;
    }
    @Test void otherPresetsAndDirectDisplayWritesKeepTheirMutabilityRules() {
        var type=ScimResourceType.groupInstance();var old=group();for(var compatibility:List.of(ScimCompatibility.strictInstance(),ScimCompatibility.microsoftEntraIdInstance())) {
            var p=provider(type,compatibility);var req=request(parse(p,type,"add","members",member("a",JsonString.fromValue("Supplied"))));
            assertSame(ScimError.mutabilityInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,p.applyPatchResult(old,req)).getError());
        }
        var p=provider(type,ScimCompatibility.oktaInstance());var req=request(parse(p,type,"replace","members[value eq \"a\"].display",JsonString.fromValue("Supplied")));
        assertSame(ScimError.mutabilityInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,p.applyPatchResult(old,req)).getError());
    }
    @Test void ignoredDisplayCannotSuppressImmutableOrUnknownPrivilegeFields() {
        var type=ScimResourceType.groupInstance();var p=provider(type,ScimCompatibility.oktaInstance());var old=group();
        var value=JsonArray.fromElements(List.of(JsonObject.builder().put("value","a").put("display","Supplied").put("type","Group").build()));
        assertSame(ScimError.mutabilityInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,p.applyPatchResult(old,request(parse(p,type,"add","members",value)))).getError());
        var invalid=JsonArray.fromElements(List.of(JsonObject.builder().put("value","a").put("display",17L).build()));
        assertInstanceOf(ScimPatchParseResult.Rejected.class,parse(p,type,"add","members",invalid));
        var privilege=JsonArray.fromElements(List.of(JsonObject.builder().put("value","a").put("admin",true).build()));
        assertInstanceOf(ScimPatchParseResult.Rejected.class,parse(p,type,"add","members",privilege));
    }
    private static @NonNull ScimResourceType secretType(boolean writeOnly,boolean nested) {
        var hidden=ScimAttributeDefinition.withName("secret").returned(ScimReturned.NEVER)
            .mutability(writeOnly?ScimMutability.WRITE_ONLY:ScimMutability.READ_WRITE).build();
        ScimAttributeDefinition data=nested?ScimAttributeDefinition.withName("credentials").type(ScimAttributeType.COMPLEX).subAttributes(List.of(hidden)).build():hidden;
        var entry=ScimAttributeDefinition.withName("entries").type(ScimAttributeType.COMPLEX).multiValued(true)
            .subAttributes(List.of(ScimAttributeDefinition.withName("value").build(),data)).build();
        return ScimResourceType.withName("Fixture").endpoint("/Fixtures")
            .schema(ScimSchema.withId("urn:test:hidden").name("Fixture").attributes(List.of(entry)).build()).build();
    }
    private static @NonNull JsonObject entry(@NonNull String id,@NonNull String secret,boolean nested) {
        var b=JsonObject.builder().put("value",id);if(nested)b.put("credentials",JsonObject.builder().put("secret",secret).build());else b.put("secret",secret);return b.build();
    }
    @TestFactory @NonNull List<@NonNull DynamicTest> complexAddIdentityCannotDependOnHiddenChildrenOrTheirComparators() {
        var tests=new ArrayList<DynamicTest>();for(boolean writeOnly:List.of(false,true))for(boolean nested:List.of(false,true))for(boolean correct:List.of(false,true))
            tests.add(DynamicTest.dynamicTest("writeOnly="+writeOnly+"/nested="+nested+"/correct="+correct,()->{
                if(nested){assertThrows(IllegalArgumentException.class,()->secretType(writeOnly,true));return;}
                var type=secretType(writeOnly,false);var calls=new AtomicInteger();var p=ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                    .resourceTypes(List.of(type)).serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).build())
                    .stringMatching((path,def,op,left,right)->{if(path.toScimString().endsWith(".secret"))calls.incrementAndGet();return ScimStringMatchResult.fromMatched(left.equals(right));}).build();
                var old=resource(type,JsonObject.builder().put("entries",JsonArray.fromElements(List.of(entry("public-id","stored-secret",nested)))).build());
                var req=request(parse(p,type,"add","entries",JsonArray.fromElements(List.of(entry("public-id",correct?"stored-secret":"guess",nested)))));
                var result=applied(p,old,req);assertFalse(result.isModified(),"hidden data must not decide ADD identity");assertSame(old,result.getResource());assertEquals(0,calls.get(),"hidden values must not reach application string comparators");
                assertTrue(result.getModifiedAttributePaths().isEmpty());assertEquals(req.getSuppliedAttributePaths(),result.getSuppliedAttributePaths());
            }));return tests;
    }
    @Test void publicDataStillSeparatesValuesAndNewHiddenDataDoesNotBorrowOldMetadata() {
        var type=secretType(true,false);var p=provider(type,ScimCompatibility.strictInstance());
        var old=resource(type,JsonObject.builder().put("entries",JsonArray.fromElements(List.of(entry("first","old",false)))).build());
        var result=applied(p,old,request(parse(p,type,"add","entries",JsonArray.fromElements(List.of(entry("second","new",false))))));
        assertTrue(result.isModified());var rows=assertInstanceOf(JsonArray.class,result.getResource().getDocument().getMembers().get("entries"));assertEquals(2,rows.getElements().size());assertEquals(entry("first","old",false),rows.getElements().get(0));assertEquals(entry("second","new",false),rows.getElements().get(1));
    }
    private static @NonNull ScimResourceType extensions() {
        var a=ScimSchema.withId("urn:test:outer").name("Outer").attributes(List.of(ScimAttributeDefinition.withName("field").build())).build();
        var b=ScimSchema.withId("urn:test:outer:inner").name("Inner").attributes(List.of(ScimAttributeDefinition.withName("field").build())).build();
        return ScimResourceType.withName("Fixture").endpoint("/Fixtures").schema(ScimSchema.withId("urn:test:base").name("Base").build())
            .schemaExtensions(List.of(ScimSchemaExtension.fromSchema(a,false),ScimSchemaExtension.fromSchema(b,false))).build();
    }
    @TestFactory @NonNull List<@NonNull DynamicTest> nestedLocalNameCannotRetargetAPrefixRelatedRegisteredSchema() {
        var tests=new ArrayList<DynamicTest>();for(String op:List.of("add","replace"))for(var compatibility:List.of(ScimCompatibility.strictInstance(),ScimCompatibility.microsoftEntraIdInstance(),ScimCompatibility.oktaInstance()))
            tests.add(DynamicTest.dynamicTest(op+"/"+(compatibility.getFeatures().isEmpty()?"strict":compatibility.equals(ScimCompatibility.microsoftEntraIdInstance())?"entra":"okta"),()->{
                var type=extensions();var p=provider(type,compatibility);var body=JsonObject.builder().put("urn:test:outer",JsonObject.builder().put("inner:field","retargeted").build()).build();
                assertSame(ScimError.invalidPathInstance(),assertInstanceOf(ScimPatchParseResult.Rejected.class,parse(p,type,op,null,body)).getError());
            }));return tests;
    }
    @Test void ordinaryLocalChildrenAndExplicitTopLevelPathCompatibilityStayIndependent() {
        var type=extensions();var p=provider(type,ScimCompatibility.strictInstance());
        var req=request(parse(p,type,"replace",null,JsonObject.builder().put("urn:test:outer",JsonObject.builder().put("field","ordinary").build()).build()));
        assertEquals(Set.of("urn:test:outer:field"),req.getSuppliedAttributePaths().stream().map(ScimAttributePath::toScimString).collect(java.util.stream.Collectors.toSet()));
        var explicit=JsonObject.builder().put("urn:test:outer:inner:field","explicit").build();
        assertInstanceOf(ScimPatchParseResult.Rejected.class,parse(p,type,"replace",null,explicit));
        assertInstanceOf(ScimPatchParseResult.Succeeded.class,parse(provider(type,ScimCompatibility.microsoftEntraIdInstance()),type,"replace",null,explicit));
    }
    @Test void displayRelaxationIsExplicitAndObservedOncePerApplicationCall() {
        var type=ScimResourceType.groupInstance();var used=new ArrayList<ScimCompatibilityFeature>();
        var mode=ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.PATCH_GROUP_MEMBER_DISPLAY_IGNORED)).build();
        var p=ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
            .resourceTypes(List.of(type)).compatibility(mode).stringMatching(EXACT)
            .observer(new ScimObserver(){@Override public void didUseCompatibilityFeature(@NonNull ScimCompatibilityFeature feature){used.add(feature);}})
            .serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).build()).build();
        var values=JsonArray.fromElements(List.of(JsonObject.builder().put("value","a").put("display","first").build(),JsonObject.builder().put("value","b").put("display","second").build()));
        var req=request(parse(p,type,"add","members",values));assertTrue(used.isEmpty());
        var result=applied(p,group(),req);assertTrue(result.isModified());
        assertEquals(List.of(ScimCompatibilityFeature.PATCH_GROUP_MEMBER_DISPLAY_IGNORED),used);
        var strict=p.copy().compatibility(ScimCompatibility.strictInstance()).finish();
        assertSame(ScimError.mutabilityInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,
            strict.applyPatchResult(group(),request(parse(strict,type,"add","members",values)))).getError());
    }
    @Test void customMemberLookalikeCannotUseStandardGroupDisplayRelaxation() {
        var member=ScimAttributeDefinition.withName("members").type(ScimAttributeType.COMPLEX).multiValued(true)
            .subAttributes(List.of(ScimAttributeDefinition.withName("value").build(),ScimAttributeDefinition.withName("display").mutability(ScimMutability.READ_ONLY).build())).build();
        var type=ScimResourceType.withName("Fixture").endpoint("/Fixtures").schema(ScimSchema.withId("urn:test:lookalike").name("Fixture").attributes(List.of(member)).build()).build();
        var p=provider(type,ScimCompatibility.oktaInstance());var old=resource(type,JsonObject.builder().put("members",member("a",JsonString.fromValue("saved"))).build());
        assertSame(ScimError.mutabilityInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,p.applyPatchResult(old,
            request(parse(p,type,"add","members",member("a",JsonString.fromValue("supplied")))))).getError());
    }

    @Test void immutableHiddenEchoCannotTurnDuplicateAddIntoASecretGuessOracle() {
        var hidden=ScimAttributeDefinition.withName("secret").returned(ScimReturned.NEVER).mutability(ScimMutability.IMMUTABLE).build();
        var entries=ScimAttributeDefinition.withName("entries").type(ScimAttributeType.COMPLEX).multiValued(true)
            .subAttributes(List.of(ScimAttributeDefinition.withName("value").build(),hidden)).build();
        var type=ScimResourceType.withName("Fixture").endpoint("/Fixtures").schema(ScimSchema.withId("urn:test:immutable-hidden").name("Fixture").attributes(List.of(entries)).build()).build();
        var p=provider(type,ScimCompatibility.strictInstance());var old=resource(type,JsonObject.builder().put("entries",JsonArray.fromElements(List.of(entry("public-id","stored-secret",false)))).build());
        for(String supplied:List.of("stored-secret","guess")) {
            var req=request(parse(p,type,"add","entries",JsonArray.fromElements(List.of(entry("public-id",supplied,false)))));
            assertSame(ScimError.mutabilityInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,p.applyPatchResult(old,req)).getError());
        }
    }
    @Test void whollyHiddenMultivaluedAddHasNoPublicIdentityAndAlwaysRefuses() {
        for(boolean complex:List.of(false,true)) {
            var b=ScimAttributeDefinition.withName("entries").multiValued(true).returned(ScimReturned.NEVER);
            if(complex)b=b.type(ScimAttributeType.COMPLEX).subAttributes(List.of(ScimAttributeDefinition.withName("value").build()));
            var type=ScimResourceType.withName("Fixture").endpoint("/Fixtures").schema(ScimSchema.withId("urn:test:hidden-array").name("Fixture").attributes(List.of(b.build())).build()).build();
            var p=provider(type,ScimCompatibility.strictInstance());
            for(boolean existing:List.of(false,true)) {
                JsonValue value=complex?JsonObject.builder().put("value","secret").build():JsonString.fromValue("secret");
                var old=resource(type,existing?JsonObject.builder().put("entries",JsonArray.fromElements(List.of(value))).build():JsonObject.emptyInstance());
                var req=request(parse(p,type,"add","entries",JsonArray.fromElements(List.of(value))));
                assertSame(ScimError.mutabilityInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,p.applyPatchResult(old,req)).getError());
            }
        }
    }

}
