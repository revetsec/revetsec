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
import com.revetsec.internal.json.JsonDocument;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseResult;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class ScimM10ResourceTests {
    private static final @NonNull String USER = "urn:ietf:params:scim:schemas:core:2.0:User";
    private static final @NonNull String GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";
    private static final @NonNull String ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
    private static final @NonNull String WIDGET = "https://example.invalid/Widget";
    private static final @NonNull Object CONTEXT = new Object();

    @Test void postCanonicalizesAndIgnoresSubmittedReadOnlyBeforeCheckingIt() {
        ScimResourceParseResult.Succeeded result = accepted(create(ScimResourceType.userInstance(),
                "{\"SCHEMAS\":[\"URN:IETF:PARAMS:SCIM:SCHEMAS:CORE:2.0:USER\"],\"USERNAME\":\"Ada\",\"id\":[],\"meta\":42,\"externalID\":\"client-1\"}"));
        ScimResource resource = result.getResource();
        assertEquals("Ada",resource.getDocument().findString("userName").orElseThrow());
        assertEquals("client-1",resource.getExternalId().orElseThrow());
        assertTrue(resource.getId().isEmpty());
        assertFalse(resource.getDocument().getMembers().containsKey("meta"));
        assertEquals(Set.of(path("userName"),path("externalId")),result.getSuppliedAttributePaths());
        assertSame(CONTEXT,result.getSemanticContext());
        assertSame(CONTEXT,resource.getSemanticContext());
        assertSame(CONTEXT,resource.copy().document(null).finish().getSemanticContext());
        assertSame(CONTEXT,resource.copy().document(resource.getDocument()).finish().getSemanticContext());
        assertNull(ScimResource.withResourceType(ScimResourceType.userInstance()).document(resource.getDocument()).build().getSemanticContext());
        assertThrows(UnsupportedOperationException.class,() -> result.getSuppliedAttributePaths().clear());
    }

    @Test void requiredSchemaUnknownNamesAndPrimaryUniquenessAreStrict() {
        for (String body : new String[]{"{}","{\"schemas\":[\""+USER+"\"]}",
                "{\"schemas\":[\""+USER+"\"],\"userName\":null}",
                "{\"schemas\":[\""+USER+"\"],\"userName\":\"a\",\"unknown\":true}",
                "{\"schemas\":[\""+USER+"\",\""+USER+"\"],\"userName\":\"a\"}",
                "{\"schemas\":[\""+USER+"\"],\"userName\":\"a\",\"emails\":[{\"value\":\"a\",\"primary\":true},{\"value\":\"b\",\"primary\":true}]}",
                "{\"schemas\":[\""+USER+"\"],\"userName\":[],\"active\":\"true\"}"})
            rejected(create(ScimResourceType.userInstance(),body),ScimErrorType.INVALID_VALUE);
        ScimResourceParseResult.Succeeded optionalNull = accepted(create(ScimResourceType.userInstance(),
                "{\"schemas\":[\""+USER+"\"],\"userName\":\"a\",\"displayName\":null,\"emails\":[]}"));
        assertFalse(optionalNull.getResource().getDocument().getMembers().containsKey("displayName"));
        assertEquals(Set.of(path("userName"),path("displayName"),path("emails")),optionalNull.getSuppliedAttributePaths());
    }

    @Test void compatibilityFlagsOnlyChangeTheirNarrowBoundPositions() {
        String missingDeclaration = "{\"schemas\":[\""+USER+"\"],\"userName\":\"a\",\""+ENTERPRISE+"\":{\"department\":\"R&D\"}}";
        rejected(create(ScimResourceType.userInstance(),missingDeclaration),ScimErrorType.INVALID_VALUE);
        ScimCompatibility infer = compatibility(ScimCompatibilityFeature.INFER_MISSING_EXTENSION_SCHEMAS);
        ScimResource inferred = accepted(create(ScimResourceType.userInstance(),missingDeclaration,infer)).getResource();
        assertEquals(Set.of(USER,ENTERPRISE),Set.copyOf(inferred.getDocument().findStringList("schemas").orElseThrow()));
        assertEquals("R&D",ScimEnterpriseUser.fromResource(inferred).getDepartment().orElseThrow());
        String undeclared = "{\"schemas\":[\""+USER+"\",\"urn:unknown\"],\"userName\":\"a\"}";
        rejected(create(ScimResourceType.userInstance(),undeclared),ScimErrorType.INVALID_VALUE);
        assertEquals(java.util.List.of(USER),accepted(create(ScimResourceType.userInstance(),undeclared,
                compatibility(ScimCompatibilityFeature.IGNORE_UNDECLARED_SCHEMA_URIS))).getResource().getDocument().findStringList("schemas").orElseThrow());
        String bool = "{\"schemas\":[\""+USER+"\"],\"userName\":\"true\",\"active\":\"true\"}";
        ScimUser view = ScimUser.fromResource(accepted(create(ScimResourceType.userInstance(),bool,
                compatibility(ScimCompatibilityFeature.BOOLEAN_STRINGS))).getResource());
        assertTrue(view.isActive().orElseThrow()); assertEquals("true",view.getUserName());
        rejected(create(ScimResourceType.userInstance(),bool.replace("\"active\":\"true\"","\"active\":\"TRUE\""),
                compatibility(ScimCompatibilityFeature.BOOLEAN_STRINGS)),ScimErrorType.INVALID_VALUE);
        String scalar = "{\"schemas\":[\""+USER+"\",\""+ENTERPRISE+"\"],\"userName\":\"a\",\""+ENTERPRISE+"\":{\"manager\":\"m-1\"}}";
        rejected(create(ScimResourceType.userInstance(),scalar),ScimErrorType.INVALID_VALUE);
        assertEquals("m-1",ScimEnterpriseUser.fromResource(accepted(create(ScimResourceType.userInstance(),scalar,
                compatibility(ScimCompatibilityFeature.COMPLEX_VALUE_AS_SCALAR))).getResource()).getManager().orElseThrow().findString("value").orElseThrow());
    }

    @Test void integerWireTokensRejectFractionAndExponentAtEveryPosition() {
        ScimResourceType type = widget();
        for (String token : new String[]{"1.0","1e0","1E2","1.0e1","0.0","-0E0"}) {
            rejected(create(type,"{\"schemas\":[\""+WIDGET+"\"],\"title\":\"a\",\"whole\":"+token+"}"),ScimErrorType.INVALID_VALUE);
            rejected(create(type,"{\"schemas\":[\""+WIDGET+"\"],\"title\":\"a\",\"numbers\":["+token+"]}"),ScimErrorType.INVALID_VALUE);
        }
        ScimResource large = accepted(create(type,"{\"schemas\":[\""+WIDGET+"\"],\"title\":\"a\",\"whole\":18446744073709551616}")).getResource();
        assertEquals("18446744073709551616",large.getDocument().find("whole").orElseThrow().toJson());
        JsonObject trusted = JsonObject.builder().put("schemas",com.revetsec.json.JsonArray.fromElements(java.util.List.of(com.revetsec.json.JsonString.fromValue(WIDGET))))
                .put("title","a").put("whole",JsonNumber.fromValue(new BigDecimal("1.000E+20"))).build();
        assertEquals("100000000000000000000",ScimResource.withResourceType(type).document(trusted).build().getDocument().find("whole").orElseThrow().toJson());
    }

    @Test void putPreservesReadOnlyAndProtectedComplexChildrenAndClearsOmittedWritable() {
        ScimResourceType type = widget();
        ScimResource current = trusted(type,"{\"schemas\":[\""+WIDGET+"\"],\"id\":\"server-1\",\"externalId\":\"client\",\"title\":\"old\",\"locked\":\"lock\",\"server\":\"keep\",\"profile\":{\"secret\":\"protected\",\"code\":\"immutable\",\"note\":\"old\"}}");
        String before = current.getDocument().toJson();
        ScimResourceParseResult.Succeeded replacement = accepted(replace(type,current,
                "{\"schemas\":[\""+WIDGET+"\"],\"id\":{},\"title\":\"new\",\"locked\":\"lock\",\"server\":false,\"profile\":{\"note\":\"new\"}}"));
        ScimResource resource = replacement.getResource();
        assertEquals("server-1",resource.getId().orElseThrow()); assertTrue(resource.getExternalId().isEmpty());
        assertEquals("keep",resource.getDocument().findString("server").orElseThrow());
        JsonObject profile = (JsonObject)resource.getDocument().find("profile").orElseThrow();
        assertEquals("protected",profile.findString("secret").orElseThrow());
        assertEquals("immutable",profile.findString("code").orElseThrow());
        assertEquals("new",profile.findString("note").orElseThrow());
        assertEquals(Set.of(path("title"),path("locked"),path("profile.note")),replacement.getSuppliedAttributePaths());
        assertEquals(before,current.getDocument().toJson());
        for (String suffix : new String[]{"",",\"profile\":null",",\"profile\":{\"code\":null}"})
            rejected(replace(type,current,"{\"schemas\":[\""+WIDGET+"\"],\"title\":\"new\",\"locked\":\"lock\""+suffix+"}"),ScimErrorType.MUTABILITY);
        rejected(replace(type,current,"{\"schemas\":[\""+WIDGET+"\"],\"title\":\"new\",\"profile\":{}}"),ScimErrorType.MUTABILITY);
        rejected(replace(type,current,"{\"schemas\":[\""+WIDGET+"\"],\"locked\":\"lock\",\"profile\":{}}"),ScimErrorType.INVALID_VALUE);
        assertEquals(before,current.getDocument().toJson());
    }

    @Test void putGroupMembersMatchExactIdsAndPermitAddRemoveAndReorderWithoutMetadataTransfer() {
        ScimResourceType type = ScimResourceType.groupInstance();
        ScimResource current = trusted(type,"{\"schemas\":[\""+GROUP+"\"],\"displayName\":\"team\",\"members\":[{\"value\":\"one\",\"display\":\"One label\"},{\"value\":\"two\",\"display\":\"Two label\"}]}");
        ScimResource replaced = accepted(replace(type,current,"{\"schemas\":[\""+GROUP+"\"],\"displayName\":\"renamed\",\"members\":[{\"value\":\"two\",\"display\":\"stale echo\"},{\"value\":\"new\",\"display\":\"forged\"},{\"value\":\"one\"}]}" )).getResource();
        java.util.List<JsonObject> members=ScimGroup.fromResource(replaced).getMembers();
        assertEquals("two",members.get(0).findString("value").orElseThrow());
        assertEquals("Two label",members.get(0).findString("display").orElseThrow());
        assertEquals("new",members.get(1).findString("value").orElseThrow());
        assertTrue(members.get(1).findString("display").isEmpty());
        assertEquals("One label",members.get(2).findString("display").orElseThrow());
        assertTrue(ScimGroup.fromResource(accepted(replace(type,current,"{\"schemas\":[\""+GROUP+"\"],\"displayName\":\"team\",\"members\":[]}")).getResource()).getMembers().isEmpty());
        assertTrue(ScimGroup.fromResource(accepted(replace(type,current,"{\"schemas\":[\""+GROUP+"\"],\"displayName\":\"team\"}")).getResource()).getMembers().isEmpty());
        assertEquals(2,ScimGroup.fromResource(current).getMembers().size());
    }

    @Test void duplicateGroupMemberIdsAreRejectedBeforeTheyCanPoisonLaterPut() {
        ScimResourceType type = ScimResourceType.groupInstance();
        String duplicate = "{\"schemas\":[\""+GROUP+"\"],\"displayName\":\"team\",\"members\":[{\"value\":\"one\"},{\"value\":\"one\"}]}";
        rejected(create(type,duplicate),ScimErrorType.INVALID_VALUE);
        ScimResource current = trusted(type,"{\"schemas\":[\""+GROUP+"\"],\"displayName\":\"team\",\"members\":[{\"value\":\"one\"}]}");
        rejected(replace(type,current,duplicate),ScimErrorType.INVALID_VALUE);
        assertEquals(2,ScimGroup.fromResource(accepted(create(type,
                duplicate.replace("{\"value\":\"one\"}]}", "{\"value\":\"One\"}]}")))
                .getResource()).getMembers().size(), "SCIM resource IDs remain case exact");
    }

    @Test void trustedViewsAndCopierHaveIntentionalDataAccessAndFixedDiagnostics() {
        ScimResource user = trusted(ScimResourceType.userInstance(),"{\"schemas\":[\""+USER+"\"],\"userName\":\"Ada-secret\",\"password\":\"temporary-secret\",\"meta\":{\"created\":\"2000-02-29T24:00:00Z\",\"location\":\"https://example.invalid/Users/1\",\"version\":\"W/\\\"1\\\"\"}}");
        assertEquals(java.time.Instant.parse("2000-03-01T00:00:00Z"),user.getCreated().orElseThrow());
        assertEquals(java.net.URI.create("https://example.invalid/Users/1"),user.getLocation().orElseThrow());
        assertEquals("W/\"1\"",user.getVersion().orElseThrow());
        assertFalse(user.toString().contains("secret"));
        assertEquals(user.getDocument(),user.copy().document(null).finish().getDocument());
        assertEquals("Ada-secret",ScimUser.fromResource(user).getUserName());
        assertThrows(IllegalArgumentException.class,() -> ScimGroup.fromResource(user));
        assertThrows(IllegalArgumentException.class,() -> ScimEnterpriseUser.fromResource(user));
        assertThrows(IllegalStateException.class,() -> ScimResource.withResourceType(ScimResourceType.userInstance()).document(null).build());
        String mismatchedMetadata = """
                {"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"a","meta":{"resourceType":"Group"}}
                """;
        assertThrows(IllegalArgumentException.class,() -> trusted(ScimResourceType.userInstance(),mismatchedMetadata));
    }

    @Test void datatypesFollowXsdAndBase64AndReferenceGrammar() {
        for (String value : new String[]{"2008-01-23T04:56:22Z","2000-02-29T24:00:00","-0001-02-29T00:00:00+14:00","12000-01-01T00:00:00-14:00","2000-01-01T01:02:03.123456789123"})
            assertTrue(ScimResourceValidation.dateTime(value),value);
        for (String value : new String[]{"2001-02-29T00:00:00Z","0000-01-01T00:00:00Z","+2000-01-01T00:00:00Z","02000-01-01T00:00:00Z","2000-01-01t00:00:00Z","2000-01-01T24:00:00.1Z","2000-01-01T00:00:60Z","2000-01-01T00:00:00+14:01","2000-01-01T00:00:00z"})
            assertFalse(ScimResourceValidation.dateTime(value),value);
        for (String value : new String[]{"","Zg","Zg==","Zm8","Zm8=","Zm9v"}) assertTrue(ScimResourceValidation.binary(value),value);
        for (String value : new String[]{"Z","Zh","Zh==","Zm9","=","Zg=","Zg===","Z g=="}) assertFalse(ScimResourceValidation.binary(value),value);
        for (String value : new String[]{"Users/1","../Users/1","https://example.invalid/Users/1","urn:example:1","//example.invalid/User","?id=1","#here"}) assertTrue(ScimResourceValidation.reference(value),value);
        for (String value : new String[]{"https://example.invalid/%gg","bad link","https://[invalid]/x",":path"}) assertFalse(ScimResourceValidation.reference(value),value);
    }

    @Test void ignoredValuesRemainBoundedAndDiagnosticsNeverContainInput() {
        String body = "{\"schemas\":[\""+USER+"\"],\"userName\":\"a\",\"unknown\":\""+"x".repeat(11000)+"\"}";
        ScimResourceParseResult result = ScimResources.create(ScimResourceType.userInstance(),document(body),
                compatibility(ScimCompatibilityFeature.IGNORE_UNKNOWN_ATTRIBUTES),ScimLimits.builder().maximumWorkUnits(10000).build(),CONTEXT);
        assertEquals(413,assertInstanceOf(ScimResourceParseResult.Rejected.class,result).getError().getStatusCode());
        assertFalse(result.toString().contains("xxx"));
        assertFalse(create(ScimResourceType.userInstance(),"{\"schemas\":[\""+USER+"\"],\"userName\":\"error-secret\",\"unknown\":true}").toString().contains("error-secret"));
    }

    @Test void projectionStripsNeverAndRequiresExactWriteLeafProvenanceForRequestSiblings() {
        ScimResourceType type=ScimResourceType.withName("Secret").endpoint("/Secrets").schema(ScimSchema.withId("urn:example:Secret").name("Secret")
                .attributes(java.util.List.of(ScimAttributeDefinition.withName("title").build(),
                        ScimAttributeDefinition.withName("password").mutability(ScimMutability.WRITE_ONLY).returned(ScimReturned.NEVER).build(),
                        ScimAttributeDefinition.withName("profile").type(ScimAttributeType.COMPLEX).subAttributes(java.util.List.of(
                                ScimAttributeDefinition.withName("first").returned(ScimReturned.REQUEST).build(),
                                ScimAttributeDefinition.withName("second").returned(ScimReturned.REQUEST).build(),
                                ScimAttributeDefinition.withName("label").build(),
                                ScimAttributeDefinition.withName("always").returned(ScimReturned.ALWAYS).build())).build())).build()).build();
        ScimResource resource=trusted(type,"{\"schemas\":[\"urn:example:Secret\"],\"id\":\"1\",\"title\":\"shown\",\"password\":\"hidden\",\"profile\":{\"first\":\"one\",\"second\":\"two\",\"label\":\"default\",\"always\":\"mandatory\"}}");
        ScimAttributeSelection defaults=new ScimAttributeSelection(type,Set.of(),Set.of(),false,CONTEXT);
        JsonObject read=java.util.Objects.requireNonNull(ScimResources.project(resource,defaults,Set.of(),false,new ScimWork(10000)));
        assertFalse(read.getMembers().containsKey("password"));
        JsonObject profile=(JsonObject)read.find("profile").orElseThrow();
        assertEquals(Set.of("label","always"),profile.getMembers().keySet());
        JsonObject write=java.util.Objects.requireNonNull(ScimResources.project(resource,defaults,Set.of(path("profile.first")),true,new ScimWork(10000)));
        assertEquals(Set.of("first","label","always"),((JsonObject)write.find("profile").orElseThrow()).getMembers().keySet());
        ScimAttributeSelection include=new ScimAttributeSelection(type,Set.of(path("profile"),path("password")),Set.of(),true,CONTEXT);
        JsonObject full=java.util.Objects.requireNonNull(ScimResources.project(resource,include,Set.of(),false,new ScimWork(10000)));
        assertFalse(full.getMembers().containsKey("password"));
        assertEquals(Set.of("first","second","label","always"),((JsonObject)full.find("profile").orElseThrow()).getMembers().keySet());
        assertTrue(full.getMembers().containsKey("id")); assertTrue(full.getMembers().containsKey("schemas"));
        ScimAttributeSelection excluded=new ScimAttributeSelection(type,Set.of(),Set.of(path("profile"),path("id")),true,CONTEXT);
        JsonObject always=java.util.Objects.requireNonNull(ScimResources.project(resource,excluded,Set.of(path("profile.first")),true,new ScimWork(10000)));
        assertEquals(Set.of("always"),((JsonObject)always.find("profile").orElseThrow()).getMembers().keySet());
        assertTrue(always.getMembers().containsKey("id"));
        assertNull(ScimResources.project(resource,defaults,Set.of(),false,new ScimWork(1)));
    }

    @Test void customProtectedArraysRejectAmbiguousReplacementRatherThanTransferMetadata() {
        ScimResourceType type=ScimResourceType.withName("Protected").endpoint("/Protected").schema(ScimSchema.withId("urn:example:Protected").name("Protected")
                .attributes(java.util.List.of(ScimAttributeDefinition.withName("items").type(ScimAttributeType.COMPLEX).multiValued(true).subAttributes(java.util.List.of(
                        ScimAttributeDefinition.withName("code").mutability(ScimMutability.IMMUTABLE).build(),
                        ScimAttributeDefinition.withName("note").build(),
                        ScimAttributeDefinition.withName("label").mutability(ScimMutability.READ_ONLY).build())).build())).build()).build();
        ScimResource resource=trusted(type,"{\"schemas\":[\"urn:example:Protected\"],\"items\":[{\"code\":\"a\",\"note\":\"one\",\"label\":\"first\"},{\"code\":\"b\",\"note\":\"two\",\"label\":\"second\"}]}");
        accepted(replace(type,resource,"{\"schemas\":[\"urn:example:Protected\"],\"items\":[{\"code\":\"a\",\"note\":\"one\",\"label\":false},{\"code\":\"b\",\"note\":\"two\"}]}"));
        for (String items : new String[]{"[]","[{\"code\":\"b\",\"note\":\"two\"},{\"code\":\"a\",\"note\":\"one\"}]","[{\"code\":\"a\",\"note\":\"changed\"},{\"code\":\"b\",\"note\":\"two\"}]"})
            rejected(replace(type,resource,"{\"schemas\":[\"urn:example:Protected\"],\"items\":"+items+"}"),ScimErrorType.MUTABILITY);
    }

    @Test void compatibilityEventsRecordActualRewritesEvenBeforeLaterRejection() {
        java.util.Set<ScimCompatibilityFeature> used=new java.util.LinkedHashSet<>();
        ScimCompatibility flags=ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.BOOLEAN_STRINGS,ScimCompatibilityFeature.IGNORE_UNKNOWN_ATTRIBUTES,ScimCompatibilityFeature.IGNORE_UNDECLARED_SCHEMA_URIS)).build();
        accepted(ScimResources.create(ScimResourceType.userInstance(),document("{\"schemas\":[\""+USER+"\"],\"userName\":\"true\",\"active\":\"true\"}"),flags,new ScimWork(10000),CONTEXT,used));
        assertEquals(Set.of(ScimCompatibilityFeature.BOOLEAN_STRINGS),used);
        used.clear();
        rejected(ScimResources.create(ScimResourceType.userInstance(),document("{\"schemas\":[\""+USER+"\"],\"unknown\":true}"),flags,new ScimWork(10000),CONTEXT,used),ScimErrorType.INVALID_VALUE);
        assertEquals(Set.of(ScimCompatibilityFeature.IGNORE_UNKNOWN_ATTRIBUTES),used);
        used.clear();
        rejected(ScimResources.create(ScimResourceType.userInstance(),document("{\"schemas\":[\""+USER+"\",\"not a URI\"],\"userName\":\"a\"}"),flags,new ScimWork(10000),CONTEXT,used),ScimErrorType.INVALID_VALUE);
        assertTrue(used.isEmpty());
        used.clear();
        rejected(ScimResources.create(ScimResourceType.userInstance(),document("{\"schemas\":[\""+USER+"\"],\"userName\":\"a\",\"active\":\"TRUE\"}"),flags,new ScimWork(10000),CONTEXT,used),ScimErrorType.INVALID_VALUE);
        assertTrue(used.isEmpty());
        rejected(create(ScimResourceType.groupInstance(),"{\"schemas\":[\""+GROUP+"\"],\"displayName\":\"g\",\"members\":[{\"value\":\"containsBULKIDreserved\"}]}"),ScimErrorType.INVALID_VALUE);
        assertThrows(IllegalArgumentException.class,() -> trusted(ScimResourceType.userInstance(),"{\"schemas\":[\""+USER+"\"],\"userName\":\"a\",\"id\":\"prefixbulkIdsuffix\"}"));
    }

    @Test void putRetainedReadOnlyExtensionGetsAuthoritativeFinalSchemaDeclaration() {
        String extensionId="urn:example:ServerExtension";
        ScimSchema extension=ScimSchema.withId(extensionId).name("ServerExtension").attributes(java.util.List.of(ScimAttributeDefinition.withName("tag").mutability(ScimMutability.READ_ONLY).required(true).build())).build();
        ScimResourceType type=ScimResourceType.withName("Extended").endpoint("/Extended").schema(ScimSchema.withId("urn:example:Extended").name("Extended").attributes(java.util.List.of(ScimAttributeDefinition.withName("title").required(true).build())).build()).schemaExtensions(java.util.List.of(ScimSchemaExtension.fromSchema(extension,true))).build();
        ScimResource current=trusted(type,"{\"schemas\":[\"urn:example:Extended\",\""+extensionId+"\"],\"title\":\"old\",\""+extensionId+"\":{\"tag\":\"server\"}}");
        ScimResource result=accepted(replace(type,current,"{\"schemas\":[\"urn:example:Extended\"],\"title\":\"new\"}")).getResource();
        assertEquals(java.util.List.of("urn:example:Extended",extensionId),result.getDocument().findStringList("schemas").orElseThrow());
        assertEquals("server",result.getExtension(extensionId).orElseThrow().findString("tag").orElseThrow());
    }

    private static @NonNull ScimResourceType widget() {
        return ScimResourceType.withName("Widget").endpoint("/Widgets").schema(ScimSchema.withId(WIDGET).name("Widget")
                .attributes(java.util.List.of(ScimAttributeDefinition.withName("title").required(true).build(),
                        ScimAttributeDefinition.withName("whole").type(ScimAttributeType.INTEGER).build(),
                        ScimAttributeDefinition.withName("numbers").type(ScimAttributeType.INTEGER).multiValued(true).build(),
                        ScimAttributeDefinition.withName("locked").mutability(ScimMutability.IMMUTABLE).build(),
                        ScimAttributeDefinition.withName("server").mutability(ScimMutability.READ_ONLY).build(),
                        ScimAttributeDefinition.withName("profile").type(ScimAttributeType.COMPLEX).subAttributes(java.util.List.of(
                                ScimAttributeDefinition.withName("secret").mutability(ScimMutability.READ_ONLY).build(),
                                ScimAttributeDefinition.withName("code").mutability(ScimMutability.IMMUTABLE).build(),
                                ScimAttributeDefinition.withName("note").build())).build())).build()).build();
    }
    private static @NonNull ScimCompatibility compatibility(@NonNull ScimCompatibilityFeature feature) { return ScimCompatibility.builder().features(Set.of(feature)).build(); }
    private static @NonNull ScimResourceParseResult create(@NonNull ScimResourceType type,@NonNull String body) { return create(type,body,ScimCompatibility.strictInstance()); }
    private static @NonNull ScimResourceParseResult create(@NonNull ScimResourceType type,@NonNull String body,@NonNull ScimCompatibility compatibility) { return ScimResources.create(type,document(body),compatibility,ScimLimits.builder().build(),CONTEXT); }
    private static @NonNull ScimResourceParseResult replace(@NonNull ScimResourceType type,@NonNull ScimResource current,@NonNull String body) { return ScimResources.replace(type,current,document(body),ScimCompatibility.strictInstance(),ScimLimits.builder().build(),CONTEXT); }
    private static @NonNull JsonDocument document(@NonNull String body) { return assertInstanceOf(JsonParseResult.Succeeded.class,JsonCodec.parseResult(body.getBytes(StandardCharsets.UTF_8),JsonLimits.scim(1048576,100000))).getDocument(); }
    private static @NonNull ScimResource trusted(@NonNull ScimResourceType type,@NonNull String body) { return ScimResource.withResourceType(type).document((JsonObject)document(body).getValue()).build(); }
    private static ScimResourceParseResult.@NonNull Succeeded accepted(@NonNull ScimResourceParseResult result) { return assertInstanceOf(ScimResourceParseResult.Succeeded.class,result); }
    private static void rejected(@NonNull ScimResourceParseResult result,@NonNull ScimErrorType expected) { assertEquals(expected,assertInstanceOf(ScimResourceParseResult.Rejected.class,result).getError().getErrorType().orElseThrow()); }
    private static @NonNull ScimAttributePath path(@NonNull String expression) { return assertInstanceOf(ScimAttributePathParseResult.Succeeded.class,ScimAttributePath.fromExpressionResult(expression)).getAttributePath(); }
}
