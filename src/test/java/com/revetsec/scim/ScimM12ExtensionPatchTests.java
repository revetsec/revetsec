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
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import static org.junit.jupiter.api.Assertions.*;

/** The schema URI itself is a distinct registered PATCH target, never a fabricated attribute path. */
class ScimM12ExtensionPatchTests {
    private static final @NonNull String PATCH="urn:ietf:params:scim:api:messages:2.0:PatchOp";
    private static final @NonNull String ENTERPRISE=ScimSchema.enterpriseUserInstance().getId();
    private static final @NonNull ScimResourceType USER=ScimResourceType.userInstance();
    private static final @NonNull ScimStringMatching EXACT=(path,definition,operator,left,right) -> ScimStringMatchResult.fromMatched(
            operator == ScimComparisonOperator.EQ ? left.equals(right) : operator == ScimComparisonOperator.NE && !left.equals(right));
    private static @NonNull ScimServiceProvider provider(@NonNull ScimResourceType type) {
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(type)).stringMatching(EXACT)
                .compatibility(ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.PATCH_EXTENSION_SCHEMA_ROOT)).build())
                .serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).build()).build();
    }
    private static @NonNull ScimResource user(@Nullable JsonObject extension) {
        JsonObject.Builder body=JsonObject.builder().put("schemas",JsonArray.fromElements(extension == null
                ? List.of(JsonString.fromValue(USER.getSchema().getId()))
                : List.of(JsonString.fromValue(USER.getSchema().getId()),JsonString.fromValue(ENTERPRISE))))
                .put("id","user-id").put("userName","fixture").put("meta",JsonObject.builder().put("version","W/\"v1\"").build());
        if (extension != null) body.put(ENTERPRISE,extension);
        return ScimResource.withResourceType(USER).document(body.build()).build();
    }
    private static @NonNull JsonObject operation(@NonNull String kind,@NonNull String path,@Nullable JsonValue value) {
        JsonObject.Builder body=JsonObject.builder().put("op",kind).put("path",path);
        if (value != null) body.put("value",value);
        return body.build();
    }
    private static byte @NonNull [] body(@NonNull List<@NonNull JsonObject> operations) {
        return JsonObject.builder().put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(PATCH))))
                .put("Operations",JsonArray.fromElements(new ArrayList<JsonValue>(operations))).build().toJson().getBytes(StandardCharsets.UTF_8);
    }
    private static @NonNull ScimPatchRequest parse(@NonNull ScimServiceProvider p,@NonNull ScimResourceType type,@NonNull JsonObject @NonNull ... operations) {
        return assertInstanceOf(ScimPatchParseResult.Succeeded.class,p.parsePatchRequestResult(type,body(List.of(operations)))).getPatchRequest();
    }
    private static @NonNull ScimPatchResult apply(@NonNull ScimServiceProvider p,@NonNull ScimResource current,@NonNull ScimPatchRequest patch) {
        return assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,p.applyPatchResult(current,patch)).getPatchResult();
    }
    private static @NonNull Set<@NonNull String> paths(@NonNull Set<@NonNull ScimAttributePath> paths) {
        return paths.stream().map(ScimAttributePath::toScimString).collect(Collectors.toSet());
    }
    @Test void extensionUriRootAddsAndReplacesPartialObjectsWithCanonicalProvenance() {
        ScimServiceProvider p=provider(USER);
        ScimResource current=user(null);
        ScimPatchRequest patch=parse(p,USER,operation("add",ENTERPRISE,JsonObject.builder().put("DEPARTMENT","research").build()));
        ScimPatchOperation operation=patch.getOperations().get(0);
        assertEquals(ENTERPRISE,operation.getExtensionSchemaId().orElseThrow());
        assertTrue(operation.getAttributePath().isEmpty());
        assertTrue(operation.getValueFilter().isEmpty());
        assertTrue(operation.getSubAttributeName().isEmpty());
        assertEquals(Set.of("schemas",ENTERPRISE+":department"),paths(patch.getRequestedAttributePaths()));
        assertEquals(Set.of(ENTERPRISE+":department"),paths(patch.getSuppliedAttributePaths()));
        ScimPatchResult added=apply(p,current,patch);
        assertTrue(added.isModified());
        assertEquals(Set.of("schemas",ENTERPRISE+":department"),paths(added.getModifiedAttributePaths()));
        assertEquals("research",added.getResource().getExtension(ENTERPRISE).orElseThrow().findString("department").orElseThrow());
        ScimResource withSibling=user(JsonObject.builder().put("department","research").put("employeeNumber","employee-1").build());
        ScimPatchResult replaced=apply(p,withSibling,parse(p,USER,operation("replace",ENTERPRISE.toUpperCase(java.util.Locale.ROOT),
                JsonObject.builder().put("department","engineering").build())));
        JsonObject extension=replaced.getResource().getExtension(ENTERPRISE).orElseThrow();
        assertEquals("engineering",extension.findString("department").orElseThrow());
        assertEquals("employee-1",extension.findString("employeeNumber").orElseThrow());
        assertEquals(Set.of(ENTERPRISE+":department"),paths(replaced.getModifiedAttributePaths()));
        assertEquals("W/\"v1\"",replaced.getResource().getVersion().orElseThrow());
        assertFalse(replaced.toString().contains("engineering"));
        assertFalse(operation.toString().contains(ENTERPRISE));
    }
    @Test void rootRemoveTracksEveryDeclaredChildAndDeclarationAndAbsentRemovalIsNoOp() {
        ScimServiceProvider p=provider(USER);
        ScimPatchRequest removal=parse(p,USER,operation("remove",ENTERPRISE,null));
        Set<String> requested=paths(removal.getRequestedAttributePaths());
        assertTrue(requested.containsAll(Set.of("schemas",ENTERPRISE+":department",ENTERPRISE+":manager",ENTERPRISE+":manager.value")));
        assertTrue(removal.getSuppliedAttributePaths().isEmpty());
        ScimPatchResult removed=apply(p,user(JsonObject.builder().put("department","research").put("manager",JsonObject.builder().put("value","manager-id").build()).build()),removal);
        assertTrue(removed.getResource().getExtension(ENTERPRISE).isEmpty());
        assertEquals(Set.of("schemas",ENTERPRISE+":department",ENTERPRISE+":manager",ENTERPRISE+":manager.value"),paths(removed.getModifiedAttributePaths()));
        ScimResource absent=user(null);
        ScimPatchResult noOp=apply(p,absent,removal);
        assertFalse(noOp.isModified());
        assertSame(absent,noOp.getResource());
        assertEquals(removal.getRequestedAttributePaths(),noOp.getRequestedAttributePaths());
    }
    @Test void emptyObjectsRetainAnExplicitExtensionAndClearNullChildrenWithoutInventingSuppliedPaths() {
        ScimServiceProvider p=provider(USER);
        ScimPatchRequest empty=parse(p,USER,operation("add",ENTERPRISE,JsonObject.emptyInstance()));
        assertEquals(Set.of("schemas"),paths(empty.getRequestedAttributePaths()));
        assertTrue(empty.getSuppliedAttributePaths().isEmpty());
        ScimPatchResult added=apply(p,user(null),empty);
        assertEquals(JsonObject.emptyInstance(),added.getResource().getExtension(ENTERPRISE).orElseThrow());
        assertEquals(Set.of("schemas"),paths(added.getModifiedAttributePaths()));
        ScimPatchResult cleared=apply(p,user(JsonObject.builder().put("department","before").build()),
                parse(p,USER,operation("replace",ENTERPRISE,JsonObject.builder().put("department",JsonNull.defaultInstance()).build())));
        assertEquals(JsonObject.emptyInstance(),cleared.getResource().getExtension(ENTERPRISE).orElseThrow());
        assertEquals(Set.of(ENTERPRISE+":department"),paths(cleared.getModifiedAttributePaths()));
    }
    @Test void rootShapesUnknownSchemasAndRemoveValuesRemainStrictInEveryCompatibilityPreset() {
        for (ScimCompatibility compatibility:List.of(ScimCompatibility.strictInstance(),ScimCompatibility.microsoftEntraIdInstance(),ScimCompatibility.oktaInstance())) {
            assertFalse(compatibility.getFeatures().contains(ScimCompatibilityFeature.PATCH_EXTENSION_SCHEMA_ROOT));
            ScimServiceProvider strict=provider(USER).copy().compatibility(compatibility).finish();
            assertSame(ScimError.invalidPathInstance(),assertInstanceOf(ScimPatchParseResult.Rejected.class,
                    strict.parsePatchRequestResult(USER,body(List.of(operation("add",ENTERPRISE,JsonObject.emptyInstance()))))).getError());
            Set<ScimCompatibilityFeature> features=new java.util.LinkedHashSet<>(compatibility.getFeatures());
            features.add(ScimCompatibilityFeature.PATCH_EXTENSION_SCHEMA_ROOT);
            ScimServiceProvider p=strict.copy().compatibility(ScimCompatibility.builder().features(features).build()).finish();
            for (JsonValue value:List.of(JsonString.fromValue("research"),JsonNumber.fromValue(1L),JsonNull.defaultInstance(),JsonArray.fromElements(List.of(JsonObject.emptyInstance()))))
                assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimPatchParseResult.Rejected.class,
                        p.parsePatchRequestResult(USER,body(List.of(operation("replace",ENTERPRISE,value))))).getError());
            assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimPatchParseResult.Rejected.class,
                    p.parsePatchRequestResult(USER,body(List.of(operation("remove",ENTERPRISE,JsonObject.emptyInstance()))))).getError());
            for (String unknown:List.of("urn:example:unregistered",USER.getSchema().getId(),ENTERPRISE+"."))
                assertSame(ScimError.invalidPathInstance(),assertInstanceOf(ScimPatchParseResult.Rejected.class,
                        p.parsePatchRequestResult(USER,body(List.of(operation("add",unknown,JsonObject.emptyInstance()))))).getError());
        }
    }
    private static @NonNull ScimResourceType type(boolean required,@NonNull ScimMutability mutability,boolean childRequired) {
        ScimSchema extension=ScimSchema.withId("urn:example:scim:extension").name("Extra")
                .attributes(List.of(ScimAttributeDefinition.withName("field").mutability(mutability).required(childRequired).build(),
                        ScimAttributeDefinition.withName("ordinary").build(),
                        ScimAttributeDefinition.withName("complex").type(ScimAttributeType.COMPLEX)
                                .subAttributes(List.of(ScimAttributeDefinition.withName("locked").mutability(mutability).build())).build())).build();
        return ScimResourceType.withName("Fixture").endpoint("/Fixtures")
                .schema(ScimSchema.withId("urn:example:scim:base").name("Fixture").build())
                .schemaExtensions(List.of(ScimSchemaExtension.fromSchema(extension,required))).build();
    }
    private static @NonNull ScimResource fixture(@NonNull ScimResourceType type,@Nullable JsonObject extension) {
        String schema=type.getSchemaExtensions().get(0).getSchema().getId();
        JsonObject.Builder body=JsonObject.builder().put("schemas",JsonArray.fromElements(extension == null
                ? List.of(JsonString.fromValue(type.getSchema().getId())) : List.of(JsonString.fromValue(type.getSchema().getId()),JsonString.fromValue(schema))));
        if (extension != null) body.put(schema,extension);
        return ScimResource.withResourceType(type).document(body.build()).build();
    }
    @Test void requiredExtensionsAndRequiredChildrenRejectAtTheirOperationWhileOptionalContainerRemovalIsAllowed() {
        for (boolean requiredExtension:List.of(false,true)) {
            ScimResourceType type=type(requiredExtension,ScimMutability.READ_WRITE,true);
            ScimServiceProvider p=provider(type);
            String schema=type.getSchemaExtensions().get(0).getSchema().getId();
            ScimResource current=fixture(type,JsonObject.builder().put("field","assigned").build());
            ScimPatchRequest removal=parse(p,type,operation("remove",schema,null));
            if (requiredExtension) {
                assertSame(ScimError.mutabilityInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,p.applyPatchResult(current,removal)).getError());
                ScimPatchRequest removeThenRestore=parse(p,type,operation("remove",schema,null),operation("add",schema,JsonObject.builder().put("field","restored").build()));
                assertSame(ScimError.mutabilityInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,p.applyPatchResult(current,removeThenRestore)).getError());
            }
            else assertTrue(apply(p,current,removal).getResource().getExtension(schema).isEmpty());
            ScimPatchRequest clearThenRestore=parse(p,type,operation("replace",schema,JsonObject.builder().put("field",JsonNull.defaultInstance()).build()),
                    operation("replace",schema,JsonObject.builder().put("field","restored").build()));
            assertSame(ScimError.mutabilityInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,p.applyPatchResult(current,clearThenRestore)).getError());
            assertEquals("assigned",current.getExtension(schema).orElseThrow().findString("field").orElseThrow());
        }
    }
    @Test void wholeExtensionRemovalAndWritesProtectImmutableAndReadOnlyDataIncludingDescendants() {
        for (ScimMutability mutability:List.of(ScimMutability.READ_ONLY,ScimMutability.IMMUTABLE)) {
            ScimResourceType type=type(false,mutability,false);
            ScimServiceProvider p=provider(type);
            String schema=type.getSchemaExtensions().get(0).getSchema().getId();
            ScimResource current=fixture(type,JsonObject.builder().put("field","locked").build());
            for (JsonObject op:List.of(operation("remove",schema,null),operation("replace",schema,JsonObject.builder().put("field","changed").build()),
                    operation("add",schema,JsonObject.builder().put("field",JsonNull.defaultInstance()).build())))
                assertSame(ScimError.mutabilityInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,p.applyPatchResult(current,parse(p,type,op))).getError());
            assertEquals("locked",current.getExtension(schema).orElseThrow().findString("field").orElseThrow());
            ScimResource child=fixture(type,JsonObject.builder().put("complex",JsonObject.builder().put("locked","child").build()).build());
            assertSame(ScimError.mutabilityInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,
                    p.applyPatchResult(child,parse(p,type,operation("remove",schema,null)))).getError());
            ScimResource ordinary=fixture(type,JsonObject.builder().put("ordinary","mutable").build());
            assertTrue(apply(p,ordinary,parse(p,type,operation("remove",schema,null))).getResource().getExtension(schema).isEmpty());
            if (mutability == ScimMutability.IMMUTABLE) assertFalse(apply(p,current,parse(p,type,operation("replace",schema,JsonObject.builder().put("field","locked").build()))).isModified());
        }
    }
    @Test void lateRootFailurePublishesNoEarlierPatchAndSharedWorkAppliesToExtensionScans() {
        ScimServiceProvider p=provider(USER);
        ScimResource current=user(null);
        JsonObject before=current.getDocument();
        ScimPatchRequest request=parse(p,USER,operation("add",ENTERPRISE,JsonObject.builder().put("department","before-failure").build()),
                operation("replace","id",JsonString.fromValue("forbidden")));
        assertSame(ScimError.mutabilityInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,p.applyPatchResult(current,request)).getError());
        assertSame(before,current.getDocument());
        ScimServiceProvider bounded=ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(USER)).stringMatching(EXACT).limits(ScimLimits.builder().maximumWorkUnits(10000).maximumPatchOperations(128).build())
                .compatibility(ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.PATCH_EXTENSION_SCHEMA_ROOT)).build())
                .serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).build()).build();
        List<JsonObject> operations=new ArrayList<>();
        for (int index=0;index<80;index++) operations.add(operation("remove",ENTERPRISE,null));
        assertSame(ScimError.requestTooLargeInstance(),assertInstanceOf(ScimPatchParseResult.Rejected.class,
                bounded.parsePatchRequestResult(USER,body(operations))).getError());
    }

    @Test void rootProfileEmitsOncePerOperationAndDoesNotRelaxUnrelatedGrammarOrProvenance() {
        List<String> events=new ArrayList<>();
        ScimObserver observer=new ScimObserver() {
            @Override public void willProcess(@NonNull Operation operation) { events.add("will:"+operation); }
            @Override public void didProcess(@NonNull Operation operation,@NonNull Outcome outcome) { events.add("did:"+outcome); }
            @Override public void didUseCompatibilityFeature(@NonNull ScimCompatibilityFeature feature) { events.add("feature:"+feature); }
        };
        ScimServiceProvider p=ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(USER)).stringMatching(EXACT).observer(observer)
                .compatibility(ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.PATCH_EXTENSION_SCHEMA_ROOT)).build())
                .serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).build()).build();
        ScimPatchRequest patch=parse(p,USER,operation("add",ENTERPRISE,JsonObject.emptyInstance()),operation("replace",ENTERPRISE,JsonObject.emptyInstance()));
        assertEquals(List.of("will:PATCH_PARSE","feature:PATCH_EXTENSION_SCHEMA_ROOT","did:SUCCEEDED"),events);
        events.clear();
        apply(p,user(null),patch);
        assertEquals(List.of("will:PATCH_APPLY","feature:PATCH_EXTENSION_SCHEMA_ROOT","did:SUCCEEDED"),events);
        ScimServiceProvider strict=p.copy().compatibility(ScimCompatibility.strictInstance()).finish();
        assertSame(ScimError.invalidValueInstance(),assertInstanceOf(ScimPatchApplicationResult.Rejected.class,strict.applyPatchResult(user(null),patch)).getError());
        for (JsonObject operation:List.of(operation("ADD",ENTERPRISE,JsonObject.emptyInstance()),
                operation("replace","active",JsonString.fromValue("true")),
                JsonObject.builder().put("op","replace").put("value",JsonObject.builder().put("name.givenName","fixture").build()).build()))
            assertInstanceOf(ScimPatchParseResult.Rejected.class,p.parsePatchRequestResult(USER,body(List.of(operation))));
        events.clear();
        assertInstanceOf(ScimPatchParseResult.Rejected.class,p.parsePatchRequestResult(USER,body(List.of(operation("add","urn:example:unknown",JsonObject.emptyInstance())))));
        assertEquals(List.of("will:PATCH_PARSE","did:REJECTED"),events);
    }

    @Test void ordinaryRegisteredAttributePathsTakePrecedenceOverAmbiguousCustomExtensionUris() {
        ScimSchema schema=ScimSchema.withId("urn:example:prefix").name("Prefix")
                .attributes(List.of(ScimAttributeDefinition.withName("field").build())).build();
        ScimSchema extension=ScimSchema.withId(schema.getId()+":field").name("Collision")
                .attributes(List.of(ScimAttributeDefinition.withName("other").build())).build();
        ScimResourceType type=ScimResourceType.withName("Prefix").endpoint("/Prefixes").schema(schema)
                .schemaExtensions(List.of(ScimSchemaExtension.fromSchema(extension,false))).build();
        ScimResource current=ScimResource.withResourceType(type).document(JsonObject.builder()
                .put("schemas",JsonArray.fromElements(List.of(JsonString.fromValue(schema.getId())))).put("field","before").build()).build();
        for (ScimCompatibility compatibility:List.of(ScimCompatibility.strictInstance(),ScimCompatibility.builder()
                .features(Set.of(ScimCompatibilityFeature.PATCH_EXTENSION_SCHEMA_ROOT)).build())) {
            ScimServiceProvider p=provider(type).copy().compatibility(compatibility).finish();
            ScimPatchRequest request=parse(p,type,operation("replace",extension.getId(),JsonString.fromValue("after")));
            ScimPatchOperation operation=request.getOperations().get(0);
            assertTrue(operation.getExtensionSchemaId().isEmpty());
            assertEquals("field",operation.getAttributePath().orElseThrow().toScimString());
            ScimPatchResult result=apply(p,current,request);
            assertEquals("after",result.getResource().getDocument().findString("field").orElseThrow());
            assertTrue(result.getResource().getExtension(extension.getId()).isEmpty());
            assertEquals(Set.of("field"),paths(result.getModifiedAttributePaths()));
        }
    }

    @Test void nestedSchemasIsNotAnExtensionChildAndTheRootProfileDoesNotIgnoreIt() {
        for(ScimCompatibility preset:List.of(ScimCompatibility.strictInstance(),ScimCompatibility.microsoftEntraIdInstance(),ScimCompatibility.oktaInstance())) {
            Set<ScimCompatibilityFeature> features=new java.util.LinkedHashSet<>(preset.getFeatures());
            features.add(ScimCompatibilityFeature.PATCH_EXTENSION_SCHEMA_ROOT);
            ScimServiceProvider p=provider(USER).copy().compatibility(ScimCompatibility.builder().features(features).build()).finish();
            for(String name:List.of("schemas","SCHEMAS")) {
                JsonObject value=JsonObject.builder().put("employeeNumber","fixture-employee")
                        .put("department","private-fixture-department")
                        .put("manager",JsonObject.builder().put("value","fixture-manager").build())
                        .put(name,JsonArray.fromElements(List.of(JsonString.fromValue(ENTERPRISE)))).build();
                ScimPatchParseResult result=p.parsePatchRequestResult(USER,body(List.of(operation("add",ENTERPRISE,value))));
                assertSame(ScimError.invalidPathInstance(),assertInstanceOf(ScimPatchParseResult.Rejected.class,result).getError());
                assertFalse(result.toString().contains("private-fixture-department"));
            }
        }
    }
}
