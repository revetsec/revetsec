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
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** Identical entry/final public fixture for ordered manager reference instructions. */
final class ScimManagerPatchCoherenceTests {
    private static final String E = ScimSchema.enterpriseUserInstance().getId();
    private static final String M = E + ":manager";
    private static final ScimResourceType USER = ScimTestResourceTypes.userWithEnterpriseInstance();
    private static final ScimResourceType PERSON = ScimResourceType.withName("Person").endpoint("/People").schema(ScimSchema.userInstance())
            .schemaExtensions(List.of(ScimSchemaExtension.fromSchema(ScimSchema.enterpriseUserInstance(), false))).build();
    private static final ScimCompatibility ROOT = ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.PATCH_EXTENSION_SCHEMA_ROOT)).build();
    private static final ScimStringMatching NO_MATCHING = (path, definition, operator, left, right) -> {
        fail("Manager identity/reference coherence cannot invoke application matching"); return ScimStringMatchResult.unsupportedInstance();
    };

    @TestFactory Stream<DynamicTest> anEarlierExplicitReferenceSurvivesEveryLaterValueWriteShape() {
        return Stream.of(USER, PERSON).flatMap(type -> Stream.of("add", "replace").flatMap(kind -> Stream.of("child", "manager", "object", "root").flatMap(refShape ->
                Stream.of("child", "manager", "object", "root").map(valueShape -> DynamicTest.dynamicTest(type.getName() + " " + kind + " " + refShape + "->" + valueShape, () -> {
            boolean root = refShape.equals("root") || valueShape.equals("root");
            var provider = provider(type, root ? ROOT : ScimCompatibility.strictInstance()); var current = resource(type);
            var request = request(provider, type, List.of(write(kind, refShape, "$ref", "Users/new"), write(kind, valueShape, "value", "new")));
            var changed = apply(provider, current, request);
            assertEquals(manager("new", "Users/new", null), manager(changed.getResource()));
            assertEquals(manager("old", "Users/old", "Old Display"), manager(current));
            assertEquals(current.getVersion(), changed.getResource().getVersion());
            assertTrue(paths(changed.getRequestedAttributePaths()).containsAll(Set.of(M + ".$ref", M + ".value")));
            assertTrue(paths(changed.getSuppliedAttributePaths()).containsAll(Set.of(M + ".$ref", M + ".value")));
            assertTrue(paths(changed.getModifiedAttributePaths()).contains(M + ".displayName"));
        })))));
    }

    @TestFactory Stream<DynamicTest> anInheritedReferenceStillClearsWhenTheManagerChanges() {
        return Stream.of("add", "replace").flatMap(kind -> Stream.of("child", "manager", "object", "root").map(shape ->
                DynamicTest.dynamicTest(kind + " inherited " + shape, () -> {
            var provider = provider(USER, shape.equals("root") ? ROOT : ScimCompatibility.strictInstance());
            assertEquals(manager("new", null, null), manager(apply(provider, resource(USER),
                    request(provider, USER, List.of(write(kind, shape, "value", "new")))).getResource()));
        })));
    }

    @TestFactory Stream<DynamicTest> writingTheReferenceAfterTheValueKeepsOrderedSemantics() {
        return Stream.of("child", "manager", "object", "root").map(shape -> DynamicTest.dynamicTest("value then reference " + shape, () -> {
            var provider = provider(USER, shape.equals("root") ? ROOT : ScimCompatibility.strictInstance());
            var result = apply(provider, resource(USER), request(provider, USER, List.of(write("replace", shape, "value", "new"), write("replace", shape, "$ref", "Users/new"))));
            assertEquals(manager("new", "Users/new", null), manager(result.getResource()));
        }));
    }

    @Test void anExplicitNoOpReferenceWriteStillCountsAsAnInstruction() {
        var provider = provider(USER, ScimCompatibility.strictInstance());
        var result = apply(provider, resource(USER), request(provider, USER, List.of(write("replace", "child", "$ref", "Users/old"), write("replace", "child", "value", "new"))));
        assertEquals(manager("new", "Users/old", null), manager(result.getResource()));
    }

    @Test void repeatedExplicitReferencesAndValueChangesRetainTheLastReference() {
        var provider = provider(USER, ScimCompatibility.strictInstance());
        var result = apply(provider, resource(USER), request(provider, USER, List.of(write("replace", "child", "$ref", "Users/first"),
                write("replace", "manager", "$ref", "Users/final"), write("replace", "manager", "value", "second"), write("replace", "child", "value", "third"))));
        assertEquals(manager("third", "Users/final", null), manager(result.getResource()));
    }

    @Test void sameOperationValueAndReferenceAreIndependentOfObjectKeyOrder() {
        var provider = provider(USER, ScimCompatibility.strictInstance());
        for (boolean refFirst : List.of(false, true)) {
            var fields = JsonObject.builder(); if (refFirst) fields.put("$ref", "Users/new"); fields.put("value", "new"); if (!refFirst) fields.put("$ref", "Users/new");
            var result = apply(provider, resource(USER), request(provider, USER, List.of(op("replace", M, fields.build()))));
            assertEquals(manager("new", "Users/new", null), manager(result.getResource()));
        }
    }

    @Test void canonicalCaseVariantsCarryTheSameReferenceInstruction() {
        var provider = provider(USER, ScimCompatibility.strictInstance());
        var result = apply(provider, resource(USER), request(provider, USER, List.of(op("replace", M.toUpperCase(java.util.Locale.ROOT),
                JsonObject.builder().put("$REF", "Users/new").build()), op("replace", (M + ".value").toUpperCase(java.util.Locale.ROOT), JsonString.fromValue("new")))));
        assertEquals(manager("new", "Users/new", null), manager(result.getResource()));
    }

    @TestFactory Stream<DynamicTest> clearingValueDoesNotEraseAnExplicitReference() {
        return Stream.of("remove", "null-child", "null-parent").map(shape -> DynamicTest.dynamicTest("clear value " + shape, () -> {
            var provider = provider(USER, ScimCompatibility.strictInstance());
            JsonObject clear = shape.equals("remove") ? op("remove", M + ".value", null)
                    : shape.equals("null-child") ? op("replace", M + ".value", JsonNull.defaultInstance())
                    : op("replace", M, JsonObject.builder().put("value", JsonNull.defaultInstance()).build());
            var result = apply(provider, resource(USER), request(provider, USER, List.of(write("replace", "child", "$ref", "Users/new"), clear)));
            assertEquals(manager(null, "Users/new", null), manager(result.getResource()));
        }));
    }

    @TestFactory Stream<DynamicTest> explicitReferenceRemovalAndNullRemainClears() {
        return Stream.of("remove", "null-child", "null-parent").map(shape -> DynamicTest.dynamicTest("clear reference " + shape, () -> {
            var provider = provider(USER, ScimCompatibility.strictInstance());
            JsonObject clear = shape.equals("remove") ? op("remove", M + ".$ref", null)
                    : shape.equals("null-child") ? op("replace", M + ".$ref", JsonNull.defaultInstance())
                    : op("replace", M, JsonObject.builder().put("$ref", JsonNull.defaultInstance()).build());
            var result = apply(provider, resource(USER), request(provider, USER, List.of(write("replace", "child", "$ref", "Users/new"), clear, write("replace", "child", "value", "new"))));
            assertEquals(manager("new", null, null), manager(result.getResource()));
        }));
    }

    @TestFactory Stream<DynamicTest> managerAndExtensionRemovalCannotResurrectReferences() {
        return Stream.of("remove-manager", "null-manager", "remove-extension").map(shape -> DynamicTest.dynamicTest(shape, () -> {
            var provider = provider(USER, ROOT);
            JsonObject clear = shape.equals("remove-manager") ? op("remove", M, null) : shape.equals("null-manager") ? op("replace", M, JsonNull.defaultInstance()) : op("remove", E, null);
            var result = apply(provider, resource(USER), request(provider, USER, List.of(write("replace", "child", "$ref", "Users/new"), clear, write("replace", "manager", "value", "recreated"))));
            assertEquals(manager("recreated", null, null), manager(result.getResource()));
        }));
    }

    @Test void referenceProvenanceDoesNotCarryIntoAnotherPatchRequest() {
        var provider = provider(USER, ScimCompatibility.strictInstance()); var current = resource(USER);
        var first = apply(provider, current, request(provider, USER, List.of(write("replace", "child", "$ref", "Users/new")))).getResource();
        var second = apply(provider, first, request(provider, USER, List.of(write("replace", "child", "value", "new")))).getResource();
        assertEquals(manager("new", null, null), manager(second));
        assertEquals(manager("old", "Users/new", "Old Display"), manager(first));
    }

    @Test void cancellingNoOpInstructionsKeepTheSameResourceAndDisplay() {
        var provider = provider(USER, ScimCompatibility.strictInstance()); var current = resource(USER);
        var result = apply(provider, current, request(provider, USER, List.of(write("replace", "child", "$ref", "Users/old"), write("replace", "child", "value", "old"))));
        assertFalse(result.isModified()); assertSame(current, result.getResource()); assertEquals(manager("old", "Users/old", "Old Display"), manager(result.getResource()));
    }

    @Test void anotherExtensionCannotSupplyTheStandardManagerReference() {
        String other = "urn:test:other:User";
        var custom = ScimSchema.withId(other).name("Other").attributes(List.of(ScimAttributeDefinition.withName("manager").type(ScimAttributeType.COMPLEX).subAttributes(List.of(
                ScimAttributeDefinition.withName("value").build(), ScimAttributeDefinition.withName("$ref").type(ScimAttributeType.REFERENCE).build(),
                ScimAttributeDefinition.withName("displayName").mutability(ScimMutability.READ_ONLY).build())).build())).build();
        var type = ScimResourceType.withName("User").endpoint("/Users").schema(ScimSchema.userInstance()).schemaExtensions(List.of(
                ScimSchemaExtension.fromSchema(ScimSchema.enterpriseUserInstance(), false), ScimSchemaExtension.fromSchema(custom, false))).build();
        var fields = new java.util.LinkedHashMap<String, JsonValue>(resource(type).getDocument().getMembers());
        fields.put("schemas", JsonArray.fromElements(List.of(JsonString.fromValue(type.getSchema().getId()), JsonString.fromValue(E), JsonString.fromValue(other))));
        fields.put(other, JsonObject.builder().put("manager", manager("other-old", "Users/other-old", "Other Display")).build());
        var current = ScimResource.withResourceType(type).document(JsonObject.fromMembers(fields)).build(); var provider = provider(type, ScimCompatibility.strictInstance());
        var result = apply(provider, current, request(provider, type, List.of(op("replace", other + ":manager.$ref", JsonString.fromValue("Users/other-new")), write("replace", "child", "value", "new"))));
        assertEquals(manager("new", null, null), manager(result.getResource()));
        var otherManager = (JsonObject) result.getResource().getExtension(other).orElseThrow().find("manager").orElseThrow();
        assertEquals(manager("other-old", "Users/other-new", "Other Display"), otherManager);
    }

    @Test void aLateReadOnlyFailureKeepsTheOriginalAndExposesNoCandidate() {
        var provider = provider(USER, ScimCompatibility.strictInstance()); var current = resource(USER); var before = current.getDocument();
        var patch = request(provider, USER, List.of(write("replace", "child", "$ref", "Users/new"), write("replace", "child", "value", "new"), op("replace", M + ".displayName", JsonString.fromValue("forged"))));
        assertInstanceOf(ScimPatchApplicationResult.Rejected.class, provider.applyPatchResult(current, patch)); assertEquals(before, current.getDocument());
    }

    @Test void putHasNoPatchReferenceProvenance() {
        var provider = provider(USER, ScimCompatibility.strictInstance()); var current = resource(USER);
        var body = JsonObject.builder().put("schemas", schemas(USER)).put("userName", "Ada").put(E, JsonObject.builder().put("manager", manager("new", null, null)).build()).build();
        var candidate = assertInstanceOf(ScimResourceParseResult.Succeeded.class, provider.parseReplacementResult(USER, current, bytes(body))).getResource();
        assertEquals(manager("new", null, null), manager(candidate));
    }

    @Test void everyWorkCutoffRejectsAtomicallyBeforeTheFinalCoherentCandidate() {
        var provider = provider(USER, ScimCompatibility.strictInstance()); var current = resource(USER); var before = current.getDocument();
        var patch = request(provider, USER, List.of(write("replace", "manager", "$ref", "Users/new"), write("replace", "child", "value", "new")));
        long low = 0, high = 100_000; assertInstanceOf(ScimPatchApplicationResult.Succeeded.class, direct(current, patch, high));
        while (low < high) { long middle = (low + high) >>> 1; if (direct(current, patch, middle) instanceof ScimPatchApplicationResult.Succeeded) high = middle; else low = middle + 1; }
        for (long work = 0; work < low; work++) assertEquals(413, assertInstanceOf(ScimPatchApplicationResult.Rejected.class, direct(current, patch, work)).getError().getStatusCode(), "work cutoff " + work);
        var result = assertInstanceOf(ScimPatchApplicationResult.Succeeded.class, direct(current, patch, low)).getPatchResult();
        assertEquals(manager("new", "Users/new", null), manager(result.getResource())); assertEquals(before, current.getDocument());
    }

    private static ScimPatchApplicationResult direct(ScimResource current, ScimPatchRequest request, long work) { return ScimPatchEngine.apply(current, request, ScimCompatibility.strictInstance(), NO_MATCHING, new ScimWork(work), request.getSemanticContext(), EnumSet.noneOf(ScimCompatibilityFeature.class)); }
    private static JsonObject write(String kind, String shape, String field, String value) {
        if (shape.equals("child")) return op(kind, M + "." + field, JsonString.fromValue(value));
        var manager = JsonObject.builder().put(field, value).build();
        if (shape.equals("manager")) return op(kind, M, manager);
        var extension = JsonObject.builder().put("manager", manager).build();
        return shape.equals("root") ? op(kind, E, extension) : op(kind, null, JsonObject.builder().put(E, extension).build());
    }
    private static JsonObject op(String kind, @Nullable String path, @Nullable JsonValue value) { var b = JsonObject.builder().put("op", kind); if (path != null) b.put("path", path); if (value != null) b.put("value", value); return b.build(); }
    private static JsonObject manager(@Nullable String value, @Nullable String ref, @Nullable String display) { var b = JsonObject.builder(); if (value != null) b.put("value", value); if (ref != null) b.put("$ref", ref); if (display != null) b.put("displayName", display); return b.build(); }
    private static JsonObject manager(ScimResource resource) { return (JsonObject) resource.getExtension(E).orElseThrow().find("manager").orElseThrow(); }
    private static JsonArray schemas(ScimResourceType type) { return JsonArray.fromElements(List.of(JsonString.fromValue(type.getSchema().getId()), JsonString.fromValue(E))); }
    private static ScimResource resource(ScimResourceType type) { return ScimResource.withResourceType(type).document(JsonObject.builder().put("schemas", schemas(type)).put("userName", "Ada").put("id", "person").put("meta", JsonObject.builder().put("version", "W/\"one\"").build()).put(E, JsonObject.builder().put("manager", manager("old", "Users/old", "Old Display")).build()).build()).build(); }
    private static ScimServiceProvider provider(ScimResourceType type, ScimCompatibility compatibility) { return ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/")).resourceTypes(List.of(type)).stringMatching(NO_MATCHING).compatibility(compatibility).serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).build()).build(); }
    private static ScimPatchRequest request(ScimServiceProvider provider, ScimResourceType type, List<JsonObject> operations) { var body = JsonObject.builder().put("schemas", JsonArray.fromElements(List.of(JsonString.fromValue("urn:ietf:params:scim:api:messages:2.0:PatchOp")))).put("Operations", JsonArray.fromElements(operations)).build(); return assertInstanceOf(ScimPatchParseResult.Succeeded.class, provider.parsePatchRequestResult(type, bytes(body))).getPatchRequest(); }
    private static ScimPatchResult apply(ScimServiceProvider provider, ScimResource current, ScimPatchRequest patch) { return assertInstanceOf(ScimPatchApplicationResult.Succeeded.class, provider.applyPatchResult(current, patch)).getPatchResult(); }
    private static byte[] bytes(JsonObject value) { return value.toJson().getBytes(StandardCharsets.UTF_8); }
    private static Set<String> paths(Set<ScimAttributePath> values) { return values.stream().map(ScimAttributePath::toScimString).collect(java.util.stream.Collectors.toSet()); }
}
