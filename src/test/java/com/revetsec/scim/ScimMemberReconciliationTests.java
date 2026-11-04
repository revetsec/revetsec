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
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseResult;
import com.revetsec.json.*;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

final class ScimMemberReconciliationTests {
    private static final ScimResourceType GROUP = ScimResourceType.groupInstance();
    private static final ScimResourceType TEAM = ScimResourceType.withName("Team").endpoint("/Teams").schema(ScimSchema.groupInstance()).build();
    private static final ScimCompatibility COMPAT = ScimCompatibility.builder().features(Set.of(ScimCompatibilityFeature.PATCH_REMOVE_WITH_VALUE)).build();
    private static final ScimStringMatching NO_STRATEGY = (path, definition, operator, left, right) -> {
        fail("Standard Group member IDs must not use application matching"); return ScimStringMatchResult.unsupportedInstance();
    };

    @TestFactory Stream<DynamicTest> largeStableMembershipOperationsFitTheirUnchangedProfiles() {
        return Stream.of("PUT", "REPLACE", "ADD", "REMOVE").flatMap(action -> Stream.of(3000, 4000)
                .flatMap(size -> Stream.of(GROUP, TEAM).map(type -> DynamicTest.dynamicTest(
                        action + " size=" + size + " type=" + type.getName(), () -> {
            int budget = size == 3000 ? 4_000_000 : 10_000_000;
            var provider = provider(type, budget);
            List<String> oldIds = ids(0, size);
            ScimResource current = resource(type, members(oldIds, true));
            String original = current.getDocument().toJson();
            List<String> supplied = supplied(action, size);
            List<String> expected = expected(action, oldIds, supplied);
            ScimResource candidate = apply(provider, current, action, members(supplied, false));
            assertIdsAndMetadata(candidate, expected, oldIds);
            assertEquals(original, current.getDocument().toJson());
            assertEquals(current.getVersion(), candidate.getVersion());
        }))));
    }

    @TestFactory Stream<DynamicTest> aggregateWorkGrowthIsSubquadraticInStableMemberCount() {
        return Stream.of("PUT", "REPLACE", "ADD", "REMOVE").map(action -> DynamicTest.dynamicTest("charged work " + action, () -> {
            long small = minimum(action, 64), medium = minimum(action, 128), large = minimum(action, 256);
            java.nio.file.Files.writeString(java.nio.file.Path.of("target/member-work-" + action + ".txt"), small + "," + medium + "," + large);
            assertTrue(medium * 10 <= small * 28, action + " 64->128: " + small + " -> " + medium);
            assertTrue(large * 10 <= medium * 28, action + " 128->256: " + medium + " -> " + large);
        }));
    }

    @TestFactory Stream<DynamicTest> commonPrefixAndHashCollisionIdsKeepExactIdentity() {
        return Stream.of("PUT", "REPLACE", "ADD", "REMOVE").map(action -> DynamicTest.dynamicTest("collision " + action, () -> {
            List<String> keys = new ArrayList<>();
            for (int i = 0; i < 512; i++) {
                StringBuilder id = new StringBuilder();
                for (int bit = 0; bit < 9; bit++) id.append((i & (1 << bit)) == 0 ? "Aa" : "BB");
                keys.add(id.toString());
            }
            assertEquals(1, keys.stream().map(String::hashCode).distinct().count());
            var current = resource(GROUP, members(keys, true));
            List<String> supplied = new ArrayList<>(keys); Collections.reverse(supplied);
            if (action.equals("ADD")) supplied = List.of(keys.get(100), keys.get(300), "new-id");
            if (action.equals("REMOVE")) supplied = keys.subList(0, 256);
            ScimResource candidate = apply(provider(GROUP, 4_000_000), current, action, members(supplied, false));
            assertIdsAndMetadata(candidate, expected(action, keys, supplied), keys);
        }));
    }

    @TestFactory Stream<DynamicTest> exhaustionAtTheCommitBoundaryNeverPublishesAPartialCandidate() {
        return Stream.of("PUT", "REPLACE", "ADD", "REMOVE").map(action -> DynamicTest.dynamicTest("work boundary " + action, () -> {
            var current = resource(GROUP, members(ids(0, 32), true));
            String original = current.getDocument().toJson();
            long minimum = minimum(action, 32);
            for (long budget : new long[] {0, minimum - 1}) {
                Object result = direct(current, action, members(supplied(action, 32), false), budget);
                ScimError error = result instanceof ScimResourceParseResult.Rejected rejected ? rejected.getError()
                        : assertInstanceOf(ScimPatchApplicationResult.Rejected.class, result).getError();
                assertEquals(413, error.getStatusCode());
                assertEquals(original, current.getDocument().toJson());
            }
            assertTrue(succeeded(direct(current, action, members(supplied(action, 32), false), minimum)));
            // Cross every phase boundary in a small real candidate, not only the final cutoff.
            var small = resource(GROUP, members(ids(0, 2), true));
            String smallOriginal = small.getDocument().toJson();
            var smallSupplied = members(supplied(action, 2), false);
            long smallMinimum = minimum(action, 2);
            for (long budget = 0; budget < smallMinimum; budget++) {
                Object result = direct(small, action, smallSupplied, budget);
                ScimError error = result instanceof ScimResourceParseResult.Rejected rejected ? rejected.getError()
                        : assertInstanceOf(ScimPatchApplicationResult.Rejected.class, result).getError();
                assertEquals(413, error.getStatusCode(), action + " phase cutoff " + budget);
            }
            assertTrue(succeeded(direct(small, action, smallSupplied, smallMinimum)));
            assertEquals(smallOriginal, small.getDocument().toJson());
        }));
    }

    @TestFactory Stream<DynamicTest> immutableSurvivorsCannotBeChangedEvenByAddExisting() {
        return Stream.of("PUT", "REPLACE", "ADD").flatMap(action -> Stream.of("type", "$ref").map(field ->
                DynamicTest.dynamicTest("immutable " + action + " " + field, () -> {
            var current = resource(GROUP, members(List.of("a"), true));
            var changed = JsonObject.builder().put("value", "a").put(field, field.equals("type") ? "Group" : "Users/other").build();
            assertError(provider(GROUP, 4_000_000), current, action, JsonArray.fromElements(List.of(changed)), ScimErrorType.MUTABILITY);
            assertEquals("Saved:a", member(current, 0).find("display").filter(JsonString.class::isInstance).map(JsonString.class::cast).orElseThrow().getValue());
        })));
    }

    @Test void exactCaseAndUnicodeIdsDoNotInheritAStringMatchingProfile() {
        List<String> keys = List.of("a", "A", "é", "e\u0301");
        var current = resource(GROUP, members(keys, true));
        ScimResource candidate = apply(provider(GROUP, 4_000_000), current, "REPLACE", members(List.of("A", "a", "e\u0301", "é", "new"), false));
        assertIdsAndMetadata(candidate, List.of("A", "a", "e\u0301", "é", "new"), keys);
    }

    @Test void removalThenRecreationDoesNotResurrectOldMetadataAndIndexesSeeEarlierSteps() {
        var provider = provider(GROUP, 4_000_000);
        var current = resource(GROUP, members(List.of("a"), true));
        var request = request(provider, GROUP, List.of(operation("remove", null), operation("add", members(List.of("a"), false)),
                operation("add", JsonArray.fromElements(List.of(JsonObject.builder().put("value", "b").put("type", "Group").put("$ref", "Groups/b").build()))),
                operation("replace", members(List.of("b", "a"), false))));
        ScimResource next = assertInstanceOf(ScimPatchApplicationResult.Succeeded.class, provider.applyPatchResult(current, request)).getPatchResult().getResource();
        assertEquals(List.of("b", "a"), values(next));
        assertEquals("Group", member(next, 0).find("type").filter(JsonString.class::isInstance).map(JsonString.class::cast).orElseThrow().getValue());
        assertFalse(member(next, 1).getMembers().containsKey("display"));
        assertFalse(member(next, 1).getMembers().containsKey("$ref"));
        assertIdsAndMetadata(current, List.of("a"), List.of("a"));
    }

    @Test void aLateFailureKeepsTheOriginalAndNoOpKeepsTheSameResource() {
        var provider = provider(GROUP, 4_000_000);
        var current = resource(GROUP, members(List.of("a"), true));
        var noop = assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,
                provider.applyPatchResult(current, request(provider, GROUP, List.of(operation("replace", members(List.of("a"), false)))))).getPatchResult();
        assertFalse(noop.isModified()); assertSame(current, noop.getResource());
        assertFalse(noop.getRequestedAttributePaths().isEmpty());
        var absentFields = new java.util.LinkedHashMap<String, JsonValue>(current.getDocument().getMembers());
        absentFields.remove("members");
        var absent = ScimResource.withResourceType(GROUP).document(JsonObject.fromMembers(absentFields)).build();
        var absentNoop = assertInstanceOf(ScimPatchApplicationResult.Succeeded.class, provider.applyPatchResult(absent,
                request(provider, GROUP, List.of(operation("remove", members(List.of("a"), false)))))).getPatchResult();
        assertFalse(absentNoop.isModified(), "removing an ID from absent membership must not create an empty attribute");
        assertSame(absent, absentNoop.getResource());
        var invalid = JsonArray.fromElements(List.of(JsonObject.builder().put("value", "a").put("type", "Group").build()));
        assertInstanceOf(ScimPatchApplicationResult.Rejected.class, provider.applyPatchResult(current,
                request(provider, GROUP, List.of(operation("add", members(List.of("b"), false)), operation("replace", invalid)))));
        assertIdsAndMetadata(current, List.of("a"), List.of("a"));
    }

    @Test void patchAndPutKeepTheirDifferentExplicitNullReferenceRules() {
        var provider = provider(GROUP, 4_000_000);
        var current = resource(GROUP, members(List.of("a"), true));
        var nullRef = JsonArray.fromElements(List.of(JsonObject.builder().put("value", "a").put("$ref", JsonNull.defaultInstance()).build()));
        assertError(provider, current, "PUT", nullRef, ScimErrorType.MUTABILITY);
        assertIdsAndMetadata(apply(provider, current, "REPLACE", nullRef), List.of("a"), List.of("a"));
    }

    @Test void duplicateAssignedIdsStillRejectAndEmptyReplacementStillClears() {
        var provider = provider(GROUP, 4_000_000);
        var current = resource(GROUP, members(List.of("a", "b"), true));
        var duplicate = members(List.of("a", "a"), false);
        assertInstanceOf(ScimPatchParseResult.Rejected.class, provider.parsePatchRequestResult(GROUP, patch(List.of(operation("replace", duplicate))).toJson().getBytes(StandardCharsets.UTF_8)));
        assertError(provider, current, "PUT", duplicate, ScimErrorType.INVALID_VALUE);
        for (String action : List.of("PUT", "REPLACE")) assertTrue(values(apply(provider, current, action, JsonArray.fromElements(List.of()))).isEmpty());
    }

    @Test void valuelessPatchFallbackAndPutRemovalRemainSupported() {
        var provider = provider(GROUP, 4_000_000);
        var current = resource(GROUP, JsonArray.fromElements(List.of(JsonObject.builder().put("$ref", "Users/a").build())));
        var request = request(provider, GROUP, List.of(operation("add", JsonArray.fromElements(List.of(JsonObject.builder().put("$ref", "Users/b").build())))));
        ScimResource next = assertInstanceOf(ScimPatchApplicationResult.Succeeded.class, provider.applyPatchResult(current, request)).getPatchResult().getResource();
        assertEquals(2, ((JsonArray) next.getDocument().find("members").orElseThrow()).getElements().size());
        var mixed = resource(GROUP, JsonArray.fromElements(List.of(JsonObject.builder().put("$ref", "Users/a").build(), JsonObject.builder().put("value", "b").build())));
        var retained = apply(provider, mixed, "REMOVE", members(List.of("b"), false));
        var remaining = (JsonArray) retained.getDocument().find("members").orElseThrow();
        assertEquals(1, remaining.getElements().size());
        assertEquals("Users/a", ((JsonString) ((JsonObject) remaining.getElements().get(0)).find("$ref").orElseThrow()).getValue());
        // PUT can remove an anonymous row without blocking a different assigned member.
        assertIdsAndMetadata(apply(provider, current, "PUT", members(List.of("b"), false)), List.of("b"), List.of());
    }

    @Test void customMemberLikeArraysStillUseTheirApplicationEquivalence() {
        ScimResourceType custom = ScimResourceType.withName("Custom").endpoint("/Custom")
                .schema(ScimSchema.withId("urn:test:custom-members").name("Custom").attributes(List.of(
                        ScimAttributeDefinition.withName("members").type(ScimAttributeType.COMPLEX).multiValued(true)
                                .subAttributes(List.of(ScimAttributeDefinition.withName("value").build())).build())).build()).build();
        var calls = new java.util.concurrent.atomic.AtomicInteger();
        var provider = ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
                .resourceTypes(List.of(custom)).stringMatching((path, definition, operator, left, right) -> {
                    calls.incrementAndGet(); return ScimStringMatchResult.fromMatched(left.equalsIgnoreCase(right));
                }).serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).build()).build();
        var current = ScimResource.withResourceType(custom).document(JsonObject.builder().put("schemas", strings(List.of(custom.getSchema().getId())))
                .put("members", members(List.of("a"), false)).build()).build();
        var result = assertInstanceOf(ScimPatchApplicationResult.Succeeded.class, provider.applyPatchResult(current,
                request(provider, custom, List.of(operation("add", members(List.of("A"), false)))))).getPatchResult();
        assertFalse(result.isModified()); assertSame(current, result.getResource());
        assertEquals(List.of("a"), values(result.getResource())); assertTrue(calls.get() > 0);
    }

    @Test void reducedReplacePreservesItsRequestedIdOrderAndFullEvaluationMetadataContract() {
        var provider = provider(GROUP, 4_000_000);
        var current = resource(GROUP, members(List.of("a", "b"), true));
        var request = request(provider, GROUP, List.of(operation("replace", members(List.of("b", "a"), false))));
        var reduction = assertInstanceOf(ScimMembershipPatchResult.Reduced.class, provider.reduceMembershipPatchResult(request)).getMembershipPatch();
        assertEquals(ScimMembershipPatch.Kind.REPLACE_IDS, reduction.getSteps().get(0).getKind());
        assertEquals(List.of("b", "a"), reduction.getSteps().get(0).getValues());
        assertIdsAndMetadata(assertInstanceOf(ScimPatchApplicationResult.Succeeded.class, provider.applyPatchResult(current, request)).getPatchResult().getResource(), List.of("b", "a"), List.of("a", "b"));
    }

    private static long minimum(String action, int size) {
        var current = resource(GROUP, members(ids(0, size), true));
        var supplied = members(supplied(action, size), false);
        long low = 0, high = 4_000_000;
        assertTrue(succeeded(direct(current, action, supplied, high)));
        while (low < high) {
            long middle = (low + high) >>> 1;
            if (succeeded(direct(current, action, supplied, middle))) high = middle; else low = middle + 1;
        }
        return low;
    }
    private static Object direct(ScimResource current, String action, JsonArray supplied, long budget) {
        if (action.equals("PUT")) {
            var parsed = assertInstanceOf(JsonParseResult.Succeeded.class, JsonCodec.parseResult(document(current.getResourceType(), supplied).toJson().getBytes(StandardCharsets.UTF_8), JsonLimits.scim(1_000_000, 100_000))).getDocument();
            return ScimResources.replace(current.getResourceType(), current, parsed, COMPAT, new ScimWork(budget), new Object());
        }
        var provider = provider(current.getResourceType(), 4_000_000);
        var request = request(provider, current.getResourceType(), List.of(operation(action.toLowerCase(java.util.Locale.ROOT), supplied)));
        return ScimPatchEngine.apply(current, request, COMPAT, NO_STRATEGY, new ScimWork(budget), request.getSemanticContext(), EnumSet.noneOf(ScimCompatibilityFeature.class));
    }
    private static boolean succeeded(Object result) { return result instanceof ScimResourceParseResult.Succeeded || result instanceof ScimPatchApplicationResult.Succeeded; }
    private static ScimResource apply(ScimServiceProvider provider, ScimResource current, String action, JsonArray supplied) {
        if (action.equals("PUT")) return assertInstanceOf(ScimResourceParseResult.Succeeded.class,
                provider.parseReplacementResult(current.getResourceType(), current, document(current.getResourceType(), supplied).toJson().getBytes(StandardCharsets.UTF_8))).getResource();
        return assertInstanceOf(ScimPatchApplicationResult.Succeeded.class, provider.applyPatchResult(current,
                request(provider, current.getResourceType(), List.of(operation(action.toLowerCase(java.util.Locale.ROOT), supplied))))).getPatchResult().getResource();
    }
    private static void assertError(ScimServiceProvider provider, ScimResource current, String action, JsonArray supplied, ScimErrorType expected) {
        ScimError error;
        if (action.equals("PUT")) error = assertInstanceOf(ScimResourceParseResult.Rejected.class,
                provider.parseReplacementResult(current.getResourceType(), current, document(current.getResourceType(), supplied).toJson().getBytes(StandardCharsets.UTF_8))).getError();
        else error = assertInstanceOf(ScimPatchApplicationResult.Rejected.class, provider.applyPatchResult(current,
                request(provider, current.getResourceType(), List.of(operation(action.toLowerCase(java.util.Locale.ROOT), supplied))))).getError();
        assertEquals(expected, error.getErrorType().orElseThrow());
    }
    private static JsonObject operation(String action, @org.jspecify.annotations.Nullable JsonArray values) {
        var object = JsonObject.builder().put("op", action).put("path", "members");
        if (values != null) object.put("value", values);
        return object.build();
    }
    private static JsonObject patch(List<JsonObject> operations) { return JsonObject.builder().put("schemas", strings(List.of("urn:ietf:params:scim:api:messages:2.0:PatchOp"))).put("Operations", JsonArray.fromElements(operations)).build(); }
    private static ScimPatchRequest request(ScimServiceProvider provider, ScimResourceType type, List<JsonObject> operations) { return assertInstanceOf(ScimPatchParseResult.Succeeded.class, provider.parsePatchRequestResult(type, patch(operations).toJson().getBytes(StandardCharsets.UTF_8))).getPatchRequest(); }
    private static ScimServiceProvider provider(ScimResourceType type, int work) { return ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/"))
            .resourceTypes(List.of(type)).limits(ScimLimits.builder().maximumWorkUnits(work).build()).compatibility(COMPAT).stringMatching(NO_STRATEGY)
            .serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).build()).build(); }
    private static JsonObject document(ScimResourceType type, JsonArray members) { return JsonObject.builder().put("schemas", strings(List.of(type.getSchema().getId()))).put("displayName", "Team").put("members", members).build(); }
    private static ScimResource resource(ScimResourceType type, JsonArray members) {
        var fields = new java.util.LinkedHashMap<String, JsonValue>(document(type, members).getMembers());
        fields.put("id", JsonString.fromValue("group1"));
        fields.put("meta", JsonObject.builder().put("version", "W/\"one\"").build());
        return ScimResource.withResourceType(type).limits(ScimLimits.builder().maximumWorkUnits(10_000_000).build())
                .document(JsonObject.fromMembers(fields)).build();
    }
    private static JsonArray members(List<String> ids, boolean metadata) { List<JsonValue> values = new ArrayList<>(); for (String id : ids) {
        var member = JsonObject.builder().put("value", id);
        if (metadata) member.put("type", "User").put("$ref", URI.create("Users/" + id).toASCIIString()).put("display", "Saved:" + id);
        values.add(member.build());
    } return JsonArray.fromElements(values); }
    private static JsonArray strings(List<String> values) { return JsonArray.fromElements(values.stream().map(JsonString::fromValue).toList()); }
    private static List<String> ids(int start, int size) { List<String> values = new ArrayList<>(); for (int i = 0; i < size; i++) values.add("m" + Integer.toString(start + i, 36)); return values; }
    private static List<String> supplied(String action, int size) {
        List<String> values = new ArrayList<>();
        if (action.equals("ADD")) { values.addAll(ids(0, size / 2)); values.addAll(ids(size, size / 2)); }
        else if (action.equals("REMOVE")) { for (int i = 0; i < size; i += 2) values.add("m" + Integer.toString(i, 36)); }
        else { values.addAll(ids(0, size)); Collections.reverse(values); }
        return values;
    }
    private static List<String> expected(String action, List<String> old, List<String> supplied) {
        if (action.equals("PUT") || action.equals("REPLACE")) return supplied;
        List<String> values = new ArrayList<>(old);
        if (action.equals("REMOVE")) values.removeAll(supplied);
        else for (String value : supplied) if (!values.contains(value)) values.add(value);
        return values;
    }
    private static List<String> values(ScimResource resource) { var array = (JsonArray) resource.getDocument().find("members").orElseThrow(); return array.getElements().stream().map(JsonObject.class::cast).map(object -> ((JsonString) object.find("value").orElseThrow()).getValue()).toList(); }
    private static JsonObject member(ScimResource resource, int index) { return (JsonObject) ((JsonArray) resource.getDocument().find("members").orElseThrow()).getElements().get(index); }
    private static void assertIdsAndMetadata(ScimResource resource, List<String> expected, List<String> old) {
        assertEquals(expected, values(resource));
        for (int i = 0; i < expected.size(); i++) { String id = expected.get(i); JsonObject row = member(resource, i);
            if (old.contains(id)) { assertTrue(row.getMembers().keySet().containsAll(List.of("display", "type", "$ref")), "surviving member must retain protected metadata: " + id); assertEquals("Saved:" + id, ((JsonString) row.find("display").orElseThrow()).getValue()); assertEquals("User", ((JsonString) row.find("type").orElseThrow()).getValue()); assertEquals(URI.create("Users/" + id).toASCIIString(), ((JsonString) row.find("$ref").orElseThrow()).getValue()); }
            else { assertFalse(row.getMembers().containsKey("display")); assertFalse(row.getMembers().containsKey("$ref")); }
        }
    }
}
