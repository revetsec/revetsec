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

import org.jspecify.annotations.NonNull;

import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseResult;
import com.revetsec.json.*;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** Public-API regression fixture, identical on entry and repaired production. */
final class ScimValuelessMemberReplacementTests {
    private static final ScimResourceType GROUP = ScimResourceType.groupInstance();
    private static final ScimResourceType TEAM = ScimResourceType.withName("Team").endpoint("/Teams").schema(ScimSchema.groupInstance()).build();
    private static final ScimStringMatching NO_MATCHING = (path, definition, operator, left, right) -> {
        fail("Standard Group reconciliation cannot invoke application string matching"); return ScimStringMatchResult.unsupportedInstance();
    };

    @TestFactory @NonNull Stream<@NonNull DynamicTest> optionalAnonymousMembersNeverPreventClearingMembership() {
        return Stream.of(GROUP, TEAM).flatMap(type -> Stream.of("reference", "typed", "empty", "null-value")
                .flatMap(shape -> Stream.of("omitted", "null", "empty").map(clear -> DynamicTest.dynamicTest(type.getName() + " " + shape + " clear=" + clear, () -> {
            var current = resource(type, array(anonymous(shape, "saved"), assigned("a", true)));
            var before = current.getDocument();
            JsonValue next = clear.equals("omitted") ? null : clear.equals("null") ? JsonNull.defaultInstance() : array();
            var candidate = replace(type, current, next);
            assertEquals(clear.equals("empty"), candidate.getDocument().getMembers().containsKey("members"));
            if (clear.equals("empty")) assertEquals(array(), candidate.getDocument().getMembers().get("members"));
            assertEquals(before, current.getDocument()); assertEquals(current.getId(), candidate.getId()); assertEquals(current.getVersion(), candidate.getVersion());
        }))));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> reorderAndRemovalRetainOnlyMatchedMemberMetadata() {
        return Stream.of(GROUP, TEAM).flatMap(type -> Stream.of("reference", "typed", "empty", "null-value").map(shape ->
                DynamicTest.dynamicTest(type.getName() + " reorder " + shape, () -> {
            var oldAnonymous = anonymous(shape, "saved-anonymous");
            var current = resource(type, array(oldAnonymous, assigned("a", true), assigned("b", true)));
            var candidate = replace(type, current, array(assigned("b", false), writable(oldAnonymous), assigned("new", false)));
            assertEquals(assigned("b", true), rows(candidate).get(0));
            assertEquals(normalizedAnonymous(shape, "saved-anonymous"), rows(candidate).get(1));
            assertEquals(assigned("new", false), rows(candidate).get(2));
            assertEquals(3, rows(current).size()); assertEquals(current.getVersion(), candidate.getVersion());
        })));
    }

    @Test void duplicateAnonymousTuplesRetainOccurrencesOnceInCurrentOrder() {
        var first = reference("Users/a", "User", "first"); var second = reference("Users/a", "User", "second");
        var current = resource(GROUP, array(first, assigned("a", true), second));
        var supplied = reference("Users/a", "User", "forged");
        var candidate = replace(GROUP, current, array(supplied, assigned("a", false), supplied, supplied));
        assertEquals(List.of(first, assigned("a", true), second, writable(first)), rows(candidate));
        assertEquals(List.of(first, assigned("a", true), second), rows(current));
    }

    @Test void submittedDisplayCannotChooseWhichAnonymousOccurrenceSurvives() {
        var first = reference("Users/a", "User", "first"); var second = reference("Users/a", "User", "second");
        var current = resource(GROUP, array(first, second));
        var candidate = replace(GROUP, current, array(second));
        assertEquals(List.of(first), rows(candidate));
    }

    @Test void changingAnAnonymousTupleReplacesTheRowWithoutTransferringMetadata() {
        var current = resource(GROUP, array(reference("Users/a", "User", "old"), assigned("a", true)));
        for (String ref : List.of("Users/a", "Groups/b")) {
            var fresh = reference(ref, "Group", "forged");
            var candidate = replace(GROUP, current, array(fresh, assigned("a", false)));
            assertEquals(List.of(writable(fresh), assigned("a", true)), rows(candidate));
        }
    }

    @Test void referenceSpellingIsExactAndNotNormalizedIntoAnotherTuple() {
        var upper = reference("Users/A", "User", "upper"); var lower = reference("Users/a", "User", "lower");
        var escaped = reference("Users/%61", "User", "escaped");
        var current = resource(GROUP, array(upper, lower, escaped));
        var candidate = replace(GROUP, current, array(writable(escaped), writable(upper), writable(lower)));
        assertEquals(List.of(escaped, upper, lower), rows(candidate));
    }

    @Test void tupleFieldBoundariesCannotCollide() {
        var first = reference("Users/a", "Group", "first"); var second = reference("Users/aGroup", null, "second");
        var typeOnly = JsonObject.builder().put("type", "User").put("display", "type-only").build();
        var referenceOnly = reference("User", null, "reference-only");
        var current = resource(GROUP, array(first, second, typeOnly, referenceOnly));
        assertEquals(List.of(referenceOnly, typeOnly, second, first), rows(replace(GROUP, current,
                array(writable(referenceOnly), writable(typeOnly), writable(second), writable(first)))));
    }

    @Test void anAssignedIdCannotBorrowAnonymousMetadataWithTheSameReference() {
        var current = resource(GROUP, array(reference("Users/a", "User", "anonymous")));
        var supplied = JsonObject.builder().put("value", "a").put("$ref", "Users/a").put("type", "User").build();
        assertEquals(List.of(supplied), rows(replace(GROUP, current, array(supplied))));
    }

    @Test void anonymousInputCannotBorrowAssignedMetadataWithTheSameReference() {
        var current = resource(GROUP, array(assigned("a", true)));
        var supplied = reference("Users/a", "User", null);
        assertEquals(List.of(supplied), rows(replace(GROUP, current, array(supplied))));
    }

    @Test void omittedAnonymousWritableFieldsCannotBeInferredFromOtherRows() {
        var current = resource(GROUP, array(reference("Users/a", "User", "old")));
        var supplied = JsonObject.builder().put("type", "User").build();
        assertEquals(List.of(supplied), rows(replace(GROUP, current, array(supplied))));
    }

    @Test void anonymousNullFieldsNormalizeToAbsentBeforeMatching() {
        var current = resource(GROUP, array(JsonObject.builder().put("display", "saved").build()));
        var supplied = JsonObject.builder().put("value", JsonNull.defaultInstance()).put("$ref", JsonNull.defaultInstance()).put("type", JsonNull.defaultInstance()).build();
        assertEquals(List.of(JsonObject.builder().put("display", "saved").build()), rows(replace(GROUP, current, array(supplied))));
    }

    @Test void removalAndLaterRecreationCannotResurrectAnonymousMetadata() {
        var current = resource(GROUP, array(reference("Users/a", "User", "old"), assigned("a", true)));
        var provider = provider(GROUP, 4_000_000);
        var removed = accepted(provider.parseReplacementResult(GROUP, current, bytes(GROUP, array(assigned("a", false)))));
        var supplied = reference("Users/a", "User", null);
        var recreated = accepted(provider.parseReplacementResult(GROUP, removed, bytes(GROUP, array(supplied, assigned("a", false)))));
        assertEquals(List.of(supplied, assigned("a", true)), rows(recreated));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> assignedSurvivorsKeepTheirImmutableChecksInMixedArrays() {
        return Stream.of("type", "$ref").flatMap(field -> Stream.of(false, true).map(clear -> DynamicTest.dynamicTest(field + " clear=" + clear, () -> {
            var current = resource(GROUP, array(reference("Users/anonymous", "User", "saved"), assigned("a", true)));
            var changed = JsonObject.builder().put("value", "a").put(field, clear ? JsonNull.defaultInstance() : JsonString.fromValue(field.equals("type") ? "Group" : "Users/b")).build();
            var result = provider(GROUP, 4_000_000).parseReplacementResult(GROUP, current, bytes(GROUP, array(reference("Users/anonymous", "User", null), changed)));
            var rejected = assertInstanceOf(ScimResourceParseResult.Rejected.class, result);
            assertEquals(ScimErrorType.MUTABILITY, rejected.getError().getErrorType().orElseThrow());
            assertEquals(assigned("a", true), rows(current).get(1));
        })));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> invalidMemberFieldsStillRejectBeforeReconciliation() {
        return Stream.of(JsonObject.builder().put("value", "").build(), JsonObject.builder().put("value", true).build(),
                JsonObject.builder().put("$ref", 1L).build(), JsonObject.builder().put("type", 1L).build()).map(invalid -> DynamicTest.dynamicTest(invalid.toJson(), () -> {
            var current = resource(GROUP, array(reference("Users/a", "User", "saved")));
            var result = provider(GROUP, 4_000_000).parseReplacementResult(GROUP, current, bytes(GROUP, array(invalid)));
            assertEquals(ScimErrorType.INVALID_VALUE, assertInstanceOf(ScimResourceParseResult.Rejected.class, result).getError().getErrorType().orElseThrow());
        }));
    }

    @Test void duplicateAssignedIdsStillRejectInAMixedCandidate() {
        var current = resource(GROUP, array(reference("Users/a", "User", "saved")));
        var result = provider(GROUP, 4_000_000).parseReplacementResult(GROUP, current, bytes(GROUP, array(assigned("a", false), assigned("a", false))));
        assertEquals(ScimErrorType.INVALID_VALUE, assertInstanceOf(ScimResourceParseResult.Rejected.class, result).getError().getErrorType().orElseThrow());
    }

    @Test void customSchemaProtectedArraysKeepTheirExistingReplacementRules() {
        var type = ScimResourceType.withName("Custom").endpoint("/Custom").schema(ScimSchema.withId("urn:test:anonymous").name("Custom")
                .attributes(List.of(ScimAttributeDefinition.withName("members").type(ScimAttributeType.COMPLEX).multiValued(true).subAttributes(List.of(
                        ScimAttributeDefinition.withName("value").mutability(ScimMutability.IMMUTABLE).build(),
                        ScimAttributeDefinition.withName("display").mutability(ScimMutability.READ_ONLY).build())).build())).build()).build();
        var current = ScimResource.withResourceType(type).document(JsonObject.builder().put("schemas", schemas(type)).put("members", array(JsonObject.builder().put("value", "a").put("display", "saved").build())).build()).build();
        byte[] body = JsonObject.builder().put("schemas", schemas(type)).put("members", array()).build().toJson().getBytes(StandardCharsets.UTF_8);
        var result = provider(type, 4_000_000).parseReplacementResult(type, current, body);
        assertEquals(ScimErrorType.MUTABILITY, assertInstanceOf(ScimResourceParseResult.Rejected.class, result).getError().getErrorType().orElseThrow());
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> mixedMembershipFitsExplicitUnchangedWorkProfiles() {
        return Stream.of(GROUP, TEAM).flatMap(type -> Stream.of(1000, 3000).map(size -> DynamicTest.dynamicTest(type.getName() + " count=" + size, () -> {
            List<JsonValue> old = mixed(size, true); List<JsonValue> supplied = mixed(size, false); Collections.reverse(supplied);
            var current = resource(type, JsonArray.fromElements(old));
            var candidate = accepted(provider(type, size == 1000 ? 4_000_000 : 10_000_000).parseReplacementResult(type, current, bytes(type, JsonArray.fromElements(supplied))));
            Collections.reverse(old); assertEquals(old, rows(candidate));
        })));
    }

    @Test void mixedReplacementHasSubquadraticChargedWorkGrowth() throws Exception {
        long a = minimum(64), b = minimum(128), c = minimum(256);
        java.nio.file.Files.writeString(java.nio.file.Path.of("target/valueless-put-work.txt"), a + "," + b + "," + c);
        assertTrue(b * 10 <= a * 28); assertTrue(c * 10 <= b * 28);
    }

    @Test void everyMixedCandidateWorkCutoffRejectsWith413AndNoPartialCandidate() {
        var current = resource(GROUP, JsonArray.fromElements(mixed(4, true))); var before = current.getDocument();
        var supplied = JsonArray.fromElements(mixed(4, false)); long minimum = minimum(4);
        for (long budget = 0; budget < minimum; budget++) {
            var result = direct(current, supplied, budget);
            assertEquals(413, assertInstanceOf(ScimResourceParseResult.Rejected.class, result).getError().getStatusCode(), "work cutoff " + budget);
        }
        assertEquals(before, accepted(direct(current, supplied, minimum)).getDocument()); assertEquals(before, current.getDocument());
    }

    private static long minimum(int size) {
        var current = resource(GROUP, JsonArray.fromElements(mixed(size, true))); var supplied = JsonArray.fromElements(mixed(size, false));
        long low = 0, high = 10_000_000; assertInstanceOf(ScimResourceParseResult.Succeeded.class, direct(current, supplied, high));
        while (low < high) { long middle = (low + high) >>> 1; if (direct(current, supplied, middle) instanceof ScimResourceParseResult.Succeeded) high = middle; else low = middle + 1; }
        return low;
    }
    private static @NonNull ScimResourceParseResult direct(@NonNull ScimResource current, @NonNull JsonArray supplied, long work) {
        var parsed = assertInstanceOf(JsonParseResult.Succeeded.class, JsonCodec.parseResult(bytes(GROUP, supplied), JsonLimits.scim(1_000_000, 100_000))).getDocument();
        return ScimResources.replace(GROUP, current, parsed, ScimCompatibility.strictInstance(), new ScimWork(work), new Object());
    }
    private static @NonNull List<@NonNull JsonValue> mixed(int size, boolean metadata) {
        List<JsonValue> values = new ArrayList<>();
        for (int i = 0; i < size; i++) { String id = "m" + Integer.toString(i, 36); values.add(i % 2 == 0 ? assigned(id, metadata) : reference("Users/" + id, "User", metadata ? "saved:" + id : null)); }
        return values;
    }
    private static @NonNull JsonObject anonymous(@NonNull String shape, @Nullable String display) {
        var row = JsonObject.builder();
        if (shape.equals("reference") || shape.equals("typed")) row.put("$ref", "Users/anonymous");
        if (shape.equals("typed")) row.put("type", "User");
        if (shape.equals("null-value")) row.put("value", JsonNull.defaultInstance());
        if (display != null) row.put("display", display);
        return row.build();
    }
    private static @NonNull JsonObject normalizedAnonymous(@NonNull String shape, @NonNull String display) { return shape.equals("null-value") ? anonymous("empty", display) : anonymous(shape, display); }
    private static @NonNull JsonObject reference(@NonNull String ref, @Nullable String type, @Nullable String display) { var b = JsonObject.builder().put("$ref", ref); if (type != null) b.put("type", type); if (display != null) b.put("display", display); return b.build(); }
    private static @NonNull JsonObject assigned(@NonNull String id, boolean metadata) { var b = JsonObject.builder().put("value", id); if (metadata) b.put("type", "User").put("$ref", "Users/" + id).put("display", "saved:" + id); return b.build(); }
    private static @NonNull JsonObject writable(@NonNull JsonObject row) { var fields = new LinkedHashMap<String, JsonValue>(row.getMembers()); fields.remove("display"); return JsonObject.fromMembers(fields); }
    private static @NonNull JsonArray array(@NonNull JsonValue @NonNull ... rows) { return JsonArray.fromElements(List.of(rows)); }
    private static @NonNull JsonArray schemas(@NonNull ScimResourceType type) { return JsonArray.fromElements(List.of(JsonString.fromValue(type.getSchema().getId()))); }
    private static byte @NonNull [] bytes(@NonNull ScimResourceType type, @Nullable JsonValue members) { var body = JsonObject.builder().put("schemas", schemas(type)).put("displayName", "Team"); if (members != null) body.put("members", members); return body.build().toJson().getBytes(StandardCharsets.UTF_8); }
    private static @NonNull ScimResource resource(@NonNull ScimResourceType type, @NonNull JsonArray members) { return ScimResource.withResourceType(type).limits(ScimLimits.builder().maximumWorkUnits(10_000_000).build()).document(JsonObject.builder().put("schemas", schemas(type)).put("displayName", "Team").put("id", "group1").put("members", members).put("meta", JsonObject.builder().put("version", "W/\"one\"").build()).build()).build(); }
    private static @NonNull ScimResource replace(@NonNull ScimResourceType type, @NonNull ScimResource current, @Nullable JsonValue members) { return accepted(provider(type, 4_000_000).parseReplacementResult(type, current, bytes(type, members))); }
    private static @NonNull ScimResource accepted(@NonNull ScimResourceParseResult result) { return assertInstanceOf(ScimResourceParseResult.Succeeded.class, result).getResource(); }
    private static @NonNull List<@NonNull JsonValue> rows(@NonNull ScimResource resource) { return ((JsonArray) resource.getDocument().find("members").orElseThrow()).getElements(); }
    private static @NonNull ScimServiceProvider provider(@NonNull ScimResourceType type, int work) { return ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/")).resourceTypes(List.of(type)).stringMatching(NO_MATCHING).limits(ScimLimits.builder().maximumWorkUnits(work).build()).build(); }
}
