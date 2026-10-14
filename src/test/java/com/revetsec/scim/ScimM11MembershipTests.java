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

import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ScimM11MembershipTests {
    @Test void orderedStepsRetainInputIdsOriginalIndexesAndSeparateRemainderProvenance() {
        Object context = new Object();
        ScimPatchOperation add = operation(0, ScimPatchOperationType.ADD, "members", null,
                JsonArray.fromElements(List.of(member("Private-B"), member("Private-A"), member("Private-B"))));
        ScimPatchOperation rename = operation(1, ScimPatchOperationType.REPLACE, "displayName", null,
                JsonString.fromValue("Private Group"));
        ScimPatchOperation remove = operation(2, ScimPatchOperationType.REMOVE, "members",
                filter("value eq \"Private-A\""), null);
        ScimPatchOperation clear = operation(3, ScimPatchOperationType.REMOVE, "members", null, null);
        ScimPatchOperation replace = operation(4, ScimPatchOperationType.REPLACE, "members", null,
                JsonArray.fromElements(List.of(member("Private-C"), member("Private-B"))));
        Set<ScimAttributePath> requested = Set.of(path("members"), path("members.value"), path("displayName"));
        Set<ScimAttributePath> supplied = Set.of(path("members.value"), path("displayName"));
        ScimPatchRequest request = new ScimPatchRequest(ScimResourceType.groupInstance(),
                List.of(add, rename, remove, clear, replace), requested, supplied, context);
        ScimMembershipPatch reduced = reduced(request);
        assertEquals(List.of(0, 2, 3, 4), reduced.getSteps().stream().map(ScimMembershipPatch.Step::getOperationIndex).toList());
        assertEquals(List.of(ScimMembershipPatch.Kind.ADD_IDS, ScimMembershipPatch.Kind.REMOVE_IDS,
                ScimMembershipPatch.Kind.CLEAR, ScimMembershipPatch.Kind.REPLACE_IDS),
                reduced.getSteps().stream().map(ScimMembershipPatch.Step::getKind).toList());
        assertEquals(List.of("Private-B", "Private-A", "Private-B"), reduced.getSteps().get(0).getValues());
        assertEquals(List.of("Private-A"), reduced.getSteps().get(1).getValues());
        assertEquals(List.of(), reduced.getSteps().get(2).getValues());
        assertEquals(List.of("Private-C", "Private-B"), reduced.getSteps().get(3).getValues());
        assertSame(request.getResourceType(), reduced.getResourceType());
        assertEquals(requested, reduced.getRequestedAttributePaths());
        assertEquals(supplied, reduced.getSuppliedAttributePaths());
        ScimPatchRequest remainder = reduced.getRemainingPatchRequest().orElseThrow();
        assertEquals(List.of(rename), remainder.getOperations());
        assertSame(rename, remainder.getOperations().get(0));
        assertEquals(1, remainder.getOperations().get(0).getOperationIndex());
        assertSame(context, remainder.getSemanticContext());
        assertEquals(Set.of(path("displayName")), remainder.getRequestedAttributePaths());
        assertEquals(Set.of(path("displayName")), remainder.getSuppliedAttributePaths());
        assertThrows(UnsupportedOperationException.class, () -> reduced.getSteps().clear());
        assertThrows(UnsupportedOperationException.class, () -> reduced.getSteps().get(0).getValues().clear());
        assertThrows(UnsupportedOperationException.class, () -> reduced.getRequestedAttributePaths().clear());
        assertFalse(reduced.toString().contains("Private"));
        assertFalse(reduced.getSteps().toString().contains("Private"));
        assertFalse(new ScimMembershipPatchResult.Reduced(reduced).toString().contains("Private"));
        assertFalse(new ScimMembershipPatchResult.Rejected(ScimError.tooManyInstance()).toString().contains("Private"));
    }

    @Test void assignedIdValuesPermitOnlyAbsentOrNullReferenceAndNoRemainderIsEmptyOptional() {
        JsonObject nullReference = JsonObject.builder().put("value", "One").putNull("$ref").build();
        ScimPatchRequest request = request(operation(7, ScimPatchOperationType.ADD, "members", null,
                JsonArray.fromElements(List.of(nullReference, member("Two")))));
        ScimMembershipPatch reduced = reduced(request);
        assertEquals(List.of("One", "Two"), reduced.getSteps().get(0).getValues());
        assertTrue(reduced.getRemainingPatchRequest().isEmpty());
        ScimMembershipPatch clear = reduced(request(operation(8, ScimPatchOperationType.REMOVE, "members", null, null)));
        assertEquals(ScimMembershipPatch.Kind.CLEAR, clear.getSteps().get(0).getKind());
        assertTrue(clear.getSteps().get(0).getValues().isEmpty());
        ScimMembershipPatch emptyReplace = reduced(request(operation(9, ScimPatchOperationType.REPLACE, "members", null,
                JsonArray.emptyInstance())));
        assertEquals(ScimMembershipPatch.Kind.REPLACE_IDS, emptyReplace.getSteps().get(0).getKind());
        assertTrue(emptyReplace.getSteps().get(0).getValues().isEmpty());
    }

    @Test void normalizedVendorRemoveValuesPreserveTheExactInputOrder() {
        ScimMembershipPatch reduced = reduced(request(operation(3, ScimPatchOperationType.REMOVE, "members", null,
                JsonArray.fromElements(List.of(member("B"), member("A"))))));
        assertEquals(ScimMembershipPatch.Kind.REMOVE_IDS, reduced.getSteps().get(0).getKind());
        assertEquals(List.of("B", "A"), reduced.getSteps().get(0).getValues());
    }

    @Test void metadataAndNoncanonicalSelectorsRequireFullEvaluationRatherThanDiscardingData() {
        for (JsonObject member : List.of(
                JsonObject.builder().put("value", "A").put("$ref", "https://example.invalid/Users/A").build(),
                JsonObject.builder().put("value", "A").put("display", "Private Name").build(),
                JsonObject.builder().put("value", "A").putNull("display").build(),
                JsonObject.builder().put("value", "A").put("type", "User").build(),
                JsonObject.builder().put("value", "A").putNull("type").build(),
                JsonObject.emptyInstance(),
                JsonObject.builder().putNull("value").build(),
                JsonObject.builder().put("value", "").build()))
            assertFull(request(operation(0, ScimPatchOperationType.ADD, "members", null,
                    JsonArray.fromElements(List.of(member)))));
        assertFull(request(operation(0, ScimPatchOperationType.ADD, "members", null, member("A"))));
        assertFull(request(operation(0, ScimPatchOperationType.REPLACE, "members", null,
                JsonArray.fromElements(List.of(member("A"), member("A"))))));
        assertFull(request(operation(0, ScimPatchOperationType.REPLACE, "members",
                filter("value eq \"A\""), JsonArray.fromElements(List.of(member("B"))))));
        assertFull(request(operation(0, ScimPatchOperationType.REMOVE, "members.value", null, null)));
        assertFull(request(operation(0, ScimPatchOperationType.REMOVE, "members", filter("value ne \"A\""), null)));
        assertFull(request(operation(0, ScimPatchOperationType.REMOVE, "members", filter("value pr"), null)));
        assertFull(request(operation(0, ScimPatchOperationType.REMOVE, "members",
                filter("value eq \"A\" and type eq \"User\""), null)));
        ScimPatchOperation suffix = new ScimPatchOperation(0, ScimPatchOperationType.REMOVE, path("members"),
                filter("value eq \"A\""), "value", null);
        assertFull(request(suffix));
        ScimPatchOperation noPathMixed = new ScimPatchOperation(0, ScimPatchOperationType.ADD, null, null, null,
                JsonObject.builder().put("members", JsonArray.fromElements(List.of(member("A"))))
                        .put("displayName", "Private Group").build());
        assertFull(request(noPathMixed));
        assertSame(ScimMembershipPatchResult.RequiresFullEvaluation.INSTANCE,
                ScimMembershipReduction.reduce(request(noPathMixed), new ScimWork(1_000_000)));
    }

    @Test void standardSchemaIdentityIsConservativeAndUnrelatedOperationsRemainAvailable() {
        ScimPatchOperation nonmember = operation(2, ScimPatchOperationType.REPLACE, "displayName", null,
                JsonString.fromValue("New"));
        ScimMembershipPatch reduced = reduced(request(nonmember));
        assertTrue(reduced.getSteps().isEmpty());
        assertEquals(List.of(nonmember), reduced.getRemainingPatchRequest().orElseThrow().getOperations());
        ScimSchema rebuilt = ScimSchema.withId(ScimSchema.groupInstance().getId()).name("Group")
                .description(ScimSchema.groupInstance().getDescription().orElseThrow())
                .attributes(ScimSchema.groupInstance().getAttributes()).build();
        assertEquals(ScimSchema.groupInstance(), rebuilt);
        ScimResourceType custom = ScimResourceType.withName("Group").endpoint("/Groups").schema(rebuilt).build();
        ScimPatchRequest rebuiltRequest = new ScimPatchRequest(custom, List.of(nonmember),
                Set.of(path("displayName")), Set.of(path("displayName")), new Object());
        assertFull(rebuiltRequest);
        ScimPatchRequest userRequest = new ScimPatchRequest(ScimResourceType.userInstance(), List.of(nonmember),
                Set.of(path("displayName")), Set.of(path("displayName")), new Object());
        assertFull(userRequest);
    }

    @Test void workExhaustionRejectsBeforePublishingAnyEarlierInstructions() {
        List<com.revetsec.json.JsonValue> members = new ArrayList<>();
        for (int index = 0; index < 100; index++) members.add(member("Member-" + index));
        ScimPatchRequest request = request(operation(0, ScimPatchOperationType.REMOVE, "members", null, null),
                operation(1, ScimPatchOperationType.ADD, "members", null, JsonArray.fromElements(members)));
        ScimMembershipPatchResult.Rejected rejection = assertInstanceOf(ScimMembershipPatchResult.Rejected.class,
                ScimMembershipReduction.reduce(request, new ScimWork(100)));
        assertSame(ScimError.requestTooLargeInstance(), rejection.getError());
        assertEquals(2, reduced(request).getSteps().size());
        int firstAccepted = 0;
        while (!(ScimMembershipReduction.reduce(request, new ScimWork(firstAccepted)) instanceof ScimMembershipPatchResult.Reduced))
            firstAccepted++;
        assertTrue(firstAccepted > 100);
        assertInstanceOf(ScimMembershipPatchResult.Rejected.class,
                ScimMembershipReduction.reduce(request, new ScimWork(firstAccepted - 1)));
        assertInstanceOf(ScimMembershipPatchResult.Reduced.class,
                ScimMembershipReduction.reduce(request, new ScimWork(firstAccepted)));
    }

    @Test void instructionAndPathCollectionsSnapshotTheirSources() {
        List<String> ids = new ArrayList<>(List.of("A"));
        ScimMembershipPatch.Step step = new ScimMembershipPatch.Step(0, ScimMembershipPatch.Kind.ADD_IDS, ids);
        ids.clear();
        assertEquals(List.of("A"), step.getValues());
        List<ScimMembershipPatch.Step> steps = new ArrayList<>(List.of(step));
        Set<ScimAttributePath> paths = new LinkedHashSet<>(Set.of(path("members.value")));
        ScimMembershipPatch patch = new ScimMembershipPatch(ScimResourceType.groupInstance(), steps, null, paths, paths);
        steps.clear(); paths.clear();
        assertEquals(List.of(step), patch.getSteps());
        assertEquals(Set.of(path("members.value")), patch.getRequestedAttributePaths());
        assertEquals(Set.of(path("members.value")), patch.getSuppliedAttributePaths());
    }

    private static @NonNull ScimMembershipPatch reduced(@NonNull ScimPatchRequest request) {
        return assertInstanceOf(ScimMembershipPatchResult.Reduced.class,
                ScimMembershipReduction.reduce(request, new ScimWork(1_000_000))).getMembershipPatch();
    }

    private static void assertFull(@NonNull ScimPatchRequest request) {
        assertInstanceOf(ScimMembershipPatchResult.RequiresFullEvaluation.class,
                ScimMembershipReduction.reduce(request, new ScimWork(1_000_000)));
    }

    private static @NonNull ScimPatchRequest request(@NonNull ScimPatchOperation @NonNull ... operations) {
        Set<ScimAttributePath> requested = new LinkedHashSet<>();
        Set<ScimAttributePath> supplied = new LinkedHashSet<>();
        for (ScimPatchOperation operation : operations) {
            operation.getAttributePath().ifPresent(requested::add);
            if (operation.getValue().isPresent()) operation.getAttributePath().ifPresent(supplied::add);
        }
        return new ScimPatchRequest(ScimResourceType.groupInstance(), List.of(operations), requested, supplied, new Object());
    }

    private static @NonNull ScimPatchOperation operation(int index, @NonNull ScimPatchOperationType type,
            @NonNull String path, @Nullable ScimFilter filter, @Nullable JsonValue value) {
        return new ScimPatchOperation(index, type, path(path), filter, null, value);
    }

    private static @NonNull ScimAttributePath path(@NonNull String value) {
        return assertInstanceOf(ScimAttributePathParseResult.Succeeded.class,
                ScimAttributePath.fromExpressionResult(value)).getAttributePath();
    }

    private static @NonNull ScimFilter filter(@NonNull String value) {
        return assertInstanceOf(ScimFilterParseResult.Succeeded.class, ScimFilter.fromExpressionResult(value)).getFilter();
    }

    private static @NonNull JsonObject member(@NonNull String id) {
        return JsonObject.builder().put("value", id).build();
    }
}
