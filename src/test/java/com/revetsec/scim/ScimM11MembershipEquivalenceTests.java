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

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** The keyed storage executor below deliberately uses no PATCH-engine internals. */
class ScimM11MembershipEquivalenceTests {
    private static final @NonNull String PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

    @Test void orderedIdStepsAndFullEngineAgreeOnMetadataSequenceAndActualFinalDifference() {
        ScimServiceProvider provider = provider(ScimCompatibility.strictInstance());
        ScimResource original = original();
        List<String> requests = List.of(
                "{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"A\"}]}",
                "{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"a\"},{\"value\":\"A\"},{\"value\":\"C\"}]}",
                "{\"op\":\"remove\",\"path\":\"members[value eq \\\"A\\\"]\"},"
                        + "{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"A\"}]}",
                "{\"op\":\"remove\",\"path\":\"members[value eq \\\"absent\\\"]\"}",
                "{\"op\":\"replace\",\"path\":\"members\",\"value\":[{\"value\":\"B\"},{\"value\":\"A\"}]}",
                "{\"op\":\"replace\",\"path\":\"members\",\"value\":[{\"value\":\"B\"},{\"value\":\"C\"}]}",
                "{\"op\":\"remove\",\"path\":\"members\"},"
                        + "{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"B\"},{\"value\":\"A\"}]}",
                "{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"C\"}]},"
                        + "{\"op\":\"remove\",\"path\":\"members[value eq \\\"C\\\"]\"}",
                "{\"op\":\"replace\",\"path\":\"members\",\"value\":[]}",
                "{\"op\":\"remove\",\"path\":\"members\"}");
        for (String operations : requests) {
            ScimPatchRequest request = parse(provider, operations);
            ScimPatchResult full = applied(provider, original, request);
            ScimMembershipPatch reduced = reduce(provider, request);
            JsonObject keyed = executeAtomically(original, reduced);
            assertNotNull(keyed);
            assertEquals(full.getResource().getDocument(), keyed, operations);
            assertEquals(!original.getDocument().equals(keyed), full.isModified(), operations);
            assertEquals(request.getRequestedAttributePaths(), full.getRequestedAttributePaths());
            assertEquals(request.getRequestedAttributePaths(), reduced.getRequestedAttributePaths());
            assertEquals(request.getSuppliedAttributePaths(), reduced.getSuppliedAttributePaths());
            assertEquals(original.getVersion(), full.getResource().getVersion());
            assertEquals(original.getCreated(), full.getResource().getCreated());
            assertEquals(original.getLastModified(), full.getResource().getLastModified());
            assertEquals(original().getDocument(), original.getDocument(), "input snapshot remains unchanged");
        }
        ScimPatchResult addExisting = applied(provider, original,
                parse(provider, requests.get(0)));
        assertFalse(addExisting.isModified());
        assertEquals(List.of("A", "B"), ids(addExisting.getResource()));
        assertEquals("Alpha", memberOf(addExisting.getResource(), "A").find("display").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
        ScimPatchResult removeAdd = applied(provider, original, parse(provider, requests.get(2)));
        assertEquals(List.of("B", "A"), ids(removeAdd.getResource()));
        assertEquals(JsonObject.builder().put("value", "A").build(), memberOf(removeAdd.getResource(), "A"));
        assertTrue(removeAdd.isModified());
        ScimPatchResult reordered = applied(provider, original, parse(provider, requests.get(4)));
        assertEquals(List.of("B", "A"), ids(reordered.getResource()));
        assertEquals(memberOf(original, "A"), memberOf(reordered.getResource(), "A"));
        assertEquals(memberOf(original, "B"), memberOf(reordered.getResource(), "B"));
        assertTrue(reordered.isModified());
        assertFalse(applied(provider, original, parse(provider, requests.get(7))).isModified());
    }

    @Test void exactMemberIdsDoNotUseApplicationCaseInsensitiveCollation() {
        ScimServiceProvider provider = provider(ScimCompatibility.strictInstance());
        ScimResource original = original();
        ScimPatchRequest request = parse(provider,
                "{\"op\":\"remove\",\"path\":\"members[value eq \\\"a\\\"]\"},"
                        + "{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"a\"}]}");
        ScimPatchResult full = applied(provider, original, request);
        assertEquals(List.of("A", "B", "a"), ids(full.getResource()));
        assertEquals(full.getResource().getDocument(), executeAtomically(original, reduce(provider, request)));
    }

    @Test void nullReferencesAreUnassignedAndDoNotChangeTheFullOrReducedCandidate() {
        ScimServiceProvider provider = provider(ScimCompatibility.strictInstance());
        ScimResource original = original();
        for (String operation : List.of("add", "replace")) {
            ScimPatchRequest request = parse(provider, "{\"op\":\"" + operation
                    + "\",\"path\":\"members\",\"value\":[{\"value\":\"A\",\"$ref\":null},{\"value\":\"C\",\"$ref\":null}]}");
            ScimPatchResult full = applied(provider, original, request);
            assertEquals(full.getResource().getDocument(), executeAtomically(original, reduce(provider, request)));
            assertEquals("https://example.invalid/Users/A", memberOf(full.getResource(), "A").find("$ref").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
            assertTrue(memberOf(full.getResource(), "C").find("$ref").isEmpty());
        }
    }

    @Test void mixedResourceAndMembershipOperationsShareOriginalOrderAndOneAtomicOutcome() {
        ScimServiceProvider provider = provider(ScimCompatibility.strictInstance());
        ScimResource original = original();
        ScimPatchRequest request = parse(provider,
                "{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"C\"}]},"
                        + "{\"op\":\"replace\",\"value\":{\"displayName\":\"Intermediate\"}},"
                        + "{\"op\":\"remove\",\"path\":\"members[value eq \\\"A\\\"]\"},"
                        + "{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"Final Group\"},"
                        + "{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"A\"}]}");
        ScimMembershipPatch reduced = reduce(provider, request);
        assertEquals(List.of(0, 2, 4), reduced.getSteps().stream().map(ScimMembershipPatch.Step::getOperationIndex).toList());
        assertEquals(List.of(1, 3), reduced.getRemainingPatchRequest().orElseThrow().getOperations().stream()
                .map(ScimPatchOperation::getOperationIndex).toList());
        ScimPatchResult full = applied(provider, original, request);
        assertEquals(full.getResource().getDocument(), executeAtomically(original, reduced));
        assertEquals("Final Group", ScimGroup.fromResource(full.getResource()).getDisplayName());
        assertEquals(List.of("B", "C", "A"), ids(full.getResource()));

        ScimPatchRequest clearAdd = parse(provider,
                "{\"op\":\"remove\",\"path\":\"members\"},"
                        + "{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"Intermediate\"},"
                        + "{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"B\"},{\"value\":\"A\"}]},"
                        + "{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"Original Group\"}");
        ScimPatchResult clearAddFull = applied(provider, original, clearAdd);
        assertTrue(clearAddFull.isModified(), "removed and recreated metadata differs despite restored displayName");
        assertEquals(clearAddFull.getResource().getDocument(), executeAtomically(original, reduce(provider, clearAdd)));
        assertEquals(original.getVersion(), clearAddFull.getResource().getVersion());
        assertEquals(original.getLastModified(), clearAddFull.getResource().getLastModified());

        ScimPatchRequest lateFailure = parse(provider,
                "{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"C\"}]},"
                        + "{\"op\":\"replace\",\"path\":\"displayName\",\"value\":null}");
        ScimPatchApplicationResult.Rejected rejected = assertInstanceOf(ScimPatchApplicationResult.Rejected.class,
                provider.applyPatchResult(original, lateFailure));
        assertSame(ScimError.mutabilityInstance(), rejected.getError());
        assertNull(executeAtomically(original, reduce(provider, lateFailure)), "no staged candidate is published");
        assertEquals(original().getDocument(), original.getDocument());
        assertEquals(List.of("A", "B"), ids(original));
    }

    @Test void narrowEntraRemoveValueNormalizationRemainsEquivalent() {
        ScimServiceProvider provider = provider(ScimCompatibility.microsoftEntraIdInstance());
        ScimPatchRequest request = parse(provider,
                "{\"op\":\"remove\",\"path\":\"members\",\"value\":[{\"value\":\"B\"},{\"value\":\"absent\"}]}");
        ScimResource original = original();
        ScimPatchResult full = applied(provider, original, request);
        ScimMembershipPatch reduced = reduce(provider, request);
        assertEquals(List.of("B", "absent"), reduced.getSteps().get(0).getValues());
        assertEquals(full.getResource().getDocument(), executeAtomically(original, reduced));
        assertEquals(List.of("A"), ids(full.getResource()));
    }

    @Test void emptyAddsPreserveAbsentEmptyAndAssignedMembershipSnapshots() {
        ScimServiceProvider provider = provider(ScimCompatibility.strictInstance());
        ScimPatchRequest request = parse(provider, "{\"op\":\"add\",\"path\":\"members\",\"value\":[]}");
        ScimResource assigned = original();
        LinkedHashMap<String, JsonValue> document = new LinkedHashMap<>(assigned.getDocument().getMembers());
        document.remove("members");
        ScimResource absent = ScimResource.withResourceType(ScimResourceType.groupInstance())
                .document(JsonObject.fromMembers(document)).build();
        document.put("members", JsonArray.emptyInstance());
        ScimResource empty = ScimResource.withResourceType(ScimResourceType.groupInstance())
                .document(JsonObject.fromMembers(document)).build();
        for (ScimResource current : List.of(absent, empty, assigned)) {
            ScimPatchResult full = applied(provider, current, request);
            assertFalse(full.isModified());
            assertEquals(current.getDocument(), full.getResource().getDocument());
            assertEquals(full.getResource().getDocument(), executeAtomically(current, reduce(provider, request)));
        }
    }

    /** Independent keyed storage behavior, with one final publication point and no engine helpers. */
    private static @Nullable JsonObject executeAtomically(@NonNull ScimResource original,
            @NonNull ScimMembershipPatch patch) {
        LinkedHashMap<String, JsonObject> members = new LinkedHashMap<>();
        for (JsonObject member : ScimGroup.fromResource(original).getMembers())
            members.put(member.find("value").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow(), member);
        LinkedHashMap<String, JsonValue> document = new LinkedHashMap<>(original.getDocument().getMembers());
        Map<Integer, ScimMembershipPatch.Step> steps = new LinkedHashMap<>();
        for (ScimMembershipPatch.Step step : patch.getSteps()) steps.put(step.getOperationIndex(), step);
        Map<Integer, ScimPatchOperation> other = new LinkedHashMap<>();
        patch.getRemainingPatchRequest().ifPresent(request -> {
            for (ScimPatchOperation operation : request.getOperations()) other.put(operation.getOperationIndex(), operation);
        });
        int maximumIndex = -1;
        for (Integer index : steps.keySet()) maximumIndex = Math.max(maximumIndex, index);
        for (Integer index : other.keySet()) maximumIndex = Math.max(maximumIndex, index);
        boolean membersPresent = document.containsKey("members");
        for (int index = 0; index <= maximumIndex; index++) {
            ScimMembershipPatch.Step step = steps.get(index);
            if (step != null) {
                switch (step.getKind()) {
                    case ADD_IDS -> {
                        for (String id : step.getValues())
                            members.putIfAbsent(id, JsonObject.builder().put("value", id).build());
                        if (!step.getValues().isEmpty()) membersPresent = true;
                    }
                    case REMOVE_IDS -> {
                        for (String id : step.getValues()) members.remove(id);
                    }
                    case CLEAR -> { members.clear(); membersPresent = false; }
                    case REPLACE_IDS -> {
                        LinkedHashMap<String, JsonObject> replacement = new LinkedHashMap<>();
                        for (String id : step.getValues()) replacement.putIfAbsent(id,
                                members.getOrDefault(id, JsonObject.builder().put("value", id).build()));
                        members = replacement;
                        membersPresent = true;
                    }
                }
            } else {
                ScimPatchOperation operation = other.get(index);
                if (operation == null) continue;
                JsonValue value = operation.getValue().orElse(null);
                if (operation.getAttributePath().isEmpty()) {
                    JsonObject object = assertInstanceOf(JsonObject.class, value);
                    assertEquals(List.of("displayName"), new ArrayList<>(object.getMembers().keySet()));
                    value = object.getMembers().get("displayName");
                } else assertEquals("displayName", operation.getAttributePath().orElseThrow().toScimString());
                if (operation.getOperationType() == ScimPatchOperationType.REMOVE || !(value instanceof JsonString))
                    document.remove("displayName");
                else document.put("displayName", value);
            }
        }
        if (!document.containsKey("displayName")) return null;
        if (membersPresent) document.put("members", JsonArray.fromElements(new ArrayList<>(members.values())));
        else document.remove("members");
        return JsonObject.fromMembers(document);
    }

    private static @NonNull ScimPatchResult applied(@NonNull ScimServiceProvider provider,
            @NonNull ScimResource original, @NonNull ScimPatchRequest request) {
        return assertInstanceOf(ScimPatchApplicationResult.Succeeded.class,
                provider.applyPatchResult(original, request)).getPatchResult();
    }

    private static @NonNull ScimMembershipPatch reduce(@NonNull ScimServiceProvider provider,
            @NonNull ScimPatchRequest request) {
        return assertInstanceOf(ScimMembershipPatchResult.Reduced.class,
                provider.reduceMembershipPatchResult(request)).getMembershipPatch();
    }

    private static @NonNull ScimPatchRequest parse(@NonNull ScimServiceProvider provider, @NonNull String operations) {
        return assertInstanceOf(ScimPatchParseResult.Succeeded.class, provider.parsePatchRequestResult(
                ScimResourceType.groupInstance(), List.of("application/scim+json"),
                ("{\"schemas\":[\"" + PATCH + "\"],\"Operations\":[" + operations + "]}")
                        .getBytes(StandardCharsets.UTF_8))).getPatchRequest();
    }

    private static @NonNull ScimServiceProvider provider(@NonNull ScimCompatibility compatibility) {
        // Deliberately case-insensitive strategy: member IDs must still compare exactly.
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.invalid/scim/v2/"))
                .resourceTypes(List.of(ScimResourceType.groupInstance()))
                .serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).build())
                .compatibility(compatibility)
                .stringMatching((path, definition, operator, value, literal) ->
                        ScimStringMatchResult.fromMatched(value.equalsIgnoreCase(literal))).build();
    }

    private static @NonNull ScimResource original() {
        JsonObject a = JsonObject.builder().put("value", "A").put("display", "Alpha").put("type", "User")
                .put("$ref", "https://example.invalid/Users/A").build();
        JsonObject b = JsonObject.builder().put("value", "B").put("display", "Beta").put("type", "Group")
                .put("$ref", "https://example.invalid/Groups/B").build();
        JsonObject document = JsonObject.builder().put("schemas", JsonArray.fromElements(List.of(
                JsonString.fromValue(ScimSchema.groupInstance().getId())))).put("id", "Group-1")
                .put("displayName", "Original Group").put("members", JsonArray.fromElements(List.of(a, b)))
                .put("meta", JsonObject.builder().put("resourceType", "Group").put("version", "W/\"v1\"")
                        .put("created", "2026-10-13T12:00:00Z").put("lastModified", "2026-10-13T12:30:00Z").build()).build();
        return ScimResource.withResourceType(ScimResourceType.groupInstance()).document(document).build();
    }

    private static @NonNull List<@NonNull String> ids(@NonNull ScimResource resource) {
        List<String> ids = new ArrayList<>();
        for (JsonObject member : ScimGroup.fromResource(resource).getMembers())
            ids.add(member.find("value").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
        return ids;
    }

    private static @NonNull JsonObject memberOf(@NonNull ScimResource resource, @NonNull String id) {
        return ScimGroup.fromResource(resource).getMembers().stream()
                .filter(member -> id.equals(member.find("value").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow()))
                .findFirst().orElseThrow();
    }
}
