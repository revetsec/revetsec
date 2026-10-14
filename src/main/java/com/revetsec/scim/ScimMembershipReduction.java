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
import com.revetsec.json.JsonNull;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Conservative, snapshot-independent membership instruction extraction. */
final class ScimMembershipReduction {
    private ScimMembershipReduction() {}

    @SuppressWarnings("ReferenceEquality") // A standard immutable schema is the fast-path proof.
    static @NonNull ScimMembershipPatchResult reduce(@NonNull ScimPatchRequest patch,
            @NonNull ScimWork work) {
        if (!work.spend(8L * patch.getOperations().size()
                + 8L * (patch.getRequestedAttributePaths().size()
                        + patch.getSuppliedAttributePaths().size()))) return exhausted();
        if (patch.getResourceType().getSchema() != ScimSchema.groupInstance()) return full();

        // Prove every membership operation before allocating instructions or copied ID lists.
        for (ScimPatchOperation operation : patch.getOperations()) {
            ScimAttributePath path = operation.getAttributePath().orElse(null);
            if (path != null && !pathWork(path, work)) return exhausted();
            if (path == null) {
                JsonValue value = operation.getValue().orElse(null);
                if (value instanceof JsonObject object) {
                    if (!work.spend(object.getMembers().size())) return exhausted();
                    if (object.getMembers().containsKey("members")) return full();
                }
            } else if (memberPath(path) && !reducible(operation, work)) {
                return work.wasExceeded() ? exhausted() : full();
            }
        }
        for (ScimAttributePath path : patch.getRequestedAttributePaths())
            if (!pathWork(path, work)) return exhausted();
        for (ScimAttributePath path : patch.getSuppliedAttributePaths())
            if (!pathWork(path, work)) return exhausted();

        List<ScimMembershipPatch.Step> steps = new ArrayList<>();
        List<ScimPatchOperation> remaining = new ArrayList<>();
        for (ScimPatchOperation operation : patch.getOperations()) {
            ScimAttributePath path = operation.getAttributePath().orElse(null);
            if (path == null || !memberPath(path)) {
                remaining.add(operation);
                continue;
            }
            ScimMembershipPatch.Kind kind;
            List<String> values;
            JsonValue value = operation.getValue().orElse(null);
            ScimFilter filter = operation.getValueFilter().orElse(null);
            if (filter instanceof ScimFilter.Comparison comparison) {
                kind = ScimMembershipPatch.Kind.REMOVE_IDS;
                values = List.of(((ScimFilterValue.StringValue) comparison.getValue()).getValue());
            } else if (operation.getOperationType() == ScimPatchOperationType.REMOVE && value == null) {
                kind = ScimMembershipPatch.Kind.CLEAR;
                values = List.of();
            } else {
                kind = switch (operation.getOperationType()) {
                    case ADD -> ScimMembershipPatch.Kind.ADD_IDS;
                    case REMOVE -> ScimMembershipPatch.Kind.REMOVE_IDS;
                    case REPLACE -> ScimMembershipPatch.Kind.REPLACE_IDS;
                };
                JsonArray array = (JsonArray) java.util.Objects.requireNonNull(value);
                List<String> ids = new ArrayList<>(array.getElements().size());
                for (JsonValue element : array.getElements()) {
                    JsonObject object = (JsonObject) element;
                    ids.add(((JsonString) java.util.Objects.requireNonNull(object.getMembers().get("value"))).getValue());
                }
                values = ids;
            }
            steps.add(new ScimMembershipPatch.Step(operation.getOperationIndex(), kind, values));
        }
        ScimPatchRequest remainder = remaining.isEmpty() ? null : new ScimPatchRequest(
                patch.getResourceType(), remaining, remainingPaths(patch.getRequestedAttributePaths()),
                remainingPaths(patch.getSuppliedAttributePaths()), patch.getSemanticContext());
        return new ScimMembershipPatchResult.Reduced(new ScimMembershipPatch(patch.getResourceType(),
                steps, remainder, patch.getRequestedAttributePaths(), patch.getSuppliedAttributePaths()));
    }

    private static boolean reducible(@NonNull ScimPatchOperation operation, @NonNull ScimWork work) {
        ScimAttributePath path = operation.getAttributePath().orElseThrow();
        if (path.getSubAttributeName().isPresent() || operation.getSubAttributeName().isPresent()) return false;
        ScimFilter filter = operation.getValueFilter().orElse(null);
        JsonValue value = operation.getValue().orElse(null);
        if (filter != null) {
            if (operation.getOperationType() != ScimPatchOperationType.REMOVE || value != null
                    || !(filter instanceof ScimFilter.Comparison comparison)
                    || comparison.getOperator() != ScimComparisonOperator.EQ
                    || comparison.getAttributePath().getSchemaId().isPresent()
                    || comparison.getAttributePath().getSubAttributeName().isPresent()
                    || !comparison.getAttributePath().getAttributeName().equals("value")
                    || !(comparison.getValue() instanceof ScimFilterValue.StringValue string)) return false;
            return work.spend(2L * string.getValue().length() + 4);
        }
        if (operation.getOperationType() == ScimPatchOperationType.REMOVE && value == null) return true;
        if (!(value instanceof JsonArray array)) return false;
        if (!work.spend(8L * array.getElements().size())) return false;
        @Nullable Set<@NonNull String> replacementIds = operation.getOperationType() == ScimPatchOperationType.REPLACE
                ? new TreeSet<>((left, right) -> {
                    // The set is private proof work. After exhaustion its temporary comparison
                    // result is discarded immediately; no instruction can escape that failure.
                    if (!work.spend(1L + left.length() + right.length())) return 0;
                    return left.compareTo(right);
                }) : null;
        for (JsonValue element : array.getElements()) {
            if (!(element instanceof JsonObject object)) return false;
            if (!work.spend(4L * object.getMembers().size())) return false;
            JsonValue id = object.getMembers().get("value");
            if (!(id instanceof JsonString string) || string.getValue().isEmpty()) return false;
            if (!work.spend(2L * string.getValue().length() + 4)) return false;
            if (replacementIds != null && !replacementIds.add(string.getValue())) return false;
            if (work.wasExceeded()) return false;
            for (Map.Entry<String, JsonValue> entry : object.getMembers().entrySet()) {
                if (!work.spend(2L * entry.getKey().length())) return false;
                if (!entry.getKey().equals("value")
                        && !(entry.getKey().equals("$ref") && entry.getValue() instanceof JsonNull)) return false;
            }
        }
        return true;
    }

    private static boolean memberPath(@NonNull ScimAttributePath path) {
        return path.getAttributeName().equals("members")
                && (path.getSchemaId().isEmpty()
                        || path.getSchemaId().get().equals(ScimSchema.groupInstance().getId()));
    }

    private static boolean pathWork(@NonNull ScimAttributePath path, @NonNull ScimWork work) {
        return work.spend(4L * (path.getAttributeName().length()
                + path.getSchemaId().map(String::length).orElse(0)
                + path.getSubAttributeName().map(String::length).orElse(0)));
    }

    private static @NonNull Set<@NonNull ScimAttributePath> remainingPaths(
            @NonNull Set<@NonNull ScimAttributePath> paths) {
        Set<ScimAttributePath> remaining = new LinkedHashSet<>();
        for (ScimAttributePath path : paths) if (!memberPath(path)) remaining.add(path);
        return remaining;
    }

    private static @NonNull ScimMembershipPatchResult full() {
        return ScimMembershipPatchResult.RequiresFullEvaluation.INSTANCE;
    }

    private static @NonNull ScimMembershipPatchResult exhausted() {
        return new ScimMembershipPatchResult.Rejected(ScimError.requestTooLargeInstance());
    }
}
