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

import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.NavigableMap;
import java.util.TreeMap;

/** PUT-only matching: assigned IDs, or exact anonymous writable tuples consumed in order. */
final class ScimReplacementMemberIndex {
    private final @NonNull ScimMemberIndex assigned;
    private final @NonNull NavigableMap<@NonNull String, @NonNull ArrayDeque<@NonNull JsonObject>> anonymous;
    private final @NonNull ScimWork work;

    private ScimReplacementMemberIndex(@NonNull ScimMemberIndex assigned,
            @NonNull NavigableMap<@NonNull String, @NonNull ArrayDeque<@NonNull JsonObject>> anonymous,
            @NonNull ScimWork work) {
        this.assigned = assigned; this.anonymous = anonymous; this.work = work;
    }

    static @Nullable ScimReplacementMemberIndex fromValues(@NonNull List<@NonNull JsonValue> values, @NonNull ScimWork work) {
        List<JsonValue> ids = new ArrayList<>();
        NavigableMap<String, ArrayDeque<JsonObject>> anonymous = new TreeMap<>();
        for (JsonValue value : values) {
            if (!work.spend(1) || !(value instanceof JsonObject object)) return null;
            if (hasId(object)) ids.add(object);
            else {
                String key = anonymousKey(object, work);
                if (key == null || !reserve(key, anonymous.size(), work)) return null;
                anonymous.computeIfAbsent(key, ignored -> new ArrayDeque<>()).addLast(object);
            }
        }
        ScimMemberIndex assigned = ScimMemberIndex.fromValues(ids, work);
        return assigned == null ? null : new ScimReplacementMemberIndex(assigned, anonymous, work);
    }

    @Nullable JsonObject find(@NonNull JsonObject value) {
        if (hasId(value)) return assigned.find(value);
        String key = anonymousKey(value, work);
        if (key == null || !reserve(key, anonymous.size(), work)) return null;
        ArrayDeque<JsonObject> matches = anonymous.get(key);
        return matches == null ? null : matches.pollFirst();
    }

    private static boolean hasId(@NonNull JsonObject value) {
        return value.getMembers().get("value") instanceof JsonString string && !string.getValue().isEmpty();
    }

    private static @Nullable String anonymousKey(@NonNull JsonObject value, @NonNull ScimWork work) {
        // Normalized standard Group members without an ID have only these writable fields.
        // Read-only display never selects a row; absent and explicit-null input normalize alike.
        String ref = value.getMembers().get("$ref") instanceof JsonString string ? string.getValue() : null;
        String type = value.getMembers().get("type") instanceof JsonString string ? string.getValue() : null;
        long characters = 32L + (ref == null ? 0 : ref.length()) + (type == null ? 0 : type.length());
        if (!work.spend(characters)) return null;
        StringBuilder key = new StringBuilder();
        part(key, ref); part(key, type);
        return key.toString();
    }

    private static void part(@NonNull StringBuilder key, @Nullable String value) {
        if (value == null) key.append("-;");
        else key.append(value.length()).append(':').append(value).append(';');
    }

    private static boolean reserve(@NonNull String key, int size, @NonNull ScimWork work) {
        int bits = Integer.SIZE - Integer.numberOfLeadingZeros(size);
        return work.spend(4L * (key.length() + 1L) * (bits + 1L));
    }
}
