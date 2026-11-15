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
import java.util.List;
import java.util.NavigableMap;
import java.util.TreeMap;

/** Operation-local exact assigned-ID lookup; output sequence always belongs to the caller. */
final class ScimMemberIndex {
    private final @NonNull NavigableMap<@NonNull String, @NonNull JsonObject> members;
    private final @NonNull ScimWork work;
    private ScimMemberIndex(@NonNull ScimWork work) {
        this.work = work; this.members = new TreeMap<>(new ScimChargedStringComparator(work));
    }

    static @Nullable ScimMemberIndex fromValues(@NonNull List<@NonNull JsonValue> values, @NonNull ScimWork work) {
        ScimMemberIndex index = new ScimMemberIndex(work);
        for (JsonValue value : values) {
            if (!work.spend(1)) return null;
            if (!(value instanceof JsonObject object) || !index.add(object)) return null;
        }
        return index;
    }

    static boolean allAssigned(@NonNull List<@NonNull JsonValue> values, @NonNull ScimWork work) {
        for (JsonValue value : values) {
            if (!work.spend(1)) return false;
            String id = id(value);
            if (id == null || !work.spend(id.length())) return false;
        }
        return true;
    }

    @Nullable JsonObject find(@NonNull JsonValue value) {
        String id = id(value);
        if (id == null) return null;
        JsonObject found = members.get(id);
        return work.wasExceeded() ? null : found;
    }

    boolean add(@NonNull JsonObject value) {
        String id = id(value);
        if (id == null) return false;
        boolean added = members.putIfAbsent(id, value) == null;
        return !work.wasExceeded() && added;
    }

    private static @Nullable String id(@NonNull JsonValue value) {
        if (!(value instanceof JsonObject object) || !(object.getMembers().get("value") instanceof JsonString string)
                || string.getValue().isEmpty()) return null;
        return string.getValue();
    }
}
