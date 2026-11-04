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
    private final @NonNull NavigableMap<@NonNull String, @NonNull JsonObject> members = new TreeMap<>();
    private final @NonNull ScimWork work;
    private ScimMemberIndex(@NonNull ScimWork work) { this.work = work; }

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
        if (id == null || !charge(id)) return null;
        return members.get(id);
    }

    boolean add(@NonNull JsonObject value) {
        String id = id(value);
        if (id == null || !charge(id)) return false;
        return members.putIfAbsent(id, value) == null;
    }

    private boolean charge(@NonNull String id) {
        // Red-black height is at most twice log2(n+1). Charge both strings in comparisons,
        // plus per-level bookkeeping, before a lookup/insertion; avoid hash-collision scans.
        int bits = Integer.SIZE - Integer.numberOfLeadingZeros(members.size());
        return work.spend(4L * (id.length() + 1L) * (bits + 1L));
    }

    private static @Nullable String id(@NonNull JsonValue value) {
        if (!(value instanceof JsonObject object) || !(object.getMembers().get("value") instanceof JsonString string)
                || string.getValue().isEmpty()) return null;
        return string.getValue();
    }
}
