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
import org.junit.jupiter.api.Test;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

/** Final-only checks of work spent on the new PUT index, outside request normalization. */
final class ScimReplacementMemberIndexTests {
    @Test void validLongReferenceAndTypeKeysStillBuildAndRetainCompleteRows() {
        var rows = rows(64); var work = new ScimWork(10_000_000);
        var index = ScimReplacementMemberIndex.fromValues(rows, work); assertNotNull(index);
        for (JsonValue row : rows) assertEquals(row, index.find((JsonObject) row));
        assertFalse(work.wasExceeded());
    }

    @Test void successfulLookupChargesMaterializationAndAtLeastOneFullKeyComparison() {
        var rows = rows(64); var query = (JsonObject) rows.get(rows.size() - 1);
        long characters = ((JsonString) query.find("$ref").orElseThrow()).getValue().length()
                + ((JsonString) query.find("type").orElseThrow()).getValue().length();
        long emptyQuery = minimum(List.of(), query), populatedQuery = minimum(rows, query) - minimum(rows, null);
        assertTrue(populatedQuery >= 2 * characters, "fresh tuple construction and an exact populated-tree hit must both charge key characters");
        assertTrue(populatedQuery >= emptyQuery, "populating the lookup tree must not lower the reservation for the same key");
    }

    @Test void lookupUsesTheCallersAlreadyConsumedWork() {
        var work = new ScimWork(1000); assertTrue(work.spend(999));
        var index = ScimReplacementMemberIndex.fromValues(List.of(), work); assertNotNull(index);
        assertNull(index.find(JsonObject.builder().put("$ref", "Users/a").build()));
        assertTrue(work.wasExceeded(), "index construction and lookup cannot reset the caller's work");
        var row = JsonObject.builder().put("$ref", "Users/a").put("type", "User").put("display", "saved").build();
        List<JsonValue> rows = List.of(row);
        long build = minimum(rows, null), complete = minimum(rows, row);
        for (long budget = build; budget < complete; budget++) {
            var limited = new ScimWork(budget); var candidate = ScimReplacementMemberIndex.fromValues(rows, limited);
            assertNotNull(candidate);
            assertNull(candidate.find(row), "no row may escape an exhausted lookup at " + budget);
            assertTrue(limited.wasExceeded());
        }
    }

    private static long minimum(List<JsonValue> rows, @Nullable JsonObject query) {
        long low = 0, high = 10_000_000;
        var ample = new ScimWork(high); var complete = ScimReplacementMemberIndex.fromValues(rows, ample); assertNotNull(complete);
        if (query != null) complete.find(query); assertFalse(ample.wasExceeded());
        while (low < high) {
            long middle = (low + high) >>> 1; var work = new ScimWork(middle);
            var index = ScimReplacementMemberIndex.fromValues(rows, work);
            if (index != null && query != null) index.find(query);
            if (index != null && !work.wasExceeded()) high = middle; else low = middle + 1;
        }
        return low;
    }
    private static List<JsonValue> rows(int size) {
        List<JsonValue> rows = new ArrayList<>();
        for (int i = 0; i < size; i++) rows.add(JsonObject.builder().put("$ref", "Users/" + "a".repeat(512) + i)
                .put("type", i % 2 == 0 ? "User" : "x".repeat(1024)).put("display", "saved:" + i).build());
        return rows;
    }
}
