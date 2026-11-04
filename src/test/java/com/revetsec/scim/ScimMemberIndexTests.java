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
import org.junit.jupiter.api.Test;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

/** Final-only conformance of the new operation-local index and its fallback/budget outcomes. */
final class ScimMemberIndexTests {
    @Test void emptyInputIsAStableEmptyIndex() {
        ScimWork work = new ScimWork(100);
        var index = ScimMemberIndex.fromValues(List.of(), work);
        assertNotNull(index);
        assertNull(index.find(row("missing")));
        assertFalse(work.wasExceeded());
        assertTrue(ScimMemberIndex.allAssigned(List.of(), new ScimWork(0)));
    }
    @Test void exactLookupPreservesCompleteRowsAcrossCaseAndHashCollisions() {
        var work = new ScimWork(10000);
        var rows = List.<JsonValue>of(row("a"), row("A"), row("Aa"), row("BB"));
        var index = ScimMemberIndex.fromValues(rows, work);
        assertNotNull(index);
        for (JsonValue value : rows) assertEquals(value, index.find(value));
        assertNull(index.find(row("absent")));
        assertFalse(work.wasExceeded());
    }
    @Test void unsupportedOrUnassignedIdsSignalFallbackWithoutBudgetFailure() {
        for (JsonValue value : List.of(JsonNull.defaultInstance(), JsonString.fromValue("a"),
                JsonObject.emptyInstance(), JsonObject.builder().put("value", "").build(),
                JsonObject.builder().put("value", JsonNull.defaultInstance()).build())) {
            var work = new ScimWork(10000);
            assertNull(ScimMemberIndex.fromValues(List.of(value), work));
            assertFalse(work.wasExceeded());
            assertFalse(ScimMemberIndex.allAssigned(List.of(value), work));
            assertFalse(work.wasExceeded());
        }
    }
    @Test void duplicateSnapshotIdsCannotSilentlyChooseAProtectedRow() {
        var first = row("a");
        var second = JsonObject.builder().put("value", "a").put("display", "different").build();
        var work = new ScimWork(10000);
        assertNull(ScimMemberIndex.fromValues(List.of(first, second), work));
        assertFalse(work.wasExceeded());
    }
    @Test void duplicateInsertionPreservesThePriorCompleteRow() {
        var work = new ScimWork(10000);
        var index = ScimMemberIndex.fromValues(List.of(row("a")), work);
        assertNotNull(index);
        assertFalse(index.add(JsonObject.builder().put("value", "a").put("display", "forged").build()));
        assertEquals(row("a"), index.find(row("a")));
        assertFalse(work.wasExceeded());
        assertTrue(index.add(row("b")));
        assertEquals(row("b"), index.find(row("b")));
    }
    @Test void classificationCannotSkipItsSharedInputScanBudget() {
        var rows = List.<JsonValue>of(row("a"), row("b"));
        for (int amount : new int[] {0, 1, 3}) {
            var work = new ScimWork(amount);
            assertFalse(ScimMemberIndex.allAssigned(rows, work));
            assertTrue(work.wasExceeded());
        }
        var exact = new ScimWork(4);
        assertTrue(ScimMemberIndex.allAssigned(rows, exact));
        assertFalse(exact.wasExceeded());
    }
    @Test void buildingAndLookingUpShareOneBudgetAndHaveAMonotoneCutoff() {
        var consumed = new ScimWork(1000);
        assertTrue(consumed.spend(999));
        assertNull(ScimMemberIndex.fromValues(List.of(row("a")), consumed));
        assertTrue(consumed.wasExceeded(), "index creation must honor work already spent by its caller");
        var rows = List.<JsonValue>of(row("Aa"), row("BB"), row("z"));
        boolean succeeded = false;
        for (int amount = 0; amount < 1000; amount++) {
            var work = new ScimWork(amount);
            var index = ScimMemberIndex.fromValues(rows, work);
            JsonObject found = index == null ? null : index.find(row("z"));
            if (found == null) { assertFalse(succeeded); assertTrue(work.wasExceeded()); }
            else { succeeded = true; assertFalse(work.wasExceeded()); assertEquals(row("z"), found); }
        }
        assertTrue(succeeded);
    }
    @Test void longCommonPrefixesChargeBothInputAndLookupKeyWork() {
        for (int count : new int[] {1, 64}) {
            List<JsonValue> rows = new ArrayList<>();
            for (int i = 0; i < count; i++) rows.add(row("x".repeat(100) + i));
            long build = minimum(rows, false), complete = minimum(rows, true);
            long inputCharacters = rows.stream().map(JsonObject.class::cast).mapToLong(value -> ((JsonString) value.find("value").orElseThrow()).getValue().length()).sum();
            assertTrue(build >= inputCharacters);
            assertTrue(complete - build >= 100, "lookup must charge key work, not only build work");
        }
    }
    private static long minimum(List<JsonValue> rows, boolean lookup) {
        long low = 0, high = 1_000_000;
        while (low < high) {
            long middle = (low + high) >>> 1;
            var work = new ScimWork(middle);
            var index = ScimMemberIndex.fromValues(rows, work);
            boolean success = index != null && (!lookup || index.find(rows.get(rows.size() - 1)) != null);
            if (success) high = middle; else low = middle + 1;
        }
        return low;
    }
    private static JsonObject row(String id) { return JsonObject.builder().put("value", id).put("display", "Saved:" + id).build(); }
}
