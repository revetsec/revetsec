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

package com.revetsec.internal;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Iterator;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** Live collection views retain the map's value and access-order contracts. */
final class ConcurrentLruMapViewsRc1MutationTests {
    @Test
    void emptyViewsTrackTheBackingMap() {
        var map = new ConcurrentLruMap<Integer, String>(2);
        var entries = map.entrySet();
        var values = map.values();
        var keys = map.keySet();
        assertTrue(entries.isEmpty());
        assertTrue(values.isEmpty());
        assertTrue(keys.isEmpty());
        map.put(1, "one");
        assertFalse(entries.isEmpty());
        assertFalse(values.isEmpty());
        assertFalse(keys.isEmpty());
        assertEquals("one", map.remove(1));
        assertTrue(entries.isEmpty());
        assertTrue(values.isEmpty());
        assertTrue(keys.isEmpty());
    }

    @Test
    void entriesCompareBothTheirKeyAndValue() {
        var map = new ConcurrentLruMap<Integer, String>(2);
        map.put(1, "one");
        var entry = map.entrySet().iterator().next();
        assertTrue(entry.equals(Map.entry(1, "one")));
        assertFalse(entry.equals(Map.entry(2, "one")));
        assertFalse(entry.equals(Map.entry(1, "different")));
    }

    @Test
    void removingThroughValuesReleasesTheAccessOrderEntry() {
        var map = new ConcurrentLruMap<Integer, String>(2);
        map.put(1, "one");
        map.put(2, "two");
        map.drain();
        assertTrue(map.values().remove("one"));
        map.drain();
        assertEquals(1, map.size());
        assertNull(map.get(1));
        assertEquals(List.of(2), map.keysInAccessOrder());
        map.put(3, "three");
        map.drain();
        assertEquals(List.of(3, 2), map.keysInAccessOrder());
        assertFalse(map.values().remove("missing"));
    }

    @Test
    void removingThroughEachViewIteratorReleasesItsAccessOrderEntry() {
        for (String view : List.of("keys", "entries", "values")) {
            var map = new ConcurrentLruMap<Integer, String>(2);
            map.put(1, "one");
            map.put(2, "two");
            map.drain();
            Iterator<?> iterator = switch (view) {
                case "keys" -> map.keySet().iterator();
                case "entries" -> map.entrySet().iterator();
                default -> map.values().iterator();
            };
            assertNotNull(iterator.next());
            iterator.remove();
            assertThrows(IllegalStateException.class, iterator::remove);
            int retained = map.containsKey(1) ? 1 : 2;
            int removed = 3 - retained;
            map.drain();
            assertEquals(1, map.size());
            assertNull(map.get(removed));
            assertEquals(List.of(retained), map.keysInAccessOrder(), view);
            map.put(3, "three");
            map.drain();
            assertEquals(List.of(3, retained), map.keysInAccessOrder(), view);
        }
    }
}
