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

import static org.junit.jupiter.api.Assertions.*;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

final class ConcurrentLruMapTests {
    private static @NonNull ConcurrentLruMap<@NonNull Integer, @NonNull String> map() {
        return new ConcurrentLruMap<>(3);
    }

    @Test
    void upstreamSourceAndAnnotationOnlyEditsArePinned() throws Exception {
        String upstream =
                Files.readString(
                        Path.of("src/test/resources/cache-reuse/ConcurrentLruMap.soklet.java.txt"));
        String current =
                Files.readString(
                        Path.of("src/main/java/com/revetsec/internal/ConcurrentLruMap.java"));
        assertEquals(
                "503ec8be3c76f4d38b9f4744f11b97d43e615b5ff04e8a4019f4c4e0b0e834b0",
                java.util.HexFormat.of()
                        .formatHex(
                                MessageDigest.getInstance("SHA-256")
                                        .digest(
                                                upstream.getBytes(
                                                        java.nio.charset.StandardCharsets.UTF_8))));
        assertEquals(normalize(upstream), normalize(current));
    }

    private static @NonNull String normalize(@NonNull String source) {
        return source.replace("package com.soklet.internal.util;", "package com.revetsec.internal;")
                .replaceAll("@(NonNull|Nullable)\\b\\s*", "")
                .replaceAll("\\s+", "");
    }

    // Deliberate null arguments exercise the retained upstream runtime checks.
    @SuppressWarnings("NullAway")
    @Test
    void emptyReadAndWriteContracts() {
        var m = map();
        assertEquals(3, m.capacity());
        assertEquals(0, m.size());
        assertTrue(m.isEmpty());
        assertFalse(m.containsKey(1));
        assertFalse(m.containsValue("x"));
        assertNull(m.get(1));
        assertNull(m.getOrDefault(1, null));
        assertEquals("d", m.getOrDefault(1, "d"));
        assertNull(m.remove(1));
        assertFalse(m.remove(1, "x"));
        assertThrows(IllegalArgumentException.class, () -> new ConcurrentLruMap<>(0));
        assertThrows(IllegalArgumentException.class, () -> new ConcurrentLruMap<>(-1));
        assertThrows(NullPointerException.class, () -> m.put(null, "x"));
        assertThrows(NullPointerException.class, () -> m.put(1, null));
        assertThrows(NullPointerException.class, () -> m.putIfAbsent(null, "x"));
        assertThrows(NullPointerException.class, () -> m.computeIfAbsent(1, null));
    }

    @Test
    void insertReplaceConditionalDeleteAndCompute() {
        var m = map();
        assertNull(m.put(1, "a"));
        assertFalse(m.isEmpty());
        assertTrue(m.containsKey(1));
        assertTrue(m.containsValue("a"));
        assertFalse(m.containsValue("b"));
        assertEquals("a", m.getOrDefault(1, "d"));
        assertEquals("a", m.put(1, "b"));
        assertEquals("b", m.putIfAbsent(1, "c"));
        assertNull(m.putIfAbsent(2, "d"));
        AtomicInteger calls = new AtomicInteger();
        assertEquals(
                "b",
                m.computeIfAbsent(
                        1,
                        k -> {
                            calls.incrementAndGet();
                            return "x";
                        }));
        assertEquals(0, calls.get());
        assertNull(m.computeIfAbsent(3, k -> null));
        assertEquals("e", m.computeIfAbsent(3, k -> "e"));
        assertFalse(m.remove(1, "wrong"));
        assertTrue(m.remove(1, "b"));
        assertEquals("d", m.remove(2));
        m.drain();
        assertEquals(List.of(3), m.keysInAccessOrder());
    }

    @Test
    void readsPromoteAndEvictionCallbacksAreOutsideMaintenance() {
        List<Integer> evicted = new ArrayList<>();
        ConcurrentLruMap<Integer, String> m = new ConcurrentLruMap<>(2, (k, v) -> evicted.add(k));
        m.putAll(Map.of(1, "a", 2, "b"));
        m.drain();
        m.get(1);
        m.put(3, "c");
        m.drain();
        assertEquals(List.of(2), evicted);
        assertEquals(List.of(3, 1), m.keysInAccessOrder());
        m.clear();
        assertTrue(m.isEmpty());
        assertEquals(List.of(2), evicted);
    }

    // The Map views must also reject incompatible runtime element types.
    @SuppressWarnings("CollectionIncompatibleType")
    @Test
    void equalityHashAndBackedViews() {
        var m = map();
        m.putAll(Map.of(1, "a", 2, "b"));
        m.drain();
        assertEquals(m, m);
        assertNotEquals(m, "x");
        assertEquals(new HashMap<>(Map.of(1, "a", 2, "b")), m);
        assertEquals(Map.of(1, "a", 2, "b").hashCode(), m.hashCode());
        var keys = m.keySet();
        var values = m.values();
        var entries = m.entrySet();
        assertEquals(2, keys.size());
        assertFalse(keys.isEmpty());
        assertTrue(keys.contains(1));
        assertFalse(keys.contains(3));
        assertEquals(2, values.size());
        assertFalse(values.isEmpty());
        assertTrue(values.contains("b"));
        assertFalse(values.contains("wrong"));
        assertEquals(2, entries.size());
        assertFalse(entries.isEmpty());
        assertFalse(entries.contains("x"));
        assertTrue(entries.contains(Map.entry(1, "a")));
        assertFalse(entries.contains(Map.entry(1, "x")));
        assertFalse(entries.remove("x"));
        assertFalse(entries.remove(Map.entry(9, "x")));
        assertThrows(UnsupportedOperationException.class, () -> keys.add(8));
        assertThrows(UnsupportedOperationException.class, () -> entries.add(Map.entry(8, "x")));
        assertFalse(keys.remove(8));
        assertTrue(keys.remove(1));
        assertFalse(values.remove("wrong"));
        assertTrue(values.remove("b"));
        assertTrue(m.isEmpty());
        m.drain();
    }

    @Test
    void eachBackedViewClearWorks() {
        var m = map();
        m.put(1, "a");
        m.keySet().clear();
        assertTrue(m.isEmpty());
        m.put(1, "a");
        m.values().clear();
        assertTrue(m.isEmpty());
        m.put(1, "a");
        m.entrySet().clear();
        assertTrue(m.isEmpty());
    }

    @Test
    void keyIteratorRemovesOnceAndSurvivesReplacement() {
        var m = map();
        m.put(1, "a");
        Iterator<Integer> it = m.keySet().iterator();
        assertTrue(it.hasNext());
        assertThrows(IllegalStateException.class, it::remove);
        assertEquals(1, it.next());
        assertFalse(it.hasNext());
        it.remove();
        assertTrue(m.isEmpty());
        assertThrows(IllegalStateException.class, it::remove);
        m.put(2, "b");
        it = m.keySet().iterator();
        assertEquals(2, it.next());
        m.put(2, "new");
        it.remove();
        assertEquals("new", m.get(2));
        m.drain();
    }

    @Test
    void valueIteratorRemovesOnceAndSurvivesReplacement() {
        var m = map();
        m.put(1, "a");
        Iterator<String> it = m.values().iterator();
        assertTrue(it.hasNext());
        assertThrows(IllegalStateException.class, it::remove);
        assertEquals("a", it.next());
        assertFalse(it.hasNext());
        it.remove();
        assertThrows(IllegalStateException.class, it::remove);
        m.put(2, "b");
        it = m.values().iterator();
        assertEquals("b", it.next());
        m.put(2, "new");
        it.remove();
        assertEquals("new", m.get(2));
        m.drain();
    }

    @Test
    void entryIteratorAndWriteThroughEntries() {
        var m = map();
        m.put(1, "a");
        var it = m.entrySet().iterator();
        assertTrue(it.hasNext());
        assertThrows(IllegalStateException.class, it::remove);
        var e = it.next();
        assertFalse(it.hasNext());
        assertEquals(1, e.getKey());
        assertEquals("a", e.getValue());
        assertEquals(Map.entry(1, "a"), e);
        assertNotEquals(e, "x");
        assertEquals(Map.entry(1, "a").hashCode(), e.hashCode());
        assertEquals("a", e.setValue("b"));
        assertEquals("b", m.get(1));
        assertThrows(NullPointerException.class, () -> e.setValue(null));
        it.remove();
        assertEquals("b", m.get(1));
        assertThrows(IllegalStateException.class, it::remove);
        assertTrue(m.entrySet().remove(Map.entry(1, "b")));
        assertNull(e.getValue());
        assertNull(e.setValue("c"));
        var current = m.entrySet().iterator();
        current.next();
        current.remove();
        assertTrue(m.isEmpty());
        m.drain();
    }

    @Test
    void ringBufferHandlesReadBurstsAndWriteBacklog() {
        var m = new ConcurrentLruMap<Integer, String>(64);
        for (int i = 0; i < 64; i++) m.put(i, "v" + i);
        m.drain();
        for (int i = 0; i < 56; i++) m.get(i);
        List<Integer> expected = new ArrayList<>();
        for (int i = 55; i >= 0; i--) expected.add(i);
        for (int i = 63; i >= 56; i--) expected.add(i);
        assertEquals(expected, m.keysInAccessOrder());
        m.put(100, "next");
        for (int i = 0; i < 200; i++) m.get(1);
        m.drain();
        assertTrue(m.size() <= 64);
    }

    @Test
    void callbackFailuresDoNotPreventOtherCallbacksOrCorruptMap() {
        AtomicInteger calls = new AtomicInteger();
        var m =
                new ConcurrentLruMap<Integer, String>(
                        1,
                        (k, v) -> {
                            calls.incrementAndGet();
                            throw new IllegalArgumentException("fixture");
                        });
        m.put(1, "a");
        assertThrows(IllegalArgumentException.class, () -> m.put(2, "b"));
        assertEquals(1, calls.get());
        assertEquals("b", m.get(2));
        assertNull(m.get(1));
        m.clear();
        assertTrue(m.isEmpty());
    }
}
