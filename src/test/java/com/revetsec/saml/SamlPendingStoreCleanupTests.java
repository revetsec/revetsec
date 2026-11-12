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
package com.revetsec.saml;

import org.jspecify.annotations.NonNull;

import org.junit.jupiter.api.Test;
import org.jspecify.annotations.Nullable;

import java.lang.reflect.Field;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.AbstractSet;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import static org.junit.jupiter.api.Assertions.*;

/** Deterministic maintenance-work checks, not elapsed-time performance benchmarks. */
final class SamlPendingStoreCleanupTests {
    private static final Instant START = Instant.parse("2026-11-02T00:00:00Z");
    private static final Duration BUDGET = Duration.ofSeconds(5);
    private static final int BATCH = 64;

    @Test void savingAmongLiveEntriesDoesNotVisitTheWholeMap() throws Exception {
        var store = seeded(new MutableClock(), 1024, 1025, START.plusSeconds(60));
        CountingMap map = observe(store);
        assertEquals(SamlPendingSaveResult.SAVED, save(store, "new", START.plusSeconds(60)));
        assertEquals(0, map.visits, "cleanup must not iterate live map entries");
        assertEquals(1025, map.size());
        assertCoherent(store, map);
    }

    @Test void expiredBacklogIsReclaimedInBoundedBatchesWithoutFalseCapacityRefusal() throws Exception {
        var clock = new MutableClock();
        var store = seeded(clock, 1024, 1024, START.plusSeconds(1));
        CountingMap map = observe(store);
        clock.value = START.plusSeconds(1);
        assertEquals(SamlPendingSaveResult.SAVED, save(store, "new", START.plusSeconds(60)));
        assertEquals(BATCH, map.removals, "one operation must not sweep the entire expired backlog");
        assertEquals(1024 - BATCH + 1, map.size());
        for (int i = 0; i < 16; i++) {
            map.removals = 0;
            assertInstanceOf(SamlPendingConsumeResult.Missing.class, store.consume("b", "missing", BUDGET));
            assertTrue(map.removals <= BATCH);
            assertCoherent(store, map);
        }
        assertEquals(1, map.size(), "consume misses must also make expiry-cleanup progress");
        assertConsumed(store, "new");
        assertCoherent(store, map);
    }

    @Test void liveMapTraversalCannotHoldTheLockAgainstAnUnrelatedConsumer() throws Exception {
        var store = seeded(new MutableClock(), 256, 257, START.plusSeconds(60));
        CountingMap map = observe(store);
        var progress = new CompletableFuture<String>();
        var release = new CountDownLatch(1);
        map.onVisit = () -> {
            progress.complete("map traversal");
            try { assertTrue(release.await(5, TimeUnit.SECONDS)); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new AssertionError(e); }
        };
        var writer = new CompletableFuture<SamlPendingSaveResult>();
        Thread thread = new Thread(() -> {
            try { writer.complete(save(store, "new", START.plusSeconds(60))); }
            catch (Throwable t) { writer.completeExceptionally(t); }
            finally { progress.complete("completed without traversal"); }
        });
        thread.start();
        SamlPendingConsumeResult result;
        try {
            progress.get(5, TimeUnit.SECONDS);
            result = store.consume("b", "0", Duration.ofMillis(100));
        } finally {
            release.countDown();
            thread.join(5000);
        }
        assertFalse(thread.isAlive());
        assertEquals(SamlPendingSaveResult.SAVED, writer.get(5, TimeUnit.SECONDS));
        assertInstanceOf(SamlPendingConsumeResult.Consumed.class, result,
                "unrelated consume must not wait for a full live-map cleanup scan");
    }

    @Test void equalExpiriesAndCompositeKeysRemainDistinctAtExactCapacity() throws Exception {
        var clock = new MutableClock();
        var store = instrumented(clock, 3);
        Instant expiry = START.plusNanos(1);
        assertEquals(SamlPendingSaveResult.SAVED, store.save("ab", "c", "one", expiry, BUDGET));
        assertEquals(SamlPendingSaveResult.SAVED, store.save("a", "bc", "two", expiry, BUDGET));
        assertEquals(SamlPendingSaveResult.SAVED, save(store, "third", expiry));
        assertEquals(SamlPendingSaveResult.CAPACITY_REFUSED, save(store, "fourth", expiry));
        assertEquals(SamlPendingSaveResult.ALREADY_PRESENT, save(store, "third", START.plusSeconds(90)));
        assertInstanceOf(SamlPendingConsumeResult.Missing.class, store.consume("wrong", "third", BUDGET));
        clock.value = expiry;
        assertEquals(SamlPendingSaveResult.SAVED, save(store, "fourth", START.plusSeconds(1)));
        CountingMap map = observe(store);
        assertEquals(1, map.size());
        assertCoherent(store, map);
        assertConsumed(store, "fourth");
    }

    @Test void expiredAddressBeyondTheMaintenanceBatchCanBeReplacedWithoutAnIndexLeak() throws Exception {
        var clock = new MutableClock();
        var store = seeded(clock, 200, 201, START.plusSeconds(1));
        assertEquals(SamlPendingSaveResult.SAVED, save(store, "z-target", START.plusSeconds(2)));
        CountingMap map = observe(store);
        clock.value = START.plusSeconds(2);
        assertEquals(SamlPendingSaveResult.SAVED, save(store, "z-target", START.plusSeconds(90)));
        assertEquals(BATCH + 1, map.removals);
        assertCoherent(store, map);
        assertConsumed(store, "z-target");
        assertCoherent(store, map);
    }

    @Test void consumingExpiredAddressBeyondBatchUnlinksItWithoutInvokingPredicate() throws Exception {
        var clock = new MutableClock();
        var store = seeded(clock, 200, 201, START.plusSeconds(1));
        assertEquals(SamlPendingSaveResult.SAVED, save(store, "z-target", START.plusSeconds(2)));
        CountingMap map = observe(store);
        clock.value = START.plusSeconds(2);
        assertInstanceOf(SamlPendingConsumeResult.Missing.class,
                store.consumeIfMatches("b", "z-target", r -> { fail("expired record validated"); return true; }, BUDGET));
        assertEquals(BATCH + 1, map.removals);
        assertCoherent(store, map);
    }

    @Test void consumedSlotChurnDoesNotRetainAuxiliaryTombstones() throws Exception {
        var store = instrumented(new MutableClock(), 2);
        assertEquals(SamlPendingSaveResult.SAVED, save(store, "long-lived", START.plusSeconds(3600)));
        CountingMap map = observe(store);
        for (int i = 0; i < 300; i++) {
            assertEquals(SamlPendingSaveResult.SAVED, save(store, "short-" + i, START.plusSeconds(60)));
            assertConsumed(store, "short-" + i);
            assertEquals(1, map.size());
            assertCoherent(store, map);
        }
        assertConsumed(store, "long-lived");
        assertCoherent(store, map);
    }

    @Test void recursiveIdenticalReplacementKeepsBothIndexesAndSingleConsumption() throws Exception {
        var store = instrumented(new MutableClock(), 1);
        Instant expiry = START.plusSeconds(60);
        assertEquals(SamlPendingSaveResult.SAVED, save(store, "target", expiry));
        CountingMap map = observe(store);
        assertInstanceOf(SamlPendingConsumeResult.Missing.class,
                store.consumeIfMatches("b", "target", r -> {
                    assertConsumed(store, "target");
                    assertEquals(SamlPendingSaveResult.SAVED, save(store, "target", expiry));
                    return true;
                }, BUDGET));
        assertEquals(1, map.size());
        assertCoherent(store, map);
        assertConsumed(store, "target");
        assertCoherent(store, map);
    }

    @Test void rollbackAndRejectedValidationCannotRemoveLiveState() throws Exception {
        var clock = new MutableClock();
        var store = seeded(clock, 100, 101, START.plusSeconds(60));
        CountingMap map = observe(store);
        clock.value = START.minusNanos(1);
        assertEquals(SamlPendingSaveResult.UNAVAILABLE, save(store, "new", START.plusSeconds(60)));
        assertInstanceOf(SamlPendingConsumeResult.Unavailable.class, store.consume("b", "0", BUDGET));
        assertEquals(100, map.size());
        assertEquals(0, map.removals);
        clock.value = START;
        assertInstanceOf(SamlPendingConsumeResult.Missing.class,
                store.consumeIfMatches("b", "0", r -> false, BUDGET));
        assertInstanceOf(SamlPendingConsumeResult.Unavailable.class,
                store.consumeIfMatches("b", "0", r -> { throw new IllegalStateException(); }, BUDGET));
        assertEquals(100, map.size());
        assertConsumed(store, "0");
        assertCoherent(store, map);
    }

    @Test void predicateTimeAdvanceAndRollbackKeepTheExpiryAndClockFences() throws Exception {
        var clock = new MutableClock();
        var store = instrumented(clock, 1);
        Instant expiry = START.plusNanos(1);
        assertEquals(SamlPendingSaveResult.SAVED, save(store, "target", expiry));
        CountingMap map = observe(store);
        assertInstanceOf(SamlPendingConsumeResult.Unavailable.class,
                store.consumeIfMatches("b", "target", r -> { clock.value = START.minusNanos(1); return true; }, BUDGET));
        assertEquals(1, map.size());
        clock.value = START;
        assertInstanceOf(SamlPendingConsumeResult.Missing.class,
                store.consumeIfMatches("b", "target", r -> { clock.value = expiry; return true; }, BUDGET));
        assertCoherent(store, map);
        assertEquals(SamlPendingSaveResult.SAVED, save(store, "new", expiry.plusSeconds(1)));
        assertConsumed(store, "new");
    }

    @Test void interruptedMaintenanceStopsBeforeUnboundedWorkOrAdmission() throws Exception {
        var clock = new MutableClock();
        var store = seeded(clock, 200, 200, START.plusSeconds(1));
        CountingMap map = observe(store);
        clock.value = START.plusSeconds(1);
        map.onRemove = () -> Thread.currentThread().interrupt();
        try {
            assertEquals(SamlPendingSaveResult.UNAVAILABLE, save(store, "new", START.plusSeconds(60)));
            assertTrue(Thread.currentThread().isInterrupted());
            assertEquals(1, map.removals);
        } finally { Thread.interrupted(); map.onRemove = () -> {}; }
        assertCoherent(store, map);
        assertEquals(SamlPendingSaveResult.SAVED, save(store, "new", START.plusSeconds(60)));
        assertConsumed(store, "new");
    }

    @Test void interruptedSaveCommitKeepsBothIndexesAndReportsIndeterminate() throws Exception {
        var store = instrumented(new MutableClock(), 1);
        CountingMap map = observe(store);
        map.onPut = () -> Thread.currentThread().interrupt();
        try {
            assertEquals(SamlPendingSaveResult.INDETERMINATE, save(store, "target", START.plusSeconds(60)));
            assertTrue(Thread.currentThread().isInterrupted());
        } finally { Thread.interrupted(); map.onPut = () -> {}; }
        assertEquals(1, map.size());
        assertCoherent(store, map);
        assertConsumed(store, "target");
        assertCoherent(store, map);
    }

    @Test void interruptedConsumeCommitKeepsBothIndexesAndReportsIndeterminate() throws Exception {
        var store = seeded(new MutableClock(), 1, 1, START.plusSeconds(60));
        CountingMap map = observe(store);
        map.onRemove = () -> Thread.currentThread().interrupt();
        try {
            assertInstanceOf(SamlPendingConsumeResult.Indeterminate.class, store.consume("b", "0", BUDGET));
            assertTrue(Thread.currentThread().isInterrupted());
        } finally { Thread.interrupted(); map.onRemove = () -> {}; }
        assertEquals(0, map.size());
        assertCoherent(store, map);
        assertInstanceOf(SamlPendingConsumeResult.Missing.class, store.consume("b", "0", BUDGET));
    }

    @Test void interruptedConsumeCleanupDoesNotValidateOrConsumeLiveTarget() throws Exception {
        interruptedConsumeCleanup(1);
    }

    @Test void interruptedFinalCleanupStepDoesNotValidateOrConsumeLiveTarget() throws Exception {
        interruptedConsumeCleanup(BATCH);
    }

    private void interruptedConsumeCleanup(int stopAfter) throws Exception {
        var clock = new MutableClock();
        var store = seeded(clock, 200, 201, START.plusSeconds(1));
        assertEquals(SamlPendingSaveResult.SAVED, save(store, "target", START.plusSeconds(60)));
        CountingMap map = observe(store);
        clock.value = START.plusSeconds(1);
        map.onRemove = () -> { if (map.removals == stopAfter) Thread.currentThread().interrupt(); };
        try {
            assertInstanceOf(SamlPendingConsumeResult.Unavailable.class,
                    store.consumeIfMatches("b", "target", r -> { fail("budget exhausted before predicate"); return true; }, BUDGET));
            assertEquals(stopAfter, map.removals);
        } finally { Thread.interrupted(); map.onRemove = () -> {}; }
        assertCoherent(store, map);
        assertConsumed(store, "target");
        assertCoherent(store, map);
    }

    @Test void lockContentionHonorsBudgetAndInterruptionWithoutChangingState() throws Exception {
        var store = seeded(new MutableClock(), 1, 1, START.plusSeconds(60));
        CountingMap map = observe(store);
        Field field = InMemoryPendingSamlAuthenticationStore.class.getDeclaredField("lock");
        field.setAccessible(true);
        ReentrantLock lock = (ReentrantLock) field.get(store);
        var result = new CompletableFuture<SamlPendingConsumeResult>();
        Thread waiter = new Thread(() -> result.complete(store.consume("b", "0", Duration.ofMillis(20))));
        lock.lock();
        try {
            waiter.start();
            assertInstanceOf(SamlPendingConsumeResult.Unavailable.class, result.get(5, TimeUnit.SECONDS));
            assertEquals(1, map.size());
        } finally { lock.unlock(); waiter.join(5000); }
        assertConsumed(store, "0");
        assertCoherent(store, map);
    }

    private static @NonNull InMemoryPendingSamlAuthenticationStore seeded(@NonNull MutableClock clock, int count, int limit, @NonNull Instant expiry) {
        var store = instrumented(clock, limit);
        for (int i = 0; i < count; i++) assertEquals(SamlPendingSaveResult.SAVED, save(store, "" + i, expiry));
        return store;
    }
    private static @NonNull InMemoryPendingSamlAuthenticationStore instrumented(@NonNull Clock clock,int limit){return new InMemoryPendingSamlAuthenticationStore(clock,limit,new CountingMap(Map.of()));}
    private static @NonNull SamlPendingSaveResult save(@NonNull InMemoryPendingSamlAuthenticationStore store, @NonNull String handle, @NonNull Instant expiry) {
        return store.save("b", handle, handle, expiry, BUDGET);
    }
    private static void assertConsumed(@NonNull InMemoryPendingSamlAuthenticationStore store, @NonNull String handle) {
        assertEquals(handle, assertInstanceOf(SamlPendingConsumeResult.Consumed.class,
                store.consume("b", handle, BUDGET)).getSealedRecord());
    }
    @SuppressWarnings("unchecked")
    private static @NonNull CountingMap observe(@NonNull InMemoryPendingSamlAuthenticationStore store) throws Exception {
        Field field = InMemoryPendingSamlAuthenticationStore.class.getDeclaredField("entries");
        field.setAccessible(true);
        CountingMap map = (CountingMap)field.get(store);map.visits=0;map.removals=0;
        return map;
    }
    private static void assertCoherent(@NonNull InMemoryPendingSamlAuthenticationStore store, @NonNull CountingMap map) throws Exception {
        for (Field field : InMemoryPendingSamlAuthenticationStore.class.getDeclaredFields()) {
            field.setAccessible(true);
            if (field.get(store) instanceof Collection<?> index) {
                assertEquals(map.size(), index.size(), "one auxiliary expiry node per retained record");
                assertEquals(Set.copyOf(map.values()), Set.copyOf(index));
            }
        }
    }
    private static final class CountingMap extends HashMap<String, Object> {
        int visits;
        int removals;
        Runnable onVisit = () -> {};
        Runnable onRemove = () -> {};
        Runnable onPut = () -> {};
        CountingMap(@NonNull Map<@NonNull String, @NonNull Object> source) { super(source); }
        @Override public @Nullable Object put(@NonNull String key, @NonNull Object value) {
            Object prior = super.put(key, value);
            onPut.run();
            return prior;
        }
        @Override public @Nullable Object remove(@NonNull Object key) {
            Object removed = super.remove(key);
            if (removed != null) { removals++; onRemove.run(); }
            return removed;
        }
        @Override public @NonNull Set<Map.@NonNull Entry<@NonNull String, @NonNull Object>> entrySet() {
            Set<Map.Entry<String, Object>> delegate = super.entrySet();
            return new AbstractSet<>() {
                @Override public int size() { return delegate.size(); }
                @Override public @NonNull Iterator<Map.@NonNull Entry<@NonNull String, @NonNull Object>> iterator() {
                    Iterator<Map.Entry<String, Object>> iterator = delegate.iterator();
                    return new Iterator<>() {
                        @Override public boolean hasNext() { return iterator.hasNext(); }
                        @Override public Map.@NonNull Entry<@NonNull String, @NonNull Object> next() { visits++; onVisit.run(); return iterator.next(); }
                        @Override public void remove() { iterator.remove(); removals++; onRemove.run(); }
                    };
                }
            };
        }
    }
    private static final class MutableClock extends Clock {
        Instant value = START;
        @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
        @Override public @NonNull Instant instant() { return value; }
    }
}
