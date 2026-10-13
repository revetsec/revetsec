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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static java.util.Objects.requireNonNull;

final class InMemorySamlReplayCacheTests {
    private static final @NonNull Duration BUDGET = Duration.ofSeconds(5);
    private static final @NonNull Instant START = Instant.parse("2026-10-09T00:00:00Z");

    @Test void maximumCapacityAndExactMonotonicDeadlineAreAcceptedPrecisely() {
        assertDoesNotThrow(() -> InMemorySamlReplayCache.withLimit(
                Clock.fixed(START, ZoneOffset.UTC), 1_000_000));
        assertTrue(InMemorySamlReplayCache.expired(System.nanoTime() - 1));
        assertFalse(InMemorySamlReplayCache.expiredAt(100, 99, false));
        assertTrue(InMemorySamlReplayCache.expiredAt(100, 100, false));
        assertTrue(InMemorySamlReplayCache.expiredAt(100, 101, false));
        assertTrue(InMemorySamlReplayCache.expiredAt(100, 99, true));
    }

    @Test void refusesLiveEvictionAndReclaimsExpiredEntries() {
        MutableClock clock = new MutableClock(START);
        SamlReplayCache cache = InMemorySamlReplayCache.withLimit(clock, 1);
        Instant expiry = START.plusSeconds(10);
        assertEquals(SamlReplayCache.MarkResult.MARKED, cache.markIfAbsent("one", expiry, BUDGET));
        assertEquals(SamlReplayCache.MarkResult.ALREADY_PRESENT, cache.markIfAbsent("one", expiry, BUDGET));
        assertEquals(SamlReplayCache.MarkResult.CAPACITY_REFUSED,
                cache.markIfAbsent("two", expiry.plusSeconds(1), BUDGET));
        clock.set(expiry);
        assertEquals(SamlReplayCache.MarkResult.MARKED,
                cache.markIfAbsent("two", expiry.plusSeconds(1), BUDGET));
        assertEquals(SamlReplayCache.MarkResult.CAPACITY_REFUSED,
                cache.markIfAbsent("one", expiry.plusSeconds(2), BUDGET));
        assertTrue(cache.toString().contains("<redacted>"));
    }

    @Test void clockRollbackCannotReviveAnExpiredOrLiveKey() {
        MutableClock clock = new MutableClock(START);
        SamlReplayCache cache = InMemorySamlReplayCache.withLimit(clock, 2);
        Instant expiry = START.plusSeconds(10);
        assertEquals(SamlReplayCache.MarkResult.MARKED, cache.markIfAbsent("one", expiry, BUDGET));
        clock.set(START.plusSeconds(9));
        assertEquals(SamlReplayCache.MarkResult.ALREADY_PRESENT, cache.markIfAbsent("one", expiry, BUDGET));
        clock.set(START.minusSeconds(1));
        assertEquals(SamlReplayCache.MarkResult.UNAVAILABLE, cache.markIfAbsent("one", expiry, BUDGET));
        assertEquals(SamlReplayCache.MarkResult.UNAVAILABLE, cache.markIfAbsent("two", expiry, BUDGET));
        clock.set(START.plusSeconds(9));
        assertEquals(SamlReplayCache.MarkResult.ALREADY_PRESENT, cache.markIfAbsent("one", expiry, BUDGET));
        clock.set(expiry);
        assertEquals(SamlReplayCache.MarkResult.UNAVAILABLE, cache.markIfAbsent("one", expiry, BUDGET));
    }

    @Test void simultaneousAdmissionsHaveExactlyOneWinner() throws Exception {
        SamlReplayCache cache = InMemorySamlReplayCache.withLimit(Clock.fixed(START, ZoneOffset.UTC), 2);
        CountDownLatch release = new CountDownLatch(1);
        Callable<SamlReplayCache.MarkResult> admit = () -> {
            release.await();
            return cache.markIfAbsent("same", START.plusSeconds(30), BUDGET);
        };
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<SamlReplayCache.MarkResult> first = executor.submit(admit);
            Future<SamlReplayCache.MarkResult> second = executor.submit(admit);
            release.countDown();
            assertTrue((first.get() == SamlReplayCache.MarkResult.MARKED
                    && second.get() == SamlReplayCache.MarkResult.ALREADY_PRESENT)
                    || (first.get() == SamlReplayCache.MarkResult.ALREADY_PRESENT
                    && second.get() == SamlReplayCache.MarkResult.MARKED));
        } finally {
            executor.shutdownNow();
        }
    }

    @Test void lockTimeoutDoesNotAdmitAndCacheRecoversWhenHolderFinishes() throws Exception {
        BlockingClock clock = new BlockingClock(START);
        SamlReplayCache cache = InMemorySamlReplayCache.withLimit(clock, 2);
        Instant expiry = START.plusSeconds(60);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<SamlReplayCache.MarkResult> holder = executor.submit(() ->
                    cache.markIfAbsent("holder", expiry, Duration.ofSeconds(30)));
            assertTrue(clock.entered.await(1, TimeUnit.SECONDS));
            Future<SamlReplayCache.MarkResult> waiter = executor.submit(() ->
                    cache.markIfAbsent("waiter", expiry, Duration.ofMillis(40)));
            assertEquals(SamlReplayCache.MarkResult.UNAVAILABLE,
                    waiter.get(1, TimeUnit.SECONDS));
            clock.release.countDown();
            assertEquals(SamlReplayCache.MarkResult.MARKED, holder.get(1, TimeUnit.SECONDS));
            assertEquals(SamlReplayCache.MarkResult.MARKED,
                    cache.markIfAbsent("waiter", expiry, BUDGET));
        } finally {
            clock.release.countDown();
            executor.shutdownNow();
        }
    }

    @Test void interruptedLockWaitPreservesInterruptAndDoesNotAdmit() throws Exception {
        BlockingClock clock = new BlockingClock(START);
        SamlReplayCache cache = InMemorySamlReplayCache.withLimit(clock, 2);
        Instant expiry = START.plusSeconds(60);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        AtomicReference<SamlReplayCache.MarkResult> waiterResult = new AtomicReference<>();
        AtomicBoolean interruptedAfter = new AtomicBoolean();
        Thread waiter = new Thread(() -> {
            waiterResult.set(cache.markIfAbsent("waiter", expiry, BUDGET));
            interruptedAfter.set(Thread.currentThread().isInterrupted());
        });
        try {
            Future<SamlReplayCache.MarkResult> holder = executor.submit(() ->
                    cache.markIfAbsent("holder", expiry, Duration.ofSeconds(30)));
            assertTrue(clock.entered.await(1, TimeUnit.SECONDS));
            waiter.start();
            long parkedBy = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
            while (waiter.getState() != Thread.State.TIMED_WAITING && System.nanoTime() < parkedBy)
                Thread.sleep(1);
            assertEquals(Thread.State.TIMED_WAITING, waiter.getState());
            waiter.interrupt();
            waiter.join(1_000);
            assertFalse(waiter.isAlive());
            assertEquals(SamlReplayCache.MarkResult.UNAVAILABLE, waiterResult.get());
            assertTrue(interruptedAfter.get());
            clock.release.countDown();
            assertEquals(SamlReplayCache.MarkResult.MARKED, holder.get(1, TimeUnit.SECONDS));
            assertEquals(SamlReplayCache.MarkResult.MARKED,
                    cache.markIfAbsent("waiter", expiry, BUDGET));
        } finally {
            waiter.interrupt();
            clock.release.countDown();
            executor.shutdownNow();
            if (waiter.isAlive()) waiter.join(1_000);
        }
    }

    @Test void failedClockDoesNotAdmitAndRecoveryCanAdmit() {
        MutableClock clock = new MutableClock(START);
        SamlReplayCache cache = InMemorySamlReplayCache.withLimit(clock, 1);
        Instant expiry = START.plusSeconds(60);
        clock.fail();
        assertEquals(SamlReplayCache.MarkResult.UNAVAILABLE,
                cache.markIfAbsent("key", expiry, BUDGET));
        clock.recover();
        assertEquals(SamlReplayCache.MarkResult.MARKED,
                cache.markIfAbsent("key", expiry, BUDGET));
    }

    private static final class MutableClock extends Clock {
        private final @NonNull AtomicReference<@NonNull Instant> value;
        private final @NonNull AtomicBoolean failing = new AtomicBoolean();
        private MutableClock(@NonNull Instant initial) { value = new AtomicReference<>(initial); }
        private void set(@NonNull Instant instant) { value.set(instant); }
        private void fail() { failing.set(true); }
        private void recover() { failing.set(false); }
        @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return Clock.fixed(value.get(), zone); }
        @Override public @NonNull Instant instant() {
            if (failing.get()) throw new IllegalStateException("clock unavailable");
            return requireNonNull(value.get());
        }
    }

    private static final class BlockingClock extends Clock {
        private final @NonNull Instant value;
        private final @NonNull CountDownLatch entered = new CountDownLatch(1);
        private final @NonNull CountDownLatch release = new CountDownLatch(1);

        private BlockingClock(@NonNull Instant value) { this.value = value; }

        @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return Clock.fixed(value, zone); }
        @Override public @NonNull Instant instant() {
            entered.countDown();
            try {
                if (!release.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("clock not released");
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("clock interrupted", exception);
            }
            return value;
        }
    }
}
