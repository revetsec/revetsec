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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class InMemoryPendingSamlAuthenticationStoreTests {
    private static final @NonNull Instant START = Instant.parse("2026-10-09T00:00:00Z");
    private static final @NonNull Duration BUDGET = Duration.ofSeconds(1);

    @Test void monotonicDeadlineIsClosedAtTheExactNanosecond() {
        assertTrue(InMemoryPendingSamlAuthenticationStore.expired(System.nanoTime() - 1));
        assertFalse(InMemoryPendingSamlAuthenticationStore.expiredAt(100, 99, false));
        assertTrue(InMemoryPendingSamlAuthenticationStore.expiredAt(100, 100, false));
        assertTrue(InMemoryPendingSamlAuthenticationStore.expiredAt(100, 101, false));
        assertTrue(InMemoryPendingSamlAuthenticationStore.expiredAt(100, 99, true));
    }

    @Test void consumesOncePrunesExpiryAndKeepsCompoundKeysUnambiguous() {
        MutableClock clock = new MutableClock(START);
        InMemoryPendingSamlAuthenticationStore store = InMemoryPendingSamlAuthenticationStore.withLimit(clock, 2);
        Instant expiry = START.plusSeconds(60);
        assertEquals(SamlPendingSaveResult.SAVED, store.save("ab", "c", "first", expiry, BUDGET));
        assertEquals(SamlPendingSaveResult.SAVED, store.save("a", "bc", "second", expiry, BUDGET));
        assertEquals(SamlPendingSaveResult.ALREADY_PRESENT, store.save("ab", "c", "replacement", expiry, BUDGET));
        assertEquals(SamlPendingSaveResult.CAPACITY_REFUSED, store.save("another", "handle", "third", expiry, BUDGET));
        assertEquals("first", assertInstanceOf(SamlPendingConsumeResult.Consumed.class,
                store.consume("ab", "c", BUDGET)).getSealedRecord());
        assertInstanceOf(SamlPendingConsumeResult.Missing.class, store.consume("ab", "c", BUDGET));
        assertEquals("second", assertInstanceOf(SamlPendingConsumeResult.Consumed.class,
                store.consume("a", "bc", BUDGET)).getSealedRecord());
        assertEquals(SamlPendingSaveResult.SAVED, store.save("expired", "handle", "old", expiry, BUDGET));
        clock.set(expiry);
        assertInstanceOf(SamlPendingConsumeResult.Missing.class,
                store.consume("expired", "handle", BUDGET));
        assertEquals(SamlPendingSaveResult.SAVED,
                store.save("fresh", "handle", "new", expiry.plusSeconds(60), BUDGET));
        assertEquals("new", assertInstanceOf(SamlPendingConsumeResult.Consumed.class,
                store.consume("fresh", "handle", BUDGET)).getSealedRecord());
    }

    @Test void legacyStoreDoesNotFallBackToUnconditionalConsumption() {
        AtomicInteger consumes = new AtomicInteger();
        AtomicInteger validations = new AtomicInteger();
        PendingSamlAuthenticationStore legacy = new PendingSamlAuthenticationStore() {
            @Override public @NonNull SamlPendingSaveResult save(@NonNull String browserBinding,
                    @NonNull String handle, @NonNull String sealedRecord, @NonNull Instant expiresAt,
                    @NonNull Duration remaining) { return SamlPendingSaveResult.SAVED; }
            @Override public @NonNull SamlPendingConsumeResult consume(@NonNull String browserBinding,
                    @NonNull String handle, @NonNull Duration remaining) {
                consumes.incrementAndGet();
                return SamlPendingConsumeResult.Consumed.fromSealedRecord("sealed");
            }
        };
        assertInstanceOf(SamlPendingConsumeResult.Unavailable.class,
                legacy.consumeIfMatches("browser", "handle", record -> {
                    validations.incrementAndGet();
                    return true;
                }, BUDGET));
        assertEquals(0, validations.get());
        assertEquals(0, consumes.get());
    }

    @Test void refusedConditionalConsumeRetainsTheRecordForAnAcceptedCallback() {
        InMemoryPendingSamlAuthenticationStore store = InMemoryPendingSamlAuthenticationStore.withLimit(
                Clock.fixed(START, ZoneOffset.UTC), 1);
        assertEquals(SamlPendingSaveResult.SAVED,
                store.save("browser", "handle", "sealed", START.plusSeconds(60), BUDGET));
        assertInstanceOf(SamlPendingConsumeResult.Missing.class,
                store.consumeIfMatches("browser", "handle", record -> {
                    assertEquals("sealed", record);
                    return false;
                }, BUDGET));
        assertEquals("sealed", assertInstanceOf(SamlPendingConsumeResult.Consumed.class,
                store.consumeIfMatches("browser", "handle", "sealed"::equals, BUDGET)).getSealedRecord());
        assertInstanceOf(SamlPendingConsumeResult.Missing.class,
                store.consumeIfMatches("browser", "handle", record -> true, BUDGET));
    }

    @Test void throwingOrTimedOutValidationDoesNotRemoveTheRecord() {
        InMemoryPendingSamlAuthenticationStore store = InMemoryPendingSamlAuthenticationStore.withLimit(
                Clock.fixed(START, ZoneOffset.UTC), 1);
        assertEquals(SamlPendingSaveResult.SAVED,
                store.save("browser", "handle", "sealed", START.plusSeconds(60), BUDGET));
        assertInstanceOf(SamlPendingConsumeResult.Unavailable.class,
                store.consumeIfMatches("browser", "handle", record -> {
                    throw new IllegalStateException("validation unavailable");
                }, BUDGET));
        assertInstanceOf(SamlPendingConsumeResult.Unavailable.class,
                store.consumeIfMatches("browser", "handle", record -> {
                    long until = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(20);
                    while (System.nanoTime() - until < 0)
                        LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1));
                    return true;
                }, Duration.ofMillis(5)));
        assertEquals("sealed", assertInstanceOf(SamlPendingConsumeResult.Consumed.class,
                store.consume("browser", "handle", BUDGET)).getSealedRecord());
    }

    @Test void recordExpiryIsRecheckedAfterValidation() {
        MutableClock clock = new MutableClock(START);
        InMemoryPendingSamlAuthenticationStore store = InMemoryPendingSamlAuthenticationStore.withLimit(clock, 1);
        Instant expiry = START.plusSeconds(60);
        assertEquals(SamlPendingSaveResult.SAVED, store.save("browser", "handle", "sealed", expiry, BUDGET));
        assertInstanceOf(SamlPendingConsumeResult.Missing.class,
                store.consumeIfMatches("browser", "handle", record -> {
                    clock.set(expiry);
                    return true;
                }, BUDGET));
    }

    @Test void reentrantValidationCannotConsumeTheSameRecordTwiceOrRemoveAReplacement() {
        InMemoryPendingSamlAuthenticationStore store = InMemoryPendingSamlAuthenticationStore.withLimit(
                Clock.fixed(START, ZoneOffset.UTC), 1);
        Instant expiry = START.plusSeconds(60);
        for (boolean replace : new boolean[] {false, true}) {
            assertEquals(SamlPendingSaveResult.SAVED, store.save("browser", "handle", "sealed", expiry, BUDGET));
            assertInstanceOf(SamlPendingConsumeResult.Missing.class,
                    store.consumeIfMatches("browser", "handle", record -> {
                        assertEquals("sealed", assertInstanceOf(SamlPendingConsumeResult.Consumed.class,
                                store.consume("browser", "handle", BUDGET)).getSealedRecord());
                        if (replace)
                            assertEquals(SamlPendingSaveResult.SAVED,
                                    store.save("browser", "handle", "sealed", expiry, BUDGET));
                        return true;
                    }, BUDGET));
            if (replace)
                assertEquals("sealed", assertInstanceOf(SamlPendingConsumeResult.Consumed.class,
                        store.consume("browser", "handle", BUDGET)).getSealedRecord());
            else assertInstanceOf(SamlPendingConsumeResult.Missing.class, store.consume("browser", "handle", BUDGET));
        }
    }

    @Test void concurrentConditionalConsumesAdmitExactlyOneCaller() throws Exception {
        InMemoryPendingSamlAuthenticationStore store = InMemoryPendingSamlAuthenticationStore.withLimit(
                Clock.fixed(START, ZoneOffset.UTC), 1);
        assertEquals(SamlPendingSaveResult.SAVED,
                store.save("browser", "handle", "sealed", START.plusSeconds(60), BUDGET));
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger accepted = new AtomicInteger();
        AtomicInteger missing = new AtomicInteger();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Runnable consume = () -> {
            try {
                assertTrue(start.await(3, TimeUnit.SECONDS));
                SamlPendingConsumeResult result = store.consumeIfMatches("browser", "handle", "sealed"::equals, BUDGET);
                if (result instanceof SamlPendingConsumeResult.Consumed) accepted.incrementAndGet();
                else {
                    assertInstanceOf(SamlPendingConsumeResult.Missing.class, result);
                    missing.incrementAndGet();
                }
            } catch (Throwable thrown) { failure.set(thrown); }
        };
        Thread first = new Thread(consume);
        Thread second = new Thread(consume);
        first.start();
        second.start();
        start.countDown();
        first.join(3_000);
        second.join(3_000);
        assertFalse(first.isAlive());
        assertFalse(second.isAlive());
        assertNull(failure.get());
        assertEquals(1, accepted.get());
        assertEquals(1, missing.get());
    }

    @Test void failedBudgetAndClockRollbackLeavePendingRecordUntouched() {
        MutableClock clock = new MutableClock(START);
        InMemoryPendingSamlAuthenticationStore store = InMemoryPendingSamlAuthenticationStore.withLimit(clock, 1);
        Instant expiry = START.plusSeconds(60);
        assertEquals(SamlPendingSaveResult.SAVED, store.save("browser", "handle", "sealed", expiry, BUDGET));
        assertEquals(SamlPendingSaveResult.UNAVAILABLE,
                store.save("browser", "other", "other", expiry, Duration.ZERO));
        assertInstanceOf(SamlPendingConsumeResult.Unavailable.class,
                store.consume("browser", "handle", Duration.ZERO));
        clock.set(START.plusSeconds(20));
        assertInstanceOf(SamlPendingConsumeResult.Missing.class,
                store.consume("browser", "missing", BUDGET));
        clock.set(START.plusSeconds(10));
        assertEquals(SamlPendingSaveResult.UNAVAILABLE,
                store.save("browser", "other", "other", expiry, BUDGET));
        assertInstanceOf(SamlPendingConsumeResult.Unavailable.class,
                store.consume("browser", "handle", BUDGET));
        clock.set(START.plusSeconds(30));
        assertEquals("sealed", assertInstanceOf(SamlPendingConsumeResult.Consumed.class,
                store.consume("browser", "handle", BUDGET)).getSealedRecord());
    }

    @Test void invalidInputsAndFailingClockDoNotCreatePendingState() {
        MutableClock clock = new MutableClock(START);
        InMemoryPendingSamlAuthenticationStore store = InMemoryPendingSamlAuthenticationStore.withLimit(clock, 1);
        InMemoryPendingSamlAuthenticationStore.withLimit(clock, 1_000_000);
        assertThrows(IllegalArgumentException.class, () -> InMemoryPendingSamlAuthenticationStore.withLimit(clock, 0));
        assertThrows(IllegalArgumentException.class, () -> InMemoryPendingSamlAuthenticationStore.withLimit(clock, 1_000_001));
        assertThrows(IllegalArgumentException.class,
                () -> store.save("", "handle", "sealed", START.plusSeconds(60), BUDGET));
        assertThrows(IllegalArgumentException.class,
                () -> store.consume("browser", "", BUDGET));
        assertEquals(SamlPendingSaveResult.UNAVAILABLE,
                store.save("browser", "handle", "sealed", START, BUDGET));
        clock.fail();
        assertEquals(SamlPendingSaveResult.UNAVAILABLE,
                store.save("browser", "handle", "sealed", START.plusSeconds(60), BUDGET));
        assertInstanceOf(SamlPendingConsumeResult.Unavailable.class,
                store.consume("browser", "handle", BUDGET));
    }

    @Test void blockedStoreHonorsConsumerBudgetWithoutReleasingOrStealingRecord()
            throws Exception {
        BlockingClock clock = new BlockingClock();
        InMemoryPendingSamlAuthenticationStore store =
                InMemoryPendingSamlAuthenticationStore.withLimit(clock, 1);
        AtomicReference<SamlPendingSaveResult> saved = new AtomicReference<>();
        AtomicReference<SamlPendingConsumeResult> consumed = new AtomicReference<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        CountDownLatch consumerDone = new CountDownLatch(1);
        Thread writer = new Thread(() -> {
            try { saved.set(store.save("browser", "handle", "sealed", START.plusSeconds(60),
                    Duration.ofSeconds(5))); }
            catch (Throwable thrown) { failure.set(thrown); }
        });
        Thread consumer = new Thread(() -> {
            try { consumed.set(store.consume("browser", "handle", Duration.ofMillis(50))); }
            catch (Throwable thrown) { failure.set(thrown); }
            finally { consumerDone.countDown(); }
        });
        writer.start();
        try {
            assertTrue(clock.entered.await(3, TimeUnit.SECONDS));
            consumer.start();
            assertTrue(consumerDone.await(2, TimeUnit.SECONDS),
                    "The consumer must finish while the writer still holds the lock");
            assertInstanceOf(SamlPendingConsumeResult.Unavailable.class, consumed.get());
            assertNull(failure.get());
        } finally {
            clock.release.countDown();
            writer.join(3_000);
            if (consumer.isAlive()) consumer.join(3_000);
        }
        assertFalse(writer.isAlive());
        assertFalse(consumer.isAlive());
        assertEquals(SamlPendingSaveResult.SAVED, saved.get());
        assertNull(failure.get());
        assertEquals("sealed", assertInstanceOf(SamlPendingConsumeResult.Consumed.class,
                store.consume("browser", "handle", BUDGET)).getSealedRecord());
        AtomicReference<SamlPendingSaveResult> nextSave = new AtomicReference<>();
        Thread nextWriter = new Thread(() -> nextSave.set(store.save("other", "handle", "next",
                START.plusSeconds(60), BUDGET)));
        nextWriter.start();
        nextWriter.join(3_000);
        assertFalse(nextWriter.isAlive());
        assertEquals(SamlPendingSaveResult.SAVED, nextSave.get(),
                "A consumed record must release the lock for another thread");
    }

    @Test void interruptedConsumerPreservesItsInterruptAndLeavesPendingRecordUntouched()
            throws Exception {
        BlockingClock clock = new BlockingClock();
        InMemoryPendingSamlAuthenticationStore store =
                InMemoryPendingSamlAuthenticationStore.withLimit(clock, 1);
        AtomicReference<SamlPendingSaveResult> saved = new AtomicReference<>();
        AtomicReference<SamlPendingConsumeResult> consumed = new AtomicReference<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicBoolean consumerInterrupted = new AtomicBoolean();
        Thread writer = new Thread(() -> {
            try { saved.set(store.save("browser", "handle", "sealed", START.plusSeconds(60),
                    Duration.ofSeconds(5))); }
            catch (Throwable thrown) { failure.set(thrown); }
        });
        Thread consumer = new Thread(() -> {
            try { consumed.set(store.consume("browser", "handle", Duration.ofSeconds(5))); }
            catch (Throwable thrown) { failure.set(thrown); }
            finally { consumerInterrupted.set(Thread.currentThread().isInterrupted()); }
        });
        writer.start();
        try {
            assertTrue(clock.entered.await(3, TimeUnit.SECONDS));
            consumer.start();
            long observationDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
            while (consumer.getState() != Thread.State.TIMED_WAITING
                    && System.nanoTime() < observationDeadline)
                Thread.sleep(1);
            assertEquals(Thread.State.TIMED_WAITING, consumer.getState(),
                    "The consumer must be waiting for the held store lock");
            consumer.interrupt();
            consumer.join(3_000);
            assertFalse(consumer.isAlive());
            assertInstanceOf(SamlPendingConsumeResult.Unavailable.class, consumed.get());
            assertTrue(consumerInterrupted.get(), "The consumer's interrupt flag must survive");
            assertNull(failure.get());
        } finally {
            clock.release.countDown();
            writer.join(3_000);
            if (consumer.isAlive()) {
                consumer.interrupt();
                consumer.join(3_000);
            }
        }
        assertFalse(writer.isAlive());
        assertEquals(SamlPendingSaveResult.SAVED, saved.get());
        assertEquals("sealed", assertInstanceOf(SamlPendingConsumeResult.Consumed.class,
                store.consume("browser", "handle", BUDGET)).getSealedRecord());
    }

    private static final class BlockingClock extends Clock {
        private final @NonNull CountDownLatch entered = new CountDownLatch(1);
        private final @NonNull CountDownLatch release = new CountDownLatch(1);
        private final @NonNull AtomicBoolean first = new AtomicBoolean(true);

        @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }

        @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }

        @Override public @NonNull Instant instant() {
            if (first.compareAndSet(true, false)) {
                entered.countDown();
                try { release.await(); }
                catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(exception);
                }
            }
            return START;
        }
    }

    private static final class MutableClock extends Clock {
        private final @NonNull AtomicReference<@NonNull Instant> value;
        private final @NonNull AtomicBoolean failing = new AtomicBoolean();

        private MutableClock(@NonNull Instant initial) { value = new AtomicReference<>(initial); }

        private void set(@NonNull Instant next) { value.set(next); }

        private void fail() { failing.set(true); }

        @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }

        @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }

        @Override public @NonNull Instant instant() {
            if (failing.get()) throw new IllegalStateException("clock unavailable");
            return java.util.Objects.requireNonNull(value.get());
        }
    }
}
