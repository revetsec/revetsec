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
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class InMemoryPendingSamlAuthenticationStoreTests {
    private static final @NonNull Instant START = Instant.parse("2026-10-09T00:00:00Z");
    private static final @NonNull Duration BUDGET = Duration.ofSeconds(1);

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
