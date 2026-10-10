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
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static java.util.Objects.requireNonNull;

final class InMemorySamlReplayCacheTests {
    private static final @NonNull Duration BUDGET = Duration.ofSeconds(5);
    private static final @NonNull Instant START = Instant.parse("2026-10-09T00:00:00Z");

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

    private static final class MutableClock extends Clock {
        private final @NonNull AtomicReference<@NonNull Instant> value;
        private MutableClock(@NonNull Instant initial) { value = new AtomicReference<>(initial); }
        private void set(@NonNull Instant instant) { value.set(instant); }
        @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return Clock.fixed(value.get(), zone); }
        @Override public @NonNull Instant instant() { return requireNonNull(value.get()); }
    }
}
