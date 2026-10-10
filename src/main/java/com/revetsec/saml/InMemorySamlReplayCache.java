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

import javax.annotation.concurrent.ThreadSafe;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Bounded, process-local SAML assertion replay cache. A restart loses its records; use a shared
 * {@link SamlReplayCache} for more than one node. Live entries are never evicted. Expired records
 * are removed only when a subsequent write observes a clock at least as late as every prior write.
 * A clock rollback refuses new admissions until time catches up.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class InMemorySamlReplayCache implements SamlReplayCache {
    private static final int MAXIMUM_ENTRIES = 1_000_000;
    private static final @NonNull Duration MAXIMUM_BUDGET = Duration.ofSeconds(30);

    private final @NonNull ReentrantLock lock = new ReentrantLock();
    private final @NonNull Map<@NonNull String, @NonNull Instant> entries = new HashMap<>();
    private final @NonNull Clock clock;
    private final int maximumEntries;
    private @NonNull Instant lastObserved = Instant.MIN;

    private InMemorySamlReplayCache(@NonNull Clock clock, int maximumEntries) {
        this.clock = clock;
        this.maximumEntries = maximumEntries;
    }

    /**
     * Creates a volatile cache with an explicit entry limit.
     *
     * @param clock the time source used for admission and expiry
     * @param maximumEntries maximum number of live replay records, from 1 to 1000000
     * @return a new empty cache
     * @since 1.0.0
     */
    public static @NonNull InMemorySamlReplayCache withLimit(@NonNull Clock clock, int maximumEntries) {
        Objects.requireNonNull(clock);
        if (maximumEntries < 1 || maximumEntries > MAXIMUM_ENTRIES)
            throw new IllegalArgumentException("Invalid SAML replay cache capacity");
        return new InMemorySamlReplayCache(clock, maximumEntries);
    }

    /**
     * Creates a volatile cache with 65536 slots and the system UTC clock.
     *
     * @return a new cache
     * @since 1.0.0
     */
    public static @NonNull InMemorySamlReplayCache fromDefaults() {
        return withLimit(Clock.systemUTC(), 65_536);
    }

    @Override public @NonNull MarkResult markIfAbsent(@NonNull String key, @NonNull Instant expiresAt,
            @NonNull Duration remaining) {
        Objects.requireNonNull(key);
        Objects.requireNonNull(expiresAt);
        Objects.requireNonNull(remaining);
        if (key.isEmpty()) throw new IllegalArgumentException("Empty SAML replay key");
        if (remaining.isZero() || remaining.isNegative() || Thread.currentThread().isInterrupted())
            return MarkResult.UNAVAILABLE;
        Duration bounded = remaining.compareTo(MAXIMUM_BUDGET) > 0 ? MAXIMUM_BUDGET : remaining;
        long deadline = System.nanoTime() + bounded.toNanos();
        try {
            long wait = deadline - System.nanoTime();
            if (wait <= 0 || !lock.tryLock(wait, TimeUnit.NANOSECONDS)) return MarkResult.UNAVAILABLE;
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return MarkResult.UNAVAILABLE;
        }
        try {
            if (expired(deadline)) return MarkResult.UNAVAILABLE;
            Instant now;
            try { now = clock.instant(); }
            catch (RuntimeException exception) { return MarkResult.UNAVAILABLE; }
            if (now.isBefore(lastObserved)) return MarkResult.UNAVAILABLE;
            lastObserved = now;
            // A stale key cannot become fresh before the accepting caller's own expiry fence.
            if (!now.isBefore(expiresAt)) return MarkResult.UNAVAILABLE;
            Instant existing = entries.get(key);
            if (existing != null && now.isBefore(existing)) return MarkResult.ALREADY_PRESENT;
            entries.entrySet().removeIf(entry -> !now.isBefore(entry.getValue()));
            if (entries.size() >= maximumEntries) return MarkResult.CAPACITY_REFUSED;
            if (expired(deadline)) return MarkResult.UNAVAILABLE;
            entries.put(key, expiresAt);
            return expired(deadline) ? MarkResult.INDETERMINATE : MarkResult.MARKED;
        } finally {
            lock.unlock();
        }
    }

    private static boolean expired(long deadline) {
        return Thread.currentThread().isInterrupted() || deadline - System.nanoTime() <= 0;
    }

    /** Redacts replay keys. @since 1.0.0 */
    @Override public @NonNull String toString() { return "InMemorySamlReplayCache{entries=<redacted>}"; }
}
