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
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.PriorityQueue;
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
    private final @NonNull Map<@NonNull String, @NonNull ReplayEntry> entries = new HashMap<>();
    private final @NonNull Map<@NonNull String, @NonNull Integer> connectionCounts = new HashMap<>();
    private final @NonNull PriorityQueue<@NonNull ExpiryEntry> expiryIndex =
            new PriorityQueue<>(Comparator.comparing(ExpiryEntry::expiresAt));
    private final @NonNull Clock clock;
    private final int maximumEntries;
    private final int maximumPerConnection;
    private final @Nullable Map<@NonNull String, @NonNull Integer> connectionLimits;
    private @NonNull Instant lastObserved = Instant.MIN;

    private record ReplayEntry(@NonNull String connectionId, @NonNull Instant expiresAt) { }
    private record ExpiryEntry(@NonNull String key, @NonNull Instant expiresAt) { }

    private InMemorySamlReplayCache(@NonNull Clock clock, int maximumEntries,
            @Nullable Map<@NonNull String, @NonNull Integer> connectionLimits) {
        this.clock = clock;
        this.maximumEntries = maximumEntries;
        this.maximumPerConnection = Math.max(1, maximumEntries / 4);
        this.connectionLimits = connectionLimits;
    }

    /**
     * Creates a volatile cache with an explicit entry limit.
     *
     * New namespaced admissions are limited to one quarter of the total
     * capacity (at least one). Legacy three-argument admissions retain the
     * full configured capacity. This shared-pool heuristic does not reserve capacity for mutually
     * untrusted connections; use {@link #fromConnectionLimits(Clock, Map)} for fixed independent reservations.
     *
     * @param clock the time source used for admission and expiry
     * @param maximumEntries maximum number of live replay records, from 1 to 1000000
     * @return a new empty cache
     * @since 1.0.0
     */
    public static @NonNull InMemorySamlReplayCache fromLimit(@NonNull Clock clock, int maximumEntries) {
        Objects.requireNonNull(clock);
        if (maximumEntries < 1 || maximumEntries > MAXIMUM_ENTRIES)
            throw new IllegalArgumentException("Invalid SAML replay cache capacity");
        return new InMemorySamlReplayCache(clock, maximumEntries, null);
    }

    /**
     * Creates fixed independent replay reservations for application-approved IdP connections. Each connection
     * can use its entire configured quota even after all others fill theirs. Unknown connection IDs and the
     * namespace-free admission overload cannot consume reserved capacity. Live replay marks are never evicted.
     * <p>
     * Configuration is snapshotted without reading the clock. There is no borrowing or live reconfiguration;
     * replacing a populated cache requires an application transition preserving every still-live replay mark.
     * This remains a volatile, single-process cache; restart loses replay protection.
     *
     * @param clock admission and expiry clock
     * @param connectionLimits 1–1024 trusted connection IDs, each nonempty and at most 256 characters, with
     *                         positive quotas totaling at most 1000000 live records
     * @return an empty cache with immutable reservations
     * @throws NullPointerException if the clock, map, a connection ID or quota is null
     * @throws IllegalArgumentException if a configuration bound is exceeded
     * @since 1.0.0
     */
    public static @NonNull InMemorySamlReplayCache fromConnectionLimits(@NonNull Clock clock,
            @NonNull Map<@NonNull String, @NonNull Integer> connectionLimits) {
        Objects.requireNonNull(clock);
        Objects.requireNonNull(connectionLimits);
        if (connectionLimits.isEmpty() || connectionLimits.size() > 1024)
            throw new IllegalArgumentException("Invalid SAML replay connection reservations");
        Map<String, Integer> snapshot = Map.copyOf(connectionLimits);
        long total = 0;
        for (Map.Entry<String, Integer> entry : snapshot.entrySet()) {
            if (entry.getKey().isEmpty() || entry.getKey().length() > 256 || entry.getValue() < 1)
                throw new IllegalArgumentException("Invalid SAML replay connection reservations");
            total += entry.getValue();
            if (total > MAXIMUM_ENTRIES)
                throw new IllegalArgumentException("Invalid SAML replay connection reservations");
        }
        return new InMemorySamlReplayCache(clock, (int) total, snapshot);
    }

    /**
     * Creates a volatile cache with 65536 slots and the system UTC clock.
     *
     * @return a new cache
     * @since 1.0.0
     */
    public static @NonNull InMemorySamlReplayCache fromDefaults() {
        return fromLimit(Clock.systemUTC(), 65_536);
    }

    @Override public @NonNull MarkResult markIfAbsent(@NonNull String key, @NonNull Instant expiresAt,
            @NonNull Duration remaining) {
        return mark("", key, expiresAt, remaining);
    }

    @Override public @NonNull MarkResult markIfAbsent(@NonNull String connectionId,
            @NonNull String key, @NonNull Instant expiresAt, @NonNull Duration remaining) {
        Objects.requireNonNull(connectionId);
        if (connectionId.isEmpty()) throw new IllegalArgumentException("Empty SAML connection namespace");
        return mark(connectionId, key, expiresAt, remaining);
    }

    private @NonNull MarkResult mark(@NonNull String connectionId, @NonNull String key,
            @NonNull Instant expiresAt, @NonNull Duration remaining) {
        Objects.requireNonNull(key);
        Objects.requireNonNull(expiresAt);
        Objects.requireNonNull(remaining);
        if (key.isEmpty()) throw new IllegalArgumentException("Empty SAML replay key");
        if (remaining.isZero() || remaining.isNegative() || Thread.currentThread().isInterrupted())
            return MarkResult.UNAVAILABLE;
        if (this.connectionLimits != null && !this.connectionLimits.containsKey(connectionId))
            return MarkResult.CAPACITY_REFUSED;
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
            ReplayEntry existing = entries.get(key);
            if (existing != null && now.isBefore(existing.expiresAt())) return MarkResult.ALREADY_PRESENT;
            reclaimExpired(now);
            if (entries.size() >= maximumEntries) return MarkResult.CAPACITY_REFUSED;
            int connectionLimit = this.connectionLimits == null ? this.maximumPerConnection
                    : this.connectionLimits.getOrDefault(connectionId, 0);
            if (!connectionId.isEmpty()
                    && connectionCounts.getOrDefault(connectionId, 0) >= connectionLimit)
                return MarkResult.CAPACITY_REFUSED;
            if (expired(deadline)) return MarkResult.UNAVAILABLE;
            entries.put(key, new ReplayEntry(connectionId, expiresAt));
            expiryIndex.add(new ExpiryEntry(key, expiresAt));
            if (!connectionId.isEmpty()) connectionCounts.merge(connectionId, 1, Integer::sum);
            return expired(deadline) ? MarkResult.INDETERMINATE : MarkResult.MARKED;
        } finally {
            lock.unlock();
        }
    }

    private void reclaimExpired(@NonNull Instant now) {
        while (true) {
            ExpiryEntry earliest = expiryIndex.peek();
            if (earliest == null || now.isBefore(earliest.expiresAt())) return;
            expiryIndex.remove();
            ReplayEntry entry = entries.get(earliest.key());
            if (entry == null || !entry.expiresAt().equals(earliest.expiresAt())) continue;
            entries.remove(earliest.key());
            if (!entry.connectionId().isEmpty()) {
                int count = connectionCounts.getOrDefault(entry.connectionId(), 0) - 1;
                if (count == 0) connectionCounts.remove(entry.connectionId());
                else connectionCounts.put(entry.connectionId(), count);
            }
        }
    }

    static boolean expired(long deadline) {
        return expiredAt(deadline, System.nanoTime(), Thread.currentThread().isInterrupted());
    }

    static boolean expiredAt(long deadline, long now, boolean interrupted) {
        return interrupted || deadline - now <= 0;
    }

    /** Redacts replay keys. @since 1.0.0 */
    @Override public @NonNull String toString() { return "InMemorySamlReplayCache{entries=<redacted>}"; }
}
