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
import java.util.NavigableSet;
import java.util.Objects;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Predicate;

/**
 * Bounded, process-local store for pending SAML login and logout with atomic single consumption.
 * Restarting this process loses pending attempts. Distributed deployments supply their own shared store.
 * Expiry maintenance removes at most 64 unrelated expired records per operation, plus the
 * addressed record when expired. An ordered index retains exactly one node per stored record;
 * consuming a record also unlinks its node. Operations remain serialized, including conditional
 * validation, and their time budget does not guarantee a wall-clock execution bound.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class InMemoryPendingSamlAuthenticationStore implements PendingSamlAuthenticationStore {
    private static final int CLEANUP_BATCH = 64;
    private final @NonNull ReentrantLock lock = new ReentrantLock();
    private final @NonNull Map<@NonNull String, @NonNull Entry> entries;
    private final @NonNull NavigableSet<@NonNull Entry> expirations = new TreeSet<>(
            Comparator.comparing(Entry::expiresAt).thenComparing(Entry::key));
    private final @NonNull Clock clock;
    private final int maximumEntries;
    private @NonNull Instant lastObserved = Instant.MIN;

    private InMemoryPendingSamlAuthenticationStore(@NonNull Clock clock, int maximumEntries) {
        this(clock,maximumEntries,new HashMap<>());
    }

    @SuppressWarnings("unchecked")
    InMemoryPendingSamlAuthenticationStore(@NonNull Clock clock, int maximumEntries,
            @NonNull Map<@NonNull String, ?> entries) {
        this.clock = clock;
        this.maximumEntries = maximumEntries;
        Objects.requireNonNull(entries);
        if (!entries.isEmpty()) throw new IllegalArgumentException("Initial SAML pending entries must be empty");
        this.entries = (Map<@NonNull String,@NonNull Entry>)(Map<?,?>)entries;
    }

    /**
     * Creates an empty store with an explicit capacity.
     *
     * @param clock validation clock
     * @param maximumEntries maximum live attempts, from 1 to 1000000
     * @return local store
     * @since 1.0.0
     */
    public static @NonNull InMemoryPendingSamlAuthenticationStore fromLimit(@NonNull Clock clock,
            @NonNull Integer maximumEntries) {
        Objects.requireNonNull(clock);
        Objects.requireNonNull(maximumEntries);
        if (maximumEntries < 1 || maximumEntries > 1_000_000)
            throw new IllegalArgumentException("Invalid SAML pending capacity");
        return new InMemoryPendingSamlAuthenticationStore(clock, maximumEntries);
    }

    /**
     * Creates a process-local store with 65536 slots.
     *
     * @return local store
     * @since 1.0.0
     */
    public static @NonNull InMemoryPendingSamlAuthenticationStore fromDefaults() {
        return fromLimit(Clock.systemUTC(), 65_536);
    }

    @Override public @NonNull SamlPendingSaveResult save(@NonNull String browserBinding,
            @NonNull String relayStateHandle, @NonNull String sealedRecord,
            @NonNull Instant expiresAt, @NonNull Duration remaining) {
        Objects.requireNonNull(browserBinding);
        Objects.requireNonNull(relayStateHandle);
        Objects.requireNonNull(sealedRecord);
        Objects.requireNonNull(expiresAt);
        Objects.requireNonNull(remaining);
        if (browserBinding.isEmpty() || relayStateHandle.isEmpty() || sealedRecord.isEmpty())
            throw new IllegalArgumentException("Empty pending key or record");
        long deadline = deadline(remaining);
        if (deadline == 0) return SamlPendingSaveResult.UNAVAILABLE;
        if (!acquire(deadline)) return SamlPendingSaveResult.UNAVAILABLE;
        try {
            Instant now = now();
            if (now == null || !now.isBefore(expiresAt) || expired(deadline))
                return SamlPendingSaveResult.UNAVAILABLE;
            String key = key(browserBinding, relayStateHandle);
            Entry existing = entries.get(key);
            if (existing != null && now.isBefore(existing.expiresAt()))
                return SamlPendingSaveResult.ALREADY_PRESENT;
            if (existing != null) remove(existing);
            if (!cleanExpired(now, deadline)) return SamlPendingSaveResult.UNAVAILABLE;
            if (entries.size() >= maximumEntries) return SamlPendingSaveResult.CAPACITY_REFUSED;
            if (expired(deadline)) return SamlPendingSaveResult.UNAVAILABLE;
            Entry added = new Entry(key, sealedRecord, expiresAt);
            entries.put(key, added);
            expirations.add(added);
            return expired(deadline) ? SamlPendingSaveResult.INDETERMINATE : SamlPendingSaveResult.SAVED;
        } finally { lock.unlock(); }
    }

    @Override public @NonNull SamlPendingConsumeResult consume(@NonNull String browserBinding,
            @NonNull String relayStateHandle, @NonNull Duration remaining) {
        return consumeIfMatches(browserBinding, relayStateHandle, record -> true, remaining);
    }

    @SuppressWarnings("ReferenceEquality") // Removal requires the same live Entry, including identical replacements.
    @Override public @NonNull SamlPendingConsumeResult consumeIfMatches(@NonNull String browserBinding,
            @NonNull String relayStateHandle, @NonNull Predicate<@NonNull String> sealedRecordMatches,
            @NonNull Duration remaining) {
        Objects.requireNonNull(browserBinding);
        Objects.requireNonNull(relayStateHandle);
        Objects.requireNonNull(sealedRecordMatches);
        Objects.requireNonNull(remaining);
        if (browserBinding.isEmpty() || relayStateHandle.isEmpty())
            throw new IllegalArgumentException("Empty pending key");
        long deadline = deadline(remaining);
        if (deadline == 0 || !acquire(deadline)) return SamlPendingConsumeResult.Unavailable.INSTANCE;
        try {
            Instant now = now();
            if (now == null || expired(deadline)) return SamlPendingConsumeResult.Unavailable.INSTANCE;
            if (!cleanExpired(now, deadline)) return SamlPendingConsumeResult.Unavailable.INSTANCE;
            String key = key(browserBinding, relayStateHandle);
            Entry existing = entries.get(key);
            if (existing == null) return SamlPendingConsumeResult.Missing.INSTANCE;
            if (!now.isBefore(existing.expiresAt())) {
                remove(existing);
                return SamlPendingConsumeResult.Missing.INSTANCE;
            }
            boolean matches;
            try { matches = sealedRecordMatches.test(existing.sealedRecord()); }
            catch (RuntimeException exception) { return SamlPendingConsumeResult.Unavailable.INSTANCE; }
            now = now();
            if (now == null || expired(deadline)) return SamlPendingConsumeResult.Unavailable.INSTANCE;
            // The lock is reentrant: validation must not authorize a record already consumed or
            // replaced by a recursive call made by the predicate.
            if (entries.get(key) != existing || !now.isBefore(existing.expiresAt()) || !matches)
                return SamlPendingConsumeResult.Missing.INSTANCE;
            if (expired(deadline)) return SamlPendingConsumeResult.Unavailable.INSTANCE;
            remove(existing);
            return expired(deadline) ? SamlPendingConsumeResult.Indeterminate.INSTANCE
                    : SamlPendingConsumeResult.Consumed.fromSealedRecord(existing.sealedRecord());
        } finally { lock.unlock(); }
    }

    // Called only under lock after a non-rollback clock observation. No lazy tombstones:
    // arbitrary consume/save churn must not grow the expiry index beyond store capacity.
    private boolean cleanExpired(@NonNull Instant now, long deadline) {
        for (int removed = 0; removed < CLEANUP_BATCH; removed++) {
            if (expired(deadline)) return false;
            if (expirations.isEmpty()) return true;
            Entry first = expirations.first();
            if (now.isBefore(first.expiresAt())) return true;
            remove(first);
        }
        return !expired(deadline);
    }

    private void remove(@NonNull Entry entry) {
        entries.remove(entry.key());
        expirations.remove(entry);
    }

    private @Nullable Instant now() {
        Instant value;
        try { value = clock.instant(); }
        catch (RuntimeException exception) { return null; }
        if (value.isBefore(lastObserved)) return null;
        lastObserved = value;
        return value;
    }

    private static @NonNull String key(@NonNull String binding, @NonNull String relay) {
        return binding.length() + ":" + binding + relay.length() + ":" + relay;
    }

    private static long deadline(@NonNull Duration remaining) {
        if (remaining.isZero() || remaining.isNegative() || Thread.currentThread().isInterrupted()) return 0;
        long nanos;
        try { nanos = remaining.compareTo(Duration.ofSeconds(30)) > 0
                ? Duration.ofSeconds(30).toNanos() : remaining.toNanos(); }
        catch (ArithmeticException exception) { nanos = Duration.ofSeconds(30).toNanos(); }
        return System.nanoTime() + nanos;
    }

    private boolean acquire(long deadline) {
        try {
            long wait = deadline - System.nanoTime();
            return wait > 0 && lock.tryLock(wait, TimeUnit.NANOSECONDS);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    static boolean expired(long deadline) {
        return expiredAt(deadline, System.nanoTime(), Thread.currentThread().isInterrupted());
    }

    static boolean expiredAt(long deadline, long now, boolean interrupted) {
        return interrupted || deadline - now <= 0;
    }

    /**
     * Redacts pending data.
     *
     * @return redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "InMemoryPendingSamlAuthenticationStore{<redacted>}"; }

    private record Entry(@NonNull String key, @NonNull String sealedRecord, @NonNull Instant expiresAt) { }
}
