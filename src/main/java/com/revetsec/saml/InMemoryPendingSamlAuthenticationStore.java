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
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Bounded, process-local pending-login store with atomic single consumption. Restarting this
 * process loses pending logins. Distributed deployments supply their own shared store.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class InMemoryPendingSamlAuthenticationStore implements PendingSamlAuthenticationStore {
    private final @NonNull ReentrantLock lock = new ReentrantLock();
    private final @NonNull Map<@NonNull String, @NonNull Entry> entries = new HashMap<>();
    private final @NonNull Clock clock;
    private final int maximumEntries;
    private @NonNull Instant lastObserved = Instant.MIN;

    private InMemoryPendingSamlAuthenticationStore(@NonNull Clock clock, int maximumEntries) {
        this.clock = clock;
        this.maximumEntries = maximumEntries;
    }

    /**
     * Creates an empty store with an explicit capacity.
     *
     * @param clock validation clock
     * @param maximumEntries maximum live logins, from 1 to 1000000
     * @return local store
     * @since 1.0.0
     */
    public static @NonNull InMemoryPendingSamlAuthenticationStore withLimit(@NonNull Clock clock,
            int maximumEntries) {
        Objects.requireNonNull(clock);
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
        return withLimit(Clock.systemUTC(), 65_536);
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
            entries.entrySet().removeIf(entry -> !now.isBefore(entry.getValue().expiresAt()));
            if (entries.size() >= maximumEntries) return SamlPendingSaveResult.CAPACITY_REFUSED;
            if (expired(deadline)) return SamlPendingSaveResult.UNAVAILABLE;
            entries.put(key, new Entry(sealedRecord, expiresAt));
            return expired(deadline) ? SamlPendingSaveResult.INDETERMINATE : SamlPendingSaveResult.SAVED;
        } finally { lock.unlock(); }
    }

    @Override public @NonNull SamlPendingConsumeResult consume(@NonNull String browserBinding,
            @NonNull String relayStateHandle, @NonNull Duration remaining) {
        Objects.requireNonNull(browserBinding);
        Objects.requireNonNull(relayStateHandle);
        Objects.requireNonNull(remaining);
        if (browserBinding.isEmpty() || relayStateHandle.isEmpty())
            throw new IllegalArgumentException("Empty pending key");
        long deadline = deadline(remaining);
        if (deadline == 0 || !acquire(deadline)) return SamlPendingConsumeResult.Unavailable.INSTANCE;
        try {
            Instant now = now();
            if (now == null || expired(deadline)) return SamlPendingConsumeResult.Unavailable.INSTANCE;
            String key = key(browserBinding, relayStateHandle);
            Entry existing = entries.get(key);
            if (existing == null || !now.isBefore(existing.expiresAt()))
                return SamlPendingConsumeResult.Missing.INSTANCE;
            if (expired(deadline)) return SamlPendingConsumeResult.Unavailable.INSTANCE;
            entries.remove(key);
            return expired(deadline) ? SamlPendingConsumeResult.Indeterminate.INSTANCE
                    : SamlPendingConsumeResult.Consumed.fromSealedRecord(existing.sealedRecord());
        } finally { lock.unlock(); }
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

    private static boolean expired(long deadline) {
        return Thread.currentThread().isInterrupted() || deadline - System.nanoTime() <= 0;
    }

    /**
     * Redacts pending data.
     *
     * @return redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "InMemoryPendingSamlAuthenticationStore{<redacted>}"; }

    private record Entry(@NonNull String sealedRecord, @NonNull Instant expiresAt) { }
}
