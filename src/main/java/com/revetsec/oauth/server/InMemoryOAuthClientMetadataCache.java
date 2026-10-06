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

package com.revetsec.oauth.server;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.internal.ConcurrentLruMap;
import com.revetsec.internal.Limits;
import com.revetsec.internal.http.Deadline;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import javax.annotation.concurrent.ThreadSafe;

/**
 * Bounded single-process optional cache with timed interruptible locking and approximate LRU
 * eviction. The reused map is private: all access is serialized, entries are evicted before
 * insertion and every mutation drains its bounded maintenance work. No listener, loader, worker
 * thread or general map is exposed. There are at most maximumEntries retained records, each
 * syntax-bounded to a 16384-byte encrypted envelope. Reads/replacements cost bounded local work;
 * lock waits consume the supplied budget. Expiry/freshness is checked by the core before use, not
 * asserted by this storage cache. It may evict at any time and has no durability. Sharing one
 * instance shares only in-process storage; separate factories return separate caches. Applications
 * may supply a distributed implementation through the metadata policy's cache option.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
@CheckReturnValue
public final class InMemoryOAuthClientMetadataCache implements OAuthClientMetadataCache {
    private final int maximumEntries;
    private final @NonNull ReentrantLock lock = new ReentrantLock();
    private final @NonNull
            ConcurrentLruMap<
                    @NonNull OAuthClientMetadataCacheKey, @NonNull OAuthClientMetadataCacheEntry>
            entries;

    private InMemoryOAuthClientMetadataCache(int maximumEntries) {
        this.maximumEntries = maximumEntries;
        this.entries = new ConcurrentLruMap<>(maximumEntries);
    }

    /**
     * Constructs a fresh cache with the reviewed 128-entry default and no callback or thread
     * startup.
     *
     * @return the fresh local cache
     * @since 1.0.0
     */
    public static @NonNull InMemoryOAuthClientMetadataCache fromDefaults() {
        return fromMaximumEntries(Limits.CIMD_MAXIMUM_CACHE_ENTRIES.getDefaultIntValue());
    }

    /**
     * Constructs a fresh cache with a capacity from 1 through 4096, inclusive. This is local capacity
     * across all its keys.
     *
     * @param maximumEntries the entry limit
     * @return the fresh local cache
     * @throws NullPointerException if maximumEntries is null
     * @throws IllegalArgumentException if outside the allowed interval
     * @since 1.0.0
     */
    public static @NonNull InMemoryOAuthClientMetadataCache fromMaximumEntries(
            @NonNull Integer maximumEntries) {
        return new InMemoryOAuthClientMetadataCache(
                Limits.CIMD_MAXIMUM_CACHE_ENTRIES.require(requireNonNull(maximumEntries)));
    }

    /**
     * Returns the local retained-entry bound.
     *
     * @return the bound
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumEntries() {
        return this.maximumEntries;
    }

    /** {@inheritDoc}
     * @since 1.0.0
     */
    @Override
    public @NonNull Optional<@NonNull OAuthClientMetadataCacheEntry> read(
            @NonNull OAuthClientMetadataCacheKey key, @NonNull Duration remainingBudget) {
        requireNonNull(key);
        Deadline deadline = budget(remainingBudget);
        acquire(deadline);
        try {
            check(deadline);
            OAuthClientMetadataCacheEntry entry = this.entries.get(key);
            check(deadline);
            return Optional.ofNullable(entry);
        } finally {
            this.lock.unlock();
        }
    }

    /** {@inheritDoc}
     * @since 1.0.0
     */
    @Override
    public @NonNull Boolean compareAndSet(
            @NonNull OAuthClientMetadataCacheKey key,
            @Nullable String expectedVersion,
            @Nullable OAuthClientMetadataCacheEntry replacement,
            @NonNull Duration remainingBudget) {
        requireNonNull(key);
        if (expectedVersion != null) OAuthStoreFormat.nonce(expectedVersion);
        if (replacement != null
                && (!key.equals(replacement.getKey())
                        || replacement.getVersion().equals(expectedVersion)))
            throw new IllegalArgumentException("Invalid client metadata cache replacement.");
        Deadline deadline = budget(remainingBudget);
        acquire(deadline);
        try {
            check(deadline);
            OAuthClientMetadataCacheEntry current = this.entries.get(key);
            boolean matches =
                    current == null
                            ? expectedVersion == null
                            : current.getVersion().equals(expectedVersion);
            check(deadline);
            if (!matches) return false;
            if (replacement == null) {
                this.entries.remove(key);
                this.entries.drain();
            } else {
                if (current == null && this.entries.size() >= this.maximumEntries) {
                    List<OAuthClientMetadataCacheKey> order = this.entries.keysInAccessOrder();
                    this.entries.remove(order.get(order.size() - 1));
                    this.entries.drain();
                }
                this.entries.put(key, replacement);
                this.entries.drain();
            }
            check(deadline);
            return true;
        } finally {
            this.lock.unlock();
        }
    }

    private static @NonNull Deadline budget(@NonNull Duration remainingBudget) {
        requireNonNull(remainingBudget);
        if (remainingBudget.isZero() || remainingBudget.isNegative())
            throw new IllegalArgumentException("A positive cache operation budget is required.");
        return Deadline.fromNow(remainingBudget);
    }

    private void acquire(@NonNull Deadline deadline) {
        check(deadline);
        try {
            if (!this.lock.tryLock(Math.max(1, deadline.remainingNanos()), TimeUnit.NANOSECONDS))
                throw OAuthClientMetadataCacheException.fromReason(
                        OAuthClientMetadataCacheException.Reason.TIMEOUT);
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw OAuthClientMetadataCacheException.fromReason(
                    OAuthClientMetadataCacheException.Reason.INTERRUPTED);
        }
    }

    private static void check(@NonNull Deadline deadline) {
        if (Thread.currentThread().isInterrupted())
            throw OAuthClientMetadataCacheException.fromReason(
                    OAuthClientMetadataCacheException.Reason.INTERRUPTED);
        if (deadline.isExpired())
            throw OAuthClientMetadataCacheException.fromReason(
                    OAuthClientMetadataCacheException.Reason.TIMEOUT);
    }

    @NonNull ReentrantLock lockForTests() {
        return this.lock;
    }

    int sizeForTests() {
        this.lock.lock();
        try {
            return this.entries.size();
        } finally {
            this.lock.unlock();
        }
    }

    /** Returns a fixed description with no stored data.
     * @return the redacted description
     * @since 1.0.0
     */
    @Override
    public @NonNull String toString() {
        return "InMemoryOAuthClientMetadataCache{storage=<redacted>}";
    }
}
