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

import static org.junit.jupiter.api.Assertions.*;

import com.revetsec.ErrorCategory;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

final class OAuthClientMetadataCacheTests {
    private static final @NonNull Duration WAIT = Duration.ofSeconds(5);

    private static @NonNull String nonce(int n) {
        return java.util.Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(java.nio.ByteBuffer.allocate(32).putInt(n).array());
    }

    private static @NonNull OAuthClientMetadataCacheKey key(int n) {
        return OAuthClientMetadataCacheKey.fromStoredForm(
                "revetsec:cimd-cache:1:" + nonce(1) + ":" + nonce(n));
    }

    private static @NonNull OAuthClientMetadataCacheEntry entry(int n, int version) {
        return OAuthClientMetadataCacheEntry.fromStoredForm(
                key(n),
                nonce(version),
                Instant.ofEpochSecond(2000000000),
                "encrypted-test-envelope");
    }

    @Test
    void persistedCarriersRoundTripWithoutBecomingProofsAndRedact() {
        var key = key(5);
        var copy = OAuthClientMetadataCacheKey.fromStoredForm(key.getStorageKey());
        assertEquals(key, copy);
        assertEquals(key.hashCode(), copy.hashCode());
        assertNotEquals(key, key(6));
        assertNotEquals(key, null);
        assertNotEquals(key, "other");
        var e = entry(5, 7);
        var rebuilt =
                OAuthClientMetadataCacheEntry.fromStoredForm(
                        copy, e.getVersion(), e.getExpiresAt(), e.toSealedForm());
        assertEquals(key, rebuilt.getKey());
        assertEquals(nonce(7), rebuilt.getVersion());
        assertEquals(Instant.ofEpochSecond(2000000000), rebuilt.getExpiresAt());
        assertEquals("encrypted-test-envelope", rebuilt.toSealedForm());
        assertFalse(key.toString().contains(key.getStorageKey()));
        assertFalse(e.toString().contains(e.toSealedForm()));
        assertFalse(e.toString().contains(e.getVersion()));
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> malformedAddressesRejectCases() {
        String good = key(9).getStorageKey();
        return Stream.of(
                        "",
                        good + "x",
                        good.substring(1),
                        good.replace(":1:", ":2:"),
                        good.replace(':', '/'),
                        good.replace('A', '!'),
                        good.substring(0, good.length() - 1) + "B",
                        "x".repeat(4096))
                .map(
                        v ->
                                DynamicTest.dynamicTest(
                                        "address " + v.length(),
                                        () ->
                                                assertThrows(
                                                        IllegalArgumentException.class,
                                                        () ->
                                                                OAuthClientMetadataCacheKey
                                                                        .fromStoredForm(v))));
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> malformedVersionsRejectCases() {
        return Stream.of(
                        "",
                        "A".repeat(42),
                        "A".repeat(44),
                        "A".repeat(42) + "B",
                        "A".repeat(42) + "=",
                        "!".repeat(43))
                .map(
                        v ->
                                DynamicTest.dynamicTest(
                                        "version " + v.length() + " " + v,
                                        () ->
                                                assertThrows(
                                                        IllegalArgumentException.class,
                                                        () ->
                                                                OAuthClientMetadataCacheEntry
                                                                        .fromStoredForm(
                                                                                key(1),
                                                                                v,
                                                                                Instant.EPOCH,
                                                                                "opaque"))));
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> malformedEnvelopesRejectCases() {
        return Stream.of("", "é", "x".repeat(16385))
                .map(
                        v ->
                                DynamicTest.dynamicTest(
                                        "envelope " + v.length(),
                                        () ->
                                                assertThrows(
                                                        IllegalArgumentException.class,
                                                        () ->
                                                                OAuthClientMetadataCacheEntry
                                                                        .fromStoredForm(
                                                                                key(1),
                                                                                nonce(4),
                                                                                Instant.EPOCH,
                                                                                v))));
    }

    // Deliberately violate the annotated contract to check runtime misuse rejection.
    @SuppressWarnings("NullAway")
    @Test
    void envelopeBoundaryAndFiniteWholeSecondExpiryAreStorageOnly() {
        assertEquals(
                16384,
                OAuthClientMetadataCacheEntry.fromStoredForm(
                                key(1), nonce(3), Instant.MIN, "x".repeat(16384))
                        .toSealedForm()
                        .length());
        for (Instant invalid :
                List.of(Instant.MAX, OAuthStoreFormat.PERMANENT, Instant.EPOCH.plusNanos(1)))
            assertThrows(
                    IllegalArgumentException.class,
                    () ->
                            OAuthClientMetadataCacheEntry.fromStoredForm(
                                    key(1), nonce(3), invalid, "opaque"));
        assertThrows(
                NullPointerException.class, () -> OAuthClientMetadataCacheKey.fromStoredForm(null));
        assertThrows(
                NullPointerException.class,
                () ->
                        OAuthClientMetadataCacheEntry.fromStoredForm(
                                null, nonce(1), Instant.EPOCH, "opaque"));
        assertThrows(
                NullPointerException.class,
                () ->
                        OAuthClientMetadataCacheEntry.fromStoredForm(
                                key(1), null, Instant.EPOCH, "opaque"));
        assertThrows(
                NullPointerException.class,
                () ->
                        OAuthClientMetadataCacheEntry.fromStoredForm(
                                key(1), nonce(1), null, "opaque"));
        assertThrows(
                NullPointerException.class,
                () ->
                        OAuthClientMetadataCacheEntry.fromStoredForm(
                                key(1), nonce(1), Instant.EPOCH, null));
    }

    @Test
    void defaultsAreFreshBoundedAndCustomStorageIsNotCalledAtBuild() {
        assertEquals(128, InMemoryOAuthClientMetadataCache.fromDefaults().getMaximumEntries());
        assertNotSame(
                InMemoryOAuthClientMetadataCache.fromDefaults(),
                InMemoryOAuthClientMetadataCache.fromDefaults());
        AtomicInteger calls = new AtomicInteger();
        OAuthClientMetadataCache custom =
                new OAuthClientMetadataCache() {
                    @Override
                    public @NonNull Optional<@NonNull OAuthClientMetadataCacheEntry> read(
                            @NonNull OAuthClientMetadataCacheKey key, @NonNull Duration budget) {
                        calls.incrementAndGet();
                        throw OAuthClientMetadataCacheException.fromReason(
                                OAuthClientMetadataCacheException.Reason.UNAVAILABLE);
                    }

                    @Override
                    public @NonNull Boolean compareAndSet(
                            @NonNull OAuthClientMetadataCacheKey key,
                            @Nullable String v,
                            @Nullable OAuthClientMetadataCacheEntry e,
                            @NonNull Duration budget) {
                        calls.incrementAndGet();
                        return false;
                    }
                };
        var b =
                OAuthClientMetadataPolicy.withAddressResolver(
                                (h, t) -> {
                                    calls.incrementAndGet();
                                    return List.of();
                                })
                        .maximumCacheEntries(2)
                        .cache(custom);
        var explicit = b.build();
        assertSame(custom, explicit.getCache().orElseThrow());
        assertSame(custom, explicit.cacheForEngine());
        assertEquals(0, calls.get());
        var reset = b.cache(null).build();
        assertTrue(reset.getCache().isEmpty());
        var a = reset.cacheForEngine();
        var c = reset.cacheForEngine();
        assertNotSame(a, c);
        assertEquals(
                2, assertInstanceOf(InMemoryOAuthClientMetadataCache.class, a).getMaximumEntries());
        assertTrue(OAuthClientMetadataPolicy.disabledInstance().getCache().isEmpty());
        assertThrows(
                IllegalStateException.class,
                () -> OAuthClientMetadataPolicy.disabledInstance().cacheForEngine());
        assertSame(custom, explicit.cacheForEngine());
        assertEquals(0, calls.get());
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> capacityBoundsCases() {
        return Stream.of(0, -1, 4097, Integer.MAX_VALUE)
                .map(
                        n ->
                                DynamicTest.dynamicTest(
                                        n.toString(),
                                        () ->
                                                assertThrows(
                                                        IllegalArgumentException.class,
                                                        () ->
                                                                InMemoryOAuthClientMetadataCache
                                                                        .fromMaximumEntries(n))));
    }

    // Deliberately violate the annotated contract to check runtime misuse rejection.
    @SuppressWarnings("NullAway")
    @Test
    void maximumCapacityAndNullInput() {
        assertEquals(
                4096,
                InMemoryOAuthClientMetadataCache.fromMaximumEntries(4096).getMaximumEntries());
        assertThrows(
                NullPointerException.class,
                () -> InMemoryOAuthClientMetadataCache.fromMaximumEntries(null));
    }

    @Test
    void exactAtomicInsertReplacementAndRemovalProtectNewerEntries() {
        var cache = InMemoryOAuthClientMetadataCache.fromMaximumEntries(2);
        var one = entry(1, 10);
        var two = entry(1, 11);
        assertTrue(cache.read(key(1), WAIT).isEmpty());
        assertTrue(cache.compareAndSet(key(1), null, one, WAIT));
        assertSame(one, cache.read(key(1), WAIT).orElseThrow());
        assertFalse(cache.compareAndSet(key(1), null, two, WAIT));
        assertFalse(cache.compareAndSet(key(1), nonce(9), two, WAIT));
        assertTrue(cache.compareAndSet(key(1), nonce(10), two, WAIT));
        assertFalse(cache.compareAndSet(key(1), nonce(10), null, WAIT));
        assertSame(two, cache.read(key(1), WAIT).orElseThrow());
        assertTrue(cache.compareAndSet(key(1), nonce(11), null, WAIT));
        assertTrue(cache.read(key(1), WAIT).isEmpty());
        assertFalse(cache.compareAndSet(key(1), nonce(11), entry(1, 12), WAIT));
        assertTrue(cache.compareAndSet(key(1), null, null, WAIT));
        assertTrue(cache.compareAndSet(key(1), null, entry(1, 13), WAIT));
        assertFalse(cache.toString().contains(nonce(13)));
    }

    @Test
    void replacementMustMatchAddressAndUseADifferentVersion() {
        var cache = InMemoryOAuthClientMetadataCache.fromDefaults();
        assertThrows(
                IllegalArgumentException.class,
                () -> cache.compareAndSet(key(1), null, entry(2, 10), WAIT));
        assertThrows(
                IllegalArgumentException.class,
                () -> cache.compareAndSet(key(1), nonce(10), entry(1, 10), WAIT));
        assertThrows(
                IllegalArgumentException.class,
                () -> cache.compareAndSet(key(1), "bad", null, WAIT));
    }

    // Deliberately violate the annotated contract to check runtime misuse rejection.
    @SuppressWarnings("NullAway")
    @Test
    void allOperationsCheckInputsAndPositiveBudgets() {
        var cache = InMemoryOAuthClientMetadataCache.fromDefaults();
        assertThrows(NullPointerException.class, () -> cache.read(null, WAIT));
        assertThrows(NullPointerException.class, () -> cache.compareAndSet(null, null, null, WAIT));
        assertThrows(NullPointerException.class, () -> cache.read(key(1), null));
        assertThrows(
                NullPointerException.class, () -> cache.compareAndSet(key(1), null, null, null));
        for (Duration d : List.of(Duration.ZERO, Duration.ofNanos(-1))) {
            assertThrows(IllegalArgumentException.class, () -> cache.read(key(1), d));
            assertThrows(
                    IllegalArgumentException.class,
                    () -> cache.compareAndSet(key(1), null, null, d));
        }
        assertTrue(cache.read(key(1), Duration.ofSeconds(Long.MAX_VALUE)).isEmpty());
    }

    @Test
    void leastRecentlyUsedEntriesEvictBeforeInsertionAndNoAuthorityComesFromExpiry() {
        var cache = InMemoryOAuthClientMetadataCache.fromMaximumEntries(2);
        assertTrue(cache.compareAndSet(key(1), null, entry(1, 1), WAIT));
        assertTrue(cache.compareAndSet(key(2), null, entry(2, 2), WAIT));
        assertTrue(cache.read(key(1), WAIT).isPresent());
        assertTrue(cache.compareAndSet(key(3), null, entry(3, 3), WAIT));
        assertTrue(cache.read(key(2), WAIT).isEmpty());
        assertEquals(2, cache.sizeForTests());
        assertTrue(cache.read(key(1), WAIT).isPresent());
        var past =
                OAuthClientMetadataCacheEntry.fromStoredForm(
                        key(4), nonce(4), Instant.EPOCH, "opaque");
        assertTrue(cache.compareAndSet(key(4), null, past, WAIT));
        assertSame(past, cache.read(key(4), WAIT).orElseThrow());
    }

    @Test
    void explicitSharedProviderSelectionsShareStorageWhileDefaultSelectionsDoNot() {
        var shared = InMemoryOAuthClientMetadataCache.fromMaximumEntries(4);
        var p = OAuthClientMetadataPolicy.fromAddressResolver((h, t) -> List.of());
        var q =
                OAuthClientMetadataPolicy.withAddressResolver((h, t) -> List.of())
                        .cache(shared)
                        .build();
        var a = q.cacheForEngine();
        var b = q.cacheForEngine();
        assertTrue(a.compareAndSet(key(1), null, entry(1, 1), WAIT));
        assertTrue(b.read(key(1), WAIT).isPresent());
        var localA = p.cacheForEngine();
        var localB = p.cacheForEngine();
        assertTrue(localA.compareAndSet(key(1), null, entry(1, 1), WAIT));
        assertTrue(localB.read(key(1), WAIT).isEmpty());
        var other =
                OAuthClientMetadataCacheKey.fromStoredForm(
                        "revetsec:cimd-cache:1:" + nonce(2) + ":" + nonce(1));
        assertTrue(shared.read(other, WAIT).isEmpty());
    }

    @Test
    void simultaneousMissingKeyWritersHaveOneWinner() throws Exception {
        var cache = InMemoryOAuthClientMetadataCache.fromMaximumEntries(4);
        var pool = Executors.newFixedThreadPool(8);
        var start = new CountDownLatch(1);
        AtomicInteger successes = new AtomicInteger();
        List<java.util.concurrent.Future<?>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < 8; i++) {
                int v = i + 10;
                futures.add(
                        pool.submit(
                                () -> {
                                    start.await();
                                    if (cache.compareAndSet(key(1), null, entry(1, v), WAIT))
                                        successes.incrementAndGet();
                                    return true;
                                }));
            }
            start.countDown();
            for (var f : futures) f.get(5, TimeUnit.SECONDS);
            assertEquals(1, successes.get());
            assertEquals(1, cache.sizeForTests());
        } finally {
            pool.shutdownNow();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test
    void slowOlderFetchCannotOverwriteOrDeleteTheWinningVersion() throws Exception {
        var cache = InMemoryOAuthClientMetadataCache.fromDefaults();
        assertTrue(cache.compareAndSet(key(1), null, entry(1, 10), WAIT));
        var readDone = new CountDownLatch(1);
        var newerDone = new CountDownLatch(1);
        var pool = Executors.newSingleThreadExecutor();
        try {
            var slow =
                    pool.submit(
                            () -> {
                                String old = cache.read(key(1), WAIT).orElseThrow().getVersion();
                                readDone.countDown();
                                assertTrue(newerDone.await(5, TimeUnit.SECONDS));
                                assertFalse(cache.compareAndSet(key(1), old, entry(1, 12), WAIT));
                                assertFalse(cache.compareAndSet(key(1), old, null, WAIT));
                                return true;
                            });
            assertTrue(readDone.await(5, TimeUnit.SECONDS));
            assertTrue(cache.compareAndSet(key(1), nonce(10), entry(1, 11), WAIT));
            newerDone.countDown();
            assertTrue(slow.get(5, TimeUnit.SECONDS));
            assertEquals(nonce(11), cache.read(key(1), WAIT).orElseThrow().getVersion());
        } finally {
            newerDone.countDown();
            pool.shutdownNow();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test
    void concurrentUniqueWritesStayAtConfiguredCapacity() throws Exception {
        var cache = InMemoryOAuthClientMetadataCache.fromMaximumEntries(7);
        var pool = Executors.newFixedThreadPool(8);
        var start = new CountDownLatch(1);
        List<java.util.concurrent.Future<?>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < 8; i++) {
                int offset = i * 250;
                futures.add(
                        pool.submit(
                                () -> {
                                    start.await();
                                    for (int n = 0; n < 250; n++) {
                                        assertTrue(
                                                cache.compareAndSet(
                                                        key(offset + n + 1),
                                                        null,
                                                        entry(offset + n + 1, offset + n + 1),
                                                        WAIT));
                                        assertTrue(cache.sizeForTests() <= 7);
                                    }
                                    return true;
                                }));
            }
            start.countDown();
            for (var f : futures) f.get(10, TimeUnit.SECONDS);
            assertEquals(7, cache.sizeForTests());
        } finally {
            pool.shutdownNow();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test
    void contendedLockHonorsDeadlineWithoutChangingStorage() throws Exception {
        var cache = InMemoryOAuthClientMetadataCache.fromDefaults();
        var held = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var pool = Executors.newSingleThreadExecutor();
        try {
            var holder =
                    pool.submit(
                            () -> {
                                cache.lockForTests().lock();
                                try {
                                    held.countDown();
                                    release.await();
                                    return true;
                                } finally {
                                    cache.lockForTests().unlock();
                                }
                            });
            assertTrue(held.await(5, TimeUnit.SECONDS));
            var failure =
                    assertThrows(
                            OAuthClientMetadataCacheException.class,
                            () ->
                                    cache.compareAndSet(
                                            key(1), null, entry(1, 1), Duration.ofMillis(30)));
            assertEquals(OAuthClientMetadataCacheException.Reason.TIMEOUT, failure.getReason());
            assertNull(failure.getCause());
            release.countDown();
            assertTrue(holder.get(5, TimeUnit.SECONDS));
            assertTrue(cache.read(key(1), WAIT).isEmpty());
        } finally {
            release.countDown();
            pool.shutdownNow();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test
    void interruptionBeforeAndDuringLockWaitPreservesFlagsAndClosesWorkers() throws Exception {
        var cache = InMemoryOAuthClientMetadataCache.fromDefaults();
        try {
            Thread.currentThread().interrupt();
            assertEquals(
                    OAuthClientMetadataCacheException.Reason.INTERRUPTED,
                    assertThrows(
                                    OAuthClientMetadataCacheException.class,
                                    () -> cache.read(key(1), WAIT))
                            .getReason());
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
        cache.lockForTests().lock();
        AtomicReference<OAuthClientMetadataCacheException> failure = new AtomicReference<>();
        AtomicBoolean preserved = new AtomicBoolean();
        var entered = new CountDownLatch(1);
        Thread t =
                new Thread(
                        () -> {
                            entered.countDown();
                            try {
                                assertTrue(cache.read(key(1), WAIT).isEmpty());
                            } catch (OAuthClientMetadataCacheException e) {
                                failure.set(e);
                                preserved.set(Thread.currentThread().isInterrupted());
                            }
                        });
        try {
            t.start();
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            long cutoff = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
            while (!cache.lockForTests().hasQueuedThread(t)
                    && t.isAlive()
                    && System.nanoTime() < cutoff) Thread.onSpinWait();
            assertTrue(cache.lockForTests().hasQueuedThread(t));
            t.interrupt();
            t.join(2000);
            assertFalse(t.isAlive());
            assertEquals(
                    OAuthClientMetadataCacheException.Reason.INTERRUPTED,
                    java.util.Objects.requireNonNull(failure.get()).getReason());
            assertTrue(preserved.get());
        } finally {
            cache.lockForTests().unlock();
            t.interrupt();
            t.join(2000);
        }
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> providerFailureDiagnosticsCases() {
        return Stream.of(OAuthClientMetadataCacheException.Reason.values())
                .map(
                        r ->
                                DynamicTest.dynamicTest(
                                        r.name(),
                                        () -> {
                                            var e = OAuthClientMetadataCacheException.fromReason(r);
                                            assertEquals(r, e.getReason());
                                            assertEquals(ErrorCategory.TRANSPORT, e.getCategory());
                                            assertEquals(
                                                    r
                                                            != OAuthClientMetadataCacheException
                                                                    .Reason.INTERRUPTED,
                                                    e.isTransient());
                                            assertNull(e.getCause());
                                            e.addSuppressed(
                                                    new IllegalArgumentException("private-value"));
                                            assertEquals(0, e.getSuppressed().length);
                                            assertFalse(e.toString().contains("private-value"));
                                        }));
    }

    // Deliberately violate the annotated contract to check runtime misuse rejection.
    @SuppressWarnings("NullAway")
    @Test
    void nullFailureReasonIsMisuse() {
        assertThrows(
                NullPointerException.class,
                () -> OAuthClientMetadataCacheException.fromReason(null));
    }
}
