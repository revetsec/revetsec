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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.revetsec.OutboundUriPolicy;
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.ConcurrentLruMap;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.http.RawResponse;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

final class OAuthClientMetadataCacheBoundaryTests {
    private static final @NonNull String CLIENT_ID =
            "https://client.example.com/metadata";
    private static final @NonNull String ISSUER =
            "https://issuer.example.com/tenant";
    private static final @NonNull Instant NOW = Instant.parse("2026-10-06T12:00:00Z");

    @Test
    void cacheAddressValidatesTheNamespaceAndIdentifierIndependently() {
        String valid = cacheKey(1).getStorageKey();
        int namespaceOffset = "revetsec:cimd-cache:1:".length();
        String malformedNamespace =
                valid.substring(0, namespaceOffset)
                        + '!'
                        + valid.substring(namespaceOffset + 1);

        assertThrows(
                IllegalArgumentException.class,
                () -> OAuthClientMetadataCacheKey.fromStoredForm(malformedNamespace));
    }

    @Test
    void redirectCountAcceptsTheExactIngressLimit() {
        OAuthServerIngressLimits limits = OAuthServerIngressLimits.fromDefaults();
        List<JsonString> redirects = new ArrayList<>();
        for (int i = 0; i < limits.redirects; ++i)
            redirects.add(JsonString.fromValue("https://client.example.com/callback/" + i));
        byte[] document =
                JsonObject.builder()
                        .put("client_id", CLIENT_ID)
                        .put("client_name", "boundary")
                        .put("token_endpoint_auth_method", "none")
                        .put("redirect_uris", JsonArray.fromElements(redirects))
                        .build()
                        .toJson()
                        .getBytes(StandardCharsets.UTF_8);

        OAuthClientMetadataDocument parsed =
                OAuthClientMetadataDocument.parse(
                        CLIENT_ID, document, policy(null), limits, false, false);

        assertEquals(limits.redirects, parsed.redirectUris().size());
    }

    @Test
    void replacementAtCapacityRetainsEveryOtherEntry() {
        InMemoryOAuthClientMetadataCache cache =
                InMemoryOAuthClientMetadataCache.fromMaximumEntries(2);
        OAuthClientMetadataCacheEntry first = cacheEntry(1, 11);
        OAuthClientMetadataCacheEntry second = cacheEntry(2, 12);
        OAuthClientMetadataCacheEntry replacement = cacheEntry(1, 13);
        Duration budget = Duration.ofSeconds(5);
        assertTrue(cache.compareAndSet(first.getKey(), null, first, budget));
        assertTrue(cache.compareAndSet(second.getKey(), null, second, budget));

        assertTrue(
                cache.compareAndSet(
                        first.getKey(), first.getVersion(), replacement, budget));

        assertEquals(2, cache.sizeForTests());
        assertEquals(replacement, cache.read(first.getKey(), budget).orElseThrow());
        assertEquals(second, cache.read(second.getKey(), budget).orElseThrow());
    }

    @Test
    void expiredEntryWaitStopsBeforeTryingTheLock() throws Exception {
        InMemoryOAuthClientMetadataCache cache =
                InMemoryOAuthClientMetadataCache.fromMaximumEntries(2);
        InstrumentedLock lock = new InstrumentedLock(false);
        replace(cache, "lock", lock);
        try {
            Thread.currentThread().interrupt();
            OAuthClientMetadataCacheException failure =
                    assertThrows(
                            OAuthClientMetadataCacheException.class,
                            () -> cache.read(cacheKey(1), Duration.ofSeconds(5)));
            assertEquals(
                    OAuthClientMetadataCacheException.Reason.INTERRUPTED,
                    failure.getReason());
            assertEquals(0, lock.attempts.get());
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void readChecksInterruptionImmediatelyAfterAcquiringTheLock() throws Exception {
        InMemoryOAuthClientMetadataCache cache =
                InMemoryOAuthClientMetadataCache.fromMaximumEntries(2);
        InstrumentedMap entries = new InstrumentedMap(2);
        replace(cache, "entries", entries);
        replace(cache, "lock", new InstrumentedLock(true));
        try {
            OAuthClientMetadataCacheException failure =
                    assertThrows(
                            OAuthClientMetadataCacheException.class,
                            () -> cache.read(cacheKey(1), Duration.ofSeconds(5)));
            assertEquals(
                    OAuthClientMetadataCacheException.Reason.INTERRUPTED,
                    failure.getReason());
            assertEquals(0, entries.reads.get());
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void readChecksInterruptionAfterTheMapRead() throws Exception {
        InMemoryOAuthClientMetadataCache cache =
                InMemoryOAuthClientMetadataCache.fromMaximumEntries(2);
        InstrumentedMap entries = new InstrumentedMap(2);
        entries.interruptOnRead = true;
        replace(cache, "entries", entries);
        try {
            OAuthClientMetadataCacheException failure =
                    assertThrows(
                            OAuthClientMetadataCacheException.class,
                            () -> cache.read(cacheKey(1), Duration.ofSeconds(5)));
            assertEquals(
                    OAuthClientMetadataCacheException.Reason.INTERRUPTED,
                    failure.getReason());
            assertEquals(1, entries.reads.get());
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void compareAndSetChecksInterruptionBeforeReading() throws Exception {
        InMemoryOAuthClientMetadataCache cache =
                InMemoryOAuthClientMetadataCache.fromMaximumEntries(2);
        InstrumentedMap entries = new InstrumentedMap(2);
        replace(cache, "entries", entries);
        replace(cache, "lock", new InstrumentedLock(true));
        try {
            OAuthClientMetadataCacheException failure =
                    assertThrows(
                            OAuthClientMetadataCacheException.class,
                            () ->
                                    cache.compareAndSet(
                                            cacheKey(1),
                                            null,
                                            cacheEntry(1, 11),
                                            Duration.ofSeconds(5)));
            assertEquals(
                    OAuthClientMetadataCacheException.Reason.INTERRUPTED,
                    failure.getReason());
            assertEquals(0, entries.reads.get());
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void compareAndSetChecksInterruptionAfterReadingAndBeforeMutation() throws Exception {
        InMemoryOAuthClientMetadataCache cache =
                InMemoryOAuthClientMetadataCache.fromMaximumEntries(2);
        InstrumentedMap entries = new InstrumentedMap(2);
        OAuthClientMetadataCacheEntry original = cacheEntry(1, 11);
        entries.put(original.getKey(), original);
        entries.drain();
        entries.writes.set(0);
        entries.interruptOnRead = true;
        replace(cache, "entries", entries);
        try {
            OAuthClientMetadataCacheException failure =
                    assertThrows(
                            OAuthClientMetadataCacheException.class,
                            () ->
                                    cache.compareAndSet(
                                            original.getKey(),
                                            original.getVersion(),
                                            cacheEntry(1, 12),
                                            Duration.ofSeconds(5)));
            assertEquals(
                    OAuthClientMetadataCacheException.Reason.INTERRUPTED,
                    failure.getReason());
            assertEquals(0, entries.writes.get());
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void compareAndSetChecksInterruptionAfterAppliedMaintenance() throws Exception {
        InMemoryOAuthClientMetadataCache cache =
                InMemoryOAuthClientMetadataCache.fromMaximumEntries(2);
        InstrumentedMap entries = new InstrumentedMap(2);
        entries.interruptOnDrain = true;
        replace(cache, "entries", entries);
        try {
            OAuthClientMetadataCacheException failure =
                    assertThrows(
                            OAuthClientMetadataCacheException.class,
                            () ->
                                    cache.compareAndSet(
                                            cacheKey(1),
                                            null,
                                            cacheEntry(1, 11),
                                            Duration.ofSeconds(5)));
            assertEquals(
                    OAuthClientMetadataCacheException.Reason.INTERRUPTED,
                    failure.getReason());
            assertEquals(1, entries.writes.get());
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void exactCodecPlaintextAndSealedLimitsRoundTrip() {
        StateSealer sealer = sealer(1024);
        OAuthClientMetadataCacheCodec codec = codec(sealer, policy(null));

        OAuthClientMetadataCacheEntry entry =
                codec.seal(
                        CLIENT_ID,
                        clientDocument("x".repeat(146)),
                        Instant.EPOCH,
                        Instant.EPOCH.plusSeconds(120));

        assertEquals(1024, entry.toSealedForm().length());
        assertEquals(
                "x".repeat(146),
                codec.open(CLIENT_ID, entry, Instant.EPOCH)
                        .orElseThrow()
                        .document()
                        .clientName());

        IllegalArgumentException failure =
                assertThrows(
                        IllegalArgumentException.class,
                        () ->
                                codec.seal(
                                        CLIENT_ID,
                                        clientDocument("x".repeat(147)),
                                        Instant.EPOCH,
                                        Instant.EPOCH.plusSeconds(120)));
        assertEquals("Invalid OAuth store value.", failure.getMessage());
        assertEquals(0, failure.getSuppressed().length);
    }

    @Test
    void exactMaximumMetadataDocumentSurvivesTheCacheEnvelope() {
        OAuthClientMetadataPolicy policy = policy(null);
        byte[] document = exactDocument(policy.getMaximumDocumentBytes());
        StateSealer sealer = sealer(16384);
        OAuthClientMetadataCacheCodec codec = codec(sealer, policy);

        OAuthClientMetadataCacheEntry entry =
                codec.seal(CLIENT_ID, document, NOW, NOW.plusSeconds(120));

        assertEquals(policy.getMaximumDocumentBytes().intValue(), document.length);
        assertTrue(codec.open(CLIENT_ID, entry, NOW).isPresent());

        OAuthClientMetadataPolicy divisibleLimit =
                OAuthClientMetadataPolicy.withAddressResolver(
                                (host, budget) -> {
                                    throw new AssertionError("No resolver in deterministic seam.");
                                })
                        .maximumDocumentBytes(1026)
                        .build();
        byte[] divisibleDocument = exactDocument(divisibleLimit.getMaximumDocumentBytes());
        OAuthClientMetadataCacheCodec divisibleCodec = codec(sealer, divisibleLimit);
        OAuthClientMetadataCacheEntry divisibleEntry =
                divisibleCodec.seal(
                        CLIENT_ID, divisibleDocument, NOW, NOW.plusSeconds(120));
        assertTrue(divisibleCodec.open(CLIENT_ID, divisibleEntry, NOW).isPresent());
    }

    @Test
    void rollbackObservedAfterTheReadRemainsStickyThroughRelease() {
        StateSealer sealer = sealer(16384);
        OAuthClientMetadataPolicy envelopePolicy = policy(null);
        OAuthClientMetadataCacheEntry old =
                codec(sealer, envelopePolicy)
                        .seal(CLIENT_ID, clientDocument("cached"), NOW, NOW.plusSeconds(120));
        SequencedClock clock =
                new SequencedClock(
                        List.of(
                                NOW.plusSeconds(10),
                                NOW.plusSeconds(5),
                                NOW.plusSeconds(10),
                                NOW.plusSeconds(10),
                                NOW.plusSeconds(10)));
        AtomicInteger fetches = new AtomicInteger();
        OAuthClientMetadataCache cache = new FixedReadCache(old, null);
        OAuthClientMetadataFetcher fetcher =
                fetcher(
                        sealer,
                        policy(cache),
                        clock,
                        (uri, deadline) -> {
                            fetches.incrementAndGet();
                            return response("fresh");
                        });

        OAuthClientMetadataDocument result = fetcher.reusable(CLIENT_ID, deadline());

        assertEquals("fresh", result.clientName());
        assertEquals(1, fetches.get());
    }

    @Test
    void rollbackObservedAfterTheFetchSuppressesTheOptionalWrite() {
        StateSealer sealer = sealer(16384);
        AtomicInteger writes = new AtomicInteger();
        OAuthClientMetadataCache cache = new FixedReadCache(null, writes);
        SequencedClock clock =
                new SequencedClock(
                        List.of(
                                NOW.plusSeconds(10),
                                NOW.plusSeconds(10),
                                NOW.plusSeconds(5),
                                NOW.plusSeconds(10),
                                NOW.plusSeconds(10)));
        OAuthClientMetadataFetcher fetcher =
                fetcher(sealer, policy(cache), clock, (uri, deadline) -> response("fresh"));

        OAuthClientMetadataDocument result = fetcher.reusable(CLIENT_ID, deadline());

        assertEquals("fresh", result.clientName());
        assertEquals(0, writes.get());
    }

    private static byte @NonNull [] exactDocument(@NonNull Integer maximumBytes) {
        byte[] empty = clientDocumentWithPadding("");
        int paddingLength = maximumBytes - empty.length;
        assertTrue(paddingLength > 0);
        byte[] result = clientDocumentWithPadding("x".repeat(paddingLength));
        assertEquals(maximumBytes.intValue(), result.length);
        return result;
    }

    private static byte @NonNull [] clientDocument(@NonNull String name) {
        return JsonObject.builder()
                .put("client_id", CLIENT_ID)
                .put("client_name", name)
                .put("token_endpoint_auth_method", "none")
                .put(
                        "redirect_uris",
                        JsonArray.fromElements(
                                List.of(
                                        JsonString.fromValue(
                                                "https://client.example.com/callback"))))
                .build()
                .toJson()
                .getBytes(StandardCharsets.UTF_8);
    }

    private static byte @NonNull [] clientDocumentWithPadding(@NonNull String padding) {
        return JsonObject.builder()
                .put("client_id", CLIENT_ID)
                .put("client_name", "boundary")
                .put("token_endpoint_auth_method", "none")
                .put(
                        "redirect_uris",
                        JsonArray.fromElements(
                                List.of(
                                        JsonString.fromValue(
                                                "https://client.example.com/callback"))))
                .put("padding", padding)
                .build()
                .toJson()
                .getBytes(StandardCharsets.UTF_8);
    }

    private static @NonNull OAuthClientMetadataPolicy policy(
            @Nullable OAuthClientMetadataCache cache) {
        return OAuthClientMetadataPolicy.withAddressResolver(
                        (host, budget) -> {
                            throw new AssertionError("No resolver in deterministic seam.");
                        })
                .cache(cache)
                .build();
    }

    private static @NonNull OAuthClientMetadataCacheCodec codec(
            @NonNull StateSealer sealer, @NonNull OAuthClientMetadataPolicy policy) {
        return new OAuthClientMetadataCacheCodec(
                ISSUER,
                sealer,
                policy,
                OAuthServerIngressLimits.fromDefaults(),
                false,
                false);
    }

    private static @NonNull OAuthClientMetadataFetcher fetcher(
            @NonNull StateSealer sealer,
            @NonNull OAuthClientMetadataPolicy policy,
            @NonNull Clock clock,
            OAuthClientMetadataFetcher.@NonNull Transport transport) {
        return new OAuthClientMetadataFetcher(
                ISSUER,
                sealer,
                policy,
                OAuthServerIngressLimits.fromDefaults(),
                false,
                false,
                OutboundUriPolicy.defaultInstance(),
                clock,
                transport);
    }

    private static @NonNull StateSealer sealer(int maximumSealedLength) {
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; ++i) key[i] = (byte) (i + 1);
        return StateSealer.withActiveKey(
                        SealingKey.fromBase64("k", Base64.getEncoder().encodeToString(key)))
                .maximumSealedLength(maximumSealedLength)
                .build();
    }

    private static @NonNull RawResponse response(@NonNull String name) {
        return new RawResponse(
                200,
                HttpHeaders.of(Map.of("Cache-Control", List.of("max-age=120")), (a, b) -> true),
                clientDocument(name),
                null,
                false,
                Duration.ZERO);
    }

    private static @NonNull Deadline deadline() {
        return Deadline.fromNow(Duration.ofSeconds(5));
    }

    private static @NonNull OAuthClientMetadataCacheKey cacheKey(int value) {
        return OAuthClientMetadataCacheKey.fromStoredForm(
                "revetsec:cimd-cache:1:" + nonce(1) + ':' + nonce(value));
    }

    private static @NonNull OAuthClientMetadataCacheEntry cacheEntry(int key, int version) {
        return OAuthClientMetadataCacheEntry.fromStoredForm(
                cacheKey(key), nonce(version), NOW.plusSeconds(120), "opaque");
    }

    private static @NonNull String nonce(int value) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(java.nio.ByteBuffer.allocate(32).putInt(value).array());
    }

    private static void replace(
            @NonNull InMemoryOAuthClientMetadataCache cache,
            @NonNull String fieldName,
            @NonNull Object value)
            throws ReflectiveOperationException {
        java.lang.reflect.Field field =
                InMemoryOAuthClientMetadataCache.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(cache, value);
    }

    private static final class FixedReadCache implements OAuthClientMetadataCache {
        private final @Nullable OAuthClientMetadataCacheEntry entry;
        private final @Nullable AtomicInteger writes;

        private FixedReadCache(
                @Nullable OAuthClientMetadataCacheEntry entry, @Nullable AtomicInteger writes) {
            this.entry = entry;
            this.writes = writes;
        }

        @Override
        public @NonNull Optional<@NonNull OAuthClientMetadataCacheEntry> read(
                @NonNull OAuthClientMetadataCacheKey key, @NonNull Duration remainingBudget) {
            return Optional.ofNullable(this.entry);
        }

        @Override
        public @NonNull Boolean compareAndSet(
                @NonNull OAuthClientMetadataCacheKey key,
                @Nullable String expectedVersion,
                @Nullable OAuthClientMetadataCacheEntry replacement,
                @NonNull Duration remainingBudget) {
            assertNotNull(this.writes);
            this.writes.incrementAndGet();
            return true;
        }
    }

    private static final class SequencedClock extends Clock {
        private final @NonNull List<@NonNull Instant> values;
        private int index;

        private SequencedClock(@NonNull List<@NonNull Instant> values) {
            this.values = List.copyOf(values);
        }

        @Override
        public @NonNull Instant instant() {
            int selected = Math.min(this.index, this.values.size() - 1);
            ++this.index;
            return this.values.get(selected);
        }

        @Override
        public @NonNull ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public @NonNull Clock withZone(@NonNull ZoneId zone) {
            return this;
        }
    }

    private static final class InstrumentedLock extends ReentrantLock {
        private static final long serialVersionUID = 1L;
        private final boolean interruptAfterAcquire;
        private final @NonNull AtomicInteger attempts = new AtomicInteger();

        private InstrumentedLock(boolean interruptAfterAcquire) {
            this.interruptAfterAcquire = interruptAfterAcquire;
        }

        @Override
        public boolean tryLock(long timeout, @NonNull TimeUnit unit)
                throws InterruptedException {
            this.attempts.incrementAndGet();
            boolean acquired = super.tryLock(timeout, unit);
            if (acquired && this.interruptAfterAcquire) Thread.currentThread().interrupt();
            return acquired;
        }
    }

    private static final class InstrumentedMap
            extends ConcurrentLruMap<
                    @NonNull OAuthClientMetadataCacheKey,
                    @NonNull OAuthClientMetadataCacheEntry> {
        private final @NonNull AtomicInteger reads = new AtomicInteger();
        private final @NonNull AtomicInteger writes = new AtomicInteger();
        private boolean interruptOnRead;
        private boolean interruptOnDrain;

        private InstrumentedMap(int maximumEntries) {
            super(maximumEntries);
        }

        @Override
        public @Nullable OAuthClientMetadataCacheEntry get(@NonNull Object key) {
            this.reads.incrementAndGet();
            OAuthClientMetadataCacheEntry result = super.get(key);
            if (this.interruptOnRead) Thread.currentThread().interrupt();
            return result;
        }

        @Override
        public @Nullable OAuthClientMetadataCacheEntry put(
                @NonNull OAuthClientMetadataCacheKey key,
                @NonNull OAuthClientMetadataCacheEntry value) {
            this.writes.incrementAndGet();
            return super.put(key, value);
        }

        @Override
        public void drain() {
            super.drain();
            if (this.interruptOnDrain) Thread.currentThread().interrupt();
        }
    }
}
