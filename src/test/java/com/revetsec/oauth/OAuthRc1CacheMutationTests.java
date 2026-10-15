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

package com.revetsec.oauth;

import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.http.HttpExchange;
import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestTls;
import com.revetsec.json.JsonObject;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/** Cache handoff and observation contracts found by the fresh RC-1 mutation inventory. */
final class OAuthRc1CacheMutationTests {
    private static final Instant NOW = Instant.parse("2026-10-14T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String PATH = "/.well-known/oauth-authorization-server/tenant";

    @Test
    void resourceDiscoveryExactGraceKeepsTheCurrentFlightSharedAndReleasesAllCallers() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            AtomicLong nanos = new AtomicLong(Duration.ofSeconds(100).toNanos());
            ResourceServerMetadataCache<ResourceServerMetadata> cache = resource(server, CLOCK, nanos, value -> value);
            TestHttpsServer.HeldScript held = TestHttpsServer.HeldScript.fromResponse(
                    TestHttpsServer.Response.fromJson(200, document(server)));
            server.script(PATH, held);
            ExecutorService workers = callers(2);
            try {
                Future<ResourceServerMetadata> leader = workers.submit(() -> cache.get(deadline()));
                assertTrue(held.awaitHeldCount(1, Duration.ofSeconds(2)));
                nanos.set(Duration.ofSeconds(104).toNanos());
                Future<ResourceServerMetadata> follower = workers.submit(() -> cache.get(deadline()));
                assertTrue(onCaller(() -> assertDoesNotThrow(() -> cache.awaitWaitersForTests(1, Duration.ofSeconds(2)))));
                held.release();
                ResourceServerMetadata result = result(leader);
                assertSame(result, result(follower));
                assertTrue(onCaller(() -> assertDoesNotThrow(() -> cache.awaitWaitersForTests(0, Duration.ZERO))));
                assertFalse(onCaller(() -> assertDoesNotThrow(() -> cache.awaitWaitersForTests(1, Duration.ZERO))));
                assertSame(result, onCaller(() -> cache.get(deadline())));
                assertEquals(1, server.getHitCount(PATH));
            } finally { held.release(); workers.shutdownNow(); }
        }
    }

    @Test
    void resourceDiscoveryPurgesExactlyExpiredCooldownAttempts() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            TestClock clock = TestClock.fromInstant(NOW);
            AtomicLong nanos = new AtomicLong();
            ResourceServerMetadataCache<ResourceServerMetadata> cache = resource(server, clock, nanos, value -> value);
            server.script(PATH, TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200, document(server))));
            assertFalse(onCaller(() -> assertDoesNotThrow(() -> cache.awaitWaitersForTests(1, Duration.ZERO))));
            onCaller(() -> cache.get(deadline()));
            clock.advance(Duration.ofSeconds(31)); nanos.set(Duration.ofSeconds(15).toNanos());
            onCaller(() -> cache.get(deadline()));
            clock.advance(Duration.ofSeconds(31)); nanos.set(Duration.ofSeconds(30).toNanos());
            onCaller(() -> cache.get(deadline()));
            clock.advance(Duration.ofSeconds(31)); nanos.set(Duration.ofSeconds(31).toNanos());
            assertEquals(OAuthException.Reason.ATTEMPT_LIMIT, onCaller(() -> assertThrows(OAuthException.class,
                    () -> cache.get(deadline()))).getReason());
            assertEquals(3, server.getHitCount(PATH));
        }
    }

    @Test
    void resourceDiscoveryRedactsUnexpectedValidatorFailuresAndReleasesTheFailureLock() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            AtomicLong nanos = new AtomicLong();
            AtomicInteger validations = new AtomicInteger();
            ResourceServerMetadataCache<ResourceServerMetadata> cache = resource(server, CLOCK, nanos, value -> {
                if (validations.incrementAndGet() == 1) throw new IllegalStateException("TEST-ONLY-private-validator");
                return value;
            });
            server.script(PATH, TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200, document(server))));
            OAuthException first = onCaller(() -> assertThrows(OAuthException.class, () -> cache.get(deadline())));
            assertEquals(OAuthException.Reason.NETWORK_FAILURE, first.getReason());
            assertNull(first.getCause());
            assertFalse(first.toString().contains("TEST-ONLY-private-validator"));
            assertSame(first, onCaller(() -> assertThrows(OAuthException.class, () -> cache.get(deadline()))));
            assertEquals(1, server.getHitCount(PATH));
            nanos.set(Duration.ofSeconds(5).toNanos());
            assertSame(first, onCaller(() -> assertThrows(OAuthException.class, () -> cache.get(deadline()))));
            assertEquals(1, server.getHitCount(PATH));
            nanos.set(Duration.ofSeconds(30).toNanos());
            ResourceServerMetadata found = onCaller(() -> cache.get(deadline()));
            assertEquals(server.uri("/introspect"), found.endpoint());
            assertSame(found, onCaller(() -> cache.get(deadline())));
            assertEquals(2, server.getHitCount(PATH));
        }
    }

    @Test
    void resourceDiscoveryCoalescesFailureAndCleansUpEveryFollower() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            ResourceServerMetadataCache<ResourceServerMetadata> cache = resource(server, CLOCK, new AtomicLong(), value -> value);
            TestHttpsServer.HeldScript held = TestHttpsServer.HeldScript.fromResponse(TestHttpsServer.Response.fromStatus(302));
            server.script(PATH, held);
            ExecutorService workers = callers(2);
            try {
                Future<ResourceServerMetadata> leader = workers.submit(() -> cache.get(deadline()));
                assertTrue(held.awaitHeldCount(1, Duration.ofSeconds(2)));
                Future<ResourceServerMetadata> follower = workers.submit(() -> cache.get(deadline()));
                assertTrue(onCaller(() -> assertDoesNotThrow(() -> cache.awaitWaitersForTests(1, Duration.ofSeconds(2)))));
                held.release();
                OAuthException first = failure(leader);
                assertSame(first, failure(follower));
                assertTrue(onCaller(() -> assertDoesNotThrow(() -> cache.awaitWaitersForTests(0, Duration.ZERO))));
                assertFalse(onCaller(() -> assertDoesNotThrow(() -> cache.awaitWaitersForTests(1, Duration.ZERO))));
                assertSame(first, onCaller(() -> assertThrows(OAuthException.class, () -> cache.get(deadline()))));
                assertEquals(1, server.getHitCount(PATH));
            } finally { held.release(); workers.shutdownNow(); }
        }
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> authorizationDiscoveryObserverDurationsFitTheActualExchange() {
        return Stream.of(false, true).map(fails -> DynamicTest.dynamicTest(fails ? "failure" : "success", () -> {
            try (TestHttpsServer server = TestHttpsServer.start()) {
                server.script(PATH, TestHttpsServer.Script.fromResponse(fails ? TestHttpsServer.Response.fromStatus(302)
                        : TestHttpsServer.Response.fromJson(200, document(server))));
                AtomicReference<Duration> elapsed = new AtomicReference<>();
                AtomicReference<OAuthException> failure = new AtomicReference<>();
                AtomicInteger starts = new AtomicInteger();
                AtomicInteger outcomes = new AtomicInteger();
                OAuthObserver observer = new OAuthObserver() {
                    @Override public void willRequestEndpoint(@NonNull OAuthEndpoint role, @NonNull URI uri) {
                        assertEquals(OAuthEndpoint.METADATA, role); assertEquals(server.uri(PATH), uri); starts.incrementAndGet();
                    }
                    @Override public void didRequestEndpoint(@NonNull OAuthEndpoint role, @NonNull URI uri,
                                                            @Nullable Integer status, @NonNull Duration duration) {
                        assertFalse(fails); assertEquals(200, status); elapsed.set(duration); outcomes.incrementAndGet();
                    }
                    @Override public void didFailEndpoint(@NonNull OAuthEndpoint role, @NonNull URI uri,
                                                         @NonNull OAuthException cause, @NonNull Duration duration) {
                        assertTrue(fails); failure.set(cause); elapsed.set(duration); outcomes.incrementAndGet();
                    }
                };
                AuthorizationServerCache cache = authorization(server, CLOCK, observer);
                long started = System.nanoTime();
                if (fails) {
                    OAuthException rejected = onCaller(() -> assertThrows(OAuthException.class, () -> cache.get(deadline())));
                    assertSame(rejected, failure.get());
                } else assertEquals(server.uri("/tenant").toString(), onCaller(() -> cache.get(deadline())).getIssuer());
                long total = System.nanoTime() - started;
                assertEquals(1, starts.get()); assertEquals(1, outcomes.get());
                assertNotNull(elapsed.get()); assertFalse(elapsed.get().isNegative());
                assertTrue(elapsed.get().toNanos() <= total, "an exchange cannot take longer than its enclosing call");
            }
        }));
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> authorizationDiscoverySharesBothSuccessAndFailure() {
        return Stream.of(false, true).map(fails -> DynamicTest.dynamicTest(fails ? "failure" : "success", () -> {
            try (TestHttpsServer server = TestHttpsServer.start()) {
                CountDownLatch followerEntered = new CountDownLatch(1);
                AtomicInteger reads = new AtomicInteger();
                Clock clock = new Clock() {
                    @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
                    @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
                    @Override public @NonNull Instant instant() {
                        if (reads.incrementAndGet() == 2) followerEntered.countDown();
                        return NOW;
                    }
                };
                AuthorizationServerCache cache = authorization(server, clock, OAuthObserver.disabledInstance());
                TestHttpsServer.HeldScript held = TestHttpsServer.HeldScript.fromResponse(fails
                        ? TestHttpsServer.Response.fromStatus(302) : TestHttpsServer.Response.fromJson(200, document(server)));
                server.script(PATH, held);
                ExecutorService workers = callers(2);
                try {
                    Future<AuthorizationServerMetadata> leader = workers.submit(() -> cache.get(deadline()));
                    assertTrue(held.awaitHeldCount(1, Duration.ofSeconds(2)));
                    Future<AuthorizationServerMetadata> follower = workers.submit(() -> cache.get(deadline()));
                    assertTrue(followerEntered.await(2, TimeUnit.SECONDS));
                    held.release();
                    if (fails) {
                        OAuthException first = failure(leader);
                        assertSame(first, failure(follower));
                        assertSame(first, onCaller(() -> assertThrows(OAuthException.class, () -> cache.get(deadline()))));
                    } else {
                        AuthorizationServerMetadata first = result(leader);
                        assertSame(first, result(follower));
                        assertSame(first, onCaller(() -> cache.get(deadline())));
                    }
                    assertEquals(1, server.getHitCount(PATH));
                } finally { held.release(); workers.shutdownNow(); }
            }
        }));
    }

    @Test
    void authorizationDiscoveryUnexpectedClockFailureCannotPoisonTheLockOrExposeItsCause() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            AtomicInteger reads = new AtomicInteger();
            Clock clock = new Clock() {
                @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
                @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
                @Override public @NonNull Instant instant() {
                    if (reads.incrementAndGet() == 2) throw new IllegalStateException("TEST-ONLY-private-clock");
                    return NOW;
                }
            };
            AuthorizationServerCache cache = authorization(server, clock, OAuthObserver.disabledInstance());
            server.script(PATH, TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200, document(server))));
            OAuthException first = onCaller(() -> assertThrows(OAuthException.class, () -> cache.get(deadline())));
            assertEquals(OAuthException.Reason.NETWORK_FAILURE, first.getReason());
            assertNull(first.getCause()); assertFalse(first.toString().contains("TEST-ONLY-private-clock"));
            java.lang.reflect.Field flight = AuthorizationServerCache.class.getDeclaredField("flight");
            flight.setAccessible(true);
            assertNull(flight.get(cache), "A failed discovery leader must release its installed flight.");
            assertSame(first, onCaller(() -> assertThrows(OAuthException.class, () -> cache.get(deadline()))));
            assertEquals(1, server.getHitCount(PATH));
        }
    }

    @Test
    void authorizationMetadataWaiterRestoresInterruptionAndLeavesItsLeaderUsable() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            CountDownLatch followerEntered = new CountDownLatch(1);
            Clock clock = new Clock() {
                @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
                @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
                @Override public @NonNull Instant instant() {
                    if (Thread.currentThread().getName().equals("rc1-interrupted-metadata-waiter")) followerEntered.countDown();
                    return NOW;
                }
            };
            AuthorizationServerCache cache = authorization(server, clock, OAuthObserver.disabledInstance());
            TestHttpsServer.HeldScript held = TestHttpsServer.HeldScript.fromResponse(
                    TestHttpsServer.Response.fromJson(200, document(server)));
            server.script(PATH, held);
            ExecutorService workers = callers(1);
            FutureTask<OAuthException.Reason> follower = new FutureTask<>(() -> {
                OAuthException failure = assertThrows(OAuthException.class, () -> cache.get(deadline()));
                assertTrue(Thread.currentThread().isInterrupted());
                return failure.getReason();
            });
            Thread thread = new Thread(follower, "rc1-interrupted-metadata-waiter"); thread.setDaemon(true);
            try {
                Future<AuthorizationServerMetadata> leader = workers.submit(() -> cache.get(deadline()));
                assertTrue(held.awaitHeldCount(1, Duration.ofSeconds(2)));
                thread.start();
                assertTrue(followerEntered.await(2, TimeUnit.SECONDS));
                thread.interrupt();
                assertEquals(OAuthException.Reason.INTERRUPTED, result(follower));
                held.release();
                AuthorizationServerMetadata first = result(leader);
                assertSame(first, onCaller(() -> cache.get(deadline())));
                assertEquals(1, server.getHitCount(PATH));
            } finally { held.release(); follower.cancel(true); workers.shutdownNow(); }
        }
    }

    private static @NonNull ResourceServerMetadataCache<@NonNull ResourceServerMetadata> resource(
            @NonNull TestHttpsServer server, @NonNull Clock clock, @NonNull AtomicLong nanos,
            @NonNull Function<@NonNull ResourceServerMetadata, @NonNull ResourceServerMetadata> validate) {
        return new ResourceServerMetadataCache<>(server.uri("/tenant"), ResourceServerMetadata.Role.INTROSPECTION,
                HttpExchange.fromHttpClient(TestTls.httpClient(), OutboundUriPolicy.defaultInstance(), true),
                OutboundUriPolicy.defaultInstance(), true, Duration.ofSeconds(2), clock,
                OAuthObserver.disabledInstance(), Duration.ofSeconds(30), Duration.ofSeconds(30),
                Duration.ofSeconds(30), Duration.ofSeconds(30), validate, nanos::get);
    }

    private static @NonNull AuthorizationServerCache authorization(@NonNull TestHttpsServer server,
            @NonNull Clock clock, @NonNull OAuthObserver observer) {
        return new AuthorizationServerCache(server.uri("/tenant"),
                HttpExchange.fromHttpClient(TestTls.httpClient(), OutboundUriPolicy.defaultInstance(), true),
                OutboundUriPolicy.defaultInstance(), true, Duration.ofSeconds(2), clock, observer,
                Duration.ofSeconds(30), Duration.ofSeconds(30), Duration.ofSeconds(30), Duration.ofSeconds(30));
    }

    private static @NonNull String document(@NonNull TestHttpsServer server) {
        return JsonObject.builder().put("issuer", server.uri("/tenant").toString())
                .put("authorization_endpoint", server.uri("/authorize").toString())
                .put("token_endpoint", server.uri("/token").toString())
                .put("introspection_endpoint", server.uri("/introspect").toString()).build().toJson();
    }

    private static @NonNull Deadline deadline() { return Deadline.fromNow(Duration.ofSeconds(5)); }

    private static @NonNull ExecutorService callers(int count) {
        return Executors.newFixedThreadPool(count, task -> { Thread thread = new Thread(task, "rc1-oauth-cache-caller");
            thread.setDaemon(true); return thread; });
    }

    private static <T> @NonNull T result(@NonNull Future<@NonNull T> future) {
        return assertDoesNotThrow(() -> future.get(2, TimeUnit.SECONDS));
    }

    private static @NonNull OAuthException failure(@NonNull Future<?> future) {
        ExecutionException failure = assertThrows(ExecutionException.class, () -> future.get(2, TimeUnit.SECONDS));
        return assertInstanceOf(OAuthException.class, failure.getCause());
    }

    private static <T> @NonNull T onCaller(@NonNull Supplier<@NonNull T> operation) {
        FutureTask<T> future = new FutureTask<>(operation::get);
        Thread thread = new Thread(future, "rc1-oauth-isolated-caller"); thread.setDaemon(true); thread.start();
        try { return result(future); } finally { future.cancel(true); }
    }
}
