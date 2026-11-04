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
package com.revetsec.testing;

import com.revetsec.internal.http.Deadline;
import com.revetsec.oauth.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.time.*;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** The same caller-local cancellation and private-failure contract for all discovery caches. */
public abstract class DiscoveryCacheCancellationChecks {
    private static final Instant NOW = Instant.parse("2026-10-31T12:00:00Z");
    @FunctionalInterface
    protected interface Cache { @NonNull Object get(@NonNull Deadline deadline); }
    protected abstract @NonNull Cache create(@NonNull TestHttpsServer server, @NonNull Clock clock);
    protected abstract @NonNull String metadataPath();
    protected abstract @NonNull String cacheClassName();

    protected static @NonNull String document(@NonNull TestHttpsServer server) {
        String issuer = server.getBaseUri().toString();
        return "{\"issuer\":\"" + issuer + "\",\"authorization_endpoint\":\"" + issuer
                + "/authorize\",\"token_endpoint\":\"" + issuer + "/token\",\"jwks_uri\":\"" + issuer
                + "/jwks\",\"introspection_endpoint\":\"" + issuer + "/inspect\","
                + "\"response_types_supported\":[\"code\"],\"subject_types_supported\":[\"public\"],"
                + "\"id_token_signing_alg_values_supported\":[\"RS256\"]}";
    }

    @Test protected void preCancelledCallersCannotConsumeAttempts() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            scriptSuccess(server);
            Cache cache = create(server, Clock.fixed(NOW, ZoneOffset.UTC));
            for (int n = 0; n < 2; n++) {
                Thread.currentThread().interrupt();
                try {
                    assertEquals(OAuthException.Reason.INTERRUPTED,
                            assertThrows(OAuthException.class, () -> cache.get(deadline())).getReason());
                    assertTrue(Thread.currentThread().isInterrupted());
                } finally { Thread.interrupted(); }
            }
            assertEquals(0, server.getRequests().size());
            assertNotNull(assertDoesNotThrow(() -> cache.get(deadline())));
            assertEquals(1, server.getHitCount(metadataPath()));
        }
    }

    @Test protected void cancellationDuringTheAdmissionClockReadCannotConsumeAttempts() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            scriptSuccess(server);
            AtomicInteger reads = new AtomicInteger();
            Clock clock = new Clock() {
                @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
                @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
                @Override public @NonNull Instant instant() {
                    if (reads.incrementAndGet() <= 2) Thread.currentThread().interrupt();
                    return NOW;
                }
            };
            Cache cache = create(server, clock);
            for (int n = 0; n < 2; n++) {
                try {
                    assertEquals(OAuthException.Reason.INTERRUPTED,
                            assertThrows(OAuthException.class, () -> cache.get(deadline())).getReason());
                    assertTrue(Thread.currentThread().isInterrupted());
                } finally { Thread.interrupted(); }
            }
            assertEquals(0, server.getRequests().size());
            assertNotNull(assertDoesNotThrow(() -> cache.get(deadline())));
            assertEquals(1, server.getHitCount(metadataPath()));
        }
    }
    @Test protected void preExpiredCallersCannotConsumeAttemptsOrInstallBackoff() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            scriptSuccess(server);
            Cache cache = create(server, Clock.fixed(NOW, ZoneOffset.UTC));
            for (int n = 0; n < 2; n++)
                assertEquals(OAuthException.Reason.NETWORK_FAILURE,
                        assertThrows(OAuthException.class, () -> cache.get(Deadline.fromNow(Duration.ZERO))).getReason());
            assertEquals(0, server.getRequests().size());
            assertNotNull(assertDoesNotThrow(() -> cache.get(deadline())));
            assertEquals(1, server.getHitCount(metadataPath()));
        }
    }

    @Test protected void cancelledLeaderDoesNotPoisonFollowersOrBackoff() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            Cache cache = create(server, Clock.fixed(NOW, ZoneOffset.UTC));
            TestHttpsServer.HeldScript held = hold(server, 200);
            Capture leader = new Capture(() -> cache.get(deadline()));
            Capture first = new Capture(() -> cache.get(deadline()));
            Capture second = new Capture(() -> cache.get(deadline()));
            try {
                leader.start(); assertTrue(held.awaitHeldCount(1, Duration.ofSeconds(5)));
                first.start(); awaitFollower(first); second.start(); awaitFollower(second);
                leader.worker.interrupt(); leader.join(); first.join(); second.join();
                OAuthException cancelled = leader.failure();
                assertEquals(OAuthException.Reason.INTERRUPTED, cancelled.getReason());
                assertTrue(leader.interrupted.get());
                OAuthException one = first.failure(), two = second.failure();
                assertEquals(OAuthException.Reason.NETWORK_FAILURE, one.getReason());
                assertEquals(one.getReason(), two.getReason());
                assertFalse(first.interrupted.get()); assertFalse(second.interrupted.get());
                assertNotSame(cancelled, one); assertNotSame(one, two);
                scriptSuccess(server);
                assertNotNull(assertDoesNotThrow(() -> cache.get(deadline())));
                assertEquals(2, server.getHitCount(metadataPath()));
            } finally { held.release(); leader.stop(); first.stop(); second.stop(); }
        }
    }

    @Test protected void cancelledWaiterDoesNotCancelTheLeaderOrOtherWaiters() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            Cache cache = create(server, Clock.fixed(NOW, ZoneOffset.UTC));
            TestHttpsServer.HeldScript held = hold(server, 200);
            Capture leader = new Capture(() -> cache.get(deadline()));
            Capture cancelled = new Capture(() -> cache.get(deadline()));
            Capture other = new Capture(() -> cache.get(deadline()));
            try {
                leader.start(); assertTrue(held.awaitHeldCount(1, Duration.ofSeconds(5)));
                cancelled.start(); awaitFollower(cancelled); other.start(); awaitFollower(other);
                cancelled.worker.interrupt(); cancelled.join();
                assertEquals(OAuthException.Reason.INTERRUPTED, cancelled.failure().getReason());
                assertTrue(cancelled.interrupted.get());
                held.release(); leader.join(); other.join();
                assertSame(leader.value(), other.value());
                assertSame(leader.value(), cache.get(deadline()));
                assertEquals(1, server.getHitCount(metadataPath()));
            } finally { held.release(); leader.stop(); cancelled.stop(); other.stop(); }
        }
    }

    @Test protected void sharedFailureHasIndependentMutableDiagnostics() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            server.script(metadataPath(), TestHttpsServer.Script.fromResponse(
                    TestHttpsServer.Response.fromRetryAfter(503, "120")));
            Cache cache = create(server, Clock.fixed(NOW, ZoneOffset.UTC));
            OAuthErrorResponseException leader = assertThrows(OAuthErrorResponseException.class, () -> cache.get(deadline()));
            leader.addSuppressed(new IllegalStateException("caller-owned-diagnostic"));
            leader.setStackTrace(new StackTraceElement[0]);
            OAuthErrorResponseException first = assertThrows(OAuthErrorResponseException.class, () -> cache.get(deadline()));
            first.addSuppressed(new IllegalStateException("another-caller"));
            OAuthErrorResponseException second = assertThrows(OAuthErrorResponseException.class, () -> cache.get(deadline()));
            assertNotSame(leader, first); assertNotSame(first, second);
            assertEquals(503, second.getStatus());
            assertEquals(Duration.ofSeconds(120), second.getRetryAfter().orElseThrow());
            assertTrue(second.isTransient()); assertTrue(second.getErrorCode().isEmpty());
            assertEquals(0, second.getSuppressed().length); assertNull(second.getCause());
            assertTrue(second.getStackTrace().length > 0);
            assertEquals(1, server.getHitCount(metadataPath()));
        }
    }

    @Test protected void sharedFlightFailureCreatesFreshExceptionsForEveryFollower() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            Cache cache = create(server, Clock.fixed(NOW, ZoneOffset.UTC));
            TestHttpsServer.HeldScript held = hold(server, 503);
            Capture leader = new Capture(() -> cache.get(deadline()));
            Capture first = new Capture(() -> cache.get(deadline()));
            Capture second = new Capture(() -> cache.get(deadline()));
            try {
                leader.start(); assertTrue(held.awaitHeldCount(1, Duration.ofSeconds(5)));
                first.start(); awaitFollower(first); second.start(); awaitFollower(second);
                held.release(); leader.join(); first.join(); second.join();
                OAuthException own = leader.failure(), one = first.failure(), two = second.failure();
                assertNotSame(own, one); assertNotSame(one, two);
                assertEquals(OAuthException.Reason.ENDPOINT_ERROR, one.getReason());
                assertEquals(one.getReason(), two.getReason());
                one.addSuppressed(new IllegalStateException("private-follower-diagnostic"));
                assertEquals(0, two.getSuppressed().length);
                assertNotSame(two, assertThrows(OAuthException.class, () -> cache.get(deadline())));
                assertEquals(1, server.getHitCount(metadataPath()));
            } finally { held.release(); leader.stop(); first.stop(); second.stop(); }
        }
    }

    @Test protected void cancelledLateSuccessCannotPopulateTheSnapshot() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            scriptSuccess(server);
            AtomicInteger reads = new AtomicInteger();
            Clock cancelling = new Clock() {
                @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
                @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
                @Override public @NonNull Instant instant() {
                    if (reads.incrementAndGet() == 2) Thread.currentThread().interrupt();
                    return NOW;
                }
            };
            Cache cache = create(server, cancelling);
            try {
                assertEquals(OAuthException.Reason.INTERRUPTED,
                        assertThrows(OAuthException.class, () -> cache.get(deadline())).getReason());
                assertTrue(Thread.currentThread().isInterrupted());
            } finally { Thread.interrupted(); }
            assertNotNull(assertDoesNotThrow(() -> cache.get(deadline())));
            assertEquals(2, server.getHitCount(metadataPath()));
        }
    }

    private TestHttpsServer.@NonNull HeldScript hold(@NonNull TestHttpsServer server, int status) {
        TestHttpsServer.HeldScript held = TestHttpsServer.HeldScript.fromResponse(
                status == 200 ? TestHttpsServer.Response.fromJson(200, document(server))
                        : TestHttpsServer.Response.fromRetryAfter(status, "120"));
        server.script(metadataPath(), held); return held;
    }
    private void scriptSuccess(@NonNull TestHttpsServer server) {
        server.script(metadataPath(), TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200, document(server))));
    }
    private static @NonNull Deadline deadline() { return Deadline.fromNow(Duration.ofSeconds(10)); }
    private void awaitFollower(@NonNull Capture caller) {
        long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (caller.worker.isAlive() && System.nanoTime() < end) {
            for (StackTraceElement frame : caller.worker.getStackTrace())
                if (frame.getClassName().equals(cacheClassName()) && frame.getMethodName().equals("await")) return;
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1));
        }
        fail("The follower must join the existing discovery flight");
    }
    private static final class Capture {
        private final @NonNull AtomicReference<@Nullable Object> result = new AtomicReference<>();
        private final @NonNull AtomicReference<@Nullable Throwable> failed = new AtomicReference<>();
        private final @NonNull AtomicBoolean interrupted = new AtomicBoolean();
        private final @NonNull Thread worker;
        Capture(@NonNull Callable<@NonNull Object> call) {
            this.worker = new Thread(() -> {
                try { this.result.set(call.call()); }
                catch (Throwable failure) { this.failed.set(failure); }
                finally { this.interrupted.set(Thread.currentThread().isInterrupted()); }
            }, "discovery-cache-cancellation-check");
            this.worker.setDaemon(true);
        }
        void start() { this.worker.start(); }
        void join() throws InterruptedException { this.worker.join(5_000); assertFalse(this.worker.isAlive()); }
        void stop() throws InterruptedException { this.worker.interrupt(); this.worker.join(5_000); assertFalse(this.worker.isAlive()); }
        @NonNull Object value() { assertNull(this.failed.get()); return requireNonNull(this.result.get()); }
        @NonNull OAuthException failure() { return assertInstanceOf(OAuthException.class, this.failed.get()); }
    }
}
