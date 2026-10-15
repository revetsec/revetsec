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

import com.revetsec.internal.http.Deadline;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import static org.junit.jupiter.api.Assertions.*;

/** Endpoint-wide health leases never share a credential verdict or busy-poll a provider probe. */
final class OAuthRc1GuardMutationTests {
    @Test
    void exactProbeGraceCoalescesHealthAndEveryCallerRetainsItsOwnAttempt() throws Exception {
        AtomicLong nanos = new AtomicLong(100);
        AtomicInteger reads = new AtomicInteger();
        AtomicBoolean released = new AtomicBoolean();
        IntrospectionFailureGuard guard = new IntrospectionFailureGuard(Duration.ofNanos(30), () -> {
            int read = reads.incrementAndGet();
            if (read > 4 && !released.get()) throw new AssertionError("A waiting caller must park rather than poll the lease.");
            return nanos.get();
        });
        assertFalse(onCaller(() -> assertDoesNotThrow(() -> guard.awaitWaitersForTests(1, Duration.ZERO))));
        IntrospectionFailureGuard.Attempt first = onCaller(() -> guard.acquire(deadline(), Duration.ofSeconds(1)));
        OAuthException failure = OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, null);
        onCaller(() -> { guard.failed(first, failure); return true; });
        nanos.set(130);
        IntrospectionFailureGuard.Attempt probe = onCaller(() -> guard.acquire(deadline(), Duration.ofSeconds(1)));
        nanos.set(130 + Duration.ofSeconds(2).toNanos());
        FutureTask<IntrospectionFailureGuard.Attempt> follower = task(() -> guard.acquire(deadline(), Duration.ofSeconds(1)));
        try {
            assertTrue(onCaller(() -> assertDoesNotThrow(() -> guard.awaitWaitersForTests(1, Duration.ofSeconds(2)))));
            new CountDownLatch(1).await(20, TimeUnit.MILLISECONDS);
            assertFalse(follower.isDone());
            assertEquals(4, reads.get());
            released.set(true);
            onCaller(() -> { guard.healthy(probe); return true; });
            IntrospectionFailureGuard.Attempt independent = result(follower);
            assertNotSame(probe, independent);
            assertTrue(onCaller(() -> assertDoesNotThrow(() -> guard.awaitWaitersForTests(0, Duration.ZERO))));
            assertFalse(onCaller(() -> assertDoesNotThrow(() -> guard.awaitWaitersForTests(1, Duration.ZERO))));
            onCaller(() -> { guard.healthy(independent); return true; });
            assertNotSame(independent, onCaller(() -> guard.acquire(deadline(), Duration.ofSeconds(1))));
        } finally { released.set(true); follower.cancel(true); }
    }

    @Test
    void failedProbeWakesFollowersWithTheSameFailureAndReleasesItsLock() throws Exception {
        AtomicLong nanos = new AtomicLong();
        IntrospectionFailureGuard guard = new IntrospectionFailureGuard(Duration.ofNanos(30), nanos::get);
        IntrospectionFailureGuard.Attempt first = onCaller(() -> guard.acquire(deadline(), Duration.ofSeconds(1)));
        OAuthException initial = OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, null);
        onCaller(() -> { guard.failed(first, initial); return true; });
        nanos.set(29);
        assertSame(initial, onCaller(() -> assertThrows(OAuthException.class, () -> guard.acquire(deadline(), Duration.ofSeconds(1)))));
        nanos.set(30);
        IntrospectionFailureGuard.Attempt probe = onCaller(() -> guard.acquire(deadline(), Duration.ofSeconds(1)));
        FutureTask<IntrospectionFailureGuard.Attempt> follower = task(() -> guard.acquire(deadline(), Duration.ofSeconds(1)));
        try {
            assertTrue(onCaller(() -> assertDoesNotThrow(() -> guard.awaitWaitersForTests(1, Duration.ofSeconds(2)))));
            OAuthException replacement = OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, null);
            onCaller(() -> { guard.failed(probe, replacement); return true; });
            assertSame(replacement, failure(follower));
            assertTrue(onCaller(() -> assertDoesNotThrow(() -> guard.awaitWaitersForTests(0, Duration.ZERO))));
            assertFalse(onCaller(() -> assertDoesNotThrow(() -> guard.awaitWaitersForTests(1, Duration.ZERO))));
            assertSame(replacement, onCaller(() -> assertThrows(OAuthException.class,
                    () -> guard.acquire(deadline(), Duration.ofSeconds(1)))));
        } finally { follower.cancel(true); }
    }

    @Test
    void abandonedProbeWakesItsFollowerAndReleasesAllOwnership() throws Exception {
        AtomicLong nanos = new AtomicLong();
        IntrospectionFailureGuard guard = new IntrospectionFailureGuard(Duration.ofNanos(30), nanos::get);
        IntrospectionFailureGuard.Attempt first = onCaller(() -> guard.acquire(deadline(), Duration.ofSeconds(1)));
        onCaller(() -> { guard.failed(first, OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, null)); return true; });
        nanos.set(30);
        IntrospectionFailureGuard.Attempt probe = onCaller(() -> guard.acquire(deadline(), Duration.ofSeconds(1)));
        FutureTask<IntrospectionFailureGuard.Attempt> follower = task(() -> guard.acquire(deadline(), Duration.ofSeconds(1)));
        try {
            assertTrue(onCaller(() -> assertDoesNotThrow(() -> guard.awaitWaitersForTests(1, Duration.ofSeconds(2)))));
            onCaller(() -> { guard.abandon(probe); return true; });
            assertEquals(OAuthException.Reason.NETWORK_FAILURE, failure(follower).getReason());
            assertTrue(onCaller(() -> assertDoesNotThrow(() -> guard.awaitWaitersForTests(0, Duration.ZERO))));
            assertFalse(onCaller(() -> assertDoesNotThrow(() -> guard.awaitWaitersForTests(1, Duration.ZERO))));
            IntrospectionFailureGuard.Attempt replacement = onCaller(() -> guard.acquire(deadline(), Duration.ofSeconds(1)));
            assertNotSame(probe, replacement);
            onCaller(() -> { guard.abandon(replacement); return true; });
        } finally { follower.cancel(true); }
    }

    @Test
    void aWaitingCallerPreservesInterruptionWithoutAbandoningTheProviderProbe() throws Exception {
        AtomicLong nanos = new AtomicLong();
        IntrospectionFailureGuard guard = new IntrospectionFailureGuard(Duration.ofNanos(30), nanos::get);
        IntrospectionFailureGuard.Attempt first = onCaller(() -> guard.acquire(deadline(), Duration.ofSeconds(1)));
        onCaller(() -> { guard.failed(first, OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, null)); return true; });
        nanos.set(30);
        IntrospectionFailureGuard.Attempt probe = onCaller(() -> guard.acquire(deadline(), Duration.ofSeconds(1)));
        FutureTask<OAuthException.Reason> follower = new FutureTask<>(() -> {
            OAuthException failure = assertThrows(OAuthException.class, () -> guard.acquire(deadline(), Duration.ofSeconds(1)));
            assertTrue(Thread.currentThread().isInterrupted());
            return failure.getReason();
        });
        Thread thread = new Thread(follower, "rc1-interrupted-health-waiter"); thread.setDaemon(true); thread.start();
        try {
            assertTrue(onCaller(() -> assertDoesNotThrow(() -> guard.awaitWaitersForTests(1, Duration.ofSeconds(2)))));
            thread.interrupt();
            assertEquals(OAuthException.Reason.INTERRUPTED, result(follower));
            assertTrue(onCaller(() -> assertDoesNotThrow(() -> guard.awaitWaitersForTests(0, Duration.ZERO))));
            assertFalse(onCaller(() -> assertDoesNotThrow(() -> guard.awaitWaitersForTests(1, Duration.ZERO))));
            onCaller(() -> { guard.healthy(probe); return true; });
            assertNotSame(probe, onCaller(() -> guard.acquire(deadline(), Duration.ofSeconds(1))));
        } finally { follower.cancel(true); }
    }

    @Test
    void anOverdueProbeNeverReusesAnEarlierLeaseGeneration() {
        AtomicLong nanos = new AtomicLong();
        IntrospectionFailureGuard guard = new IntrospectionFailureGuard(Duration.ofNanos(30), nanos::get);
        IntrospectionFailureGuard.Attempt first = onCaller(() -> guard.acquire(deadline(), Duration.ofSeconds(1)));
        onCaller(() -> { guard.failed(first, OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, null)); return true; });
        nanos.set(30);
        IntrospectionFailureGuard.Attempt overdue = onCaller(() -> guard.acquire(deadline(), Duration.ofSeconds(1)));
        nanos.set(31 + Duration.ofSeconds(2).toNanos());
        IntrospectionFailureGuard.Attempt replacement = onCaller(() -> guard.acquire(deadline(), Duration.ofSeconds(1)));
        assertNotSame(overdue, replacement);
        onCaller(() -> { guard.failed(first, OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, null)); return true; });
        onCaller(() -> { guard.healthy(replacement); return true; });
        assertNotSame(replacement, onCaller(() -> guard.acquire(deadline(), Duration.ofSeconds(1))));
    }

    private static @NonNull Deadline deadline() { return Deadline.fromNow(Duration.ofSeconds(5)); }
    private static <T> @NonNull FutureTask<@NonNull T> task(@NonNull Supplier<@NonNull T> operation) {
        FutureTask<T> future = new FutureTask<>(operation::get);
        Thread thread = new Thread(future, "rc1-isolated-health-caller"); thread.setDaemon(true); thread.start();
        return future;
    }
    private static <T> @NonNull T result(@NonNull FutureTask<@NonNull T> future) {
        return assertDoesNotThrow(() -> future.get(2, TimeUnit.SECONDS));
    }
    private static @NonNull OAuthException failure(@NonNull FutureTask<?> future) {
        return assertInstanceOf(OAuthException.class, assertThrows(ExecutionException.class,
                () -> future.get(2, TimeUnit.SECONDS)).getCause());
    }
    private static <T> @NonNull T onCaller(@NonNull Supplier<@NonNull T> operation) {
        FutureTask<T> future = task(operation);
        try { return result(future); } finally { future.cancel(true); }
    }
}
