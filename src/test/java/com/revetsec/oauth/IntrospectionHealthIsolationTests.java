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
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

final class IntrospectionHealthIsolationTests {
    private static final Duration SECOND = Duration.ofSeconds(1);
    private static Deadline deadline() { return Deadline.fromNow(Duration.ofSeconds(10)); }
    private static OAuthErrorResponseException status(int status) {
        return OAuthErrorResponseException.fromResponse(status, "invalid_request", Optional.empty());
    }
    private static OAuthTransportException network() {
        return OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, null);
    }
    private static IntrospectionFailureGuard.Attempt allowed(IntrospectionFailureGuard guard) {
        return assertDoesNotThrow(() -> guard.acquire(deadline(), SECOND));
    }
    @Test void expiredPartialWindowCannotExtendAnUnrelatedHealthSignal() {
        AtomicLong time = new AtomicLong(); var guard = new IntrospectionFailureGuard(SECOND, time::get);
        guard.failed(allowed(guard), OAuthErrorResponseException.fromResponse(503, "", Optional.of(Duration.ofMinutes(10))));
        time.set(SECOND.toNanos()); guard.failed(allowed(guard), status(401));
        time.addAndGet(SECOND.toNanos()); guard.healthy(allowed(guard));
    }
    @Test void serverErrorRangeIncludes599WithoutTreatingOtherStatusesAsHealth() {
        var guard = new IntrospectionFailureGuard(SECOND, new AtomicLong()::get);
        for (int n = 0; n < 3; n++) guard.failed(allowed(guard), status(599));
        assertThrows(OAuthTransportException.class, () -> guard.acquire(deadline(), SECOND));
        var neutral = new IntrospectionFailureGuard(SECOND, new AtomicLong()::get);
        for (int n = 0; n < 3; n++) neutral.failed(allowed(neutral), status(499));
        neutral.healthy(allowed(neutral));
    }
    @Test void aPartialServerFailureProbeCannotPublishLateHealth() {
        AtomicLong time = new AtomicLong(); var guard = new IntrospectionFailureGuard(SECOND, time::get);
        var old = allowed(guard); guard.failed(allowed(guard), network()); time.set(SECOND.toNanos());
        var stale = allowed(guard); guard.failed(stale, status(503));
        var second = allowed(guard); guard.healthy(stale); guard.healthy(old); guard.failed(second, status(503));
        guard.failed(allowed(guard), status(503));
        assertThrows(OAuthTransportException.class, () -> guard.acquire(deadline(), SECOND));
    }
    @Test void aPreInterruptedCallerNeverWaitsForTheGuardMutex() throws Exception {
        var guard = new IntrospectionFailureGuard(SECOND, new AtomicLong()::get);
        ReentrantLock lock = mutex(guard);
        FutureTask<OAuthException> result = new FutureTask<>(() -> {
            Thread.currentThread().interrupt();
            OAuthException failure = assertThrows(OAuthException.class, () -> guard.acquire(deadline(), SECOND));
            assertTrue(Thread.currentThread().isInterrupted()); return failure;
        });
        Thread worker = new Thread(result, "pre-interrupted-health-caller"); worker.setDaemon(true);
        lock.lock();
        try {
            worker.start();
            assertEquals(OAuthException.Reason.INTERRUPTED, assertDoesNotThrow(() -> result.get(2, TimeUnit.SECONDS)).getReason());
        } finally { lock.unlock(); worker.interrupt(); worker.join(2000); }
        assertFalse(worker.isAlive());
    }
    @Test void interruptionWhileWaitingForTheMutexCannotAdmitAnAttempt() throws Exception {
        var guard = new IntrospectionFailureGuard(SECOND, new AtomicLong()::get);
        ReentrantLock lock = mutex(guard);
        FutureTask<OAuthException> result = new FutureTask<>(() -> {
            OAuthException failure = assertThrows(OAuthException.class, () -> guard.acquire(deadline(), SECOND));
            assertTrue(Thread.currentThread().isInterrupted()); return failure;
        });
        Thread worker = new Thread(result, "cancelled-health-mutex-waiter"); worker.setDaemon(true);
        lock.lock();
        try {
            worker.start(); Deadline wait = Deadline.fromNow(Duration.ofSeconds(2));
            while (!lock.hasQueuedThread(worker) && worker.isAlive() && !wait.isExpired()) Thread.yield();
            assertTrue(lock.hasQueuedThread(worker)); worker.interrupt();
        } finally { lock.unlock(); }
        try {
            assertEquals(OAuthException.Reason.INTERRUPTED, assertDoesNotThrow(() -> result.get(2, TimeUnit.SECONDS)).getReason());
        } finally { worker.interrupt(); worker.join(2000); }
        assertFalse(worker.isAlive());
        guard.healthy(allowed(guard));
    }
    private static ReentrantLock mutex(IntrospectionFailureGuard guard) throws ReflectiveOperationException {
        var field = IntrospectionFailureGuard.class.getDeclaredField("lock"); field.setAccessible(true);
        return assertInstanceOf(ReentrantLock.class, field.get(guard));
    }
    @Test void thresholdRetainsTheLargestBoundedRetryAfterInItsWindow() {
        AtomicLong time = new AtomicLong(); var guard = new IntrospectionFailureGuard(SECOND, time::get);
        guard.failed(allowed(guard), OAuthErrorResponseException.fromResponse(503, "", Optional.of(Duration.ofDays(1000))));
        guard.failed(allowed(guard), status(500)); guard.failed(allowed(guard), status(503));
        time.set(Duration.ofMinutes(10).toNanos() - 1);
        assertThrows(OAuthTransportException.class, () -> guard.acquire(deadline(), SECOND));
        time.incrementAndGet(); guard.healthy(allowed(guard));
    }
    @Test void tokenSpecificResponsesDoNotOpenTheGuard() {
        var guard = new IntrospectionFailureGuard(SECOND, new AtomicLong()::get);
        for (int code : new int[]{400,403,404,405,413,415,422,431}) {
            guard.failed(allowed(guard), status(code));
            guard.healthy(allowed(guard));
        }
    }
    @Test void tokenSpecificResponsesDoNotErasePartialServerHealthEvidence() {
        var guard = new IntrospectionFailureGuard(SECOND, new AtomicLong()::get);
        guard.failed(allowed(guard), status(503)); guard.failed(allowed(guard), status(503));
        guard.failed(allowed(guard), status(403)); guard.failed(allowed(guard), status(500));
        assertThrows(OAuthTransportException.class, () -> guard.acquire(deadline(), SECOND));
    }
    @Test void anAbandonedProbeCannotPublishLateHealth() {
        AtomicLong time = new AtomicLong(); var guard = new IntrospectionFailureGuard(SECOND, time::get);
        var old = allowed(guard); guard.failed(allowed(guard), network()); time.set(SECOND.toNanos());
        var abandoned = allowed(guard); guard.abandon(abandoned);
        var replacement = allowed(guard); guard.healthy(abandoned); guard.healthy(old); guard.failed(replacement, network());
        assertThrows(OAuthTransportException.class, () -> guard.acquire(deadline(), SECOND));
    }
    @Test void isolatedServerErrorsDoNotOpenTheGuardButThreeInAWindowDo() {
        AtomicLong time = new AtomicLong(); var guard = new IntrospectionFailureGuard(SECOND, time::get);
        for (int n = 0; n < 2; n++) guard.failed(allowed(guard), status(503));
        guard.failed(allowed(guard), status(500));
        assertEquals(OAuthException.Reason.NETWORK_FAILURE,
                assertThrows(OAuthTransportException.class, () -> guard.acquire(deadline(), SECOND)).getReason());
        time.set(SECOND.toNanos()); guard.healthy(allowed(guard));
    }
    @Test void sparseServerErrorsAndAValidResponseResetThePartialWindow() {
        AtomicLong time = new AtomicLong(); var guard = new IntrospectionFailureGuard(SECOND, time::get);
        for (int n = 0; n < 5; n++) {
            guard.failed(allowed(guard), status(500)); time.addAndGet(SECOND.toNanos());
        }
        guard.failed(allowed(guard), status(503));
        guard.healthy(allowed(guard));
        guard.failed(allowed(guard), status(503));
        guard.failed(allowed(guard), status(503));
        guard.healthy(allowed(guard));
    }
    @Test void sharedHealthNeverReplaysAnotherRequestsEndpointRejection() {
        var guard = new IntrospectionFailureGuard(SECOND, new AtomicLong()::get);
        guard.failed(allowed(guard), status(401));
        OAuthException first = assertThrows(OAuthTransportException.class, () -> guard.acquire(deadline(), SECOND));
        first.addSuppressed(new IllegalStateException("caller-owned"));
        OAuthException second = assertThrows(OAuthTransportException.class, () -> guard.acquire(deadline(), SECOND));
        assertNotSame(first, second); assertEquals(0, second.getSuppressed().length);
        assertEquals(OAuthException.Reason.NETWORK_FAILURE, second.getReason());
    }
    @Test void tokenResponseDuringRecoveryPreservesPreviousHealthAndFailureStreak() {
        AtomicLong time = new AtomicLong(); var guard = new IntrospectionFailureGuard(SECOND, time::get);
        guard.failed(allowed(guard), network()); time.set(SECOND.toNanos());
        guard.failed(allowed(guard), status(403));
        var another = allowed(guard); guard.failed(another, network());
        time.addAndGet(SECOND.toNanos());
        assertThrows(OAuthTransportException.class, () -> guard.acquire(deadline(), SECOND));
        time.addAndGet(SECOND.toNanos()); guard.healthy(allowed(guard));
    }
    @Test void interruptedRecoveryDoesNotMarkItsFollowersInterrupted() throws Exception {
        AtomicLong time = new AtomicLong(); var guard = new IntrospectionFailureGuard(SECOND, time::get);
        guard.failed(allowed(guard), network()); time.set(SECOND.toNanos());
        var probe = allowed(guard); ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<OAuthException> one = pool.submit(() -> assertThrows(OAuthException.class, () -> guard.acquire(deadline(), SECOND)));
            Future<OAuthException> two = pool.submit(() -> assertThrows(OAuthException.class, () -> guard.acquire(deadline(), SECOND)));
            assertTrue(guard.awaitWaitersForTests(2, Duration.ofSeconds(5)));
            guard.failed(probe, OAuthTransportException.fromReason(OAuthException.Reason.INTERRUPTED, null));
            OAuthException first = one.get(5, TimeUnit.SECONDS), second = two.get(5, TimeUnit.SECONDS);
            assertEquals(OAuthException.Reason.NETWORK_FAILURE, first.getReason());
            assertEquals(first.getReason(), second.getReason()); assertNotSame(first, second);
            guard.healthy(allowed(guard));
        } finally { pool.shutdownNow(); assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS)); }
    }
}
