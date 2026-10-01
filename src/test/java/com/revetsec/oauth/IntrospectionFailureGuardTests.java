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

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import com.revetsec.testing.*;
import com.revetsec.jose.*;
import com.revetsec.json.*;
import com.revetsec.internal.http.*;
import com.revetsec.internal.jose.*;
import com.revetsec.OutboundUriPolicy;
import org.jspecify.annotations.Nullable;
import java.net.*;
import java.net.http.*;
import java.time.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;
import java.util.stream.*;
import static com.revetsec.oauth.Phase2Fixtures.*;

/** Endpoint health generation, bounded monotonic backoff and independent deadline-bound recovery waiters. */
final class IntrospectionFailureGuardTests {
    private static final Duration REQUEST=Duration.ofSeconds(1);
    private static Deadline deadline(){return Deadline.fromNow(Duration.ofSeconds(10));}
    private static OAuthException failure(){return OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE,null);}
    @Test void oldSuccessCannotClearNewFailureAndHealthyCallsAreNotThrottled() {
        AtomicLong time=new AtomicLong();IntrospectionFailureGuard guard=new IntrospectionFailureGuard(Duration.ofSeconds(1),time::get);
        var first=guard.acquire(deadline(),REQUEST);var second=guard.acquire(deadline(),REQUEST);var third=guard.acquire(deadline(),REQUEST);
        guard.healthy(first);OAuthException failed=failure();guard.failed(second,failed);guard.healthy(third);assertSame(failed,assertThrows(OAuthException.class,()->guard.acquire(deadline(),REQUEST)));
        time.set(Duration.ofSeconds(1).toNanos());var recovery=guard.acquire(deadline(),REQUEST);guard.healthy(recovery);guard.failed(third,failure());
        for(int i=0;i<10;i++)guard.healthy(guard.acquire(deadline(),REQUEST));
    }
    @Test void oneRecoveryProbeWakesWaitersWithoutSharingACredentialResult() throws Exception {
        AtomicLong time=new AtomicLong();IntrospectionFailureGuard guard=new IntrospectionFailureGuard(Duration.ofSeconds(1),time::get);guard.failed(guard.acquire(deadline(),REQUEST),failure());time.set(Duration.ofSeconds(1).toNanos());var probe=guard.acquire(deadline(),REQUEST);
        ExecutorService pool=Executors.newFixedThreadPool(2);
        try {
            Future<IntrospectionFailureGuard.Attempt> waiter=pool.submit(()->guard.acquire(deadline(),REQUEST));assertTrue(guard.awaitWaitersForTests(1,Duration.ofSeconds(5)));
            assertThrows(OAuthTransportException.class,()->guard.acquire(Deadline.fromNow(Duration.ofMillis(10)),REQUEST));guard.healthy(probe);
            var own=waiter.get(5,TimeUnit.SECONDS);assertNotSame(probe,own);guard.healthy(own);
        } finally{pool.shutdownNow();assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS));}
    }
    @Test void failedRecoveryWakesWaitersWithInfrastructureFailure() throws Exception {
        AtomicLong time=new AtomicLong();IntrospectionFailureGuard guard=new IntrospectionFailureGuard(Duration.ofSeconds(1),time::get);guard.failed(guard.acquire(deadline(),REQUEST),failure());time.set(Duration.ofSeconds(1).toNanos());var probe=guard.acquire(deadline(),REQUEST);
        ExecutorService pool=Executors.newSingleThreadExecutor();try {
            Future<IntrospectionFailureGuard.Attempt> waiter=pool.submit(()->guard.acquire(deadline(),REQUEST));assertTrue(guard.awaitWaitersForTests(1,Duration.ofSeconds(5)));OAuthException failed=failure();guard.failed(probe,failed);
            assertSame(failed,assertThrows(ExecutionException.class,()->waiter.get(5,TimeUnit.SECONDS)).getCause());
        }finally{pool.shutdownNow();assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS));}
    }
    @Test void overdueOrAbandonedRecoveryCannotPublishOldHealth() {
        AtomicLong time=new AtomicLong();IntrospectionFailureGuard guard=new IntrospectionFailureGuard(Duration.ofSeconds(1),time::get);guard.failed(guard.acquire(deadline(),REQUEST),failure());time.set(Duration.ofSeconds(1).toNanos());var old=guard.acquire(deadline(),REQUEST);time.addAndGet(Duration.ofSeconds(3).toNanos());var replacement=guard.acquire(deadline(),REQUEST);guard.healthy(old);guard.failed(old,failure());
        OAuthException newer=failure();guard.failed(replacement,newer);assertSame(newer,assertThrows(OAuthException.class,()->guard.acquire(deadline(),REQUEST)));time.addAndGet(Duration.ofSeconds(2).toNanos());var abandoned=guard.acquire(deadline(),REQUEST);guard.abandon(abandoned);guard.healthy(guard.acquire(deadline(),REQUEST));
    }
    @Test void exponentialBackoffCappedRetryAfterAndInterruption() {
        AtomicLong time=new AtomicLong();IntrospectionFailureGuard guard=new IntrospectionFailureGuard(Duration.ofSeconds(1),time::get);
        for(int seconds:new int[]{1,2,4,8,10,10}){OAuthException failed=failure();guard.failed(guard.acquire(deadline(),REQUEST),failed);time.addAndGet(Duration.ofSeconds(seconds).toNanos()-1);assertSame(failed,assertThrows(OAuthException.class,()->guard.acquire(deadline(),REQUEST)));time.incrementAndGet();}
        guard.healthy(guard.acquire(deadline(),REQUEST));var attempt=guard.acquire(deadline(),REQUEST);OAuthException longDelay=OAuthErrorResponseException.fromResponse(429,"",Optional.of(Duration.ofDays(1000)));guard.failed(attempt,longDelay);time.addAndGet(Duration.ofMinutes(10).toNanos()-1);assertSame(longDelay,assertThrows(OAuthException.class,()->guard.acquire(deadline(),REQUEST)));time.incrementAndGet();guard.healthy(guard.acquire(deadline(),REQUEST));
        guard.failed(guard.acquire(deadline(),REQUEST),OAuthTransportException.fromReason(OAuthException.Reason.INTERRUPTED,null));guard.healthy(guard.acquire(deadline(),REQUEST));
        assertThrows(OAuthTransportException.class,()->guard.acquire(Deadline.fromNow(Duration.ZERO),REQUEST));Thread.currentThread().interrupt();try{assertThrows(OAuthTransportException.class,()->guard.acquire(deadline(),REQUEST));assertTrue(Thread.currentThread().isInterrupted());}finally{Thread.interrupted();}
    }
}
