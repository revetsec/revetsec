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

import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestTls;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.function.IntUnaryOperator;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** Shared renewal never resurrects a token invalidated while its waiter was waking. */
final class OAuthRc1TokenSourceMutationTests {
    private static final Instant NOW=Instant.parse("2026-10-14T12:00:00Z");

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> wakingWaitersRecheckInvalidationAndReplacement() {
        return Stream.of(0,1,2).map(variant -> DynamicTest.dynamicTest(variant==1?"replacement already published":variant==2?"expired before publication check":"invalidated before publication check",()->{
            try(TestHttpsServer server=TestHttpsServer.start()) {
                AtomicReference<ClientCredentialsTokenSource> sourceRef=new AtomicReference<>();
                AtomicReference<AccessToken> sharedRef=new AtomicReference<>();
                AtomicReference<Instant> clockNow=new AtomicReference<>(NOW);
                AtomicInteger followerReads=new AtomicInteger();
                AtomicBoolean interleaved=new AtomicBoolean();
                CountDownLatch followerEntered=new CountDownLatch(1);
                CountDownLatch releaseClock=new CountDownLatch(1);
                Clock clock=new Clock() {
                    @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
                    @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}
                    @Override public @NonNull Instant instant(){
                        if(Thread.currentThread().getName().equals("rc1-token-follower")) {
                            int read=followerReads.incrementAndGet();
                            if(read==1)followerEntered.countDown();
                            if(read==2&&interleaved.compareAndSet(false,true)) {
                                await(releaseClock);
                                ClientCredentialsTokenSource source=java.util.Objects.requireNonNull(sourceRef.get());
                                if(variant==2)clockNow.set(NOW.plusSeconds(61));
                                else source.invalidate(java.util.Objects.requireNonNull(sharedRef.get()));
                                if(variant==1)assertEquals("TEST-ONLY-second",assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken().getValue());
                            }
                        }
                        return java.util.Objects.requireNonNull(clockNow.get());
                    }
                };
                ClientCredentialsTokenSource source=ClientCredentialsTokenSource.withClient(client(server,clock)).build();
                sourceRef.set(source);
                TestHttpsServer.HeldScript held=TestHttpsServer.HeldScript.fromResponse(token("TEST-ONLY-first"));
                server.script("/token",held);
                FutureTask<AccessToken> leader=task("rc1-token-leader",() -> assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken());
                FutureTask<AccessToken> follower=null;
                try {
                    assertTrue(held.awaitHeldCount(1,Duration.ofSeconds(2)));
                    follower=task("rc1-token-follower",() -> assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken());
                    assertTrue(followerEntered.await(2,TimeUnit.SECONDS));
                    server.script("/token",TestHttpsServer.Script.fromResponse(token("TEST-ONLY-second")));
                    held.release();
                    AccessToken first=result(leader); sharedRef.set(first); releaseClock.countDown();
                    AccessToken second=result(follower);
                    assertEquals("TEST-ONLY-first",first.getValue());
                    assertEquals("TEST-ONLY-second",second.getValue());
                    assertNotSame(first,second);
                    onCaller(()->{source.invalidate(first);return true;});
                    assertSame(second,onCaller(() -> assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken()));
                    assertEquals(2,server.getHitCount("/token"));
                } finally {releaseClock.countDown();held.release();leader.cancel(true);if(follower!=null)follower.cancel(true);}
            }
        }));
    }

    @Test
    void earlyRenewalFailureServesOnlyTheStillValidCachedToken() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            TestClock clock=TestClock.fromInstant(NOW);
            ClientCredentialsTokenSource source=ClientCredentialsTokenSource.withClient(client(server,clock))
                    .renewBefore(Duration.ofSeconds(10)).build();
            server.script("/token",TestHttpsServer.Script.fromResponse(token("TEST-ONLY-first")));
            AccessToken first=onCaller(() -> assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken());
            assertSame(first,onCaller(() -> assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken()));
            clock.advance(Duration.ofSeconds(51));
            server.script("/token",TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromStatus(503)));
            assertSame(first,onCaller(() -> assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken()));
            assertSame(first,onCaller(() -> assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken()));
            clock.advance(Duration.ofSeconds(9));
            OAuthException failure=onCaller(()->assertThrows(OAuthException.class,source::getAccessTokenResult));
            assertEquals(OAuthException.Reason.ENDPOINT_ERROR,failure.getReason());
            assertEquals(2,server.getHitCount("/token"));
        }
    }

    @Test
    void unexpectedPostResponseClockFailureReleasesTheCacheAndRedactsItsCause() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            AtomicInteger reads=new AtomicInteger();
            Clock clock=new Clock(){
                @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
                @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}
                @Override public @NonNull Instant instant(){
                    if(reads.incrementAndGet()==3)throw new IllegalStateException("TEST-ONLY-private-clock");
                    return NOW;
                }
            };
            ClientCredentialsTokenSource source=ClientCredentialsTokenSource.withClient(client(server,clock)).build();
            server.script("/token",TestHttpsServer.Script.fromResponse(token("TEST-ONLY-first")));
            OAuthException first=onCaller(()->assertThrows(OAuthException.class,source::getAccessTokenResult));
            assertEquals(OAuthException.Reason.NETWORK_FAILURE,first.getReason());assertNull(first.getCause());
            java.lang.reflect.Field flight=ClientCredentialsTokenSource.class.getDeclaredField("flight");
            flight.setAccessible(true);assertNull(flight.get(source),"An unexpected leader failure must release its installed flight.");
            java.lang.reflect.Field count=ClientCredentialsTokenSource.class.getDeclaredField("failureCount");
            count.setAccessible(true);assertEquals(1,count.getInt(source),"The first infrastructure failure starts the bounded backoff sequence.");
            assertFalse(first.toString().contains("TEST-ONLY-private-clock"));
            assertSame(first,onCaller(()->assertThrows(OAuthException.class,source::getAccessTokenResult)));
            assertEquals(1,server.getHitCount("/token"));
        }
    }

    @Test
    void injectedErrorCannotLeaveTheRenewalFlightInstalled() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            AtomicInteger reads=new AtomicInteger();
            Clock clock=new Clock(){
                @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
                @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}
                @Override public @NonNull Instant instant(){
                    if(reads.incrementAndGet()==3)throw new AssertionError("TEST-ONLY-clock-error");
                    return NOW;
                }
            };
            ClientCredentialsTokenSource source=ClientCredentialsTokenSource.withClient(client(server,clock)).build();
            server.script("/token",TestHttpsServer.Script.fromResponse(token("TEST-ONLY-recovered")));
            AssertionError first=onCaller(()->assertThrows(AssertionError.class,source::getAccessTokenResult));
            assertEquals("TEST-ONLY-clock-error",first.getMessage());
            java.lang.reflect.Field flight=ClientCredentialsTokenSource.class.getDeclaredField("flight");
            flight.setAccessible(true);assertNull(flight.get(source));
            assertEquals("TEST-ONLY-recovered",onCaller(() -> assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken()).getValue());
            assertEquals(2,server.getHitCount("/token"));
        }
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> coalescedFailureAndInterruptionKeepTheirOriginalMeaning() {
        return Stream.of(false,true).map(interrupt -> DynamicTest.dynamicTest(interrupt?"interrupted waiter":"failed leader",()->{
            try(TestHttpsServer server=TestHttpsServer.start()) {
                CountDownLatch followerEntered=new CountDownLatch(1);
                Clock clock=new Clock(){
                    @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
                    @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}
                    @Override public @NonNull Instant instant(){
                        if(Thread.currentThread().getName().equals("rc1-failed-token-follower"))followerEntered.countDown();
                        return NOW;
                    }
                };
                ClientCredentialsTokenSource source=ClientCredentialsTokenSource.withClient(client(server,clock)).build();
                TestHttpsServer.HeldScript held=TestHttpsServer.HeldScript.fromResponse(TestHttpsServer.Response.fromStatus(503));
                server.script("/token",held);
                FutureTask<OAuthException> leader=task("rc1-failed-token-leader",()->assertThrows(OAuthException.class,source::getAccessTokenResult));
                FutureTask<OAuthException> follower=new FutureTask<>(()->{
                    OAuthException failure=assertThrows(OAuthException.class,source::getAccessTokenResult);
                    if(interrupt)assertTrue(Thread.currentThread().isInterrupted());
                    return failure;
                });
                Thread thread=new Thread(follower,"rc1-failed-token-follower");thread.setDaemon(true);
                try {
                    assertTrue(held.awaitHeldCount(1,Duration.ofSeconds(2)));
                    thread.start();assertTrue(followerEntered.await(2,TimeUnit.SECONDS));
                    if(interrupt){thread.interrupt();assertEquals(OAuthException.Reason.INTERRUPTED,result(follower).getReason());}
                    held.release();OAuthException first=result(leader);
                    if(!interrupt)assertSame(first,result(follower));
                    assertSame(first,onCaller(()->assertThrows(OAuthException.class,source::getAccessTokenResult)));
                    assertEquals(1,server.getHitCount("/token"));
                } finally {held.release();leader.cancel(true);follower.cancel(true);}
            }
        }));
    }

    @Test
    void freshPublicationReturnsItsTokenWithoutStartingAnotherGrantAfterAClockAdvance() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            AtomicInteger secretReads=new AtomicInteger();
            Clock clock=clockWithReads(read->read<=3?0:61);
            ClientAuthentication authentication=ClientAuthentication.fromClientSecretPost(()->{
                if(secretReads.incrementAndGet()>1)throw new IllegalStateException("TEST-ONLY-unexpected-second-grant");
                return "TEST-ONLY-secret";
            });
            ClientCredentialsTokenSource source=ClientCredentialsTokenSource.withClient(client(server,clock,authentication)).build();
            server.script("/token",TestHttpsServer.Script.fromResponse(token("TEST-ONLY-first")));
            assertEquals("TEST-ONLY-first",onCaller(() -> assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken()).getValue());
            assertEquals(1,secretReads.get());assertEquals(1,server.getHitCount("/token"));
        }
    }

    @Test
    void failedEarlyRenewalReturnsItsStillValidFallbackBeforeAnotherClockRead() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            Clock clock=clockWithReads(read->read<=3?0:read<=6?51:61);
            ClientCredentialsTokenSource source=ClientCredentialsTokenSource.withClient(client(server,clock))
                    .renewBefore(Duration.ofSeconds(10)).build();
            server.script("/token",TestHttpsServer.Script.fromResponse(token("TEST-ONLY-first")));
            AccessToken first=onCaller(() -> assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken());
            server.script("/token",TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromStatus(503)));
            assertSame(first,onCaller(() -> assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken()));
            assertEquals(2,server.getHitCount("/token"));
        }
    }

    @Test
    void completedWaiterReturnsTheSharedTokenWithoutRepeatingTheGrant() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            CountDownLatch followerEntered=new CountDownLatch(1);
            AtomicInteger followerReads=new AtomicInteger();AtomicInteger secretReads=new AtomicInteger();
            Clock clock=clockWithReads(read->{
                if(Thread.currentThread().getName().equals("rc1-returning-token-follower")){
                    int count=followerReads.incrementAndGet();if(count==1)followerEntered.countDown();
                    return count<=2?0:61;
                }
                return 0;
            });
            ClientAuthentication authentication=ClientAuthentication.fromClientSecretPost(()->{
                if(secretReads.incrementAndGet()>1)throw new IllegalStateException("TEST-ONLY-unexpected-second-grant");
                return "TEST-ONLY-secret";
            });
            ClientCredentialsTokenSource source=ClientCredentialsTokenSource.withClient(client(server,clock,authentication)).build();
            TestHttpsServer.HeldScript held=TestHttpsServer.HeldScript.fromResponse(token("TEST-ONLY-shared"));
            server.script("/token",held);
            FutureTask<AccessToken> leader=task("rc1-returning-token-leader",() -> assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken());
            FutureTask<AccessToken> follower=null;
            try{
                assertTrue(held.awaitHeldCount(1,Duration.ofSeconds(2)));
                follower=task("rc1-returning-token-follower",() -> assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken());
                assertTrue(followerEntered.await(2,TimeUnit.SECONDS));held.release();
                AccessToken token=result(leader);assertSame(token,result(follower));
                assertEquals("TEST-ONLY-shared",token.getValue());assertEquals(2,followerReads.get());
                assertEquals(1,secretReads.get());assertEquals(1,server.getHitCount("/token"));
            }finally{held.release();leader.cancel(true);if(follower!=null)follower.cancel(true);}
        }
    }

    private static @NonNull Clock clockWithReads(@NonNull IntUnaryOperator secondsAfterStart){
        AtomicInteger reads=new AtomicInteger();
        return new Clock(){
            @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
            @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}
            @Override public @NonNull Instant instant(){return NOW.plusSeconds(secondsAfterStart.applyAsInt(reads.incrementAndGet()));}
        };
    }
    private static @NonNull OAuthClient client(@NonNull TestHttpsServer server,@NonNull Clock clock) {
        return client(server,clock,ClientAuthentication.fromClientSecretBasic("TEST-ONLY-secret"));
    }
    private static @NonNull OAuthClient client(@NonNull TestHttpsServer server,@NonNull Clock clock,@NonNull ClientAuthentication authentication) {
        return OAuthClient.withAuthorizationServerMetadata(AuthorizationServerMetadata.withIssuer(server.uri("/tenant").toString())
            .authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token")).build())
            .clientId("client").clientAuthentication(authentication)
            .httpClient(TestTls.httpClient()).clock(clock).build();
    }
    private static TestHttpsServer.@NonNull Response token(@NonNull String value){
        return TestHttpsServer.Response.fromJson(200,"{\"access_token\":\""+value+"\",\"token_type\":\"Bearer\",\"expires_in\":60}");
    }
    private static void await(@NonNull CountDownLatch latch){
        assertDoesNotThrow(()->assertTrue(latch.await(2,TimeUnit.SECONDS)));
    }
    private static <T> @NonNull FutureTask<@NonNull T> task(@NonNull String name,@NonNull Supplier<@NonNull T> action){
        FutureTask<T> future=new FutureTask<>(action::get);Thread thread=new Thread(future,name);thread.setDaemon(true);thread.start();return future;
    }
    private static <T> @NonNull T result(@NonNull FutureTask<@NonNull T> future){return assertDoesNotThrow(()->future.get(2,TimeUnit.SECONDS));}
    private static <T> @NonNull T onCaller(@NonNull Supplier<@NonNull T> action){
        FutureTask<T> future=task("rc1-isolated-token-caller",action);try{return result(future);}finally{future.cancel(true);}
    }
}
