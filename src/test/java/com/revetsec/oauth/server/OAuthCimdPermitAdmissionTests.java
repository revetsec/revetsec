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

import com.revetsec.OutboundUriPolicy;
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.http.RawResponse;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.Supplier;
import static org.junit.jupiter.api.Assertions.*;

/** Real bounded semaphores, deterministic held transport, no socket or production test hook. */
final class OAuthCimdPermitAdmissionTests {
 private static final String ID="https://client.example.com/metadata";
 private static Deadline deadline(){return Deadline.fromNow(Duration.ofSeconds(5));}
 private static final class Fixture {
  final CountDownLatch entered,release=new CountDownLatch(1);
  final AtomicInteger calls=new AtomicInteger(),active=new AtomicInteger(),peak=new AtomicInteger();
  final OAuthClientMetadataFetcher fetcher;
  Fixture(int maximum,int hold) {
   this.entered=new CountDownLatch(hold);
   byte[] key=new byte[32];for(int i=0;i<32;i++)key[i]=(byte)(i+1);
   var sealer=StateSealer.withActiveKey(SealingKey.fromBase64("k",Base64.getEncoder().encodeToString(key))).maximumSealedLength(16384).build();
   var policy=OAuthClientMetadataPolicy.withAddressResolver((host,budget)->{throw new AssertionError("no DNS");})
     .cache(InMemoryOAuthClientMetadataCache.fromMaximumEntries(16)).maximumConcurrentFetches(maximum).build();
   this.fetcher=new OAuthClientMetadataFetcher("https://issuer.example.com",sealer,policy,OAuthServerIngressLimits.fromDefaults(),false,false,
    OutboundUriPolicy.defaultInstance(),Clock.fixed(Instant.parse("2026-10-31T12:00:00Z"),ZoneOffset.UTC),(uri,budget)->{
     int ordinal=this.calls.incrementAndGet();int outstanding=this.active.incrementAndGet();this.peak.accumulateAndGet(outstanding,Math::max);
     try {
      if(ordinal<=hold){this.entered.countDown();try{if(!this.release.await(10,TimeUnit.SECONDS))throw new AssertionError("transport release");}
       catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new IllegalStateException("cancelled fixture");}}
      String body="{\"client_id\":\""+ID+"\",\"client_name\":\"Fixture\",\"token_endpoint_auth_method\":\"none\",\"redirect_uris\":[\"https://client.example.com/callback\"]}";
      return new RawResponse(200,HttpHeaders.of(Map.of("Cache-Control",List.of("no-store")),(a,b)->true),body.getBytes(StandardCharsets.UTF_8),null,false,Duration.ZERO);
     } finally {this.active.decrementAndGet();}
    });
  }
  Semaphore semaphore(String name) throws ReflectiveOperationException {
   var field=OAuthClientMetadataFetcher.class.getDeclaredField(name);field.setAccessible(true);return assertInstanceOf(Semaphore.class,field.get(this.fetcher));
  }
  Capture caller(boolean fresh,Deadline budget){return new Capture(()->fresh?this.fetcher.fresh(ID,budget):this.fetcher.reusable(ID,budget));}
  void held() throws InterruptedException {assertTrue(this.entered.await(3,TimeUnit.SECONDS));}
 }
 private static final class Capture {
  final FutureTask<OAuthClientMetadataDocument> result;
  final Thread worker;
  final AtomicBoolean interrupted=new AtomicBoolean();
  Capture(Supplier<OAuthClientMetadataDocument> work){
   this.result=new FutureTask<>(()->{try{return work.get();}finally{this.interrupted.set(Thread.currentThread().isInterrupted());}});
   this.worker=new Thread(this.result,"cimd-permit-admission");this.worker.setDaemon(true);
  }
  void start(){this.worker.start();}
  void success(){assertNotNull(assertDoesNotThrow(()->this.result.get(3,TimeUnit.SECONDS)));}
  void infrastructure(){
   ExecutionException failed=assertThrows(ExecutionException.class,()->this.result.get(3,TimeUnit.SECONDS));
   OAuthServerAdmissionFailure cause=assertInstanceOf(OAuthServerAdmissionFailure.class,failed.getCause());assertEquals(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,cause.reason());
   assertNull(cause.getCause());
  }
  void stop() throws InterruptedException {this.worker.interrupt();this.worker.join(3000);assertFalse(this.worker.isAlive());}
 }
 private static void queued(Semaphore semaphore,Capture caller){
  Deadline wait=Deadline.fromNow(Duration.ofSeconds(2));
  while(!semaphore.hasQueuedThreads() && caller.worker.isAlive() && !wait.isExpired())Thread.yield();
  assertTrue(semaphore.hasQueuedThreads(),"A live caller must wait interruptibly for bounded fetch capacity.");
  assertFalse(caller.result.isDone());
 }
 @Test void fixtureMetadataIsAcceptedWithoutContention() throws Exception {
  var f=new Fixture(1,0);assertNotNull(assertDoesNotThrow(()->f.fetcher.fresh(ID,deadline())));
  assertNotNull(assertDoesNotThrow(()->f.fetcher.reusable(ID,deadline())));assertEquals(2,f.calls.get());
  assertEquals(1,f.semaphore("fetches").availablePermits());assertEquals(1,f.semaphore("authorizationFetches").availablePermits());
 }
 @Test void credentialFetchWaitsForCapacityAndPerformsItsOwnRequest() throws Exception {
  var f=new Fixture(1,1);var first=f.caller(true,deadline());var second=f.caller(true,deadline());
  try {
   first.start();f.held();second.start();queued(f.semaphore("fetches"),second);assertEquals(1,f.calls.get());
   f.release.countDown();first.success();second.success();assertEquals(2,f.calls.get());assertEquals(1,f.peak.get());
  } finally {f.release.countDown();first.stop();second.stop();}
  assertEquals(1,f.semaphore("fetches").availablePermits());
 }
 @Test void authorizationQueueCannotTakeTheCredentialReserve() throws Exception {
  var f=new Fixture(2,1);var first=f.caller(false,deadline());var second=f.caller(false,deadline());
  try {
   first.start();f.held();second.start();queued(f.semaphore("authorizationFetches"),second);
   assertNotNull(assertDoesNotThrow(()->f.fetcher.fresh(ID,deadline())));assertEquals(2,f.calls.get());assertEquals(2,f.peak.get());
   f.release.countDown();first.success();second.success();assertEquals(3,f.calls.get());
  } finally {f.release.countDown();first.stop();second.stop();}
  assertEquals(2,f.semaphore("fetches").availablePermits());assertEquals(1,f.semaphore("authorizationFetches").availablePermits());
 }
 @Test void queuedDeadlineExpiresWithoutARequestOrPermitLeak() throws Exception {
  var f=new Fixture(1,1);var first=f.caller(true,deadline());
  try {
   first.start();f.held();var second=f.caller(false,Deadline.fromNow(Duration.ofSeconds(1)));
   try {second.start();queued(f.semaphore("fetches"),second);second.infrastructure();assertEquals(1,f.calls.get());assertEquals(1,f.semaphore("authorizationFetches").availablePermits());}
   finally {second.stop();}
   f.release.countDown();first.success();assertNotNull(assertDoesNotThrow(()->f.fetcher.reusable(ID,deadline())));assertEquals(2,f.calls.get());
  } finally {f.release.countDown();first.stop();}
  assertEquals(1,f.semaphore("fetches").availablePermits());
 }
 @Test void queuedInterruptionRestoresTheFlagAndReleasesPartialAdmission() throws Exception {
  var f=new Fixture(1,1);var first=f.caller(true,deadline());var second=f.caller(false,deadline());
  try {
   first.start();f.held();second.start();queued(f.semaphore("fetches"),second);second.worker.interrupt();second.infrastructure();
   assertTrue(second.interrupted.get());assertEquals(1,f.calls.get());assertEquals(1,f.semaphore("authorizationFetches").availablePermits());
   f.release.countDown();first.success();assertNotNull(assertDoesNotThrow(()->f.fetcher.reusable(ID,deadline())));
  } finally {f.release.countDown();first.stop();second.stop();}
  assertEquals(1,f.semaphore("fetches").availablePermits());
 }
 @Test void cancellationInTheAuthorizationQueueDoesNotReleaseAnotherCallersPermit() throws Exception {
  var f=new Fixture(2,1);var first=f.caller(false,deadline());var second=f.caller(false,deadline());
  try {
   first.start();f.held();second.start();queued(f.semaphore("authorizationFetches"),second);second.worker.interrupt();second.infrastructure();
   assertTrue(second.interrupted.get());assertEquals(0,f.semaphore("authorizationFetches").availablePermits());assertEquals(1,f.semaphore("fetches").availablePermits());
   assertNotNull(assertDoesNotThrow(()->f.fetcher.fresh(ID,deadline())));f.release.countDown();first.success();
  } finally {f.release.countDown();first.stop();second.stop();}
  assertEquals(1,f.semaphore("authorizationFetches").availablePermits());assertEquals(2,f.semaphore("fetches").availablePermits());
 }
 @Test void preInterruptedOrExpiredCallersDoNotAcquireOrFetch() throws Exception {
  var f=new Fixture(2,0);
  assertEquals(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,assertThrows(OAuthServerAdmissionFailure.class,()->f.fetcher.fresh(ID,Deadline.fromNow(Duration.ZERO))).reason());
  Thread.currentThread().interrupt();try{assertThrows(OAuthServerAdmissionFailure.class,()->f.fetcher.reusable(ID,deadline()));assertTrue(Thread.currentThread().isInterrupted());}finally{Thread.interrupted();}
  assertEquals(0,f.calls.get());assertEquals(2,f.semaphore("fetches").availablePermits());assertEquals(1,f.semaphore("authorizationFetches").availablePermits());
 }
}
