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

import com.revetsec.internal.http.Deadline;
import com.revetsec.testing.TestJwk;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Actual two-caller lifecycle ordering, never distributed publication or durable history proof. */
final class OAuthIssuerOvertakenSnapshotTests {
 private static final @NonNull Instant NOW=Instant.parse("2026-10-05T12:00:00Z");
 private static final TestJwk.@NonNull Fixture A=TestJwk.Fixture.IDP_SIGNING_RSA_2048;
 private static @NonNull OAuthIssuerKeySnapshot keys(int generation) {
  return OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromRsaKeyPair("a",A.getPrivateKey(),A.getPublicKey()))
   .generation("g"+generation).publishedAt(NOW.minusSeconds(120-generation)).build();
 }
 private static @NonNull OAuthGrantRetention retention(){return new OAuthGrantRetention(Duration.ofMinutes(5),Duration.ZERO,Duration.ofSeconds(1),Duration.ZERO);}
 private static @NonNull Deadline deadline(){return Deadline.fromNow(Duration.ofSeconds(5));}
 private static @NonNull OAuthIssuerKeyLifecycle lifecycle(@NonNull OAuthIssuerKeyProvider provider,@NonNull Clock clock){return new OAuthIssuerKeyLifecycle(provider,clock,Duration.ZERO,retention());}
 @SuppressWarnings("unchecked") private static <E extends Throwable> void raise(@NonNull Throwable fault)throws E{throw (E)fault;}
 private static void refused(@NonNull Runnable call){var x=assertThrows(OAuthServerAdmissionFailure.class,call::run);assertEquals(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,x.reason());assertNull(x.getCause());}
 private static void await(@NonNull CountDownLatch latch){try{assertTrue(latch.await(3,TimeUnit.SECONDS),"bounded latch wait");}catch(InterruptedException e){Thread.currentThread().interrupt();throw new AssertionError(e);}}
 @TestFactory @NonNull List<@NonNull DynamicTest> overtakenReadIsRevalidatedOutsideLockInBothHistories(){
  List<DynamicTest> tests=new ArrayList<>();
  for(String mode:List.of("provisional","admitted","sign"))tests.add(DynamicTest.dynamicTest(mode,()->{
   var first=keys(1);var latest=keys(2);AtomicInteger calls=new AtomicInteger();AtomicReference<Thread> delayed=new AtomicReference<>();
   CountDownLatch fetched=new CountDownLatch(1),release=new CountDownLatch(1);List<Duration> budgets=Collections.synchronizedList(new ArrayList<>());
   var life=lifecycle(budget->{if(Thread.currentThread().equals(delayed.get())){budgets.add(budget);if(calls.incrementAndGet()==1){fetched.countDown();await(release);return first;}}return latest;},Clock.fixed(NOW,ZoneOffset.UTC));
   ExecutorService executor=Executors.newSingleThreadExecutor();
   try{
    Future<?> result=executor.submit(()->{delayed.set(Thread.currentThread());if(mode.equals("provisional"))assertSame(latest,life.snapshot(deadline()));
     else if(mode.equals("admitted"))assertNotNull(life.verificationKeys(deadline(),()->NOW));
     else assertFalse(life.sign("{}".getBytes(StandardCharsets.UTF_8),NOW.plusSeconds(60),deadline(),()->NOW).isEmpty());});
    await(fetched);
    // Completes while the other provider callback is blocked: callbacks cannot hold the lifecycle lock.
    if(mode.equals("provisional"))assertSame(latest,life.snapshot(deadline()));else assertNotNull(life.verificationKeys(deadline(),()->NOW));
    release.countDown();assertDoesNotThrow(()->result.get(3,TimeUnit.SECONDS));assertEquals(mode.equals("sign")?3:2,calls.get());
    for(int n=1;n<budgets.size();n++)assertTrue(budgets.get(n).compareTo(budgets.get(n-1))<0,"one shrinking deadline");
   }finally{release.countDown();executor.shutdownNow();assertTrue(executor.awaitTermination(3,TimeUnit.SECONDS));}
  }));return tests;
 }
 @Test void secondOvertakeRefusesWithoutThirdProviderRead()throws Exception{
  CountDownLatch firstFetched=new CountDownLatch(1),firstRelease=new CountDownLatch(1),secondFetched=new CountDownLatch(1),secondRelease=new CountDownLatch(1);
  AtomicInteger reads=new AtomicInteger();AtomicReference<Thread> delayed=new AtomicReference<>();AtomicReference<OAuthIssuerKeySnapshot> current=new AtomicReference<>(keys(2));
  var life=lifecycle(budget->{if(Thread.currentThread().equals(delayed.get())){int n=reads.incrementAndGet();if(n==1){firstFetched.countDown();await(firstRelease);return keys(1);}if(n==2){var selected=requireNonNull(current.get());secondFetched.countDown();await(secondRelease);return selected;}}return requireNonNull(current.get());},Clock.fixed(NOW,ZoneOffset.UTC));
  ExecutorService executor=Executors.newSingleThreadExecutor();try{
   Future<?> result=executor.submit(()->{delayed.set(Thread.currentThread());refused(()->life.snapshot(deadline()));});await(firstFetched);assertNotNull(life.snapshot(deadline()));firstRelease.countDown();await(secondFetched);current.set(keys(3));assertNotNull(life.snapshot(deadline()));secondRelease.countDown();assertDoesNotThrow(()->result.get(3,TimeUnit.SECONDS));assertEquals(2,reads.get());
  }finally{firstRelease.countDown();secondRelease.countDown();executor.shutdownNow();assertTrue(executor.awaitTermination(3,TimeUnit.SECONDS));}
 }
 @Test void ordinaryRollbackStillRefusesOnceAndDoesNotReplaceHistory(){
  AtomicReference<OAuthIssuerKeySnapshot> current=new AtomicReference<>(keys(2));AtomicInteger calls=new AtomicInteger();var life=lifecycle(budget->{calls.incrementAndGet();return requireNonNull(current.get());},Clock.fixed(NOW,ZoneOffset.UTC));
  assertNotNull(life.snapshot(deadline()));current.set(keys(1));refused(()->life.snapshot(deadline()));assertEquals(2,calls.get());current.set(keys(2));assertNotNull(life.snapshot(deadline()));assertEquals(3,calls.get());
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> refreshStillChecksClockAndRetirementAndFaults(){
  List<DynamicTest> tests=new ArrayList<>();
  for(String mode:List.of("clock","retirement","interrupt","fatal"))tests.add(DynamicTest.dynamicTest(mode,()->{
   CountDownLatch fetched=new CountDownLatch(1),release=new CountDownLatch(1);AtomicInteger calls=new AtomicInteger();AtomicReference<Thread> delayed=new AtomicReference<>();AtomicReference<Instant> now=new AtomicReference<>(NOW);var first=keys(1);var latest=keys(2);
   var invalid=OAuthIssuerKeySnapshot.withActiveKey(latest.getActiveKey()).generation("g3").publishedAt(NOW.minusSeconds(90)).retirementNotBefore(Map.of("a",NOW.plusSeconds(1))).build();
   var life=lifecycle(budget->{if(Thread.currentThread().equals(delayed.get())){if(calls.incrementAndGet()==1){fetched.countDown();await(release);return first;}if(mode.equals("interrupt"))raise(new InterruptedException("private"));if(mode.equals("fatal"))throw new InternalError("private");if(mode.equals("retirement"))return invalid;}return latest;},Clock.fixed(NOW,ZoneOffset.UTC));
   ExecutorService executor=Executors.newSingleThreadExecutor();try{
    Future<?> result=executor.submit(()->{delayed.set(Thread.currentThread());try{
     if(mode.equals("fatal"))assertThrows(InternalError.class,()->life.verificationKeys(deadline(),()->requireNonNull(now.get())));
     else if(mode.equals("retirement"))refused(()->life.sign("{}".getBytes(StandardCharsets.UTF_8),NOW.plusSeconds(60),deadline(),()->requireNonNull(now.get())));
     else refused(()->life.verificationKeys(deadline(),()->requireNonNull(now.get())));
     assertEquals(mode.equals("interrupt"),Thread.currentThread().isInterrupted());
    }finally{Thread.interrupted();}});await(fetched);assertNotNull(life.verificationKeys(deadline(),()->NOW));if(mode.equals("clock"))now.set(NOW.minusNanos(1));release.countDown();assertDoesNotThrow(()->result.get(3,TimeUnit.SECONDS));assertEquals(mode.equals("clock")?1:2,calls.get());
   }finally{release.countDown();executor.shutdownNow();assertTrue(executor.awaitTermination(3,TimeUnit.SECONDS));}
  }));return tests;
 }
 @Test void provisionalAdvanceDoesNotOvertakeAdmittedHistory()throws Exception{
  AtomicInteger calls=new AtomicInteger();AtomicReference<Thread> delayed=new AtomicReference<>();CountDownLatch fetched=new CountDownLatch(1),release=new CountDownLatch(1);var first=keys(1);var latest=keys(2);
  var life=lifecycle(budget->{if(Thread.currentThread().equals(delayed.get())){calls.incrementAndGet();fetched.countDown();await(release);return first;}return latest;},Clock.fixed(NOW,ZoneOffset.UTC));ExecutorService executor=Executors.newSingleThreadExecutor();try{
   Future<?> result=executor.submit(()->{delayed.set(Thread.currentThread());assertNotNull(life.verificationKeys(deadline(),()->NOW));});await(fetched);assertSame(latest,life.snapshot(deadline()));release.countDown();assertDoesNotThrow(()->result.get(3,TimeUnit.SECONDS));assertEquals(1,calls.get());
  }finally{release.countDown();executor.shutdownNow();assertTrue(executor.awaitTermination(3,TimeUnit.SECONDS));}
 }
}
