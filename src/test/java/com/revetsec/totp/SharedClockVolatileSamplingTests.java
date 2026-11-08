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


package com.revetsec.totp;

import com.revetsec.StoreTimeObservation;
import com.revetsec.oauth.server.OAuthStoreKey;
import com.revetsec.oauth.server.OAuthStoreReadResult;
import com.revetsec.testing.ScriptedOAuthStore;
import com.revetsec.testing.ScriptedWebAuthnStore;
import com.revetsec.webauthn.WebAuthnStoreKey;
import com.revetsec.webauthn.WebAuthnStoreReadResult;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.function.Supplier;
import static org.junit.jupiter.api.Assertions.*;

/** SC-API-11 bounded volatile fixture contract; no durable/native authority capability claim. */
final class SharedClockVolatileSamplingTests {
 private static final @NonNull Instant TIME=Instant.parse("2026-10-29T12:00:00Z");
 private static final @NonNull Duration BUDGET=Duration.ofSeconds(5);
 private enum Family { TOTP, WEBAUTHN, ISSUER_NORMAL }
 @TestFactory @NonNull List<@NonNull DynamicTest> earlierSamplesNeverBecomeHealthyEvenAfterClockGenerationRotation(){
  List<DynamicTest> cells=new ArrayList<>();for(Family family:Family.values())for(boolean rotate:List.of(false,true))cells.add(DynamicTest.dynamicTest("SC-API-11/"+family+"/new-generation="+rotate,()->{
   Fixture f=fixture(family);f.setTime().accept(TIME.plusSeconds(1));var first=healthy(f.read().get());f.setTime().accept(TIME.plusSeconds(2));var second=healthy(f.read().get());assertEquals(TIME.plusSeconds(1),first.getObservedAt());assertEquals(TIME.plusSeconds(2),second.getObservedAt());assertEquals(first.getClockGeneration(),second.getClockGeneration());if(rotate)f.rotate().run();f.setTime().accept(TIME.plusSeconds(2).minusNanos(1));StoreTimeObservation unavailable=f.read().get();assertInstanceOf(StoreTimeObservation.Unavailable.class,unavailable);assertEquals(second.getAdmission(),unavailable.getAdmission());
  }));return cells;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> delayedFirstReplyDoesNotReverseSamplingOrderOrLowerTheProviderFloor(){
  List<DynamicTest> cells=new ArrayList<>();for(Family family:Family.values())cells.add(DynamicTest.dynamicTest("SC-API-11/"+family+"/reverse-reply-delivery",()->{
   Fixture f=fixture(family);List<String> trace=new CopyOnWriteArrayList<>();CountDownLatch captured=new CountDownLatch(1),release=new CountDownLatch(1);ExecutorService executor=Executors.newSingleThreadExecutor();
   try{
    Future<StoreTimeObservation> delayed=executor.submit(()->{StoreTimeObservation observation=f.read().get();trace.add("sample-one");captured.countDown();assertTrue(release.await(5,TimeUnit.SECONDS));trace.add("first-delivered");return observation;});assertTrue(captured.await(5,TimeUnit.SECONDS));f.setTime().accept(TIME.plusSeconds(1));var second=healthy(f.read().get());trace.add("sample-two");trace.add("second-delivered");assertFalse(delayed.isDone());release.countDown();var first=healthy(delayed.get(5,TimeUnit.SECONDS));assertEquals(TIME,first.getObservedAt());assertEquals(TIME.plusSeconds(1),second.getObservedAt());assertEquals(first.getClockGeneration(),second.getClockGeneration());assertEquals(first.getAdmission(),second.getAdmission());assertEquals(List.of("sample-one","sample-two","second-delivered","first-delivered"),trace);f.setTime().accept(TIME.plusMillis(500));assertInstanceOf(StoreTimeObservation.Unavailable.class,f.read().get(),"Reply delivery must not lower the already sampled maximum");
   }finally{release.countDown();executor.shutdownNow();assertTrue(executor.awaitTermination(5,TimeUnit.SECONDS));}
  }));return cells;
 }
 private static StoreTimeObservation.@NonNull Healthy healthy(@NonNull StoreTimeObservation observation){return assertInstanceOf(StoreTimeObservation.Healthy.class,observation);}
 private record Fixture(@NonNull Consumer<@NonNull Instant> setTime,@NonNull Runnable rotate,@NonNull Supplier<@NonNull StoreTimeObservation> read) { }
 private static @NonNull Fixture fixture(@NonNull Family family){
  return switch(family){
   case TOTP->{ScriptedTotpStore store=new ScriptedTotpStore("sample-order","epoch",TIME);TotpStoreKey key=TotpStoreKey.forNamespace("sample-order","epoch");yield new Fixture(store::setTime,store::rotateClockGeneration,()->assertInstanceOf(TotpStoreReadResult.Available.class,store.read(Set.of(key),BUDGET)).getSnapshot().getTimeObservation());}
   case WEBAUTHN->{ScriptedWebAuthnStore store=new ScriptedWebAuthnStore(TIME);WebAuthnStoreKey key=WebAuthnStoreKey.forNamespaceClock("sample-order","login.example.com");yield new Fixture(store::setTime,store::rotateClockGeneration,()->assertInstanceOf(WebAuthnStoreReadResult.Available.class,store.read(Set.of(key),BUDGET)).getSnapshot().getTimeObservation());}
   case ISSUER_NORMAL->{ScriptedOAuthStore store=new ScriptedOAuthStore(TIME);String ns="A".repeat(43);OAuthStoreKey key=OAuthStoreKey.fromStoredForm("revetsec:as:1:"+ns+":ISSUER_STATE:"+ns);yield new Fixture(store::setTime,store::rotateClockGeneration,()->assertInstanceOf(OAuthStoreReadResult.Available.class,store.read(key,BUDGET)).getTimeObservation());}
  };
 }
}
