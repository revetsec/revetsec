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

package com.revetsec.saml;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.lang.reflect.InvocationTargetException;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** Explicit approved-connection reservations retain replay marks and independent capacity. */
final class SamlReplayCapacityTests {
 private static final @NonNull Instant START=Instant.parse("2026-11-05T12:00:00Z");
 private static final @NonNull Duration BUDGET=Duration.ofSeconds(5);
 private static @NonNull InMemorySamlReplayCache cache(@Nullable Clock clock,@Nullable Map<@NonNull String,@NonNull Integer> quotas){
  var method=assertDoesNotThrow(()->InMemorySamlReplayCache.class.getMethod("fromConnectionLimits",Clock.class,Map.class),"Explicit connection reservations must be available");
  try{return (InMemorySamlReplayCache)method.invoke(null,clock,quotas);}
  catch(InvocationTargetException failure){if(failure.getCause() instanceof RuntimeException cause)throw cause;if(failure.getCause() instanceof Error cause)throw cause;throw new AssertionError("Unexpected factory failure");}
  catch(IllegalAccessException failure){throw new AssertionError("Factory inaccessible");}
 }
 private static SamlReplayCache.@NonNull MarkResult mark(@NonNull SamlReplayCache cache,@NonNull String connection,@NonNull String key,@NonNull Instant expiry){return cache.markIfAbsent(connection,key,expiry,BUDGET);}
 @Test void fourHostileConnectionsCannotSpendTheHealthyReservation(){
  var clock=Clock.fixed(START,ZoneOffset.UTC);var quotas=Map.of("hostile-a",4,"hostile-b",4,"hostile-c",4,"hostile-d",4,"healthy",4);var c=cache(clock,quotas);var end=START.plusSeconds(60);
  for(String connection:List.of("hostile-a","hostile-b","hostile-c","hostile-d")){
   for(int i=0;i<4;i++)assertEquals(SamlReplayCache.MarkResult.MARKED,mark(c,connection,connection+i,end));
   assertEquals(SamlReplayCache.MarkResult.CAPACITY_REFUSED,mark(c,connection,connection+"over",end));
  }
  for(int i=0;i<4;i++)assertEquals(SamlReplayCache.MarkResult.MARKED,mark(c,"healthy","healthy"+i,end));
  assertEquals(SamlReplayCache.MarkResult.CAPACITY_REFUSED,mark(c,"healthy","healthy-over",end));
  for(String connection:quotas.keySet())for(int i=0;i<4;i++)assertEquals(SamlReplayCache.MarkResult.ALREADY_PRESENT,mark(c,connection,connection+i,end));
 }
 /** The before fixture selects the legacy publicfactory only while the newfactory is absent. */
 @Test void fourSaturatedConnectionsStillLeaveTheHealthyConnectionsDeclaredCapacity()throws Exception{
  var clock=Clock.fixed(START,ZoneOffset.UTC);var quotas=Map.of("hostile-a",4,"hostile-b",4,"hostile-c",4,"hostile-d",4,"healthy",4);SamlReplayCache selected;
  try{InMemorySamlReplayCache.class.getMethod("fromConnectionLimits",Clock.class,Map.class);selected=cache(clock,quotas);}
  catch(NoSuchMethodException originalImplementation){selected=InMemorySamlReplayCache.fromLimit(clock,20);}
  var counts=new ArrayList<Integer>();var end=START.plusSeconds(60);
  for(String connection:List.of("hostile-a","hostile-b","hostile-c","hostile-d")){
   int admitted=0;for(int i=0;i<=20;i++){var result=mark(selected,connection,connection+i,end);if(result==SamlReplayCache.MarkResult.MARKED)admitted++;else{assertEquals(SamlReplayCache.MarkResult.CAPACITY_REFUSED,result);break;}}counts.add(admitted);
  }
  // Original quarter quotas admit five marks each, exhaust all20 and deny this actual healthy admission.
  for(int i=0;i<4;i++)assertEquals(SamlReplayCache.MarkResult.MARKED,mark(selected,"healthy","healthy"+i,end),"A saturated hostile set must leave the approved healthy reservation");
  assertEquals(List.of(4,4,4,4),counts);
 }
 @Test void oneConfiguredConnectionReceivesItsFullDeclaredCapacity(){var c=cache(Clock.fixed(START,ZoneOffset.UTC),Map.of("only",8));for(int i=0;i<8;i++)assertEquals(SamlReplayCache.MarkResult.MARKED,mark(c,"only","k"+i,START.plusSeconds(60)));assertEquals(SamlReplayCache.MarkResult.CAPACITY_REFUSED,mark(c,"only","over",START.plusSeconds(60)));}
 @Test void unknownAndLegacyNamespacesCannotBorrowOrAllocate(){var c=cache(Clock.fixed(START,ZoneOffset.UTC),Map.of("healthy",2));var end=START.plusSeconds(60);for(int i=0;i<1024;i++)assertEquals(SamlReplayCache.MarkResult.CAPACITY_REFUSED,mark(c,"unknown"+i,"unknown-key"+i,end));assertEquals(SamlReplayCache.MarkResult.CAPACITY_REFUSED,c.markIfAbsent("legacy",end,BUDGET));assertEquals(SamlReplayCache.MarkResult.MARKED,mark(c,"healthy","one",end));assertEquals(SamlReplayCache.MarkResult.MARKED,mark(c,"healthy","two",end));assertEquals(SamlReplayCache.MarkResult.CAPACITY_REFUSED,mark(c,"healthy","three",end));}
 @Test void configurationIsImmutableAndConstructionDoesNotReadTheClock(){
  var time=new TestClock();var quotas=new HashMap<>(Map.of("a",1,"b",1));var c=cache(time,quotas);assertEquals(0,time.reads.get());quotas.clear();quotas.put("evil",999);var end=START.plusSeconds(60);assertEquals(SamlReplayCache.MarkResult.MARKED,mark(c,"a","one",end));assertEquals(SamlReplayCache.MarkResult.CAPACITY_REFUSED,mark(c,"a","over",end));assertEquals(SamlReplayCache.MarkResult.CAPACITY_REFUSED,mark(c,"evil","evil",end));assertEquals(SamlReplayCache.MarkResult.MARKED,mark(c,"b","two",end));assertEquals("InMemorySamlReplayCache{entries=<redacted>}",c.toString());
 }
 @Test void exactExpiryReleasesOnlyItsOwningReservationAndRollbackNeverEvicts(){
  var time=new TestClock();var c=cache(time,Map.of("a",1,"b",1));var first=START.plusSeconds(10);var last=START.plusSeconds(30);assertEquals(SamlReplayCache.MarkResult.MARKED,mark(c,"a","old-a",first));assertEquals(SamlReplayCache.MarkResult.MARKED,mark(c,"b","live-b",last));time.value.set(first.minusNanos(1));assertEquals(SamlReplayCache.MarkResult.CAPACITY_REFUSED,mark(c,"a","new-a",last));time.value.set(START.minusNanos(1));assertEquals(SamlReplayCache.MarkResult.UNAVAILABLE,mark(c,"a","new-a",last));time.value.set(first);assertEquals(SamlReplayCache.MarkResult.MARKED,mark(c,"a","new-a",last));assertEquals(SamlReplayCache.MarkResult.ALREADY_PRESENT,mark(c,"b","live-b",last));assertEquals(SamlReplayCache.MarkResult.CAPACITY_REFUSED,mark(c,"b","new-b",last));assertEquals(SamlReplayCache.MarkResult.CAPACITY_REFUSED,mark(c,"a","another-a",last));
 }
 @Test void zeroBudgetAndInterruptionDoNotReadClockOrSpendQuota(){var time=new TestClock();var c=cache(time,Map.of("a",1));var end=START.plusSeconds(60);assertEquals(SamlReplayCache.MarkResult.UNAVAILABLE,c.markIfAbsent("a","k",end,Duration.ZERO));Thread.currentThread().interrupt();try{assertEquals(SamlReplayCache.MarkResult.UNAVAILABLE,mark(c,"a","k",end));assertTrue(Thread.currentThread().isInterrupted());}finally{Thread.interrupted();}assertEquals(0,time.reads.get());assertEquals(SamlReplayCache.MarkResult.MARKED,mark(c,"a","k",end));}
 @Test void concurrentAdmissionsSettleExactlyTheirOwnQuotas()throws Exception{
  var c=cache(Clock.fixed(START,ZoneOffset.UTC),Map.of("a",8,"b",3));var pool=Executors.newFixedThreadPool(12);var start=new CountDownLatch(1);var tasks=new ArrayList<Future<SamlReplayCache.@NonNull MarkResult>>();
  try{for(int i=0;i<48;i++){int number=i;tasks.add(pool.submit(()->{start.await();return mark(c,number<32?"a":"b","k"+number,START.plusSeconds(60));}));}start.countDown();int a=0,b=0;for(int i=0;i<tasks.size();i++){var result=tasks.get(i).get(10,TimeUnit.SECONDS);if(result==SamlReplayCache.MarkResult.MARKED){if(i<32)a++;else b++;}else assertEquals(SamlReplayCache.MarkResult.CAPACITY_REFUSED,result);}assertEquals(8,a);assertEquals(3,b);}finally{start.countDown();pool.shutdownNow();assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS));}
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> invalidConfigurationIsBounded(){
  var invalid=new ArrayList<Map<@NonNull String,@NonNull Integer>>();invalid.add(Map.of());invalid.add(Map.of("",1));invalid.add(Map.of("x".repeat(257),1));invalid.add(Map.of("a",0));invalid.add(Map.of("a",-1));invalid.add(Map.of("a",1_000_001));invalid.add(Map.of("a",1_000_000,"b",1));var nullKey=new HashMap<String,Integer>();nullKey.put(null,1);invalid.add(nullKey);var nullValue=new HashMap<String,Integer>();nullValue.put("a",null);invalid.add(nullValue);var excessive=new HashMap<String,Integer>();for(int i=0;i<1025;i++)excessive.put("c"+i,1);invalid.add(excessive);
  return java.util.stream.IntStream.range(0,invalid.size()).mapToObj(i->DynamicTest.dynamicTest("invalid-reservation-"+i,()->assertThrows(RuntimeException.class,()->cache(Clock.fixed(START,ZoneOffset.UTC),invalid.get(i)))));
 }
 @Test void nullRequiredConfigurationIsRejected(){assertThrows(NullPointerException.class,()->cache(null,Map.of("a",1)));assertThrows(NullPointerException.class,()->cache(Clock.fixed(START,ZoneOffset.UTC),null));}
 @Test void exactConfigurationLimitsAreAccepted(){var c=cache(Clock.fixed(START,ZoneOffset.UTC),Map.of("x".repeat(256),1_000_000));assertEquals(SamlReplayCache.MarkResult.MARKED,mark(c,"x".repeat(256),"key",START.plusSeconds(60)));var quotas=new HashMap<String,Integer>();for(int i=0;i<1024;i++)quotas.put("c"+i,1);assertDoesNotThrow(()->cache(Clock.fixed(START,ZoneOffset.UTC),quotas));}
 private static final class TestClock extends Clock{
  private final @NonNull AtomicReference<@NonNull Instant> value=new AtomicReference<>(START);private final @NonNull AtomicInteger reads=new AtomicInteger();
  @Override public @NonNull Instant instant(){reads.incrementAndGet();return java.util.Objects.requireNonNull(value.get());}
  @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
  @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}
 }
}
