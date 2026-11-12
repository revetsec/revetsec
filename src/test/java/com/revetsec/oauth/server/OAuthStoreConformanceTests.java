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

import com.revetsec.StoreTemporalCondition;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.StoreTimeAccess;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Portable issuer-store transaction checks. Subclasses control an independent authority and
 * provide a fresh empty namespace; durability and cross-process progress are separate profiles. */
@javax.annotation.concurrent.NotThreadSafe
public abstract class OAuthStoreConformanceTests {
 private static final @NonNull Duration BUDGET=Duration.ofSeconds(5);
 protected static final @NonNull Instant NOW=Instant.parse("2026-10-04T00:00:00Z");
 private static final @NonNull String NS=nonce(1);
 private static final @NonNull OAuthStoreKey ROOT=key(OAuthStoreKey.Kind.ISSUER_STATE,1);
 private static final @NonNull OAuthStoreKey SUBJECT=key(OAuthStoreKey.Kind.SUBJECT_STATE,2);
 private static final @NonNull OAuthStoreKey CODE=key(OAuthStoreKey.Kind.CODE,3);

 protected abstract @NonNull OAuthAuthorizationServerStore newStore();
 protected abstract @NonNull OAuthAuthorizationServerStore newStoreWithEntryLimit(int maximumEntries);
 protected abstract void setAuthorityHealthy(@NonNull OAuthAuthorizationServerStore store,boolean healthy);
 protected abstract void advanceAuthorityTo(@NonNull OAuthAuthorizationServerStore store,@NonNull Instant instant);
 protected abstract void rotateClockGeneration(@NonNull OAuthAuthorizationServerStore store);
 protected abstract void rotateRecoveryGeneration(@NonNull OAuthAuthorizationServerStore store);

 @Test void changedUnrelatedConditionCancelsTheWholeMutationSet(){
  OAuthAuthorizationServerStore store=initialized();
  StoreTimeObservation.Healthy time=healthy(store);
  OAuthStoreTransaction proposed=timed(time,List.of(present(ROOT,1),absent(CODE),absent(SUBJECT)),
    List.of(put(entry(SUBJECT,4))));
  assertEquals(OAuthStoreCommitStatus.COMMITTED,store.commit(timed(time,List.of(present(ROOT,1),absent(CODE)),
    List.of(put(entry(CODE,5)))),BUDGET).getStatus());
  assertEquals(OAuthStoreCommitStatus.CONFLICT,store.commit(proposed,BUDGET).getStatus());
  assertTrue(available(store,SUBJECT).getEntry().isEmpty());
  assertEquals(nonce(5),available(store,CODE).getEntry().orElseThrow().getVersion());
 }

 @Test void conditionOnlyBarrierReturnsTimeWithoutRewritingData(){
  OAuthAuthorizationServerStore store=initialized();
  OAuthStoreEntry before=available(store,ROOT).getEntry().orElseThrow();
  OAuthStoreCommitReceipt receipt=store.commit(timed(healthy(store),List.of(present(ROOT,1)),List.of()),BUDGET);
  assertEquals(OAuthStoreCommitStatus.COMMITTED,receipt.getStatus());
  assertTrue(receipt.getTiming().isPresent());
  OAuthStoreEntry after=available(store,ROOT).getEntry().orElseThrow();
  assertEquals(before.getVersion(),after.getVersion());
  assertEquals(before.toSealedForm(),after.toSealedForm());
 }

 @Test void futureFloorAndNonpositiveBudgetRefuseWithoutEffect(){
  OAuthAuthorizationServerStore store=initialized();StoreTimeObservation.Healthy time=healthy(store);
  StoreTemporalCondition future=StoreTimeAccess.get().fromObservation(time,time.getObservedAt().plusSeconds(3600),null);
  OAuthStoreTransaction tooEarly=OAuthStoreTransaction.fromConditions(OAuthStoreTransaction.Purpose.TIMED,
    time.getAdmission(),future,List.of(present(ROOT,1),absent(CODE)),List.of(put(entry(CODE,6))));
  assertEquals(OAuthStoreCommitStatus.TIME_BEFORE_FLOOR,store.commit(tooEarly,BUDGET).getStatus());
  OAuthStoreTransaction valid=timed(time,List.of(present(ROOT,1),absent(CODE)),List.of(put(entry(CODE,6))));
  assertEquals(OAuthStoreCommitStatus.UNAVAILABLE,store.commit(valid,Duration.ZERO).getStatus());
  assertInstanceOf(OAuthStoreReadResult.Unavailable.class,store.read(ROOT,Duration.ZERO));
  assertTrue(available(store,CODE).getEntry().isEmpty());
 }

 @Test void temporalBoundsAreInclusiveBelowAndExclusiveAboveAtNanosecondEdges(){
  OAuthAuthorizationServerStore store=initialized();
  StoreTimeObservation.Healthy time=healthy(store);
  StoreTemporalCondition window=StoreTimeAccess.get().fromObservation(time,
    NOW.plusNanos(1),NOW.plusNanos(3));
  OAuthStoreTransaction barrier=OAuthStoreTransaction.fromConditions(OAuthStoreTransaction.Purpose.TIMED,
    time.getAdmission(),window,List.of(present(ROOT,1)),List.of());
  assertEquals(OAuthStoreCommitStatus.TIME_BEFORE_FLOOR,store.commit(barrier,BUDGET).getStatus());
  advanceAuthorityTo(store,NOW.plusNanos(1));
  assertEquals(OAuthStoreCommitStatus.COMMITTED,store.commit(barrier,BUDGET).getStatus());
  advanceAuthorityTo(store,NOW.plusNanos(2));
  assertEquals(OAuthStoreCommitStatus.COMMITTED,store.commit(barrier,BUDGET).getStatus());
  advanceAuthorityTo(store,NOW.plusNanos(3));
  assertEquals(OAuthStoreCommitStatus.TIME_EXPIRED,store.commit(barrier,BUDGET).getStatus());
  advanceAuthorityTo(store,NOW.plusNanos(4));
  assertEquals(OAuthStoreCommitStatus.TIME_EXPIRED,store.commit(barrier,BUDGET).getStatus());
  assertEquals(nonce(1),available(store,ROOT).getEntry().orElseThrow().getVersion());
 }

 @Test void clockGenerationChangeFencesThePreparedTimedWrite(){
  OAuthAuthorizationServerStore store=initialized();
  OAuthStoreTransaction stale=timed(healthy(store),List.of(present(ROOT,1),absent(CODE)),
    List.of(put(entry(CODE,9))));
  rotateClockGeneration(store);
  assertEquals(OAuthStoreCommitStatus.FENCED,store.commit(stale,BUDGET).getStatus());
  assertTrue(available(store,CODE).getEntry().isEmpty());
  assertEquals(OAuthStoreCommitStatus.COMMITTED,store.commit(timed(healthy(store),
    List.of(present(ROOT,1),absent(CODE)),List.of(put(entry(CODE,9)))),BUDGET).getStatus());
 }

 @Test void recoveryGenerationChangeFencesEvenTheClocklessPermanentMutation(){
  OAuthAuthorizationServerStore store=initialized();
  StoreTimeObservation.Healthy time=healthy(store);
  OAuthStoreTransaction stale=OAuthStoreTransaction.fromConditions(OAuthStoreTransaction.Purpose.FENCE_ONLY,
    time.getAdmission(),null,List.of(present(ROOT,1)),List.of(put(entry(ROOT,10))));
  rotateRecoveryGeneration(store);
  assertEquals(OAuthStoreCommitStatus.FENCED,store.commit(stale,BUDGET).getStatus());
  assertEquals(nonce(1),available(store,ROOT).getEntry().orElseThrow().getVersion());
 }

 @Test void capacityRefusalLeavesEveryPermanentAndAbsentFactIntact(){
  OAuthAuthorizationServerStore store=newStoreWithEntryLimit(1);
  StoreTimeObservation.Healthy time=healthy(store);
  assertEquals(OAuthStoreCommitStatus.COMMITTED,store.commit(timed(time,List.of(absent(ROOT)),
    List.of(put(entry(ROOT,1)))),BUDGET).getStatus());
  assertEquals(OAuthStoreCommitStatus.CAPACITY,store.commit(timed(healthy(store),
    List.of(present(ROOT,1),absent(CODE)),List.of(put(entry(CODE,11)))),BUDGET).getStatus());
  assertEquals(nonce(1),available(store,ROOT).getEntry().orElseThrow().getVersion());
  assertTrue(available(store,CODE).getEntry().isEmpty());
 }

 @Test void utcOutageBlocksTimedWriteButAllowsNarrowPermanentFence(){
  OAuthAuthorizationServerStore store=initialized();StoreTimeObservation.Healthy time=healthy(store);
  assertEquals(OAuthStoreCommitStatus.COMMITTED,store.commit(timed(time,List.of(present(ROOT,1),absent(SUBJECT)),
    List.of(put(entry(SUBJECT,2)))),BUDGET).getStatus());
  OAuthStoreTransaction timed=timed(time,List.of(present(ROOT,1),present(SUBJECT,2)),List.of(put(entry(SUBJECT,3))));
  OAuthStoreTransaction fence=OAuthStoreTransaction.fromConditions(OAuthStoreTransaction.Purpose.FENCE_ONLY,
    time.getAdmission(),null,List.of(present(ROOT,1),present(SUBJECT,2)),List.of(put(entry(SUBJECT,3))));
  setAuthorityHealthy(store,false);
  assertEquals(OAuthStoreCommitStatus.TIME_UNAVAILABLE,store.commit(timed,BUDGET).getStatus());
  assertEquals(nonce(2),available(store,SUBJECT).getEntry().orElseThrow().getVersion());
  OAuthStoreCommitReceipt receipt=store.commit(fence,BUDGET);
  assertEquals(OAuthStoreCommitStatus.COMMITTED,receipt.getStatus());
  assertTrue(receipt.getTiming().isEmpty());
  assertEquals(nonce(3),available(store,SUBJECT).getEntry().orElseThrow().getVersion());
 }

 @Test void simultaneousExpectedVersionHasOneWinner()throws Exception{
  OAuthAuthorizationServerStore store=initialized();StoreTimeObservation.Healthy time=healthy(store);
  OAuthStoreTransaction one=timed(time,List.of(present(ROOT,1)),List.of(put(entry(ROOT,7))));
  OAuthStoreTransaction two=timed(time,List.of(present(ROOT,1)),List.of(put(entry(ROOT,8))));
  CountDownLatch start=new CountDownLatch(1);var workers=Executors.newFixedThreadPool(2);
  try{
   var first=workers.submit(()->{start.await();return store.commit(one,BUDGET).getStatus();});
   var second=workers.submit(()->{start.await();return store.commit(two,BUDGET).getStatus();});
   start.countDown();
   List<OAuthStoreCommitStatus> results=List.of(first.get(8,TimeUnit.SECONDS),second.get(8,TimeUnit.SECONDS));
   assertEquals(1,results.stream().filter(value->value==OAuthStoreCommitStatus.COMMITTED).count());
   assertEquals(1,results.stream().filter(value->value==OAuthStoreCommitStatus.CONFLICT).count());
  }finally{workers.shutdownNow();assertTrue(workers.awaitTermination(3,TimeUnit.SECONDS));}
  String version=available(store,ROOT).getEntry().orElseThrow().getVersion();
  assertTrue(version.equals(nonce(7))||version.equals(nonce(8)));
 }

 private @NonNull OAuthAuthorizationServerStore initialized(){
  OAuthAuthorizationServerStore store=newStore();StoreTimeObservation.Healthy time=healthy(store);
  assertTrue(available(store,ROOT).getEntry().isEmpty());
  assertEquals(OAuthStoreCommitStatus.COMMITTED,store.commit(timed(time,List.of(absent(ROOT)),
    List.of(put(entry(ROOT,1)))),BUDGET).getStatus());
  return store;
 }
 private static OAuthStoreReadResult.@NonNull Available available(@NonNull OAuthAuthorizationServerStore store,@NonNull OAuthStoreKey key){
  return assertInstanceOf(OAuthStoreReadResult.Available.class,store.read(key,BUDGET));
 }
 private static StoreTimeObservation.@NonNull Healthy healthy(@NonNull OAuthAuthorizationServerStore store){
  return assertInstanceOf(StoreTimeObservation.Healthy.class,available(store,ROOT).getTimeObservation());
 }
 private static @NonNull OAuthStoreTransaction timed(StoreTimeObservation.@NonNull Healthy time,
   @NonNull List<OAuthStoreTransaction.@NonNull Condition> conditions,
   @NonNull List<OAuthStoreTransaction.@NonNull Mutation> mutations){
  StoreTemporalCondition condition=StoreTimeAccess.get().fromObservation(time,time.getObservedAt(),null);
  return OAuthStoreTransaction.fromConditions(OAuthStoreTransaction.Purpose.TIMED,time.getAdmission(),condition,conditions,mutations);
 }
 private static OAuthStoreTransaction.@NonNull Condition absent(@NonNull OAuthStoreKey key){return OAuthStoreTransaction.Condition.fromAbsent(key);}
 private static OAuthStoreTransaction.@NonNull Condition present(@NonNull OAuthStoreKey key,int version){return OAuthStoreTransaction.Condition.fromVersion(key,nonce(version));}
 private static OAuthStoreTransaction.@NonNull Mutation put(@NonNull OAuthStoreEntry entry){return OAuthStoreTransaction.Mutation.fromPut(entry);}
 private static @NonNull OAuthStoreEntry entry(@NonNull OAuthStoreKey key,int version){
  return OAuthStoreEntry.fromStoredForm(key,nonce(version),
    key.getKind()==OAuthStoreKey.Kind.ISSUER_STATE||key.getKind()==OAuthStoreKey.Kind.SUBJECT_STATE?OAuthStoreFormat.PERMANENT:NOW.plusSeconds(3600),"opaque");
 }
 private static @NonNull OAuthStoreKey key(OAuthStoreKey.@NonNull Kind kind,int id){return OAuthStoreFormat.key(NS,kind,nonce(id));}
 private static @NonNull String nonce(int value){byte[] bytes=new byte[32];Arrays.fill(bytes,(byte)value);return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
}
