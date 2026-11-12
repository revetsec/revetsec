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
package com.revetsec.webauthn;

import com.revetsec.StoreTemporalCondition;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.StoreTimeAccess;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Additional store checks for an independent, explicitly controlled authority profile. */
@javax.annotation.concurrent.NotThreadSafe
public abstract class WebAuthnControlledStoreConformanceTests extends WebAuthnStoreConformanceTests {
 protected abstract void setAuthorityTime(@NonNull WebAuthnStore store,@NonNull Instant time);
 protected abstract void setAuthorityHealthy(@NonNull WebAuthnStore store,boolean healthy);
 protected abstract void rotateClockGeneration(@NonNull WebAuthnStore store);
 protected abstract void rotateRecoveryGeneration(@NonNull WebAuthnStore store);

 @Test void lowerInclusiveAndUpperExclusiveAtExactNanosecondBoundaries(){
  WebAuthnStore store=initialized();
  WebAuthnStoreSnapshot before=snapshot(store,Set.of(ROOT));
  StoreTimeObservation.Healthy observed=healthy(before);
  Instant lower=observed.getObservedAt().plusNanos(1),upper=lower.plusNanos(2);
  StoreTemporalCondition window=StoreTimeAccess.get().fromObservation(observed,lower,upper);
  WebAuthnStoreWrite barrier=WebAuthnStoreWrite.fromSnapshotAndMutations(before,List.of(),window);
  assertEquals(WebAuthnStoreCommitResult.TIME_BEFORE_FLOOR,store.compareAndCommit(barrier,BUDGET).getStatus());
  setAuthorityTime(store,lower);
  assertEquals(WebAuthnStoreCommitResult.COMMITTED,store.compareAndCommit(barrier,BUDGET).getStatus());
  setAuthorityTime(store,upper.minusNanos(1));
  assertEquals(WebAuthnStoreCommitResult.COMMITTED,store.compareAndCommit(barrier,BUDGET).getStatus());
  setAuthorityTime(store,upper);
  assertEquals(WebAuthnStoreCommitResult.TIME_EXPIRED,store.compareAndCommit(barrier,BUDGET).getStatus());
  setAuthorityTime(store,upper.plusNanos(1));
  assertEquals(WebAuthnStoreCommitResult.TIME_EXPIRED,store.compareAndCommit(barrier,BUDGET).getStatus());
  assertArrayEquals(present(before,ROOT).getVersion(),present(snapshot(store,Set.of(ROOT)),ROOT).getVersion());
 }

 @Test void utcOutageKeepsFactsReadableButRefusesTimedMutation(){
  WebAuthnStore store=initialized();
  WebAuthnStoreSnapshot before=snapshot(store,Set.of(ROOT,FIRST));
  WebAuthnStoreWrite attempted=write(before,List.of(WebAuthnStoreWrite.Mutation.insert(FIRST,new byte[]{7})));
  setAuthorityHealthy(store,false);
  WebAuthnStoreSnapshot unavailable=snapshot(store,Set.of(ROOT,FIRST));
  assertInstanceOf(StoreTimeObservation.Unavailable.class,unavailable.getTimeObservation());
  assertArrayEquals(present(before,ROOT).getVersion(),present(unavailable,ROOT).getVersion());
  assertInstanceOf(WebAuthnStoreEntry.Absent.class,unavailable.getEntry(FIRST));
  assertEquals(WebAuthnStoreCommitResult.TIME_UNAVAILABLE,store.compareAndCommit(attempted,BUDGET).getStatus());
  setAuthorityHealthy(store,true);
  assertEquals(WebAuthnStoreCommitResult.COMMITTED,store.compareAndCommit(attempted,BUDGET).getStatus());
  assertArrayEquals(new byte[]{7},present(snapshot(store,Set.of(ROOT,FIRST)),FIRST).getSealedBytes());
 }

 @Test void clockAndRecoveryGenerationChangesFenceOldPreparedWrites(){
  for(boolean recovery:List.of(false,true)){
   WebAuthnStore store=initialized();
   WebAuthnStoreSnapshot before=snapshot(store,Set.of(ROOT,FIRST));
   WebAuthnStoreWrite stale=write(before,List.of(WebAuthnStoreWrite.Mutation.insert(FIRST,new byte[]{8})));
   if(recovery)rotateRecoveryGeneration(store);else rotateClockGeneration(store);
   assertEquals(WebAuthnStoreCommitResult.FENCED,store.compareAndCommit(stale,BUDGET).getStatus());
   assertInstanceOf(WebAuthnStoreEntry.Absent.class,snapshot(store,Set.of(ROOT,FIRST)).getEntry(FIRST));
   WebAuthnStoreSnapshot fresh=snapshot(store,Set.of(ROOT,FIRST));
   assertEquals(WebAuthnStoreCommitResult.COMMITTED,store.compareAndCommit(write(fresh,
     List.of(WebAuthnStoreWrite.Mutation.insert(FIRST,new byte[]{8}))),BUDGET).getStatus());
  }
 }

 private @NonNull WebAuthnStore initialized(){
  WebAuthnStore store=newStore();
  assertEquals(WebAuthnStoreCommitResult.COMMITTED,store.compareAndCommit(write(snapshot(store,Set.of(ROOT)),
    List.of(WebAuthnStoreWrite.Mutation.insert(ROOT,new byte[]{1}))),BUDGET).getStatus());
  return store;
 }
 private static StoreTimeObservation.@NonNull Healthy healthy(@NonNull WebAuthnStoreSnapshot snapshot){
  return assertInstanceOf(StoreTimeObservation.Healthy.class,snapshot.getTimeObservation());
 }
}
