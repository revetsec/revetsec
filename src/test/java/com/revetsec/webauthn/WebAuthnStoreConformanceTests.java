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
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Portable WebAuthn store contract checks; subclasses supply a fresh empty authoritative scope.
 * Durable and nonblocking progress require separate backend-specific controls. */
@javax.annotation.concurrent.NotThreadSafe
public abstract class WebAuthnStoreConformanceTests {
 protected static final @NonNull Duration BUDGET=Duration.ofSeconds(5);
 protected static final @NonNull WebAuthnStoreKey ROOT=WebAuthnStoreKey.forNamespaceClock("conformance", "login.example.com");
 protected static final @NonNull WebAuthnStoreKey FIRST=WebAuthnStoreKey.forCredential("conformance", "login.example.com",new byte[]{1});
 protected static final @NonNull WebAuthnStoreKey SECOND=WebAuthnStoreKey.forCredential("conformance", "login.example.com",new byte[]{2});

 protected abstract @NonNull WebAuthnStore newStore();
 protected abstract @NonNull WebAuthnStore newStoreWithEntryLimit(int maximumEntries);
 protected abstract void advanceAuthorityPast(@NonNull WebAuthnStore store,@NonNull Instant exclusiveEnd)throws Exception;

 @Test void completeReadSetConflictCancelsTheWholeWrite() {
  WebAuthnStore store=initialized();
  WebAuthnStoreSnapshot before=snapshot(store,Set.of(ROOT,FIRST,SECOND));
  assertEquals(Set.of(ROOT,FIRST,SECOND),before.getEntries().keySet());
  assertInstanceOf(WebAuthnStoreEntry.Absent.class,before.getEntry(FIRST));
  assertInstanceOf(WebAuthnStoreEntry.Absent.class,before.getEntry(SECOND));
  WebAuthnStoreWrite proposed=write(before,List.of(
    WebAuthnStoreWrite.Mutation.insert(FIRST,new byte[]{11}),
    WebAuthnStoreWrite.Mutation.insert(SECOND,new byte[]{12})));
  assertEquals(WebAuthnStoreCommitResult.COMMITTED,store.compareAndCommit(write(snapshot(store,Set.of(ROOT,SECOND)),
    List.of(WebAuthnStoreWrite.Mutation.insert(SECOND,new byte[]{22}))),BUDGET).getStatus());
  assertEquals(WebAuthnStoreCommitResult.CONFLICT,store.compareAndCommit(proposed,BUDGET).getStatus());
  WebAuthnStoreSnapshot after=snapshot(store,Set.of(ROOT,FIRST,SECOND));
  assertInstanceOf(WebAuthnStoreEntry.Absent.class,after.getEntry(FIRST));
  assertArrayEquals(new byte[]{22},present(after,SECOND).getSealedBytes());
 }

 @Test void barrierChecksPredicatesWithoutRewritingVersions() {
  WebAuthnStore store=initialized();
  WebAuthnStoreSnapshot empty=snapshot(store,Set.of(ROOT,FIRST));
  assertEquals(WebAuthnStoreCommitResult.COMMITTED,store.compareAndCommit(write(empty,
    List.of(WebAuthnStoreWrite.Mutation.insert(FIRST,new byte[]{31}))),BUDGET).getStatus());
  WebAuthnStoreSnapshot before=snapshot(store,Set.of(ROOT,FIRST));
  byte[] rootVersion=present(before,ROOT).getVersion(),firstVersion=present(before,FIRST).getVersion();
  WebAuthnStoreCommitReceipt receipt=store.compareAndCommit(write(before,List.of()),BUDGET);
  assertEquals(WebAuthnStoreCommitResult.COMMITTED,receipt.getStatus());
  assertTrue(receipt.getTiming().isPresent());
  WebAuthnStoreSnapshot after=snapshot(store,Set.of(ROOT,FIRST));
  assertArrayEquals(rootVersion,present(after,ROOT).getVersion());
  assertArrayEquals(firstVersion,present(after,FIRST).getVersion());
  assertArrayEquals(new byte[]{31},present(after,FIRST).getSealedBytes());
 }

 @Test void futureFloorAndEmptyBudgetRefuseWithoutAnyWrite() {
  WebAuthnStore store=initialized();
  WebAuthnStoreSnapshot before=snapshot(store,Set.of(ROOT,FIRST));
  StoreTimeObservation.Healthy observed=assertInstanceOf(StoreTimeObservation.Healthy.class,before.getTimeObservation());
  StoreTemporalCondition future=StoreTimeAccess.get().fromObservation(observed,observed.getObservedAt().plusSeconds(3600),null);
  WebAuthnStoreWrite tooEarly=WebAuthnStoreWrite.fromSnapshotAndMutations(before,
    List.of(WebAuthnStoreWrite.Mutation.insert(FIRST,new byte[]{41})),future);
  assertEquals(WebAuthnStoreCommitResult.TIME_BEFORE_FLOOR,store.compareAndCommit(tooEarly,BUDGET).getStatus());
  assertEquals(WebAuthnStoreCommitResult.UNAVAILABLE,store.compareAndCommit(write(before,
    List.of(WebAuthnStoreWrite.Mutation.insert(FIRST,new byte[]{42}))),Duration.ZERO).getStatus());
  assertInstanceOf(WebAuthnStoreReadResult.Unavailable.class,store.read(Set.of(ROOT),Duration.ZERO));
  assertInstanceOf(WebAuthnStoreEntry.Absent.class,snapshot(store,Set.of(FIRST)).getEntry(FIRST));
 }

 @Test void expiredExclusiveWindowRefusesWithoutMutation() throws Exception {
  WebAuthnStore store=initialized();
  WebAuthnStoreSnapshot before=snapshot(store,Set.of(ROOT,FIRST));
  StoreTimeObservation.Healthy observed=assertInstanceOf(StoreTimeObservation.Healthy.class,before.getTimeObservation());
  StoreTemporalCondition expired=StoreTimeAccess.get().fromObservation(observed,
    observed.getObservedAt(),observed.getObservedAt().plusNanos(1));
  WebAuthnStoreWrite attempted=WebAuthnStoreWrite.fromSnapshotAndMutations(before,
    List.of(WebAuthnStoreWrite.Mutation.insert(FIRST,new byte[]{43})),expired);
  advanceAuthorityPast(store,observed.getObservedAt().plusNanos(1));
  assertEquals(WebAuthnStoreCommitResult.TIME_EXPIRED,store.compareAndCommit(attempted,BUDGET).getStatus());
  assertInstanceOf(WebAuthnStoreEntry.Absent.class,snapshot(store,Set.of(FIRST)).getEntry(FIRST));
 }

 @Test void capacityRefusalPreservesTheNamespaceRoot() {
  WebAuthnStore store=newStoreWithEntryLimit(1);
  assertEquals(WebAuthnStoreCommitResult.COMMITTED,store.compareAndCommit(write(snapshot(store,Set.of(ROOT)),
    List.of(WebAuthnStoreWrite.Mutation.insert(ROOT,new byte[]{1}))),BUDGET).getStatus());
  WebAuthnStoreSnapshot before=snapshot(store,Set.of(ROOT,FIRST));
  assertEquals(WebAuthnStoreCommitResult.CAPACITY,store.compareAndCommit(write(before,
    List.of(WebAuthnStoreWrite.Mutation.insert(FIRST,new byte[]{44}))),BUDGET).getStatus());
  WebAuthnStoreSnapshot after=snapshot(store,Set.of(ROOT,FIRST));
  assertArrayEquals(present(before,ROOT).getVersion(),present(after,ROOT).getVersion());
  assertInstanceOf(WebAuthnStoreEntry.Absent.class,after.getEntry(FIRST));
 }

 @Test void sameAbsenceHasOneWinnerAndReplacementChangesVersion() throws Exception {
  WebAuthnStore store=initialized();
  WebAuthnStoreSnapshot before=snapshot(store,Set.of(ROOT,FIRST));
  WebAuthnStoreWrite one=write(before,List.of(WebAuthnStoreWrite.Mutation.insert(FIRST,new byte[]{51})));
  WebAuthnStoreWrite two=write(before,List.of(WebAuthnStoreWrite.Mutation.insert(FIRST,new byte[]{52})));
  CountDownLatch start=new CountDownLatch(1);
  var workers=Executors.newFixedThreadPool(2);
  try {
   var first=workers.submit(()->{start.await();return store.compareAndCommit(one,BUDGET).getStatus();});
   var second=workers.submit(()->{start.await();return store.compareAndCommit(two,BUDGET).getStatus();});
   start.countDown();
   List<WebAuthnStoreCommitResult> results=List.of(first.get(8,TimeUnit.SECONDS),second.get(8,TimeUnit.SECONDS));
   assertEquals(1,results.stream().filter(value->value==WebAuthnStoreCommitResult.COMMITTED).count());
   assertEquals(1,results.stream().filter(value->value==WebAuthnStoreCommitResult.CONFLICT).count());
  } finally {workers.shutdownNow();assertTrue(workers.awaitTermination(3,TimeUnit.SECONDS));}
  WebAuthnStoreSnapshot current=snapshot(store,Set.of(ROOT,FIRST));byte[] old=present(current,FIRST).getVersion();
  assertEquals(WebAuthnStoreCommitResult.COMMITTED,store.compareAndCommit(write(current,
    List.of(WebAuthnStoreWrite.Mutation.replace(FIRST,new byte[]{53}))),BUDGET).getStatus());
  WebAuthnStoreSnapshot after=snapshot(store,Set.of(FIRST));
  assertFalse(Arrays.equals(old,present(after,FIRST).getVersion()));
  assertArrayEquals(new byte[]{53},present(after,FIRST).getSealedBytes());
 }

 private @NonNull WebAuthnStore initialized(){
  WebAuthnStore store=newStore();
  assertEquals(WebAuthnStoreCommitResult.COMMITTED,store.compareAndCommit(write(snapshot(store,Set.of(ROOT)),
    List.of(WebAuthnStoreWrite.Mutation.insert(ROOT,new byte[]{1}))),BUDGET).getStatus());
  return store;
 }
 protected static @NonNull WebAuthnStoreSnapshot snapshot(@NonNull WebAuthnStore store,@NonNull Set<@NonNull WebAuthnStoreKey> keys){
  return assertInstanceOf(WebAuthnStoreReadResult.Available.class,store.read(keys,BUDGET)).getSnapshot();
 }
 protected static WebAuthnStoreEntry.@NonNull Present present(@NonNull WebAuthnStoreSnapshot snapshot,@NonNull WebAuthnStoreKey key){
  return assertInstanceOf(WebAuthnStoreEntry.Present.class,snapshot.getEntry(key));
 }
 protected static @NonNull WebAuthnStoreWrite write(@NonNull WebAuthnStoreSnapshot snapshot,@NonNull List<WebAuthnStoreWrite.@NonNull Mutation> mutations){
  StoreTimeObservation.Healthy observed=assertInstanceOf(StoreTimeObservation.Healthy.class,snapshot.getTimeObservation());
  return WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot,mutations,
    StoreTimeAccess.get().fromObservation(observed,observed.getObservedAt(),null));
 }
}
