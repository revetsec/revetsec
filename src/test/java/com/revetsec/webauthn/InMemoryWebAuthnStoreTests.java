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

import com.revetsec.StoreAdmission;
import com.revetsec.StoreTemporalCondition;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.StoreTimeAccess;
import java.time.Duration;
import java.time.Instant;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import org.jspecify.annotations.Nullable;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class InMemoryWebAuthnStoreTests {
 private static final Duration BUDGET = Duration.ofSeconds(3);
 private static final WebAuthnStoreKey FIRST = WebAuthnStoreKey.forCredential(
   "tenant", "login.example.com", new byte[] {1});
 private static final WebAuthnStoreKey SECOND = WebAuthnStoreKey.forCredential(
   "tenant", "login.example.com", new byte[] {2});
 private static final WebAuthnStoreKey CEREMONY = WebAuthnStoreKey.forCeremony(
   "tenant", "login.example.com", new byte[32]);

 @Test void expiredCeremoniesRemainRetainedThroughQueriesBarriersAndCapacityRefusal() {
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.fromLimits(1, 100);
  WebAuthnStoreSnapshot empty = snapshot(store, Set.of(CEREMONY));
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(
    write(empty, List.of(WebAuthnStoreWrite.Mutation.insertExpiring(CEREMONY, new byte[] {1}, Instant.EPOCH))), BUDGET).getStatus());
  WebAuthnStoreSnapshot before = snapshot(store, Set.of(CEREMONY, FIRST));
  byte[] version = present(before, CEREMONY).getVersion();
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(write(before, List.of()), BUDGET).getStatus());
  assertEquals(WebAuthnStoreCommitResult.CAPACITY, store.compareAndCommit(write(before,
    List.of(WebAuthnStoreWrite.Mutation.insert(FIRST, new byte[] {2}))), BUDGET).getStatus());
  WebAuthnStoreSnapshot after = snapshot(store, Set.of(CEREMONY, FIRST));
  assertArrayEquals(version, present(after, CEREMONY).getVersion());
  assertArrayEquals(new byte[] {1}, present(after, CEREMONY).getSealedBytes());
  assertInstanceOf(WebAuthnStoreEntry.Absent.class, after.getEntry(FIRST));
 }

 @Test void repeatedCeremonyReplacementRemainsWithinTheDeclaredRecordCapacity() {
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.fromLimits(1, 1);
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(
    write(snapshot(store, Set.of(CEREMONY)), List.of(
      WebAuthnStoreWrite.Mutation.insertExpiring(CEREMONY, new byte[] {1}, Instant.EPOCH))), BUDGET).getStatus());
  for (int index = 0; index < 1000; index++) {
   assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(
     write(snapshot(store, Set.of(CEREMONY)), List.of(
       WebAuthnStoreWrite.Mutation.replaceExpiring(CEREMONY, new byte[] {(byte) index}, Instant.EPOCH))), BUDGET).getStatus());
  }
  assertArrayEquals(new byte[] {(byte) 999}, present(snapshot(store, Set.of(CEREMONY)), CEREMONY).getSealedBytes());
 }

 @Test void capacityRejectsWholeWriteAndNeverEvictsRecords() {
  assertThrows(IllegalArgumentException.class, () -> InMemoryWebAuthnStore.fromLimits(0, 10));
  assertThrows(IllegalArgumentException.class, () -> InMemoryWebAuthnStore.fromLimits(1, 0));
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.fromLimits(1, 3);
  WebAuthnStoreSnapshot empty = snapshot(store, Set.of(FIRST, SECOND));
  WebAuthnStoreWrite both = write(empty, List.of(
    WebAuthnStoreWrite.Mutation.insert(FIRST, new byte[] {1}),
    WebAuthnStoreWrite.Mutation.insert(SECOND, new byte[] {2})));
  assertEquals(WebAuthnStoreCommitResult.CAPACITY, store.compareAndCommit(both, BUDGET).getStatus());
  assertTrue(snapshot(store, Set.of(FIRST, SECOND)).getEntry(FIRST) instanceof WebAuthnStoreEntry.Absent);
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(
    write(empty,
      List.of(WebAuthnStoreWrite.Mutation.insert(FIRST, new byte[] {1, 2, 3}))), BUDGET).getStatus());
  WebAuthnStoreSnapshot full = snapshot(store, Set.of(FIRST, SECOND));
  assertEquals(WebAuthnStoreCommitResult.CAPACITY, store.compareAndCommit(
    write(full,
      List.of(WebAuthnStoreWrite.Mutation.insert(SECOND, new byte[] {4}))), BUDGET).getStatus());
  assertEquals(WebAuthnStoreCommitResult.CAPACITY, store.compareAndCommit(
    write(full,
      List.of(WebAuthnStoreWrite.Mutation.replace(FIRST, new byte[] {1, 2, 3, 4}))), BUDGET).getStatus());
  assertArrayEquals(new byte[] {1, 2, 3}, present(snapshot(store, Set.of(FIRST)), FIRST).getSealedBytes());
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(
    write(full, List.of(
      WebAuthnStoreWrite.Mutation.delete(FIRST),
      WebAuthnStoreWrite.Mutation.insert(SECOND, new byte[] {5, 6}))), BUDGET).getStatus());
  assertTrue(snapshot(store, Set.of(FIRST)).getEntry(FIRST) instanceof WebAuthnStoreEntry.Absent);
  assertArrayEquals(new byte[] {5, 6}, present(snapshot(store, Set.of(SECOND)), SECOND).getSealedBytes());
 }

 @Test void compareAllPredicatesAndRenewVersionsAcrossDeleteAndReinsert() {
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.fromLimits(2, 100);
  WebAuthnStoreSnapshot empty = snapshot(store, Set.of(FIRST, SECOND));
  WebAuthnStoreWrite insert = write(empty,
    List.of(WebAuthnStoreWrite.Mutation.insert(FIRST, new byte[] {7})));
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(insert, BUDGET).getStatus());
  assertEquals(WebAuthnStoreCommitResult.CONFLICT, store.compareAndCommit(insert, BUDGET).getStatus());
  WebAuthnStoreSnapshot first = snapshot(store, Set.of(FIRST, SECOND));
  byte[] oldVersion = present(first, FIRST).getVersion();
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(
    write(first,
      List.of(WebAuthnStoreWrite.Mutation.replace(FIRST, new byte[] {8}))), BUDGET).getStatus());
  assertEquals(WebAuthnStoreCommitResult.CONFLICT, store.compareAndCommit(
    write(first, List.of()), BUDGET).getStatus());
  WebAuthnStoreSnapshot second = snapshot(store, Set.of(FIRST, SECOND));
  assertNotEquals(java.util.Arrays.toString(oldVersion),
    java.util.Arrays.toString(present(second, FIRST).getVersion()));
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(
    write(second,
      List.of(WebAuthnStoreWrite.Mutation.delete(FIRST))), BUDGET).getStatus());
  WebAuthnStoreSnapshot absent = snapshot(store, Set.of(FIRST));
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(
    write(absent,
      List.of(WebAuthnStoreWrite.Mutation.insert(FIRST, new byte[] {9}))), BUDGET).getStatus());
  assertNotEquals(java.util.Arrays.toString(oldVersion),
    java.util.Arrays.toString(present(snapshot(store, Set.of(FIRST)), FIRST).getVersion()));
  assertEquals(WebAuthnStoreCommitResult.CONFLICT, store.compareAndCommit(
    write(second, List.of()), BUDGET).getStatus());
 }

 @Test void concurrentWritersHaveExactlyOneWinnerAndBudgetOrInterruptNeverMutates() throws Exception {
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.fromLimits(1, 100);
  WebAuthnStoreSnapshot empty = snapshot(store, Set.of(FIRST));
  WebAuthnStoreWrite insert = write(empty,
    List.of(WebAuthnStoreWrite.Mutation.insert(FIRST, new byte[] {1})));
  CountDownLatch start = new CountDownLatch(1);
  ExecutorService workers = Executors.newFixedThreadPool(2);
  try {
   Future<WebAuthnStoreCommitResult> one = workers.submit(() -> {
    start.await(); return store.compareAndCommit(insert, BUDGET).getStatus();
   });
   Future<WebAuthnStoreCommitResult> two = workers.submit(() -> {
    start.await(); return store.compareAndCommit(insert, BUDGET).getStatus();
   });
   start.countDown();
   assertEquals(Set.of(WebAuthnStoreCommitResult.COMMITTED, WebAuthnStoreCommitResult.CONFLICT),
     Set.of(one.get(), two.get()));
  } finally {
   workers.shutdownNow();
  }
  WebAuthnStoreSnapshot current = snapshot(store, Set.of(FIRST));
  WebAuthnStoreWrite replace = write(current,
    List.of(WebAuthnStoreWrite.Mutation.replace(FIRST, new byte[] {2})));
  assertEquals(WebAuthnStoreCommitResult.UNAVAILABLE,
    store.compareAndCommit(replace, Duration.ZERO).getStatus());
  Thread.currentThread().interrupt();
  try {
   assertEquals(WebAuthnStoreCommitResult.UNAVAILABLE, store.compareAndCommit(replace, BUDGET).getStatus());
   assertInstanceOf(WebAuthnStoreReadResult.Unavailable.class, store.read(Set.of(FIRST), BUDGET));
   assertTrue(Thread.currentThread().isInterrupted());
  } finally {
   Thread.interrupted();
  }
  assertFalse(Thread.currentThread().isInterrupted());
  assertArrayEquals(new byte[] {1}, present(snapshot(store, Set.of(FIRST)), FIRST).getSealedBytes());
  assertFalse(store.toString().contains(FIRST.getStorageKey()));
 }

 private static @NonNull WebAuthnStoreSnapshot snapshot(@NonNull WebAuthnStore store,
   @NonNull Set<@NonNull WebAuthnStoreKey> keys) {
  return assertInstanceOf(WebAuthnStoreReadResult.Available.class,
    store.read(keys, BUDGET)).getSnapshot();
 }

 private static WebAuthnStoreEntry.@NonNull Present present(@NonNull WebAuthnStoreSnapshot snapshot,
   @NonNull WebAuthnStoreKey key) {
  return assertInstanceOf(WebAuthnStoreEntry.Present.class, snapshot.getEntry(key));
 }

 @Test void constructionAndNonpositiveOrInvalidCallsDoNotAcquireTimeOrRandomness() throws Exception {
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.fromLimits(4, 100);
  assertNull(field(store, "admission")); assertNull(field(store, "authorityAnchor")); assertNull(field(store, "entropy")); assertNull(field(store, "versionPrefix"));
  assertThrows(IllegalArgumentException.class, () -> store.read(Set.of(), BUDGET));
  assertInstanceOf(WebAuthnStoreReadResult.Unavailable.class, store.read(Set.of(FIRST), Duration.ZERO));
  assertNull(field(store, "admission")); assertNull(field(store, "authorityAnchor")); assertNull(field(store, "entropy"));
 }

 @Test void scopedReadsHaveOneOwnedMonotoneProjectionAndRejectMixedScope() {
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.fromLimits(4, 100);
  WebAuthnStoreKey other = WebAuthnStoreKey.forCredential("other", "other.example.com", new byte[] {3});
  assertThrows(IllegalArgumentException.class, () -> store.read(Set.of(FIRST, other), BUDGET));
  StoreTimeObservation.Healthy first = healthy(snapshot(store, Set.of(FIRST)));
  StoreTimeObservation.Healthy second = healthy(snapshot(store, Set.of(other)));
  assertEquals(first.getAdmission().getAuthorityId(), second.getAdmission().getAuthorityId());
  assertEquals(first.getAdmission().getRecoveryGeneration(), second.getAdmission().getRecoveryGeneration());
  assertEquals(first.getClockGeneration(), second.getClockGeneration()); assertFalse(second.getObservedAt().isBefore(first.getObservedAt()));
 }

 @Test void currentAuthorityRecoveryClockAndFixedErrorProfileAreComparedBeforeMutation() {
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.fromLimits(1, 100);
  WebAuthnStoreSnapshot snapshot = snapshot(store, Set.of(FIRST)); StoreTimeObservation.Healthy time = healthy(snapshot);
  String foreign = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
  // The literal ID is legal synthetic external metadata, not a backend-issued capability.
  for (StoreTimeObservation.Healthy changed : List.of(
    StoreTimeObservation.Healthy.fromObservation(StoreAdmission.fromIdentifiers(foreign, time.getAdmission().getRecoveryGeneration()), time.getClockGeneration(), time.getObservedAt(), time.getMaximumUtcError()),
    StoreTimeObservation.Healthy.fromObservation(StoreAdmission.fromIdentifiers(time.getAdmission().getAuthorityId(), foreign), time.getClockGeneration(), time.getObservedAt(), time.getMaximumUtcError()),
    StoreTimeObservation.Healthy.fromObservation(time.getAdmission(), foreign, time.getObservedAt(), time.getMaximumUtcError()),
    StoreTimeObservation.Healthy.fromObservation(time.getAdmission(), time.getClockGeneration(), time.getObservedAt(), Duration.ZERO))) {
   WebAuthnStoreSnapshot altered = WebAuthnStoreSnapshot.fromEntries(Set.of(FIRST), snapshot.getEntries(), changed);
   assertEquals(WebAuthnStoreCommitResult.FENCED, store.compareAndCommit(write(altered,
     List.of(WebAuthnStoreWrite.Mutation.insert(FIRST, new byte[] {1}))), BUDGET).getStatus());
   assertInstanceOf(WebAuthnStoreEntry.Absent.class, snapshot(store, Set.of(FIRST)).getEntry(FIRST));
  }
 }

 @Test void floorAndOriginalExpiryUseFreshTimeAfterTheActualStoreLockWait() throws Exception {
  InMemoryWebAuthnStore store=InMemoryWebAuthnStore.fromLimits(1,100);WebAuthnStoreSnapshot before=snapshot(store,Set.of(FIRST));StoreTimeObservation.Healthy time=healthy(before);List<WebAuthnStoreWrite.Mutation> insertion=List.of(WebAuthnStoreWrite.Mutation.insert(FIRST,new byte[]{1}));StoreTemporalCondition future=StoreTimeAccess.get().fromObservation(time,time.getObservedAt().plusSeconds(3600),null);assertEquals(WebAuthnStoreCommitResult.TIME_BEFORE_FLOOR,store.compareAndCommit(WebAuthnStoreWrite.fromSnapshotAndMutations(before,insertion,future),BUDGET).getStatus());before=snapshot(store,Set.of(FIRST));time=healthy(before);Instant upper=time.getObservedAt().plusMillis(500);WebAuthnStoreWrite write=WebAuthnStoreWrite.fromSnapshotAndMutations(before,insertion,StoreTimeAccess.get().fromObservation(time,time.getObservedAt(),upper));Object entries=field(store,"entries"),sequence=field(store,"sequence"),bytes=field(store,"sealedBytes"),prefix=field(store,"versionPrefix");ReentrantLock lock=(ReentrantLock)Objects.requireNonNull(field(store,"lock"));ExecutorService executor=Executors.newSingleThreadExecutor();CountDownLatch entered=new CountDownLatch(1);List<String> trace=new java.util.concurrent.CopyOnWriteArrayList<>();Future<WebAuthnStoreCommitReceipt> waiting;
  try{lock.lock();try{
   trace.add("snapshot-before-E");waiting=executor.submit(()->{trace.add("commit-call");entered.countDown();WebAuthnStoreCommitReceipt receipt=store.compareAndCommit(write,BUDGET);trace.add("callback-returned");return receipt;});assertTrue(entered.await(2,TimeUnit.SECONDS));long queued=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);while(!lock.hasQueuedThreads()&&System.nanoTime()<queued)Thread.yield();assertTrue(lock.hasQueuedThreads());assertFalse(waiting.isDone());trace.add("queued-under-lock");StoreTimeObservation.Healthy current=healthy(snapshot(store,Set.of(FIRST)));assertTrue(current.getObservedAt().isBefore(upper),"Queued call must begin before E");long limit=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);while(current.getObservedAt().isBefore(upper)){assertTrue(System.nanoTime()<limit);assertFalse(waiting.isDone());Thread.sleep(1);current=healthy(snapshot(store,Set.of(FIRST)));}trace.add("reached-E-under-lock");assertFalse(waiting.isDone());trace.add("releasing-lock");
  }finally{lock.unlock();}
  WebAuthnStoreCommitReceipt receipt=waiting.get(5,TimeUnit.SECONDS);assertEquals(WebAuthnStoreCommitResult.TIME_EXPIRED,receipt.getStatus());assertTrue(receipt.getTiming().isEmpty());assertEquals(List.of("snapshot-before-E","commit-call","queued-under-lock","reached-E-under-lock","releasing-lock","callback-returned"),trace);assertInstanceOf(WebAuthnStoreEntry.Absent.class,snapshot(store,Set.of(FIRST)).getEntry(FIRST));assertSame(entries,field(store,"entries"));assertEquals(sequence,field(store,"sequence"));assertEquals(bytes,field(store,"sealedBytes"));assertSame(prefix,field(store,"versionPrefix"));
  }finally{executor.shutdownNow();assertTrue(executor.awaitTermination(5,TimeUnit.SECONDS));}
 }

 @Test void authorityContinuityLossPreservesRowsAndRefusesEvenAnEmptyTimedBarrier() throws Exception {
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.fromLimits(1, 100);
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(write(snapshot(store, Set.of(CEREMONY)),
    List.of(WebAuthnStoreWrite.Mutation.insertExpiring(CEREMONY, new byte[] {1}, Instant.EPOCH))), BUDGET).getStatus());
  WebAuthnStoreSnapshot before = snapshot(store, Set.of(CEREMONY)); byte[] version = present(before, CEREMONY).getVersion();
  Field lost = InMemoryWebAuthnStore.class.getDeclaredField("authorityContinuityLost"); lost.setAccessible(true); lost.setBoolean(store, true);
  WebAuthnStoreSnapshot unavailable = snapshot(store, Set.of(CEREMONY));
  assertInstanceOf(StoreTimeObservation.Unavailable.class, unavailable.getTimeObservation());
  assertArrayEquals(version, present(unavailable, CEREMONY).getVersion());
  assertEquals(WebAuthnStoreCommitResult.TIME_UNAVAILABLE, store.compareAndCommit(write(before, List.of()), BUDGET).getStatus());
  assertArrayEquals(version, present(snapshot(store, Set.of(CEREMONY)), CEREMONY).getVersion());
 }

 @Test void timedBarrierHasRequiredReceiptButTouchesNoDataCountersOrBackingMap() throws Exception {
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.fromLimits(2, 100);
  WebAuthnStoreKey root = WebAuthnStoreKey.forNamespaceClock("tenant", "login.example.com");
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(write(snapshot(store, Set.of(root)),
    List.of(WebAuthnStoreWrite.Mutation.insert(root, new byte[] {1}))), BUDGET).getStatus());
  WebAuthnStoreSnapshot before = snapshot(store, Set.of(root)); byte[] version = present(before, root).getVersion();
  Object entries = field(store, "entries"), prefix = field(store, "versionPrefix"), scopes = field(store, "activatedScopes");
  Object sequence = field(store, "sequence"), bytes = field(store, "sealedBytes");
  WebAuthnStoreCommitReceipt receipt = store.compareAndCommit(write(before, List.of()), BUDGET);
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, receipt.getStatus()); assertTrue(receipt.getTiming().orElseThrow().getCompletedTime().isEmpty());
  assertFalse(receipt.getTiming().orElseThrow().getValidatedTime().getObservedAt().isBefore(healthy(before).getObservedAt()));
  assertSame(entries, field(store, "entries")); assertSame(prefix, field(store, "versionPrefix")); assertSame(scopes, field(store, "activatedScopes"));
  assertEquals(sequence, field(store, "sequence")); assertEquals(bytes, field(store, "sealedBytes"));
  assertArrayEquals(version, present(snapshot(store, Set.of(root)), root).getVersion());
 }

 @Test void knownRootLossCannotBecomeConfirmedAbsenceOrAutomaticReinitialization() {
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.fromLimits(2, 100);
  WebAuthnStoreKey root = WebAuthnStoreKey.forNamespaceClock("tenant", "login.example.com");
  WebAuthnStoreSnapshot empty = snapshot(store, Set.of(root));
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(write(empty,
    List.of(WebAuthnStoreWrite.Mutation.insert(root, new byte[] {1}))), BUDGET).getStatus());
  WebAuthnStoreSnapshot established = snapshot(store, Set.of(root));
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(write(established,
    List.of(WebAuthnStoreWrite.Mutation.delete(root))), BUDGET).getStatus());
  assertInstanceOf(WebAuthnStoreReadResult.Unavailable.class, store.read(Set.of(root), BUDGET));
  WebAuthnStoreSnapshot forgedAbsent = WebAuthnStoreSnapshot.fromEntries(Set.of(root), Map.of(root, WebAuthnStoreEntry.Absent.confirmed()), established.getTimeObservation());
  assertEquals(WebAuthnStoreCommitResult.UNAVAILABLE, store.compareAndCommit(write(forgedAbsent,
    List.of(WebAuthnStoreWrite.Mutation.insert(root, new byte[] {2}))), BUDGET).getStatus());
 }

 @Test void preexistingOrphanedScopeCannotAcquireAnInventedStableMinimum() {
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.fromLimits(2, 100);
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(write(snapshot(store, Set.of(FIRST)),
    List.of(WebAuthnStoreWrite.Mutation.insert(FIRST, new byte[] {1}))), BUDGET).getStatus());
  assertInstanceOf(WebAuthnStoreReadResult.Unavailable.class, store.read(Set.of(WebAuthnStoreKey.forNamespaceClock("tenant", "login.example.com")), BUDGET));
  WebAuthnStoreKey freshScopeRoot = WebAuthnStoreKey.forNamespaceClock("fresh", "other.example.com");
  assertInstanceOf(WebAuthnStoreEntry.Absent.class, snapshot(store, Set.of(freshScopeRoot)).getEntry(freshScopeRoot));
 }

 private static @Nullable Object field(@NonNull InMemoryWebAuthnStore store, @NonNull String name) throws Exception {
  Field field = InMemoryWebAuthnStore.class.getDeclaredField(name); field.setAccessible(true); return field.get(store);
 }
 private static StoreTimeObservation.@NonNull Healthy healthy(@NonNull WebAuthnStoreSnapshot snapshot) {
  return assertInstanceOf(StoreTimeObservation.Healthy.class, snapshot.getTimeObservation());
 }

 private static @NonNull WebAuthnStoreWrite write(@NonNull WebAuthnStoreSnapshot snapshot,
   @NonNull List<WebAuthnStoreWrite.@NonNull Mutation> changes) {
  StoreTimeObservation.Healthy time = (StoreTimeObservation.Healthy) snapshot.getTimeObservation();
  return WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot, changes,
    StoreTimeAccess.get().fromObservation(time, time.getObservedAt(), null));
 }


 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi06BelowFloorWaitUsesValidationAfterTheActualLock(){
  List<org.junit.jupiter.api.DynamicTest> cases=new java.util.ArrayList<>();for(boolean mutate:List.of(false,true))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-06/WEBAUTHN/below-N-to-valid/mutation="+mutate,()->{
   InMemoryWebAuthnStore store=InMemoryWebAuthnStore.fromLimits(2,100);WebAuthnStoreSnapshot initial=snapshot(store,Set.of(FIRST));StoreTimeObservation.Healthy original=healthy(initial);Instant lower=original.getObservedAt().plusMillis(500),upper=lower.plusSeconds(10);WebAuthnStoreWrite write=WebAuthnStoreWrite.fromSnapshotAndMutations(initial,mutate?List.of(WebAuthnStoreWrite.Mutation.insert(FIRST,new byte[]{1})):List.of(),StoreTimeAccess.get().fromObservation(original,lower,upper));Object entries=field(store,"entries"),sequence=field(store,"sequence"),bytes=field(store,"sealedBytes");ReentrantLock lock=(ReentrantLock)Objects.requireNonNull(field(store,"lock"));List<String> trace=new java.util.concurrent.CopyOnWriteArrayList<>();java.util.concurrent.atomic.AtomicReference<Thread> callback=new java.util.concurrent.atomic.AtomicReference<>();ExecutorService executor=Executors.newSingleThreadExecutor();CountDownLatch entered=new CountDownLatch(1);Future<WebAuthnStoreCommitReceipt> waiting;Instant heldSample;
   try{lock.lock();try{
    trace.add("snapshot-below-N");assertTrue(original.getObservedAt().isBefore(lower));waiting=executor.submit(()->{callback.set(Thread.currentThread());trace.add("commit-call");entered.countDown();WebAuthnStoreCommitReceipt receipt=store.compareAndCommit(write,BUDGET);trace.add("callback-returned");return receipt;});assertTrue(entered.await(2,TimeUnit.SECONDS));long queuedDeadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);while(!lock.hasQueuedThreads()&&System.nanoTime()<queuedDeadline)Thread.yield();assertTrue(lock.hasQueuedThread(Objects.requireNonNull(callback.get())));assertFalse(waiting.isDone());trace.add("queued-under-lock");StoreTimeObservation.Healthy current=healthy(snapshot(store,Set.of(FIRST)));assertTrue(current.getObservedAt().isBefore(lower),"Queued call must begin before N");long floorDeadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);while(current.getObservedAt().isBefore(lower)){assertTrue(System.nanoTime()<floorDeadline,"Authority did not reach N");assertFalse(waiting.isDone());Thread.sleep(1);current=healthy(snapshot(store,Set.of(FIRST)));}heldSample=current.getObservedAt();trace.add("reached-N-under-lock");assertFalse(waiting.isDone());trace.add("releasing-lock");
   }finally{lock.unlock();}
   WebAuthnStoreCommitReceipt receipt=waiting.get(5,TimeUnit.SECONDS);assertEquals(WebAuthnStoreCommitResult.COMMITTED,receipt.getStatus());var timing=receipt.getTiming().orElseThrow();assertFalse(timing.getValidatedTime().getObservedAt().isBefore(lower));assertFalse(timing.getValidatedTime().getObservedAt().isBefore(heldSample));assertTrue(timing.getValidatedTime().getObservedAt().isBefore(upper));assertEquals(original.getAdmission(),timing.getValidatedTime().getAdmission());assertEquals(original.getClockGeneration(),timing.getValidatedTime().getClockGeneration());assertTrue(timing.getCompletedTime().isEmpty());assertEquals(List.of("snapshot-below-N","commit-call","queued-under-lock","reached-N-under-lock","releasing-lock","callback-returned"),trace);if(mutate)assertArrayEquals(new byte[]{1},present(snapshot(store,Set.of(FIRST)),FIRST).getSealedBytes());else{assertInstanceOf(WebAuthnStoreEntry.Absent.class,snapshot(store,Set.of(FIRST)).getEntry(FIRST));assertSame(entries,field(store,"entries"));assertEquals(sequence,field(store,"sequence"));assertEquals(bytes,field(store,"sealedBytes"));}}
   finally{executor.shutdownNow();assertTrue(executor.awaitTermination(5,TimeUnit.SECONDS));}
  }));return cases;
 }

 @SuppressWarnings("try") // Early close releases waiting writers before joining the executor; repeated close is idempotent.
 @Test void scApi07PostValidationCopyKeepsActualLockUntilVersionsAndAccountingPublish()throws Exception{
  InMemoryWebAuthnStore store=InMemoryWebAuthnStore.fromLimits(5,100);WebAuthnStoreKey root=WebAuthnStoreKey.forNamespaceClock("tenant","login.example.com");WebAuthnStoreSnapshot empty=snapshot(store,Set.of(root,FIRST));assertEquals(WebAuthnStoreCommitResult.COMMITTED,store.compareAndCommit(write(empty,List.of(WebAuthnStoreWrite.Mutation.insert(root,new byte[]{9}),WebAuthnStoreWrite.Mutation.insert(FIRST,new byte[]{1}))),BUDGET).getStatus());WebAuthnStoreSnapshot before=snapshot(store,Set.of(root,FIRST,SECOND));StoreTimeObservation.Healthy observed=healthy(before);WebAuthnStoreWrite primary=write(before,List.of(WebAuthnStoreWrite.Mutation.replace(FIRST,new byte[]{2}),WebAuthnStoreWrite.Mutation.insert(SECOND,new byte[]{3}))),competitor=write(before,List.of(WebAuthnStoreWrite.Mutation.replace(FIRST,new byte[]{4}),WebAuthnStoreWrite.Mutation.insert(SECOND,new byte[]{5})));Object sequence=field(store,"sequence"),bytes=field(store,"sealedBytes"),prefix=field(store,"versionPrefix");ReentrantLock lock=(ReentrantLock)Objects.requireNonNull(field(store,"lock"));List<String> trace=new java.util.concurrent.CopyOnWriteArrayList<>();ExecutorService executor=Executors.newFixedThreadPool(2);java.util.concurrent.atomic.AtomicReference<Thread> rival=new java.util.concurrent.atomic.AtomicReference<>();CountDownLatch called=new CountDownLatch(1);
  try(var pause=com.revetsec.testing.StoreCommitPause.install(store,"entries",trace,lock::isHeldByCurrentThread)){
   try{
    Future<WebAuthnStoreCommitReceipt> one=executor.submit(()->{trace.add("primary-call");pause.selectCurrentWriter();var result=store.compareAndCommit(primary,Duration.ofSeconds(10));trace.add("primary-returned");return result;});assertTrue(pause.awaitEntered());assertTrue(pause.wasProtected(),"Post-validation state apply lost its real lock");assertEquals(InMemoryWebAuthnStore.class.getName(),pause.getCallSite().getClassName());assertEquals("compareAndCommit",pause.getCallSite().getMethodName());assertSame(pause.installedMap(),field(store,"entries"));assertEquals(sequence,field(store,"sequence"));assertEquals(bytes,field(store,"sealedBytes"));assertSame(prefix,field(store,"versionPrefix"));
    Future<WebAuthnStoreCommitReceipt> two=executor.submit(()->{rival.set(Thread.currentThread());trace.add("competitor-call");called.countDown();var result=store.compareAndCommit(competitor,Duration.ofSeconds(10));trace.add("competitor-returned");return result;});assertTrue(called.await(2,TimeUnit.SECONDS));long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);while(!lock.hasQueuedThread(Objects.requireNonNull(rival.get()))&&System.nanoTime()<end&&!two.isDone())Thread.yield();assertTrue(lock.hasQueuedThread(Objects.requireNonNull(rival.get())),"Competing write must queue on the real store lock");assertFalse(two.isDone());trace.add("competitor-queued");pause.resume();WebAuthnStoreCommitReceipt committed=one.get(5,TimeUnit.SECONDS);assertEquals(WebAuthnStoreCommitResult.COMMITTED,committed.getStatus());assertFalse(committed.getTiming().orElseThrow().getValidatedTime().getObservedAt().isBefore(observed.getObservedAt()));assertEquals(observed.getAdmission(),committed.getTiming().orElseThrow().getValidatedTime().getAdmission());assertTrue(committed.getTiming().orElseThrow().getCompletedTime().isEmpty());WebAuthnStoreCommitReceipt rejected=two.get(5,TimeUnit.SECONDS);assertEquals(WebAuthnStoreCommitResult.CONFLICT,rejected.getStatus());assertTrue(rejected.getTiming().isEmpty());WebAuthnStoreSnapshot after=snapshot(store,Set.of(root,FIRST,SECOND));assertArrayEquals(new byte[]{2},present(after,FIRST).getSealedBytes());assertArrayEquals(new byte[]{3},present(after,SECOND).getSealedBytes());assertFalse(java.util.Arrays.equals(present(before,FIRST).getVersion(),present(after,FIRST).getVersion()));assertEquals(((Long)Objects.requireNonNull(sequence))+2,field(store,"sequence"));assertEquals(3L,field(store,"sealedBytes"));assertArrayEquals(present(before,root).getVersion(),present(after,root).getVersion());assertArrayEquals(present(before,root).getSealedBytes(),present(after,root).getSealedBytes());assertSame(prefix,field(store,"versionPrefix"));assertEquals(List.of("primary-call","validated-copy-paused","competitor-call","competitor-queued","release-copy","copy-resumed"),trace.subList(0,6));assertEquals(8,trace.size());
   }finally{pause.close();executor.shutdown();if(!executor.awaitTermination(3,TimeUnit.SECONDS)){executor.shutdownNow();assertTrue(executor.awaitTermination(3,TimeUnit.SECONDS));}}
  }finally{executor.shutdownNow();assertTrue(executor.awaitTermination(3,TimeUnit.SECONDS));}
 }

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi09HealthyReadThenAuthorityLossRefusesMutationAndBarrierWithoutClockFallback(){
  List<org.junit.jupiter.api.DynamicTest> cells=new java.util.ArrayList<>();
  for(boolean mutate:List.of(false,true))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-09/WEBAUTHN/authority-loss-before-validation/mutation="+mutate,()->{
   InMemoryWebAuthnStore store=InMemoryWebAuthnStore.fromLimits(4,100);
   WebAuthnStoreKey root=WebAuthnStoreKey.forNamespaceClock("tenant","login.example.com");
   assertEquals(WebAuthnStoreCommitResult.COMMITTED,store.compareAndCommit(write(snapshot(store,Set.of(root,FIRST)),List.of(WebAuthnStoreWrite.Mutation.insert(root,new byte[]{9}),WebAuthnStoreWrite.Mutation.insert(FIRST,new byte[]{1}))),BUDGET).getStatus());
   WebAuthnStoreSnapshot before=snapshot(store,Set.of(root,FIRST,SECOND));StoreTimeObservation.Healthy original=healthy(before);Instant upper=original.getObservedAt().plusSeconds(30);
   WebAuthnStoreWrite write=WebAuthnStoreWrite.fromSnapshotAndMutations(before,mutate?List.of(WebAuthnStoreWrite.Mutation.replace(FIRST,new byte[]{2}),WebAuthnStoreWrite.Mutation.insert(SECOND,new byte[]{3})):List.of(),StoreTimeAccess.get().fromObservation(original,original.getObservedAt(),upper));
   Object entries=Objects.requireNonNull(field(store,"entries")),prefix=Objects.requireNonNull(field(store,"versionPrefix")),sequence=Objects.requireNonNull(field(store,"sequence")),bytes=Objects.requireNonNull(field(store,"sealedBytes"));
   Field lost=InMemoryWebAuthnStore.class.getDeclaredField("authorityContinuityLost");lost.setAccessible(true);lost.setBoolean(store,true);
   Instant temptingWorker=java.time.Clock.fixed(original.getObservedAt().plusSeconds(1),java.time.ZoneOffset.UTC).instant();assertFalse(temptingWorker.isBefore(original.getObservedAt()));assertTrue(temptingWorker.isBefore(upper));assertTrue(Instant.now().isBefore(upper));
   WebAuthnStoreCommitReceipt refused=store.compareAndCommit(write,BUDGET);assertEquals(WebAuthnStoreCommitResult.TIME_UNAVAILABLE,refused.getStatus(),"An earlier healthy sample cannot replace authority validation");assertTrue(refused.getTiming().isEmpty());
   WebAuthnStoreSnapshot after=snapshot(store,Set.of(root,FIRST,SECOND));assertInstanceOf(StoreTimeObservation.Unavailable.class,after.getTimeObservation());assertEquals(original.getAdmission(),after.getTimeObservation().getAdmission());
   for(WebAuthnStoreKey key:List.of(root,FIRST)){assertArrayEquals(present(before,key).getVersion(),present(after,key).getVersion());assertArrayEquals(present(before,key).getSealedBytes(),present(after,key).getSealedBytes());}
   assertInstanceOf(WebAuthnStoreEntry.Absent.class,after.getEntry(SECOND));assertSame(entries,field(store,"entries"));assertSame(prefix,field(store,"versionPrefix"));assertEquals(sequence,field(store,"sequence"));assertEquals(bytes,field(store,"sealedBytes"));assertTrue(lost.getBoolean(store));
  }));return cells;
 }

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi04EveryWebAuthnKindAndAbsenceDefeatsBothWholeMutationAndBarrier() {
  List<org.junit.jupiter.api.DynamicTest> cells=new java.util.ArrayList<>();
  for(WebAuthnStoreKey.Kind kind:WebAuthnStoreKey.Kind.values())for(boolean exists:List.of(false,true))for(boolean mutate:List.of(false,true))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-04+10/WA/"+kind+"/present="+exists+"/mutation="+mutate,()->{
   InMemoryWebAuthnStore store=InMemoryWebAuthnStore.fromLimits(10,100);WebAuthnStoreKey root=WebAuthnStoreKey.forNamespaceClock("tenant","login.example.com"),target=scApi04WebAuthnKey(kind);
   Set<WebAuthnStoreKey> keys=Set.of(root,FIRST,SECOND).contains(target)?Set.of(root,FIRST,SECOND):Set.of(root,FIRST,SECOND,target);
   List<WebAuthnStoreWrite.Mutation> seed=new java.util.ArrayList<>();if(kind!=WebAuthnStoreKey.Kind.NAMESPACE_CLOCK || exists)seed.add(WebAuthnStoreWrite.Mutation.insert(root,new byte[]{9}));if(exists&&!target.equals(root))seed.add(WebAuthnStoreWrite.Mutation.insert(target,new byte[]{1}));
   if(!seed.isEmpty())assertEquals(WebAuthnStoreCommitResult.COMMITTED,store.compareAndCommit(write(snapshot(store,keys),seed),BUDGET).getStatus());
   WebAuthnStoreSnapshot observed=snapshot(store,keys);List<WebAuthnStoreWrite.Mutation> candidates=target.equals(root)&&!exists?List.of(WebAuthnStoreWrite.Mutation.insert(root,new byte[]{20}),WebAuthnStoreWrite.Mutation.insert(FIRST,new byte[]{21})):List.of(WebAuthnStoreWrite.Mutation.insert(FIRST,new byte[]{20}),WebAuthnStoreWrite.Mutation.insert(SECOND,new byte[]{21}));
   WebAuthnStoreWrite pending=write(observed,mutate?candidates:List.of());WebAuthnStoreWrite.Mutation rival=exists?WebAuthnStoreWrite.Mutation.replace(target,new byte[]{10}):WebAuthnStoreWrite.Mutation.insert(target,new byte[]{10});
   assertEquals(WebAuthnStoreCommitResult.COMMITTED,store.compareAndCommit(write(observed,List.of(rival)),BUDGET).getStatus());WebAuthnStoreSnapshot afterRival=snapshot(store,keys);
   Object retained=Objects.requireNonNull(field(store,"entries")),bytes=Objects.requireNonNull(field(store,"sealedBytes")),sequence=Objects.requireNonNull(field(store,"sequence")),prefix=Objects.requireNonNull(field(store,"versionPrefix"));var refused=store.compareAndCommit(pending,BUDGET);
   org.junit.jupiter.api.Assertions.assertAll(()->assertEquals(WebAuthnStoreCommitResult.CONFLICT,refused.getStatus()),()->assertTrue(refused.getTiming().isEmpty()),()->assertSame(retained,field(store,"entries"),"A conflicting row cannot permit any prefix write"),()->assertEquals(bytes,field(store,"sealedBytes")),()->assertEquals(sequence,field(store,"sequence")),()->assertSame(prefix,field(store,"versionPrefix")));
   WebAuthnStoreSnapshot after=snapshot(store,keys);for(WebAuthnStoreKey key:keys){if(afterRival.getEntry(key) instanceof WebAuthnStoreEntry.Present expected){assertArrayEquals(expected.getVersion(),present(after,key).getVersion());assertArrayEquals(expected.getSealedBytes(),present(after,key).getSealedBytes());}else assertInstanceOf(WebAuthnStoreEntry.Absent.class,after.getEntry(key));}
   assertEquals(keys,pending.getSnapshot().getEntries().keySet());assertEquals(mutate?2:0,pending.getMutations().size());assertEquals(WebAuthnStoreCommitResult.COMMITTED,store.compareAndCommit(write(after,List.of()),BUDGET).getStatus());assertSame(retained,field(store,"entries"));assertEquals(bytes,field(store,"sealedBytes"));assertEquals(sequence,field(store,"sequence"));
  }));return cells;
 }
 private static @NonNull WebAuthnStoreKey scApi04WebAuthnKey(WebAuthnStoreKey.@NonNull Kind kind){return switch(kind){case CEREMONY->CEREMONY;case CREDENTIAL->WebAuthnStoreKey.forCredential("tenant","login.example.com",new byte[]{7});case ACCOUNT_CREDENTIAL_INDEX->WebAuthnStoreKey.forAccountCredentialIndex("tenant","login.example.com",new byte[]{7});case ACCOUNT_FENCE->WebAuthnStoreKey.forAccountFence("tenant","login.example.com",new byte[]{7});case NAMESPACE_CLOCK->WebAuthnStoreKey.forNamespaceClock("tenant","login.example.com");};}
}
