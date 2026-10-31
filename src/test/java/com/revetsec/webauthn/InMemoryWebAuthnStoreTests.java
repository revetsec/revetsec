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
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.withLimits(1, 100);
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
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.withLimits(1, 1);
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
  assertThrows(IllegalArgumentException.class, () -> InMemoryWebAuthnStore.withLimits(0, 10));
  assertThrows(IllegalArgumentException.class, () -> InMemoryWebAuthnStore.withLimits(1, 0));
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.withLimits(1, 3);
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
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.withLimits(2, 100);
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
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.withLimits(1, 100);
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
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.withLimits(4, 100);
  assertNull(field(store, "admission")); assertNull(field(store, "authorityAnchor")); assertNull(field(store, "entropy")); assertNull(field(store, "versionPrefix"));
  assertThrows(IllegalArgumentException.class, () -> store.read(Set.of(), BUDGET));
  assertInstanceOf(WebAuthnStoreReadResult.Unavailable.class, store.read(Set.of(FIRST), Duration.ZERO));
  assertNull(field(store, "admission")); assertNull(field(store, "authorityAnchor")); assertNull(field(store, "entropy"));
 }

 @Test void scopedReadsHaveOneOwnedMonotoneProjectionAndRejectMixedScope() {
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.withLimits(4, 100);
  WebAuthnStoreKey other = WebAuthnStoreKey.forCredential("other", "other.example.com", new byte[] {3});
  assertThrows(IllegalArgumentException.class, () -> store.read(Set.of(FIRST, other), BUDGET));
  StoreTimeObservation.Healthy first = healthy(snapshot(store, Set.of(FIRST)));
  StoreTimeObservation.Healthy second = healthy(snapshot(store, Set.of(other)));
  assertEquals(first.getAdmission().getAuthorityId(), second.getAdmission().getAuthorityId());
  assertEquals(first.getAdmission().getRecoveryGeneration(), second.getAdmission().getRecoveryGeneration());
  assertEquals(first.getClockGeneration(), second.getClockGeneration()); assertFalse(second.getObservedAt().isBefore(first.getObservedAt()));
 }

 @Test void currentAuthorityRecoveryClockAndFixedErrorProfileAreComparedBeforeMutation() {
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.withLimits(1, 100);
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
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.withLimits(1, 100);
  WebAuthnStoreSnapshot snapshot = snapshot(store, Set.of(FIRST)); StoreTimeObservation.Healthy time = healthy(snapshot);
  List<WebAuthnStoreWrite.Mutation> insertion = List.of(WebAuthnStoreWrite.Mutation.insert(FIRST, new byte[] {1}));
  StoreTemporalCondition future = StoreTimeAccess.get().fromObservation(time, time.getObservedAt().plusSeconds(3600), null);
  assertEquals(WebAuthnStoreCommitResult.TIME_BEFORE_FLOOR, store.compareAndCommit(WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot, insertion, future), BUDGET).getStatus());
  snapshot = snapshot(store, Set.of(FIRST)); time = healthy(snapshot);
  Instant upper = time.getObservedAt().plusMillis(100);
  WebAuthnStoreWrite write = WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot, insertion,
    StoreTimeAccess.get().fromObservation(time, time.getObservedAt(), upper));
  ReentrantLock lock = (ReentrantLock) Objects.requireNonNull(field(store, "lock"));
  ExecutorService worker = Executors.newSingleThreadExecutor(); CountDownLatch entered = new CountDownLatch(1);
  Future<WebAuthnStoreCommitReceipt> waiting;
  lock.lock();
  try {
   waiting = worker.submit(() -> { entered.countDown(); return store.compareAndCommit(write, BUDGET); });
   assertTrue(entered.await(2, TimeUnit.SECONDS));
   long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
   while (!lock.hasQueuedThreads() && System.nanoTime() < until) Thread.yield();
   assertTrue(lock.hasQueuedThreads()); Thread.sleep(150);
  } finally { lock.unlock(); }
  try { assertEquals(WebAuthnStoreCommitResult.TIME_EXPIRED, waiting.get(2, TimeUnit.SECONDS).getStatus()); }
  finally { worker.shutdownNow(); assertTrue(worker.awaitTermination(2, TimeUnit.SECONDS)); }
  assertInstanceOf(WebAuthnStoreEntry.Absent.class, snapshot(store, Set.of(FIRST)).getEntry(FIRST));
 }

 @Test void authorityContinuityLossPreservesRowsAndRefusesEvenAnEmptyTimedBarrier() throws Exception {
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.withLimits(1, 100);
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
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.withLimits(2, 100);
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
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.withLimits(2, 100);
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
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.withLimits(2, 100);
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

}
