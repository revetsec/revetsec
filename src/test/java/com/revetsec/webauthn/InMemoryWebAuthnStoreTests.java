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

import java.time.Duration;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
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

 @Test void reclaimsExpiredCeremoniesBeforeReadsAndCapacityChecks() {
  AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-10-15T12:00:00Z"));
  Clock clock = new Clock() {
   @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
   @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
   @Override public @NonNull Instant instant() { return Objects.requireNonNull(now.get()); }
  };
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.withLimits(1, 100, clock);
  Instant expiresAt = Objects.requireNonNull(now.get()).plusSeconds(1);
  WebAuthnStoreSnapshot empty = snapshot(store, Set.of(CEREMONY));
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(
    WebAuthnStoreWrite.fromSnapshotAndMutations(empty, List.of(
      WebAuthnStoreWrite.Mutation.insertExpiring(CEREMONY, new byte[] {1}, expiresAt))), BUDGET));
  WebAuthnStoreSnapshot live = snapshot(store, Set.of(CEREMONY, FIRST));
  assertInstanceOf(WebAuthnStoreEntry.Present.class, live.getEntry(CEREMONY));
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(
    WebAuthnStoreWrite.fromSnapshotAndMutations(live, List.of(
      WebAuthnStoreWrite.Mutation.replaceExpiring(CEREMONY, new byte[] {3}, expiresAt))), BUDGET));
  live = snapshot(store, Set.of(CEREMONY, FIRST));
  now.set(expiresAt);
  assertInstanceOf(WebAuthnStoreEntry.Absent.class, snapshot(store, Set.of(CEREMONY)).getEntry(CEREMONY));
  assertEquals(WebAuthnStoreCommitResult.CONFLICT, store.compareAndCommit(
    WebAuthnStoreWrite.fromSnapshotAndMutations(live, List.of()), BUDGET));
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(
    WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot(store, Set.of(FIRST)), List.of(
      WebAuthnStoreWrite.Mutation.insert(FIRST, new byte[] {2}))), BUDGET));
  now.set(Objects.requireNonNull(now.get()).plusSeconds(86_400));
  assertInstanceOf(WebAuthnStoreEntry.Present.class, snapshot(store, Set.of(FIRST)).getEntry(FIRST));
 }

 @Test void repeatedCeremonyReplacementKeepsExpiryQueueWithinConfiguredCapacity() {
  Instant now = Instant.parse("2026-10-15T12:00:00Z");
  Instant expiresAt = now.plusSeconds(3600);
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.withLimits(1, 1,
    Clock.fixed(now, ZoneOffset.UTC));
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(
    WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot(store, Set.of(CEREMONY)), List.of(
      WebAuthnStoreWrite.Mutation.insertExpiring(CEREMONY, new byte[] {1}, expiresAt))), BUDGET));
  for (int index = 0; index < 1_000; index++) {
   assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(
     WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot(store, Set.of(CEREMONY)), List.of(
       WebAuthnStoreWrite.Mutation.replaceExpiring(CEREMONY, new byte[] {(byte) index}, expiresAt))),
     BUDGET));
  }
  assertTrue(store.expiryQueueSize() <= 8);
  assertInstanceOf(WebAuthnStoreEntry.Present.class, snapshot(store, Set.of(CEREMONY)).getEntry(CEREMONY));
 }

 @Test void capacityRejectsWholeWriteAndNeverEvictsRecords() {
  assertThrows(IllegalArgumentException.class, () -> InMemoryWebAuthnStore.withLimits(0, 10));
  assertThrows(IllegalArgumentException.class, () -> InMemoryWebAuthnStore.withLimits(1, 0));
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.withLimits(1, 3);
  WebAuthnStoreSnapshot empty = snapshot(store, Set.of(FIRST, SECOND));
  WebAuthnStoreWrite both = WebAuthnStoreWrite.fromSnapshotAndMutations(empty, List.of(
    WebAuthnStoreWrite.Mutation.insert(FIRST, new byte[] {1}),
    WebAuthnStoreWrite.Mutation.insert(SECOND, new byte[] {2})));
  assertEquals(WebAuthnStoreCommitResult.CAPACITY, store.compareAndCommit(both, BUDGET));
  assertTrue(snapshot(store, Set.of(FIRST, SECOND)).getEntry(FIRST) instanceof WebAuthnStoreEntry.Absent);
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(
    WebAuthnStoreWrite.fromSnapshotAndMutations(empty,
      List.of(WebAuthnStoreWrite.Mutation.insert(FIRST, new byte[] {1, 2, 3}))), BUDGET));
  WebAuthnStoreSnapshot full = snapshot(store, Set.of(FIRST, SECOND));
  assertEquals(WebAuthnStoreCommitResult.CAPACITY, store.compareAndCommit(
    WebAuthnStoreWrite.fromSnapshotAndMutations(full,
      List.of(WebAuthnStoreWrite.Mutation.insert(SECOND, new byte[] {4}))), BUDGET));
  assertEquals(WebAuthnStoreCommitResult.CAPACITY, store.compareAndCommit(
    WebAuthnStoreWrite.fromSnapshotAndMutations(full,
      List.of(WebAuthnStoreWrite.Mutation.replace(FIRST, new byte[] {1, 2, 3, 4}))), BUDGET));
  assertArrayEquals(new byte[] {1, 2, 3}, present(snapshot(store, Set.of(FIRST)), FIRST).getSealedBytes());
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(
    WebAuthnStoreWrite.fromSnapshotAndMutations(full, List.of(
      WebAuthnStoreWrite.Mutation.delete(FIRST),
      WebAuthnStoreWrite.Mutation.insert(SECOND, new byte[] {5, 6}))), BUDGET));
  assertTrue(snapshot(store, Set.of(FIRST)).getEntry(FIRST) instanceof WebAuthnStoreEntry.Absent);
  assertArrayEquals(new byte[] {5, 6}, present(snapshot(store, Set.of(SECOND)), SECOND).getSealedBytes());
 }

 @Test void compareAllPredicatesAndRenewVersionsAcrossDeleteAndReinsert() {
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.withLimits(2, 100);
  WebAuthnStoreSnapshot empty = snapshot(store, Set.of(FIRST, SECOND));
  WebAuthnStoreWrite insert = WebAuthnStoreWrite.fromSnapshotAndMutations(empty,
    List.of(WebAuthnStoreWrite.Mutation.insert(FIRST, new byte[] {7})));
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(insert, BUDGET));
  assertEquals(WebAuthnStoreCommitResult.CONFLICT, store.compareAndCommit(insert, BUDGET));
  WebAuthnStoreSnapshot first = snapshot(store, Set.of(FIRST, SECOND));
  byte[] oldVersion = present(first, FIRST).getVersion();
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(
    WebAuthnStoreWrite.fromSnapshotAndMutations(first,
      List.of(WebAuthnStoreWrite.Mutation.replace(FIRST, new byte[] {8}))), BUDGET));
  assertEquals(WebAuthnStoreCommitResult.CONFLICT, store.compareAndCommit(
    WebAuthnStoreWrite.fromSnapshotAndMutations(first, List.of()), BUDGET));
  WebAuthnStoreSnapshot second = snapshot(store, Set.of(FIRST, SECOND));
  assertNotEquals(java.util.Arrays.toString(oldVersion),
    java.util.Arrays.toString(present(second, FIRST).getVersion()));
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(
    WebAuthnStoreWrite.fromSnapshotAndMutations(second,
      List.of(WebAuthnStoreWrite.Mutation.delete(FIRST))), BUDGET));
  WebAuthnStoreSnapshot absent = snapshot(store, Set.of(FIRST));
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(
    WebAuthnStoreWrite.fromSnapshotAndMutations(absent,
      List.of(WebAuthnStoreWrite.Mutation.insert(FIRST, new byte[] {9}))), BUDGET));
  assertNotEquals(java.util.Arrays.toString(oldVersion),
    java.util.Arrays.toString(present(snapshot(store, Set.of(FIRST)), FIRST).getVersion()));
  assertEquals(WebAuthnStoreCommitResult.CONFLICT, store.compareAndCommit(
    WebAuthnStoreWrite.fromSnapshotAndMutations(second, List.of()), BUDGET));
 }

 @Test void concurrentWritersHaveExactlyOneWinnerAndBudgetOrInterruptNeverMutates() throws Exception {
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.withLimits(1, 100);
  WebAuthnStoreSnapshot empty = snapshot(store, Set.of(FIRST));
  WebAuthnStoreWrite insert = WebAuthnStoreWrite.fromSnapshotAndMutations(empty,
    List.of(WebAuthnStoreWrite.Mutation.insert(FIRST, new byte[] {1})));
  CountDownLatch start = new CountDownLatch(1);
  ExecutorService workers = Executors.newFixedThreadPool(2);
  try {
   Future<WebAuthnStoreCommitResult> one = workers.submit(() -> {
    start.await(); return store.compareAndCommit(insert, BUDGET);
   });
   Future<WebAuthnStoreCommitResult> two = workers.submit(() -> {
    start.await(); return store.compareAndCommit(insert, BUDGET);
   });
   start.countDown();
   assertEquals(Set.of(WebAuthnStoreCommitResult.COMMITTED, WebAuthnStoreCommitResult.CONFLICT),
     Set.of(one.get(), two.get()));
  } finally {
   workers.shutdownNow();
  }
  WebAuthnStoreSnapshot current = snapshot(store, Set.of(FIRST));
  WebAuthnStoreWrite replace = WebAuthnStoreWrite.fromSnapshotAndMutations(current,
    List.of(WebAuthnStoreWrite.Mutation.replace(FIRST, new byte[] {2})));
  assertEquals(WebAuthnStoreCommitResult.UNAVAILABLE,
    store.compareAndCommit(replace, Duration.ZERO));
  Thread.currentThread().interrupt();
  try {
   assertEquals(WebAuthnStoreCommitResult.UNAVAILABLE, store.compareAndCommit(replace, BUDGET));
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
}
