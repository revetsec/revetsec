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

import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * Shared transactional contract checks for TOTP stores. A future backend test can subclass this
 * suite and supply a fresh, empty scope plus its own externally controlled epoch transition. These
 * checks exercise observable atomicity and fencing; durable backends also need restart, backup
 * restore, unknown-acknowledgement and fault-injection tests specific to their transaction system.
 */
@javax.annotation.concurrent.NotThreadSafe
public abstract class TotpStoreConformanceTests {
 private static final @NonNull Duration BUDGET = Duration.ofSeconds(5);
 private static final @NonNull String NAMESPACE = "conformance-accounts";
 private static final @NonNull String FIRST_EPOCH = "conformance-epoch-one";
 private static final @NonNull String SECOND_EPOCH = "conformance-epoch-two";
 private static final @NonNull TotpStoreKey ROOT = TotpStoreKey.forNamespace(NAMESPACE, FIRST_EPOCH);
 private static final @NonNull TotpStoreKey ACCOUNT = TotpStoreKey.forAccount(NAMESPACE, FIRST_EPOCH, "account-a");
 private static final @NonNull TotpStoreKey OTHER = TotpStoreKey.forAccount(NAMESPACE, FIRST_EPOCH, "account-b");

 /** Creates a new empty store configured with the first namespace and epoch. */
 protected abstract @NonNull TotpStore newStore();

 /** Fences the first epoch and selects the second through the backend's recovery controller. */
 protected abstract void provisionSecondEpoch(@NonNull TotpStore store);

 @Test void initializationIsOneTimeAndRootIsPermanent() {
  TotpStore store = newStore();
  TotpStoreSnapshot absent = snapshot(store, Set.of(ROOT));
  assertInstanceOf(TotpStoreEntry.Absent.class, absent.getEntry(ROOT));
  TotpStoreWrite initialize = initialize(absent, ROOT, 1);
  assertEquals(TotpStoreCommitResult.COMMITTED, store.compareAndCommit(initialize, BUDGET));
  assertEquals(TotpStoreCommitResult.CONFLICT, store.compareAndCommit(initialize, BUDGET));
  assertArrayEquals(new byte[] {1}, present(snapshot(store, Set.of(ROOT)), ROOT).getSealedBytes());
 }

 @Test void comparesEveryAbsenceAndVersionBeforeApplyingAnyMutation() {
  TotpStore store = initializedStore();
  TotpStoreSnapshot observed = snapshot(store, Set.of(ROOT, ACCOUNT, OTHER));
  TotpStoreWrite first = update(observed, List.of(TotpStoreWrite.Mutation.insert(record(ACCOUNT, 2))));
  assertEquals(TotpStoreCommitResult.COMMITTED, store.compareAndCommit(first, BUDGET));
  assertEquals(TotpStoreCommitResult.CONFLICT, store.compareAndCommit(first, BUDGET));
  TotpStoreWrite staleOtherInsert = update(observed, List.of(TotpStoreWrite.Mutation.insert(record(OTHER, 3))));
  assertEquals(TotpStoreCommitResult.CONFLICT, store.compareAndCommit(staleOtherInsert, BUDGET));
  assertInstanceOf(TotpStoreEntry.Absent.class, snapshot(store, Set.of(ROOT, OTHER)).getEntry(OTHER));

  TotpStoreSnapshot current = snapshot(store, Set.of(ROOT, ACCOUNT, OTHER));
  TotpStoreWrite both = update(current, List.of(
    TotpStoreWrite.Mutation.replace(record(ACCOUNT, 4)), TotpStoreWrite.Mutation.insert(record(OTHER, 5))));
  assertEquals(TotpStoreCommitResult.COMMITTED, store.compareAndCommit(both, BUDGET));
  TotpStoreSnapshot after = snapshot(store, Set.of(ROOT, ACCOUNT, OTHER));
  assertArrayEquals(new byte[] {4}, present(after, ACCOUNT).getSealedBytes());
  assertArrayEquals(new byte[] {5}, present(after, OTHER).getSealedBytes());
  assertEquals(TotpStoreCommitResult.CONFLICT, store.compareAndCommit(update(current, List.of()), BUDGET));
 }

 @Test void simultaneousWritersToOneAbsenceHaveExactlyOneWinner() throws Exception {
  TotpStore store = initializedStore();
  TotpStoreSnapshot observed = snapshot(store, Set.of(ROOT, ACCOUNT));
  TotpStoreWrite firstWrite = update(observed, List.of(TotpStoreWrite.Mutation.insert(record(ACCOUNT, 2))));
  TotpStoreWrite secondWrite = update(observed, List.of(TotpStoreWrite.Mutation.insert(record(ACCOUNT, 3))));
  CountDownLatch start = new CountDownLatch(1);
  ExecutorService executor = Executors.newFixedThreadPool(2);
  try {
   Future<TotpStoreCommitResult> first = executor.submit(() -> {
    start.await(); return store.compareAndCommit(firstWrite, BUDGET);
   });
   Future<TotpStoreCommitResult> second = executor.submit(() -> {
    start.await(); return store.compareAndCommit(secondWrite, BUDGET);
   });
   start.countDown();
   List<TotpStoreCommitResult> results = List.of(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS));
   assertEquals(1L, results.stream().filter(result -> result == TotpStoreCommitResult.COMMITTED).count());
   assertEquals(1L, results.stream().filter(result -> result == TotpStoreCommitResult.CONFLICT).count());
  } finally { executor.shutdownNow(); }
 }

 @Test void epochChangeFencesOldReadsAndCommitsIncludingStaleSnapshots() {
  TotpStore store = initializedStore();
  TotpStoreSnapshot oldSnapshot = snapshot(store, Set.of(ROOT, ACCOUNT));
  TotpStoreWrite oldWrite = update(oldSnapshot, List.of(TotpStoreWrite.Mutation.insert(record(ACCOUNT, 2))));
  provisionSecondEpoch(store);
  assertInstanceOf(TotpStoreReadResult.Fenced.class, store.read(Set.of(ROOT), BUDGET));
  assertEquals(TotpStoreCommitResult.FENCED, store.compareAndCommit(oldWrite, BUDGET));

  TotpStoreKey newRoot = TotpStoreKey.forNamespace(NAMESPACE, SECOND_EPOCH);
  TotpStoreKey newAccount = TotpStoreKey.forAccount(NAMESPACE, SECOND_EPOCH, "account-a");
  TotpStoreSnapshot absent = snapshot(store, Set.of(newRoot));
  assertInstanceOf(TotpStoreEntry.Absent.class, absent.getEntry(newRoot));
  assertEquals(TotpStoreCommitResult.COMMITTED, store.compareAndCommit(initialize(absent, newRoot, 3), BUDGET));
  assertInstanceOf(TotpStoreEntry.Absent.class, snapshot(store, Set.of(newRoot, newAccount)).getEntry(newAccount));
  assertEquals(TotpStoreCommitResult.FENCED, store.compareAndCommit(oldWrite, BUDGET));
 }

 private @NonNull TotpStore initializedStore() {
  TotpStore store = newStore();
  assertEquals(TotpStoreCommitResult.COMMITTED,
    store.compareAndCommit(initialize(snapshot(store, Set.of(ROOT)), ROOT, 1), BUDGET));
  return store;
 }
 private static @NonNull TotpStoreSnapshot snapshot(@NonNull TotpStore store,
   @NonNull Set<@NonNull TotpStoreKey> keys) {
  TotpStoreReadResult.Available available = assertInstanceOf(TotpStoreReadResult.Available.class,
    store.read(keys, BUDGET));
  assertEquals(keys, available.getSnapshot().getEntries().keySet());
  return available.getSnapshot();
 }
 private static @NonNull TotpStoreWrite initialize(@NonNull TotpStoreSnapshot snapshot,
   @NonNull TotpStoreKey key, int value) {
  return TotpStoreWrite.fromSnapshotAndMutations(TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE, snapshot,
    List.of(TotpStoreWrite.Mutation.insert(record(key, value))));
 }
 private static @NonNull TotpStoreWrite update(@NonNull TotpStoreSnapshot snapshot,
   @NonNull List<TotpStoreWrite.@NonNull Mutation> mutations) {
  return TotpStoreWrite.fromSnapshotAndMutations(TotpStoreWrite.Purpose.UPDATE, snapshot, mutations);
 }
 private static @NonNull TotpStoreRecord present(@NonNull TotpStoreSnapshot snapshot,
   @NonNull TotpStoreKey key) {
  return assertInstanceOf(TotpStoreEntry.Present.class, snapshot.getEntry(key)).getRecord();
 }
 private static @NonNull TotpStoreRecord record(@NonNull TotpStoreKey key, int value) {
  byte[] version = new byte[32];
  Arrays.fill(version, (byte) value);
  return TotpStoreRecord.fromStoredForm(key, Base64.getUrlEncoder().withoutPadding().encodeToString(version),
    new byte[] {(byte) value});
 }
}
