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

import java.lang.reflect.Field;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class TotpStoreTests {
 private static final Duration BUDGET = Duration.ofSeconds(3);
 private static final TotpStoreKey ROOT = TotpStoreKey.forNamespace("accounts", "epoch-one");
 private static final TotpStoreKey ACCOUNT = TotpStoreKey.forAccount("accounts", "epoch-one", "person@example.com");
 private static final TotpStoreKey OTHER = TotpStoreKey.forAccount("accounts", "epoch-one", "another-person");

 @Test void addressesAreCanonicalOpaqueAndScopeBound() {
  assertEquals(ACCOUNT, TotpStoreKey.fromStoredForm(ACCOUNT.getStorageKey()));
  assertEquals(ROOT, TotpStoreKey.fromStoredForm(ROOT.getStorageKey()));
  assertEquals("accounts", ACCOUNT.getCredentialNamespace());
  assertEquals("epoch-one", ACCOUNT.getRecoveryEpoch());
  assertEquals(TotpStoreKey.Kind.ACCOUNT_STATE, ACCOUNT.getKind());
  assertEquals(TotpStoreKey.Kind.NAMESPACE_STATE, ROOT.getKind());
  assertFalse(ACCOUNT.getStorageKey().contains("person@example.com"));
  assertNotEquals(ACCOUNT, TotpStoreKey.forAccount("other", "epoch-one", "person@example.com"));
  assertNotEquals(ACCOUNT, TotpStoreKey.forAccount("accounts", "epoch-two", "person@example.com"));
  assertNotEquals(ACCOUNT, OTHER);
  assertNotEquals(ACCOUNT, ROOT);
  assertEquals(ACCOUNT.hashCode(), TotpStoreKey.fromStoredForm(ACCOUNT.getStorageKey()).hashCode());
  assertFalse(ACCOUNT.toString().contains("accounts"));
  assertFalse(ACCOUNT.toString().contains(ACCOUNT.getStorageKey()));
 }

 @Test void rejectsNoncanonicalAddressesAndMalformedIdentifiers() {
  assertThrows(IllegalArgumentException.class, () -> TotpStoreKey.forNamespace("", "epoch"));
  assertThrows(IllegalArgumentException.class, () -> TotpStoreKey.forNamespace("space name", "epoch"));
  assertThrows(IllegalArgumentException.class, () -> TotpStoreKey.forNamespace("accounts", "époch"));
  assertThrows(IllegalArgumentException.class, () -> TotpStoreKey.forAccount("accounts", "epoch", ""));
  assertThrows(IllegalArgumentException.class, () -> TotpStoreKey.forAccount("accounts", "epoch", "\uD800"));
  assertThrows(IllegalArgumentException.class, () -> TotpStoreKey.forAccount("accounts", "epoch", "é".repeat(513)));
  assertThrows(IllegalArgumentException.class, () -> TotpStoreKey.fromStoredForm(ACCOUNT.getStorageKey() + "="));
  assertThrows(IllegalArgumentException.class, () -> TotpStoreKey.fromStoredForm("totp1:" + "A".repeat(500)));
  String wrongRoot = ROOT.getStorageKey().substring(0, ROOT.getStorageKey().lastIndexOf(':') + 1) + version(17);
  assertThrows(IllegalArgumentException.class, () -> TotpStoreKey.fromStoredForm(wrongRoot));
  String paddedScope = ROOT.getStorageKey().replace("YWNjb3VudHM", "YWNjb3VudHM=");
  assertThrows(IllegalArgumentException.class, () -> TotpStoreKey.fromStoredForm(paddedScope));
  assertEquals(TotpStoreKey.forAccount("accounts", "epoch", "😀"),
    TotpStoreKey.fromStoredForm(TotpStoreKey.forAccount("accounts", "epoch", "😀").getStorageKey()));
 }

 @Test void recordsDefensivelyCopyAndValidateVersionsAndFraming() {
  byte[] bytes = {3, 4};
  TotpStoreRecord record = TotpStoreRecord.fromStoredForm(ACCOUNT, version(1), bytes);
  bytes[0] = 9;
  assertArrayEquals(new byte[] {3, 4}, record.getSealedBytes());
  byte[] returned = record.getSealedBytes(); returned[1] = 8;
  assertArrayEquals(new byte[] {3, 4}, record.getSealedBytes());
  assertEquals(ACCOUNT, record.getKey());
  assertEquals(version(1), record.getVersion());
  assertThrows(IllegalArgumentException.class, () -> TotpStoreRecord.fromStoredForm(ACCOUNT, "bad", new byte[] {1}));
  assertThrows(IllegalArgumentException.class, () -> TotpStoreRecord.fromStoredForm(ACCOUNT, version(1) + "=", new byte[] {1}));
  String noncanonical = version(0).substring(0, 42) + "B";
  assertThrows(IllegalArgumentException.class, () -> TotpStoreRecord.fromStoredForm(ACCOUNT, noncanonical, new byte[] {1}));
  assertThrows(IllegalArgumentException.class, () -> TotpStoreRecord.fromStoredForm(ACCOUNT, version(1), new byte[0]));
  assertThrows(IllegalArgumentException.class, () -> TotpStoreRecord.fromStoredForm(ACCOUNT, version(1), new byte[65537]));
  assertEquals(65536, TotpStoreRecord.fromStoredForm(ACCOUNT, version(1), new byte[65536]).getSealedBytes().length);
  assertFalse(record.toString().contains(version(1)));
  assertFalse(record.toString().contains(ACCOUNT.getStorageKey()));
 }

 @Test void snapshotsRequireCompleteSingleScopeAddressMatchedObservations() {
  Map<TotpStoreKey, TotpStoreEntry> entries = new HashMap<>();
  entries.put(ROOT, TotpStoreEntry.Present.fromRecord(record(ROOT, 1, 1)));
  entries.put(ACCOUNT, TotpStoreEntry.Absent.confirmed());
  Set<TotpStoreKey> keys = new HashSet<>(entries.keySet());
  TotpStoreSnapshot snapshot = TotpStoreSnapshot.fromEntries(keys, entries);
  keys.clear(); entries.clear();
  assertEquals(2, snapshot.getEntries().size());
  assertInstanceOf(TotpStoreEntry.Absent.class, snapshot.getEntry(ACCOUNT));
  assertThrows(UnsupportedOperationException.class, () -> snapshot.getEntries().clear());
  assertThrows(IllegalArgumentException.class, () -> snapshot.getEntry(OTHER));
  assertThrows(IllegalArgumentException.class, () -> TotpStoreSnapshot.fromEntries(Set.of(ROOT), Map.of()));
  assertThrows(IllegalArgumentException.class, () -> TotpStoreSnapshot.fromEntries(Set.of(), Map.of()));
  assertThrows(IllegalArgumentException.class, () -> TotpStoreSnapshot.fromEntries(Set.of(ROOT),
    Map.of(ROOT, TotpStoreEntry.Present.fromRecord(record(ACCOUNT, 2, 2)))));
  TotpStoreKey nextEpoch = TotpStoreKey.forNamespace("accounts", "epoch-two");
  assertThrows(IllegalArgumentException.class, () -> TotpStoreSnapshot.fromEntries(Set.of(ROOT, nextEpoch),
    Map.of(ROOT, TotpStoreEntry.Absent.confirmed(), nextEpoch, TotpStoreEntry.Absent.confirmed())));
  Set<TotpStoreKey> tooMany = new HashSet<>(); Map<TotpStoreKey, TotpStoreEntry> tooManyEntries = new HashMap<>();
  for (int i = 0; i < 17; i++) {
   TotpStoreKey key = TotpStoreKey.forAccount("accounts", "epoch-one", "account-" + i);
   tooMany.add(key); tooManyEntries.put(key, TotpStoreEntry.Absent.confirmed());
  }
  assertThrows(IllegalArgumentException.class, () -> TotpStoreSnapshot.fromEntries(tooMany, tooManyEntries));
 }

 @Test void writeGrammarRequiresInitializedRootAndFreshVersionWithExactMutationPredicates() {
  TotpStoreSnapshot absent = TotpStoreSnapshot.fromEntries(Set.of(ROOT), Map.of(ROOT, TotpStoreEntry.Absent.confirmed()));
  assertThrows(IllegalArgumentException.class, () -> write(absent, List.of()));
  assertThrows(IllegalArgumentException.class, () -> TotpStoreWrite.fromSnapshotAndMutations(
    TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE, absent, List.of()));
  TotpStoreWrite initialize = TotpStoreWrite.fromSnapshotAndMutations(TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE,
    absent, List.of(TotpStoreWrite.Mutation.insert(record(ROOT, 1, 1))));
  assertEquals("accounts", initialize.getCredentialNamespace());
  assertEquals("epoch-one", initialize.getRecoveryEpoch());
  assertEquals(TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE, initialize.getPurpose());
  TotpStoreSnapshot rootAndAbsent = TotpStoreSnapshot.fromEntries(Set.of(ROOT, ACCOUNT), Map.of(
    ROOT, TotpStoreEntry.Present.fromRecord(record(ROOT, 1, 1)), ACCOUNT, TotpStoreEntry.Absent.confirmed()));
  assertThrows(IllegalArgumentException.class, () -> write(rootAndAbsent,
    List.of(TotpStoreWrite.Mutation.insert(record(ROOT, 2, 2)))));
  assertThrows(IllegalArgumentException.class, () -> write(rootAndAbsent,
    List.of(TotpStoreWrite.Mutation.replace(record(ACCOUNT, 2, 2)))));
  assertThrows(IllegalArgumentException.class, () -> write(rootAndAbsent,
    List.of(TotpStoreWrite.Mutation.replace(record(ROOT, 1, 2)))));
  assertThrows(IllegalArgumentException.class, () -> write(rootAndAbsent,
    List.of(TotpStoreWrite.Mutation.insert(record(OTHER, 2, 2)))));
  assertThrows(IllegalArgumentException.class, () -> write(rootAndAbsent, List.of(
    TotpStoreWrite.Mutation.insert(record(ACCOUNT, 2, 2)), TotpStoreWrite.Mutation.insert(record(ACCOUNT, 3, 3)))));
  List<TotpStoreWrite.Mutation> changes = new ArrayList<>(List.of(TotpStoreWrite.Mutation.insert(record(ACCOUNT, 2, 2))));
  TotpStoreWrite update = write(rootAndAbsent, changes); changes.clear();
  assertEquals(1, update.getMutations().size());
  assertThrows(UnsupportedOperationException.class, () -> update.getMutations().clear());
  assertEquals(TotpStoreWrite.Mutation.Kind.INSERT, update.getMutations().get(0).getKind());
 }

 @Test void initializationIsAtomicAndCannotRepeatOrBeRecreatedAfterRootLoss() throws Exception {
  InMemoryTotpStore store = store(5, 100);
  TotpStoreSnapshot absent = snapshot(store, Set.of(ROOT));
  assertInstanceOf(TotpStoreEntry.Absent.class, absent.getEntry(ROOT));
  assertInstanceOf(TotpStoreReadResult.Unavailable.class, store.read(Set.of(ROOT, ACCOUNT), BUDGET));
  TotpStoreWrite initialize = initialization(absent, ROOT, 1);
  assertEquals(TotpStoreCommitResult.COMMITTED, store.compareAndCommit(initialize, BUDGET));
  assertEquals(TotpStoreCommitResult.CONFLICT, store.compareAndCommit(initialize, BUDGET));
  assertInstanceOf(TotpStoreEntry.Present.class, snapshot(store, Set.of(ROOT)).getEntry(ROOT));
  Field records = InMemoryTotpStore.class.getDeclaredField("records"); records.setAccessible(true);
  records.set(store, Map.of());
  assertInstanceOf(TotpStoreReadResult.Unavailable.class, store.read(Set.of(ROOT), BUDGET));
  assertEquals(TotpStoreCommitResult.UNAVAILABLE, store.compareAndCommit(initialize, BUDGET));
 }

 @Test void comparesEveryAbsenceAndVersionIncludingConditionOnlyWrites() {
  InMemoryTotpStore store = initializedStore(5, 100);
  TotpStoreSnapshot initial = snapshot(store, Set.of(ROOT, ACCOUNT, OTHER));
  TotpStoreWrite insert = write(initial, List.of(TotpStoreWrite.Mutation.insert(record(ACCOUNT, 2, 7))));
  assertEquals(TotpStoreCommitResult.COMMITTED, store.compareAndCommit(insert, BUDGET));
  assertEquals(TotpStoreCommitResult.CONFLICT, store.compareAndCommit(insert, BUDGET));
  assertEquals(TotpStoreCommitResult.CONFLICT, store.compareAndCommit(write(initial, List.of()), BUDGET));
  TotpStoreSnapshot first = snapshot(store, Set.of(ROOT, ACCOUNT, OTHER));
  assertEquals(TotpStoreCommitResult.COMMITTED, store.compareAndCommit(write(first,
    List.of(TotpStoreWrite.Mutation.replace(record(ACCOUNT, 3, 8)))), BUDGET));
  assertEquals(TotpStoreCommitResult.CONFLICT, store.compareAndCommit(write(first,
    List.of(TotpStoreWrite.Mutation.insert(record(OTHER, 4, 9)))), BUDGET));
  assertInstanceOf(TotpStoreEntry.Absent.class, snapshot(store, Set.of(ROOT, OTHER)).getEntry(OTHER));
  TotpStoreSnapshot second = snapshot(store, Set.of(ROOT, ACCOUNT));
  assertArrayEquals(new byte[] {8}, present(second, ACCOUNT).getSealedBytes());
  assertNotEquals(present(first, ACCOUNT).getVersion(), present(second, ACCOUNT).getVersion());
  assertEquals(TotpStoreCommitResult.COMMITTED, store.compareAndCommit(write(second, List.of()), BUDGET));
  assertEquals(TotpStoreCommitResult.COMMITTED, store.compareAndCommit(write(second,
    List.of(TotpStoreWrite.Mutation.replace(record(ROOT, 5, 6)))), BUDGET));
  assertEquals(TotpStoreCommitResult.CONFLICT, store.compareAndCommit(write(second, List.of()), BUDGET));
 }

 @Test void concurrentWritersHaveExactlyOneWinner() throws Exception {
  InMemoryTotpStore store = initializedStore(5, 100);
  TotpStoreSnapshot shared = snapshot(store, Set.of(ROOT, ACCOUNT));
  CountDownLatch start = new CountDownLatch(1);
  ExecutorService executor = Executors.newFixedThreadPool(2);
  try {
   Future<TotpStoreCommitResult> first = executor.submit(() -> {
    start.await(); return store.compareAndCommit(write(shared,
      List.of(TotpStoreWrite.Mutation.insert(record(ACCOUNT, 2, 2)))), BUDGET);
   });
   Future<TotpStoreCommitResult> second = executor.submit(() -> {
    start.await(); return store.compareAndCommit(write(shared,
      List.of(TotpStoreWrite.Mutation.insert(record(ACCOUNT, 3, 3)))), BUDGET);
   });
   start.countDown();
   List<TotpStoreCommitResult> results = List.of(first.get(5, TimeUnit.SECONDS), second.get(5, TimeUnit.SECONDS));
   assertEquals(1L, results.stream().filter(result -> result == TotpStoreCommitResult.COMMITTED).count());
   assertEquals(1L, results.stream().filter(result -> result == TotpStoreCommitResult.CONFLICT).count());
  } finally { executor.shutdownNow(); }
 }

 @Test void capacityRefusesWholeTransitionWithoutEvictionAndCountsOldEpochs() {
  assertThrows(IllegalArgumentException.class, () -> InMemoryTotpStore.withNamespace("accounts", "epoch-one").maximumEntries(0));
  assertThrows(IllegalArgumentException.class, () -> InMemoryTotpStore.withNamespace("accounts", "epoch-one").maximumSealedBytes(0L));
  InMemoryTotpStore store = initializedStore(2, 4);
  TotpStoreSnapshot absent = snapshot(store, Set.of(ROOT, ACCOUNT, OTHER));
  assertEquals(TotpStoreCommitResult.CAPACITY_REFUSED, store.compareAndCommit(write(absent, List.of(
    TotpStoreWrite.Mutation.insert(record(ACCOUNT, 2, 2)), TotpStoreWrite.Mutation.insert(record(OTHER, 3, 3)))), BUDGET));
  assertInstanceOf(TotpStoreEntry.Absent.class, snapshot(store, Set.of(ROOT, ACCOUNT)).getEntry(ACCOUNT));
  assertEquals(TotpStoreCommitResult.COMMITTED, store.compareAndCommit(write(absent,
    List.of(TotpStoreWrite.Mutation.insert(record(ACCOUNT, 2, 2)))), BUDGET));
  TotpStoreSnapshot full = snapshot(store, Set.of(ROOT, ACCOUNT));
  TotpStoreRecord oversized = TotpStoreRecord.fromStoredForm(ACCOUNT, version(3), new byte[] {3, 4, 5, 6});
  assertEquals(TotpStoreCommitResult.CAPACITY_REFUSED, store.compareAndCommit(write(full,
    List.of(TotpStoreWrite.Mutation.replace(oversized))), BUDGET));
  assertArrayEquals(new byte[] {2}, present(snapshot(store, Set.of(ROOT, ACCOUNT)), ACCOUNT).getSealedBytes());
  assertEquals(TotpStoreCommitResult.COMMITTED, store.provisionRecoveryEpoch("epoch-two", BUDGET));
  TotpStoreKey nextRoot = TotpStoreKey.forNamespace("accounts", "epoch-two");
  assertEquals(TotpStoreCommitResult.CAPACITY_REFUSED, store.compareAndCommit(
    initialization(snapshot(store, Set.of(nextRoot)), nextRoot, 4), BUDGET));
 }

 @Test void freshEpochAtomicallyFencesSnapshotsAndNeverRevivesOlderEpochs() {
  InMemoryTotpStore store = initializedStore(10, 100);
  TotpStoreSnapshot before = snapshot(store, Set.of(ROOT, ACCOUNT));
  TotpStoreWrite oldWrite = write(before, List.of(TotpStoreWrite.Mutation.insert(record(ACCOUNT, 2, 2))));
  assertEquals(TotpStoreCommitResult.COMMITTED, store.provisionRecoveryEpoch("epoch-two", BUDGET));
  assertInstanceOf(TotpStoreReadResult.Fenced.class, store.read(Set.of(ROOT), BUDGET));
  assertEquals(TotpStoreCommitResult.FENCED, store.compareAndCommit(oldWrite, BUDGET));
  assertThrows(IllegalArgumentException.class, () -> store.provisionRecoveryEpoch("epoch-one", BUDGET));
  assertThrows(IllegalArgumentException.class, () -> store.provisionRecoveryEpoch("epoch-two", BUDGET));
  TotpStoreKey rootTwo = TotpStoreKey.forNamespace("accounts", "epoch-two");
  assertEquals(TotpStoreCommitResult.COMMITTED, store.compareAndCommit(
    initialization(snapshot(store, Set.of(rootTwo)), rootTwo, 3), BUDGET));
  TotpStoreKey accountTwo = TotpStoreKey.forAccount("accounts", "epoch-two", "person@example.com");
  assertInstanceOf(TotpStoreEntry.Absent.class, snapshot(store, Set.of(rootTwo, accountTwo)).getEntry(accountTwo));
  assertInstanceOf(TotpStoreReadResult.Fenced.class, store.read(Set.of(TotpStoreKey.forNamespace("other", "epoch-two")), BUDGET));
 }

 @Test void budgetAndInterruptionBeforeCommitNeverMutateAndLockAcquisitionIsBounded() throws Exception {
  InMemoryTotpStore store = initializedStore(5, 100);
  TotpStoreWrite insert = write(snapshot(store, Set.of(ROOT, ACCOUNT)),
    List.of(TotpStoreWrite.Mutation.insert(record(ACCOUNT, 2, 2))));
  assertEquals(TotpStoreCommitResult.UNAVAILABLE, store.compareAndCommit(insert, Duration.ZERO));
  assertInstanceOf(TotpStoreReadResult.Unavailable.class, store.read(Set.of(ROOT), Duration.ofSeconds(-1)));
  assertEquals(TotpStoreCommitResult.UNAVAILABLE, store.provisionRecoveryEpoch("epoch-two", Duration.ZERO));
  Thread.currentThread().interrupt();
  try {
   assertEquals(TotpStoreCommitResult.UNAVAILABLE, store.compareAndCommit(insert, BUDGET));
   assertInstanceOf(TotpStoreReadResult.Unavailable.class, store.read(Set.of(ROOT), BUDGET));
   assertTrue(Thread.currentThread().isInterrupted());
  } finally { Thread.interrupted(); }
  assertInstanceOf(TotpStoreEntry.Absent.class, snapshot(store, Set.of(ROOT, ACCOUNT)).getEntry(ACCOUNT));
  Field lockField = InMemoryTotpStore.class.getDeclaredField("lock"); lockField.setAccessible(true);
  ReentrantLock lock = (ReentrantLock) lockField.get(store);
  ExecutorService executor = Executors.newSingleThreadExecutor();
  lock.lock();
  try {
   Future<TotpStoreCommitResult> blocked = executor.submit(() -> store.compareAndCommit(insert, Duration.ofMillis(20)));
   assertEquals(TotpStoreCommitResult.UNAVAILABLE, blocked.get(2, TimeUnit.SECONDS));
   Future<TotpStoreReadResult> blockedRead = executor.submit(() -> store.read(Set.of(ROOT), Duration.ofMillis(20)));
   assertInstanceOf(TotpStoreReadResult.Unavailable.class, blockedRead.get(2, TimeUnit.SECONDS));
  } finally { lock.unlock(); executor.shutdownNow(); }
  assertEquals(TotpStoreCommitResult.COMMITTED, store.compareAndCommit(insert, BUDGET));
 }

 @Test void recoveryContextDefensivelyCapturesExactConfigurationAndPurpose() {
  Set<String> ids = new HashSet<>(Set.of("current", "previous"));
  TotpRecoveryContext context = TotpRecoveryContext.fromConfiguration("accounts", "epoch-one", "current", ids,
    TotpRecoveryContext.Purpose.INITIALIZE_NAMESPACE);
  ids.clear();
  assertEquals(Set.of("current", "previous"), context.getOpeningSealingKeyIds());
  assertEquals("current", context.getActiveSealingKeyId());
  assertEquals("accounts", context.getCredentialNamespace());
  assertEquals("epoch-one", context.getRecoveryEpoch());
  assertEquals(TotpRecoveryContext.Purpose.INITIALIZE_NAMESPACE, context.getPurpose());
  assertThrows(UnsupportedOperationException.class, () -> context.getOpeningSealingKeyIds().clear());
  assertThrows(IllegalArgumentException.class, () -> TotpRecoveryContext.fromConfiguration(
    "accounts", "epoch-one", "missing", Set.of("current"), TotpRecoveryContext.Purpose.OPERATION));
  assertFalse(context.toString().contains("accounts"));
  assertFalse(context.toString().contains("current"));
 }

 private static @NonNull InMemoryTotpStore store(int entries, long bytes) {
  return InMemoryTotpStore.withNamespace("accounts", "epoch-one").maximumEntries(entries).maximumSealedBytes(bytes).build();
 }
 private static @NonNull InMemoryTotpStore initializedStore(int entries, long bytes) {
  InMemoryTotpStore store = store(entries, bytes);
  assertEquals(TotpStoreCommitResult.COMMITTED, store.compareAndCommit(initialization(snapshot(store, Set.of(ROOT)), ROOT, 1), BUDGET));
  return store;
 }
 private static @NonNull TotpStoreSnapshot snapshot(@NonNull TotpStore store, @NonNull Set<@NonNull TotpStoreKey> keys) {
  return assertInstanceOf(TotpStoreReadResult.Available.class, store.read(keys, BUDGET)).getSnapshot();
 }
 private static @NonNull TotpStoreWrite initialization(@NonNull TotpStoreSnapshot snapshot, @NonNull TotpStoreKey key, int version) {
  return TotpStoreWrite.fromSnapshotAndMutations(TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE, snapshot,
    List.of(TotpStoreWrite.Mutation.insert(record(key, version, 1))));
 }
 private static @NonNull TotpStoreWrite write(@NonNull TotpStoreSnapshot snapshot,
   @NonNull List<TotpStoreWrite.@NonNull Mutation> changes) {
  return TotpStoreWrite.fromSnapshotAndMutations(TotpStoreWrite.Purpose.UPDATE, snapshot, changes);
 }
 private static @NonNull TotpStoreRecord present(@NonNull TotpStoreSnapshot snapshot, @NonNull TotpStoreKey key) {
  return assertInstanceOf(TotpStoreEntry.Present.class, snapshot.getEntry(key)).getRecord();
 }
 private static @NonNull TotpStoreRecord record(@NonNull TotpStoreKey key, int version, int payload) {
  return TotpStoreRecord.fromStoredForm(key, version(version), new byte[] {(byte) payload});
 }
 private static @NonNull String version(int value) {
  byte[] version = new byte[32]; Arrays.fill(version, (byte) value);
  return Base64.getUrlEncoder().withoutPadding().encodeToString(version);
 }
}
