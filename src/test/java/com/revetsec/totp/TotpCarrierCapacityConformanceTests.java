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

import com.revetsec.StoreTemporalCondition;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.StoreTimeAccess;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class TotpCarrierCapacityConformanceTests {
 private static final Duration BUDGET = Duration.ofSeconds(3);
 private static final String NAMESPACE = "bound01-accounts";
 private static final String EPOCH = "bound01-epoch";
 private static final TotpStoreKey ROOT = TotpStoreKey.forNamespace(NAMESPACE, EPOCH);

 @Test void exactSixteenReadsAndMutationsRemainSupportedAndSeventeenMutationsRefuseBeforeCommit() {
  InMemoryTotpStore store = InMemoryTotpStore.withNamespace(NAMESPACE, EPOCH)
    .maximumEntries(16).maximumSealedBytes(16L).build();
  TotpStoreSnapshot emptyRoot = snapshot(store, Set.of(ROOT));
  TotpStoreWrite initialize = TotpStoreWrite.fromSnapshotAndMutations(
    TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE, emptyRoot,
    List.of(TotpStoreWrite.Mutation.insert(record(ROOT, 1))), condition(emptyRoot));
  assertEquals(TotpStoreCommitResult.COMMITTED, store.compareAndCommit(initialize, BUDGET).getStatus());

  Set<TotpStoreKey> keys = new LinkedHashSet<>();
  keys.add(ROOT);
  for (int index = 0; index < 15; index++)
   keys.add(TotpStoreKey.forAccount(NAMESPACE, EPOCH, "account-" + index));
  TotpStoreSnapshot exactRead = snapshot(store, keys);
  assertEquals(16, exactRead.getEntries().size());

  List<TotpStoreWrite.Mutation> exactMutations = new ArrayList<>();
  exactMutations.add(TotpStoreWrite.Mutation.replace(record(ROOT, 2)));
  int version = 3;
  for (TotpStoreKey key : keys)
   if (!key.equals(ROOT)) exactMutations.add(TotpStoreWrite.Mutation.insert(record(key, version++)));
  TotpStoreWrite exactWrite = TotpStoreWrite.fromSnapshotAndMutations(
    TotpStoreWrite.Purpose.UPDATE, exactRead, exactMutations, condition(exactRead));
  assertEquals(16, exactWrite.getMutations().size());
  assertEquals(TotpStoreCommitResult.COMMITTED, store.compareAndCommit(exactWrite, BUDGET).getStatus());
  TotpStoreSnapshot committed = snapshot(store, keys);
  for (TotpStoreKey key : keys) assertInstanceOf(TotpStoreEntry.Present.class, committed.getEntry(key));

  List<TotpStoreWrite.Mutation> tooMany = new ArrayList<>(exactMutations);
  tooMany.add(exactMutations.get(0));
  IllegalArgumentException refusal = assertThrows(IllegalArgumentException.class,
    () -> TotpStoreWrite.fromSnapshotAndMutations(
      TotpStoreWrite.Purpose.UPDATE, committed, tooMany, condition(committed)));
  assertEquals("Too many TOTP mutations", refusal.getMessage());
  assertEquals(16, snapshot(store, keys).getEntries().size());
 }

 @Test void exactSixteenReadCarrierDoesNotSilentlyExpandToSeventeen() {
  Map<TotpStoreKey, TotpStoreEntry> entries = new LinkedHashMap<>();
  entries.put(ROOT, TotpStoreEntry.Present.fromRecord(record(ROOT, 1)));
  for (int index = 0; index < 15; index++) {
   TotpStoreKey key = TotpStoreKey.forAccount(NAMESPACE, EPOCH, "accepted-" + index);
   entries.put(key, TotpStoreEntry.Absent.confirmed());
  }
  assertEquals(16, TotpStoreSnapshot.fromEntries(entries.keySet(), entries, healthy()).getEntries().size());
  TotpStoreKey extra = TotpStoreKey.forAccount(NAMESPACE, EPOCH, "rejected-extra");
  entries.put(extra, TotpStoreEntry.Absent.confirmed());
  IllegalArgumentException refusal = assertThrows(IllegalArgumentException.class,
    () -> TotpStoreSnapshot.fromEntries(entries.keySet(), entries, healthy()));
  assertEquals("Incomplete TOTP store snapshot", refusal.getMessage());
 }

 private static @NonNull TotpStoreSnapshot snapshot(@NonNull TotpStore store,
   @NonNull Set<@NonNull TotpStoreKey> keys) {
  return assertInstanceOf(TotpStoreReadResult.Available.class, store.read(keys, BUDGET)).getSnapshot();
 }

 private static @NonNull StoreTemporalCondition condition(@NonNull TotpStoreSnapshot snapshot) {
  StoreTimeObservation.Healthy time = assertInstanceOf(
    StoreTimeObservation.Healthy.class, snapshot.getTimeObservation());
  return StoreTimeAccess.get().fromObservation(time, time.getObservedAt(), null);
 }

 private static @NonNull TotpStoreRecord record(@NonNull TotpStoreKey key, int value) {
  return TotpStoreRecord.fromStoredForm(key, version(value), new byte[] {(byte) value});
 }

 private static @NonNull String version(int value) {
  byte[] bytes = new byte[32];
  Arrays.fill(bytes, (byte) value);
  return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
 }

 private static StoreTimeObservation.@NonNull Healthy healthy() {
  return StoreTimeObservation.Healthy.fromObservation(
    com.revetsec.StoreAdmission.fromIdentifiers(version(101), version(102)), version(103),
    java.time.Instant.ofEpochSecond(1800000000), Duration.ZERO);
 }
}
