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

import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.StoreTimeAccess;
import java.lang.reflect.Field;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class WebAuthnCarrierCapacityConformanceTests {
 private static final Duration BUDGET = Duration.ofSeconds(3);
 private static final String NAMESPACE = "bound01-tenant";
 private static final String RP = "login.example.com";

 @Test void exactEightMutationsRemainSupportedAndNineRefuseBeforeCommit() {
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.fromLimits(8, 8);
  Set<WebAuthnStoreKey> keys = new LinkedHashSet<>();
  for (int index = 0; index < 8; index++) keys.add(credential(index));
  WebAuthnStoreSnapshot empty = snapshot(store, keys);
  List<WebAuthnStoreWrite.Mutation> exactMutations = new ArrayList<>();
  int value = 1;
  for (WebAuthnStoreKey key : keys)
   exactMutations.add(WebAuthnStoreWrite.Mutation.insert(key, new byte[] {(byte) value++}));
  WebAuthnStoreWrite exactWrite = write(empty, exactMutations);
  assertEquals(8, exactWrite.getMutations().size());
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, store.compareAndCommit(exactWrite, BUDGET).getStatus());
  WebAuthnStoreSnapshot committed = snapshot(store, keys);
  value = 1;
  for (WebAuthnStoreKey key : keys)
   assertArrayEquals(new byte[] {(byte) value++}, present(committed, key).getSealedBytes());

  Set<WebAuthnStoreKey> nineKeys = new LinkedHashSet<>(keys);
  WebAuthnStoreKey ninth = credential(8);
  nineKeys.add(ninth);
  WebAuthnStoreSnapshot nineRead = snapshot(store, nineKeys);
  List<WebAuthnStoreWrite.Mutation> tooMany = new ArrayList<>();
  for (WebAuthnStoreKey key : keys)
   tooMany.add(WebAuthnStoreWrite.Mutation.replace(key, new byte[] {9}));
  tooMany.add(WebAuthnStoreWrite.Mutation.insert(ninth, new byte[] {9}));
  IllegalArgumentException refusal = assertThrows(IllegalArgumentException.class,
    () -> write(nineRead, tooMany));
  assertEquals("Too many mutations", refusal.getMessage());
  WebAuthnStoreSnapshot unchanged = snapshot(store, nineKeys);
  assertInstanceOf(WebAuthnStoreEntry.Absent.class, unchanged.getEntry(ninth));
  assertEquals(8, exactWrite.getMutations().size());
 }

 @Test void sequenceExhaustionAtLongMaxRefusesWithoutAnyPartialStorageMutation() throws Exception {
  InMemoryWebAuthnStore store = InMemoryWebAuthnStore.fromLimits(2, 16);
  WebAuthnStoreKey key = credential(90);
  WebAuthnStoreSnapshot before = snapshot(store, Set.of(key));
  WebAuthnStoreWrite insert = write(before,
    List.of(WebAuthnStoreWrite.Mutation.insert(key, new byte[] {1, 2, 3})));

  Field sequenceField = field("sequence");
  sequenceField.setLong(store, Long.MAX_VALUE);
  Object entries = value(store, "entries");
  Object activatedScopes = value(store, "activatedScopes");
  Object versionPrefix = value(store, "versionPrefix");
  long sealedBytes = ((Long) Objects.requireNonNull(value(store, "sealedBytes"))).longValue();

  WebAuthnStoreCommitReceipt refusal = store.compareAndCommit(insert, BUDGET);
  assertEquals(WebAuthnStoreCommitResult.CAPACITY, refusal.getStatus());
  assertTrue(refusal.getTiming().isEmpty());
  assertSame(entries, value(store, "entries"));
  assertSame(activatedScopes, value(store, "activatedScopes"));
  assertNull(versionPrefix);
  assertSame(versionPrefix, value(store, "versionPrefix"));
  assertEquals(Long.MAX_VALUE, sequenceField.getLong(store));
  assertEquals(sealedBytes, ((Long) Objects.requireNonNull(value(store, "sealedBytes"))).longValue());
  assertInstanceOf(WebAuthnStoreEntry.Absent.class, snapshot(store, Set.of(key)).getEntry(key));
 }

 private static @NonNull WebAuthnStoreKey credential(int value) {
  return WebAuthnStoreKey.forCredential(NAMESPACE, RP, new byte[] {(byte) value});
 }

 private static @NonNull WebAuthnStoreSnapshot snapshot(@NonNull WebAuthnStore store,
   @NonNull Set<@NonNull WebAuthnStoreKey> keys) {
  return assertInstanceOf(WebAuthnStoreReadResult.Available.class, store.read(keys, BUDGET)).getSnapshot();
 }

 private static WebAuthnStoreEntry.@NonNull Present present(@NonNull WebAuthnStoreSnapshot snapshot,
   @NonNull WebAuthnStoreKey key) {
  return assertInstanceOf(WebAuthnStoreEntry.Present.class, snapshot.getEntry(key));
 }

 private static @NonNull WebAuthnStoreWrite write(@NonNull WebAuthnStoreSnapshot snapshot,
   @NonNull List<WebAuthnStoreWrite.@NonNull Mutation> mutations) {
  StoreTimeObservation.Healthy time = assertInstanceOf(
    StoreTimeObservation.Healthy.class, snapshot.getTimeObservation());
  return WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot, mutations,
    StoreTimeAccess.get().fromObservation(time, time.getObservedAt(), null));
 }

 private static @NonNull Field field(@NonNull String name) throws Exception {
  Field field = InMemoryWebAuthnStore.class.getDeclaredField(name);
  field.setAccessible(true);
  return field;
 }

 private static @Nullable Object value(@NonNull InMemoryWebAuthnStore store, @NonNull String name) throws Exception {
  return field(name).get(store);
 }
}
