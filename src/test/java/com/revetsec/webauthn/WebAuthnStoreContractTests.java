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
import com.revetsec.StoreCommitTiming;
import com.revetsec.StoreTemporalCondition;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.StoreTimeAccess;
import java.time.Duration;
import java.time.Instant;
import org.jspecify.annotations.NonNull;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Arrays;
import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class WebAuthnStoreContractTests {
 private static final String NAMESPACE = "tenant:one";
 private static final String RP = "login.example.com";

 @Test void addressesBindNamespaceRelyingPartyAndKindWithoutRawIdentifiers() {
  byte[] id = {1, 2, 3};
  WebAuthnStoreKey credential = WebAuthnStoreKey.forCredential(NAMESPACE, RP, id);
  String address = credential.getStorageKey();
  id[0] = 9;
  assertEquals(credential, WebAuthnStoreKey.forCredential(NAMESPACE, RP, new byte[] {1, 2, 3}));
  assertEquals(address, credential.getStorageKey());
  assertNotEquals(credential, WebAuthnStoreKey.forCredential("tenant:two", RP, new byte[] {1, 2, 3}));
  assertNotEquals(credential, WebAuthnStoreKey.forCredential(NAMESPACE, "other.example.com", new byte[] {1, 2, 3}));
  assertNotEquals(credential, WebAuthnStoreKey.forAccountFence(NAMESPACE, RP, new byte[] {1, 2, 3}));
  WebAuthnStoreKey namespaceClock = WebAuthnStoreKey.forNamespaceClock(NAMESPACE, RP);
  assertNotEquals(credential, namespaceClock);
  assertEquals(namespaceClock, WebAuthnStoreKey.forNamespaceClock(NAMESPACE, RP));
  assertNotEquals(namespaceClock, WebAuthnStoreKey.forNamespaceClock("tenant:two", RP));
  assertNotEquals(namespaceClock, WebAuthnStoreKey.forNamespaceClock(NAMESPACE, "other.example.com"));
  assertFalse(namespaceClock.toString().contains(namespaceClock.getStorageKey()));
  assertFalse(address.contains(RP));
  assertFalse(address.contains(NAMESPACE));
  assertFalse(address.contains("AQID"));
  assertFalse(credential.toString().contains(address));
 }

 @Test @SuppressWarnings("NullAway") // Deliberate required-argument misuse.
 void keyFactoriesRejectWrongBinaryBoundsAndNoncanonicalAddresses() {
  assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreKey.forCeremony(NAMESPACE, RP, new byte[31]));
  assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreKey.forCredential(NAMESPACE, RP, new byte[0]));
  assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreKey.forCredential(NAMESPACE, RP, new byte[1024]));
  assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreKey.forAccountFence(NAMESPACE, RP, new byte[65]));
  assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreKey.forCredential(NAMESPACE, "Login.example.com", new byte[] {1}));
  assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreKey.forCredential(NAMESPACE, "login.example.com.", new byte[] {1}));
  assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreKey.forCredential(NAMESPACE, "127.0.0.1", new byte[] {1}));
  assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreKey.forCredential("bad\nnamespace", RP, new byte[] {1}));
  assertThrows(NullPointerException.class, () -> WebAuthnStoreKey.forCredential(NAMESPACE, RP, null));
  assertEquals(WebAuthnStoreKey.Kind.CEREMONY,
    WebAuthnStoreKey.forCeremony(NAMESPACE, RP, new byte[32]).getKind());
 }

 @Test void snapshotRequiresExplicitObservationForEveryRequestedKey() {
  WebAuthnStoreKey ceremony = WebAuthnStoreKey.forCeremony(NAMESPACE, RP, new byte[32]);
  WebAuthnStoreKey fence = WebAuthnStoreKey.forAccountFence(NAMESPACE, RP, new byte[] {7});
  Map<WebAuthnStoreKey, WebAuthnStoreEntry> partial = Map.of(ceremony, WebAuthnStoreEntry.Absent.confirmed());
  assertThrows(IllegalArgumentException.class,
    () -> snapshot(Set.of(ceremony, fence), partial));
  assertThrows(IllegalArgumentException.class,
    () -> snapshot(Set.of(ceremony), Map.of(fence, WebAuthnStoreEntry.Absent.confirmed())));
  Map<WebAuthnStoreKey, WebAuthnStoreEntry> complete = new HashMap<>(partial);
  complete.put(fence, WebAuthnStoreEntry.Absent.confirmed());
  WebAuthnStoreSnapshot snapshot = snapshot(Set.of(ceremony, fence), complete);
  complete.clear();
  assertEquals(Set.of(ceremony, fence), snapshot.getEntries().keySet());
  assertTrue(snapshot.getEntry(fence) instanceof WebAuthnStoreEntry.Absent);
  assertThrows(IllegalArgumentException.class, () -> snapshot.getEntry(
    WebAuthnStoreKey.forCredential(NAMESPACE, RP, new byte[] {7})));
  assertThrows(UnsupportedOperationException.class,
    () -> snapshot.getEntries().put(fence, WebAuthnStoreEntry.Absent.confirmed()));
 }

 @Test void versionsAndSealedRecordsAreBoundedCopiedAndRedacted() {
  byte[] version = {4};
  byte[] sealed = "sealed-secret".getBytes(StandardCharsets.US_ASCII);
  WebAuthnStoreEntry.Present present = WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(version, sealed);
  version[0] = 0; sealed[0] = 0;
  assertArrayEquals(new byte[] {4}, present.getVersion());
  assertArrayEquals("sealed-secret".getBytes(StandardCharsets.US_ASCII), present.getSealedBytes());
  present.getVersion()[0] = 9; present.getSealedBytes()[0] = 9;
  assertArrayEquals(new byte[] {4}, present.getVersion());
  assertArrayEquals("sealed-secret".getBytes(StandardCharsets.US_ASCII), present.getSealedBytes());
  assertFalse(present.toString().contains("secret"));
  assertThrows(IllegalArgumentException.class,
    () -> WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[0], new byte[] {1}));
  assertThrows(IllegalArgumentException.class,
    () -> WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[] {1}, new byte[262145]));
 }

 @Test @SuppressWarnings("NullAway") // Deliberate required-argument misuse.
 void writeRequiresExactPriorStateAndNoRepeatedOrUnobservedChanges() {
  WebAuthnStoreKey absent = WebAuthnStoreKey.forCeremony(NAMESPACE, RP, new byte[32]);
  WebAuthnStoreKey present = WebAuthnStoreKey.forCredential(NAMESPACE, RP, new byte[] {3});
  WebAuthnStoreKey unobserved = WebAuthnStoreKey.forCredential(NAMESPACE, RP, new byte[] {4});
  WebAuthnStoreSnapshot snapshot = snapshot(Set.of(absent, present), Map.of(
    absent, WebAuthnStoreEntry.Absent.confirmed(),
    present, WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[] {1}, new byte[] {2})));
  byte[] payload = {5};
  WebAuthnStoreWrite.Mutation insertion = WebAuthnStoreWrite.Mutation.insert(absent, payload);
  payload[0] = 8;
  assertArrayEquals(new byte[] {5}, insertion.getSealedBytes().orElseThrow());
  insertion.getSealedBytes().orElseThrow()[0] = 7;
  assertArrayEquals(new byte[] {5}, insertion.getSealedBytes().orElseThrow());
  WebAuthnStoreWrite write = write(snapshot,
    List.of(insertion, WebAuthnStoreWrite.Mutation.delete(present)));
  assertEquals(2, write.getMutations().size());
  assertEquals(2, write.getSnapshot().getEntries().size());
  assertTrue(write(snapshot, List.of()).getMutations().isEmpty());
  assertThrows(NullPointerException.class, () -> write(null, List.of()));
  assertThrows(IllegalArgumentException.class, () -> write(snapshot,
    List.of(WebAuthnStoreWrite.Mutation.insert(present, new byte[] {1}))));
  assertThrows(IllegalArgumentException.class, () -> write(snapshot,
    List.of(WebAuthnStoreWrite.Mutation.replace(absent, new byte[] {1}))));
  assertThrows(IllegalArgumentException.class, () -> write(snapshot,
    List.of(WebAuthnStoreWrite.Mutation.delete(absent))));
  assertThrows(IllegalArgumentException.class, () -> write(snapshot,
    List.of(WebAuthnStoreWrite.Mutation.delete(unobserved))));
  assertThrows(IllegalArgumentException.class, () -> write(snapshot,
    List.of(insertion, insertion)));
  assertFalse(write.toString().contains(absent.getStorageKey()));
  assertFalse(insertion.toString().contains(absent.getStorageKey()));
 }

 @Test @SuppressWarnings("NullAway") // Required argument and collection-member contract misuse.
 void snapshotRequiresTimeAndSingleNamespaceRpScopeBeforeAnyBackendUse() {
  WebAuthnStoreKey key = WebAuthnStoreKey.forCredential(NAMESPACE, RP, new byte[] {1});
  WebAuthnStoreKey otherNamespace = WebAuthnStoreKey.forCredential("other-tenant", RP, new byte[] {2});
  WebAuthnStoreKey otherRp = WebAuthnStoreKey.forCredential(NAMESPACE, "other.example.com", new byte[] {2});
  StoreTimeObservation.Healthy time = healthy();
  Map<WebAuthnStoreKey, WebAuthnStoreEntry> entries = Map.of(key, WebAuthnStoreEntry.Absent.confirmed());
  assertThrows(NullPointerException.class, () -> WebAuthnStoreSnapshot.fromEntries(Set.of(key), entries, null));
  assertThrows(NullPointerException.class, () -> WebAuthnStoreSnapshot.fromEntries(null, entries, time));
  assertThrows(NullPointerException.class, () -> WebAuthnStoreSnapshot.fromEntries(Set.of(key), null, time));
  assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreSnapshot.fromEntries(Set.of(), Map.of(), time));
  for (WebAuthnStoreKey other : List.of(otherNamespace, otherRp))
   assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreSnapshot.fromEntries(Set.of(key, other),
     Map.of(key, WebAuthnStoreEntry.Absent.confirmed(), other, WebAuthnStoreEntry.Absent.confirmed()), time));
  Set<WebAuthnStoreKey> badKeys = new HashSet<>(); badKeys.add(null);
  Map<WebAuthnStoreKey, WebAuthnStoreEntry> badEntries = new HashMap<>(); badEntries.put(null, WebAuthnStoreEntry.Absent.confirmed());
  assertThrows(NullPointerException.class, () -> WebAuthnStoreSnapshot.fromEntries(badKeys, badEntries, time));
  Map<WebAuthnStoreKey, WebAuthnStoreEntry> nullValue = new HashMap<>(); nullValue.put(key, null);
  assertThrows(NullPointerException.class, () -> WebAuthnStoreSnapshot.fromEntries(Set.of(key), nullValue, time));
  WebAuthnStoreSnapshot value = WebAuthnStoreSnapshot.fromEntries(Set.of(key), entries, time);
  assertSame(time, value.getTimeObservation());
  assertThrows(NullPointerException.class, () -> value.getEntry(null));
 }

 @Test void seventeenKeysRemainUnsupportedAndCompleteAbsenceDoesNotConsumeMetadataSlots() {
  Set<WebAuthnStoreKey> keys = new HashSet<>(); Map<WebAuthnStoreKey, WebAuthnStoreEntry> entries = new HashMap<>();
  for (int i = 0; i < 16; i++) { WebAuthnStoreKey key = WebAuthnStoreKey.forCredential(NAMESPACE, RP, new byte[] {(byte)i}); keys.add(key); entries.put(key, WebAuthnStoreEntry.Absent.confirmed()); }
  assertEquals(16, WebAuthnStoreSnapshot.fromEntries(keys, entries, healthy()).getEntries().size());
  WebAuthnStoreKey extra = WebAuthnStoreKey.forCredential(NAMESPACE, RP, new byte[] {16}); keys.add(extra); entries.put(extra, WebAuthnStoreEntry.Absent.confirmed());
  assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreSnapshot.fromEntries(keys, entries, healthy()));
 }

 @Test @SuppressWarnings("NullAway") // Explicit required-condition contract misuse.
 void temporalWriteRequiresHealthyMatchingTupleAndNonregressingFloor() {
  WebAuthnStoreKey key = WebAuthnStoreKey.forNamespaceClock(NAMESPACE, RP);
  StoreTimeObservation.Healthy time = healthy(); Map<WebAuthnStoreKey, WebAuthnStoreEntry> entries = Map.of(key, WebAuthnStoreEntry.Absent.confirmed());
  WebAuthnStoreSnapshot snapshot = WebAuthnStoreSnapshot.fromEntries(Set.of(key), entries, time);
  StoreTemporalCondition condition = StoreTimeAccess.get().fromObservation(time, time.getObservedAt(), time.getObservedAt().plusSeconds(1));
  WebAuthnStoreWrite barrier = WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot, List.of(), condition);
  assertSame(condition, barrier.getTemporalCondition()); assertTrue(barrier.getMutations().isEmpty());
  assertThrows(NullPointerException.class, () -> WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot, List.of(), null));
  assertThrows(NullPointerException.class, () -> WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot, null, condition));
  assertThrows(NullPointerException.class, () -> WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot, Arrays.asList((WebAuthnStoreWrite.Mutation)null), condition));
  WebAuthnStoreSnapshot unavailable = WebAuthnStoreSnapshot.fromEntries(Set.of(key), entries, StoreTimeObservation.Unavailable.fromAdmission(time.getAdmission()));
  assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreWrite.fromSnapshotAndMutations(unavailable, List.of(), condition));
  StoreTimeObservation.Healthy earlier = StoreTimeObservation.Healthy.fromObservation(time.getAdmission(), time.getClockGeneration(), time.getObservedAt().minusNanos(1), time.getMaximumUtcError());
  StoreTemporalCondition behind = StoreTimeAccess.get().fromObservation(earlier, earlier.getObservedAt(), null);
  assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot, List.of(), behind));
  StoreTimeObservation.Healthy changedClock = StoreTimeObservation.Healthy.fromObservation(time.getAdmission(),
    "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA", time.getObservedAt(), time.getMaximumUtcError());
  assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot, List.of(),
    StoreTimeAccess.get().fromObservation(changedClock, changedClock.getObservedAt(), null)));
  StoreAdmission changedAdmission = StoreAdmission.fromIdentifiers(time.getAdmission().getAuthorityId(), "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA");
  StoreTimeObservation.Healthy changedRecovery = StoreTimeObservation.Healthy.fromObservation(changedAdmission, time.getClockGeneration(), time.getObservedAt(), time.getMaximumUtcError());
  assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot, List.of(),
    StoreTimeAccess.get().fromObservation(changedRecovery, changedRecovery.getObservedAt(), null)));
 }

 @Test @SuppressWarnings("NullAway") // Receipt factories reject explicitly illegal shapes.
 void contextualReceiptRetainsTimingOnlyForKnownCommitAndRedactsAllMetadata() {
  StoreCommitTiming timing = StoreCommitTiming.fromTimes(healthy(), null);
  WebAuthnStoreCommitReceipt committed = WebAuthnStoreCommitReceipt.fromCommittedTiming(timing);
  assertEquals(WebAuthnStoreCommitResult.COMMITTED, committed.getStatus()); assertSame(timing, committed.getTiming().orElseThrow());
  assertThrows(NullPointerException.class, () -> WebAuthnStoreCommitReceipt.fromCommittedTiming(null));
  assertThrows(NullPointerException.class, () -> WebAuthnStoreCommitReceipt.fromRefusal(null));
  for (WebAuthnStoreCommitResult status : WebAuthnStoreCommitResult.values()) {
   if (status == WebAuthnStoreCommitResult.COMMITTED || status == WebAuthnStoreCommitResult.UNKNOWN) {
    assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreCommitReceipt.fromRefusal(status));
   } else {
    WebAuthnStoreCommitReceipt refusal = WebAuthnStoreCommitReceipt.fromRefusal(status);
    assertEquals(status, refusal.getStatus()); assertTrue(refusal.getTiming().isEmpty());
   }
  }
  WebAuthnStoreCommitReceipt unknown = WebAuthnStoreCommitReceipt.unknownInstance();
  assertEquals(WebAuthnStoreCommitResult.UNKNOWN, unknown.getStatus()); assertTrue(unknown.getTiming().isEmpty());
  assertEquals("WebAuthnStoreCommitReceipt{receipt=<redacted>}", committed.toString());
  assertEquals(0, WebAuthnStoreCommitReceipt.class.getConstructors().length);
  assertEquals(6, Arrays.stream(WebAuthnStoreCommitReceipt.class.getDeclaredMethods()).filter(m -> Modifier.isPublic(m.getModifiers())).count());
 }

 @Test void fencedReadIsDistinctPayloadFreeSingletonAndStatusesHaveExactSelectedOrder() {
  assertSame(WebAuthnStoreReadResult.Fenced.get(), WebAuthnStoreReadResult.Fenced.get());
  assertInstanceOf(WebAuthnStoreReadResult.Fenced.class, WebAuthnStoreReadResult.Fenced.get());
  assertEquals("Fenced{}", WebAuthnStoreReadResult.Fenced.get().toString());
  assertEquals(0, WebAuthnStoreReadResult.Fenced.class.getConstructors().length);
  assertEquals(List.of("COMMITTED", "CONFLICT", "CAPACITY", "FENCED", "TIME_UNAVAILABLE", "TIME_BEFORE_FLOOR", "TIME_EXPIRED", "UNAVAILABLE", "UNKNOWN"),
    Arrays.stream(WebAuthnStoreCommitResult.values()).map(Enum::name).toList());
 }

 private static StoreTimeObservation.@NonNull Healthy healthy() {
  return StoreTimeObservation.Healthy.fromObservation(StoreAdmission.fromIdentifiers(
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"),
    "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA", Instant.ofEpochSecond(1700000000), Duration.ofMillis(250));
 }
 private static @NonNull WebAuthnStoreSnapshot snapshot(@NonNull Set<@NonNull WebAuthnStoreKey> keys,
   @NonNull Map<@NonNull WebAuthnStoreKey, @NonNull WebAuthnStoreEntry> entries) {
  return WebAuthnStoreSnapshot.fromEntries(keys, entries, healthy());
 }
 private static @NonNull WebAuthnStoreWrite write(@NonNull WebAuthnStoreSnapshot snapshot,
   @NonNull List<WebAuthnStoreWrite.@NonNull Mutation> changes) {
  StoreTimeObservation.Healthy time = (StoreTimeObservation.Healthy) snapshot.getTimeObservation();
  return WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot, changes,
    StoreTimeAccess.get().fromObservation(time, time.getObservedAt(), null));
 }

}
