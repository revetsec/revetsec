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

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
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
    () -> WebAuthnStoreSnapshot.fromEntries(Set.of(ceremony, fence), partial));
  assertThrows(IllegalArgumentException.class,
    () -> WebAuthnStoreSnapshot.fromEntries(Set.of(ceremony), Map.of(fence, WebAuthnStoreEntry.Absent.confirmed())));
  Map<WebAuthnStoreKey, WebAuthnStoreEntry> complete = new HashMap<>(partial);
  complete.put(fence, WebAuthnStoreEntry.Absent.confirmed());
  WebAuthnStoreSnapshot snapshot = WebAuthnStoreSnapshot.fromEntries(Set.of(ceremony, fence), complete);
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
  WebAuthnStoreSnapshot snapshot = WebAuthnStoreSnapshot.fromEntries(Set.of(absent, present), Map.of(
    absent, WebAuthnStoreEntry.Absent.confirmed(),
    present, WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[] {1}, new byte[] {2})));
  byte[] payload = {5};
  WebAuthnStoreWrite.Mutation insertion = WebAuthnStoreWrite.Mutation.insert(absent, payload);
  payload[0] = 8;
  assertArrayEquals(new byte[] {5}, insertion.getSealedBytes().orElseThrow());
  insertion.getSealedBytes().orElseThrow()[0] = 7;
  assertArrayEquals(new byte[] {5}, insertion.getSealedBytes().orElseThrow());
  WebAuthnStoreWrite write = WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot,
    List.of(insertion, WebAuthnStoreWrite.Mutation.delete(present)));
  assertEquals(2, write.getMutations().size());
  assertEquals(2, write.getSnapshot().getEntries().size());
  assertTrue(WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot, List.of()).getMutations().isEmpty());
  assertThrows(NullPointerException.class, () -> WebAuthnStoreWrite.fromSnapshotAndMutations(null, List.of()));
  assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot,
    List.of(WebAuthnStoreWrite.Mutation.insert(present, new byte[] {1}))));
  assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot,
    List.of(WebAuthnStoreWrite.Mutation.replace(absent, new byte[] {1}))));
  assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot,
    List.of(WebAuthnStoreWrite.Mutation.delete(absent))));
  assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot,
    List.of(WebAuthnStoreWrite.Mutation.delete(unobserved))));
  assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot,
    List.of(insertion, insertion)));
  assertFalse(write.toString().contains(absent.getStorageKey()));
  assertFalse(insertion.toString().contains(absent.getStorageKey()));
 }
}
