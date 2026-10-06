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

package com.revetsec.internal.http;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Iterator;
import java.util.stream.Stream;

final class PinnedHttpsAddressesTests {
 private static final Duration BUDGET = Duration.ofSeconds(10);

 @TestFactory
 @NonNull Stream<@NonNull DynamicTest> everyUnsafeAnswerRejectsTheWholeSet() {
  return Stream.of("0.0.0.0", "0.255.255.255", "10.0.0.1", "100.64.0.0", "100.127.255.255",
    "127.0.0.1", "127.255.255.255", "169.254.0.1", "172.16.0.0", "172.31.255.255", "192.168.0.1",
    "100.100.100.200", "168.63.129.16", "192.0.0.0", "192.0.0.9", "192.0.0.10", "192.0.0.255",
    "192.0.2.1", "192.31.196.0", "192.31.196.255", "192.52.193.0", "192.52.193.255",
    "192.88.99.1", "192.175.48.0", "192.175.48.255", "198.18.0.0", "198.19.255.255",
    "198.51.100.1", "203.0.113.1", "224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255",
    "::", "::1", "::8.8.8.8", "::ffff:8.8.8.8", "::ffff:0:8.8.8.8", "64:ff9b::808:808",
    "64:ff9b:1::808:808", "fe80::1", "fc00::1", "fd00:ec2::254", "fd00:ec2::23", "fd20:ce::254",
    "ff02::1", "2002:808:808::1", "2001::1", "2001:1::1", "2001:db8::1", "3fff::1",
    "2620:4f:8000::1", "4000::1").map(text -> DynamicTest.dynamicTest(text, () -> {
     InetAddress unsafe = numeric(text);
     rejected(List.of(numeric("8.8.8.8"), unsafe));
     rejected(List.of(unsafe, numeric("1.1.1.1")));
    }));
 }

 @TestFactory
 @NonNull Stream<@NonNull DynamicTest> ordinaryAddressesAndSpecialBlockBoundariesPass() {
  return Stream.of("1.1.1.1", "8.8.8.8", "100.63.255.255", "100.128.0.0", "172.15.255.255",
    "172.32.0.0", "192.0.1.0", "192.31.195.255", "192.31.197.0", "192.52.192.255",
    "192.52.194.0", "192.175.47.255", "192.175.49.0", "198.17.255.255", "198.20.0.0",
    "223.255.255.255", "2001:4860::8888", "2606:4700::1111", "2620:4f:7fff::1",
    "2620:4f:8001::1").map(text -> DynamicTest.dynamicTest(text, () -> {
     InetAddress original = numeric(text);
     List<InetAddress> copied = checked(List.of(original), 16);
     Assertions.assertEquals(1, copied.size());
     Assertions.assertArrayEquals(original.getAddress(), copied.get(0).getAddress());
     Assertions.assertNotSame(original, copied.get(0));
    }));
 }

 @Test
 void snapshotsAndDeduplicatesWithoutRetainingResolverHostnames() throws Exception {
  byte[] bytes = {8, 8, 8, 8};
  InetAddress named = InetAddress.getByAddress("metadata.google.internal", bytes);
  List<InetAddress> original = new ArrayList<>(List.of(named, numeric("1.1.1.1"), named));
  List<InetAddress> copied = checked(original, 3);
  original.clear(); bytes[0] = 127;
  Assertions.assertEquals(2, copied.size());
  Assertions.assertArrayEquals(new byte[]{8, 8, 8, 8}, copied.get(0).getAddress());
  Assertions.assertFalse(copied.get(0).toString().contains("metadata.google.internal"));
  Assertions.assertThrows(UnsupportedOperationException.class, () -> copied.add(named));
 }

 @Test
 void boundsAllSuppliedAnswersBeforeDeduplication() throws Exception {
  InetAddress address = numeric("8.8.8.8");
  Assertions.assertEquals(1, checked(List.of(address, address), 2).size());
  HttpExchangeException failure = Assertions.assertThrows(HttpExchangeException.class,
    () -> checked(List.of(address, address), 1));
  Assertions.assertEquals(HttpExchangeException.Kind.URI_REJECTED, failure.getKind());
  Assertions.assertEquals(1, checked(java.util.Collections.nCopies(64, address), 64).size());
  Assertions.assertThrows(IllegalArgumentException.class, () -> checked(List.of(address), 0));
  Assertions.assertThrows(IllegalArgumentException.class, () -> checked(List.of(address), 65));
 }

 @Test
 void rejectsEmptyScopedAndNullAnswers() throws Exception {
  rejected(List.of());
  rejected(Arrays.asList((@Nullable InetAddress) null));
  byte[] global = numeric("2001:4860::8888").getAddress();
  rejected(List.of(Inet6Address.getByAddress(null, global, 1)));
 }

 @Test
 void checksActualIterationCountAndRedactsProviderFaults() throws Exception {
  InetAddress address = numeric("8.8.8.8");
  List<InetAddress> misleading = new AbstractList<>() {
   @Override public int size() { return 1; }
   @Override public @NonNull InetAddress get(int index) {
    if (index > 1) throw new IndexOutOfBoundsException();
    return address;
   }
   @Override public @NonNull Iterator<@NonNull InetAddress> iterator() {
    return List.of(address, address).iterator();
   }
  };
  Assertions.assertEquals(HttpExchangeException.Kind.URI_REJECTED,
    Assertions.assertThrows(HttpExchangeException.class, () -> checked(misleading, 1)).getKind());
  List<InetAddress> broken = new AbstractList<>() {
   @Override public int size() { throw new IllegalStateException("REMOTE_SENTINEL"); }
   @Override public @NonNull InetAddress get(int index) { throw new IllegalStateException("REMOTE_SENTINEL"); }
  };
  HttpExchangeException failure = Assertions.assertThrows(HttpExchangeException.class, () -> checked(broken, 16));
  Assertions.assertEquals(HttpExchangeException.Kind.IO, failure.getKind());
  Assertions.assertNull(failure.getCause());
  Assertions.assertFalse(failure.toString().contains("REMOTE_SENTINEL"));
 }

 @Test
 @SuppressWarnings("NullAway") // Explicit tests of required-input null checks.
 void deadlineAndInterruptionPreventInspectionAndPreserveFlags() throws Exception {
  InetAddress address = numeric("8.8.8.8");
  List<InetAddress> untouched = new AbstractList<>() {
   @Override public int size() { throw new AssertionError("must not inspect expired/interrupt input"); }
   @Override public @NonNull InetAddress get(int index) { throw new AssertionError("must not inspect input"); }
  };
  Assertions.assertEquals(HttpExchangeException.Kind.TIMEOUT, Assertions.assertThrows(HttpExchangeException.class,
    () -> PinnedHttpsAddresses.checked(untouched, 16, Deadline.fromNow(Duration.ZERO))).getKind());
  Thread.currentThread().interrupt();
  try {
   Assertions.assertEquals(HttpExchangeException.Kind.INTERRUPTED,
     Assertions.assertThrows(HttpExchangeException.class, () -> checked(untouched, 16)).getKind());
   Assertions.assertTrue(Thread.currentThread().isInterrupted());
  } finally { Thread.interrupted(); }
  Assertions.assertThrows(NullPointerException.class, () -> PinnedHttpsAddresses.checked(null, 16, Deadline.fromNow(BUDGET)));
  Assertions.assertThrows(NullPointerException.class, () -> PinnedHttpsAddresses.checked(List.of(address), 16, null));
 }

 @Test
 void aMisleadingNonemptyListWithNoActualAnswersCannotEstablishAPeer() {
  List<InetAddress> empty = new AbstractList<>() {
   @Override public int size() { return 1; }
   @Override public @NonNull InetAddress get(int index) { throw new AssertionError(); }
   @Override public @NonNull Iterator<@NonNull InetAddress> iterator() { return List.<InetAddress>of().iterator(); }
  };
  rejected(empty);
 }

 private static @NonNull List<@NonNull InetAddress> checked(@NonNull List<@NonNull InetAddress> addresses, int cap)
   throws HttpExchangeException {
  return PinnedHttpsAddresses.checked(addresses, cap, Deadline.fromNow(BUDGET));
 }

 private static void rejected(@NonNull List<@NonNull InetAddress> addresses) {
  HttpExchangeException failure = Assertions.assertThrows(HttpExchangeException.class, () -> checked(addresses, 16));
  Assertions.assertEquals(HttpExchangeException.Kind.URI_REJECTED, failure.getKind());
  Assertions.assertNull(failure.getCause());
 }

 private static @NonNull InetAddress numeric(@NonNull String text) throws UnknownHostException {
  // Test input is fixed numeric text only. Keep mapped forms as16bytes instead of the JDK's IPv4 normalization.
  InetAddress parsed = InetAddress.getByName(text);
  if (text.indexOf(':') >= 0 && parsed.getAddress().length == 4) {
   byte[] mapped = new byte[16]; mapped[10] = (byte) 255; mapped[11] = (byte) 255;
   System.arraycopy(parsed.getAddress(), 0, mapped, 12, 4);
   return Inet6Address.getByAddress(null, mapped, 0);
  }
  return parsed;
 }
}
