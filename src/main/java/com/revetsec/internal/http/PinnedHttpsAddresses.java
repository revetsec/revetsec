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

import com.revetsec.internal.HostClassifier;
import com.revetsec.internal.Limits;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.ThreadSafe;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import static java.util.Objects.requireNonNull;

/**
 * Copies every resolved numeric answer before a pinned connection can select one. No hostname, reverse lookup,
 * socket or system resolver is used. The supplied-answer cap applies before deduplication. Besides the existing
 * classifier's non-global/metadata rules, CIMD rejects all currently listed special-purpose IPv4 blocks and the
 * AS112 IPv6 prefix, including globally reachable special-purpose services (IANA registries read2026-10-05).
 * Only native unscoped IPv6 in the classifier's global range is eligible; represented mapped/translated/known
 * NAT64 forms cannot pass. A resolver-normalized Inet4Address is an ordinary numeric IPv4 answer; lost original
 * representation cannot be recovered. Network-specific translations require trusted deployment controls.
 */
@ThreadSafe
final class PinnedHttpsAddresses {
 private PinnedHttpsAddresses() {}

 static @NonNull List<@NonNull InetAddress> checked(@NonNull List<@NonNull InetAddress> answers,
   int maximumAnswers, @NonNull Deadline deadline) throws HttpExchangeException {
  requireNonNull(answers); requireNonNull(deadline);
  Limits.CIMD_MAXIMUM_RESOLVED_ADDRESSES.require(maximumAnswers);
  checkBudget(deadline);
  Map<String, InetAddress> copied = new LinkedHashMap<>();
  int count = 0;
  try {
   if (answers.isEmpty() || answers.size() > maximumAnswers) throw rejected();
   for (InetAddress answer : answers) {
    checkBudget(deadline);
    if (++count > maximumAnswers || answer == null) throw rejected();
    if (answer instanceof Inet6Address ipv6 && (ipv6.getScopeId() != 0 || ipv6.getScopedInterface() != null))
     throw rejected();
    byte[] bytes = answer.getAddress().clone();
    checkBudget(deadline);
    String literal = literal(bytes);
    if (!plainAddress(bytes) || HostClassifier.classify(literal) != HostClassifier.HostClass.OTHER_ADDRESS)
     throw rejected();
    copied.putIfAbsent(literal, InetAddress.getByAddress(bytes));
   }
  } catch (UnknownHostException | RuntimeException failure) {
   throw new HttpExchangeException(HttpExchangeException.Kind.IO);
  }
  checkBudget(deadline);
  if (count == 0) throw rejected();
  return List.copyOf(copied.values());
 }

 private static boolean plainAddress(byte @NonNull [] bytes) {
  if (bytes.length == 4) {
   int a = bytes[0] & 255, b = bytes[1] & 255, c = bytes[2] & 255;
   return !(a == 192 && ((b == 0 && c == 0) || (b == 31 && c == 196)
     || (b == 52 && c == 193) || (b == 175 && c == 48)));
  }
  return bytes.length == 16 && (bytes[0] & 224) == 32
    && !(bytes[0] == 0x26 && bytes[1] == 0x20 && bytes[2] == 0 && bytes[3] == 0x4f
      && (bytes[4] & 255) == 0x80 && bytes[5] == 0);
 }

 private static @NonNull String literal(byte @NonNull [] bytes) throws HttpExchangeException {
  if (bytes.length == 4)
   return (bytes[0] & 255) + "." + (bytes[1] & 255) + "." + (bytes[2] & 255) + "." + (bytes[3] & 255);
  if (bytes.length != 16) throw rejected();
  StringBuilder text = new StringBuilder("[");
  for (int i = 0; i < bytes.length; i += 2) {
   if (i != 0) text.append(':');
   text.append(Integer.toHexString(((bytes[i] & 255) << 8) | (bytes[i + 1] & 255)));
  }
  return text.append(']').toString();
 }

 private static @NonNull HttpExchangeException rejected() {
  return new HttpExchangeException(HttpExchangeException.Kind.URI_REJECTED);
 }

 private static void checkBudget(@NonNull Deadline deadline) throws HttpExchangeException {
  if (Thread.currentThread().isInterrupted())
   throw new HttpExchangeException(HttpExchangeException.Kind.INTERRUPTED);
  if (deadline.isExpired()) throw new HttpExchangeException(HttpExchangeException.Kind.TIMEOUT);
 }
}
