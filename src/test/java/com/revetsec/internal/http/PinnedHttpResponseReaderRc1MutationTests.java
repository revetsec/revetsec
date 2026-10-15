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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/** Exact raw-byte and total-framing boundaries retained from RC-1 mutation qualification. */
final class PinnedHttpResponseReaderRc1MutationTests {
 private static final String PREFIX = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n";

 @Test void nulBytesArePreservedByFixedAndEofDelimitedBodies() throws Exception {
  for (String headers : List.of("Content-Length: 3\r\n", "")) {
   byte[] body = {0, 1, 0};
   ByteArrayOutputStream wire = new ByteArrayOutputStream();
   wire.writeBytes((PREFIX + headers + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
   wire.writeBytes(body);
   Assertions.assertArrayEquals(body, read(wire.toByteArray()).body());
  }
 }

 @Test void everyAsciiLetterAndDigitBoundaryIsLegalInHeaderAndExtensionTokens() throws Exception {
  for (String token : List.of("0", "9", "A", "Z", "a", "z")) {
   String wire = PREFIX + token + ": value\r\nTransfer-Encoding: chunked\r\n\r\n1;" + token + "=ok\r\nx\r\n0\r\n\r\n";
   Assertions.assertArrayEquals(new byte[]{'x'}, read(wire.getBytes(StandardCharsets.ISO_8859_1)).body());
  }
 }

 @Test void legalChunkExtensionAndQuotedEscapeMakeBoundedForwardProgress() {
  Assertions.assertTimeoutPreemptively(Duration.ofSeconds(2), () -> {
   for (String extension : List.of(";flag", ";flag=value", ";flag=\"escaped\\\"quote\"")) {
    byte[] wire = (PREFIX + "Transfer-Encoding: chunked\r\n\r\n1" + extension + "\r\nx\r\n0\r\n\r\n")
      .getBytes(StandardCharsets.ISO_8859_1);
    Assertions.assertArrayEquals(new byte[]{'x'}, read(wire).body());
   }
  });
 }

 @Test void lowercaseAndUppercaseFinalHexDigitAreAccepted() throws Exception {
  for (String hex : List.of("f", "F")) {
   String wire = PREFIX + "Transfer-Encoding: chunked\r\n\r\n" + hex + "\r\n" + "x".repeat(15) + "\r\n0\r\n\r\n";
   Assertions.assertEquals(15, read(wire.getBytes(StandardCharsets.ISO_8859_1)).body().length);
  }
 }

 @Test void oversizedChunkCannotOverflowItsAnnouncedSize() {
  for (String hex : List.of("401;", "80000000", "ffffffffffffffff", "100000000")) {
   HttpExchangeException failure = Assertions.assertThrows(HttpExchangeException.class,
     () -> read((PREFIX + "Transfer-Encoding: chunked\r\n\r\n" + hex + "\r\n").getBytes(StandardCharsets.ISO_8859_1)));
   Assertions.assertEquals(HttpExchangeException.Kind.TOO_LARGE, failure.getKind());
  }
 }

 @Test void totalWireBudgetIncludesNulBodyBytesAndAdmitsTheExactBoundary() throws Exception {
  int cap = PinnedHttpResponseReader.MAXIMUM_FRAMING_BYTES + 1024;
  byte[] atBoundary = chunkedWire(cap);
  Assertions.assertEquals(cap, atBoundary.length);
  Assertions.assertEquals(9, read(atBoundary).body().length);
  HttpExchangeException failure = Assertions.assertThrows(HttpExchangeException.class, () -> read(chunkedWire(cap + 1)));
  Assertions.assertEquals(HttpExchangeException.Kind.FRAMING, failure.getKind());
 }

 @Test void callbackInterruptionWinsOverMalformedReturnedOctet() {
  try {
   HttpExchangeException failure = Assertions.assertThrows(HttpExchangeException.class,
     () -> PinnedHttpResponseReader.read(() -> { Thread.currentThread().interrupt(); return 256; },
       1024, Deadline.fromNow(Duration.ofSeconds(10)), System.nanoTime()));
   Assertions.assertEquals(HttpExchangeException.Kind.INTERRUPTED, failure.getKind());
   Assertions.assertTrue(Thread.currentThread().isInterrupted());
  } finally { Thread.interrupted(); }
 }

 @Test void elapsedMetadataMeasuresDurationSinceExchangeStart() throws Exception {
  long before = System.nanoTime();
  RawResponse response = read((PREFIX + "Content-Length: 0\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1), before);
  long after = System.nanoTime();
  Assertions.assertFalse(response.elapsed().isNegative());
  Assertions.assertTrue(response.elapsed().toNanos() <= after - before);
 }

 @Test void finalPublicationGuardRefusesInterruptedOrExpiredCall() throws Exception {
  // Isolate the last guard after framing work; a concurrent interrupt or expiry can occur after the last byte.
  Constructor<PinnedHttpResponseReader> constructor = PinnedHttpResponseReader.class.getDeclaredConstructor(
    PinnedHttpResponseReader.ByteReader.class, int.class, Deadline.class);
  constructor.setAccessible(true);
  Method result = PinnedHttpResponseReader.class.getDeclaredMethod("result", int.class, HttpHeaders.class,
    byte[].class, MediaType.class, boolean.class, long.class);
  result.setAccessible(true);
  for (boolean interrupted : List.of(false, true)) {
   PinnedHttpResponseReader reader = constructor.newInstance((PinnedHttpResponseReader.ByteReader) () -> -1,
     1024, Deadline.fromNow(interrupted ? Duration.ofSeconds(10) : Duration.ZERO));
   try {
    if (interrupted) Thread.currentThread().interrupt();
    InvocationTargetException wrapper = Assertions.assertThrows(InvocationTargetException.class,
      () -> result.invoke(reader, 200, HttpHeaders.of(Map.of(), (name, value) -> true), new byte[0], null, false, System.nanoTime()));
    HttpExchangeException failure = Assertions.assertInstanceOf(HttpExchangeException.class, wrapper.getCause());
    Assertions.assertEquals(interrupted ? HttpExchangeException.Kind.INTERRUPTED : HttpExchangeException.Kind.TIMEOUT, failure.getKind());
   } finally { Thread.interrupted(); }
  }
 }

 private static byte @NonNull [] chunkedWire(int target) {
  String prefix = PREFIX + "Transfer-Encoding: chunked\r\n\r\n";
  // Nine 1-byte chunks allow bounded individual extension lines to consume the full aggregate framing budget.
  int padding = target - prefix.length() - 5 - 9 * 9;
  ByteArrayOutputStream wire = new ByteArrayOutputStream();
  wire.writeBytes(prefix.getBytes(StandardCharsets.ISO_8859_1));
  for (int i = 0; i < 9; ++i) {
   int thisPadding = Math.min(padding, 8185);
   wire.writeBytes(("1;x=" + "a".repeat(thisPadding) + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
   wire.write(0);
   wire.writeBytes("\r\n".getBytes(StandardCharsets.ISO_8859_1));
   padding -= thisPadding;
  }
  Assertions.assertEquals(0, padding);
  wire.writeBytes("0\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
  return wire.toByteArray();
 }

 private static @NonNull RawResponse read(byte @NonNull [] bytes) throws HttpExchangeException { return read(bytes, System.nanoTime()); }
 private static @NonNull RawResponse read(byte @NonNull [] bytes, long started) throws HttpExchangeException {
  return Assertions.assertTimeoutPreemptively(Duration.ofSeconds(2), () -> {
   int[] position = {0};
   return PinnedHttpResponseReader.read(() -> position[0] == bytes.length ? -1 : bytes[position[0]++] & 255,
     1024, Deadline.fromNow(Duration.ofSeconds(10)), started);
  });
 }
}
