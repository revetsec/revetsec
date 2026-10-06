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
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

final class PinnedHttpResponseReaderTests {
 private static final Duration BUDGET = Duration.ofSeconds(10);
 private static final String JSON = "Content-Type: application/json\r\n";

 @TestFactory
 @NonNull Stream<@NonNull DynamicTest> malformedStatusAndHeaderGrammarRejects() {
  return Stream.of("", "HTTP/1.1 200", "HTTP/1.0 200 OK\r\n\r\n", "HTTP/2 200 OK\r\n\r\n",
    "HTTP/1.1 099 Bad\r\n\r\n", "HTTP/1.1 600 Bad\r\n\r\n", "HTTP/1.1 2a0 Bad\r\n\r\n",
    "HTTP/1.1 20a Bad\r\n\r\n", "HTTP/1.1 200xBad\r\n\r\n", "HTTP/1.1 200 OK\n\n",
    "HTTP/1.1 200 OK\rX", "HTTP/1.1 200 OK\r\n Content-Type: application/json\r\n\r\n",
    "HTTP/1.1 200 OK\r\nContent-Type : application/json\r\n\r\n",
    "HTTP/1.1 200 OK\r\n: empty\r\n\r\n", "HTTP/1.1 200 OK\r\nX@bad: value\r\n\r\n",
    "HTTP/1.1 200 OK\r\nX: \u0000\r\n\r\n", "HTTP/1.1 200 OK\r\nX: \u007f\r\n\r\n",
    "HTTP/1.1 200 OK\r\nX: value\rX", "HTTP/1.1 200 OK\r\nmissing-colon\r\n\r\n",
    "HTTP/1.1 200 OK\r\nX: folded\r\n\tcontinuation\r\n\r\n")
    .map(wire -> badTest("grammar", wire, HttpExchangeException.Kind.FRAMING));
 }

 @TestFactory
 @NonNull Stream<@NonNull DynamicTest> ambiguousAndUnsupportedFramingRejects() {
  return Stream.of("Content-Length: 2\r\nContent-Length: 2\r\n", "Content-Length: 2\r\ncontent-length: 3\r\n",
    "Content-Length: 2, 2\r\n", "Content-Length: +2\r\n", "Content-Length: -1\r\n", "Content-Length: \r\n",
    "Content-Length: 2x\r\n", "Content-Length: 2 2\r\n", "Content-Length: 2\r\nTransfer-Encoding: chunked\r\n",
    "Transfer-Encoding: gzip, chunked\r\n", "Transfer-Encoding: chunked, chunked\r\n",
    "Transfer-Encoding: identity\r\n", "Transfer-Encoding: \r\n",
    "Transfer-Encoding: chunked\r\ntransfer-encoding: chunked\r\n")
    .map(headers -> badTest("framing", wire(headers, "{}"), HttpExchangeException.Kind.FRAMING));
 }

 @TestFactory
 @NonNull Stream<@NonNull DynamicTest> contentTypeAndEncodingAreChecked() {
  Stream<DynamicTest> media = Stream.of("", "Content-Type: text/plain\r\n", "Content-Type: application/jwk-set+json\r\n",
    "Content-Type: application/json; charset=latin1\r\n", "Content-Type: application/json; charset=utf-8; charset=utf-8\r\n",
    "Content-Type: application/json;charset =utf-8\r\n")
    .map(header -> badTest("media", "HTTP/1.1 200 OK\r\n" + header + "Content-Length: 2\r\n\r\n{}",
      HttpExchangeException.Kind.MEDIA_TYPE));
  Stream<DynamicTest> encoding = Stream.of("gzip", "br", "identity, identity", "", "IDENTITY, gzip")
    .map(value -> badTest("encoding", wire("Content-Encoding: " + value + "\r\nContent-Length: 2\r\n", "{}"),
      HttpExchangeException.Kind.CONTENT_ENCODING));
  return Stream.concat(Stream.concat(media, encoding), Stream.of(
    badTest("duplicate-type", wire(JSON + "Content-Length: 2\r\n", "{}"), HttpExchangeException.Kind.FRAMING),
    badTest("duplicate-encoding", wire("Content-Encoding: identity\r\nContent-Encoding: identity\r\n", "{}"),
      HttpExchangeException.Kind.FRAMING)));
 }

 @TestFactory
 @NonNull Stream<@NonNull DynamicTest> malformedChunksReject() {
  return Stream.of("", "z\r\n", "-1\r\n", "+1\r\n", "1x\r\n", "1 \r\nx\r\n0\r\n\r\n",
    "2\r\nx", "1\r\nxX", "1\r\nx\rX", "1\r\nx\r\n", "0\r\n", "0\r\nX: trailer\r\n\r\n",
    "1;\r\nx\r\n0\r\n\r\n", "1;=value\r\nx\r\n0\r\n\r\n", "1;flag=\r\nx\r\n0\r\n\r\n",
    "1;flag=\"unterminated\r\nx\r\n0\r\n\r\n", "1;flag=\"escape\\\r\nx\r\n0\r\n\r\n",
    "1;flag@\r\nx\r\n0\r\n\r\n", "1;flag \r\nx\r\n0\r\n\r\n")
    .map(body -> badTest("chunks", wire("Transfer-Encoding: chunked\r\n", body), HttpExchangeException.Kind.FRAMING));
 }

 @TestFactory
 @NonNull Stream<@NonNull DynamicTest> allRedirectsIncluding304RejectWithoutFollowing() {
  return Stream.of(300, 301, 302, 303, 304, 305, 307, 308, 399).map(status ->
    badTest("redirect", "HTTP/1.1 " + status + " Redirect\r\nLocation: https://127.0.0.1/PRIVATE_SENTINEL\r\n\r\n",
      HttpExchangeException.Kind.REDIRECT));
 }

 @TestFactory
 @NonNull Stream<@NonNull DynamicTest> validChunkExtensionsAndHexDigitsPreserveExactBody() {
  return Stream.of("", ";flag", ";flag=value", ";flag=\"quoted value\"", ";a=\"escaped\\\"quote\";b=token",
    " ; flag \t= \"value\" ; other", ";a=\"\t\u00ff\"", ";a=\"escaped\\\\slash\"", ";flag ; next=value")
    .map(extension -> DynamicTest.dynamicTest("extension " + extension, () -> {
     RawResponse result = read(wire("Transfer-Encoding: CHUNKED\r\n", "2" + extension + "\r\n{}\r\n0\r\n\r\n"));
     Assertions.assertArrayEquals(new byte[]{'{', '}'}, result.body());
    }));
 }

 @Test
 void acceptsFixedChunkedAndCleanCloseDelimitedBodies() throws Exception {
  for (String headers : List.of("Content-Length: 2\r\n", "Content-Length:\t0002 \t\r\n", "")) {
   RawResponse result = read(wire(headers, "{}"));
   Assertions.assertEquals(200, result.status()); Assertions.assertFalse(result.errorBodyDropped());
   Assertions.assertArrayEquals(new byte[]{'{', '}'}, result.body());
   Assertions.assertFalse(result.elapsed().isNegative());
  }
  Assertions.assertArrayEquals(new byte[]{'{', '}'}, read(wire("Transfer-Encoding: chunked\r\n",
    "1\r\n{\r\n1\r\n}\r\n0\r\n\r\n")).body());
  Assertions.assertEquals(0, read(wire("Content-Length: 0\r\n", "")).body().length);
  Assertions.assertEquals(0, read(wire("Transfer-Encoding: chunked\r\n", "0\r\n\r\n")).body().length);
  Assertions.assertEquals(0, read(wire("", "")).body().length);
  Assertions.assertEquals(10, read(wire("Transfer-Encoding: chunked\r\n", "A\r\n0123456789\r\n0\r\n\r\n")).body().length);
  Assertions.assertEquals(10, read(wire("Transfer-Encoding: chunked\r\n", "a\r\n0123456789\r\n0\r\n\r\n")).body().length);
 }

 @Test
 void admitsOnlyFinal200DocumentAndPreservesRepeatedCacheFields() throws Exception {
  String headers = "Content-Length: 2\r\nContent-Encoding: IDENTITY\r\nCache-Control: max-age=60\r\n"
    + "cache-control: no-cache\r\nAge: 5\r\nage: 7\r\nSet-Cookie: ignored=COOKIE_SENTINEL\r\n";
  RawResponse result = read(wire(headers, "{}"));
  Assertions.assertEquals(List.of("max-age=60", "no-cache"), result.headers().allValues("cache-control"));
  Assertions.assertEquals(List.of("5", "7"), result.headers().allValues("age"));
  Assertions.assertFalse(result.toString().contains("COOKIE_SENTINEL"));
  byte[] copy = result.body(); copy[0] = 0; Assertions.assertEquals('{', result.body()[0]);
  RawResponse utf8 = read("HTTP/1.1 200 \r\nContent-Type:\tApplication/JSON; charset=\"UTF-8\"; other=value \t\r\n"
    + "Content-Length: 2\r\nX: \u00ff\r\n\r\n{}");
  Assertions.assertEquals("application/json", java.util.Objects.requireNonNull(utf8.mediaType()).getEssence());
  for (int status : List.of(201, 204, 400, 401, 429, 500, 599)) {
   ByteInput input = new ByteInput("HTTP/1.1 " + status + " Response\r\nContent-Length: 999999999\r\n\r\nUNREAD_SENTINEL");
   RawResponse other = read(input);
   Assertions.assertEquals(status, other.status()); Assertions.assertEquals(0, other.body().length);
   Assertions.assertEquals(status >= 400, other.errorBodyDropped());
   Assertions.assertEquals("UNREAD_SENTINEL", input.remainder());
  }
 }

 @Test
 void boundsInformationalResponsesAndDoesNotMergeTheirHeaders() throws Exception {
  String early = "HTTP/1.1 103 Early Hints\r\nCache-Control: max-age=999999\r\n\r\n";
  RawResponse result = read(early.repeat(4) + wire("Content-Length: 2\r\n", "{}"));
  Assertions.assertTrue(result.headers().allValues("cache-control").isEmpty());
  bad(early.repeat(5) + wire("Content-Length: 2\r\n", "{}"), HttpExchangeException.Kind.FRAMING);
  bad("HTTP/1.1 101 Switching Protocols\r\n\r\n", HttpExchangeException.Kind.FRAMING);
  bad("HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n", HttpExchangeException.Kind.FRAMING);
  bad("HTTP/1.1 102 Processing\r\nTransfer-Encoding: chunked\r\n\r\n", HttpExchangeException.Kind.FRAMING);
 }

 @Test
 void exactDocumentCapOverflowAndTruncationAreBounded() throws Exception {
  String body = "x".repeat(1024);
  Assertions.assertEquals(1024, read(wire("Content-Length: 1024\r\n", body)).body().length);
  Assertions.assertEquals(1024, read(wire("", body)).body().length);
  Assertions.assertEquals(1024, read(wire("Transfer-Encoding: chunked\r\n", "400\r\n" + body + "\r\n0\r\n\r\n")).body().length);
  for (String length : List.of("1025", "999999999999999999999999999999999999"))
   bad(wire("Content-Length: " + length + "\r\n", ""), HttpExchangeException.Kind.TOO_LARGE);
  bad(wire("", body + "x"), HttpExchangeException.Kind.TOO_LARGE);
  bad(wire("Transfer-Encoding: chunked\r\n", "401\r\n"), HttpExchangeException.Kind.TOO_LARGE);
  bad(wire("Transfer-Encoding: chunked\r\n", "400\r\n" + body + "\r\n1\r\nx\r\n"), HttpExchangeException.Kind.TOO_LARGE);
  bad(wire("Content-Length: 2\r\n", "{"), HttpExchangeException.Kind.FRAMING);
  Assertions.assertThrows(IllegalArgumentException.class, () -> PinnedHttpResponseReader.read(new ByteInput(""), 1023,
    Deadline.fromNow(BUDGET), System.nanoTime()));
  Assertions.assertThrows(IllegalArgumentException.class, () -> PinnedHttpResponseReader.read(new ByteInput(""), 5121,
    Deadline.fromNow(BUDGET), System.nanoTime()));
 }

 @Test
 void lineHeaderFieldAndAggregateWireCeilingsApply() throws Exception {
  String exactLine = "X:" + "a".repeat(PinnedHttpResponseReader.MAXIMUM_LINE_BYTES - 2) + "\r\n";
  Assertions.assertEquals(200, read(wire(exactLine + "Content-Length: 2\r\n", "{}")).status());
  bad(wire("X:" + "a".repeat(PinnedHttpResponseReader.MAXIMUM_LINE_BYTES - 1) + "\r\n", "{}"), HttpExchangeException.Kind.FRAMING);
  String field = "X: a\r\n";
  Assertions.assertEquals(200, read(wire(field.repeat(126) + "Content-Length: 2\r\n", "{}")).status());
  bad(wire(field.repeat(127) + "Content-Length: 2\r\n", "{}"), HttpExchangeException.Kind.FRAMING);
  int base = "HTTP/1.1 200 OK\r\n".length() + JSON.length() + "Content-Length: 2\r\n\r\n".length();
  String three = exactLine.repeat(3);
  int last = PinnedHttpResponseReader.MAXIMUM_HEADER_BYTES - base - three.length();
  String remaining = "Y:" + "a".repeat(last - 4) + "\r\n";
  Assertions.assertEquals(200, read(wire(three + remaining + "Content-Length: 2\r\n", "{}")).status());
  bad(wire(three + remaining.replace("Y:", "Y:a") + "Content-Length: 2\r\n", "{}"), HttpExchangeException.Kind.FRAMING);
  String hugeFraming = ("1;" + "e".repeat(1000) + "\r\nx\r\n").repeat(70) + "0\r\n\r\n";
  bad(wire("Transfer-Encoding: chunked\r\n", hugeFraming), HttpExchangeException.Kind.FRAMING);
 }

 @Test
 @SuppressWarnings("NullAway") // Explicit tests of required-input null checks.
 void deadlineInterruptionReaderFaultAndInvalidBytePreserveSafeFailures() throws Exception {
  AtomicInteger calls = new AtomicInteger();
  PinnedHttpResponseReader.ByteReader untouched = () -> { calls.incrementAndGet(); throw new AssertionError(); };
  Assertions.assertEquals(HttpExchangeException.Kind.TIMEOUT, Assertions.assertThrows(HttpExchangeException.class,
    () -> PinnedHttpResponseReader.read(untouched, 1024, Deadline.fromNow(Duration.ZERO), System.nanoTime())).getKind());
  Thread.currentThread().interrupt();
  try {
   Assertions.assertEquals(HttpExchangeException.Kind.INTERRUPTED,
     Assertions.assertThrows(HttpExchangeException.class, () -> read(untouched)).getKind());
   Assertions.assertTrue(Thread.currentThread().isInterrupted());
  } finally { Thread.interrupted(); }
  Assertions.assertEquals(0, calls.get());
  PinnedHttpResponseReader.ByteReader interrupting = () -> { Thread.currentThread().interrupt(); return 'H'; };
  try {
   Assertions.assertEquals(HttpExchangeException.Kind.INTERRUPTED,
     Assertions.assertThrows(HttpExchangeException.class, () -> read(interrupting)).getKind());
   Assertions.assertTrue(Thread.currentThread().isInterrupted());
  } finally { Thread.interrupted(); }
  for (int value : List.of(-2, 256))
   Assertions.assertEquals(HttpExchangeException.Kind.FRAMING,
     Assertions.assertThrows(HttpExchangeException.class, () -> read(() -> value)).getKind());
  HttpExchangeException fixed = new HttpExchangeException(HttpExchangeException.Kind.IO);
  Assertions.assertSame(fixed, Assertions.assertThrows(HttpExchangeException.class, () -> read(() -> { throw fixed; })));
  Deadline deadline = Deadline.fromNow(Duration.ofMillis(100));
  PinnedHttpResponseReader.ByteReader expiring = () -> { while (!deadline.isExpired()) Thread.onSpinWait(); return 'H'; };
  Assertions.assertEquals(HttpExchangeException.Kind.TIMEOUT, Assertions.assertThrows(HttpExchangeException.class,
    () -> PinnedHttpResponseReader.read(expiring, 1024, deadline, System.nanoTime())).getKind());
  Assertions.assertThrows(NullPointerException.class, () -> read((PinnedHttpResponseReader.ByteReader) null));
  Assertions.assertThrows(NullPointerException.class, () -> PinnedHttpResponseReader.read(new ByteInput(""), 1024, null, System.nanoTime()));
 }

 @Test
 void configuredMaximumAndEveryAllowedHeaderTokenCharacterWork() throws Exception {
  String body = "x".repeat(5120);
  for (String response : List.of(wire("Content-Length: 5120\r\n", body), wire("", body),
    wire("Transfer-Encoding: chunked\r\n", "1400\r\n" + body + "\r\n0\r\n\r\n"))) {
   RawResponse result = PinnedHttpResponseReader.read(new ByteInput(response), 5120, Deadline.fromNow(BUDGET), System.nanoTime());
   Assertions.assertEquals(5120, result.body().length);
  }
  Assertions.assertEquals(HttpExchangeException.Kind.TOO_LARGE, Assertions.assertThrows(HttpExchangeException.class,
    () -> PinnedHttpResponseReader.read(new ByteInput(wire("Content-Length: 5121\r\n", "")), 5120,
      Deadline.fromNow(BUDGET), System.nanoTime())).getKind());
  Assertions.assertEquals(200, read(wire("!#$%&'*+-.^_`|~: value\r\nContent-Length: 2\r\n", "{}")).status());
 }

 private static @NonNull DynamicTest badTest(@NonNull String label, @NonNull String wire,
   HttpExchangeException.@NonNull Kind kind) {
  return DynamicTest.dynamicTest(label + " " + Integer.toHexString(wire.hashCode()), () -> bad(wire, kind));
 }
 private static void bad(@NonNull String wire, HttpExchangeException.@NonNull Kind kind) {
  HttpExchangeException failure = Assertions.assertThrows(HttpExchangeException.class, () -> read(wire));
  Assertions.assertEquals(kind, failure.getKind()); Assertions.assertNull(failure.getCause());
  Assertions.assertFalse(failure.toString().contains("SENTINEL"));
 }
 private static @NonNull String wire(@NonNull String headers, @NonNull String body) {
  return "HTTP/1.1 200 OK\r\n" + JSON + headers + "\r\n" + body;
 }
 private static @NonNull RawResponse read(@NonNull String text) throws HttpExchangeException { return read(new ByteInput(text)); }
 private static @NonNull RawResponse read(PinnedHttpResponseReader.@NonNull ByteReader reader) throws HttpExchangeException {
  return PinnedHttpResponseReader.read(reader, 1024, Deadline.fromNow(BUDGET), System.nanoTime());
 }
 private static final class ByteInput implements PinnedHttpResponseReader.ByteReader {
  private final byte @NonNull [] bytes;
  private int index;
  private ByteInput(@NonNull String text) { this.bytes = text.getBytes(StandardCharsets.ISO_8859_1); }
  @Override public int read() { return this.index == this.bytes.length ? -1 : this.bytes[this.index++] & 255; }
  private @NonNull String remainder() { return new String(this.bytes, this.index, this.bytes.length - this.index, StandardCharsets.ISO_8859_1); }
 }
}
