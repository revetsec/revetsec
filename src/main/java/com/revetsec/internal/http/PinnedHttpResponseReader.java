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

import com.revetsec.internal.Limits;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.NotThreadSafe;
import java.io.ByteArrayOutputStream;
import java.net.http.HttpHeaders;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import static java.util.Objects.requireNonNull;

/**
 * Bounded HTTP/1.1 response admission for one anonymous metadata GET. It performs no I/O itself. A live TLS
 * adapter must return minus one only on authenticated TLS end-of-stream, and honor the same deadline while
 * waiting. Every callback is checked before and after it returns. Only200 admits a JSON document body; redirects
 * reject, and other final statuses carry an empty body for the caller's protocol decision. Informational responses
 * are bounded and cannot supply final cache fields. Chunk extensions are checked; nonempty trailers are refused.
 * No response, reader or diagnostic confers DNS/TLS, freshness or authorization proof.
 */
@NotThreadSafe
final class PinnedHttpResponseReader {
 static final int MAXIMUM_LINE_BYTES = 8192;
 static final int MAXIMUM_HEADER_BYTES = 32768;
 static final int MAXIMUM_HEADER_FIELDS = 128;
 static final int MAXIMUM_INFORMATIONAL_RESPONSES = 4;
 static final int MAXIMUM_FRAMING_BYTES = 65536;

 @FunctionalInterface
 interface ByteReader {
  int read() throws HttpExchangeException;
 }

 private final @NonNull ByteReader reader;
 private final @NonNull Deadline deadline;
 private final int maximumDocumentBytes;
 private int wireBytes;

 private PinnedHttpResponseReader(@NonNull ByteReader reader, int maximumDocumentBytes, @NonNull Deadline deadline) {
  this.reader = requireNonNull(reader);
  this.maximumDocumentBytes = Limits.CIMD_MAXIMUM_DOCUMENT_BYTES.require(maximumDocumentBytes);
  this.deadline = requireNonNull(deadline);
 }

 static @NonNull RawResponse read(@NonNull ByteReader reader, int maximumDocumentBytes,
   @NonNull Deadline deadline, long exchangeStartedNanos) throws HttpExchangeException {
  return new PinnedHttpResponseReader(reader, maximumDocumentBytes, deadline).response(exchangeStartedNanos);
 }

 private @NonNull RawResponse response(long started) throws HttpExchangeException {
  int informational = 0;
  int status;
  HttpHeaders headers;
  do {
   String line = line();
   if (line.length() < 13 || !line.startsWith("HTTP/1.1 ") || line.charAt(12) != ' '
     || line.charAt(9) < '1' || line.charAt(9) > '5'
     || !digit(line.charAt(10)) || !digit(line.charAt(11))) throw framing();
   status = (line.charAt(9) - '0') * 100 + (line.charAt(10) - '0') * 10 + line.charAt(11) - '0';
   headers = headers(line.length() + 2);
   if (status < 200 && (status == 101 || ++informational > MAXIMUM_INFORMATIONAL_RESPONSES
     || !headers.allValues("content-length").isEmpty() || !headers.allValues("transfer-encoding").isEmpty()))
    throw framing();
  } while (status < 200);
  if (status >= 300 && status < 400) throw new HttpExchangeException(HttpExchangeException.Kind.REDIRECT);
  if (status != 200)
   return result(status, headers, new byte[0], null, status >= 400, started);

  @Nullable String length = single(headers, "content-length");
  @Nullable String transfer = single(headers, "transfer-encoding");
  if (length != null && transfer != null) throw framing();
  if (transfer != null && !"chunked".equalsIgnoreCase(transfer)) throw framing();
  @Nullable String encoding = single(headers, "content-encoding");
  if (encoding != null && !"identity".equalsIgnoreCase(encoding))
   throw new HttpExchangeException(HttpExchangeException.Kind.CONTENT_ENCODING);
  @Nullable String type = single(headers, "content-type");
  @Nullable MediaType media = type == null ? null : MediaType.parse(type).orElse(null);
  if (media == null || !ResponseProfile.METADATA.accepts(media))
   throw new HttpExchangeException(HttpExchangeException.Kind.MEDIA_TYPE);

  byte[] body;
  if (length != null) body = exact(decimal(length));
  else if (transfer != null) body = chunked();
  else body = untilEnd();
  return result(status, headers, body, media, false, started);
 }

 private @NonNull HttpHeaders headers(int used) throws HttpExchangeException {
  Map<String, List<String>> values = new LinkedHashMap<>();
  int count = 0;
  while (true) {
   String line = line();
   used += line.length() + 2;
   if (used > MAXIMUM_HEADER_BYTES) throw framing();
   if (line.isEmpty()) return HttpHeaders.of(values, (name, value) -> true);
   if (++count > MAXIMUM_HEADER_FIELDS) throw framing();
   int colon = line.indexOf(':');
   if (colon <= 0) throw framing();
   for (int i = 0; i < colon; i++) if (!token(line.charAt(i))) throw framing();
   String name = line.substring(0, colon).toLowerCase(Locale.ROOT);
   values.computeIfAbsent(name, ignored -> new ArrayList<>()).add(ows(line.substring(colon + 1)));
  }
 }

 private static @Nullable String single(@NonNull HttpHeaders headers, @NonNull String name)
   throws HttpExchangeException {
  List<String> values = headers.allValues(name);
  if (values.size() > 1) throw framing();
  return values.isEmpty() ? null : values.get(0);
 }

 private int decimal(@NonNull String text) throws HttpExchangeException {
  if (text.isEmpty()) throw framing();
  int value = 0;
  for (int i = 0; i < text.length(); i++) {
   char c = text.charAt(i);
   if (!digit(c)) throw framing();
   if (value > (this.maximumDocumentBytes - (c - '0')) / 10) throw tooLarge();
   value = value * 10 + c - '0';
  }
  return value;
 }

 private byte @NonNull [] exact(int count) throws HttpExchangeException {
  byte[] bytes = new byte[count];
  for (int i = 0; i < count; i++) {
   int next = next();
   if (next < 0) throw framing();
   bytes[i] = (byte) next;
  }
  return bytes;
 }

 private byte @NonNull [] untilEnd() throws HttpExchangeException {
  ByteArrayOutputStream body = new ByteArrayOutputStream();
  for (int next; (next = next()) >= 0;) {
   if (body.size() == this.maximumDocumentBytes) throw tooLarge();
   body.write(next);
  }
  return body.toByteArray();
 }

 private byte @NonNull [] chunked() throws HttpExchangeException {
  ByteArrayOutputStream body = new ByteArrayOutputStream();
  while (true) {
   String line = line();
   int end = 0, count = 0;
   while (end < line.length() && hex(line.charAt(end)) >= 0) {
    int value = hex(line.charAt(end++));
    if (count > (this.maximumDocumentBytes - value) / 16) throw tooLarge();
    count = count * 16 + value;
   }
   if (end == 0) throw framing();
   extensions(line, end);
   if (count == 0) {
    if (!line().isEmpty()) throw framing();
    return body.toByteArray();
   }
   if (count > this.maximumDocumentBytes - body.size()) throw tooLarge();
   body.writeBytes(exact(count));
   if (next() != '\r' || next() != '\n') throw framing();
  }
 }

 private static void extensions(@NonNull String line, int index) throws HttpExchangeException {
  while (index < line.length()) {
   index = skipOws(line, index);
   if (index == line.length() || line.charAt(index++) != ';') throw framing();
   index = skipOws(line, index);
   int start = index;
   while (index < line.length() && token(line.charAt(index))) index++;
   if (index == start) throw framing();
   int tokenEnd = index;
   index = skipOws(line, index);
   if (index < line.length() && line.charAt(index) == '=') {
    index = skipOws(line, index + 1);
    if (index < line.length() && line.charAt(index) == '"') {
     index = quoted(line, index + 1);
    } else {
     start = index;
     while (index < line.length() && token(line.charAt(index))) index++;
     if (index == start) throw framing();
    }
   } else {
    index = tokenEnd;
   }
  }
 }

 private static int quoted(@NonNull String line, int index) throws HttpExchangeException {
  while (index < line.length()) {
   char c = line.charAt(index++);
   if (c == '"') return index;
   if (c == '\\') {
    if (index == line.length()) throw framing();
    index++;
   }
  }
  throw framing();
 }

 private @NonNull String line() throws HttpExchangeException {
  StringBuilder text = new StringBuilder();
  while (true) {
   int next = next();
   if (next == '\r') {
    if (next() != '\n') throw framing();
    return text.toString();
   }
   if (next < 0 || next == 127 || (next < 32 && next != '\t') || text.length() == MAXIMUM_LINE_BYTES)
    throw framing();
   text.append((char) next);
  }
 }

 private int next() throws HttpExchangeException {
  checkBudget();
  int next = this.reader.read();
  checkBudget();
  if (next < -1 || next > 255) throw framing();
  if (next >= 0 && ++this.wireBytes > MAXIMUM_FRAMING_BYTES + this.maximumDocumentBytes) throw framing();
  return next;
 }

 private void checkBudget() throws HttpExchangeException {
  if (Thread.currentThread().isInterrupted())
   throw new HttpExchangeException(HttpExchangeException.Kind.INTERRUPTED);
  if (this.deadline.isExpired()) throw new HttpExchangeException(HttpExchangeException.Kind.TIMEOUT);
 }

 private @NonNull RawResponse result(int status, @NonNull HttpHeaders headers, byte @NonNull [] body,
   @Nullable MediaType media, boolean dropped, long started) throws HttpExchangeException {
  checkBudget();
  return new RawResponse(status, headers, body, media, dropped,
    Duration.ofNanos(Math.max(0, System.nanoTime() - started)));
 }

 private static @NonNull String ows(@NonNull String text) {
  int start = skipOws(text, 0), end = text.length();
  while (end > start && (text.charAt(end - 1) == ' ' || text.charAt(end - 1) == '\t')) end--;
  return text.substring(start, end);
 }

 private static int skipOws(@NonNull String text, int index) {
  while (index < text.length() && (text.charAt(index) == ' ' || text.charAt(index) == '\t')) index++;
  return index;
 }

 private static boolean digit(char c) { return c >= '0' && c <= '9'; }
 private static int hex(char c) {
  if (digit(c)) return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
 }
 private static boolean token(char c) {
  return digit(c) || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
    || "!#$%&'*+-.^_`|~".indexOf(c) >= 0;
 }
 private static @NonNull HttpExchangeException framing() {
  return new HttpExchangeException(HttpExchangeException.Kind.FRAMING);
 }
 private static @NonNull HttpExchangeException tooLarge() {
  return new HttpExchangeException(HttpExchangeException.Kind.TOO_LARGE);
 }
}
