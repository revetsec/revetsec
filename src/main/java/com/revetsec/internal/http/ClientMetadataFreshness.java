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
import javax.annotation.concurrent.ThreadSafe;
import java.net.http.HttpHeaders;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import static java.util.Objects.requireNonNull;

/** Conservative explicit CIMD reuse; no heuristics, stale use or conditional validation. */
@ThreadSafe
public final class ClientMetadataFreshness {
 private ClientMetadataFreshness() {}
 public static @NonNull Duration remaining(@NonNull RawResponse response, @NonNull Instant receivedAt,
   @NonNull Duration maximum) {
  requireNonNull(response); requireNonNull(receivedAt); requireNonNull(maximum);
  if (maximum.isNegative()) throw new IllegalArgumentException("Invalid metadata freshness bound.");
  HttpHeaders headers = response.headers();
  if (response.status() != 200 || !headers.allValues("Vary").isEmpty()
    || blocked(headers.allValues("Cache-Control"))) return Duration.ZERO;
  List<String> ages = headers.allValues("Age");
  long age = 0;
  if (!ages.isEmpty()) {
   if (ages.size() != 1) return Duration.ZERO;
   String value = HttpDate.trimOws(ages.get(0));
   if (!HttpDate.isAllDigits(value, 0, value.length())) return Duration.ZERO;
   for (int i = 0; i < value.length() && age < CacheLifetime.MAXIMUM_DELTA_SECONDS; i++)
    age = age * 10 + value.charAt(i) - '0';
   age = Math.min(age, CacheLifetime.MAXIMUM_DELTA_SECONDS);
  }
  Optional<Instant> date = HttpDate.parseSingleField(headers.allValues("Date"), receivedAt);
  if (!headers.allValues("Date").isEmpty() && date.isEmpty()) return Duration.ZERO;
  if (!headers.allValues("Expires").isEmpty() && HttpDate.parseSingleField(headers.allValues("Expires"), receivedAt).isEmpty()) return Duration.ZERO;
  Duration apparentAge = date.isPresent() && date.get().isBefore(receivedAt)
    ? Duration.between(date.get(), receivedAt) : Duration.ZERO;
  // Entire bounded exchange elapsed upper-bounds RFC9111 response_delay, including DNS/TLS.
  if (response.elapsed().compareTo(Duration.ofSeconds(CacheLifetime.MAXIMUM_DELTA_SECONDS)) > 0) return Duration.ZERO;
  Duration correctedAge = Duration.ofSeconds(age).plus(response.elapsed());
  if (apparentAge.compareTo(correctedAge) > 0) correctedAge = apparentAge;
  Duration lifetime = CacheLifetime.timeToLive(HttpHeaders.of(headers.map(), (name, value) -> !name.equalsIgnoreCase("Age")),
    receivedAt, Duration.ZERO, Duration.ZERO, Duration.ofSeconds(CacheLifetime.MAXIMUM_DELTA_SECONDS));
  Duration result = lifetime.minus(correctedAge);
  if (result.isNegative()) return Duration.ZERO;
  return result.compareTo(maximum) > 0 ? maximum : result;
 }
 private static boolean blocked(@NonNull List<@NonNull String> values) {
  for (String value : values) {
   int i = 0;
   while (i < value.length()) {
    i = MediaType.owsEnd(value, i, value.length());
    if (i == value.length()) break;
    if (value.charAt(i) == ',') { i++; continue; }
    int end = MediaType.tokenEnd(value, i, value.length());
    if (end == i) return true;
    String name = MediaType.asciiLowerCase(value.substring(i, end));
    if (name.equals("private") || name.equals("s-maxage")) return true;
    i = end;
    if (i < value.length() && value.charAt(i) == '=') {
     i++;
     if (i < value.length() && value.charAt(i) == '"') {
      i = MediaType.quotedStringEnd(value, i, value.length(), new StringBuilder());
      if (i < 0) return true;
     } else {
      end = MediaType.tokenEnd(value, i, value.length());
      if (end == i) return true;
      i = end;
     }
    }
    i = MediaType.owsEnd(value, i, value.length());
    if (i < value.length() && value.charAt(i) != ',') return true;
   }
  }
  return false;
 }
}
