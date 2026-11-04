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
import javax.annotation.concurrent.ThreadSafe;
import java.net.http.HttpHeaders;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import static java.util.Objects.requireNonNull;

/** Shared anonymous CIMD reuse for one fixed request profile; no heuristics, stale use or conditional validation. */
@ThreadSafe
public final class ClientMetadataFreshness {
 private static final long NO_AGE = -2, NO_REUSE = -1;
 private ClientMetadataFreshness() {}
 public static @NonNull Duration remaining(@NonNull RawResponse response, @NonNull Instant receivedAt,
   @NonNull Duration maximum) {
  requireNonNull(response); requireNonNull(receivedAt); requireNonNull(maximum);
  if (maximum.isNegative()) throw new IllegalArgumentException("Invalid metadata freshness bound.");
  HttpHeaders headers = response.headers();
  long maxAge = sharedMaxAge(headers.allValues("Cache-Control"));
  if (response.status() != 200 || maxAge == NO_REUSE || !fixedVariant(headers.allValues("Vary"))) return Duration.ZERO;
  List<String> ages = headers.allValues("Age"); long age = 0;
  if (!ages.isEmpty()) {
   if (ages.size() != 1) return Duration.ZERO;
   age = delta(HttpDate.trimOws(ages.get(0)));
   if (age < 0) return Duration.ZERO;
  }
  Optional<Instant> date = HttpDate.parseSingleField(headers.allValues("Date"), receivedAt);
  if (!headers.allValues("Date").isEmpty() && date.isEmpty()) return Duration.ZERO;
  Optional<Instant> expires = HttpDate.parseSingleField(headers.allValues("Expires"), receivedAt);
  if (!headers.allValues("Expires").isEmpty() && expires.isEmpty()) return Duration.ZERO;
  Duration lifetime;
  if (maxAge != NO_AGE) lifetime = Duration.ofSeconds(maxAge);
  else if (expires.isPresent()) lifetime = Duration.between(date.orElse(receivedAt), expires.orElseThrow());
  else return Duration.ZERO;
  Duration maximumLifetime = Duration.ofSeconds(CacheLifetime.MAXIMUM_DELTA_SECONDS);
  if (lifetime.compareTo(maximumLifetime) > 0) lifetime = maximumLifetime;
  Duration apparentAge = date.isPresent() && date.orElseThrow().isBefore(receivedAt)
    ? Duration.between(date.orElseThrow(), receivedAt) : Duration.ZERO;
  // Entire bounded exchange elapsed upper-bounds RFC9111 response_delay, including DNS/TLS.
  if (response.elapsed().compareTo(Duration.ofSeconds(CacheLifetime.MAXIMUM_DELTA_SECONDS)) > 0) return Duration.ZERO;
  Duration correctedAge = Duration.ofSeconds(age).plus(response.elapsed());
  if (apparentAge.compareTo(correctedAge) > 0) correctedAge = apparentAge;
  Duration result = lifetime.minus(correctedAge);
  if (result.isNegative()) return Duration.ZERO;
  return result.compareTo(maximum) > 0 ? maximum : result;
 }
 private static long sharedMaxAge(@NonNull List<@NonNull String> values) {
  long maxAge = NO_AGE, sharedAge = NO_AGE;
  for (String value : values) {
   int i = 0;
   while (i < value.length()) {
    i = MediaType.owsEnd(value, i, value.length());
    if (i == value.length()) break;
    if (value.charAt(i) == ',') { i++; continue; }
    int end = MediaType.tokenEnd(value, i, value.length());
    if (end == i) return NO_REUSE;
    String name = MediaType.asciiLowerCase(value.substring(i, end));
    if (name.equals("private") || name.equals("no-store") || name.equals("no-cache")) return NO_REUSE;
    i = end; @Nullable String argument = null;
    if (i < value.length() && value.charAt(i) == '=') {
     i++;
     if (i < value.length() && value.charAt(i) == '"') {
      StringBuilder unquoted = new StringBuilder();
      i = MediaType.quotedStringEnd(value, i, value.length(), unquoted);
      if (i < 0) return NO_REUSE;
      argument = unquoted.toString();
     } else {
      end = MediaType.tokenEnd(value, i, value.length());
      if (end == i) return NO_REUSE;
      argument = value.substring(i, end); i = end;
     }
    }
    i = MediaType.owsEnd(value, i, value.length());
    if (i < value.length() && value.charAt(i) != ',') return NO_REUSE;
    if (name.equals("max-age") || name.equals("s-maxage")) {
     long parsed = delta(argument);
     if (parsed < 0) return NO_REUSE;
     if (name.equals("s-maxage")) {
      if (sharedAge != NO_AGE && sharedAge != parsed) return NO_REUSE;
      sharedAge = parsed;
     } else {
      if (maxAge != NO_AGE && maxAge != parsed) return NO_REUSE;
      maxAge = parsed;
     }
    }
   }
  }
  return sharedAge != NO_AGE ? sharedAge : maxAge;
 }
 private static long delta(@Nullable String value) {
  if (value == null || !HttpDate.isAllDigits(value, 0, value.length())) return NO_REUSE;
  long number = 0;
  for (int i = 0; i < value.length() && number < CacheLifetime.MAXIMUM_DELTA_SECONDS; i++) number = number * 10 + value.charAt(i) - '0';
  return Math.min(number, CacheLifetime.MAXIMUM_DELTA_SECONDS);
 }
 private static boolean fixedVariant(@NonNull List<@NonNull String> values) {
  // Every request field is fixed by the namespace-bound pinned GET profile, or consistently absent.
  for (String value : values) {
   int i = 0;
   while (i < value.length()) {
    i = MediaType.owsEnd(value, i, value.length());
    if (i == value.length()) break;
    if (value.charAt(i) == ',') { i++; continue; }
    int end = MediaType.tokenEnd(value, i, value.length());
    if (end == i || value.substring(i, end).equals("*")) return false;
    i = MediaType.owsEnd(value, end, value.length());
    if (i < value.length() && value.charAt(i) != ',') return false;
   }
  }
  return true;
 }
}
