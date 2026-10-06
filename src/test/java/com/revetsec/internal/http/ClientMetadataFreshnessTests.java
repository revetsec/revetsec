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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.net.http.HttpHeaders;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

class ClientMetadataFreshnessTests {
 private static final @NonNull Instant NOW = Instant.parse("2026-10-06T12:00:00Z");
 private static @NonNull RawResponse response(@NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers, @NonNull Duration elapsed) {
  return new RawResponse(200, HttpHeaders.of(headers, (a,b)->true), new byte[]{1}, null, false, elapsed);
 }
 private static @NonNull Duration ttl(@NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers) {
  return ClientMetadataFreshness.remaining(response(headers,Duration.ZERO), NOW,Duration.ofSeconds(300));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> blockedOrAmbiguousControlIsNeverReusable() {
  return Stream.of("no-store, max-age=120", "no-cache, max-age=120", "no-cache=\"field\", max-age=120",
   "private, max-age=120", "PrIvAtE=\"field\", max-age=120", "s-maxage=120, max-age=120", "max-age=1, max-age=2",
   "max-age", "max-age=-1", "max-age=1.5", "max-age=\"\"", "max-age=\"12", "{bad}", "max-age =12",
   "public", "max-age=120, other=", "max-age=120, other=\"x\" garbage").map(value->DynamicTest.dynamicTest(value,()->
     assertEquals(Duration.ZERO,ttl(Map.of("Cache-Control",List.of(value))))));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> malformedAgeCannotBecomeZeroAge() {
  return Stream.of("", "-1", "+1", "1.5", "3,3", ",3", "words", "é").map(value->DynamicTest.dynamicTest("age-"+value,()->
   assertEquals(Duration.ZERO,ttl(Map.of("Cache-Control",List.of("max-age=120"),"Age",List.of(value))))));
 }
 @Test void explicitGrammarAndCapAreReused() {
  assertEquals(Duration.ofSeconds(300),ttl(Map.of("Cache-Control",List.of("max-age=1000"))));
  assertEquals(Duration.ofSeconds(120),ttl(Map.of("Cache-Control",List.of(",, max-age=\"120\", unknown=\"private,x\",", "MAX-AGE=120"))));
  assertEquals(Duration.ZERO,ttl(Map.of()));
  assertEquals(Duration.ZERO,ttl(Map.of("Cache-Control",List.of("max-age=0"))));
  assertEquals(Duration.ZERO,ClientMetadataFreshness.remaining(response(Map.of("Cache-Control",List.of("max-age=10")),Duration.ZERO),NOW,Duration.ZERO));
 }
 @Test void ageApparentAgeAndExchangeDelayAreConservative() {
  assertEquals(Duration.ofMillis(119750),ClientMetadataFreshness.remaining(response(Map.of("Cache-Control",List.of("max-age=120")),Duration.ofMillis(250)),NOW,Duration.ofSeconds(300)));
  assertEquals(Duration.ofMillis(79250),ClientMetadataFreshness.remaining(response(Map.of("Cache-Control",List.of("max-age=120"),"Age",List.of("40")),Duration.ofMillis(750)),NOW,Duration.ofSeconds(300)));
  assertEquals(Duration.ofSeconds(30),ttl(Map.of("Cache-Control",List.of("max-age=120"),"Date",List.of("Tue, 06 Oct 2026 11:58:30 GMT"),"Age",List.of("10"))));
  assertEquals(Duration.ofSeconds(120),ttl(Map.of("Cache-Control",List.of("max-age=120"),"Date",List.of("Tue, 06 Oct 2026 12:01:00 GMT"))));
  assertEquals(Duration.ZERO,ttl(Map.of("Cache-Control",List.of("max-age=120"),"Age",List.of("9".repeat(500)))));
 }
 @Test void invalidSingletonsAndVaryCannotGuessFreshness() {
  for(String name:List.of("Date","Age","Expires")) assertEquals(Duration.ZERO,ttl(Map.of("Cache-Control",List.of("max-age=120"),name,List.of("bad","bad"))));
  assertEquals(Duration.ZERO,ttl(Map.of("Cache-Control",List.of("max-age=120"),"Date",List.of("bad"))));
  assertEquals(Duration.ZERO,ttl(Map.of("Cache-Control",List.of("max-age=120"),"Vary",List.of(""))));
  assertEquals(Duration.ZERO,ttl(Map.of("Cache-Control",List.of("max-age=120"),"Vary",List.of("Accept"))));
 }
 @Test void expiresRequiresExplicitFiniteDateAndAge() {
  assertEquals(Duration.ofSeconds(60),ttl(Map.of("Expires",List.of("Tue, 06 Oct 2026 12:01:00 GMT"))));
  assertEquals(Duration.ofSeconds(30),ttl(Map.of("Expires",List.of("Tue, 06 Oct 2026 12:01:00 GMT"),"Age",List.of("30"))));
  assertEquals(Duration.ZERO,ttl(Map.of("Expires",List.of("0"))));
  assertEquals(Duration.ZERO,ttl(Map.of("Expires",List.of("Tue, 06 Oct 2026 11:59:59 GMT"))));
 }
 @Test void absurdExchangeDelayCannotOverflowIntoReusableTime() {
  assertEquals(Duration.ZERO,ClientMetadataFreshness.remaining(response(Map.of("Cache-Control",List.of("max-age=120")),Duration.ofSeconds(Long.MAX_VALUE)),NOW,Duration.ofSeconds(300)));
 }
 @Test void errorAndInvalidBoundsCannotSupplyReuse() {
  RawResponse error=new RawResponse(503,HttpHeaders.of(Map.of("Cache-Control",List.of("max-age=100")),(a,b)->true),new byte[0],null,false,Duration.ZERO);
  assertEquals(Duration.ZERO,ClientMetadataFreshness.remaining(error,NOW,Duration.ofSeconds(300)));
  assertThrows(IllegalArgumentException.class,()->ClientMetadataFreshness.remaining(response(Map.of(),Duration.ZERO),NOW,Duration.ofSeconds(-1)));
 }
}
