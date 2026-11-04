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

import java.net.http.HttpHeaders;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import static org.junit.jupiter.api.Assertions.*;

/** Shared reuse is specific to the pinned anonymous CIMD request, not the general document TTL helper. */
final class CimdSharedFreshnessTests {
 private static final Instant NOW=Instant.parse("2026-10-31T12:00:00Z");
 private static Duration ttl(Map<String,List<String>> headers,Duration delay) {
  return ClientMetadataFreshness.remaining(new RawResponse(200,HttpHeaders.of(headers,(a,b)->true),new byte[0],null,false,delay),NOW,Duration.ofSeconds(300));
 }
 private static Duration ttl(String control){return ttl(Map.of("Cache-Control",List.of(control)),Duration.ZERO);}
 @TestFactory Stream<DynamicTest> sharedMaxAgeIsExplicitAndOverridesPrivateFreshness() {
  return Stream.of("s-maxage=5,max-age=120","max-age=120,s-maxage=5","s-maxage=5", "S-MAXAGE=\"5\"", "s-maxage=005,S-MAXAGE=5", "s-maxage=5,unknown=\"max-age=200,private\"")
   .map(control->DynamicTest.dynamicTest(control,()->assertEquals(Duration.ofSeconds(5),ttl(control))));
 }
 @Test void sharedAgeCanBeLongerThanMaxAgeButCannotExceedTheLocalBound() {
  assertEquals(Duration.ofSeconds(240),ttl("s-maxage=240,max-age=1"));
  assertEquals(Duration.ofSeconds(120),ttl("max-age=0,s-maxage=120"));
  assertEquals(Duration.ofSeconds(120),ttl("s-maxage=120,max-age=0"));
  assertEquals(Duration.ofSeconds(300),ttl("s-maxage="+"9".repeat(500)+",max-age=1"));
  assertEquals(Duration.ZERO,ttl("s-maxage=0,max-age=120"));
 }
 @Test void sharedAgeOverridesExpiresAndKeepsCorrectedAgeAccounting() {
  assertEquals(Duration.ofSeconds(120),ttl(Map.of("Cache-Control",List.of("s-maxage=120"),"Age",List.of("0")),Duration.ZERO));
  assertEquals(Duration.ofSeconds(120),ttl(Map.of("Cache-Control",List.of("max-age=120"),"Age",List.of("000")),Duration.ZERO));
  assertEquals(Duration.ofSeconds(5),ttl(Map.of("Cache-Control",List.of("s-maxage=5"),"Date",List.of("Sat, 31 Oct 2026 12:00:00 GMT"),"Expires",List.of("Sat, 31 Oct 2026 12:02:00 GMT")),Duration.ZERO));
  assertEquals(Duration.ofMillis(99500),ttl(Map.of("Cache-Control",List.of("s-maxage=120,max-age=1"),"Age",List.of("20")),Duration.ofMillis(500)));
  assertEquals(Duration.ofSeconds(30),ttl(Map.of("Cache-Control",List.of("s-maxage=120,max-age=1"),"Date",List.of("Sat, 31 Oct 2026 11:58:30 GMT")),Duration.ZERO));
 }
 @TestFactory Stream<DynamicTest> invalidOrConflictingSharedAgeCannotBorrowMaxAge() {
  return Stream.of("s-maxage", "s-maxage=-1", "s-maxage=+1", "s-maxage=1.5", "s-maxage=\"\"", "s-maxage=\"12", "s-maxage =5", "s-maxage=1,s-maxage=2")
   .map(value->DynamicTest.dynamicTest(value,()->assertEquals(Duration.ZERO,ttl("max-age=120,"+value))));
 }
 @TestFactory Stream<DynamicTest> sharedFreshnessCannotOverrideNoReuseOrMalformedControl() {
  return Stream.of("no-store","no-cache","private","private=\"Set-Cookie\"","no-cache=\"ETag\"","{bad}","unknown=", "unknown=\"unfinished")
   .map(value->DynamicTest.dynamicTest(value,()->assertEquals(Duration.ZERO,ttl("s-maxage=120,"+value))));
 }
 @TestFactory Stream<DynamicTest> namedVaryMatchesTheFixedRequestIncludingAbsentFields() {
  return Stream.of("Accept","Accept-Encoding,User-Agent","Host","Authorization,Cookie","Origin,Accept-Language,X-Unsent","accept,,", "", " , , ")
   .map(value->DynamicTest.dynamicTest("Vary="+value,()->assertEquals(Duration.ofSeconds(120),ttl(Map.of("Cache-Control",List.of("max-age=120"),"Vary",List.of(value)),Duration.ZERO))));
 }
 @Test void repeatedVaryFieldsHaveOneFixedRequestProfile() {
  assertEquals(Duration.ofSeconds(120),ttl(Map.of("Cache-Control",List.of("s-maxage=120"),"Vary",List.of("Accept", "accept-encoding,User-Agent", "X-Absent")),Duration.ZERO));
 }
 @TestFactory Stream<DynamicTest> wildcardAndMalformedVaryCannotAuthorizeReuse() {
  return Stream.of("*","Accept,*", "Accept;foo", "\"Accept\"", "Accept=foo", "Accept Accept-Encoding", "{bad}", "é")
   .map(value->DynamicTest.dynamicTest(value,()->assertEquals(Duration.ZERO,ttl(Map.of("Cache-Control",List.of("s-maxage=120,max-age=120"),"Vary",List.of(value)),Duration.ZERO))));
 }
 @Test void namedVaryCannotSupplyFreshnessOrOverridePrivate() {
  assertEquals(Duration.ZERO,ttl(Map.of("Vary",List.of("Accept")),Duration.ZERO));
  assertEquals(Duration.ZERO,ttl(Map.of("Cache-Control",List.of("private,max-age=120"),"Vary",List.of("Accept")),Duration.ZERO));
  assertEquals(Duration.ZERO,ttl(Map.of("Cache-Control",List.of("s-maxage=120"),"Vary",List.of("Accept","*")),Duration.ZERO));
 }
 @Test void sharedDirectivesDoNotChangeTheGeneralDocumentLifetimeProfile() {
  assertEquals(Duration.ofSeconds(120),CacheLifetime.timeToLive(HttpHeaders.of(Map.of("Cache-Control",List.of("s-maxage=5,max-age=120")),(a,b)->true),NOW,Duration.ZERO,Duration.ZERO,Duration.ofSeconds(300)));
 }
}
