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
import java.time.Duration;
import java.util.List;

/** Admission checks retained from the RC-1 media-type mutation review. */
final class MediaTypeRc1MutationTests {
 @Test void quotedTextAndQuotedPairsMatchTheCompleteHeaderOctetAlphabet() {
  Assertions.assertTimeoutPreemptively(Duration.ofSeconds(2), () -> {
   StringBuilder pair = new StringBuilder("\t");
   for (int c = 32; c <= 126; ++c) pair.append((char) c);
   for (int c = 128; c <= 255; ++c) pair.append((char) c);
   String text = pair.toString().replace("\"", "").replace("\\", "");
   for (int c = 0; c <= 256; ++c) {
    char character = (char) c;
    Assertions.assertEquals(text.indexOf(character) >= 0,
      MediaType.parse("a/b;p=\"" + character + "\"").isPresent(), "qdtext octet " + c);
    Assertions.assertEquals(pair.indexOf(String.valueOf(character)) >= 0,
      MediaType.parse("a/b;p=\"\\" + character + "\"").isPresent(), "quoted-pair octet " + c);
   }
  });
 }

 @Test void asciiCaseAndTokenBoundariesArePreserved() {
  Assertions.assertTimeoutPreemptively(Duration.ofSeconds(2), () -> {
   MediaType value = parse("AZ/aZ;Z=A");
   Assertions.assertEquals("az/az", value.getEssence());
   Assertions.assertEquals("A", value.getParameters().get("z"));
   for (String token : List.of("0", "9", "A", "Z", "a", "z"))
    Assertions.assertEquals(token.toLowerCase(java.util.Locale.ROOT), parse(token + "/x").getType());
  });
 }

 @Test void equalityAcceptsSelfAndRejectsUnrelatedObjects() {
  MediaType value = parse("a/b;p=x");
  Assertions.assertTrue(value.equals(value));
  Assertions.assertFalse(value.equals(new Object()));
  Assertions.assertFalse(value.equals(null));
  Assertions.assertEquals(value, parse("A/B;P=x"));
  Assertions.assertEquals(value.hashCode(), parse("A/B;P=x").hashCode());
 }

 @Test void whitespaceAndQuotedParametersMakeBoundedForwardProgress() {
  Assertions.assertTimeoutPreemptively(Duration.ofSeconds(2), () -> {
   for (String field : List.of(" a/b ; p=x ", "a/b; p=\"\\\"\"", "a/b; p=\"x\"; q=y"))
    Assertions.assertEquals("a/b", parse(field).getEssence());
   for (String field : List.of("a/b;p=\"\\", "a/b;p=\"\n\"", "a/b;p=\"unterminated"))
    Assertions.assertTrue(MediaType.parse(field).isEmpty());
  });
 }

 @Test void malformedCacheControlQuotesCannotRestartTheDirectiveLoop() {
  Assertions.assertTimeoutPreemptively(Duration.ofSeconds(2),()->{
   for(String field:List.of(",max-age=\"60",",max-age=\"60\\",",max-age=\"60"+(char)1+"x")) {
    var headers=java.net.http.HttpHeaders.of(java.util.Map.of("Cache-Control",List.of(field)),(name,value)->true);
    Assertions.assertEquals(Duration.ofSeconds(5),CacheLifetime.timeToLive(headers,java.time.Instant.EPOCH,Duration.ofSeconds(5),Duration.ofSeconds(60),Duration.ofSeconds(120)));
   }
  });
 }

 private static @NonNull MediaType parse(@NonNull String field) { return MediaType.parse(field).orElseThrow(); }
}
