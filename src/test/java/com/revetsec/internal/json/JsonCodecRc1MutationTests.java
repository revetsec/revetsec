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

package com.revetsec.internal.json;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

/** Adversarial admission boundaries retained from RC-1 mutation qualification. */
final class JsonCodecRc1MutationTests {
 private static final JsonLimits SMALL = new JsonLimits(4096, 8, 64, 2, 32, 1000, false);

 @Test void decodedStringLengthCountsEveryEscapeAndUtf8CodeUnit() {
  for (String unit : List.of("\\n", "\\\"", "\\u0061", "é", "€", "😀")) {
   int units = unit.equals("😀") ? 2 : 1;
   String accepted = "\"" + unit.repeat(2 / units) + "\"";
   Assertions.assertInstanceOf(JsonParseResult.Succeeded.class, parse(accepted, SMALL), accepted);
   String rejected = "\"" + unit.repeat(2 / units + 1) + "\"";
   JsonParseResult.Rejected failure = Assertions.assertInstanceOf(JsonParseResult.Rejected.class, parse(rejected, SMALL), rejected);
   Assertions.assertEquals(JsonParseException.Kind.STRING_LENGTH, failure.getKind());
   Assertions.assertEquals(0, failure.getByteOffset());
  }
 }

 @Test void incompleteLiteralNeverBecomesACompleteDocument() {
  for (String literal : List.of("true", "false", "null"))
   for (int length = 1; length < literal.length(); ++length) {
    String input = literal.substring(0, length);
    JsonParseResult.Rejected failure = Assertions.assertInstanceOf(JsonParseResult.Rejected.class, parse(input, SMALL), input);
    Assertions.assertEquals(JsonParseException.Kind.SYNTAX, failure.getKind());
    Assertions.assertEquals(input.length(), failure.getByteOffset());
   }
 }

 @Test void unterminatedStringEndingInRawJsonWhitespaceAlwaysRejects() {
  for (char control : new char[]{'\t', '\r', '\n'}) {
   String input = "\"" + control;
   JsonParseResult.Rejected failure = Assertions.assertInstanceOf(JsonParseResult.Rejected.class, parse(input, SMALL));
   Assertions.assertEquals(JsonParseException.Kind.SYNTAX, failure.getKind());
   Assertions.assertEquals(1, failure.getByteOffset());
  }
 }

 @Test void invalidTokenRemainsSyntaxEvenAtDepthAndNodeBudget() {
  for (JsonLimits limits : List.of(new JsonLimits(4096, 1, 64, 2, 32, 1000, false),
    new JsonLimits(4096, 8, 1, 2, 32, 1000, false))) {
   JsonParseResult.Rejected failure = Assertions.assertInstanceOf(JsonParseResult.Rejected.class, parse("[x]", limits));
   Assertions.assertEquals(JsonParseException.Kind.SYNTAX, failure.getKind());
   Assertions.assertEquals(1, failure.getByteOffset());
  }
 }

 @Test void scientificNumberCanonicalLengthTerminatesForSingleDigitExponent() {
  Assertions.assertInstanceOf(JsonParseResult.Succeeded.class, parse("1e-7", SMALL));
 }

 private static @NonNull JsonParseResult parse(@NonNull String input, @NonNull JsonLimits limits) {
  return Assertions.assertTimeoutPreemptively(Duration.ofSeconds(2),
    () -> JsonCodec.parseResult(input.getBytes(StandardCharsets.UTF_8), limits));
 }
}
