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

import com.revetsec.internal.json.JsonParseException.Kind;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonBoolean;
import com.revetsec.json.JsonNull;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import com.revetsec.testing.ChildJvm;
import com.revetsec.testing.Sentinels;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.ByteArrayOutputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.stream.Stream;

import static com.revetsec.internal.json.JsonFailures.ANY_OFFSET;
import static com.revetsec.internal.json.JsonFailures.SENTINEL;
import static com.revetsec.internal.json.JsonFailures.assertRejected;
import static com.revetsec.internal.json.JsonFailures.utf8;

/**
 * The JSON codec (RFC 8259; M1 plan gate 7 and exit criteria 2 and 3).
 * <p>
 * The first group ports 31 of the 34 cases of Soklet's {@code McpJsonCodecTests} at {@code 38786326} (G7-1), renamed
 * as behavior sentences and adapted where Revetsec dropped a Soklet feature: the {@code String} input path (inputs are
 * UTF-8 bytes), the output-byte and raw-token limits, and the writer's own limits (the model's invariants bound the
 * writer instead, G7-6). Cases that were about the dropped features now test the behavior that replaced them. The
 * other three live elsewhere: {@code retainedJsonCorpusMatchesItsSha256Manifest} is in
 * {@link JsonCorpusManifestTests}, and {@code jsonLimitsRejectUnsafeOrNonPositiveConfigurations} and
 * {@code productionJsonLimitsAndHardCeilingsAreFrozen} are in {@link JsonLimitsTests}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JsonCodecTests {
	/**
	 * Soklet's test profile: 4,096 input bytes, depth 16, 512 nodes, strings and numbers of 512, exponent 10,000.
	 */
	private static final JsonLimits LIMITS = new JsonLimits(4_096, 16, 512, 512, 512, 10_000, false);

	/**
	 * The default protocol profile, with room for JSONTestSuite's largest file.
	 */
	private static final JsonLimits PROTOCOL = JsonLimits.protocolDocument(256 * 1_024);

	/**
	 * The default SCIM profile.
	 */
	private static final JsonLimits SCIM = JsonLimits.scim(256 * 1_024, 100_000);

	private static final JsonLimits MAXIMUM = JsonLimits.maximumCaps();

	// ---------------------------------------------------------------------------------------------------------------
	// Ported from Soklet McpJsonCodecTests (38786326)
	// ---------------------------------------------------------------------------------------------------------------

	// Soklet: strictJsonParserAcceptsObjectRoot.
	@Test
	void parsesAnObjectRoot() throws JsonParseException {
		JsonValue value = parse("{\"jsonrpc\":\"2.0\",\"id\":1,\"params\":{}}", LIMITS);

		Assertions.assertInstanceOf(JsonObject.class, value);
		Assertions.assertEquals(JsonString.fromValue("2.0"), ((JsonObject) value).getMembers().get("jsonrpc"));
		Assertions.assertEquals(JsonObject.emptyInstance(), ((JsonObject) value).getMembers().get("params"));
	}

	// Soklet: strictJsonParserDecodesUtf8AndEscapedUnicode.
	@Test
	void decodesUtf8AndEscapedUnicode() throws JsonParseException {
		JsonValue value = parse("[\"caf\u00E9\",\"\\uD83D\\uDE80\"]", LIMITS);

		Assertions.assertEquals(JsonArray.fromElements(List.of(JsonString.fromValue("caf\u00E9"),
				JsonString.fromValue("\uD83D\uDE80"))), value);
	}

	// Soklet: strictJsonWriterRejectsUnpairedSurrogateBeforeOutput. Revetsec's writer cannot meet an unpaired
	// surrogate, because the model's factories reject one before any value (and so any output) exists (G7-6).
	@Test
	void theModelRejectsUnpairedSurrogatesBeforeAnyOutputExists() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> JsonString.fromValue("bad\uD800"));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> JsonObject.fromMembers(Map.of("bad\uDC00", JsonNull.defaultInstance())));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> JsonObject.builder().putNull("bad\uDC00"));
	}

	// Soklet: strictJsonWriterPreservesValidSurrogatePairs.
	@Test
	void writesValidSurrogatePairsAsUtf8AndParsesThemBack() throws JsonParseException {
		JsonString value = JsonString.fromValue("launch \uD83D\uDE80");
		byte[] serialized = JsonCodec.toUtf8Bytes(value);

		Assertions.assertArrayEquals(utf8("\"launch \uD83D\uDE80\""), serialized);
		Assertions.assertEquals(value, JsonCodec.parse(serialized, LIMITS));
	}

	// Soklet: strictJsonWriterEmitsJsonLineSeparatorsWithoutTokenExpansion. RFC 8259 does not require escaping
	// U+2028 and U+2029.
	@Test
	void writesLineAndParagraphSeparatorsUnescaped() throws JsonParseException {
		JsonString value = JsonString.fromValue("a\u2028b\u2029c");

		Assertions.assertEquals("\"a\u2028b\u2029c\"", value.toJson());
		Assertions.assertEquals(value, JsonCodec.parse(JsonCodec.toUtf8Bytes(value), LIMITS));
	}

	// Soklet: strictJsonWriterEmitsExponentNumbersThatReparse.
	@Test
	void writesExponentNumbersThatParseBack() throws JsonParseException {
		for (String number : List.of("1e1", "1e600", "1e-600", "12.50E+20")) {
			JsonValue parsed = parse(number, LIMITS);
			Assertions.assertEquals(parsed, JsonCodec.parse(utf8(parsed.toJson()), LIMITS), number);
		}
	}

	// Soklet: strictJsonWriterEscapesAndRoundTripsValues.
	@Test
	void escapesOnlyWhatJsonRequiresAndRoundTrips() throws JsonParseException {
		JsonObject value = JsonObject.builder()
				.put("quote\"slash\\", "\b\f\n\r\t\u0001")
				.put("number", new BigDecimal("123.4500"))
				.put("boolean", true)
				.putNull("null")
				.put("array", JsonArray.fromElements(List.of(JsonString.fromValue("\u00E9"))))
				.build();

		Assertions.assertEquals(value, JsonCodec.parse(JsonCodec.toUtf8Bytes(value), LIMITS));
		Assertions.assertEquals("{\"quote\\\"slash\\\\\":\"\\b\\f\\n\\r\\t\\u0001\",\"number\":123.4500,"
				+ "\"boolean\":true,\"null\":null,\"array\":[\"\u00E9\"]}", value.toJson());
	}

	// Soklet: strictJsonParserRejectsTrailingComma.
	@Test
	void rejectsTrailingCommas() {
		assertRejected(Kind.SYNTAX, 3, "[1,]", LIMITS);
		assertRejected(Kind.SYNTAX, 7, "{\"a\":1,}", LIMITS);
	}

	// Soklet: strictJsonParserRejectsLeadingZeroNumber (RFC 8259 section 6).
	@Test
	void rejectsLeadingZeros() {
		assertRejected(Kind.SYNTAX, 1, "01", LIMITS);
		assertRejected(Kind.SYNTAX, 2, "-01", LIMITS);
		assertRejected(Kind.SYNTAX, 1, "00.1", LIMITS);
	}

	// Soklet: strictJsonParserRejectsTrailingGarbage.
	@Test
	void rejectsTrailingContent() {
		assertRejected(Kind.SYNTAX, 3, "{} trailing", LIMITS);
		assertRejected(Kind.SYNTAX, 5, "true false", LIMITS);
	}

	// Soklet: strictJsonParserRejectsLeadingBom (RFC 8259 section 8.1). Soklet also rejected U+FEFF at the start of a
	// String input; Revetsec takes bytes only.
	@Test
	void rejectsALeadingByteOrderMark() {
		assertRejected(Kind.BOM, 0, new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF, '{', '}'}, LIMITS);
		assertRejected(Kind.BOM, 0, utf8("\uFEFF{}"), LIMITS);
	}

	// Soklet: strictJsonParserRejectsDuplicateObjectKey. Names compare after unescaping.
	@Test
	void rejectsDuplicateMemberNamesAfterUnescaping() {
		assertRejected(Kind.DUPLICATE_MEMBER, 7, "{\"a\":1,\"a\":2}", LIMITS);
		assertRejected(Kind.DUPLICATE_MEMBER, 7, "{\"a\":1,\"\\u0061\":2}", LIMITS);
	}

	// Soklet: strictJsonParserRejectsLoneLowSurrogate. Soklet's raw form was a String input holding U+DC00; as bytes, a
	// raw lone surrogate can only arrive encoded (ED B0 80), which is ill-formed UTF-8.
	@Test
	void rejectsALoneLowSurrogate() {
		assertRejected(Kind.UNPAIRED_SURROGATE, 1, "\"\\uDC00\"", LIMITS);
		assertRejected(Kind.INVALID_UTF8, 1, new byte[]{'"', (byte) 0xED, (byte) 0xB0, (byte) 0x80, '"'}, LIMITS);
	}

	// Soklet: strictJsonParserRejectsIncompleteObjectPropertyName.
	@Test
	void rejectsAnIncompleteMemberName() {
		assertRejected(Kind.SYNTAX, 1, "{", LIMITS);
		assertRejected(Kind.SYNTAX, 2, "{\"", LIMITS);
		assertRejected(Kind.SYNTAX, 6, "{\"name", LIMITS);
		assertRejected(Kind.SYNTAX, 7, "{\"name\"", LIMITS);
		assertRejected(Kind.SYNTAX, 8, "{\"name\":", LIMITS);
	}

	// Soklet: strictJsonParserRejectsNestingBeyondLimit. The writer has no depth limit of its own: the model's cap
	// bounds it (G7-6), so the depth-3 value serializes.
	@Test
	void rejectsNestingBeyondTheProfileDepth() throws JsonParseException {
		JsonLimits depthThree = new JsonLimits(4_096, 3, 512, 512, 512, 10_000, false);

		Assertions.assertEquals(parse("[[0]]", LIMITS), parse("[[0]]", depthThree));
		assertRejected(Kind.DEPTH, 3, "[[[0]]]", depthThree);
		Assertions.assertEquals("[[[0]]]", parse("[[[0]]]", LIMITS).toJson());
	}

	// Soklet: strictJsonParserRejectsNumberBeyondLengthLimit.
	@Test
	void rejectsANumberLongerThanTheProfileAllows() throws JsonParseException {
		assertRejected(Kind.NUMBER_LENGTH, 0, "1".repeat(513), LIMITS);
		Assertions.assertEquals(JsonNumber.fromValue(new BigDecimal("1".repeat(512))), parse("1".repeat(512), LIMITS));
	}

	// M1 plan "Number cost" and INV-G4: the number limit bounds the written text while it is scanned, before any
	// BigDecimal work, even when the canonical form would be short. Leading zeros in a fraction or an exponent, and the
	// sign, all count: 513 characters are rejected under a 512-character limit, and 512 pass.
	@Test
	void boundsANumbersWrittenTextEvenWhenItsCanonicalFormIsShorter() throws JsonParseException {
		for (String[] row : List.of(
				new String[]{"0." + "0".repeat(509) + "1", "1E-510"},
				new String[]{"-0." + "0".repeat(508) + "1", "-1E-509"},
				new String[]{"1e" + "0".repeat(509) + "1", "1E+1"},
				new String[]{"1.0e-" + "0".repeat(506) + "1", "0.10"})) {
			String longest = row[0];
			String tooLong = longest.substring(0, longest.length() - 1) + "0" + longest.charAt(longest.length() - 1);

			Assertions.assertEquals(512, longest.length());
			Assertions.assertEquals(row[1], parse(longest, LIMITS).toJson(), longest);
			assertRejected(Kind.NUMBER_LENGTH, 0, tooLong, LIMITS);
			assertRejected(Kind.NUMBER_LENGTH, 1, "[" + tooLong + "]", LIMITS);
		}
	}

	// Soklet: strictJsonParserAcceptsMaximumExponentMagnitude.
	@Test
	void acceptsTheMaximumExponentMagnitude() throws JsonParseException {
		Assertions.assertEquals(JsonNumber.fromValue(new BigDecimal("1e10000")), parse("1e10000", LIMITS));
		Assertions.assertEquals(JsonNumber.fromValue(new BigDecimal("1e-10000")), parse("1e-10000", LIMITS));
	}

	// Soklet: strictJsonParserRejectsExponentBeyondMagnitudeLimit.
	@Test
	void rejectsAnExponentBeyondTheMagnitudeLimit() {
		assertRejected(Kind.EXPONENT, 0, "1e10001", LIMITS);
		assertRejected(Kind.EXPONENT, 0, "1e-10001", LIMITS);
		assertRejected(Kind.EXPONENT, 0, "1e999999999999999999", LIMITS);
	}

	// Soklet: strictJsonParserRejectsCanonicalNumberBeyondLengthLimit. The file's text is 511 characters, but its
	// canonical form (9.99...E+517) is 515.
	@Test
	void rejectsANumberWhoseCanonicalFormIsLongerThanTheProfileAllows() {
		byte[] input = JsonCorpus.read("parse/canonical-length-overflow.json");

		Assertions.assertEquals(511, input.length);
		assertRejected(Kind.NUMBER_LENGTH, 0, input, LIMITS);
	}

	// Soklet: strictJsonParserRejectsCanonicalExponentBeyondMagnitudeLimit. 12e10000 is 1.2E+10001: its written
	// exponent is allowed, its adjusted exponent is not. The model accepts it (its cap is 100,000), and its canonical
	// form is rejected by the same profile.
	@Test
	void rejectsANumberWhoseAdjustedExponentIsBeyondTheMagnitudeLimit() {
		assertRejected(Kind.EXPONENT, 0, "12e10000", LIMITS);

		JsonNumber model = JsonNumber.fromValue(new BigDecimal("12e10000"));
		Assertions.assertEquals("1.2E+10001", model.toJson());
		assertRejected(Kind.EXPONENT, 0, model.toJson(), LIMITS);
	}

	// Soklet: strictJsonParserRejectsMalformedUtf8ByteSequences (Unicode Table 3-7).
	@Test
	void rejectsMalformedUtf8() {
		assertRejected(Kind.INVALID_UTF8, 16, JsonCorpus.read("parse/invalid-utf8-large-truncated-envelope.bin"),
				LIMITS);
		assertRejected(Kind.INVALID_UTF8, 2, JsonCorpus.read("parse/invalid-utf8-nested-object.bin"), LIMITS);
		assertRejected(Kind.INVALID_UTF8, 5, JsonCorpus.read("parse/invalid-utf8-property-name-truncated-id.bin"),
				LIMITS);
		assertRejected(Kind.INVALID_UTF8, 1, new byte[]{'"', (byte) 0xC0, (byte) 0xAF, '"'}, LIMITS);

		for (byte[] invalid : List.of(
				new byte[]{(byte) 0xC2},
				new byte[]{(byte) 0xE2, (byte) 0x82},
				new byte[]{(byte) 0xF0, (byte) 0x9F, (byte) 0x92},
				new byte[]{(byte) 0x80},
				new byte[]{(byte) 0xED, (byte) 0xA0, (byte) 0x80},
				new byte[]{(byte) 0xF4, (byte) 0x90, (byte) 0x80, (byte) 0x80}))
			assertRejected(Kind.INVALID_UTF8, 0, invalid, LIMITS);
	}

	// Soklet: strictJsonParserAndWriterAcceptDepth256AndRejectDepth257, at Revetsec's model cap of 64 (G5-2, G7-6):
	// the maximum-cap profile parses depth 64, the writer writes it, and depth 65 is rejected by both the profile and
	// the model.
	@Test
	void acceptsTheModelDepthCapAndRejectsOneLevelMore() throws JsonParseException {
		JsonValue depth64 = JsonNumber.fromValue(0L);
		String depth64Json = "0";

		for (int depth = 1; depth < 64; ++depth) {
			depth64 = JsonArray.fromElements(List.of(depth64));
			depth64Json = "[" + depth64Json + "]";
		}

		Assertions.assertEquals(depth64, parse(depth64Json, MAXIMUM));
		Assertions.assertEquals(depth64Json, depth64.toJson());
		assertRejected(Kind.DEPTH, 64, "[" + depth64Json + "]", MAXIMUM);

		JsonValue deepest = depth64;
		Assertions.assertThrows(IllegalArgumentException.class, () -> JsonArray.fromElements(List.of(deepest)));
	}

	// Soklet: productionJsonDepthAccepts128AndRejects129, for Revetsec's default profiles (exit criterion 2): protocol
	// documents nest at most 32 deep and SCIM documents 64. N nested empty arrays have depth N; N arrays around a
	// scalar have depth N + 1.
	@TestFactory
	Stream<DynamicTest> enforcesTheExactDepthBoundaryOfEachProfile() {
		return Stream.of(new Object[]{"protocol", PROTOCOL, 32}, new Object[]{"scim", SCIM, 64}).flatMap(row -> {
			String name = (String) row[0];
			JsonLimits limits = (JsonLimits) row[1];
			int maximum = (Integer) row[2];

			return Stream.of(
					DynamicTest.dynamicTest(name + ": " + maximum + " nested empty arrays pass",
							() -> Assertions.assertEquals(nested(maximum, ""), parse(nested(maximum, ""), limits).toJson())),
					DynamicTest.dynamicTest(name + ": " + (maximum - 1) + " arrays around a scalar pass",
							() -> Assertions.assertEquals(nested(maximum - 1, "0"),
									parse(nested(maximum - 1, "0"), limits).toJson())),
					DynamicTest.dynamicTest(name + ": " + (maximum + 1) + " nested empty arrays give DEPTH",
							() -> assertRejected(Kind.DEPTH, maximum, nested(maximum + 1, ""), limits)),
					DynamicTest.dynamicTest(name + ": " + maximum + " arrays around a scalar give DEPTH",
							() -> assertRejected(Kind.DEPTH, maximum, nested(maximum, "0"), limits)),
					DynamicTest.dynamicTest(name + ": objects follow the same count",
							() -> {
								Assertions.assertEquals(nestedObjects(maximum - 1, "0"),
										parse(nestedObjects(maximum - 1, "0"), limits).toJson());
								assertRejected(Kind.DEPTH, 5 * maximum, nestedObjects(maximum, "0"), limits);
							}));
		});
	}

	// Soklet: strictJsonParserEnforcesRawTokenAndDecodedStringBounds. The raw-token limit was dropped; the decoded
	// string limit counts UTF-16 code units after unescaping, in values and member names alike.
	@Test
	void boundsEachDecodedStringInUtf16CodeUnits() throws JsonParseException {
		JsonLimits four = new JsonLimits(64, 4, 16, 4, 16, 16, false);
		JsonLimits three = new JsonLimits(64, 4, 16, 3, 16, 16, false);

		Assertions.assertEquals(JsonString.fromValue("a"), parse("\"\\u0061\"", three));
		Assertions.assertEquals(JsonString.fromValue("abcd"), parse("\"abcd\"", four));
		assertRejected(Kind.STRING_LENGTH, 0, "\"abcd\"", three);
		assertRejected(Kind.STRING_LENGTH, 1, "{\"abcd\":1}", three);
		// One supplementary character is two code units, raw or escaped.
		Assertions.assertEquals(JsonString.fromValue("a\uD83D\uDE80"), parse("\"a\uD83D\uDE80\"", three));
		Assertions.assertEquals(JsonString.fromValue("a\uD83D\uDE80"), parse("\"a\\uD83D\\uDE80\"", three));
		assertRejected(Kind.STRING_LENGTH, 0, "\"ab\uD83D\uDE80\"", three);
		assertRejected(Kind.STRING_LENGTH, 0, "\"ab\\uD83D\\uDE80\"", three);
		// Characters of two and three UTF-8 bytes are one code unit each.
		Assertions.assertEquals(JsonString.fromValue("\u00E9\u20AC\u00E9"), parse("\"\u00E9\u20AC\u00E9\"", three));
	}

	// Soklet: strictJsonParserAndWriterEnforceExactNodeCounts. Every value counts, the root and containers included;
	// member names do not. The writer has no node limit.
	@Test
	void countsEveryValueAsANodeButNoMemberName() throws JsonParseException {
		JsonArray threeNodes = JsonArray.fromElements(List.of(JsonNull.defaultInstance(),
				JsonBoolean.trueInstance()));
		JsonLimits threeNodeLimits = new JsonLimits(4_096, 16, 3, 512, 512, 10_000, false);
		JsonLimits twoNodeLimits = new JsonLimits(4_096, 16, 2, 512, 512, 10_000, false);

		Assertions.assertEquals(threeNodes, JsonCodec.parse(utf8("[null,true]"), threeNodeLimits));
		Assertions.assertEquals("[null,true]", threeNodes.toJson());
		assertRejected(Kind.NODES, 6, "[null,true]", twoNodeLimits);
		// {"a":{"b":1}} is three values; the two names do not count.
		Assertions.assertEquals(3, countValues(parse("{\"a\":{\"b\":1}}", threeNodeLimits)));
		assertRejected(Kind.NODES, 10, "{\"a\":{\"b\":1}}", twoNodeLimits);
	}

	// Soklet: strictJsonWriterEnforcesExactUtf8OutputBytes. The output-byte limit was dropped; toUtf8Bytes writes
	// exactly the UTF-8 encoding of the JSON text.
	@Test
	void writesExactlyTheUtf8EncodingOfTheJsonText() {
		JsonString value = JsonString.fromValue("\u00E9");

		Assertions.assertArrayEquals(new byte[]{'"', (byte) 0xC3, (byte) 0xA9, '"'}, JsonCodec.toUtf8Bytes(value));
		Assertions.assertArrayEquals(utf8(value.toJson()), JsonCodec.toUtf8Bytes(value));
	}

	// Soklet: strictJsonParserEnforcesExactUtf8InputBytes. The limit counts bytes, not characters, and is checked
	// before anything is read.
	@Test
	void boundsTheInputInBytes() throws JsonParseException {
		byte[] value = utf8("\"\u00E9\"");
		JsonLimits fourBytes = new JsonLimits(4, 16, 512, 512, 512, 10_000, false);
		JsonLimits threeBytes = new JsonLimits(3, 16, 512, 512, 512, 10_000, false);

		Assertions.assertEquals(JsonString.fromValue("\u00E9"), JsonCodec.parse(value, fourBytes));
		assertRejected(Kind.INPUT_SIZE, 3, value, threeBytes);
		// Nothing else is read: an oversized input that is also ill-formed is still INPUT_SIZE.
		assertRejected(Kind.INPUT_SIZE, 3, new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF, (byte) 0xFF}, threeBytes);
	}

	// Soklet: strictJsonParserRejectsEveryUnpairedSurrogateForm.
	@Test
	void rejectsEveryUnpairedSurrogateForm() {
		assertRejected(Kind.UNPAIRED_SURROGATE, 1, "\"\\uD800\"", LIMITS);
		assertRejected(Kind.UNPAIRED_SURROGATE, 1, "\"\\uD800x\"", LIMITS);
		assertRejected(Kind.UNPAIRED_SURROGATE, 1, "\"\\uD800\\u0041\"", LIMITS);
		assertRejected(Kind.UNPAIRED_SURROGATE, 1, "\"\\uDC00\"", LIMITS);
		assertRejected(Kind.INVALID_UTF8, 1, new byte[]{'"', (byte) 0xED, (byte) 0xA0, (byte) 0x80, '"'}, LIMITS);
		Assertions.assertThrows(IllegalArgumentException.class, () -> JsonString.fromValue("\uDC00"));
	}

	// Soklet: strictJsonParserImplementsTheCompleteJsonNumberGrammar (RFC 8259 section 6).
	@TestFactory
	Stream<DynamicTest> implementsTheCompleteNumberGrammar() {
		Stream<DynamicTest> valid = Stream.of("0", "-0", "1", "-1", "0.0", "-0.1", "1e0", "1E+2", "1e-2", "1.23e4",
				"1E-0", "0e0", "-0.0e-0", "123456789012345678901234567890").map(number -> DynamicTest.dynamicTest(
				"accepts " + number, () -> Assertions.assertEquals(JsonNumber.fromValue(new BigDecimal(number)),
						parse(number, LIMITS))));
		Stream<DynamicTest> invalid = Stream.of(
				new Object[]{"-", 1}, new Object[]{"+1", 0}, new Object[]{"01", 1}, new Object[]{"-01", 2},
				new Object[]{".1", 0}, new Object[]{"1.", 2}, new Object[]{"1e", 2}, new Object[]{"1e+", 3},
				new Object[]{"--1", 1}, new Object[]{"NaN", 0}, new Object[]{"Infinity", 0}, new Object[]{"00", 1},
				new Object[]{"1..0", 2}, new Object[]{"-a", 1}, new Object[]{"1.e1", 2}, new Object[]{"1e1.5", 3},
				new Object[]{"0x1", 1}, new Object[]{"1_000", 1}, new Object[]{"-Infinity", 1}, new Object[]{"1E++1", 3})
				.map(row -> DynamicTest.dynamicTest("rejects " + row[0],
						() -> assertRejected(Kind.SYNTAX, (Integer) row[1], (String) row[0], LIMITS)));
		return Stream.concat(valid, invalid);
	}

	// Soklet: strictJsonCodecReplaysTheRetainedCorpus, with the default protocol profile as Soklet's production
	// profile, plus the round-trip files under the maximum-cap profile.
	@Test
	void replaysTheRetainedCorpus() throws JsonParseException {
		for (String fixture : List.of("parse/array.json", "parse/object.json", "parse/string-escapes.json",
				"parse/surrogate-pair.json", "parse/deep-array.json", "parse/exponent-limit.json")) {
			Assertions.assertDoesNotThrow(() -> JsonCodec.parse(JsonCorpus.read(fixture), LIMITS), fixture);
			Assertions.assertDoesNotThrow(() -> JsonCodec.parse(JsonCorpus.read(fixture), PROTOCOL), fixture);
		}

		Map<String, Kind> rejected = new LinkedHashMap<>();
		rejected.put("parse/canonical-exponent-overflow.json", Kind.EXPONENT);
		rejected.put("parse/canonical-length-overflow.json", Kind.NUMBER_LENGTH);
		rejected.put("parse/duplicate-keys.json", Kind.DUPLICATE_MEMBER);
		rejected.put("parse/incomplete-object.json", Kind.SYNTAX);
		rejected.put("parse/invalid-number.json", Kind.SYNTAX);
		rejected.put("parse/leading-bom.json", Kind.BOM);
		rejected.put("parse/lone-low-surrogate.json", Kind.UNPAIRED_SURROGATE);
		rejected.put("parse/truncated-array-object-with-whitespace.json", Kind.SYNTAX);
		rejected.put("parse/truncated-deep-array-object.json", Kind.SYNTAX);
		rejected.put("parse/truncated-nested-array-object.json", Kind.SYNTAX);
		rejected.put("parse/truncated-object-minimal.json", Kind.SYNTAX);

		for (Map.Entry<String, Kind> fixture : rejected.entrySet())
			assertRejected(fixture.getValue(), ANY_OFFSET, JsonCorpus.read(fixture.getKey()), LIMITS);

		for (String fixture : List.of("round-trip/exponent-scale.json", "round-trip/large-exponent.json",
				"round-trip/line-separators.json", "round-trip/nested.json", "round-trip/surrogate-pair.json")) {
			JsonValue value = JsonCodec.parse(JsonCorpus.read(fixture), LIMITS);
			Assertions.assertEquals(value, JsonCodec.parse(JsonCodec.toUtf8Bytes(value), LIMITS), fixture);
			Assertions.assertEquals(value, JsonCodec.parse(JsonCodec.toUtf8Bytes(value), MAXIMUM), fixture);
		}
	}

	// Soklet: strictJsonCodecPreservesEncounterOrderAndRejectsNonJsonWhitespace (RFC 8259 section 2).
	@Test
	void keepsMemberOrderAndRejectsWhitespaceJsonDoesNotDefine() throws JsonParseException {
		Assertions.assertEquals("{\"z\":null,\"a\":true}", JsonObject.builder().putNull("z").put("a", true).build()
				.toJson());
		Assertions.assertEquals("{\"z\":null,\"a\":true}", parse(" {\t\"z\" :\r\nnull , \"a\":true}\n", LIMITS)
				.toJson());
		assertRejected(Kind.SYNTAX, 0, "\u00A0null", LIMITS);
		assertRejected(Kind.SYNTAX, 0, "\u000Bnull", LIMITS);
		assertRejected(Kind.SYNTAX, 0, "\u000Cnull", LIMITS);
		assertRejected(Kind.SYNTAX, 1, "[\u2028]", LIMITS);
		assertRejected(Kind.SYNTAX, 4, "null\u0000", LIMITS);
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Exit criterion 2: lone surrogates, BOM, exponents
	// ---------------------------------------------------------------------------------------------------------------

	// Exit criterion 2: lone surrogates escaped (UNPAIRED_SURROGATE, at the escape's backslash), raw (a surrogate code
	// unit written straight into the bytes, as modified UTF-8 or WTF-8 does) and UTF-8-encoded (a pair as CESU-8)
	// are rejected, in values and member names, under both profiles. The last two are ill-formed UTF-8 (Unicode
	// Table 3-7), so they fail before tokenizing.
	@TestFactory
	Stream<DynamicTest> rejectsLoneSurrogatesEscapedRawAndUtf8Encoded() {
		List<DynamicTest> tests = new ArrayList<>();

		for (JsonLimits limits : List.of(PROTOCOL, SCIM)) {
			String profile = limits.isAsciiCaseVariantNamesRejected() ? "scim" : "protocol";
			tests.add(DynamicTest.dynamicTest(profile + ": escaped high surrogate at the end of a string",
					() -> assertRejected(Kind.UNPAIRED_SURROGATE, 4, "[\"ab\\uD834\"]", limits)));
			tests.add(DynamicTest.dynamicTest(profile + ": escaped high surrogate before a plain character",
					() -> assertRejected(Kind.UNPAIRED_SURROGATE, 2, "[\"\\uD834x\\uDD1E\"]", limits)));
			tests.add(DynamicTest.dynamicTest(profile + ": escaped high surrogate before another escape",
					() -> assertRejected(Kind.UNPAIRED_SURROGATE, 2, "[\"\\uD834\\n\"]", limits)));
			tests.add(DynamicTest.dynamicTest(profile + ": two escaped high surrogates",
					() -> assertRejected(Kind.UNPAIRED_SURROGATE, 2, "[\"\\uD834\\uD834\"]", limits)));
			tests.add(DynamicTest.dynamicTest(profile + ": escaped high surrogate before a malformed escape",
					() -> assertRejected(Kind.UNPAIRED_SURROGATE, 2, "[\"\\uD834\\uDD1\"]", limits)));
			tests.add(DynamicTest.dynamicTest(profile + ": escaped high surrogate at the end of the input",
					() -> assertRejected(Kind.UNPAIRED_SURROGATE, 2, "[\"\\uD834", limits)));
			tests.add(DynamicTest.dynamicTest(profile + ": escaped low surrogate alone",
					() -> assertRejected(Kind.UNPAIRED_SURROGATE, 2, "[\"\\uDD1E\"]", limits)));
			tests.add(DynamicTest.dynamicTest(profile + ": escaped pair in the wrong order",
					() -> assertRejected(Kind.UNPAIRED_SURROGATE, 2, "[\"\\uDD1E\\uD834\"]", limits)));
			tests.add(DynamicTest.dynamicTest(profile + ": escaped low surrogate in a member name",
					() -> assertRejected(Kind.UNPAIRED_SURROGATE, 8, "{\"a\":1,\"\\uDFFF\":2}", limits)));
			tests.add(DynamicTest.dynamicTest(profile + ": raw high surrogate (ED A0 80)",
					() -> assertRejected(Kind.INVALID_UTF8, 2, bytes('[', '"', 0xED, 0xA0, 0x80, '"', ']'), limits)));
			tests.add(DynamicTest.dynamicTest(profile + ": raw low surrogate (ED BF BF) in a member name",
					() -> assertRejected(Kind.INVALID_UTF8, 2, bytes('{', '"', 0xED, 0xBF, 0xBF, '"', ':', '1', '}'),
							limits)));
			tests.add(DynamicTest.dynamicTest(profile + ": UTF-8-encoded pair (CESU-8 of U+1D11E)",
					() -> assertRejected(Kind.INVALID_UTF8, 2, bytes('[', '"', 0xED, 0xA0, 0xB4, 0xED, 0xB4, 0x9E, '"',
							']'), limits)));
			tests.add(DynamicTest.dynamicTest(profile + ": escaped and encoded pairs are accepted",
					() -> Assertions.assertEquals(parse("[\"\\uD834\\uDD1E\"]", limits),
							JsonCodec.parse(bytes('[', '"', 0xF0, 0x9D, 0x84, 0x9E, '"', ']'), limits))));
		}

		return tests.stream();
	}

	// Exit criterion 2 and RFC 8259 section 8.1: a leading UTF-8 byte-order mark is BOM; U+FEFF inside a string is
	// data; elsewhere it is a character outside a string; UTF-16 byte-order marks are not UTF-8.
	@Test
	void rejectsAByteOrderMarkWhereverItIsNotData() throws JsonParseException {
		for (JsonLimits limits : List.of(PROTOCOL, SCIM)) {
			assertRejected(Kind.BOM, 0, bytes(0xEF, 0xBB, 0xBF), limits);
			assertRejected(Kind.BOM, 0, bytes(0xEF, 0xBB, 0xBF, '[', ']'), limits);
			assertRejected(Kind.SYNTAX, 1, bytes(' ', 0xEF, 0xBB, 0xBF, '[', ']'), limits);
			assertRejected(Kind.INVALID_UTF8, 0, bytes(0xFE, 0xFF, 0x00, '['), limits);
			assertRejected(Kind.INVALID_UTF8, 0, bytes(0xFF, 0xFE, '[', 0x00), limits);
			assertRejected(Kind.INVALID_UTF8, 0, bytes(0xEF, 0xBB), limits);
			Assertions.assertEquals(JsonString.fromValue("\uFEFF"), JsonCodec.parse(bytes('"', 0xEF, 0xBB, 0xBF, '"'),
					limits));
		}
	}

	// Exit criterion 2: 1E+2147483648 (an exponent past Integer.MAX_VALUE) and 12e10000 (adjusted exponent 10,001)
	// give EXPONENT, at the number's first byte, under both profiles, while 1e10000 and 1.5e+9999 pass.
	@Test
	void rejectsExponentsBeyondTheDefaultMagnitude() throws JsonParseException {
		for (JsonLimits limits : List.of(PROTOCOL, SCIM)) {
			assertRejected(Kind.EXPONENT, 0, "1E+2147483648", limits);
			assertRejected(Kind.EXPONENT, 0, "12e10000", limits);
			assertRejected(Kind.EXPONENT, 1, "[1E+2147483648]", limits);
			assertRejected(Kind.EXPONENT, 6, "{\"a\": 12e10000}", limits);
			// The written exponent is checked as it is read, before any BigDecimal work.
			assertRejected(Kind.EXPONENT, 0, "1e" + "9".repeat(1_000), limits);
			// The adjusted exponent: 0.001e10002 is 1E+9999, but its written exponent is too large; 1000e9998 is
			// 1E+10001 with an allowed written exponent.
			assertRejected(Kind.EXPONENT, 0, "0.001e10002", limits);
			assertRejected(Kind.EXPONENT, 0, "1000e9998", limits);
			assertRejected(Kind.EXPONENT, 0, "0e10001", limits);
			assertRejected(Kind.EXPONENT, 0, "0.0001e-9997", limits);
			Assertions.assertEquals("1E+10000", parse("1e10000", limits).toJson());
			Assertions.assertEquals("1.5E+9999", parse("1.5e+9999", limits).toJson());
			Assertions.assertEquals("1E-10000", parse("0.001e-9997", limits).toJson());
			Assertions.assertEquals("1E+9", parse("1e00000000000000000009", limits).toJson());
		}
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Exit criterion 3: duplicate members
	// ---------------------------------------------------------------------------------------------------------------

	// Exit criterion 3: a repeated name is rejected at every depth either profile allows, inside objects and inside
	// arrays of objects, at the repeated name's opening quotation mark.
	@TestFactory
	Stream<DynamicTest> rejectsDuplicateMembersAtEveryDepth() {
		List<DynamicTest> tests = new ArrayList<>();

		for (JsonLimits limits : List.of(PROTOCOL, SCIM)) {
			String profile = limits.isAsciiCaseVariantNamesRejected() ? "scim" : "protocol";

			// An object with members is at most one level above the deepest allowed value, so depth maxDepth - 1 is the
			// deepest place a duplicate can be.
			for (int depth = 1; depth < limits.getMaxDepth(); ++depth) {
				int level = depth;
				// depth - 1 objects {"k": ...} around the object that repeats "a". Where there is room, a nested "a" in
				// another object comes between the two, and must not count.
				String prefix = "{\"k\":".repeat(depth - 1);
				String suffix = "}".repeat(depth - 1);
				String inner = depth + 3 <= limits.getMaxDepth() ? "{\"a\":1,\"b\":[{\"a\":1}],\"a\":2}"
						: "{\"a\":1,\"a\":2}";
				int offset = prefix.length() + inner.lastIndexOf("\"a\"");

				tests.add(DynamicTest.dynamicTest(profile + ": duplicate at depth " + level, () -> {
					assertRejected(Kind.DUPLICATE_MEMBER, offset, prefix + inner + suffix, limits);
					Assertions.assertDoesNotThrow(() -> JsonCodec.parse(utf8(prefix + inner.replace(",\"a\":2", "")
							+ suffix), limits));
				}));
			}

			String arrayPrefix = "[".repeat(limits.getMaxDepth() - 2);
			String arraySuffix = "]".repeat(limits.getMaxDepth() - 2);
			tests.add(DynamicTest.dynamicTest(profile + ": duplicate in an object at the deepest level, inside arrays",
					() -> assertRejected(Kind.DUPLICATE_MEMBER, arrayPrefix.length() + 7, arrayPrefix
							+ "{\"x\":0,\"x\":0}" + arraySuffix, limits)));
		}

		return tests.stream();
	}

	// M1 plan: duplicates are rejected after unescaping, before the member's value is parsed, so a repeated name
	// followed by a malformed or oversized value still reports DUPLICATE_MEMBER.
	@Test
	void detectsADuplicateBeforeParsingItsValue() {
		assertRejected(Kind.DUPLICATE_MEMBER, 7, "{\"a\":1,\"a\":@", LIMITS);
		assertRejected(Kind.DUPLICATE_MEMBER, 7, "{\"a\":1,\"a\":" + "[".repeat(100), LIMITS);
		assertRejected(Kind.DUPLICATE_MEMBER, 7, "{\"a\":1,\"a\":1e99999}", LIMITS);
		assertRejected(Kind.DUPLICATE_MEMBER, 7, "{\"a\":1,\"a\"", LIMITS);
		assertRejected(Kind.DUPLICATE_MEMBER, 8, "{\"\\/\":1,\"/\":2}", LIMITS);
	}

	// Exit criterion 3 and G7-7: under SCIM, names that differ only in ASCII case are duplicates at every depth
	// (id and ID); the protocol profile keeps them apart.
	@TestFactory
	Stream<DynamicTest> scimRejectsNamesThatDifferOnlyInAsciiCase() {
		List<DynamicTest> tests = new ArrayList<>();

		for (int depth : List.of(1, 2, 8, 15, 31, 32, 33, 48, 62, 63)) {
			String prefix = "{\"Wrapper\":".repeat(depth - 1);
			String suffix = "}".repeat(depth - 1);
			String inner = "{\"id\":\"1\",\"ID\":\"2\"}";
			int offset = prefix.length() + inner.indexOf("\"ID\"");
			tests.add(DynamicTest.dynamicTest("id and ID at depth " + depth, () -> {
				assertRejected(Kind.DUPLICATE_MEMBER, offset, prefix + inner + suffix, SCIM);
				// The maximum-cap profile compares names exactly, at the same depth cap as SCIM.
				Assertions.assertEquals(2, ((JsonObject) innermost(parse(prefix + inner + suffix, MAXIMUM))).getMembers()
						.size());
			}));
		}

		tests.add(DynamicTest.dynamicTest("every mixed-case spelling of userName is one name", () -> {
			for (String variant : List.of("USERNAME", "username", "UserName", "uSeRnAmE"))
				assertRejected(Kind.DUPLICATE_MEMBER, 16, "{\"userName\":\"a\",\"" + variant + "\":\"b\"}", SCIM);
		}));
		tests.add(DynamicTest.dynamicTest("escaped case variants are compared after unescaping",
				() -> assertRejected(Kind.DUPLICATE_MEMBER, 8, "{\"id\":1,\"\\u0049\\u0044\":2}", SCIM)));
		tests.add(DynamicTest.dynamicTest("exact duplicates are still duplicates",
				() -> assertRejected(Kind.DUPLICATE_MEMBER, 8, "{\"id\":1,\"id\":2}", SCIM)));
		tests.add(DynamicTest.dynamicTest("case variants in sibling objects are not duplicates",
				() -> Assertions.assertDoesNotThrow(() -> JsonCodec.parse(utf8("[{\"id\":1},{\"ID\":2}]"), SCIM))));

		return tests.stream();
	}

	// Exit criterion 3 and G7-7: only A-Z fold, so the dotless i (U+0131), the dotted capital I (U+0130), the Kelvin
	// sign (U+212A) and the long s (U+017F), which the JDK's case-insensitive comparisons equate with ASCII letters,
	// give distinct names under SCIM.
	@Test
	void scimKeepsNonAsciiCaseVariantsDistinct() throws JsonParseException {
		for (String pair : List.of("{\"\u0131d\":1,\"id\":2}", "{\"\u0130D\":1,\"id\":2}", "{\"\u212Aey\":1,\"key\":2}",
				"{\"\u017Fub\":1,\"sub\":2}", "{\"\\u0131d\":1,\"ID\":2}"))
			Assertions.assertEquals(2, ((JsonObject) parse(pair, SCIM)).getMembers().size(), pair);
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Failure contract (R9, G7-3): a Kind, a byte offset and a fixed message, and never the input
	// ---------------------------------------------------------------------------------------------------------------

	// G7-3 and R9: every Kind is reachable, and each failure carries the fixed message, a byte offset into the input,
	// no cause and nothing suppressed, while no rendering (message, toString, stack trace) contains the sentinel
	// embedded next to the failing byte.
	@TestFactory
	Stream<DynamicTest> everyFailureHasAFixedMessageAndNeverEchoesTheInput() {
		JsonLimits small = new JsonLimits(4_096, 4, 16, 64, 64, 100, false);
		JsonLimits smallScim = new JsonLimits(4_096, 4, 16, 64, 64, 100, true);
		String secret = SENTINEL;
		Map<Kind, List<Object[]>> cases = new EnumMap<>(Kind.class);
		cases.put(Kind.SYNTAX, List.<Object[]>of(
				new Object[]{"[\"" + secret + "\" " + secret + "]", small},
				new Object[]{"{\"" + secret + "\":" + secret + "}", small},
				new Object[]{"\"" + secret + "\\q\"", small},
				new Object[]{"\"" + secret + "\u0001\"", small},
				new Object[]{"[\"" + secret + "\"", small}));
		cases.put(Kind.INVALID_UTF8, List.<Object[]>of(new Object[]{concat(utf8("[\"" + secret),
				bytes(0xC0, 0x80, '"', ']')), small}));
		cases.put(Kind.BOM, List.<Object[]>of(new Object[]{concat(bytes(0xEF, 0xBB, 0xBF), utf8("\"" + secret + "\"")),
				small}));
		cases.put(Kind.UNPAIRED_SURROGATE, List.<Object[]>of(new Object[]{"[\"" + secret + "\\uDEAD\"]", small},
				new Object[]{"{\"" + secret + "\\uD800\":0}", small}));
		cases.put(Kind.DUPLICATE_MEMBER, List.<Object[]>of(
				new Object[]{"{\"" + secret + "\":1,\"" + secret + "\":2}", small},
				new Object[]{"{\"" + secret + "\":1,\"" + secret.toUpperCase(Locale.ROOT) + "\":2}",
						smallScim}));
		cases.put(Kind.DEPTH, List.<Object[]>of(new Object[]{"[[[[\"" + secret + "\"]]]]", small}));
		cases.put(Kind.NODES, List.<Object[]>of(new Object[]{"[\"" + secret + "\"" + ",0".repeat(16) + "]", small}));
		cases.put(Kind.STRING_LENGTH, List.<Object[]>of(new Object[]{"[\"" + secret + secret + "\"]", small}));
		cases.put(Kind.NUMBER_LENGTH, List.<Object[]>of(new Object[]{"[\"" + secret + "\"," + "7".repeat(65) + "]",
				small}));
		cases.put(Kind.EXPONENT, List.<Object[]>of(new Object[]{"[\"" + secret + "\",1e101]", small}));
		cases.put(Kind.INPUT_SIZE, List.<Object[]>of(new Object[]{"\"" + secret + "\"",
				new JsonLimits(8, 4, 16, 64, 64, 100, false)}));

		Assertions.assertEquals(EnumSet.allOf(Kind.class), cases.keySet(), "every Kind needs a no-echo case");

		return cases.entrySet().stream().flatMap(entry -> entry.getValue().stream().map(row -> {
			byte[] input = row[0] instanceof String text ? utf8(text) : (byte[]) row[0];
			return DynamicTest.dynamicTest(entry.getKey() + " " + JsonFailures.describe(input).replace(secret, "<s>"),
					() -> {
						Assertions.assertTrue(Sentinels.containsSentinel(new String(input, StandardCharsets.ISO_8859_1)),
								"positive control: the input holds the sentinel");
						JsonParseException exception = assertRejected(entry.getKey(), ANY_OFFSET, input, (JsonLimits) row[1]);
						Assertions.assertEquals(entry.getKey().getMessage(), exception.getMessage());
						Assertions.assertTrue(exception.toString().endsWith(exception.getMessage()));
					});
		}));
	}

	// G7-3: the offsets each Kind documents.
	@TestFactory
	Stream<DynamicTest> reportsTheDocumentedByteOffset() {
		return Stream.of(
				new Object[]{"", Kind.SYNTAX, 0, "empty input: the input length"},
				new Object[]{" \n\t\r", Kind.SYNTAX, 4, "only whitespace: the input length"},
				new Object[]{"[1,2", Kind.SYNTAX, 4, "input ended early: the input length"},
				new Object[]{"[1 2]", Kind.SYNTAX, 3, "the byte where the grammar failed"},
				new Object[]{"{\"a\" 1}", Kind.SYNTAX, 5, "a missing colon"},
				new Object[]{"{1:2}", Kind.SYNTAX, 1, "a name that is not a string"},
				new Object[]{"[tru]", Kind.SYNTAX, 4, "a mistyped literal: its first wrong byte"},
				new Object[]{"[nul", Kind.SYNTAX, 4, "a truncated literal"},
				new Object[]{"[\"a\\x\"]", Kind.SYNTAX, 4, "an invalid escape: the escaped character"},
				new Object[]{"[\"\\u12G4\"]", Kind.SYNTAX, 6, "an invalid hexadecimal digit"},
				new Object[]{"[\"\\u12", Kind.SYNTAX, 6, "a truncated escape"},
				new Object[]{"[\"\\", Kind.SYNTAX, 3, "a lone backslash at the end"},
				new Object[]{"[\"\\uD834\\uDD1E", Kind.SYNTAX, 14, "an escaped pair that ends the input"},
				new Object[]{"[\"a\tb\"]", Kind.SYNTAX, 3, "an unescaped control character"},
				new Object[]{"[\"a\u00E9\u0000\"]", Kind.SYNTAX, 5, "a raw NUL after a two-byte character"},
				new Object[]{"\u00E9", Kind.SYNTAX, 0, "a non-ASCII character outside a string"},
				new Object[]{"[\"\u00E9\"x]", Kind.SYNTAX, 5, "after a string holding a two-byte character"})
				.map(row -> DynamicTest.dynamicTest(row[3] + " (" + row[1] + " at " + row[2] + ")",
						() -> assertRejected((Kind) row[1], (Integer) row[2], (String) row[0], LIMITS)));
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Grammar and model
	// ---------------------------------------------------------------------------------------------------------------

	// RFC 8259 section 2: any value may be the root.
	@Test
	void acceptsEveryKindOfRootValue() throws JsonParseException {
		Assertions.assertEquals(JsonNumber.fromValue(1L), parse("1", LIMITS));
		Assertions.assertEquals(JsonString.fromValue("s"), parse("\"s\"", LIMITS));
		Assertions.assertSame(JsonBoolean.trueInstance(), parse("true", LIMITS));
		Assertions.assertSame(JsonBoolean.falseInstance(), parse(" false ", LIMITS));
		Assertions.assertSame(JsonNull.defaultInstance(), parse("null", LIMITS));
		Assertions.assertSame(JsonArray.emptyInstance(), parse("[ ]", LIMITS));
		Assertions.assertSame(JsonObject.emptyInstance(), parse("{ }", LIMITS));
	}

	// RFC 8259 section 7 and JSONTestSuite y_ files: every escape decodes; NUL and noncharacters are data (unlike
	// I-JSON, by design); raw control characters must be escaped.
	@Test
	void decodesEveryEscapeAndAcceptsNulAndNoncharacters() throws JsonParseException {
		Assertions.assertEquals(JsonString.fromValue("\"\\/\b\f\n\r\t\u00E9\u00E9"),
				parse("\"\\\"\\\\\\/\\b\\f\\n\\r\\t\\u00e9\\u00E9\"", LIMITS));
		Assertions.assertEquals(JsonString.fromValue("\u0000\uFFFF\uFDD0\uDBFF\uDFFF"),
				parse("\"\\u0000\\uFFFF\\uFDD0\\uDBFF\\uDFFF\"", LIMITS));
		Assertions.assertEquals(JsonString.fromValue("\uFFFF\u007F"), parse("\"\uFFFF\u007F\"", LIMITS));
		Assertions.assertEquals(JsonString.fromValue("mixed \u00E9 and \u00E9 and \uD83D\uDE80"),
				parse("\"mixed \u00E9 and \\u00e9 and \\uD83D\\uDE80\"", LIMITS));
		assertRejected(Kind.SYNTAX, 1, "\"\u001F\"", LIMITS);
	}

	// G7-4: the codec returns BigDecimal values exactly as written (scale included) and never expands them.
	@Test
	void parsesNumbersExactly() throws JsonParseException {
		Assertions.assertEquals(new BigDecimal("1.50").scale(), ((JsonNumber) parse("1.50", LIMITS)).getValue().scale());
		Assertions.assertEquals("1E+10000", ((JsonNumber) parse("1e10000", LIMITS)).getValue().toString());
		Assertions.assertEquals("0", ((JsonNumber) parse("-0", LIMITS)).getValue().toString());
		Assertions.assertEquals(new BigDecimal("-123456789012345678901234567890.5e-3"),
				((JsonNumber) parse("-123456789012345678901234567890.5e-3", LIMITS)).getValue());
	}

	// The canonical-length arithmetic (Soklet's canonicalNumberLength) agrees with BigDecimal.toString() on edge
	// values of plain and scientific notation and on random numbers.
	@Test
	void computesTheCanonicalNumberLengthWithoutBuildingIt() {
		List<BigDecimal> values = new ArrayList<>();

		for (String text : List.of("0", "-0", "0.0", "0.000000", "0.0000000", "0e5", "0e-7", "1", "-1", "1e2", "12e2",
				"1.5", "0.000001", "0.0000001", "-0.000001234", "123.456", "1e-6", "1e-7", "12345678901234567890e-25",
				"9".repeat(509) + "e9", "1e100000", "-1.5e-100000", "100", "1.0e3"))
			values.add(new BigDecimal(text));

		Random random = new Random(0x5EED_0007L);

		for (int count = 0; count < 20_000; ++count) {
			StringBuilder digits = new StringBuilder();
			int length = 1 + random.nextInt(random.nextBoolean() ? 5 : 40);

			for (int index = 0; index < length; ++index)
				digits.append((char) ('0' + random.nextInt(10)));

			BigDecimal value = new BigDecimal(new BigInteger(digits.toString()), random.nextInt(60) - 30);
			values.add(random.nextBoolean() ? value : value.negate());
		}

		for (BigDecimal value : values) {
			long adjustedExponent = (long) value.precision() - value.scale() - 1;
			Assertions.assertEquals(value.toString().length(), JsonCodec.canonicalNumberLength(value, adjustedExponent),
					value::toString);
		}
	}

	// Unicode Table 3-7: the UTF-8 check matches the JDK's strict decoder, both on whether input is well-formed and
	// on where it stops, for every sequence of one to four bytes drawn from the table's boundary values, and for
	// random input.
	@Test
	void validatesUtf8ExactlyAsTheJdkStrictDecoderDoes() {
		CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
				.onMalformedInput(CodingErrorAction.REPORT)
				.onUnmappableCharacter(CodingErrorAction.REPORT);
		int[] boundaries = {0x00, 0x22, 0x5C, 0x7F, 0x80, 0x8F, 0x90, 0x9F, 0xA0, 0xBF, 0xC0, 0xC1, 0xC2, 0xDF, 0xE0,
				0xE1, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF3, 0xF4, 0xF5, 0xFF};
		int checked = 0;

		for (int length = 1; length <= 4; ++length) {
			int[] indexes = new int[length];

			while (true) {
				byte[] input = new byte[length];

				for (int position = 0; position < length; ++position)
					input[position] = (byte) boundaries[indexes[position]];

				assertUtf8LikeTheJdk(decoder, input);
				++checked;

				int position = length - 1;

				while (position >= 0 && ++indexes[position] == boundaries.length)
					indexes[position--] = 0;

				if (position < 0)
					break;
			}
		}

		Random random = new Random(0x5EED_0008L);

		for (int count = 0; count < 20_000; ++count) {
			byte[] input = new byte[random.nextInt(12)];

			for (int position = 0; position < input.length; ++position)
				input[position] = (byte) (random.nextInt(3) == 0 ? random.nextInt(128)
						: boundaries[random.nextInt(boundaries.length)]);

			assertUtf8LikeTheJdk(decoder, input);
			++checked;
		}

		Assertions.assertTrue(checked > 460_000);
	}

	// M1 plan: IllegalArgumentException never escapes parse; nor does anything but JsonParseException. A deterministic
	// mutation run over the corpus (the fuzz targets run the open-ended version).
	@Test
	void throwsOnlyJsonParseExceptionForMutatedInput() throws JsonParseException {
		List<byte[]> seeds = new ArrayList<>();

		for (String file : JsonCorpus.files())
			seeds.add(JsonCorpus.read(file));

		Random random = new Random(0x5EED_0009L);
		byte[] interesting = utf8("{}[]\",:\\u0123456789eE+-.tfn \t\r\n");
		int accepted = 0;

		for (int count = 0; count < 30_000; ++count) {
			byte[] input = seeds.get(random.nextInt(seeds.size())).clone();

			for (int mutation = 1 + random.nextInt(4); mutation > 0 && input.length > 0; --mutation) {
				int position = random.nextInt(input.length);

				switch (random.nextInt(4)) {
					case 0 -> input[position] = interesting[random.nextInt(interesting.length)];
					case 1 -> input[position] = (byte) random.nextInt(256);
					case 2 -> input = concat(Arrays.copyOf(input, position),
							Arrays.copyOfRange(input, position + 1, input.length));
					default -> input = concat(Arrays.copyOf(input, position),
							new byte[]{interesting[random.nextInt(interesting.length)]},
							Arrays.copyOfRange(input, position, input.length));
				}
			}

			for (JsonLimits limits : List.of(LIMITS, SCIM)) {
				JsonValue value;

				try {
					value = JsonCodec.parse(input, limits);
				} catch (JsonParseException expected) {
					Assertions.assertEquals(JsonFailures.PARSE_MESSAGES.get(expected.getKind()), expected.getMessage());
					continue;
				} catch (RuntimeException | StackOverflowError unexpected) {
					throw new AssertionError("unexpected " + unexpected.getClass().getName() + " for "
							+ JsonFailures.describe(input), unexpected);
				}

				Assertions.assertEquals(value, JsonCodec.parse(JsonCodec.toUtf8Bytes(value), MAXIMUM));
				++accepted;
			}
		}

		Assertions.assertTrue(accepted > 1_000, "the mutations should leave some inputs valid");
	}

	// G7-6: whatever any profile accepts serializes to text that the maximum-cap profile parses back to an equal
	// value, with the same JSON text.
	@Test
	void roundTripsEveryAcceptedCorpusFileUnderTheMaximumCapProfile() throws JsonParseException {
		int accepted = 0;

		for (String file : JsonCorpus.files()) {
			for (JsonLimits limits : List.of(PROTOCOL, SCIM, MAXIMUM)) {
				JsonValue value;

				try {
					value = JsonCodec.parse(JsonCorpus.read(file), limits);
				} catch (JsonParseException rejected) {
					continue;
				}

				JsonValue reparsed = JsonCodec.parse(JsonCodec.toUtf8Bytes(value), MAXIMUM);
				Assertions.assertEquals(value, reparsed, file);
				Assertions.assertEquals(value.hashCode(), reparsed.hashCode(), file);
				Assertions.assertEquals(value.toJson(), reparsed.toJson(), file);
				++accepted;
			}
		}

		Assertions.assertTrue(accepted >= 3 * 12, "accepted " + accepted);
	}

	// G7-4 and G7-6: whatever the writer writes, the codec parses back to an equal value with the same text, for
	// random values holding every kind of character (controls, quotation marks, reverse solidi, noncharacters,
	// surrogate pairs) and numbers at many scales.
	@Test
	void parsesBackWhateverTheWriterWritesForRandomValues() throws JsonParseException {
		Random random = new Random(0x5EED_000AL);

		for (int count = 0; count < 3_000; ++count) {
			JsonValue value = randomValue(random, 1 + random.nextInt(8));
			byte[] written = JsonCodec.toUtf8Bytes(value);
			JsonValue parsed = JsonCodec.parse(written, MAXIMUM);

			Assertions.assertEquals(value, parsed, value::toJson);
			Assertions.assertEquals(value.hashCode(), parsed.hashCode(), value::toJson);
			Assertions.assertArrayEquals(written, JsonCodec.toUtf8Bytes(parsed), value::toJson);
		}
	}

	// Plan risk "Recursion": the depth cap keeps the recursive parser, writer, equals and hashCode inside a 256 KiB
	// thread stack even when nothing is compiled yet (-Xint), in a fresh JVM.
	@Test
	void handlesTheMaximumDepthOnA256KibStackBeforeJitWarmUp() throws Exception {
		ChildJvm.Result result = ChildJvm.withMainClass(MaximumDepthOnASmallStack.class)
				.jvmOptions(List.of("-Xint", "-Xss256k"))
				.timeout(Duration.ofSeconds(60))
				.build()
				.run();

		Assertions.assertEquals(0, result.getExitCode(), result::toString);
		Assertions.assertTrue(result.getStandardOutput().contains("depth 64 ok"), result::toString);
	}

	/**
	 * The child-JVM half of {@link #handlesTheMaximumDepthOnA256KibStackBeforeJitWarmUp()}.
	 */
	public static final class MaximumDepthOnASmallStack {
		private MaximumDepthOnASmallStack() {
		}

		/**
		 * Parses, serializes, compares and hashes depth-64 arrays and objects.
		 *
		 * @param arguments unused
		 * @throws JsonParseException if the codec rejects the input
		 */
		public static void main(String[] arguments) throws JsonParseException {
			JsonLimits scim = JsonLimits.scim(1_024 * 1_024, 100_000);

			for (String json : List.of(nested(64, ""), nested(63, "0"), nestedObjects(63, "{}"),
					nestedObjects(31, nested(32, "\"x\"")))) {
				JsonValue first = JsonCodec.parse(utf8(json), scim);
				JsonValue second = JsonCodec.parse(JsonCodec.toUtf8Bytes(first), scim);

				if (!first.equals(second) || first.hashCode() != second.hashCode() || !json.equals(second.toJson()))
					throw new AssertionError("round trip changed a depth-64 value");
			}

			System.out.println("depth 64 ok");
		}
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Helpers
	// ---------------------------------------------------------------------------------------------------------------

	private static JsonValue parse(String json, JsonLimits limits) throws JsonParseException {
		return JsonCodec.parse(utf8(json), limits);
	}

	/**
	 * {@code count} arrays around {@code core}.
	 */
	static String nested(int count, String core) {
		return "[".repeat(count) + core + "]".repeat(count);
	}

	/**
	 * {@code count} objects {@code {"a":...}} around {@code core}; each level adds five bytes before the core.
	 */
	static String nestedObjects(int count, String core) {
		return "{\"a\":".repeat(count) + core + "}".repeat(count);
	}

	private static JsonValue randomValue(Random random, int depthLeft) {
		int kind = random.nextInt(depthLeft > 1 ? 8 : 5);

		return switch (kind) {
			case 0 -> JsonString.fromValue(randomString(random));
			case 1 -> JsonNumber.fromValue(new BigDecimal(new BigInteger(1 + random.nextInt(120), random)
					.subtract(BigInteger.valueOf(random.nextInt(1_000))), random.nextInt(200) - 100));
			case 2 -> JsonBoolean.fromValue(random.nextBoolean());
			case 3 -> JsonNull.defaultInstance();
			case 4 -> JsonNumber.fromValue((long) random.nextInt());
			case 5 -> {
				List<JsonValue> elements = new ArrayList<>();

				for (int index = random.nextInt(5); index > 0; --index)
					elements.add(randomValue(random, depthLeft - 1));

				yield JsonArray.fromElements(elements);
			}
			default -> {
				Map<String, JsonValue> members = new LinkedHashMap<>();

				for (int index = random.nextInt(5); index > 0; --index)
					members.put(randomString(random), randomValue(random, depthLeft - 1));

				yield JsonObject.fromMembers(members);
			}
		};
	}

	private static String randomString(Random random) {
		String pool = "aZ09 \"\\/\b\f\n\r\t\u0000\u001F\u007F\u00E9\u2028\u2029\uFEFF\uFFFF\uFFFE";
		StringBuilder value = new StringBuilder();

		for (int index = random.nextInt(8); index > 0; --index) {
			if (random.nextInt(6) == 0)
				value.appendCodePoint(0x10000 + random.nextInt(0x100000));
			else
				value.append(pool.charAt(random.nextInt(pool.length())));
		}

		return value.toString();
	}

	private static JsonValue innermost(JsonValue value) {
		JsonValue current = value;

		while (current instanceof JsonObject object && object.getMembers().size() == 1
				&& object.getMembers().containsKey("Wrapper"))
			current = object.getMembers().get("Wrapper");

		return current;
	}

	private static int countValues(JsonValue value) {
		int count = 1;

		if (value instanceof JsonObject object)
			for (JsonValue member : object.getMembers().values())
				count += countValues(member);
		else if (value instanceof JsonArray array)
			for (JsonValue element : array.getElements())
				count += countValues(element);

		return count;
	}

	private static byte[] bytes(int... values) {
		byte[] result = new byte[values.length];

		for (int index = 0; index < values.length; ++index)
			result[index] = (byte) values[index];

		return result;
	}

	private static byte[] concat(byte[]... parts) {
		ByteArrayOutputStream output = new ByteArrayOutputStream();

		for (byte[] part : parts)
			output.writeBytes(part);

		return output.toByteArray();
	}

	private static void assertUtf8LikeTheJdk(CharsetDecoder decoder, byte[] input) {
		decoder.reset();
		ByteBuffer buffer = ByteBuffer.wrap(input);
		CoderResult result = decoder.decode(buffer, CharBuffer.allocate(input.length + 1), true);
		int expected = result.isError() ? buffer.position() : -1;

		Assertions.assertEquals(expected, JsonCodec.firstIllFormedUtf8Offset(input),
				() -> JsonFailures.describe(input));
	}
}
