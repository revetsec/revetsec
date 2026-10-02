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

package com.revetsec.internal.encoding;

import org.jspecify.annotations.NonNull;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Random;
import java.util.stream.Stream;

/**
 * Strict UTF-8 (RFC 3629; the Unicode Standard, Table 3-7; M1 plan internal types: {@code getBytes(UTF_8)}
 * silently maps a lone surrogate to {@code ?}).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class StrictUtf8Tests {
	/**
	 * Lead and continuation octets at every boundary of Table 3-7.
	 */
	private static final int[] BOUNDARY_OCTETS = {0x00, 0x7F, 0x80, 0x8F, 0x90, 0x9F, 0xA0, 0xBF, 0xC0, 0xC1, 0xC2,
			0xDF, 0xE0, 0xE1, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF3, 0xF4, 0xF5, 0xFF};

	// For well-formed input the encoder is byte-for-byte the JDK's; checks every BMP code point that is not a
	// surrogate, one at a time, and random supplementary code points.
	@Test
	void encodesEveryWellFormedCodePointAsTheJdkDoes() throws EncodingException {
		for (int codePoint = 0; codePoint <= 0xFFFF; ++codePoint) {
			if (Character.isSurrogate((char) codePoint))
				continue;
			String value = new String(Character.toChars(codePoint));
			Assertions.assertArrayEquals(value.getBytes(StandardCharsets.UTF_8), StrictUtf8.encode(value), value);
		}
		Random random = new Random(0x5EED_0005L);
		for (int count = 0; count < 20_000; ++count) {
			int codePoint = 0x10000 + random.nextInt(0x100000);
			String value = "a" + new String(Character.toChars(codePoint)) + "\u00E9";
			Assertions.assertArrayEquals(value.getBytes(StandardCharsets.UTF_8), StrictUtf8.encode(value));
		}
		String maximum = new String(Character.toChars(Character.MAX_CODE_POINT));
		Assertions.assertEquals("f48fbfbf", HexFormat.of().formatHex(StrictUtf8.encode(maximum)));
	}

	// M1 plan: getBytes(UTF_8) maps an unpaired surrogate to '?' (0x3F); the strict encoder rejects it.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> rejectsUnpairedSurrogatesThatGetBytesSilentlyReplaces() {
		return Stream.of("\uD800", "\uDFFF", "a\uDC00b", "\uDBFF", "x\uD83D", "\uDE00\uD83D", "\uD800\uD800",
				EncodingFailures.SENTINEL + "\uDC00").map(input -> DynamicTest.dynamicTest(
				EncodingFailures.describe(input), () -> {
					Assertions.assertTrue(new String(input.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8)
							.contains("?"), "the JDK's lenient encoder replaces the surrogate with '?'");
					EncodingFailures.assertRejected(EncodingException.Kind.UNPAIRED_SURROGATE, input,
							() -> StrictUtf8.encode(input));
					Assertions.assertFalse(StrictUtf8.isWellFormed(input));
				}));
	}

	@Test
	void isWellFormedAcceptsPairedSurrogatesAndRejectsUnpairedOnes() {
		Assertions.assertTrue(StrictUtf8.isWellFormed(""));
		Assertions.assertTrue(StrictUtf8.isWellFormed("plain ASCII"));
		Assertions.assertTrue(StrictUtf8.isWellFormed("\uD83D\uDE00 \u00E9 \uFFFF \u0000"));
		Assertions.assertTrue(StrictUtf8.isWellFormed("\uDBFF\uDFFF"));
		Assertions.assertFalse(StrictUtf8.isWellFormed("\uD83D"));
		Assertions.assertFalse(StrictUtf8.isWellFormed("\uDE00"));
		Assertions.assertFalse(StrictUtf8.isWellFormed("\uDE00\uD83D"));
		Assertions.assertFalse(StrictUtf8.isWellFormed("ok\uD83D\uDE00\uD83D"));
	}

	// Table 3-7 rows and their classic violations. new String(bytes, UTF_8) maps each of these to U+FFFD; the strict
	// decoder rejects it instead.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> rejectsIllFormedSequencesInsteadOfReplacingThem() {
		return Stream.of(
				"c080", // overlong NUL
				"c0af", // overlong '/'
				"c1bf", // overlong
				"e08080", // overlong three-octet NUL
				"e09fbf", // overlong U+07FF
				"f0808080", // overlong four-octet NUL
				"f08fbfbf", // overlong U+FFFF
				"eda080", // U+D800 as CESU-8
				"edbfbf", // U+DFFF as CESU-8
				"eda0bdedb880", // a CESU-8 surrogate pair
				"f4908080", // U+110000
				"f5808080", "f8888080", "fc8480808080", "fe", "ff", // never-valid lead octets
				"80", "bf", "41bf42", // stray continuation octets
				"c3", "e282", "f09f98", // truncated at the end
				"c328", "e228a1", "f0289fbc", // a non-continuation octet too early
				"61c3") // truncated after valid text
				.map(hex -> DynamicTest.dynamicTest(hex, () -> {
					byte[] bytes = HexFormat.of().parseHex(hex);
					Assertions.assertTrue(new String(bytes, StandardCharsets.UTF_8).contains("\uFFFD"),
							"the JDK's lenient decoder substitutes U+FFFD");
					Assertions.assertFalse(Utf8Reference.isWellFormed(bytes));
					EncodingFailures.assertRejected(EncodingException.Kind.INVALID_UTF8, hex,
							() -> StrictUtf8.decode(bytes));
				}));
	}

	// Well-formed input decodes as itself, including NUL, noncharacters, the largest code point and a leading
	// U+FEFF, which is kept (a BOM is data here; callers that forbid one check for it).
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> decodesEdgeCasesThatAreWellFormed() {
		return Stream.of(new String[][]{
				{"", ""}, {"00", "\u0000"}, {"7f", "\u007F"}, {"c280", "\u0080"}, {"dfbf", "\u07FF"},
				{"e0a080", "\u0800"}, {"ed9fbf", "\uD7FF"}, {"ee8080", "\uE000"}, {"efbfbd", "\uFFFD"},
				{"efbfbe", "\uFFFE"}, {"efbfbf", "\uFFFF"}, {"f0908080", "\uD800\uDC00"},
				{"f48fbfbf", "\uDBFF\uDFFF"}, {"efbbbf41", "\uFEFFA"}, {"efb790", "\uFDD0"}
		}).map(vector -> DynamicTest.dynamicTest("octets [" + vector[0] + "]", () ->
				Assertions.assertEquals(vector[1], StrictUtf8.decode(HexFormat.of().parseHex(vector[0])))));
	}

	// Every one- and two-octet sequence, compared with the Table 3-7 oracle and with the JDK's own result.
	@Test
	void agreesWithTheTableOracleOnEveryOneAndTwoOctetSequence() {
		for (int first = 0; first < 256; ++first) {
			assertAgreesWithTheOracle(new byte[]{(byte) first});
			for (int second = 0; second < 256; ++second)
				assertAgreesWithTheOracle(new byte[]{(byte) first, (byte) second});
		}
	}

	// Three- and four-octet sequences over every Table 3-7 boundary octet (24^3 + 24^4 = 345,600 sequences).
	@Test
	void agreesWithTheTableOracleOnEveryBoundaryOctetCombination() {
		for (int first : BOUNDARY_OCTETS)
			for (int second : BOUNDARY_OCTETS)
				for (int third : BOUNDARY_OCTETS) {
					assertAgreesWithTheOracle(new byte[]{(byte) first, (byte) second, (byte) third});
					for (int fourth : BOUNDARY_OCTETS)
						assertAgreesWithTheOracle(new byte[]{(byte) first, (byte) second, (byte) third,
								(byte) fourth});
				}
	}

	@Test
	void roundTripsRandomWellFormedText() throws EncodingException {
		Random random = new Random(0x5EED_0006L);
		for (int count = 0; count < 2_000; ++count) {
			StringBuilder text = new StringBuilder();
			int length = random.nextInt(40);
			while (text.length() < length) {
				int codePoint = random.nextInt(Character.MAX_CODE_POINT + 1);
				if (codePoint < Character.MIN_SURROGATE || codePoint > Character.MAX_SURROGATE)
					text.appendCodePoint(codePoint);
			}
			String value = text.toString();
			Assertions.assertEquals(value, StrictUtf8.decode(StrictUtf8.encode(value)));
		}
	}

	@Test
	void decodesARangeWithoutTouchingTheRestOfTheArray() throws EncodingException {
		byte[] bytes = HexFormat.of().parseHex("ff41c3a9ff");
		byte[] copy = bytes.clone();
		Assertions.assertEquals("A\u00E9", StrictUtf8.decode(bytes, 1, 3));
		Assertions.assertEquals("", StrictUtf8.decode(bytes, 5, 0));
		Assertions.assertArrayEquals(copy, bytes, "the input array is not modified");
		EncodingFailures.assertRejected(EncodingException.Kind.INVALID_UTF8, "ff41c3a9ff",
				() -> StrictUtf8.decode(bytes, 1, 2));
		EncodingFailures.assertRejected(EncodingException.Kind.INVALID_UTF8, "ff41c3a9ff",
				() -> StrictUtf8.decode(bytes, 0, 2));
	}

	@Test
	void rejectsARangeOutsideTheArrayWithIndexOutOfBoundsException() {
		byte[] bytes = new byte[4];
		Assertions.assertThrows(IndexOutOfBoundsException.class, () -> StrictUtf8.decode(bytes, -1, 2));
		Assertions.assertThrows(IndexOutOfBoundsException.class, () -> StrictUtf8.decode(bytes, 3, 2));
		Assertions.assertThrows(IndexOutOfBoundsException.class, () -> StrictUtf8.decode(bytes, 0, -1));
	}

	@Test
	@SuppressWarnings("NullAway")
	void rejectsNullArgumentsWithNullPointerException() {
		Assertions.assertThrows(NullPointerException.class, () -> StrictUtf8.encode(null));
		Assertions.assertThrows(NullPointerException.class, () -> StrictUtf8.decode(null));
		Assertions.assertThrows(NullPointerException.class, () -> StrictUtf8.decode(null, 0, 0));
		Assertions.assertThrows(NullPointerException.class, () -> StrictUtf8.isWellFormed(null));
	}

	private static void assertAgreesWithTheOracle(byte @NonNull [] bytes) {
		boolean wellFormed = Utf8Reference.isWellFormed(bytes);
		try {
			String decoded = StrictUtf8.decode(bytes);
			Assertions.assertTrue(wellFormed, () -> HexFormat.of().formatHex(bytes) + " was accepted");
			Assertions.assertEquals(new String(bytes, StandardCharsets.UTF_8), decoded);
		} catch (EncodingException e) {
			Assertions.assertFalse(wellFormed, () -> HexFormat.of().formatHex(bytes) + " was rejected");
			Assertions.assertEquals(EncodingException.Kind.INVALID_UTF8, e.getKind());
		}
	}
}
