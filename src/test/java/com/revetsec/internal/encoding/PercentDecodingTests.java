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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.stream.Stream;

/**
 * Strict percent-decoding (RFC 3986 sections 2.1 and 2.5; R7; exit criterion 6: invalid UTF-8 is rejected, never
 * mapped to U+FFFD).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class PercentDecodingTests {
	@TestFactory
	Stream<DynamicTest> decodesEscapesOfEitherCaseAndLeavesOtherCharactersAlone() {
		return Stream.of(new String[][]{
				{"", ""}, {"plain", "plain"}, {"%20", " "}, {"%25", "%"}, {"a%2Fb", "a/b"}, {"a%2fb", "a/b"},
				{"%41%42%43", "ABC"}, {"caf%C3%A9", "caf\u00E9"}, {"caf%c3%a9", "caf\u00E9"},
				{"%E2%82%AC", "\u20AC"}, {"%F0%9F%98%80", "\uD83D\uDE00"}, {"%00", "\u0000"},
				{"%EF%BB%BF", "\uFEFF"}, {"a+b", "a+b"}, {"a+b%20c", "a+b c"}, {"%2B", "+"}, {"~-._", "~-._"},
				{"https%3A%2F%2Fclient.example.com%2Fcb", "https://client.example.com/cb"}
		}).map(vector -> DynamicTest.dynamicTest(EncodingFailures.describe(vector[0]), () ->
				Assertions.assertEquals(vector[1], PercentDecoding.decode(vector[0]))));
	}

	// Characters that are not escapes contribute their own UTF-8 octets, so raw and escaped forms may be mixed,
	// including supplementary characters.
	@Test
	void decodesRawNonAsciiCharactersAsTheirOwnUtf8Octets() throws EncodingException {
		Assertions.assertEquals("caf\u00E9", PercentDecoding.decode("caf\u00E9"));
		Assertions.assertEquals("\u00E9\u00E9", PercentDecoding.decode("%C3%A9\u00E9"));
		Assertions.assertEquals("\uD83D\uDE00!", PercentDecoding.decode("\uD83D\uDE00%21"));
		Assertions.assertEquals("\u20AC\u20AC", PercentDecoding.decode("\u20AC%E2%82%AC"));
	}

	// RFC 3986 section 2.1: '%' must be followed by two hexadecimal digits. Only ASCII digits count:
	// Character.digit would also accept Arabic-Indic and fullwidth digits.
	@TestFactory
	Stream<DynamicTest> rejectsMalformedEscapes() {
		return rejections(EncodingException.Kind.MALFORMED_PERCENT_ENCODING, "%", "%2", "a%", "ab%4", "%G1", "%1G",
				"%%41", "% 41", "%+1", "%-1", "%\u0663\u0663", "%\uFF11\uFF11", "%4\u00E9", "100%",
				EncodingFailures.SENTINEL + "%ZZ");
	}

	// R7: invalid percent-encoded UTF-8 is rejected; URLDecoder maps each of these to U+FFFD.
	@TestFactory
	Stream<DynamicTest> rejectsInvalidUtf8WhereUrlDecoderSubstitutesTheReplacementCharacter() {
		return Stream.of("%C3", "%C3%28", "%80", "%BF", "%C0%AF", "%C1%BF", "%E0%80%80", "%ED%A0%80",
				"%ED%BF%BF", "%F4%90%80%80", "%F5%80%80%80", "%FE", "%FF", "a%E2%82", "%F0%9F%98",
				EncodingFailures.SENTINEL + "%C3").map(input -> DynamicTest.dynamicTest(input, () -> {
			Assertions.assertTrue(URLDecoder.decode(input, StandardCharsets.UTF_8).contains("\uFFFD"),
					"URLDecoder substitutes U+FFFD");
			EncodingFailures.assertRejected(EncodingException.Kind.INVALID_UTF8, input,
					() -> PercentDecoding.decode(input));
		}));
	}

	// Validity is judged on the whole octet sequence, so an escaped lead octet followed by a raw character whose
	// UTF-8 is not a continuation is rejected, and so is an escaped continuation after raw text.
	@TestFactory
	Stream<DynamicTest> judgesUtf8OverTheMixedOctetSequence() {
		return rejections(EncodingException.Kind.INVALID_UTF8, "%C3\u00A9", "%E2%82\u00AC", "\u00E9%A9", "%C3a",
				"a%A9");
	}

	@TestFactory
	Stream<DynamicTest> rejectsUnpairedSurrogatesInTheInput() {
		return rejections(EncodingException.Kind.UNPAIRED_SURROGATE, "\uD800", "a\uDC00", "%41\uD83D",
				"\uDE00\uD83D", "%41\uDFFF%42");
	}

	// Every two-escape sequence %XX%YY (65,536 of them) decodes exactly when the Table 3-7 oracle calls the two
	// octets well-formed, and then to what the JDK decodes them to.
	@Test
	void agreesWithTheTableOracleOnEveryTwoOctetEscapeSequence() {
		for (int first = 0; first < 256; ++first) {
			for (int second = 0; second < 256; ++second) {
				byte[] bytes = {(byte) first, (byte) second};
				String input = String.format(Locale.ROOT, "%%%02X%%%02x", first, second);
				boolean wellFormed = Utf8Reference.isWellFormed(bytes);
				try {
					String decoded = PercentDecoding.decode(input);
					Assertions.assertTrue(wellFormed, input);
					Assertions.assertEquals(new String(bytes, StandardCharsets.UTF_8), decoded, input);
				} catch (EncodingException e) {
					Assertions.assertFalse(wellFormed, input);
					Assertions.assertEquals(EncodingException.Kind.INVALID_UTF8, e.getKind(), input);
				}
			}
		}
	}

	// hexValue accepts exactly 0-9, A-F and a-f.
	@Test
	void hexValueAcceptsOnlyAsciiHexadecimalDigits() {
		String digits = "0123456789abcdef";
		for (int value = 0; value <= Character.MAX_VALUE; ++value) {
			char character = (char) value;
			int expected = character < 0x80 ? digits.indexOf(Character.toLowerCase(character)) : -1;
			Assertions.assertEquals(expected, PercentDecoding.hexValue(character),
					() -> "character " + Integer.toHexString(character));
		}
	}

	// R9: the message is fixed; a sentinel inside rejected input never reaches any rendering.
	@Test
	void failuresNeverEchoTheInput() {
		String input = "code=" + EncodingFailures.SENTINEL + "%E2%82";
		EncodingFailures.assertRejected(EncodingException.Kind.INVALID_UTF8, input,
				() -> PercentDecoding.decode(input));
	}

	@Test
	@SuppressWarnings("NullAway")
	void rejectsANullArgumentWithNullPointerException() {
		Assertions.assertThrows(NullPointerException.class, () -> PercentDecoding.decode(null));
	}

	private static Stream<DynamicTest> rejections(EncodingException.Kind kind, String... inputs) {
		return Stream.of(inputs).map(input -> DynamicTest.dynamicTest(EncodingFailures.describe(input),
				() -> EncodingFailures.assertRejected(kind, input, () -> PercentDecoding.decode(input))));
	}
}
