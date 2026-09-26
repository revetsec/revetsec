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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.stream.Stream;

/**
 * {@code application/x-www-form-urlencoded} per RFC 6749 Appendix B (R7; exit criterion 6: the Appendix B vector
 * passes).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class FormUrlEncodingTests {
	/**
	 * RFC 6749 Appendix B: U+0020, U+0025, U+0026, U+002B, U+00A3 and U+20AC.
	 */
	private static final String APPENDIX_B_VALUE = " %&+\u00A3\u20AC";
	private static final String APPENDIX_B_ENCODED = "+%25%26%2B%C2%A3%E2%82%AC";

	// RFC 6749 Appendix B, in both directions.
	@Test
	void encodesTheRfc6749AppendixBExample() throws EncodingException {
		Assertions.assertEquals(6, APPENDIX_B_VALUE.codePointCount(0, APPENDIX_B_VALUE.length()));
		Assertions.assertEquals(APPENDIX_B_ENCODED, FormUrlEncoding.encode(APPENDIX_B_VALUE));
	}

	@Test
	void decodesTheRfc6749AppendixBExample() throws EncodingException {
		Assertions.assertEquals(APPENDIX_B_VALUE, FormUrlEncoding.decode(APPENDIX_B_ENCODED));
	}

	// The unreserved set is A-Z, a-z, 0-9, '*', '-', '.' and '_'; a space becomes '+', everything else %XX with
	// uppercase digits.
	@TestFactory
	Stream<DynamicTest> encodesEachCharacterClassAsSpecified() {
		return Stream.of(new String[][]{
				{"", ""}, {"AZaz09*-._", "AZaz09*-._"}, {" ", "+"}, {"~", "%7E"}, {"+", "%2B"}, {"/", "%2F"},
				{"=", "%3D"}, {"&", "%26"}, {"%", "%25"}, {"\u0000", "%00"}, {"\u007F", "%7F"}, {"\u00E9", "%C3%A9"},
				{"\uD83D\uDE00", "%F0%9F%98%80"},
				{"https://client.example.com/cb?x=1", "https%3A%2F%2Fclient.example.com%2Fcb%3Fx%3D1"}
		}).map(vector -> DynamicTest.dynamicTest(EncodingFailures.describe(vector[0]), () -> {
			Assertions.assertEquals(vector[1], FormUrlEncoding.encode(vector[0]));
			Assertions.assertEquals(vector[0], FormUrlEncoding.decode(vector[1]));
		}));
	}

	// For well-formed input the encoder's output is exactly URLEncoder's with UTF-8 (the plan's App. B
	// reference implementation); checks every BMP code point that is not a surrogate, and supplementary ones.
	@Test
	void matchesUrlEncoderOnEveryWellFormedCodePoint() throws EncodingException {
		for (int codePoint = 0; codePoint <= 0xFFFF; ++codePoint) {
			if (Character.isSurrogate((char) codePoint))
				continue;
			String value = "a" + new String(Character.toChars(codePoint)) + "b";
			Assertions.assertEquals(URLEncoder.encode(value, StandardCharsets.UTF_8), FormUrlEncoding.encode(value));
		}
		Random random = new Random(0x5EED_0007L);
		for (int count = 0; count < 5_000; ++count) {
			String value = new String(Character.toChars(0x10000 + random.nextInt(0x100000)));
			Assertions.assertEquals(URLEncoder.encode(value, StandardCharsets.UTF_8), FormUrlEncoding.encode(value));
		}
	}

	// URLEncoder writes an unpaired surrogate as "%3F", so two different strings encode alike; Revetsec rejects it.
	@TestFactory
	Stream<DynamicTest> rejectsUnpairedSurrogatesThatUrlEncoderReplaces() {
		return Stream.of("\uD800", "a\uDC00", "\uDE00\uD83D", EncodingFailures.SENTINEL + "\uD83D").map(input ->
				DynamicTest.dynamicTest(EncodingFailures.describe(input), () -> {
					Assertions.assertTrue(URLEncoder.encode(input, StandardCharsets.UTF_8).contains("%3F"));
					EncodingFailures.assertRejected(EncodingException.Kind.UNPAIRED_SURROGATE, input,
							() -> FormUrlEncoding.encode(input));
				}));
	}

	// RFC 6749 Appendix B: '+' is a space when decoding, and an encoded "%2B" stays a plus sign.
	@Test
	void decodesPlusAsSpaceAndEncodedPlusAsPlus() throws EncodingException {
		Assertions.assertEquals("openid profile", FormUrlEncoding.decode("openid+profile"));
		Assertions.assertEquals("a+b", FormUrlEncoding.decode("a%2Bb"));
		Assertions.assertEquals("  ", FormUrlEncoding.decode("++"));
		Assertions.assertEquals(" + ", FormUrlEncoding.decode("+%2b+"));
		Assertions.assertEquals("\u00A3", FormUrlEncoding.decode("%c2%a3"));
	}

	@TestFactory
	Stream<DynamicTest> rejectsMalformedEscapesWhenDecoding() {
		return Stream.of("%", "a+%2", "%G0", "+%+", EncodingFailures.SENTINEL + "%x").map(input ->
				DynamicTest.dynamicTest(EncodingFailures.describe(input), () ->
						EncodingFailures.assertRejected(EncodingException.Kind.MALFORMED_PERCENT_ENCODING, input,
								() -> FormUrlEncoding.decode(input))));
	}

	// R7: invalid UTF-8 is rejected, never mapped to U+FFFD as URLDecoder does.
	@TestFactory
	Stream<DynamicTest> rejectsInvalidUtf8WhenDecoding() {
		return Stream.of("%C3", "+%C3+", "%C0%AF", "%ED%A0%80", "%FF", "state=" + EncodingFailures.SENTINEL + "%80")
				.map(input -> DynamicTest.dynamicTest(input, () -> {
					Assertions.assertTrue(URLDecoder.decode(input, StandardCharsets.UTF_8).contains("\uFFFD"));
					EncodingFailures.assertRejected(EncodingException.Kind.INVALID_UTF8, input,
							() -> FormUrlEncoding.decode(input));
				}));
	}

	@Test
	void roundTripsRandomWellFormedText() throws EncodingException {
		Random random = new Random(0x5EED_0008L);
		for (int count = 0; count < 2_000; ++count) {
			StringBuilder text = new StringBuilder();
			int length = random.nextInt(30);
			while (text.length() < length) {
				int codePoint = random.nextInt(4) == 0 ? random.nextInt(0x80)
						: random.nextInt(Character.MAX_CODE_POINT + 1);
				if (codePoint < Character.MIN_SURROGATE || codePoint > Character.MAX_SURROGATE)
					text.appendCodePoint(codePoint);
			}
			String value = text.toString();
			String encoded = FormUrlEncoding.encode(value);
			Assertions.assertEquals(value, FormUrlEncoding.decode(encoded));
			Assertions.assertEquals(value, URLDecoder.decode(encoded, StandardCharsets.UTF_8));
		}
	}

	@Test
	@SuppressWarnings("NullAway")
	void rejectsNullArgumentsWithNullPointerException() {
		Assertions.assertThrows(NullPointerException.class, () -> FormUrlEncoding.encode(null));
		Assertions.assertThrows(NullPointerException.class, () -> FormUrlEncoding.decode(null));
	}
}
