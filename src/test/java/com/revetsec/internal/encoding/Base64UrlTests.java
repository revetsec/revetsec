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
import java.util.Base64;
import java.util.Random;
import java.util.stream.Stream;

/**
 * Canonical unpadded base64url (RFC 4648 section 5; RFC 7515 section 2; plan 8; INV-J7; exit criterion 6: padding,
 * non-zero trailing bits and characters outside the alphabet are rejected).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class Base64UrlTests {
	private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

	// RFC 4648 section 10 test vectors, written in the base64url alphabet without padding.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> encodesAndDecodesTheRfc4648Vectors() {
		return Stream.of(new String[][]{
				{"", ""}, {"f", "Zg"}, {"fo", "Zm8"}, {"foo", "Zm9v"}, {"foob", "Zm9vYg"}, {"fooba", "Zm9vYmE"},
				{"foobar", "Zm9vYmFy"}
		}).map(vector -> DynamicTest.dynamicTest("\"" + vector[0] + "\" <-> \"" + vector[1] + "\"", () -> {
			byte[] bytes = vector[0].getBytes(StandardCharsets.US_ASCII);
			Assertions.assertEquals(vector[1], Base64Url.encode(bytes));
			Assertions.assertArrayEquals(bytes, Base64Url.decode(vector[1]));
		}));
	}

	// RFC 4648 section 5: 62 and 63 are '-' and '_', never '+' and '/'.
	@Test
	void usesTheUrlSafeAlphabetForSixtyTwoAndSixtyThree() throws EncodingException {
		byte[] bytes = {(byte) 0xFB, (byte) 0xFF, (byte) 0xBF};
		Assertions.assertEquals("-_-_", Base64Url.encode(bytes));
		Assertions.assertArrayEquals(bytes, Base64Url.decode("-_-_"));
		Assertions.assertArrayEquals(new byte[]{(byte) 0xFF, (byte) 0xFE}, Base64Url.decode("__4"));
	}

	// RFC 7515 section 2: base64url "with all trailing '=' characters omitted"; INV-J7.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> rejectsPaddingAnywhere() {
		return rejections(EncodingException.Kind.PADDING, "Zg==", "Zg=", "Zm8=", "Zm9v====", "=", "==", "Zm9v=Zm9v",
				"=Zm9v", EncodingFailures.SENTINEL + "==");
	}

	// RFC 4648 section 5 alphabet only: the standard alphabet's '+' and '/', whitespace and every non-ASCII
	// character, including letters and digits outside ASCII, are rejected.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> rejectsCharactersOutsideTheAlphabet() {
		return rejections(EncodingException.Kind.INVALID_CHARACTER, "Zm9+", "Zm9/", "Zm 9v", "Zm9v\n", "Zm9v\r\n",
				"\tZm9v", "Zm9.", "Zm9\u00E9", "Zm9\u0000", "\uFF3Am9v", "Zm9\u0663", "Zm\uD83D\uDE00", "Zm9\uD800",
				"Zm9v\u00A0", EncodingFailures.SENTINEL + "+");
	}

	// RFC 4648 section 4: a final quantum has 2 or 3 characters, never 1, so a length of 4n + 1 encodes nothing.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> rejectsLengthsNoOctetStringEncodesTo() {
		return rejections(EncodingException.Kind.INVALID_LENGTH, "A", "AAAAA", "Zm9vY", "Zm9vYmFyZ",
				EncodingFailures.SENTINEL + "A");
	}

	// Plan 8: re-encode and compare. Every two-character input decodes (the JDK ignores the low four bits of the
	// second character) but only the 256 whose low four bits are zero are canonical; this checks all 4,096.
	@Test
	void acceptsExactlyTheCanonicalTwoCharacterInputs() throws EncodingException {
		int accepted = 0;
		for (int firstIndex = 0; firstIndex < ALPHABET.length(); ++firstIndex) {
			char first = ALPHABET.charAt(firstIndex);
			for (int secondIndex = 0; secondIndex < ALPHABET.length(); ++secondIndex) {
				char second = ALPHABET.charAt(secondIndex);
				String input = "" + first + second;
				boolean canonical = (secondIndex & 0x0F) == 0;
				if (canonical) {
					byte[] decoded = Base64Url.decode(input);
					Assertions.assertArrayEquals(Base64.getUrlDecoder().decode(input), decoded, input);
					Assertions.assertEquals(input, Base64Url.encode(decoded));
					++accepted;
				} else {
					EncodingFailures.assertRejected(EncodingException.Kind.NON_CANONICAL, input,
							() -> Base64Url.decode(input));
				}
			}
		}
		Assertions.assertEquals(256, accepted);
	}

	// Plan 8: a three-character final quantum must have its low two bits zero; checks all 262,144 inputs.
	@Test
	void acceptsExactlyTheCanonicalThreeCharacterInputs() {
		int accepted = 0;
		int rejected = 0;
		for (int firstIndex = 0; firstIndex < ALPHABET.length(); ++firstIndex) {
			char first = ALPHABET.charAt(firstIndex);
			for (int secondIndex = 0; secondIndex < ALPHABET.length(); ++secondIndex) {
				char second = ALPHABET.charAt(secondIndex);
				for (int thirdIndex = 0; thirdIndex < ALPHABET.length(); ++thirdIndex) {
					char third = ALPHABET.charAt(thirdIndex);
					String input = "" + first + second + third;
					boolean canonical = (thirdIndex & 0x03) == 0;
					try {
						byte[] decoded = Base64Url.decode(input);
						Assertions.assertTrue(canonical, input);
						Assertions.assertEquals(input, Base64Url.encode(decoded));
						++accepted;
					} catch (EncodingException e) {
						Assertions.assertFalse(canonical, input);
						Assertions.assertEquals(EncodingException.Kind.NON_CANONICAL, e.getKind(), input);
						++rejected;
					}
				}
			}
		}
		Assertions.assertEquals(65_536, accepted);
		Assertions.assertEquals(196_608, rejected);
	}

	// The strict decoder agrees with the JDK on every canonical input, and encode/decode are inverse.
	@Test
	void roundTripsEveryLengthFromZeroToFiveHundredTwelve() throws EncodingException {
		Random random = new Random(0x5EED_0001L);
		for (int length = 0; length <= 512; ++length) {
			byte[] bytes = new byte[length];
			random.nextBytes(bytes);
			String encoded = Base64Url.encode(bytes);
			Assertions.assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes), encoded);
			Assertions.assertFalse(encoded.contains("="));
			Assertions.assertArrayEquals(bytes, Base64Url.decode(encoded));
		}
	}

	@Test
	void decodesTheEmptyStringToNoOctets() throws EncodingException {
		Assertions.assertArrayEquals(new byte[0], Base64Url.decode(""));
		Assertions.assertEquals("", Base64Url.encode(new byte[0]));
	}

	@Test
	void isAlphabetAcceptsExactlyTheSixtyFourCharacters() {
		for (int value = 0; value <= Character.MAX_VALUE; ++value) {
			char character = (char) value;
			Assertions.assertEquals(ALPHABET.indexOf(character) >= 0, Base64Url.isAlphabet(character),
					() -> "character " + Integer.toHexString(character));
		}
	}

	// R9: the message is fixed; a sentinel inside rejected input never reaches any rendering.
	@Test
	void failuresNeverEchoTheInput() {
		String input = "eyJhbGciOiJub25lIn0." + EncodingFailures.SENTINEL;
		EncodingFailures.assertRejected(EncodingException.Kind.INVALID_CHARACTER, input, () -> Base64Url.decode(input));
	}

	@Test
	@SuppressWarnings("NullAway")
	void rejectsNullArgumentsWithNullPointerException() {
		Assertions.assertThrows(NullPointerException.class, () -> Base64Url.decode(null));
		Assertions.assertThrows(NullPointerException.class, () -> Base64Url.encode(null));
	}

	private static @NonNull Stream<@NonNull DynamicTest> rejections(EncodingException.@NonNull Kind kind, @NonNull String @NonNull ... inputs) {
		return Stream.of(inputs).map(input -> DynamicTest.dynamicTest(EncodingFailures.describe(input),
				() -> EncodingFailures.assertRejected(kind, input, () -> Base64Url.decode(input))));
	}
}
