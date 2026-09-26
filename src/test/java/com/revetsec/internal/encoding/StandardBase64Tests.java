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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.stream.Stream;

/**
 * Canonical padded standard Base64 (RFC 4648 section 4; plan 8), the form of {@code SealingKey}'s 44-character keys
 * (G6-9) and of PEM bodies.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class StandardBase64Tests {
	private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	// RFC 4648 section 10 test vectors.
	@TestFactory
	Stream<DynamicTest> encodesAndDecodesTheRfc4648Vectors() {
		return Stream.of(new String[][]{
				{"", ""}, {"f", "Zg=="}, {"fo", "Zm8="}, {"foo", "Zm9v"}, {"foob", "Zm9vYg=="}, {"fooba", "Zm9vYmE="},
				{"foobar", "Zm9vYmFy"}
		}).map(vector -> DynamicTest.dynamicTest("\"" + vector[0] + "\" <-> \"" + vector[1] + "\"", () -> {
			byte[] bytes = vector[0].getBytes(StandardCharsets.US_ASCII);
			Assertions.assertEquals(vector[1], StandardBase64.encode(bytes));
			Assertions.assertArrayEquals(bytes, StandardBase64.decode(vector[1]));
		}));
	}

	// RFC 4648 section 4: 62 and 63 are '+' and '/'.
	@Test
	void usesTheStandardAlphabetForSixtyTwoAndSixtyThree() throws EncodingException {
		byte[] bytes = {(byte) 0xFB, (byte) 0xFF, (byte) 0xBF};
		Assertions.assertEquals("+/+/", StandardBase64.encode(bytes));
		Assertions.assertArrayEquals(bytes, StandardBase64.decode("+/+/"));
	}

	// G6-9: a sealing key is exactly 32 bytes as canonical 44-character standard Base64, one '=' at the end.
	@Test
	void decodesAThirtyTwoByteKeyFromFortyFourCharacters() throws EncodingException {
		byte[] key = new byte[32];
		new Random(0x5EED_0002L).nextBytes(key);
		String encoded = StandardBase64.encode(key);
		Assertions.assertEquals(44, encoded.length());
		Assertions.assertTrue(encoded.endsWith("=") && !encoded.endsWith("=="));
		Assertions.assertArrayEquals(key, StandardBase64.decode(encoded));

		// The same key without its padding, or with non-zero trailing bits, is not accepted.
		String unpadded = encoded.substring(0, 43);
		EncodingFailures.assertRejected(EncodingException.Kind.PADDING, unpadded,
				() -> StandardBase64.decode(unpadded));
		char last = encoded.charAt(42);
		char alias = ALPHABET.charAt(ALPHABET.indexOf(last) ^ 0x01);
		String nonCanonical = encoded.substring(0, 42) + alias + "=";
		Assertions.assertArrayEquals(key, Base64.getDecoder().decode(nonCanonical),
				"the JDK decoder accepts the alias, which is why the re-encode check exists");
		EncodingFailures.assertRejected(EncodingException.Kind.NON_CANONICAL, nonCanonical,
				() -> StandardBase64.decode(nonCanonical));
	}

	// Canonical form requires padding to a multiple of four, at the end only, at most two characters.
	@TestFactory
	Stream<DynamicTest> rejectsMissingMisplacedOrExcessPadding() {
		return rejections(EncodingException.Kind.PADDING, "Zg", "Zg=", "Zm8", "Zm9vYg", "Zm9vYmE", "Zg===",
				"Z===", "====", "==", "Zg==Zg==", "Zm9v=Zm9v", "A=A=", "Zm9vYg=", EncodingFailures.SENTINEL + "==");
	}

	@TestFactory
	Stream<DynamicTest> rejectsCharactersOutsideTheAlphabet() {
		return rejections(EncodingException.Kind.INVALID_CHARACTER, "Zm9-", "Zm9_", "Zm 9v", "Zm9v\n", "Zm9v\r\n",
				"\tZm9v", "Zm9.", "Zm9\u00E9", "Zm9\u0000", "\uFF3Am9v", "Zm9\uD800", "Zm9v\u00A0",
				EncodingFailures.SENTINEL + "-A==");
	}

	@TestFactory
	Stream<DynamicTest> rejectsLengthsNoOctetStringEncodesTo() {
		return rejections(EncodingException.Kind.INVALID_LENGTH, "A", "=", "AAAAA", "Zm9vY", "Zm9v=",
				EncodingFailures.SENTINEL + "A");
	}

	// Plan 8: every "XY==" decodes with the JDK, but only those whose second character has zero low four bits are
	// canonical; every "XYZ=" decodes, but only those whose third character has zero low two bits are canonical.
	@Test
	void acceptsExactlyTheCanonicalPaddedFinalQuanta() {
		int accepted = 0;
		int rejected = 0;
		for (int firstIndex = 0; firstIndex < ALPHABET.length(); ++firstIndex) {
			char first = ALPHABET.charAt(firstIndex);
			for (int secondIndex = 0; secondIndex < ALPHABET.length(); ++secondIndex) {
				char second = ALPHABET.charAt(secondIndex);
				String twoCharacters = "" + first + second + "==";
				if (isAccepted(twoCharacters, (secondIndex & 0x0F) == 0))
					++accepted;
				else
					++rejected;
				for (int thirdIndex = 0; thirdIndex < ALPHABET.length(); ++thirdIndex) {
					char third = ALPHABET.charAt(thirdIndex);
					String threeCharacters = "" + first + second + third + "=";
					if (isAccepted(threeCharacters, (thirdIndex & 0x03) == 0))
						++accepted;
					else
						++rejected;
				}
			}
		}
		Assertions.assertEquals(256 + 65_536, accepted);
		Assertions.assertEquals(3_840 + 196_608, rejected);
	}

	@Test
	void roundTripsEveryLengthFromZeroToFiveHundredTwelve() throws EncodingException {
		Random random = new Random(0x5EED_0003L);
		for (int length = 0; length <= 512; ++length) {
			byte[] bytes = new byte[length];
			random.nextBytes(bytes);
			String encoded = StandardBase64.encode(bytes);
			Assertions.assertEquals(Base64.getEncoder().encodeToString(bytes), encoded);
			Assertions.assertEquals(0, encoded.length() % 4);
			Assertions.assertArrayEquals(bytes, StandardBase64.decode(encoded));
		}
	}

	@Test
	void decodesTheEmptyStringToNoOctets() throws EncodingException {
		Assertions.assertArrayEquals(new byte[0], StandardBase64.decode(""));
	}

	@Test
	void isAlphabetAcceptsExactlyTheSixtyFourCharacters() {
		for (int value = 0; value <= Character.MAX_VALUE; ++value) {
			char character = (char) value;
			Assertions.assertEquals(ALPHABET.indexOf(character) >= 0, StandardBase64.isAlphabet(character),
					() -> "character " + Integer.toHexString(character));
		}
	}

	@Test
	void returnsAFreshArrayOnEveryDecode() throws EncodingException {
		// The decoder returns a fresh array each time, so zeroing one result never affects another.
		byte[] first = StandardBase64.decode("AQIDBA==");
		byte[] second = StandardBase64.decode("AQIDBA==");
		Arrays.fill(first, (byte) 0);
		Assertions.assertArrayEquals(new byte[]{1, 2, 3, 4}, second);
	}

	// R9: the message is fixed; a sentinel inside rejected input never reaches any rendering.
	@Test
	void failuresNeverEchoTheInput() {
		String input = EncodingFailures.SENTINEL + "AAAAAAAAAAAAAAAAAAAAAAAA=";
		EncodingFailures.assertRejected(EncodingException.Kind.INVALID_LENGTH, input,
				() -> StandardBase64.decode(input));
	}

	@Test
	@SuppressWarnings("NullAway")
	void rejectsNullArgumentsWithNullPointerException() {
		Assertions.assertThrows(NullPointerException.class, () -> StandardBase64.decode(null));
		Assertions.assertThrows(NullPointerException.class, () -> StandardBase64.encode(null));
	}

	private static boolean isAccepted(String input, boolean canonical) {
		try {
			byte[] decoded = StandardBase64.decode(input);
			Assertions.assertTrue(canonical, input);
			Assertions.assertEquals(input, StandardBase64.encode(decoded));
			return true;
		} catch (EncodingException e) {
			Assertions.assertFalse(canonical, input);
			Assertions.assertEquals(EncodingException.Kind.NON_CANONICAL, e.getKind(), input);
			// The JDK decoder accepts every one of them.
			Assertions.assertDoesNotThrow(() -> Base64.getDecoder().decode(input));
			return false;
		}
	}

	private static Stream<DynamicTest> rejections(EncodingException.Kind kind, String... inputs) {
		return Stream.of(inputs).map(input -> DynamicTest.dynamicTest(EncodingFailures.describe(input),
				() -> EncodingFailures.assertRejected(kind, input, () -> StandardBase64.decode(input))));
	}
}
