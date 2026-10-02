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

package com.revetsec.internal.jose;

import org.jspecify.annotations.NonNull;

import com.revetsec.jose.JoseException;
import com.revetsec.testing.TestJws;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.SplittableRandom;
import java.util.stream.Stream;

/**
 * {@link CompactJwsParser}: steps 1 to 3 of the plan's "JOSE semantics" (P1, P2; RFC 7515 sections 2, 3.1, 5.2 and
 * 7.1; INV-J7): the size before anything else, the JSON serialization, one linear pass over the characters and the dot
 * count, the JWE shape, an empty header, and canonical base64url for every segment.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class CompactJwsParserTests {
	// 22, 11 and 5 octets: none a multiple of 3, so each segment has unused trailing bits to set.
	private static final String HEADER_JSON = "{\"alg\":\"RS256\",\"x\":10}";
	private static final String HEADER = TestJws.base64Url(HEADER_JSON);
	private static final String PAYLOAD = TestJws.base64Url("{\"iss\":\"a\"}");
	private static final String SIGNATURE = TestJws.base64Url(new byte[]{1, 2, 3, 4, 5});

	// Step 1: a token longer than the maximum is TOKEN_TOO_LARGE whatever it holds, even characters that would
	// otherwise be the JSON serialization or a syntax error; one at the maximum goes on to the other checks.
	@Test
	void aTokenOverTheMaximumIsTooLargeWhateverItHolds() throws JoseFailure {
		String token = HEADER + "." + PAYLOAD + "." + SIGNATURE;

		assertFailure(JoseException.Reason.TOKEN_TOO_LARGE, token, token.length() - 1);
		assertFailure(JoseException.Reason.TOKEN_TOO_LARGE, "{" + "=".repeat(99), 99);
		assertFailure(JoseException.Reason.TOKEN_TOO_LARGE, "\u0000".repeat(8_193), 8_192);
		Assertions.assertEquals(token, CompactJwsParser.parse(token, token.length()).getCompactSerialization());
		assertFailure(JoseException.Reason.JSON_SERIALIZATION, "{" + "=".repeat(99), 100);
	}

	// Step 2 (RFC 7515 section 7.2): a token that starts with a brace is the JWS JSON serialization, which is not
	// supported; anything before the brace is just a character outside the alphabet.
	@Test
	void aLeadingBraceIsTheJsonSerialization() {
		for (String token : List.of("{", "{}", "{\"payload\":\"e30\",\"signatures\":[]}", "{" + HEADER + "." + PAYLOAD
				+ "." + SIGNATURE))
			assertFailure(JoseException.Reason.JSON_SERIALIZATION, token);

		assertFailure(JoseException.Reason.TOKEN_SYNTAX, " {}");
		assertFailure(JoseException.Reason.TOKEN_SYNTAX, HEADER + ".{." + SIGNATURE);
	}

	// Step 2 (RFC 7516 section 7.1): four dots are the JWE compact serialization; every other count but two is
	// TOKEN_SYNTAX, including 2, 4 and 6 segments.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> theDotCountDecidesTheSerialization() {
		Map<String, JoseException.Reason> cases = new LinkedHashMap<>();
		cases.put("", JoseException.Reason.TOKEN_SYNTAX);
		cases.put(HEADER, JoseException.Reason.TOKEN_SYNTAX);
		cases.put(HEADER + "." + PAYLOAD, JoseException.Reason.TOKEN_SYNTAX);
		cases.put(HEADER + "." + PAYLOAD + "." + SIGNATURE + ".e30", JoseException.Reason.TOKEN_SYNTAX);
		cases.put(HEADER + "." + PAYLOAD + "." + SIGNATURE + ".e30.e30", JoseException.Reason.ENCRYPTED_TOKEN);
		cases.put("....", JoseException.Reason.ENCRYPTED_TOKEN);
		cases.put(HEADER + "." + PAYLOAD + "." + SIGNATURE + ".e30.e30.e30", JoseException.Reason.TOKEN_SYNTAX);
		cases.put(".".repeat(1_000), JoseException.Reason.TOKEN_SYNTAX);
		// The character check runs in the same pass, so a JWE shape with a bad character is a syntax error.
		cases.put(HEADER + "." + PAYLOAD + "." + SIGNATURE + ".e30.e3=", JoseException.Reason.TOKEN_SYNTAX);

		return cases.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey().length() + " characters: "
				+ entry.getValue(), () -> assertFailure(entry.getValue(), entry.getKey())));
	}

	// P1 as amended by M2-6: an empty header is TOKEN_SYNTAX, while an empty payload and an empty signature pass the
	// parser (RFC 7515 allows an empty payload, and every algorithm refuses an empty signature by its length).
	@Test
	void onlyTheHeaderSegmentMustBeNonEmpty() throws JoseFailure {
		assertFailure(JoseException.Reason.TOKEN_SYNTAX, "." + PAYLOAD + "." + SIGNATURE);
		assertFailure(JoseException.Reason.TOKEN_SYNTAX, "..");

		CompactJws jws = CompactJwsParser.parse(HEADER + "..", 1_000);
		Assertions.assertArrayEquals(new byte[0], jws.getPayload());
		Assertions.assertArrayEquals(new byte[0], jws.getSignature());
		Assertions.assertArrayEquals((HEADER + ".").getBytes(StandardCharsets.US_ASCII), jws.getSigningInput());
	}

	// RFC 7515 section 2 and RFC 4648 section 5: only the base64url alphabet, so padding, the standard alphabet,
	// whitespace, controls and non-ASCII characters are TOKEN_SYNTAX in any segment.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> aCharacterOutsideTheAlphabetIsTokenSyntaxInAnySegment() {
		List<String> characters = List.of("=", "+", "/", " ", "\t", "\r", "\n", "\u0000", "%", "\\", "\"", "\u00e9",
				"\u00a0", "\uff21", "\ud83d\ude00", "\ud800", "\u0660");
		return characters.stream().flatMap(character -> Stream.of(0, 1, 2).map(segment -> DynamicTest.dynamicTest(
				"U+" + Integer.toHexString(character.codePointAt(0)) + " in segment " + segment, () -> {
					String[] segments = {HEADER, PAYLOAD, SIGNATURE};
					segments[segment] = segments[segment].substring(0, 2) + character + segments[segment].substring(2);
					assertFailure(JoseException.Reason.TOKEN_SYNTAX, String.join(".", segments));
				})));
	}

	// Step 3 (INV-J7): each segment must be the canonical encoding: unused trailing bits set, or a length of 4n + 1,
	// is TOKEN_SYNTAX in the header, the payload and the signature alike.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> aNonCanonicalSegmentIsTokenSyntax() {
		Map<String, String> cases = new LinkedHashMap<>();
		cases.put("header with trailing bits", TestJws.withNonCanonicalTrailingBits(HEADER) + "." + PAYLOAD + "."
				+ SIGNATURE);
		cases.put("payload with trailing bits", HEADER + "." + TestJws.withNonCanonicalTrailingBits(PAYLOAD) + "."
				+ SIGNATURE);
		cases.put("signature with trailing bits", HEADER + "." + PAYLOAD + "."
				+ TestJws.withNonCanonicalTrailingBits(SIGNATURE));
		cases.put("header of length 4n + 1", "AAAAA." + PAYLOAD + "." + SIGNATURE);
		cases.put("payload of length 4n + 1", HEADER + ".AAAAA." + SIGNATURE);
		cases.put("signature of length 4n + 1", HEADER + "." + PAYLOAD + ".A");

		return cases.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () -> assertFailure(
				JoseException.Reason.TOKEN_SYNTAX, entry.getValue())));
	}

	// RFC 7515 section 5.2 step 8: the segments decode, and the signing input is the received ASCII header.payload,
	// never a re-encoding. Each accessor hands out a copy.
	@Test
	void theSegmentsDecodeAndTheSigningInputIsTheReceivedText() throws JoseFailure {
		CompactJws jws = CompactJwsParser.parse(HEADER + "." + PAYLOAD + "." + SIGNATURE, 1_000);

		Assertions.assertEquals(HEADER_JSON, new String(jws.getHeader(), StandardCharsets.UTF_8));
		Assertions.assertEquals("{\"iss\":\"a\"}", new String(jws.getPayload(), StandardCharsets.UTF_8));
		Assertions.assertArrayEquals(new byte[]{1, 2, 3, 4, 5}, jws.getSignature());
		Assertions.assertArrayEquals((HEADER + "." + PAYLOAD).getBytes(StandardCharsets.US_ASCII),
				jws.getSigningInput());

		jws.getSignature()[0] = 9;
		jws.getHeader()[0] = 9;
		Assertions.assertArrayEquals(new byte[]{1, 2, 3, 4, 5}, jws.getSignature());
		Assertions.assertEquals('{', jws.getHeader()[0]);
		Assertions.assertFalse(jws.toString().contains(HEADER));
		Assertions.assertEquals("CompactJws{headerLength=22, payloadLength=11, signatureLength=5}", jws.toString());
	}

	// INV-G1: whatever the text, the parser either returns or throws JoseFailure; nothing else escapes. A fixed seed
	// keeps the run reproducible.
	@Test
	void arbitraryTextNeverEscapesAsAnythingButJoseFailure() {
		SplittableRandom random = new SplittableRandom(20_260_927L);
		String alphabet = "AZaz09-_.={}+/ \u00e9\ud800";

		for (int round = 0; round < 20_000; ++round) {
			StringBuilder token = new StringBuilder();
			int length = random.nextInt(40);
			for (int index = 0; index < length; ++index)
				token.append(alphabet.charAt(random.nextInt(alphabet.length())));

			try {
				CompactJwsParser.parse(token.toString(), 30);
			} catch (JoseFailure expected) {
				Assertions.assertNotNull(expected.getReason());
			}
		}
	}

	private static void assertFailure(JoseException.@NonNull Reason reason,
																		@NonNull String token) {
		assertFailure(reason, token, 100_000);
	}

	private static void assertFailure(JoseException.@NonNull Reason reason,
																		@NonNull String token,
																		int maximumLength) {
		JoseFailure failure = Assertions.assertThrows(JoseFailure.class, () -> CompactJwsParser.parse(token,
				maximumLength));
		Assertions.assertEquals(reason, failure.getReason());
	}
}
