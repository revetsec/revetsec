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

import com.revetsec.internal.json.JsonLimits;
import com.revetsec.jose.JoseException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;

/**
 * {@link JwtClaimsReader}: steps 8 and 9 of the plan's "JOSE semantics" (RFC 7519 sections 2, 4.1 and 7.2): the
 * payload is a strict UTF-8 JSON object, and the registered claims have their types, with a wrong type, an
 * out-of-range NumericDate or JSON {@code null} refused as {@link JoseException.Reason#CLAIMS}, never read as absent.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JwtClaimsReaderTests {
	private static final JsonLimits LIMITS = JsonLimits.jose(65_536);

	// RFC 7519 section 4.1: the registered claims are read with their types, aud as a string or an array, and the
	// whole claims set is kept, other members included.
	@Test
	void theRegisteredClaimsAreReadWithTheirTypes() throws JoseFailure {
		RegisteredClaims claims = read("{\"iss\":\"https://issuer.example.com\",\"sub\":\"s\",\"aud\":[\"a\",\"b\",\"a\"],"
				+ "\"exp\":1300819380,\"iat\":1300819000.5,\"nbf\":-1,\"jti\":\"j\",\"x\":{\"y\":[1]}}");

		Assertions.assertEquals("https://issuer.example.com", claims.issuer());
		Assertions.assertEquals("s", claims.subject());
		Assertions.assertEquals(List.of("a", "b", "a"), claims.audiences());
		Assertions.assertEquals(Instant.ofEpochSecond(1_300_819_380L), claims.expiresAt());
		Assertions.assertEquals(Instant.ofEpochSecond(1_300_819_000L, 500_000_000L), claims.issuedAt());
		Assertions.assertEquals(Instant.ofEpochSecond(-1L), claims.notBefore());
		Assertions.assertEquals("j", claims.jwtId());
		Assertions.assertTrue(claims.claims().find("x").isPresent());
		Assertions.assertEquals("RegisteredClaims{<redacted>}", claims.toString());

		RegisteredClaims empty = read("{}");
		Assertions.assertNull(empty.issuer());
		Assertions.assertEquals(List.of(), empty.audiences());
		Assertions.assertNull(empty.expiresAt());

		Assertions.assertEquals(List.of("only"), read("{\"aud\":\"only\"}").audiences());
		Assertions.assertEquals(List.of(""), read("{\"aud\":\"\"}").audiences());
	}

	// RFC 7519 section 7.2 steps 9 and 10: a payload that is not a strict UTF-8 JSON object is CLAIMS, the empty
	// payload included (RFC 7515 allows it at the JWS layer only).
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> aPayloadThatIsNotAJsonObjectIsMalformed() {
		return Stream.of("", " ", "[]", "\"claims\"", "1", "null", "{", "{}{}", "{\"iss\":\"a\",\"iss\":\"a\"}",
				"{\"sub\":\"a\",\"sub\":\"b\"}", "{\"x\":\"\\udc00\"}", "\ufeff{}", "{\"x\":" + "[".repeat(40) + "]".repeat(40)
						+ "}").map(text -> DynamicTest.dynamicTest("[" + (text.length() > 30 ? text.substring(0, 30) : text) + "]",
				() -> assertMalformed(text.getBytes(StandardCharsets.UTF_8))));
	}

	// Ill-formed UTF-8 is CLAIMS.
	@Test
	void illFormedUtf8IsMalformed() {
		assertMalformed(new byte[]{'{', '"', 'x', '"', ':', '"', (byte) 0xFF, '"', '}'});
		assertMalformed(new byte[]{'{', '"', 'x', '"', ':', '"', (byte) 0xED, (byte) 0xA0, (byte) 0x80, '"', '}'});
	}

	// RFC 7519 sections 4.1.1 to 4.1.7: a registered claim of the wrong type or JSON null is CLAIMS, and aud must be a
	// string or a non-empty array of strings.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> aRegisteredClaimOfTheWrongTypeIsMalformed() {
		List<String> members = List.of("\"iss\":null", "\"iss\":1", "\"iss\":[\"a\"]", "\"sub\":null", "\"sub\":{}",
				"\"jti\":null", "\"jti\":7", "\"aud\":null", "\"aud\":[]", "\"aud\":[123]", "\"aud\":[\"a\",null]",
				"\"aud\":[[\"a\"]]", "\"aud\":123", "\"aud\":{}", "\"exp\":null", "\"exp\":\"1300819380\"", "\"exp\":true",
				"\"exp\":[1]", "\"iat\":null", "\"iat\":\"0\"", "\"nbf\":null", "\"nbf\":{}");
		return members.stream().map(member -> DynamicTest.dynamicTest(member, () -> assertMalformed(("{" + member + "}")
				.getBytes(StandardCharsets.UTF_8))));
	}

	// RFC 7519 section 2: a NumericDate outside years -9999 to 9999 is CLAIMS, 2^63 and huge exponents included, and
	// is range-checked before any conversion.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> aNumericDateOutOfRangeIsMalformed() {
		return Stream.of("9223372036854775808", "9223372036854775807", "253402300800", "-377705116801", "1e19",
				"1e999999", "-1e999999", "1E+100").flatMap(value -> Stream.of("exp", "iat", "nbf").map(name ->
				DynamicTest.dynamicTest(name + " " + value, () -> assertMalformed(("{\"" + name + "\":" + value + "}")
						.getBytes(StandardCharsets.UTF_8)))));
	}

	// The last NumericDates inside the range are read, and a fraction finer than a nanosecond rounds toward the past.
	@Test
	void numericDatesAtTheEdgesOfTheRangeAreRead() throws JoseFailure {
		Assertions.assertEquals(Instant.parse("9999-12-31T23:59:59Z"), read("{\"exp\":253402300799}").expiresAt());
		Assertions.assertEquals(Instant.parse("-9999-01-01T00:00:00Z"), read("{\"exp\":-377705116800}").expiresAt());
		Assertions.assertEquals(Instant.ofEpochSecond(1L, 999_999_999L), read("{\"exp\":1.9999999999}").expiresAt());
		Assertions.assertEquals(Instant.EPOCH, read("{\"exp\":1e-100}").expiresAt());
	}

	private static @NonNull RegisteredClaims read(@NonNull String payload) throws JoseFailure {
		return JwtClaimsReader.read(payload.getBytes(StandardCharsets.UTF_8), LIMITS);
	}

	private static void assertMalformed(byte @NonNull [] payload) {
		JoseFailure failure = Assertions.assertThrows(JoseFailure.class, () -> JwtClaimsReader.read(payload, LIMITS));
		Assertions.assertEquals(JoseException.Reason.CLAIMS, failure.getReason());
	}
}
