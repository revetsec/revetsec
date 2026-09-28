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

package com.revetsec.jose;

import com.revetsec.testing.TestJsonWebKeys;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws;
import com.revetsec.testing.TestJws.Algorithm;
import com.revetsec.testing.TestJws.Variant;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * {@link JwtValidator#validate(String)} on the token's form and JOSE header (plan "JOSE semantics", steps 1 to 4,
 * P1 to P8; RFC 7515 sections 2, 4, 5.2 and 7; RFC 8725 sections 3.7, 3.10 and 3.11): each refusal through the leaf
 * exception its reason belongs to, before any key is used.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JwtValidatorHeaderTests {
	private static final JwtValidator VALIDATOR = JwtFixtures.validator(Fixture.IDP_SIGNING_RSA_2048, JwsAlgorithm.RS256);

	// RFC 8725 section 3.11 and M2-4 (exit criterion 10): with the default {JWT}, an absent typ and JWT, jwt and
	// application/JWT are accepted, and Jwt.getType gives the raw value. RFC 7515 section 4.1.9 (read 2026-09-28) makes
	// typ a media type, case-insensitive, with application/ implied when it has no /.
	@TestFactory
	Stream<DynamicTest> theDefaultTypeAcceptsJwtInAnyAsciiCaseOrNoType() {
		return Stream.of("JWT", "jwt", "application/JWT", "application/jwt", "Application/Jwt").map(type ->
				DynamicTest.dynamicTest(type, () -> {
					Jwt jwt = JwtFixtures.assertAccepted(VALIDATOR, JwtFixtures.token(Algorithm.RS256).typ(type)
							.sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
					Assertions.assertEquals(type, jwt.getType().orElseThrow());
				}));
	}

	// RFC 8725 section 3.12: types that mark other JWT profiles are INVALID_TYPE under the default, so an access
	// token, a logout token or a security event token is never taken for a generic JWT (exit criterion 10).
	@TestFactory
	Stream<DynamicTest> typesOfOtherProfilesAreRefused() {
		return Stream.of("at+jwt", "logout+jwt", "application/secevent+jwt", "application/at+jwt", "JOSE", "JOSE+JSON",
				"jwt; charset=utf-8", "").map(type -> DynamicTest.dynamicTest("[" + type + "]", () ->
				JwtFixtures.assertRejected(JoseException.Reason.INVALID_TYPE, VALIDATOR, JwtFixtures.token(Algorithm.RS256)
						.typ(type).sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()))));
	}

	// A profile's own type set: at+jwt required, so an untyped or JWT-typed token is INVALID_TYPE.
	@Test
	void aRequiredTypeRefusesUntypedAndOtherTokens() {
		JwtValidator accessTokens = JwtFixtures.validator(JwtFixtures.source(Fixture.IDP_SIGNING_RSA_2048))
				.allowedTypes(Set.of("at+jwt")).typeRequired(true).build();

		JwtFixtures.assertAccepted(accessTokens, JwtFixtures.token(Algorithm.RS256).typ("application/at+jwt")
				.sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
		JwtFixtures.assertRejected(JoseException.Reason.INVALID_TYPE, accessTokens, JwtFixtures.signed(
				Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256));
		JwtFixtures.assertRejected(JoseException.Reason.INVALID_TYPE, accessTokens, JwtFixtures.token(Algorithm.RS256)
				.typ("JWT").sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
	}

	// RFC 7515 section 7.1 and RFC 7516 section 7.1: 2, 4 and 6 segments are TOKEN_SYNTAX, 5 are a JWE
	// (ENCRYPTED_TOKEN), and the JSON serialization is JSON_SERIALIZATION.
	@Test
	void theSerializationIsCompactJwsOnly() {
		TestJws.Signed signed = JwtFixtures.token(Algorithm.RS256).signed(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());

		JwtFixtures.assertRejected(JoseException.Reason.TOKEN_SYNTAX, VALIDATOR, signed.getSigningInput());
		JwtFixtures.assertRejected(JoseException.Reason.TOKEN_SYNTAX, VALIDATOR, signed.withVariant(
				Variant.EXTRA_SEGMENT));
		JwtFixtures.assertRejected(JoseException.Reason.TOKEN_SYNTAX, VALIDATOR, signed.withVariant(Variant.FIVE_SEGMENTS)
				+ ".e30");
		JwtFixtures.assertRejected(JoseException.Reason.ENCRYPTED_TOKEN, VALIDATOR, signed.withVariant(
				Variant.FIVE_SEGMENTS));
		JwtFixtures.assertRejected(JoseException.Reason.ENCRYPTED_TOKEN, VALIDATOR, "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6Ik"
				+ "ExMjhHQ00ifQ.a.b.c.d");
		JwtFixtures.assertRejected(JoseException.Reason.JSON_SERIALIZATION, VALIDATOR, "{\"payload\":\""
				+ signed.getPayloadSegment() + "\",\"protected\":\"" + signed.getHeaderSegment() + "\",\"signature\":\""
				+ signed.getSignatureSegment() + "\"}");
		JwtFixtures.assertRejected(JoseException.Reason.TOKEN_SYNTAX, VALIDATOR, "");
	}

	// RFC 7515 section 2 (INV-J7): a validly signed token with padding, the standard alphabet, whitespace or a
	// non-canonical last character in any segment is TOKEN_SYNTAX, before its signature is looked at.
	@TestFactory
	Stream<DynamicTest> aNonCanonicalEncodingOfAValidTokenIsTokenSyntax() {
		TestJws.Signed signed = JwtFixtures.token(Algorithm.RS256).signed(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());
		JwtFixtures.assertAccepted(VALIDATOR, signed.toCompactSerialization());

		Map<String, String> cases = new LinkedHashMap<>();
		for (Variant variant : List.of(Variant.PADDED_HEADER, Variant.PADDED_PAYLOAD, Variant.PLUS_IN_SIGNATURE,
				Variant.SLASH_IN_SIGNATURE))
			cases.put(variant.name(), signed.withVariant(variant));
		String token = signed.toCompactSerialization();
		cases.put("a space inside", token.substring(0, 10) + " " + token.substring(10));
		cases.put("a trailing newline", token + "\n");
		cases.put("a leading space", " " + token);
		cases.put("a header with trailing bits", TestJws.compact(TestJws.withNonCanonicalTrailingBits(
				signed.getHeaderSegment()), signed.getPayloadSegment(), signed.getSignatureSegment()));
		// 256 octets are 342 characters, so three more make a length of 4n + 1.
		Assertions.assertEquals(342, signed.getSignatureSegment().length());
		cases.put("a signature of length 4n + 1", token + "AAA");

		return cases.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () ->
				JwtFixtures.assertRejected(JoseException.Reason.TOKEN_SYNTAX, VALIDATOR, entry.getValue())));
	}

	// RFC 7515 section 5.2 step 3 and RFC 8725 section 3.7: a header that is a JSON array, ill-formed UTF-8, has a
	// BOM, a duplicate alg or a lone surrogate is HEADER, even when the token is otherwise validly signed.
	@TestFactory
	Stream<DynamicTest> aHeaderThatIsNotAStrictJsonObjectIsMalformed() {
		Map<String, byte[]> headers = new LinkedHashMap<>();
		headers.put("a JSON array", bytes("[\"RS256\"]"));
		headers.put("ill-formed UTF-8", concat(bytes("{\"alg\":\"RS256\",\"x\":\""), new byte[]{(byte) 0xFF},
				bytes("\"}")));
		headers.put("a byte-order mark", concat(new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF},
				bytes("{\"alg\":\"RS256\"}")));
		headers.put("a duplicate alg", bytes("{\"alg\":\"RS256\",\"alg\":\"RS256\"}"));
		headers.put("a lone surrogate", bytes("{\"alg\":\"RS256\",\"kid\":\"\\ud800\"}"));
		headers.put("1,000 levels deep", bytes("{\"alg\":\"RS256\",\"x\":" + "[".repeat(1_000) + "]".repeat(1_000)
				+ "}"));
		headers.put("alg missing", bytes("{\"kid\":\"" + JwtFixtures.KID + "\"}"));
		headers.put("alg a number", bytes("{\"alg\":256}"));
		headers.put("kid empty", bytes("{\"alg\":\"RS256\",\"kid\":\"\"}"));
		headers.put("kid 257 characters", bytes("{\"alg\":\"RS256\",\"kid\":\"" + "k".repeat(257) + "\"}"));
		headers.put("kid a number", bytes("{\"alg\":\"RS256\",\"kid\":1}"));

		return headers.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () ->
				JwtFixtures.assertRejected(JoseException.Reason.HEADER, VALIDATOR, TestJws.withAlgorithm(Algorithm.RS256)
						.headerBytes(entry.getValue()).payload(JwtFixtures.claims().toJson()).sign(
								Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()))));
	}

	// RFC 7515 section 4.1.11 and RFC 7797 section 6: crit, with any value, and b64 and zip are unsupported, so a
	// crit naming exp, or naming b64 with b64 false, is never processed.
	@Test
	void criticalUnencodedAndCompressedTokensAreUnsupported() {
		Map<JoseException.Reason, TestJws.Builder> cases = new LinkedHashMap<>();
		cases.put(JoseException.Reason.CRITICAL_HEADER, JwtFixtures.token(Algorithm.RS256).headerMember("crit",
				"[\"exp\"]"));
		cases.put(JoseException.Reason.UNENCODED_PAYLOAD, JwtFixtures.token(Algorithm.RS256).headerMember("b64", "false"));
		cases.put(JoseException.Reason.COMPRESSED_PAYLOAD, JwtFixtures.token(Algorithm.RS256).headerMember("zip",
				"\"DEF\""));

		cases.forEach((reason, builder) -> Assertions.assertInstanceOf(UnsupportedJoseFeatureException.class,
				JwtFixtures.assertRejected(reason, VALIDATOR, builder.sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()))));
		JwtFixtures.assertRejected(JoseException.Reason.CRITICAL_HEADER, VALIDATOR, JwtFixtures.token(Algorithm.RS256)
				.headerMember("crit", "[\"b64\"]").headerMember("b64", "false").sign(
						Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
	}

	// RFC 8725 section 3.10 and CVE-2018-0114 (exit criterion 5, static half): an embedded jwk carrying the attacker's
	// own key, validly self-signed and naming the trusted key's kid, is UNTRUSTED_KEY_REFERENCE, as are jku (even one
	// equal to a trusted key set's URI) and x5u. Without the header, the same forgery fails only on its signature.
	@Test
	void keysAndKeyLocationsInTheHeaderAreNeverTrusted() {
		Fixture attacker = Fixture.NEGATIVE_ATTACKER_RSA_2048;
		String attackerJwk = TestJsonWebKeys.withFixture(attacker).kid(JwtFixtures.KID).toJson();

		for (Map.Entry<String, String> member : List.of(Map.entry("jwk", attackerJwk),
				Map.entry("jku", "\"https://idp.example.com/.well-known/jwks.json\""),
				Map.entry("jku", "\"https://attacker.example.com/jwks\""),
				Map.entry("x5u", "\"https://attacker.example.com/cert.pem\"")))
			JwtFixtures.assertRejected(JoseException.Reason.UNTRUSTED_KEY_REFERENCE, VALIDATOR,
					JwtFixtures.token(Algorithm.RS256).headerMember(member.getKey(), member.getValue()).sign(
							attacker.getPrivateKey()));

		JwtFixtures.assertRejected(JoseException.Reason.SIGNATURE_MISMATCH, VALIDATOR, JwtFixtures.token(Algorithm.RS256)
				.sign(attacker.getPrivateKey()));
		// x5c, x5t and x5t#S256 are ignored: the trusted key still decides.
		JwtFixtures.assertAccepted(VALIDATOR, JwtFixtures.token(Algorithm.RS256).headerMember("x5c", "[\"MIIB\"]")
				.headerMember("x5t", "\"abc\"").headerMember("x5t#S256", "\"def\"").sign(
						Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
	}

	// RFC 7519 section 7.2 step 8: a cty header marks a nested token, which is not processed.
	@Test
	void aNestedTokenIsUnsupported() {
		for (String cty : List.of("\"JWT\"", "\"jwt\"", "\"application/json\""))
			JwtFixtures.assertRejected(JoseException.Reason.NESTED_TOKEN, VALIDATOR, JwtFixtures.token(Algorithm.RS256)
					.headerMember("cty", cty).sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
	}

	// Plan "JOSE semantics" step 4: the header checks run in a fixed order, alg (P4), then crit, b64 and zip (P5), then
	// jwk, jku and x5u (P6), then typ (P7), then cty (P8), then the kid's form, and the first one that fails names the
	// reason, through its leaf exception.
	@TestFactory
	Stream<DynamicTest> theFirstFailingHeaderCheckNamesTheReason() {
		String jku = "\"https://attacker.example.com/jwks\"";
		List<Map.Entry<String, Map.Entry<JoseException.Reason, TestJws.Builder>>> rows = List.of(
				row("an algorithm not allowed, and crit", JoseException.Reason.ALGORITHM_NOT_ALLOWED,
						JwtFixtures.token(Algorithm.PS256).headerMember("crit", "[\"exp\"]")),
				row("zip and jku", JoseException.Reason.COMPRESSED_PAYLOAD, JwtFixtures.token(Algorithm.RS256)
						.headerMember("zip", "\"DEF\"").headerMember("jku", jku)),
				row("jku and a type not allowed", JoseException.Reason.UNTRUSTED_KEY_REFERENCE,
						JwtFixtures.token(Algorithm.RS256).typ("at+jwt").headerMember("jku", jku)),
				row("cty and jku", JoseException.Reason.UNTRUSTED_KEY_REFERENCE, JwtFixtures.token(Algorithm.RS256)
						.headerMember("cty", "\"JWT\"").headerMember("jku", jku)),
				row("cty and a type not allowed", JoseException.Reason.INVALID_TYPE, JwtFixtures.token(Algorithm.RS256)
						.typ("at+jwt").headerMember("cty", "\"JWT\"")),
				row("cty and an empty kid", JoseException.Reason.NESTED_TOKEN, JwtFixtures.token(Algorithm.RS256).kid("")
						.headerMember("cty", "\"JWT\"")),
				row("an empty kid alone", JoseException.Reason.HEADER, JwtFixtures.token(Algorithm.RS256).kid("")));

		return rows.stream().map(row -> DynamicTest.dynamicTest(row.getKey(), () -> JwtFixtures.assertRejected(
				row.getValue().getKey(), VALIDATOR, row.getValue().getValue().sign(
						Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()))));
	}

	// P1 (R8 COMPACT_JWT_SIZE): a 70 KiB token is TOKEN_TOO_LARGE under the default 64 KiB before it is decoded, even
	// when its characters are not base64url.
	@Test
	void anOversizedTokenIsRefusedBeforeDecoding() {
		JwtFixtures.assertRejected(JoseException.Reason.TOKEN_TOO_LARGE, VALIDATOR, "{".repeat(70 * 1_024));
		JwtFixtures.assertRejected(JoseException.Reason.TOKEN_TOO_LARGE, VALIDATOR, JwtFixtures.signed(
				Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256, JwtFixtures.claims().put("pad", "p".repeat(70 * 1_024))));
		JwtFixtures.assertRejected(JoseException.Reason.JSON_SERIALIZATION, VALIDATOR, "{".repeat(64 * 1_024));
	}

	// Members the header does not need are ignored (RFC 7515 section 4), so a header with extra members verifies.
	@Test
	void unknownHeaderMembersAreIgnored() {
		JwtFixtures.assertAccepted(VALIDATOR, JwtFixtures.token(Algorithm.RS256).headerMember("x-custom", "{\"a\":[1]}")
				.headerMember("iss", "\"someone-else\"").sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
	}

	private static Map.Entry<String, Map.Entry<JoseException.Reason, TestJws.Builder>> row(String name,
			JoseException.Reason reason, TestJws.Builder token) {
		return Map.entry(name, Map.entry(reason, token));
	}

	private static byte[] bytes(String text) {
		return text.getBytes(StandardCharsets.UTF_8);
	}

	private static byte[] concat(byte[]... parts) {
		int length = 0;
		for (byte[] part : parts)
			length += part.length;
		byte[] result = new byte[length];
		int offset = 0;
		for (byte[] part : parts) {
			System.arraycopy(part, 0, result, offset, part.length);
			offset += part.length;
		}
		return result;
	}
}
