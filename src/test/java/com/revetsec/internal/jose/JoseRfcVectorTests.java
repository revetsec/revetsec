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

import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.jose.JoseException;
import com.revetsec.jose.JsonWebKeySkipReason;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.json.JsonObject;
import com.revetsec.testing.WycheproofVectors;
import com.revetsec.testing.WycheproofVectors.TestGroup;
import com.revetsec.testing.WycheproofVectors.VectorFile;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * The IETF JOSE examples at the JWS layer, through {@link JwtProcessor} with no JWT claims check, because several
 * payloads are not JSON (plan M2 exit criterion 2): RFC 7515 appendix A.4 (ES512), RFC 7520 sections 4.1 to 4.3
 * (RS256, PS384 and ES512 over a text payload), RFC 8037 appendix A.4 (EdDSA) and its {@code Ed25519} re-signing
 * (RFC 9864), each verified with its key as a {@link VerifiedJws}, and each refused with
 * {@link JoseException.Reason#SIGNATURE_MISMATCH} once one bit of its signature is flipped. RFC 7515 appendix A.1 and
 * RFC 7520 section 4.4 (HS256) verify through the internal HMAC engine only. RFC 7517's private and symmetric example
 * keys are skipped.
 * <p>
 * Every example's effective algorithm set is its own {@code alg}, so an RSA key without {@code alg} verifies both
 * RFC 7520 section 4.1 (RS256) and section 4.2 (PS384), one algorithm at a time (RFC 8725 section 3.1). Both examples
 * sign with the key of RFC 7520 figure 4, whose public half, section 3.3's figure 3, carries no {@code alg} (RFC 7520
 * and RFC 8725 read from rfc-editor.org on 2026-09-28).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JoseRfcVectorTests {
	/**
	 * The SHA-256 of the payload all of RFC 7520 section 4's examples sign, 167 octets of UTF-8 text. The text quotes a
	 * literary work, so it is pinned by its digest rather than transcribed.
	 */
	private static final String RFC_7520_PAYLOAD_SHA_256 = "7066357f041418c95dc530f99781d8f5bf0ef8fd231279f8da16170a283"
			+ "a57b2";

	/**
	 * The SHA-256 of the {@code n} of RFC 7520 section 3.3's RSA public key (figure 3), as its base64url text with the
	 * figure's line breaks and indentation removed (read 2026-09-28).
	 */
	private static final String RFC_7520_FIGURE_3_N_SHA_256 = "899e5f256f06c99898e0a2a74db6281360ac8505b2fc3b33ff0bfaedcc"
			+ "48ab32";

	/**
	 * The SHA-256 of the {@code x} and {@code y} of RFC 7520 section 3.1's EC public key (figure 1), as their base64url
	 * texts joined by a period, with the figure's line breaks and indentation removed (read 2026-09-28).
	 */
	private static final String RFC_7520_FIGURE_1_COORDINATES_SHA_256 = "b50293237d67eb9f9219f68a3be0bd6c1e302f6c4da0e"
			+ "abed5f9713db9b53363";

	// Each public-key example verifies under its key at the JWS layer, and one flipped signature bit refuses it.
	@TestFactory
	Stream<DynamicTest> everyPublicKeyExampleVerifiesAndAFlippedBitDoesNot() {
		Map<String, Example> examples = new LinkedHashMap<>();
		examples.put("RFC 7515 A.4 (ES512)", new Example(RfcJoseExamples.RFC_7515_A4_JWS, RfcJoseExamples.rfc7515A4Key(),
				JwsAlgorithm.ES512, "Payload", null));
		examples.put("RFC 8037 A.4 (EdDSA)", new Example(RfcJoseExamples.RFC_8037_A4_JWS, RfcJoseExamples.rfc8037A2Key(),
				JwsAlgorithm.EDDSA, RfcJoseExamples.ED25519_PAYLOAD, null));
		examples.put("RFC 8037 A.4 re-signed as Ed25519 (RFC 9864)", new Example(RfcJoseExamples.ED25519_FIXTURE_JWS,
				RfcJoseExamples.rfc8037A2Key(), JwsAlgorithm.ED25519, RfcJoseExamples.ED25519_PAYLOAD, null));
		examples.put("RFC 7515 A.2 (RS256)", new Example(RfcJoseExamples.RFC_7515_A2_JWS, RfcJoseExamples.rfc7515A2Key(),
				JwsAlgorithm.RS256, null, null));
		examples.put("RFC 7515 A.3 (ES256)", new Example(RfcJoseExamples.RFC_7515_A3_JWS, RfcJoseExamples.rfc7515A3Key(),
				JwsAlgorithm.ES256, null, null));

		JsonWebSignatureFile rfc7520 = JsonWebSignatureFile.load();
		examples.put("RFC 7520 4.1 (RS256), Wycheproof tcId 345", rfc7520.example(345, JwsAlgorithm.RS256));
		examples.put("RFC 7520 4.2 (PS384), Wycheproof tcId 346", rfc7520.example(346, JwsAlgorithm.PS384));
		examples.put("RFC 7520 4.3 (ES512), Wycheproof tcId 347", rfc7520.example(347, JwsAlgorithm.ES512));

		return examples.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () -> {
			Example example = entry.getValue();
			VerificationKey key = JwkParser.parse(json(example.jwk()));
			KeySelection selection = KeySelector.select(List.of(key), query(example));
			Assertions.assertEquals(KeySelection.Kind.FOUND, selection.getKind());

			VerifiedJws verified = JwtProcessor.verify(prepare(example.jws(), example.algorithm()), selection);
			Assertions.assertEquals(example.algorithm(), verified.getAlgorithm());
			Assertions.assertSame(key, verified.findKey().orElseThrow());
			String expectedPayload = example.payload();
			if (expectedPayload != null)
				Assertions.assertEquals(expectedPayload, new String(verified.getPayload(), StandardCharsets.UTF_8));
			String expectedPayloadSha256 = example.payloadSha256();
			if (expectedPayloadSha256 != null)
				Assertions.assertEquals(expectedPayloadSha256, sha256(verified.getPayload()));

			JoseFailure failure = Assertions.assertThrows(JoseFailure.class, () -> JwtProcessor.verify(
					prepare(flipLastSignatureBit(example.jws()), example.algorithm()), selection));
			Assertions.assertEquals(JoseException.Reason.SIGNATURE_MISMATCH, failure.getReason());
		}));
	}

	// RFC 7520 sections 4.1 to 4.3 carry a text payload, not JSON: the JWS layer accepts it, and only the JWT layer
	// would refuse it as CLAIMS, after the signature verified. The vendored copies of their keys carry an alg per test,
	// which RFC 7520 section 3's keys do not (read 2026-09-28): figure 3's RSA key has kty, kid, use, n and e, and
	// figure 1's EC key kty, kid, use, crv, x and y.
	@Test
	void theRfc7520ExamplesSignTheSameTextPayload() throws Exception {
		JsonWebSignatureFile rfc7520 = JsonWebSignatureFile.load();

		for (int tcId = 345; tcId <= 348; ++tcId) {
			String jws = rfc7520.jws(tcId);
			String payload = jws.substring(jws.indexOf('.') + 1, jws.lastIndexOf('.'));
			byte[] text = Base64Url.decode(payload);
			Assertions.assertEquals(167, text.length, "tcId " + tcId);
			Assertions.assertEquals(RFC_7520_PAYLOAD_SHA_256, sha256(text), "tcId " + tcId);
		}

		// The alg Wycheproof adds follows the test: one RSA key, RS256 for tcId 345 and PS256 for tcId 346.
		JsonObject rs256Key = rfc7520.group(345).getObject("public");
		JsonObject ps256Key = rfc7520.group(346).getObject("public");
		Assertions.assertEquals(rs256Key.findString("kid").orElseThrow(), ps256Key.findString("kid").orElseThrow());
		Assertions.assertEquals(rs256Key.findString("n").orElseThrow(), ps256Key.findString("n").orElseThrow());
		Assertions.assertEquals("RS256", rs256Key.findString("alg").orElseThrow());
		Assertions.assertEquals("PS256", ps256Key.findString("alg").orElseThrow());

		// Apart from that alg, the vendored keys are RFC 7520's own: section 3.3's RSA key, and section 3.1's EC key.
		Assertions.assertEquals(Set.of("kty", "kid", "use", "n", "e", "alg"), rs256Key.getMembers().keySet());
		Assertions.assertEquals("RSA", rs256Key.findString("kty").orElseThrow());
		Assertions.assertEquals(RFC_7520_FIGURE_3_N_SHA_256, sha256(rs256Key.findString("n").orElseThrow()
				.getBytes(StandardCharsets.US_ASCII)));
		Assertions.assertEquals("AQAB", rs256Key.findString("e").orElseThrow());
		JsonObject ecKey = rfc7520.group(347).getObject("public");
		Assertions.assertEquals(Set.of("kty", "kid", "use", "crv", "x", "y", "alg"), ecKey.getMembers().keySet());
		Assertions.assertEquals("EC", ecKey.findString("kty").orElseThrow());
		Assertions.assertEquals("P-521", ecKey.findString("crv").orElseThrow());
		Assertions.assertEquals(RFC_7520_FIGURE_1_COORDINATES_SHA_256, sha256((ecKey.findString("x").orElseThrow() + "."
				+ ecKey.findString("y").orElseThrow()).getBytes(StandardCharsets.US_ASCII)));
		for (JsonObject key : List.of(rs256Key, ecKey)) {
			Assertions.assertEquals("bilbo.baggins@hobbiton.example", key.findString("kid").orElseThrow());
			Assertions.assertEquals("sig", key.findString("use").orElseThrow());
		}

		Example example = rfc7520.example(345, JwsAlgorithm.RS256);
		PreparedJws prepared = prepare(example.jws(), example.algorithm());
		KeySelection selection = KeySelection.fromKey(JwkParser.parse(json(example.jwk())));
		JoseFailure failure = Assertions.assertThrows(JoseFailure.class, () -> JwtProcessor.complete(prepared, selection,
				JwtClaimsPolicy.fromSettings("issuer", null, Set.of(), Duration.ZERO), Instant.EPOCH));
		Assertions.assertEquals(JoseException.Reason.CLAIMS, failure.getReason());
	}

	// RFC 7515 A.1 and RFC 7520 section 4.4 are HS256: they verify only through the internal HMAC engine, over the
	// configured secret, and a flipped bit refuses them. RFC 7515 A.1's claims then pass a policy for issuer joe
	// before its exp.
	@Test
	void theHmacExamplesVerifyThroughTheInternalEngineOnly() throws Exception {
		byte[] rfc7515Secret = Base64Url.decode(RfcJoseExamples.RFC_7515_A1_KEY);
		PreparedJws rfc7515 = prepare(RfcJoseExamples.RFC_7515_A1_JWS, JwsAlgorithm.HS256);

		VerifiedJws verified = JwtProcessor.verifyWithSecret(rfc7515, rfc7515Secret);
		Assertions.assertEquals(JwsAlgorithm.HS256, verified.getAlgorithm());
		Assertions.assertEquals("JWT", verified.findType().orElseThrow());
		Assertions.assertTrue(verified.findKey().isEmpty());

		JwtClaimsPolicy joe = JwtClaimsPolicy.fromSettings("joe", null, Set.of(), Duration.ofSeconds(60));
		VerifiedJwt jwt = JwtProcessor.completeWithSecret(rfc7515, rfc7515Secret, joe,
				Instant.ofEpochSecond(RfcJoseExamples.RFC_7515_JWT_EXPIRES_AT - 1));
		Assertions.assertEquals("joe", jwt.claims().issuer());
		Assertions.assertEquals(Instant.ofEpochSecond(RfcJoseExamples.RFC_7515_JWT_EXPIRES_AT), jwt.claims().expiresAt());
		Assertions.assertTrue(jwt.claims().claims().findBoolean("http://example.com/is_root").orElseThrow());
		Assertions.assertNull(jwt.key());

		JoseFailure flipped = Assertions.assertThrows(JoseFailure.class, () -> JwtProcessor.verifyWithSecret(
				prepare(flipLastSignatureBit(RfcJoseExamples.RFC_7515_A1_JWS), JwsAlgorithm.HS256), rfc7515Secret));
		Assertions.assertEquals(JoseException.Reason.SIGNATURE_MISMATCH, flipped.getReason());

		JsonWebSignatureFile rfc7520 = JsonWebSignatureFile.load();
		String rfc7520Jws = rfc7520.jws(348);
		byte[] rfc7520Secret = Base64Url.decode(rfc7520.group(348).getObject("private").findString("k")
				.orElseThrow());
		Assertions.assertEquals(RFC_7520_PAYLOAD_SHA_256, sha256(JwtProcessor.verifyWithSecret(prepare(rfc7520Jws,
				JwsAlgorithm.HS256), rfc7520Secret).getPayload()));
		JoseFailure flipped7520 = Assertions.assertThrows(JoseFailure.class, () -> JwtProcessor.verifyWithSecret(
				prepare(flipLastSignatureBit(rfc7520Jws), JwsAlgorithm.HS256), rfc7520Secret));
		Assertions.assertEquals(JoseException.Reason.SIGNATURE_MISMATCH, flipped7520.getReason());

		// Under the public-key path the same token has no key: nothing in a key set fits HS256.
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, KeySelector.select(List.of(JwkParser.parse(json(
				RfcJoseExamples.rfc7515A2Key()))), rfc7515.getKeyQuery()).getKind());
	}

	// RFC 7517 appendix A: the public keys load (the RSA key is RFC 7638 section 3.1's, with its thumbprint), the EC
	// key is for encryption and so is skipped, and the private and symmetric example keys are skipped, never used for
	// their public half (Discovery section 3; RFC 7517 section 4.2).
	@Test
	void theRfc7517ExampleKeysAreUsableOnlyAsPublicSigningKeys() throws Exception {
		String rsa = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFF"
				+ "xuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Qvz"
				+ "qY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XP"
				+ "ksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\"e\":\"AQAB\",\"alg\":\"RS256\","
				+ "\"kid\":\"2011-04-29\"}";
		String keySet = "{\"keys\":[" + RfcJoseExamples.RFC_7517_A1_EC_KEY + "," + rsa + ","
				+ RfcJoseExamples.RFC_7517_A2_EC_KEY + "," + RfcJoseExamples.RFC_7517_A3_HMAC_KEY + "]}";

		ParsedKeySet parsed = JwkSetParser.parse(keySet, 256 * 1024, 100);
		Assertions.assertEquals(1, parsed.keys().size());
		VerificationKey key = parsed.keys().get(0);
		Assertions.assertEquals("2011-04-29", key.keyId());
		Assertions.assertEquals(JwsAlgorithm.RS256, key.algorithm());
		Assertions.assertEquals("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", key.thumbprintSha256());
		Assertions.assertEquals(List.of(new ParsedKeySet.Skip(0, JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY),
				new ParsedKeySet.Skip(2, JsonWebKeySkipReason.PRIVATE_KEY_MEMBERS),
				new ParsedKeySet.Skip(3, JsonWebKeySkipReason.SYMMETRIC_KEY)), parsed.skips());

		// Without use, the same EC key is a usable ES256 key, so use: enc alone decided the skip.
		Assertions.assertEquals("1", JwkParser.parse(json(RfcJoseExamples.RFC_7517_A1_EC_KEY.replace(
				",\"use\":\"enc\"", ""))).keyId());
	}

	private static PreparedJws prepare(String jws,
																		 JwsAlgorithm algorithm) throws JoseFailure {
		return JwtProcessor.prepare(jws, JoseHeaderPolicy.fromSettings(64 * 1024, Set.of(algorithm), Set.of("JWT"),
				false));
	}

	private static KeyQuery query(Example example) throws JoseFailure {
		return prepare(example.jws(), example.algorithm()).getKeyQuery();
	}

	private static JsonObject json(String text) throws Exception {
		return (JsonObject) JsonCodec.parse(text.getBytes(StandardCharsets.UTF_8), JsonLimits.jose(64 * 1024));
	}

	/**
	 * The token with the lowest bit of its signature's last octet flipped.
	 */
	static String flipLastSignatureBit(String jws) throws Exception {
		int dot = jws.lastIndexOf('.');
		byte[] signature = Base64Url.decode(jws.substring(dot + 1));
		signature[signature.length - 1] ^= 1;
		return jws.substring(0, dot + 1) + Base64Url.encode(signature);
	}

	/**
	 * The lowercase hexadecimal SHA-256 of {@code bytes}.
	 */
	private static String sha256(byte[] bytes) throws Exception {
		return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
	}

	/**
	 * One example: the token, its key's JWK, its algorithm, and its payload text or the SHA-256 of its payload when the
	 * test checks it.
	 */
	private record Example(String jws, String jwk, JwsAlgorithm algorithm, @Nullable String payload,
												 @Nullable String payloadSha256) {
	}

	/**
	 * The vendored Wycheproof JWS file, which carries RFC 7520's section 4 examples with the section 3 public keys.
	 * Wycheproof gives each key an {@code alg} that follows the test rather than the key: the same RSA key is RS256 in
	 * tcId 345's group and PS256 in tcId 346's, and the EC key's ES521 is no JWS algorithm. RFC 7520 section 3's own
	 * keys carry no {@code alg} (read 2026-09-28), so the tests drop that member and verify each example under its own
	 * algorithm alone, as an application holding the RFC's keys would.
	 */
	private record JsonWebSignatureFile(VectorFile file) {
		static JsonWebSignatureFile load() {
			return new JsonWebSignatureFile(WycheproofVectors.fromVendoredFiles().getFile("json_web_signature_test.json"));
		}

		String jws(int tcId) {
			return this.file.getTest(tcId).getString("jws");
		}

		TestGroup group(int tcId) {
			return this.file.getTest(tcId).getGroup();
		}

		Example example(int tcId,
										JwsAlgorithm algorithm) {
			Assertions.assertEquals("rfc7520", group(tcId).getJson().findString("comment").orElseThrow());
			JsonObject.Builder key = JsonObject.builder();
			group(tcId).getObject("public").getMembers().forEach((name, value) -> {
				if (!name.equals("alg"))
					key.put(name, value);
			});
			Assertions.assertTrue(group(tcId).getObject("public").find("d").isEmpty());
			return new Example(jws(tcId), key.build().toJson(), algorithm, null, RFC_7520_PAYLOAD_SHA_256);
		}
	}
}
