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

import com.revetsec.internal.jose.JwkSetParser;
import com.revetsec.internal.jose.ParsedKeySet;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonValue;
import com.revetsec.testing.TestJsonWebKeys;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws;
import com.revetsec.testing.TestJws.Algorithm;
import com.revetsec.testing.WycheproofVectors;
import com.revetsec.testing.WycheproofVectors.VectorFile;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * {@link JwtValidator} over a {@link StaticJsonWebKeySource}: which key verifies a token (INV-J3, INV-J9; plan "Key
 * selection" and "Keys"; plan M2 exit criteria 7 and 10). A key the key-set rules skip never verifies, not even a token
 * signed with its own private key; a {@code kid} selects at most one key; a duplicate {@code kid} or a {@code kid}-less
 * token with two candidates is ambiguous (OpenID Connect Core section 10.1); an RSA key without {@code alg} serves only
 * a lone RSA algorithm (G8-2, RFC 8725 section 3.1, read 2026-09-28); and a failed signature never falls back to
 * another key.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JwtValidatorKeySelectionTests {
	private static final String BAD_KID = "bad";
	private static final BigInteger ED25519_P = TestJsonWebKeys.ED25519_FIELD_PRIME;

	// Exit criterion 7: every key the rules skip is skipped with its reason, and a token naming its kid is
	// UNKNOWN_KEY, even when signed by that key's own private key (or, for a key that is only a variant of a good key,
	// by the good key's private key), so no skipped key is ever used for its public half.
	@TestFactory
	Stream<DynamicTest> aSkippedKeyNeverVerifiesATokenNamingIt() throws Exception {
		Map<String, SkippedCase> cases = new LinkedHashMap<>();
		PrivateKey rsa = Fixture.IDP_SIGNING_RSA_2048.getPrivateKey();
		cases.put("a ROCA-fingerprinted modulus", new SkippedCase(TestJsonWebKeys.withKeyPair(
				TestJsonWebKeys.rocaFingerprintedRsaKeyPair()), JsonWebKeySkipReason.WEAK_KEY, Algorithm.RS256,
				TestJsonWebKeys.rocaFingerprintedRsaKeyPair().getPrivate()));
		for (long exponent : List.of(1L, 3L, 65_535L, 65_536L, 65_538L, 4_294_967_297L))
			cases.put("e = " + exponent, new SkippedCase(TestJsonWebKeys.rsaWithExponent(BigInteger.valueOf(exponent)),
					JsonWebKeySkipReason.RSA_EXPONENT, Algorithm.RS256, rsa));
		cases.put("a non-minimal n", new SkippedCase(TestJsonWebKeys.rsaWithLeadingZeroModulus(),
				JsonWebKeySkipReason.MALFORMED_KEY, Algorithm.RS256, rsa));
		cases.put("a 31-octet EC x", new SkippedCase(TestJsonWebKeys.ecWithShortX(), JsonWebKeySkipReason.MALFORMED_KEY,
				Algorithm.ES256, TestJsonWebKeys.ecKeyPairWithLeadingZeroX().getPrivate()));
		cases.put("an EC point off the curve", new SkippedCase(TestJsonWebKeys.ecOffCurve(),
				JsonWebKeySkipReason.EC_POINT_NOT_ON_CURVE, Algorithm.ES256, Fixture.IDP_SIGNING_EC_P256.getPrivateKey()));
		cases.put("a non-canonical Ed25519 y (p + 1)", new SkippedCase(TestJsonWebKeys.ed25519WithX(
				TestJsonWebKeys.ed25519PublicKeyEncoding(ED25519_P.add(BigInteger.ONE), false)),
				JsonWebKeySkipReason.MALFORMED_KEY, Algorithm.EDDSA, Fixture.ED25519.getPrivateKey()));
		cases.put("an Ed25519 x that does not decode (y = 2)", new SkippedCase(TestJsonWebKeys.ed25519WithX(
				TestJsonWebKeys.ed25519PublicKeyEncoding(BigInteger.TWO, false)), JsonWebKeySkipReason.MALFORMED_KEY,
				Algorithm.EDDSA, Fixture.ED25519.getPrivateKey()));
		cases.put("x = 0 with the sign bit set (y = 1)", new SkippedCase(TestJsonWebKeys.ed25519WithX(
				TestJsonWebKeys.ed25519PublicKeyEncoding(BigInteger.ONE, true)), JsonWebKeySkipReason.MALFORMED_KEY,
				Algorithm.EDDSA, Fixture.ED25519.getPrivateKey()));
		cases.put("x = 0 with the sign bit set (y = p - 1)", new SkippedCase(TestJsonWebKeys.ed25519WithX(
				TestJsonWebKeys.ed25519PublicKeyEncoding(ED25519_P.subtract(BigInteger.ONE), true)),
				JsonWebKeySkipReason.MALFORMED_KEY, Algorithm.EDDSA, Fixture.ED25519.getPrivateKey()));
		cases.put("an Ed448 key", new SkippedCase(TestJsonWebKeys.withKeyPair(KeyPairGenerator.getInstance("Ed448")
				.generateKeyPair()), JsonWebKeySkipReason.UNSUPPORTED_CURVE, Algorithm.EDDSA, Fixture.ED25519.getPrivateKey()));
		cases.put("an X25519 key", new SkippedCase(TestJsonWebKeys.withKeyPair(KeyPairGenerator.getInstance("X25519")
				.generateKeyPair()), JsonWebKeySkipReason.UNSUPPORTED_CURVE, Algorithm.EDDSA, Fixture.ED25519.getPrivateKey()));
		for (String issuer : List.of("null", "123", "[]", "\"\""))
			cases.put("an issuer member of " + issuer, new SkippedCase(TestJsonWebKeys.withFixture(
					Fixture.IDP_SIGNING_RSA_2048).member("issuer", issuer), JsonWebKeySkipReason.MALFORMED_KEY, Algorithm.RS256,
					rsa));
		cases.put("private members", new SkippedCase(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048)
				.includePrivateMembers(true), JsonWebKeySkipReason.PRIVATE_KEY_MEMBERS, Algorithm.RS256, rsa));
		cases.put("a symmetric key", new SkippedCase(TestJsonWebKeys.octWithK(TestJws.base64Url(new byte[32])),
				JsonWebKeySkipReason.SYMMETRIC_KEY, Algorithm.RS256, rsa));
		cases.put("use enc", new SkippedCase(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).use("enc"),
				JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY, Algorithm.RS256, rsa));
		cases.put("key_ops [encrypt]", new SkippedCase(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048)
				.keyOps(List.of("encrypt")), JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY, Algorithm.RS256, rsa));
		cases.put("use sig with key_ops [encrypt]", new SkippedCase(TestJsonWebKeys.withFixture(
				Fixture.IDP_SIGNING_RSA_2048).use("sig").keyOps(List.of("encrypt")),
				JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY, Algorithm.RS256, rsa));
		cases.put("an x5c for another key", new SkippedCase(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048)
				.x5c(List.of(Fixture.SP_SIGNING_RSA_2048.getCertificate().orElseThrow())),
				JsonWebKeySkipReason.CERTIFICATE_MISMATCH, Algorithm.RS256, rsa));

		return cases.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () -> {
			SkippedCase example = entry.getValue();
			String keySet = TestJsonWebKeys.keySet(List.of(example.jwk().kid(BAD_KID).toJson(),
					TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P384).kid("good").toJson()));

			ParsedKeySet parsed = JwkSetParser.parse(keySet, 256 * 1_024, 100);
			Assertions.assertEquals(List.of(new ParsedKeySet.Skip(0, example.reason())), parsed.skips());
			Assertions.assertEquals(List.of("good"), JsonWebKeySet.fromJson(keySet).getKeys().stream().map(key ->
					key.getKeyId().orElseThrow()).toList());

			JwtValidator validator = JwtFixtures.validator(StaticJsonWebKeySource.fromJsonWebKeySet(
					JsonWebKeySet.fromJson(keySet))).allowedAlgorithms(Set.of(jwsAlgorithm(example.algorithm()))).build();
			JwtFixtures.assertRejected(JoseException.Reason.UNKNOWN_KEY, validator, TestJws.withAlgorithm(
					example.algorithm()).kid(BAD_KID).payload(JwtFixtures.claims().toJson()).sign(example.signer()));
		}));
	}

	// M2-7: the Ed25519 identity key admits the forgery R = identity, S = 0 for every message, so it is skipped as
	// WEAK_KEY and the forgery naming it is UNKNOWN_KEY; kid-less, it finds no candidate either.
	@Test
	void theSmallOrderForgeryNeverVerifies() {
		String keySet = TestJsonWebKeys.keySet(List.of(TestJsonWebKeys.ed25519SmallOrder().kid(BAD_KID).toJson(),
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P384).kid("good").toJson()));
		byte[] forgery = new byte[64];
		forgery[0] = 1;

		JwtValidator validator = JwtFixtures.validator(StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(
				keySet))).allowedAlgorithms(Set.of(JwsAlgorithm.EDDSA, JwsAlgorithm.ED25519)).build();
		JwtFixtures.assertRejected(JoseException.Reason.UNKNOWN_KEY, validator, JwtFixtures.token(Algorithm.EDDSA)
				.kid(BAD_KID).withSignature(forgery));
		JwtFixtures.assertRejected(JoseException.Reason.UNKNOWN_KEY, validator, TestJws.withAlgorithm(Algorithm.ED25519)
				.payload(JwtFixtures.claims().toJson()).withSignature(forgery));
	}

	// An RSA key below 2,048 bits is skipped (RSA_KEY_SIZE). Its own 128-octet signature is SIGNATURE_MALFORMED
	// before key resolution (M2-6's 256 to 2,048-octet bound), and a well-formed token naming its kid is UNKNOWN_KEY.
	@Test
	void anRsa1024KeyIsSkippedAndItsTokensNeverReachIt() throws Exception {
		String keySet = TestJsonWebKeys.keySet(List.of(TestJsonWebKeys.withFixture(Fixture.NEGATIVE_RSA_1024).kid(BAD_KID)
				.toJson(), JwtFixtures.jwk(Fixture.IDP_SIGNING_RSA_2048).toJson()));
		Assertions.assertEquals(List.of(new ParsedKeySet.Skip(0, JsonWebKeySkipReason.RSA_KEY_SIZE)), parse(keySet)
				.skips());
		JwtValidator validator = JwtFixtures.validator(StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(
				keySet))).build();

		JwtFixtures.assertRejected(JoseException.Reason.SIGNATURE_MALFORMED, validator, TestJws.withAlgorithm(
				Algorithm.RS256).kid(BAD_KID).payload(JwtFixtures.claims().toJson()).sign(
				Fixture.NEGATIVE_RSA_1024.getPrivateKey()));
		JwtFixtures.assertRejected(JoseException.Reason.UNKNOWN_KEY, validator, TestJws.withAlgorithm(Algorithm.RS256)
				.kid(BAD_KID).payload(JwtFixtures.claims().toJson()).sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
	}

	// Exit criterion 7 with Wycheproof's own keys (json_web_key_test.json): tcId 7's ROCA key is WEAK_KEY, tcId 8's
	// RSA-1024 key RSA_KEY_SIZE, tcId 9's e = 1 key RSA_EXPONENT and tcId 22's point EC_POINT_NOT_ON_CURVE, and
	// each tcId's token is refused: UNKNOWN_KEY, or SIGNATURE_MALFORMED for tcId 8's 128-octet signature.
	@TestFactory
	Stream<DynamicTest> wycheproofsInvalidKeysAreSkippedAndTheirTokensRefused() {
		VectorFile file = WycheproofVectors.fromVendoredFiles().getFile("json_web_key_test.json");
		Map<Integer, List<Object>> expected = new LinkedHashMap<>();
		expected.put(7, List.of(JsonWebKeySkipReason.WEAK_KEY, JoseException.Reason.UNKNOWN_KEY));
		expected.put(8, List.of(JsonWebKeySkipReason.RSA_KEY_SIZE, JoseException.Reason.SIGNATURE_MALFORMED));
		expected.put(9, List.of(JsonWebKeySkipReason.RSA_EXPONENT, JoseException.Reason.UNKNOWN_KEY));
		expected.put(22, List.of(JsonWebKeySkipReason.EC_POINT_NOT_ON_CURVE, JoseException.Reason.UNKNOWN_KEY));

		return expected.entrySet().stream().map(entry -> DynamicTest.dynamicTest("tcId " + entry.getKey(), () -> {
			WycheproofVectors.TestVector vector = file.getTest(entry.getKey());
			Assertions.assertEquals(WycheproofVectors.Result.INVALID, vector.getResult());
			String publicKeys = vector.getGroup().getObject("public").toJson();
			List<ParsedKeySet.Skip> skips = parse(publicKeys).skips();
			Assertions.assertFalse(skips.isEmpty());
			for (ParsedKeySet.Skip skip : skips)
				Assertions.assertEquals(entry.getValue().get(0), skip.reason());

			List<String> keys = new ArrayList<>();
			for (JsonValue key : ((JsonArray) vector.getGroup().getObject("public")
					.find("keys").orElseThrow()).getElements())
				keys.add(key.toJson());
			keys.add(JwtFixtures.jwk(Fixture.IDP_SIGNING_EC_P384).kid("good").toJson());
			JwtValidator validator = JwtFixtures.validator(StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(
					TestJsonWebKeys.keySet(keys)))).allowedAlgorithms(Set.of(JwsAlgorithm.RS256, JwsAlgorithm.ES256)).build();
			JwtFixtures.assertRejected((JoseException.Reason) entry.getValue().get(1), validator, vector.getString("jws"));
		}));
	}

	// INV-J9 (Wycheproof JWK tcId 4): two fitting keys with one kid are AMBIGUOUS_KEY, even though one of them signed
	// the token; the kid is compared exactly, so a key whose kid differs only in case is another key.
	@Test
	void aDuplicateKidIsAmbiguous() {
		JwtValidator duplicate = JwtFixtures.validator(JwtFixtures.source(JwtFixtures.jwk(Fixture.IDP_SIGNING_RSA_2048)
				.toJson(), JwtFixtures.jwk(Fixture.NEGATIVE_ATTACKER_RSA_2048).toJson())).build();
		JwtFixtures.assertRejected(JoseException.Reason.AMBIGUOUS_KEY, duplicate, JwtFixtures.signed(
				Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256));

		JwtValidator caseDistinct = JwtFixtures.validator(JwtFixtures.source(JwtFixtures.jwk(Fixture.IDP_SIGNING_RSA_2048)
				.toJson(), JwtFixtures.jwk(Fixture.NEGATIVE_ATTACKER_RSA_2048).kid(JwtFixtures.KID.toUpperCase(
				Locale.ROOT)).toJson())).build();
		JwtFixtures.assertAccepted(caseDistinct, JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256));

		// A shared kid is fine when only one of the keys fits the token's algorithm.
		JwtValidator mixed = JwtFixtures.validator(JwtFixtures.source(JwtFixtures.jwk(Fixture.IDP_SIGNING_RSA_2048)
				.toJson(), JwtFixtures.jwk(Fixture.IDP_SIGNING_EC_P256).toJson())).allowedAlgorithms(Set.of(
				JwsAlgorithm.RS256, JwsAlgorithm.ES256)).build();
		JwtFixtures.assertAccepted(mixed, JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256));
		JwtFixtures.assertAccepted(mixed, JwtFixtures.signed(Fixture.IDP_SIGNING_EC_P256, Algorithm.ES256));
	}

	// OpenID Connect Core section 10.1: a token without kid is verified by the one candidate key; with two candidates
	// it is AMBIGUOUS_KEY, never "try each", and with none UNKNOWN_KEY.
	@Test
	void aTokenWithoutKidNeedsExactlyOneCandidate() {
		String token = TestJws.withAlgorithm(Algorithm.RS256).payload(JwtFixtures.claims().toJson()).sign(
				Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());

		JwtFixtures.assertAccepted(JwtFixtures.validator(JwtFixtures.source(JwtFixtures.jwk(Fixture.IDP_SIGNING_RSA_2048)
				.toJson(), JwtFixtures.jwk(Fixture.IDP_SIGNING_EC_P256).kid("ec").toJson())).build(), token);
		JwtFixtures.assertRejected(JoseException.Reason.AMBIGUOUS_KEY, JwtFixtures.validator(JwtFixtures.source(
				JwtFixtures.jwk(Fixture.IDP_SIGNING_RSA_2048).toJson(), JwtFixtures.jwk(Fixture.NEGATIVE_ATTACKER_RSA_2048)
						.kid("other").toJson())).build(), token);
		JwtFixtures.assertRejected(JoseException.Reason.UNKNOWN_KEY, JwtFixtures.validator(JwtFixtures.source(
				Fixture.IDP_SIGNING_EC_P256)).build(), token);
	}

	// Plan "Key selection" (RFC 7517 section 4.5): a token that names a kid is verified only by a key with exactly that
	// kid, so a key set whose only key has no kid refuses it as UNKNOWN_KEY, even though that key signed it; the same
	// key verifies the token without a kid.
	@Test
	void aTokenWithAKidIsNeverVerifiedByAKeyWithoutOne() {
		JwtValidator validator = JwtFixtures.validator(JwtFixtures.source(TestJsonWebKeys.withFixture(
				Fixture.IDP_SIGNING_RSA_2048).toJson())).build();

		JwtFixtures.assertRejected(JoseException.Reason.UNKNOWN_KEY, validator, JwtFixtures.signed(
				Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256));
		JwtFixtures.assertAccepted(validator, TestJws.withAlgorithm(Algorithm.RS256).payload(JwtFixtures.claims()
				.toJson()).sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
	}

	// G8-2 and INV-J3 (exit criterion 10): an RSA key without alg verifies RS256 under {RS256}; under {RS256, PS256}
	// it fits neither, so RS256 and PS256 tokens naming it are KEY_ALGORITHM_MISMATCH (never a refresh), and a
	// kid-less token finds no candidate. A key that names its alg keeps working.
	@Test
	void anRsaKeyWithoutAlgServesOnlyALoneRsaAlgorithm() {
		StaticJsonWebKeySource bare = JwtFixtures.source(Fixture.IDP_SIGNING_RSA_2048);
		JwtFixtures.assertAccepted(JwtFixtures.validator(bare).build(), JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048,
				Algorithm.RS256));
		JwtFixtures.assertAccepted(JwtFixtures.validator(bare).allowedAlgorithms(Set.of(JwsAlgorithm.PS256,
				JwsAlgorithm.ES256)).build(), JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.PS256));

		JwtValidator two = JwtFixtures.validator(bare).allowedAlgorithms(Set.of(JwsAlgorithm.RS256, JwsAlgorithm.PS256))
				.build();
		JwtFixtures.assertRejected(JoseException.Reason.KEY_ALGORITHM_MISMATCH, two, JwtFixtures.signed(
				Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256));
		JwtFixtures.assertRejected(JoseException.Reason.KEY_ALGORITHM_MISMATCH, two, JwtFixtures.signed(
				Fixture.IDP_SIGNING_RSA_2048, Algorithm.PS256));
		JwtFixtures.assertRejected(JoseException.Reason.UNKNOWN_KEY, two, TestJws.withAlgorithm(Algorithm.RS256)
				.payload(JwtFixtures.claims().toJson()).sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));

		JwtValidator named = JwtFixtures.validator(JwtFixtures.source(JwtFixtures.jwk(Fixture.IDP_SIGNING_RSA_2048)
				.alg("PS256").toJson())).allowedAlgorithms(Set.of(JwsAlgorithm.RS256, JwsAlgorithm.PS256)).build();
		JwtFixtures.assertAccepted(named, JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.PS256));
	}

	// INV-J9: during a rotation each key verifies only its own tokens. A token signed by the new key but naming the
	// old key's kid is SIGNATURE_MISMATCH: the one selected key is tried, and a failure never falls back to another.
	// A key of another size is SIGNATURE_MALFORMED, and another issuer's key is UNKNOWN_KEY.
	@Test
	void aFailedSignatureNeverFallsBackToAnotherKey() {
		JwtValidator rotating = JwtFixtures.validator(JwtFixtures.source(JwtFixtures.jwk(Fixture.IDP_SIGNING_RSA_2048)
				.kid("old").toJson(), JwtFixtures.jwk(Fixture.SP_SIGNING_RSA_2048).kid("new").toJson(),
				JwtFixtures.jwk(Fixture.IDP_SIGNING_RSA_3072).kid("big").toJson())).build();

		JwtFixtures.assertAccepted(rotating, JwtFixtures.token(Algorithm.RS256).kid("old").sign(
				Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
		JwtFixtures.assertAccepted(rotating, JwtFixtures.token(Algorithm.RS256).kid("new").sign(
				Fixture.SP_SIGNING_RSA_2048.getPrivateKey()));
		JwtFixtures.assertRejected(JoseException.Reason.SIGNATURE_MISMATCH, rotating, JwtFixtures.token(Algorithm.RS256)
				.kid("old").sign(Fixture.SP_SIGNING_RSA_2048.getPrivateKey()));
		JwtFixtures.assertRejected(JoseException.Reason.SIGNATURE_MALFORMED, rotating, JwtFixtures.token(Algorithm.RS256)
				.kid("big").sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
		JwtFixtures.assertRejected(JoseException.Reason.UNKNOWN_KEY, rotating, JwtFixtures.token(Algorithm.RS256)
				.kid("another-issuers-key").sign(Fixture.NEGATIVE_ATTACKER_RSA_2048.getPrivateKey()));
	}

	private static ParsedKeySet parse(String keySet) throws Exception {
		return JwkSetParser.parse(keySet, 256 * 1_024, 100);
	}

	private static JwsAlgorithm jwsAlgorithm(Algorithm algorithm) {
		return JwsAlgorithm.findByWireValue(algorithm.getWireValue()).orElseThrow();
	}

	private record SkippedCase(TestJsonWebKeys.Builder jwk, JsonWebKeySkipReason reason, Algorithm algorithm,
														 PrivateKey signer) {
	}
}
