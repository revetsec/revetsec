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

import com.revetsec.internal.crypto.VerifyResult;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.jose.JwsVerifier;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws;
import com.revetsec.testing.TestJws.Algorithm;
import com.revetsec.testing.TestJws.Variant;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;

/**
 * {@link JwtValidator} on the signature's shape (plan M2 exit criterion 6, static half; M2-6 step 5; G8-3; RFC 7518
 * sections 3.3 to 3.5; RFC 8037 section 3.1; CVE-2022-21449): a malformed signature is
 * {@link JoseException.Reason#SIGNATURE_MALFORMED} before any key is resolved, so a token whose {@code kid} no key has
 * still gets that reason and never {@link JoseException.Reason#UNKNOWN_KEY}; the internal engine reports why, as
 * {@link VerifyResult#OUT_OF_RANGE} or {@link VerifyResult#WRONG_LENGTH}. The exact RSA length (the key's modulus
 * length) is checked once the key is known.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JwtValidatorSignatureShapeTests {
	// In enum order, so the dynamic tests built from it have the same order and numbering in every JVM.
	private static final Map<Algorithm, Fixture> EC = Collections.unmodifiableMap(new EnumMap<>(Map.of(
			Algorithm.ES256, Fixture.IDP_SIGNING_EC_P256, Algorithm.ES384, Fixture.IDP_SIGNING_EC_P384, Algorithm.ES512,
			Fixture.IDP_SIGNING_EC_P521)));

	// CVE-2022-21449 (exit criterion 6): r = 0, s = 0, r = n, s = n, r = n + 1 and an all-zero signature are
	// SIGNATURE_MALFORMED before the key is resolved, and the internal engine reports OUT_OF_RANGE.
	@TestFactory
	Stream<DynamicTest> ecdsaValuesOutsideTheOrderAreMalformedBeforeKeyResolution() {
		List<DynamicTest> tests = new ArrayList<>();
		for (Algorithm algorithm : List.of(Algorithm.ES256, Algorithm.ES384, Algorithm.ES512))
			for (Variant variant : List.of(Variant.R_ZERO, Variant.S_ZERO, Variant.R_EQUALS_ORDER, Variant.S_EQUALS_ORDER,
					Variant.R_ORDER_PLUS_ONE, Variant.ZERO_SIGNATURE))
				tests.add(DynamicTest.dynamicTest(algorithm + " " + variant, () -> assertMalformedBeforeKeyResolution(
						algorithm, requireNonNull(EC.get(algorithm)), variant, VerifyResult.OUT_OF_RANGE)));
		return tests.stream();
	}

	// RFC 7518 section 3.4 and G8-3 (exit criterion 1's DER fixture): an ECDSA signature of the wrong length, the
	// DER encoding an IdP might send included, one octet short or long, or empty, is SIGNATURE_MALFORMED before key
	// resolution, with WRONG_LENGTH.
	@TestFactory
	Stream<DynamicTest> ecdsaSignaturesOfTheWrongLengthAreMalformed() {
		List<DynamicTest> tests = new ArrayList<>();
		for (Algorithm algorithm : List.of(Algorithm.ES256, Algorithm.ES384, Algorithm.ES512))
			for (Variant variant : List.of(Variant.DER_SIGNATURE, Variant.ONE_OCTET_SHORT, Variant.ONE_OCTET_LONG,
					Variant.EMPTY_SIGNATURE))
				tests.add(DynamicTest.dynamicTest(algorithm + " " + variant, () -> assertMalformedBeforeKeyResolution(
						algorithm, requireNonNull(EC.get(algorithm)), variant, VerifyResult.WRONG_LENGTH)));
		return tests.stream();
	}

	// RFC 7518 section 3.4 and G8-3 (exit criterion 1's DER fixture): an ES256 signature DER-encoded, the interop fault
	// an operator must tell apart from a forgery, is 6 + |r| + |s| octets, where |r| and |s| are the minimal
	// two's-complement lengths: usually 70 to 72, and fewer about once in 256 signatures, when r or s is below 2^247.
	// At every length it is SIGNATURE_MALFORMED, before key resolution. The fixed fixtures below give 72, 71, 70 and
	// 69 octets whatever a signature's random values are.
	@Test
	void aDerEncodedEs256SignatureIsMalformedAtEveryLength() throws Exception {
		JwtValidator validator = JwtFixtures.validator(Fixture.IDP_SIGNING_EC_P256, JwsAlgorithm.ES256);
		TestJws.Signed signed = JwtFixtures.token(Algorithm.ES256).signed(Fixture.IDP_SIGNING_EC_P256.getPrivateKey());
		byte[] signature = signed.getSignature();
		String der = signed.withVariant(Variant.DER_SIGNATURE);
		byte[] encoded = Base64Url.decode(der.substring(der.lastIndexOf('.') + 1));

		Assertions.assertEquals(0x30, encoded[0]);
		Assertions.assertEquals(6 + TestJws.ecdsaR(signature).toByteArray().length
				+ TestJws.ecdsaS(signature).toByteArray().length, encoded.length);
		JwtFixtures.assertRejected(JoseException.Reason.SIGNATURE_MALFORMED, validator, der);

		// A top bit set needs a sign octet (33 octets in DER); a value below 2^247 needs only 31.
		BigInteger topBitSet = BigInteger.ONE.shiftLeft(255).add(BigInteger.ONE);
		BigInteger topBitClear = BigInteger.ONE.shiftLeft(254).add(BigInteger.ONE);
		BigInteger small = BigInteger.ONE.shiftLeft(246).add(BigInteger.ONE);
		Map<Integer, BigInteger[]> fixtures = new LinkedHashMap<>();
		fixtures.put(72, new BigInteger[]{topBitSet, topBitSet});
		fixtures.put(71, new BigInteger[]{topBitSet, topBitClear});
		fixtures.put(70, new BigInteger[]{topBitClear, topBitClear});
		fixtures.put(69, new BigInteger[]{small, topBitClear});

		for (Map.Entry<Integer, BigInteger[]> fixture : fixtures.entrySet()) {
			byte[] fixed = TestJws.derEncodedEcdsaSignature(TestJws.ecdsaSignature(fixture.getValue()[0],
					fixture.getValue()[1], 32));
			Assertions.assertEquals(fixture.getKey(), fixed.length);
			JwtFixtures.assertRejected(JoseException.Reason.SIGNATURE_MALFORMED, validator, JwtFixtures.token(
					Algorithm.ES256).kid("unknown-kid").withSignature(fixed));
			Assertions.assertEquals(VerifyResult.WRONG_LENGTH, JwsVerifier.findShapeFailure(JwsAlgorithm.ES256, fixed)
					.orElseThrow());
		}
	}

	// RFC 8037 section 3.1: an Ed25519 or EdDSA signature must be exactly 64 octets; 63, 65 (which the JDK 17 engine
	// alone accepts, Wycheproof Ed25519 tcId 37) and 0 are SIGNATURE_MALFORMED before key resolution.
	@TestFactory
	Stream<DynamicTest> ed25519SignaturesMustBeSixtyFourOctets() {
		return Stream.of(Algorithm.ED25519, Algorithm.EDDSA).flatMap(algorithm -> Stream.of(Variant.ONE_OCTET_SHORT,
				Variant.ONE_OCTET_LONG, Variant.EMPTY_SIGNATURE).map(variant -> DynamicTest.dynamicTest(algorithm + " "
				+ variant, () -> assertMalformedBeforeKeyResolution(algorithm, Fixture.ED25519, variant,
				VerifyResult.WRONG_LENGTH))));
	}

	// M2-6 (exit criterion 6): an RS256 or PS256 signature of 0, 1, 255 or 2,049 octets is outside every modulus
	// length the key policy allows, so it is SIGNATURE_MALFORMED before key resolution, with WRONG_LENGTH, and a
	// garbage signature never reaches a key set.
	@TestFactory
	Stream<DynamicTest> rsaSignaturesOutsideTheModulusBoundAreMalformedBeforeKeyResolution() {
		return Stream.of(Algorithm.RS256, Algorithm.PS256, Algorithm.RS512, Algorithm.PS384).flatMap(algorithm -> Stream.of(
				0, 1, 255, 2_049).map(length -> DynamicTest.dynamicTest(algorithm + " " + length + " octets", () -> {
			String token = JwtFixtures.token(algorithm).kid("unknown-kid").withSignature(new byte[length]);
			JwtFixtures.assertRejected(JoseException.Reason.SIGNATURE_MALFORMED, validator(Fixture.IDP_SIGNING_RSA_2048,
					algorithm), token);
			Assertions.assertEquals(VerifyResult.WRONG_LENGTH, JwsVerifier.findShapeFailure(jwsAlgorithm(algorithm),
					new byte[length]).orElseThrow());
		})));
	}

	// Step 7: within the bound, an RSA signature must be exactly as long as the key's modulus: 256 octets for a 3,072-bit
	// key, or 384 octets for a 2,048-bit key, are SIGNATURE_MALFORMED once the key is known.
	@Test
	void anRsaSignatureMustMatchTheModulusLengthOfItsKey() {
		JwtValidator rsa3072 = JwtFixtures.validator(Fixture.IDP_SIGNING_RSA_3072, JwsAlgorithm.RS256);
		JwtFixtures.assertRejected(JoseException.Reason.SIGNATURE_MALFORMED, rsa3072, JwtFixtures.token(Algorithm.RS256)
				.withSignature(new byte[256]));
		JwtFixtures.assertAccepted(rsa3072, JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_3072, Algorithm.RS256));

		JwtValidator rsa2048 = JwtFixtures.validator(Fixture.IDP_SIGNING_RSA_2048, JwsAlgorithm.PS256);
		JwtFixtures.assertRejected(JoseException.Reason.SIGNATURE_MALFORMED, rsa2048, JwtFixtures.token(Algorithm.PS256)
				.withSignature(new byte[384]));
		// With an unknown kid the same in-bound signature reaches key resolution.
		JwtFixtures.assertRejected(JoseException.Reason.UNKNOWN_KEY, rsa2048, JwtFixtures.token(Algorithm.PS256)
				.kid("unknown-kid").withSignature(new byte[384]));
	}

	// A signature of the right shape but the wrong value is SIGNATURE_MISMATCH, for every algorithm (tri-state safe:
	// the JCA's false is never success).
	@TestFactory
	Stream<DynamicTest> aFlippedBitIsASignatureMismatchForEveryAlgorithm() {
		Map<Algorithm, Fixture> fixtures = new LinkedHashMap<>(EC);
		fixtures.put(Algorithm.RS256, Fixture.IDP_SIGNING_RSA_2048);
		fixtures.put(Algorithm.RS384, Fixture.IDP_SIGNING_RSA_3072);
		fixtures.put(Algorithm.RS512, Fixture.IDP_SIGNING_RSA_2048);
		fixtures.put(Algorithm.PS256, Fixture.IDP_SIGNING_RSA_2048);
		fixtures.put(Algorithm.PS384, Fixture.IDP_SIGNING_RSA_2048);
		fixtures.put(Algorithm.PS512, Fixture.IDP_SIGNING_RSA_3072);
		fixtures.put(Algorithm.ED25519, Fixture.ED25519);
		fixtures.put(Algorithm.EDDSA, Fixture.ED25519);

		return fixtures.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey().getWireValue(), () -> {
			JwtValidator validator = validator(entry.getValue(), entry.getKey());
			TestJws.Signed signed = JwtFixtures.token(entry.getKey()).signed(entry.getValue().getPrivateKey());
			JwtFixtures.assertAccepted(validator, signed.toCompactSerialization());
			JwtFixtures.assertRejected(JoseException.Reason.SIGNATURE_MISMATCH, validator, signed.withVariant(
					Variant.FLIPPED_BIT));
		}));
	}

	// ECDSA signatures are malleable: with s replaced by n - s the signature still verifies on the JDK, so a
	// signature's bytes never identify a token (no cache may key on them).
	@TestFactory
	Stream<DynamicTest> ecdsaSignaturesAreMalleableInS() {
		return EC.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey().getWireValue(), () -> {
			TestJws.Signed signed = JwtFixtures.token(entry.getKey()).signed(entry.getValue().getPrivateKey());
			byte[] signature = signed.getSignature();
			BigInteger order = TestJws.curveOrder(entry.getKey());
			byte[] highS = TestJws.ecdsaSignature(TestJws.ecdsaR(signature), order.subtract(TestJws.ecdsaS(signature)),
					signature.length / 2);

			JwtValidator validator = validator(entry.getValue(), entry.getKey());
			Jwt original = JwtFixtures.assertAccepted(validator, signed.toCompactSerialization());
			Jwt malleated = JwtFixtures.assertAccepted(validator, signed.withSignature(highS));
			Assertions.assertNotEquals(original.toCompactSerialization(), malleated.toCompactSerialization());
		}));
	}

	private static void assertMalformedBeforeKeyResolution(Algorithm algorithm,
																												 Fixture fixture,
																												 Variant variant,
																												 VerifyResult engineResult) throws Exception {
		JwtValidator validator = validator(fixture, algorithm);
		TestJws.Signed known = JwtFixtures.token(algorithm).signed(fixture.getPrivateKey());
		TestJws.Signed unknown = JwtFixtures.token(algorithm).kid("unknown-kid").signed(fixture.getPrivateKey());

		JwtFixtures.assertAccepted(validator, known.toCompactSerialization());
		JwtFixtures.assertRejected(JoseException.Reason.SIGNATURE_MALFORMED, validator, known.withVariant(variant));
		JwtFixtures.assertRejected(JoseException.Reason.SIGNATURE_MALFORMED, validator, unknown.withVariant(variant));
		JwtFixtures.assertRejected(JoseException.Reason.UNKNOWN_KEY, validator, unknown.toCompactSerialization());

		String token = unknown.withVariant(variant);
		byte[] signature = Base64Url.decode(token.substring(token.lastIndexOf('.') + 1));
		Assertions.assertEquals(engineResult, JwsVerifier.findShapeFailure(jwsAlgorithm(algorithm), signature)
				.orElseThrow());
	}

	private static JwtValidator validator(Fixture fixture,
																				Algorithm algorithm) {
		return JwtFixtures.validator(fixture, jwsAlgorithm(algorithm));
	}

	private static JwsAlgorithm jwsAlgorithm(Algorithm algorithm) {
		return JwsAlgorithm.findByWireValue(algorithm.getWireValue()).orElseThrow();
	}
}
