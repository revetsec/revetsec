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

import com.revetsec.internal.crypto.EcCurve;
import com.revetsec.internal.crypto.HashAlgorithm;
import com.revetsec.jose.JwsAlgorithm;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

/**
 * {@link Algorithms}: each {@link JwsAlgorithm}'s family, key type, curve, hash and fixed signature length as RFC 7518
 * section 3.1, RFC 8037 section 3.1 and RFC 9864 define them, transcribed here as an independent table, and the one
 * RSA algorithm an RSA key without {@code alg} may serve (G8-2).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class AlgorithmsTests {
	/**
	 * One row per algorithm: family, kty, crv, curve, hash, and signature length in octets (RSA: the modulus length,
	 * so none fixed).
	 */
	private static final List<Row> TABLE = List.of(
			new Row(JwsAlgorithm.RS256, Algorithms.Family.RSA_PKCS1, "RSA", null, null, HashAlgorithm.SHA_256, null),
			new Row(JwsAlgorithm.RS384, Algorithms.Family.RSA_PKCS1, "RSA", null, null, HashAlgorithm.SHA_384, null),
			new Row(JwsAlgorithm.RS512, Algorithms.Family.RSA_PKCS1, "RSA", null, null, HashAlgorithm.SHA_512, null),
			new Row(JwsAlgorithm.PS256, Algorithms.Family.RSA_PSS, "RSA", null, null, HashAlgorithm.SHA_256, null),
			new Row(JwsAlgorithm.PS384, Algorithms.Family.RSA_PSS, "RSA", null, null, HashAlgorithm.SHA_384, null),
			new Row(JwsAlgorithm.PS512, Algorithms.Family.RSA_PSS, "RSA", null, null, HashAlgorithm.SHA_512, null),
			new Row(JwsAlgorithm.ES256, Algorithms.Family.ECDSA, "EC", "P-256", EcCurve.P_256, HashAlgorithm.SHA_256, 64),
			new Row(JwsAlgorithm.ES384, Algorithms.Family.ECDSA, "EC", "P-384", EcCurve.P_384, HashAlgorithm.SHA_384, 96),
			new Row(JwsAlgorithm.ES512, Algorithms.Family.ECDSA, "EC", "P-521", EcCurve.P_521, HashAlgorithm.SHA_512, 132),
			new Row(JwsAlgorithm.ED25519, Algorithms.Family.EDDSA, "OKP", "Ed25519", null, null, 64),
			new Row(JwsAlgorithm.EDDSA, Algorithms.Family.EDDSA, "OKP", "Ed25519", null, null, 64),
			new Row(JwsAlgorithm.HS256, Algorithms.Family.HMAC, "oct", null, null, HashAlgorithm.SHA_256, 32),
			new Row(JwsAlgorithm.HS384, Algorithms.Family.HMAC, "oct", null, null, HashAlgorithm.SHA_384, 48),
			new Row(JwsAlgorithm.HS512, Algorithms.Family.HMAC, "oct", null, null, HashAlgorithm.SHA_512, 64));

	// RFC 7518 section 3.1, RFC 8037 section 3.1 and RFC 9864: the table covers every constant, and each answer matches.
	@TestFactory
	Stream<DynamicTest> everyAlgorithmMapsToItsFamilyKeyTypeCurveHashAndLength() {
		Assertions.assertEquals(List.of(JwsAlgorithm.values()), TABLE.stream().map(Row::algorithm).toList());

		return TABLE.stream().map(row -> DynamicTest.dynamicTest(row.algorithm().getWireValue(), () -> {
			JwsAlgorithm algorithm = row.algorithm();
			Assertions.assertEquals(row.family(), Algorithms.familyOf(algorithm));
			Assertions.assertEquals(row.keyType(), Algorithms.keyTypeOf(algorithm));
			Assertions.assertEquals(Optional.ofNullable(row.curveName()), Algorithms.findCurveName(algorithm));
			Assertions.assertEquals(Optional.ofNullable(row.curve()), Algorithms.findEcCurve(algorithm));
			Assertions.assertEquals(Optional.ofNullable(row.hash()), Algorithms.findHash(algorithm));
			Assertions.assertEquals(Optional.ofNullable(row.signatureLength()), Algorithms.findSignatureLength(algorithm));
			Assertions.assertEquals(row.family() == Algorithms.Family.RSA_PKCS1 || row.family() == Algorithms.Family.RSA_PSS,
					Algorithms.isRsa(algorithm));
		}));
	}

	// G8-2: an RSA key without alg serves the effective set's RSA algorithm only when the set holds exactly one.
	@Test
	void theSoleRsaAlgorithmExistsOnlyWhenTheSetHoldsExactlyOne() {
		Assertions.assertEquals(Optional.empty(), Algorithms.findSoleRsaAlgorithm(Set.of()));
		Assertions.assertEquals(Optional.empty(), Algorithms.findSoleRsaAlgorithm(Set.of(JwsAlgorithm.ES256,
				JwsAlgorithm.EDDSA, JwsAlgorithm.HS256)));
		Assertions.assertEquals(Optional.of(JwsAlgorithm.RS256), Algorithms.findSoleRsaAlgorithm(Set.of(
				JwsAlgorithm.RS256)));
		Assertions.assertEquals(Optional.of(JwsAlgorithm.PS512), Algorithms.findSoleRsaAlgorithm(Set.of(
				JwsAlgorithm.PS512, JwsAlgorithm.ES256, JwsAlgorithm.ED25519, JwsAlgorithm.HS512)));
		Assertions.assertEquals(Optional.empty(), Algorithms.findSoleRsaAlgorithm(Set.of(JwsAlgorithm.RS256,
				JwsAlgorithm.PS256)));
		Assertions.assertEquals(Optional.empty(), Algorithms.findSoleRsaAlgorithm(EnumSet.allOf(JwsAlgorithm.class)));
	}

	private record Row(JwsAlgorithm algorithm, Algorithms.Family family, String keyType, @Nullable String curveName,
										 @Nullable EcCurve curve, @Nullable HashAlgorithm hash, @Nullable Integer signatureLength) {
	}
}
