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

package com.revetsec.internal.crypto;

import org.jspecify.annotations.NonNull;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.stream.Stream;

/**
 * {@link EcPublicKeys}: fixed-length coordinates (RFC 7518 section 6.2.1.2), the range and on-curve checks in
 * {@code BigInteger} before {@code KeyFactory} (INV-J5), the same checks for SPKI keys the JCA accepts off the curve
 * (plan section 8), and the INV-G1 inventory rows for EC key construction.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class EcPublicKeysTests {
	// A JDK key's fixed-length coordinates rebuild the same key, and it verifies the JDK's signature. P-521's 66-byte
	// coordinates always start with seven zero bits, so that curve always exercises leading zero octets.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> fixedLengthCoordinatesRebuildTheJdksKey() {
		return Stream.of(EcCurve.values()).map(curve -> DynamicTest.dynamicTest(curve.name(), () -> {
			EcdsaSignaturesTests.Fixture fixture = EcdsaSignaturesTests.Fixture.forCurve(curve);
			ECPublicKey jdkKey = (ECPublicKey) fixture.publicKey;
			byte[] x = EcdsaSignaturesTests.fixed(jdkKey.getW().getAffineX(), curve.getCoordinateLength());
			byte[] y = EcdsaSignaturesTests.fixed(jdkKey.getW().getAffineY(), curve.getCoordinateLength());
			byte[] xCopy = x.clone();

			ECPublicKey key = EcPublicKeys.fromCoordinates(curve, x, y);

			Assertions.assertArrayEquals(xCopy, x, "the coordinates are not modified");
			Assertions.assertEquals(jdkKey.getW(), key.getW());
			Assertions.assertTrue(curve.isDescribedBy(key.getParams()));
			Assertions.assertArrayEquals(jdkKey.getEncoded(), key.getEncoded(), "the same SPKI encoding");
			Assertions.assertEquals(VerifyResult.VALID, SignatureVerifier.verifyEcdsa(curve, fixture.hash, key,
					EcdsaSignaturesTests.MESSAGE, fixture.signature));
			EcPublicKeys.checkPublicKey(curve, key);
			EcPublicKeys.checkPublicKey(curve, jdkKey);
		}));
	}

	// RFC 7518 section 6.2.1.2: "The length of this octet string MUST be the full size of a coordinate for the curve",
	// so a 31-byte x (the form a producer that trims leading zero octets sends) and a zero-padded 33-byte x are
	// malformed, even when the value is on the curve.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> coordinatesOfAnyOtherLengthAreMalformed() {
		return Stream.of(EcCurve.values()).map(curve -> DynamicTest.dynamicTest(curve.name(), () -> {
			int length = curve.getCoordinateLength();
			ECPoint g = curve.getParameterSpec().getGenerator();
			byte[] x = EcdsaSignaturesTests.fixed(g.getAffineX(), length);
			byte[] y = EcdsaSignaturesTests.fixed(g.getAffineY(), length);

			assertRejected(KeyRejectedException.Kind.MALFORMED, curve, Arrays.copyOfRange(x, 1, length), y);
			assertRejected(KeyRejectedException.Kind.MALFORMED, curve, x, Arrays.copyOfRange(y, 1, length));
			assertRejected(KeyRejectedException.Kind.MALFORMED, curve, EcdsaSignaturesTests.concat(new byte[1], x), y);
			assertRejected(KeyRejectedException.Kind.MALFORMED, curve, x, EcdsaSignaturesTests.concat(new byte[1], y));
			assertRejected(KeyRejectedException.Kind.MALFORMED, curve, new byte[0], new byte[0]);
			assertRejected(KeyRejectedException.Kind.MALFORMED, curve, new byte[2 * length], new byte[0]);

			// Other curves' lengths are malformed before anything else is checked.
			for (EcCurve other : EcCurve.values())
				if (other.getCoordinateLength() != length)
					assertRejected(KeyRejectedException.Kind.MALFORMED, curve, new byte[other.getCoordinateLength()],
							new byte[other.getCoordinateLength()]);

			Assertions.assertEquals(g, EcPublicKeys.fromCoordinates(curve, x, y).getW());
		}));
	}

	// INV-J5: 0 <= x, y < p and y^2 = x^3 + a*x + b, in BigInteger, before KeyFactory (which accepts off-curve points).
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> pointsOffTheCurveOrOutsideTheFieldAreRefused() {
		return Stream.of(EcCurve.values()).map(curve -> DynamicTest.dynamicTest(curve.name(), () -> {
			int length = curve.getCoordinateLength();
			BigInteger p = curve.getFieldPrime();
			ECPoint g = curve.getParameterSpec().getGenerator();
			byte[] gx = EcdsaSignaturesTests.fixed(g.getAffineX(), length);
			byte[] gy = EcdsaSignaturesTests.fixed(g.getAffineY(), length);
			byte[] allOnes = new byte[length];
			Arrays.fill(allOnes, (byte) 0xff);

			assertRejected(KeyRejectedException.Kind.NOT_ON_CURVE, curve, gx,
					EcdsaSignaturesTests.fixed(g.getAffineY().add(BigInteger.ONE), length));
			assertRejected(KeyRejectedException.Kind.NOT_ON_CURVE, curve, new byte[length], new byte[length]);
			assertRejected(KeyRejectedException.Kind.NOT_ON_CURVE, curve, EcdsaSignaturesTests.fixed(p, length), gy);
			assertRejected(KeyRejectedException.Kind.NOT_ON_CURVE, curve, gx, EcdsaSignaturesTests.fixed(p, length));
			assertRejected(KeyRejectedException.Kind.NOT_ON_CURVE, curve, allOnes, gy);
			assertRejected(KeyRejectedException.Kind.NOT_ON_CURVE, curve, gx, allOnes);

			// The field bound at its edge: (0, sqrt(b)) is a point, and x = p, its residue, is not a field element.
			byte[] rootB = EcdsaSignaturesTests.fixed(EcCurveTests.squareRootOfB(curve), length);
			Assertions.assertEquals(BigInteger.ZERO, EcPublicKeys.fromCoordinates(curve, new byte[length], rootB).getW()
					.getAffineX(), "x = 0 is a field element");
			assertRejected(KeyRejectedException.Kind.NOT_ON_CURVE, curve, EcdsaSignaturesTests.fixed(p, length), rootB);

			// y + p is the same residue as y; it fits the fixed length only on P-521, whose prime has 521 bits.
			BigInteger yPlusP = g.getAffineY().add(p);
			if (yPlusP.bitLength() <= 8 * length)
				assertRejected(KeyRejectedException.Kind.NOT_ON_CURVE, curve, gx, EcdsaSignaturesTests.fixed(yPlusP, length));

			// The other curves' generators, at this curve's length where they fit, are not on this curve.
			for (EcCurve other : EcCurve.values()) {
				ECPoint otherG = other.getParameterSpec().getGenerator();
				if (other != curve && otherG.getAffineX().bitLength() <= 8 * length
						&& otherG.getAffineY().bitLength() <= 8 * length)
					assertRejected(KeyRejectedException.Kind.NOT_ON_CURVE, curve,
							EcdsaSignaturesTests.fixed(otherG.getAffineX(), length),
							EcdsaSignaturesTests.fixed(otherG.getAffineY(), length));
			}
		}));
	}

	// The JCA builds keys from off-curve SPKI encodings, so certificate and PEM keys get the same check (plan section
	// 8; the JCA builds the off-curve key below without complaint).
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> spkiKeysOffTheCurveAreRefused() {
		return Stream.of(EcCurve.values()).map(curve -> DynamicTest.dynamicTest(curve.name(), () -> {
			ECPublicKey jdkKey = (ECPublicKey) generate(curve).getPublic();
			byte[] encoded = jdkKey.getEncoded();
			// The SPKI ends with the uncompressed point's y-coordinate; changing its last byte moves y off the curve.
			encoded[encoded.length - 1] ^= 0x01;
			ECPublicKey offCurve = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(encoded));

			Assertions.assertFalse(curve.isOnCurve(offCurve.getW().getAffineX(), offCurve.getW().getAffineY()));
			Assertions.assertEquals(KeyRejectedException.Kind.NOT_ON_CURVE, Assertions.assertThrows(
					KeyRejectedException.class, () -> EcPublicKeys.checkPublicKey(curve, offCurve)).getKind());

			for (EcCurve other : EcCurve.values())
				if (other != curve)
					Assertions.assertEquals(KeyRejectedException.Kind.MALFORMED, Assertions.assertThrows(
									KeyRejectedException.class, () -> EcPublicKeys.checkPublicKey(other, jdkKey)).getKind(),
							other::name);
		}));
	}

	// A key implementation outside the JDK may report the point at infinity, no parameters, or throw; each is refused
	// with a checked exception (INV-G1).
	@Test
	void unusualKeyImplementationsAreRefusedWithoutAnUncheckedException() {
		EcCurve curve = EcCurve.P_256;
		ECParameterSpec parameters = curve.getParameterSpec();
		ECPoint g = parameters.getGenerator();

		assertCheckRejected(KeyRejectedException.Kind.NOT_ON_CURVE, new UnusualEcKey(parameters, ECPoint.POINT_INFINITY,
				false));
		assertCheckRejected(KeyRejectedException.Kind.NOT_ON_CURVE, new UnusualEcKey(parameters,
				new ECPoint(g.getAffineX().add(curve.getFieldPrime()), g.getAffineY()), false));
		assertCheckRejected(KeyRejectedException.Kind.MALFORMED, new UnusualEcKey(null, g, false));
		assertCheckRejected(KeyRejectedException.Kind.MALFORMED, new UnusualEcKey(parameters, null, false));
		assertCheckRejected(KeyRejectedException.Kind.MALFORMED, new UnusualEcKey(parameters, g, true));
		assertCheckRejected(KeyRejectedException.Kind.MALFORMED, new UnusualEcKey(EcCurve.P_384.getParameterSpec(), g,
				false));
	}

	// INV-G1 inventory: KeyFactory("EC") throws a raw RuntimeException for a coordinate wider than the field, and
	// ECPublicKeySpec throws IllegalArgumentException for the point at infinity. Neither is reachable here.
	@Test
	void theJcasUncheckedExceptionsForEcKeysAreNeverReached() throws GeneralSecurityException {
		EcCurve curve = EcCurve.P_256;
		ECPoint g = curve.getParameterSpec().getGenerator();
		BigInteger wideX = g.getAffineX().add(curve.getFieldPrime());

		// Controls: the JCA's own unchecked exceptions.
		Assertions.assertThrows(RuntimeException.class, () -> KeyFactory.getInstance("EC")
				.generatePublic(new ECPublicKeySpec(new ECPoint(wideX, g.getAffineY()), curve.getParameterSpec())));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> new ECPublicKeySpec(ECPoint.POINT_INFINITY, curve.getParameterSpec()));

		byte[] y = EcdsaSignaturesTests.fixed(g.getAffineY(), 32);
		assertRejected(KeyRejectedException.Kind.MALFORMED, curve, wideX.toByteArray(), y);
		assertRejected(KeyRejectedException.Kind.MALFORMED, curve, BigInteger.TWO.pow(300).toByteArray(), y);
		assertCheckRejected(KeyRejectedException.Kind.NOT_ON_CURVE,
				new UnusualEcKey(curve.getParameterSpec(), ECPoint.POINT_INFINITY, false));
	}

	// Deliberate null inputs verify runtime rejection.
	@SuppressWarnings("NullAway")
	@Test
	void rejectsNullArguments() throws GeneralSecurityException {
		ECPublicKey key = (ECPublicKey) generate(EcCurve.P_256).getPublic();

		Assertions.assertThrows(NullPointerException.class, () -> EcPublicKeys.fromCoordinates(nullValue(), new byte[32],
				new byte[32]));
		Assertions.assertThrows(NullPointerException.class, () -> EcPublicKeys.fromCoordinates(EcCurve.P_256, nullValue(),
				new byte[32]));
		Assertions.assertThrows(NullPointerException.class, () -> EcPublicKeys.fromCoordinates(EcCurve.P_256,
				new byte[32], nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> EcPublicKeys.checkPublicKey(nullValue(), key));
		Assertions.assertThrows(NullPointerException.class, () -> EcPublicKeys.checkPublicKey(EcCurve.P_256,
				nullValue()));
	}

	private static @NonNull KeyPair generate(@NonNull EcCurve curve) throws GeneralSecurityException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec(curve.getStandardName()));
		return generator.generateKeyPair();
	}

	private static void assertRejected(KeyRejectedException.@NonNull Kind kind, @NonNull EcCurve curve, byte @NonNull [] x, byte @NonNull [] y) {
		Assertions.assertEquals(kind, Assertions.assertThrows(KeyRejectedException.class,
				() -> EcPublicKeys.fromCoordinates(curve, x, y)).getKind(), () -> curve + " " + x.length + "/" + y.length);
	}

	private static void assertCheckRejected(KeyRejectedException.@NonNull Kind kind, @NonNull ECPublicKey key) {
		Assertions.assertEquals(kind, Assertions.assertThrows(KeyRejectedException.class,
				() -> EcPublicKeys.checkPublicKey(EcCurve.P_256, key)).getKind());
	}

	/**
	 * Hides a {@code null} from NullAway, for the tests that check null handling.
	 */
	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> @Nullable T nullValue() {
		return null;
	}

	/**
	 * An {@link ECPublicKey} implementation outside the JDK, which may report no parameters or no point, or throw.
	 */
	@SuppressWarnings("NullAway")
	static final class UnusualEcKey implements ECPublicKey {
		private static final long serialVersionUID = 1L;

		private final transient @Nullable ECParameterSpec parameters;
		private final transient @Nullable ECPoint point;
		private final boolean throwing;

		UnusualEcKey(@Nullable ECParameterSpec parameters, @Nullable ECPoint point, boolean throwing) {
			this.parameters = parameters;
			this.point = point;
			this.throwing = throwing;
		}

		@Override
		public @NonNull ECPoint getW() {
			if (this.throwing)
				throw new IllegalStateException("A key implementation that throws.");
			return this.point;
		}

		@Override
		public @NonNull ECParameterSpec getParams() {
			return this.parameters;
		}

		@Override
		public @NonNull String getAlgorithm() {
			return "EC";
		}

		@Override
		public @NonNull String getFormat() {
			return "X.509";
		}

		@Override
		public byte @NonNull [] getEncoded() {
			return new byte[0];
		}
	}
}
