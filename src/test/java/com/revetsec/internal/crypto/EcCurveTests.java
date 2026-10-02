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

import org.jspecify.annotations.Nullable;

import org.jspecify.annotations.NonNull;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * {@link EcCurve}: Revetsec's own parameters for P-256, P-384 and P-521 agree with the JDK's named curves (SEC 2
 * version 2, sections 2.4.2, 2.5.1 and 2.6.1), names match exactly (RFC 7518 section 6.2.1.1), parameter matching
 * compares every field, and the on-curve check bounds both coordinates by the field prime (INV-J5).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class EcCurveTests {
	// SEC 2 version 2: the JDK's own named-curve parameters are the independent source for Revetsec's constants.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> parametersEqualTheJdkNamedCurves() {
		return Stream.of(EcCurve.values()).map(curve -> DynamicTest.dynamicTest(curve.name(), () -> {
			ECParameterSpec jdk = jdkParameters(curve);
			ECParameterSpec ours = curve.getParameterSpec();

			Assertions.assertEquals(((ECFieldFp) jdk.getCurve().getField()).getP(), curve.getFieldPrime());
			Assertions.assertEquals(jdk.getCurve().getA(), curve.getA());
			Assertions.assertEquals(curve.getFieldPrime().subtract(BigInteger.valueOf(3)), curve.getA());
			Assertions.assertEquals(jdk.getCurve().getB(), curve.getB());
			Assertions.assertEquals(jdk.getGenerator(), ours.getGenerator());
			Assertions.assertEquals(jdk.getOrder(), curve.getOrder());
			Assertions.assertEquals(1, ours.getCofactor());
			Assertions.assertEquals(jdk.getCurve(), ours.getCurve());
			Assertions.assertTrue(curve.isDescribedBy(jdk));
			Assertions.assertTrue(curve.isDescribedBy(ours));
			Assertions.assertEquals(Optional.of(curve), EcCurve.findByParameterSpec(jdk));
			Assertions.assertTrue(curve.isOnCurve(jdk.getGenerator().getAffineX(), jdk.getGenerator().getAffineY()));
			Assertions.assertEquals((curve.getFieldPrime().bitLength() + 7) / 8, curve.getCoordinateLength());
			Assertions.assertEquals((curve.getOrder().bitLength() + 7) / 8, curve.getCoordinateLength());
		}));
	}

	// RFC 7518 section 3.4: 64, 96 and 132 octets; section 6.2.1.2: the full coordinate length.
	@Test
	void coordinateAndSignatureLengthsAreFixedPerCurve() {
		Assertions.assertEquals(List.of(32, 48, 66),
				Stream.of(EcCurve.values()).map(EcCurve::getCoordinateLength).toList());
		Assertions.assertEquals(List.of(64, 96, 132),
				Stream.of(EcCurve.values()).map(EcCurve::getSignatureLength).toList());
		Assertions.assertEquals(List.of("P-256", "P-384", "P-521"),
				Stream.of(EcCurve.values()).map(EcCurve::getName).toList());
		Assertions.assertEquals(List.of("secp256r1", "secp384r1", "secp521r1"),
				Stream.of(EcCurve.values()).map(EcCurve::getStandardName).toList());
	}

	// RFC 7518 section 6.2.1.1: "P-256", "P-384" and "P-521", case-sensitive; secp256k1 is not a JOSE ES curve.
	// Deliberate null inputs verify runtime rejection.
	@SuppressWarnings("NullAway")
	@Test
	void findsCurvesByTheirExactNameOnly() {
		Assertions.assertEquals(Optional.of(EcCurve.P_256), EcCurve.findByName("P-256"));
		Assertions.assertEquals(Optional.of(EcCurve.P_384), EcCurve.findByName("P-384"));
		Assertions.assertEquals(Optional.of(EcCurve.P_521), EcCurve.findByName("P-521"));

		for (String name : List.of("p-256", "P256", "P-256 ", "secp256r1", "secp256k1", "P-512", "Ed25519", ""))
			Assertions.assertEquals(Optional.empty(), EcCurve.findByName(name), name);

		Assertions.assertThrows(NullPointerException.class, () -> EcCurve.findByName(nullValue()));
	}

	// A key's parameters identify its curve only when the field, both coefficients, the base point, its order and the
	// cofactor all match; a curve that differs in any one of them is another curve.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> parameterMatchingComparesEveryField() {
		EcCurve curve = EcCurve.P_256;
		ECParameterSpec base = curve.getParameterSpec();
		EllipticCurve field = base.getCurve();
		BigInteger p = curve.getFieldPrime();
		ECPoint g = base.getGenerator();
		BigInteger n = curve.getOrder();

		return Stream.of(
						new Variant("binary field", new ECParameterSpec(new EllipticCurve(new ECFieldF2m(163,
								new int[]{7, 6, 3}), BigInteger.ONE, BigInteger.ONE), g, n, 1)),
						new Variant("another field prime", new ECParameterSpec(new EllipticCurve(
								new ECFieldFp(EcCurve.P_384.getFieldPrime()), curve.getA(), curve.getB()), g, n, 1)),
						new Variant("another a", new ECParameterSpec(new EllipticCurve(field.getField(), BigInteger.ONE,
								curve.getB()), g, n, 1)),
						new Variant("another b", new ECParameterSpec(new EllipticCurve(field.getField(), curve.getA(),
								curve.getB().add(BigInteger.ONE)), g, n, 1)),
						new Variant("generator at infinity", new ECParameterSpec(field, ECPoint.POINT_INFINITY, n, 1)),
						new Variant("another generator x", new ECParameterSpec(field,
								new ECPoint(g.getAffineX().add(BigInteger.ONE), g.getAffineY()), n, 1)),
						new Variant("negated generator (same x)", new ECParameterSpec(field,
								new ECPoint(g.getAffineX(), p.subtract(g.getAffineY())), n, 1)),
						new Variant("another order", new ECParameterSpec(field, g, n.add(BigInteger.TWO), 1)),
						new Variant("cofactor 2", new ECParameterSpec(field, g, n, 2)))
				.map(variant -> DynamicTest.dynamicTest(variant.name, () -> {
					Assertions.assertFalse(curve.isDescribedBy(variant.parameterSpec));
					Assertions.assertEquals(Optional.empty(), EcCurve.findByParameterSpec(variant.parameterSpec));
				}));
	}

	// Deliberate null inputs verify runtime rejection.
	@SuppressWarnings("NullAway")
	@Test
	void noParametersDescribeNoCurve() {
		for (EcCurve curve : EcCurve.values())
			Assertions.assertFalse(curve.isDescribedBy(null));

		Assertions.assertThrows(NullPointerException.class, () -> EcCurve.findByParameterSpec(nullValue()));
	}

	// Keys the JDK generates on each curve carry parameters that identify exactly that curve, never another.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> jdkGeneratedKeysIdentifyTheirCurve() {
		return Stream.of(EcCurve.values()).map(curve -> DynamicTest.dynamicTest(curve.name(), () -> {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(new ECGenParameterSpec(curve.getStandardName()));
			ECPublicKey key = (ECPublicKey) generator.generateKeyPair().getPublic();

			Assertions.assertEquals(Optional.of(curve), EcCurve.findByParameterSpec(key.getParams()));
			for (EcCurve other : EcCurve.values())
				Assertions.assertEquals(other == curve, other.isDescribedBy(key.getParams()), other::name);
			Assertions.assertTrue(curve.isOnCurve(key.getW().getAffineX(), key.getW().getAffineY()));
		}));
	}

	// INV-J5: 0 <= x, y < p and the curve equation; x = p is the same residue as 0 but is not a field element.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> onCurveCheckBoundsBothCoordinatesByTheFieldPrime() {
		return Stream.of(EcCurve.values()).map(curve -> DynamicTest.dynamicTest(curve.name(), () -> {
			ECPoint g = curve.getParameterSpec().getGenerator();
			BigInteger p = curve.getFieldPrime();
			BigInteger x = g.getAffineX();
			BigInteger y = g.getAffineY();

			Assertions.assertTrue(curve.isOnCurve(x, y));
			Assertions.assertTrue(curve.isOnCurve(x, p.subtract(y)), "-G is on the curve");
			Assertions.assertFalse(curve.isOnCurve(x, y.add(BigInteger.ONE)), "off the curve");
			Assertions.assertFalse(curve.isOnCurve(x.add(p), y), "x + p is the same residue but not below p");
			Assertions.assertFalse(curve.isOnCurve(x, y.add(p)), "y + p is the same residue but not below p");
			Assertions.assertFalse(curve.isOnCurve(x.subtract(p), y), "x - p is negative");
			Assertions.assertFalse(curve.isOnCurve(x, y.subtract(p)), "y - p is negative");
			Assertions.assertFalse(curve.isOnCurve(BigInteger.ZERO, BigInteger.ZERO));
			Assertions.assertFalse(curve.isOnCurve(p, BigInteger.ZERO));

			for (EcCurve other : EcCurve.values())
				if (other != curve)
					Assertions.assertFalse(other.isOnCurve(x, y), other::name);
		}));
	}

	// The bounds at their exact edges: b is a square on all three curves, so (0, sqrt(b)) is a point, and x = p is its
	// residue but not a field element. (No point has y = 0: with cofactor 1 there is no point of order 2.)
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> onCurveCheckAcceptsZeroAndRefusesTheFieldPrimeItself() {
		return Stream.of(EcCurve.values()).map(curve -> DynamicTest.dynamicTest(curve.name(), () -> {
			BigInteger p = curve.getFieldPrime();
			BigInteger y = squareRootOfB(curve);

			Assertions.assertTrue(curve.isOnCurve(BigInteger.ZERO, y), "(0, sqrt(b))");
			Assertions.assertTrue(curve.isOnCurve(BigInteger.ZERO, p.subtract(y)), "(0, -sqrt(b))");
			Assertions.assertFalse(curve.isOnCurve(p, y), "(p, sqrt(b)): p is 0's residue but not below p");
			Assertions.assertFalse(curve.isOnCurve(BigInteger.ZERO, y.add(p)), "(0, sqrt(b) + p)");
		}));
	}

	/**
	 * A square root of {@code b} modulo {@code p}, as {@code b^((p + 1) / 4)}, which works because {@code p = 3 mod 4}
	 * on all three curves; the test fails if {@code b} is not a square.
	 */
	static @NonNull BigInteger squareRootOfB(@NonNull EcCurve curve) {
		BigInteger p = curve.getFieldPrime();
		Assertions.assertEquals(3, p.mod(BigInteger.valueOf(4)).intValueExact());
		BigInteger root = curve.getB().modPow(p.add(BigInteger.ONE).shiftRight(2), p);
		Assertions.assertEquals(curve.getB(), root.multiply(root).mod(p), "b is a square modulo p");
		return root;
	}

	// Deliberate null inputs verify runtime rejection.
	@SuppressWarnings("NullAway")
	@Test
	void onCurveCheckRejectsNullCoordinates() {
		Assertions.assertThrows(NullPointerException.class, () -> EcCurve.P_256.isOnCurve(nullValue(), BigInteger.ONE));
		Assertions.assertThrows(NullPointerException.class, () -> EcCurve.P_256.isOnCurve(BigInteger.ONE, nullValue()));
	}

	@Test
	void everyCallReturnsFreshButEqualParameters() {
		for (EcCurve curve : EcCurve.values()) {
			ECParameterSpec first = curve.getParameterSpec();
			ECParameterSpec second = curve.getParameterSpec();

			Assertions.assertNotSame(first, second);
			Assertions.assertEquals(first.getCurve(), second.getCurve());
			Assertions.assertEquals(first.getGenerator(), second.getGenerator());
			Assertions.assertNull(first.getCurve().getSeed());
		}
	}

	private static @NonNull ECParameterSpec jdkParameters(@NonNull EcCurve curve) throws GeneralSecurityException {
		AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
		parameters.init(new ECGenParameterSpec(curve.getStandardName()));
		return parameters.getParameterSpec(ECParameterSpec.class);
	}

	/**
	 * Hides a {@code null} from NullAway, for the tests that check null handling.
	 */
	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> @Nullable T nullValue() {
		return null;
	}

	private static final class Variant {
		private final String name;
		private final ECParameterSpec parameterSpec;

		private Variant(@NonNull String name, @NonNull ECParameterSpec parameterSpec) {
			this.name = name;
			this.parameterSpec = parameterSpec;
		}
	}
}
