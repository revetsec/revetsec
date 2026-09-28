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

import javax.annotation.concurrent.Immutable;
import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * The three prime-field elliptic curves Revetsec verifies ECDSA signatures on: P-256, P-384 and P-521 (SEC 2 version
 * 2, sections 2.4.2, 2.5.1 and 2.6.1, where they are secp256r1, secp384r1 and secp521r1).
 * <p>
 * Each curve is {@code y^2 = x^3 + a*x + b} over the prime field of order {@code p}, with {@code a = p - 3} on all
 * three, a base point {@code G} of prime order {@code n}, and cofactor 1. Because the cofactor is 1, every point on
 * the curve other than the point at infinity is in the prime-order group, so an on-curve check is the whole public
 * key validation. The parameters here are Revetsec's own, so the binding between a curve, its coordinate length and
 * its signature length never depends on a JCA provider.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public enum EcCurve {
	/**
	 * P-256 (secp256r1), with 32-byte coordinates.
	 */
	P_256("P-256", "secp256r1", 32,
			"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
			"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
			"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
			"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
			"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
	/**
	 * P-384 (secp384r1), with 48-byte coordinates.
	 */
	P_384("P-384", "secp384r1", 48,
			"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
			"b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
			"aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
			"3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
			"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"),
	/**
	 * P-521 (secp521r1), with 66-byte coordinates. A 66-byte value can exceed the 521-bit field prime, so the range
	 * check matters most here.
	 */
	P_521("P-521", "secp521r1", 66,
			// 2^521 - 1, a Mersenne prime.
			"01" + "ff".repeat(65),
			"0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf07357"
					+ "3df883d2c34f1ef451fd46b503f00",
			"00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de334"
					+ "8b3c1856a429bf97e7e31c2e5bd66",
			"011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353"
					+ "c7086a272c24088be94769fd16650",
			"01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5"
					+ "c9b8899c47aebb6fb71e91386409");

	private static final int HEX = 16;

	@NonNull
	private final String name;
	@NonNull
	private final String standardName;
	private final int coordinateLength;
	@NonNull
	private final BigInteger fieldPrime;
	@NonNull
	private final BigInteger a;
	@NonNull
	private final BigInteger b;
	@NonNull
	private final BigInteger generatorX;
	@NonNull
	private final BigInteger generatorY;
	@NonNull
	private final BigInteger order;

	EcCurve(@NonNull String name,
					@NonNull String standardName,
					int coordinateLength,
					@NonNull String fieldPrime,
					@NonNull String b,
					@NonNull String generatorX,
					@NonNull String generatorY,
					@NonNull String order) {
		this.name = name;
		this.standardName = standardName;
		this.coordinateLength = coordinateLength;
		this.fieldPrime = new BigInteger(fieldPrime, HEX);
		this.a = this.fieldPrime.subtract(BigInteger.valueOf(3));
		this.b = new BigInteger(b, HEX);
		this.generatorX = new BigInteger(generatorX, HEX);
		this.generatorY = new BigInteger(generatorY, HEX);
		this.order = new BigInteger(order, HEX);
	}

	/**
	 * Returns the curve whose name is exactly {@code name}: {@code P-256}, {@code P-384} or {@code P-521}. The match
	 * is exact and case-sensitive, so {@code p-256} and {@code secp256r1} find nothing.
	 *
	 * @param name the curve name, such as a JSON Web Key's {@code crv}
	 * @return the curve, or empty if the name is not one of the three
	 */
	@NonNull
	public static Optional<EcCurve> findByName(@NonNull String name) {
		requireNonNull(name);

		return switch (name) {
			case "P-256" -> Optional.of(P_256);
			case "P-384" -> Optional.of(P_384);
			case "P-521" -> Optional.of(P_521);
			default -> Optional.empty();
		};
	}

	/**
	 * Returns the curve that {@code parameterSpec} describes, comparing the field prime, both coefficients, the base
	 * point, its order and the cofactor, but not the optional seed. A JCA provider's named-curve parameters and the
	 * explicit parameters of an SPKI key both match this way.
	 *
	 * @param parameterSpec the parameters of an EC key, such as {@code ECPublicKey.getParams()}
	 * @return the curve, or empty if the parameters are not exactly one of the three curves
	 */
	@NonNull
	public static Optional<EcCurve> findByParameterSpec(@NonNull ECParameterSpec parameterSpec) {
		requireNonNull(parameterSpec);

		for (EcCurve curve : values())
			if (curve.isDescribedBy(parameterSpec))
				return Optional.of(curve);

		return Optional.empty();
	}

	/**
	 * Returns this curve's name, such as {@code P-256}.
	 *
	 * @return the name
	 */
	@NonNull
	public String getName() {
		return this.name;
	}

	/**
	 * Returns this curve's SEC 2 name, such as {@code secp256r1}, which is also its JCA {@code ECGenParameterSpec}
	 * name.
	 *
	 * @return the SEC 2 name
	 */
	@NonNull
	public String getStandardName() {
		return this.standardName;
	}

	/**
	 * Returns the fixed length of one coordinate or one ECDSA signature half, in bytes: 32, 48 or 66.
	 *
	 * @return the coordinate length
	 */
	public int getCoordinateLength() {
		return this.coordinateLength;
	}

	/**
	 * Returns the fixed length of an ECDSA signature {@code r || s} on this curve, in bytes: 64, 96 or 132.
	 *
	 * @return twice the coordinate length
	 */
	public int getSignatureLength() {
		return 2 * this.coordinateLength;
	}

	/**
	 * Returns the field prime {@code p}.
	 *
	 * @return the field prime
	 */
	@NonNull
	public BigInteger getFieldPrime() {
		return this.fieldPrime;
	}

	/**
	 * Returns the coefficient {@code a}, which is {@code p - 3} on all three curves.
	 *
	 * @return the coefficient {@code a}
	 */
	@NonNull
	public BigInteger getA() {
		return this.a;
	}

	/**
	 * Returns the coefficient {@code b}.
	 *
	 * @return the coefficient {@code b}
	 */
	@NonNull
	public BigInteger getB() {
		return this.b;
	}

	/**
	 * Returns the order {@code n} of the base point, the bound for ECDSA's {@code r} and {@code s}.
	 *
	 * @return the order
	 */
	@NonNull
	public BigInteger getOrder() {
		return this.order;
	}

	/**
	 * Returns this curve's JCA parameters, with cofactor 1 and no seed.
	 *
	 * @return new parameters
	 */
	@NonNull
	public ECParameterSpec getParameterSpec() {
		return new ECParameterSpec(new EllipticCurve(new ECFieldFp(this.fieldPrime), this.a, this.b),
				new ECPoint(this.generatorX, this.generatorY), this.order, 1);
	}

	/**
	 * Returns whether {@code (x, y)} is a point on this curve: {@code 0 <= x, y < p} and
	 * {@code y^2 = x^3 + a*x + b (mod p)}. The point at infinity has no affine coordinates and is never on the curve
	 * here.
	 *
	 * @param x the affine x-coordinate
	 * @param y the affine y-coordinate
	 * @return {@code true} if the point is on the curve
	 */
	public boolean isOnCurve(@NonNull BigInteger x,
													 @NonNull BigInteger y) {
		requireNonNull(x);
		requireNonNull(y);

		if (!isFieldElement(x) || !isFieldElement(y))
			return false;

		BigInteger left = y.multiply(y).mod(this.fieldPrime);
		BigInteger right = x.multiply(x).add(this.a).multiply(x).add(this.b).mod(this.fieldPrime);

		return left.compareTo(right) == 0;
	}

	/**
	 * Returns whether {@code parameterSpec} describes this curve (see {@link #findByParameterSpec(ECParameterSpec)}).
	 *
	 * @param parameterSpec the parameters to compare, or {@code null}
	 * @return {@code true} if they describe this curve
	 */
	public boolean isDescribedBy(@Nullable ECParameterSpec parameterSpec) {
		if (parameterSpec == null)
			return false;

		EllipticCurve curve = parameterSpec.getCurve();
		ECPoint generator = parameterSpec.getGenerator();

		// The point at infinity is the one ECPoint without affine coordinates.
		return curve.getField() instanceof ECFieldFp field
				&& field.getP().compareTo(this.fieldPrime) == 0
				&& curve.getA().compareTo(this.a) == 0
				&& curve.getB().compareTo(this.b) == 0
				&& !ECPoint.POINT_INFINITY.equals(generator)
				&& generator.getAffineX().compareTo(this.generatorX) == 0
				&& generator.getAffineY().compareTo(this.generatorY) == 0
				&& parameterSpec.getOrder().compareTo(this.order) == 0
				&& parameterSpec.getCofactor() == 1;
	}

	private boolean isFieldElement(@NonNull BigInteger value) {
		return value.signum() >= 0 && value.compareTo(this.fieldPrime) < 0;
	}
}
