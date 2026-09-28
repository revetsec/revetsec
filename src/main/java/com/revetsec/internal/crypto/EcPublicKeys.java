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

import javax.annotation.concurrent.ThreadSafe;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

import static java.util.Objects.requireNonNull;

/**
 * Builds and validates EC public keys on {@link EcCurve}'s three curves.
 * <p>
 * The JDK's {@code KeyFactory("EC")} validates nothing about the point: it accepts points off the curve (from an
 * {@code ECPublicKeySpec} and from an SPKI encoding alike), and it throws a raw {@code RuntimeException} for a
 * coordinate wider than the field, and an {@code IllegalArgumentException} for the point at infinity. So every check
 * here runs in {@code BigInteger} before the JCA sees the point (INV-J5, INV-G1): the fixed coordinate length, then
 * {@code 0 <= x, y < p} and the curve equation. The curves have cofactor 1, so that is the whole public key
 * validation.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class EcPublicKeys {
	private static final String KEY_ALGORITHM = "EC";

	private EcPublicKeys() {
		// Static helpers only.
	}

	/**
	 * Builds the public key {@code (x, y)} on {@code curve} from fixed-length, unsigned big-endian coordinates, such as
	 * a JSON Web Key's {@code x} and {@code y} (RFC 7518 section 6.2.1.2 requires the full coordinate length).
	 *
	 * @param curve the curve
	 * @param x     the x-coordinate, exactly {@link EcCurve#getCoordinateLength()} bytes; not modified
	 * @param y     the y-coordinate, exactly {@link EcCurve#getCoordinateLength()} bytes; not modified
	 * @return the public key
	 * @throws KeyRejectedException {@link KeyRejectedException.Kind#MALFORMED} if a coordinate has another length or
	 *                              the JCA provider refuses the point after every check passed, and
	 *                              {@link KeyRejectedException.Kind#NOT_ON_CURVE} if a coordinate is not below the
	 *                              field prime or the point is not on the curve
	 */
	@NonNull
	public static ECPublicKey fromCoordinates(@NonNull EcCurve curve,
																						byte @NonNull [] x,
																						byte @NonNull [] y) throws KeyRejectedException {
		requireNonNull(curve);
		requireNonNull(x);
		requireNonNull(y);

		if (x.length != curve.getCoordinateLength() || y.length != curve.getCoordinateLength())
			throw new KeyRejectedException(KeyRejectedException.Kind.MALFORMED);

		BigInteger affineX = new BigInteger(1, x);
		BigInteger affineY = new BigInteger(1, y);

		if (!curve.isOnCurve(affineX, affineY))
			throw new KeyRejectedException(KeyRejectedException.Kind.NOT_ON_CURVE);

		try {
			// A provider whose EC key does not implement ECPublicKey fails the cast, which is caught like any refusal.
			return (ECPublicKey) KeyFactory.getInstance(KEY_ALGORITHM)
					.generatePublic(new ECPublicKeySpec(new ECPoint(affineX, affineY), curve.getParameterSpec()));
		} catch (GeneralSecurityException | RuntimeException exception) {
			throw new KeyRejectedException(KeyRejectedException.Kind.MALFORMED);
		}
	}

	/**
	 * Checks an EC public key that did not come from {@link #fromCoordinates(EcCurve, byte[], byte[])}, such as one
	 * from an SPKI encoding in a certificate or a PEM file, which the JCA accepts off the curve: its parameters must be
	 * exactly {@code curve}'s, and its point must be on the curve.
	 *
	 * @param curve the curve the key must be on, usually from {@link EcCurve#findByParameterSpec}
	 * @param key   the key
	 * @throws KeyRejectedException {@link KeyRejectedException.Kind#MALFORMED} if the key's parameters are not
	 *                              {@code curve}'s or the key cannot report them, and
	 *                              {@link KeyRejectedException.Kind#NOT_ON_CURVE} if its point is the point at infinity
	 *                              or is not on the curve
	 */
	public static void checkPublicKey(@NonNull EcCurve curve,
																		@NonNull ECPublicKey key) throws KeyRejectedException {
		requireNonNull(curve);
		requireNonNull(key);

		try {
			if (!curve.isDescribedBy(key.getParams()))
				throw new KeyRejectedException(KeyRejectedException.Kind.MALFORMED);

			ECPoint point = key.getW();

			// The point at infinity is the one ECPoint without affine coordinates.
			if (ECPoint.POINT_INFINITY.equals(point) || !curve.isOnCurve(point.getAffineX(), point.getAffineY()))
				throw new KeyRejectedException(KeyRejectedException.Kind.NOT_ON_CURVE);
		} catch (RuntimeException exception) {
			// A key implementation outside the JDK may throw from its accessors or return null.
			throw new KeyRejectedException(KeyRejectedException.Kind.MALFORMED);
		}
	}
}
