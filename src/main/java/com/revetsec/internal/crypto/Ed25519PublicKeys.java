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
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;

import static java.util.Objects.requireNonNull;

/**
 * Builds and validates Ed25519 public keys (RFC 8032 section 5.1).
 * <p>
 * The JDK's {@code KeyFactory("Ed25519")} accepts every 32-byte encoding and decodes the point only when a signature
 * is verified. An encoding that does not decode then throws {@code InvalidKeyException} at verification, and about
 * half of all 32-byte strings do not decode. A small-order key is worse: under the identity point, the signature
 * {@code R} = identity, {@code S} = 0 verifies for every message. So the whole decoding runs here, in
 * {@code BigInteger}, before the JCA sees the key (gate 8's M2-7):
 * <ol>
 *   <li>the encoding is 32 bytes, else {@link KeyRejectedException.Kind#MALFORMED};</li>
 *   <li>it decodes under RFC 8032 section 5.1.3: {@code y < p}; {@code x^2 = (y^2 - 1) / (d*y^2 + 1)} has a square
 *   root modulo {@code p}; and {@code x = 0} never comes with the sign bit set. Otherwise
 *   {@link KeyRejectedException.Kind#MALFORMED};</li>
 *   <li>the point does not have small order, that is, {@code [8]P} is not the identity; the curve's eight
 *   small-order points are exactly its 8-torsion subgroup. Otherwise {@link KeyRejectedException.Kind#WEAK}.</li>
 * </ol>
 * A point with a small-order component added to a point of large order is not refused. The JCA algorithm name is
 * pinned to {@code Ed25519}, never the generic {@code EdDSA}, which also accepts Ed448 keys.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class Ed25519PublicKeys {
	/**
	 * The length of an encoded Ed25519 public key, in bytes.
	 */
	public static final int KEY_LENGTH = 32;

	/**
	 * The length of an Ed25519 signature, in bytes.
	 */
	public static final int SIGNATURE_LENGTH = 64;

	/**
	 * The JCA name of the Ed25519 key and signature algorithms, and of its {@code NamedParameterSpec}.
	 */
	static final String ALGORITHM = "Ed25519";

	/**
	 * The field prime {@code p = 2^255 - 19}.
	 */
	private static final BigInteger FIELD_PRIME = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));

	/**
	 * The curve constant {@code d = -121665 / 121666 (mod p)}.
	 */
	private static final BigInteger D = BigInteger.valueOf(-121_665)
			.multiply(BigInteger.valueOf(121_666).modInverse(FIELD_PRIME)).mod(FIELD_PRIME);

	/**
	 * A square root of -1 modulo {@code p}: {@code 2^((p - 1) / 4)}.
	 */
	private static final BigInteger SQUARE_ROOT_OF_MINUS_ONE = BigInteger.TWO
			.modPow(FIELD_PRIME.subtract(BigInteger.ONE).shiftRight(2), FIELD_PRIME);

	/**
	 * The exponent {@code (p - 5) / 8} of RFC 8032 section 5.1.3's square-root candidate.
	 */
	private static final BigInteger CANDIDATE_EXPONENT = FIELD_PRIME.subtract(BigInteger.valueOf(5)).shiftRight(3);

	private static final int SIGN_BIT = 0x80;
	private static final int SMALL_ORDER_DOUBLINGS = 3;

	private Ed25519PublicKeys() {
		// Static helpers only.
	}

	/**
	 * Builds an Ed25519 public key from its 32-byte encoding (RFC 8032 section 5.1.2), such as a JSON Web Key's
	 * decoded {@code x} (RFC 8037 section 2), after decoding it and checking its order as the class documentation
	 * describes.
	 *
	 * @param encoded the encoded point; not modified
	 * @return the public key
	 * @throws KeyRejectedException {@link KeyRejectedException.Kind#MALFORMED} if the encoding is not 32 bytes, does not
	 *                              decode, or the JCA provider refuses it after every check passed, and
	 *                              {@link KeyRejectedException.Kind#WEAK} if the point has small order
	 */
	@NonNull
	public static EdECPublicKey fromEncoded(byte @NonNull [] encoded) throws KeyRejectedException {
		requireNonNull(encoded);

		if (encoded.length != KEY_LENGTH)
			throw new KeyRejectedException(KeyRejectedException.Kind.MALFORMED);

		// Little-endian, with the sign of x in the top bit of the last byte.
		boolean xOdd = (encoded[KEY_LENGTH - 1] & SIGN_BIT) != 0;
		byte[] bigEndian = new byte[KEY_LENGTH];

		for (int index = 0; index < KEY_LENGTH; ++index)
			bigEndian[index] = encoded[KEY_LENGTH - 1 - index];

		bigEndian[0] = (byte) (bigEndian[0] & ~SIGN_BIT);

		BigInteger y = new BigInteger(1, bigEndian);

		checkPoint(y, xOdd);

		try {
			// A provider whose key does not implement EdECPublicKey fails the cast, which is caught like any refusal.
			return (EdECPublicKey) KeyFactory.getInstance(ALGORITHM)
					.generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, new EdECPoint(xOdd, y)));
		} catch (GeneralSecurityException | RuntimeException exception) {
			throw new KeyRejectedException(KeyRejectedException.Kind.MALFORMED);
		}
	}

	/**
	 * Checks an Ed25519 public key that did not come from {@link #fromEncoded(byte[])}, such as one from an SPKI
	 * encoding in a certificate or a PEM file, which the JCA accepts without decoding: its parameters must be Ed25519,
	 * and its point must decode and not have small order.
	 *
	 * @param key the key
	 * @throws KeyRejectedException {@link KeyRejectedException.Kind#MALFORMED} if the key is not an Ed25519 key, cannot
	 *                              report its point, or its point does not decode, and
	 *                              {@link KeyRejectedException.Kind#WEAK} if the point has small order
	 */
	public static void checkPublicKey(@NonNull EdECPublicKey key) throws KeyRejectedException {
		requireNonNull(key);

		BigInteger y;
		boolean xOdd;

		try {
			if (!isEd25519(key.getParams()))
				throw new KeyRejectedException(KeyRejectedException.Kind.MALFORMED);

			EdECPoint point = key.getPoint();
			y = requireNonNull(point.getY());
			xOdd = point.isXOdd();
		} catch (RuntimeException exception) {
			// A key implementation outside the JDK may throw from its accessors or return null.
			throw new KeyRejectedException(KeyRejectedException.Kind.MALFORMED);
		}

		checkPoint(y, xOdd);
	}

	/**
	 * Whether {@code parameters} name Ed25519, compared by {@code switch} rather than by string equality.
	 */
	static boolean isEd25519(@NonNull NamedParameterSpec parameters) {
		return switch (parameters.getName()) {
			case ALGORITHM -> true;
			default -> false;
		};
	}

	/**
	 * Decodes the point {@code (y, xOdd)} under RFC 8032 section 5.1.3 and refuses a point of small order.
	 */
	private static void checkPoint(@NonNull BigInteger y,
																 boolean xOdd) throws KeyRejectedException {
		if (y.signum() < 0 || y.compareTo(FIELD_PRIME) >= 0)
			throw new KeyRejectedException(KeyRejectedException.Kind.MALFORMED);

		BigInteger x = recoverX(y, xOdd);

		if (hasSmallOrder(x, y))
			throw new KeyRejectedException(KeyRejectedException.Kind.WEAK);
	}

	/**
	 * RFC 8032 section 5.1.3, steps 2 to 4: recovers x from {@code y < p} and the sign bit. Package-private so that the
	 * tests can check the recovered point against the curve equation, which the small-order check relies on.
	 */
	@NonNull
	static BigInteger recoverX(@NonNull BigInteger y,
																		 boolean xOdd) throws KeyRejectedException {
		BigInteger ySquared = y.multiply(y).mod(FIELD_PRIME);
		BigInteger u = ySquared.subtract(BigInteger.ONE).mod(FIELD_PRIME);
		// d * y^2 + 1 is never 0: that would need y^2 = -1/d, which is not a square, because d is not one and -1 is.
		BigInteger v = D.multiply(ySquared).add(BigInteger.ONE).mod(FIELD_PRIME);
		BigInteger vCubed = v.multiply(v).multiply(v).mod(FIELD_PRIME);
		BigInteger vToTheSeventh = vCubed.multiply(vCubed).multiply(v).mod(FIELD_PRIME);
		BigInteger x = u.multiply(vCubed)
				.multiply(u.multiply(vToTheSeventh).mod(FIELD_PRIME).modPow(CANDIDATE_EXPONENT, FIELD_PRIME))
				.mod(FIELD_PRIME);
		BigInteger vTimesXSquared = v.multiply(x).multiply(x).mod(FIELD_PRIME);

		if (vTimesXSquared.compareTo(u) != 0) {
			if (vTimesXSquared.compareTo(u.negate().mod(FIELD_PRIME)) != 0)
				// x^2 = u / v has no square root: the encoding is not a point.
				throw new KeyRejectedException(KeyRejectedException.Kind.MALFORMED);

			x = x.multiply(SQUARE_ROOT_OF_MINUS_ONE).mod(FIELD_PRIME);
		}

		if (x.signum() == 0 && xOdd)
			throw new KeyRejectedException(KeyRejectedException.Kind.MALFORMED);

		return x.testBit(0) == xOdd ? x : FIELD_PRIME.subtract(x);
	}

	/**
	 * Whether {@code [8](x, y)} is the identity {@code (0, 1)}, by three doublings under the complete twisted Edwards
	 * addition law with {@code a = -1} (RFC 8032 section 5.1.4). Its denominators {@code 1 +/- d*x^2*y^2} are never 0
	 * for a point on the curve, because {@code d} is not a square.
	 */
	private static boolean hasSmallOrder(@NonNull BigInteger x,
																			 @NonNull BigInteger y) {
		BigInteger currentX = x;
		BigInteger currentY = y;

		for (int doubling = 0; doubling < SMALL_ORDER_DOUBLINGS; ++doubling) {
			BigInteger xSquared = currentX.multiply(currentX).mod(FIELD_PRIME);
			BigInteger ySquared = currentY.multiply(currentY).mod(FIELD_PRIME);
			BigInteger product = D.multiply(xSquared).mod(FIELD_PRIME).multiply(ySquared).mod(FIELD_PRIME);
			BigInteger nextX = currentX.multiply(currentY).shiftLeft(1)
					.multiply(BigInteger.ONE.add(product).modInverse(FIELD_PRIME)).mod(FIELD_PRIME);
			BigInteger nextY = ySquared.add(xSquared)
					.multiply(BigInteger.ONE.subtract(product).mod(FIELD_PRIME).modInverse(FIELD_PRIME)).mod(FIELD_PRIME);
			currentX = nextX;
			currentY = nextY;
		}

		return currentX.signum() == 0 && currentY.compareTo(BigInteger.ONE) == 0;
	}
}
