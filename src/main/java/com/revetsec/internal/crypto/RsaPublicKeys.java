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
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * Builds and validates RSA public keys under Revetsec's key policy (plan section 9.3, gate 8's M2-7). The checks run
 * in this order, and the first failure names the refusal:
 * <ol>
 *   <li>the modulus {@code n} and exponent {@code e} are minimal unsigned big-endian integers, with no leading zero
 *   octet (RFC 7518 section 2, Base64urlUInt), and {@code n} is odd, else
 *   {@link KeyRejectedException.Kind#MALFORMED};</li>
 *   <li>{@code n} has {@value #MINIMUM_MODULUS_BITS} to {@value #MAXIMUM_MODULUS_BITS} bits, else
 *   {@link KeyRejectedException.Kind#RSA_KEY_SIZE};</li>
 *   <li>{@code e} is odd, at least 65537 and below 2^32, else {@link KeyRejectedException.Kind#RSA_EXPONENT};</li>
 *   <li>{@code n} does not carry the ROCA fingerprint, else {@link KeyRejectedException.Kind#WEAK}.</li>
 * </ol>
 * The JDK's {@code KeyFactory("RSA")} accepts an even {@code e}, an even {@code n} and a 512-bit {@code n}, so none
 * of this is left to it. The exponent floor is 65537 rather than 3 because a provider that parses the PKCS #1 v1.5
 * padding instead of encoding and comparing it is open to low-exponent signature forgery with {@code e = 3}
 * (Bleichenbacher, 2006); the JDK encodes and compares, but Revetsec works with any JCA provider. Integers are always
 * read with {@code new BigInteger(1, bytes)}, because a signed read turns a modulus with its high bit set negative.
 * <p>
 * <strong>ROCA</strong> (CVE-2017-15361; Nemec et al., CCS 2017): a vulnerable library built each prime as
 * {@code k * M + (65537^a mod M)} for a primorial {@code M}, so for every small prime {@code p} dividing {@code M},
 * the modulus modulo {@code p} lies in the subgroup that 65537 generates modulo {@code p}. The check tests that
 * property for the {@value #ROCA_PRIME_COUNT} odd primes from 3 to 167; a random modulus passes all of them with
 * probability about 4 * 10^-9.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class RsaPublicKeys {
	/**
	 * The shortest allowed modulus, in bits.
	 */
	public static final int MINIMUM_MODULUS_BITS = 2048;

	/**
	 * The longest allowed modulus, in bits.
	 */
	public static final int MAXIMUM_MODULUS_BITS = 16_384;

	/**
	 * The shortest possible signature under an allowed key, in bytes: the length of a
	 * {@value #MINIMUM_MODULUS_BITS}-bit modulus.
	 */
	public static final int MINIMUM_SIGNATURE_LENGTH = MINIMUM_MODULUS_BITS / Byte.SIZE;

	/**
	 * The longest possible signature under an allowed key, in bytes: the length of a
	 * {@value #MAXIMUM_MODULUS_BITS}-bit modulus.
	 */
	public static final int MAXIMUM_SIGNATURE_LENGTH = MAXIMUM_MODULUS_BITS / Byte.SIZE;

	/**
	 * The smallest allowed public exponent, 65537 (F4).
	 */
	@NonNull
	public static final BigInteger MINIMUM_PUBLIC_EXPONENT = BigInteger.valueOf(65_537);

	/**
	 * The exclusive upper bound of the public exponent, 2^32.
	 */
	@NonNull
	public static final BigInteger PUBLIC_EXPONENT_LIMIT = BigInteger.ONE.shiftLeft(32);

	/**
	 * The small primes whose residues the ROCA check tests: the odd primes from 3 to 167.
	 */
	@NonNull
	public static final List<@NonNull Integer> ROCA_PRIMES = List.of(3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
			47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167);

	/**
	 * How many primes {@link #ROCA_PRIMES} holds.
	 */
	public static final int ROCA_PRIME_COUNT = 38;

	private static final int ROCA_GENERATOR = 65_537;

	/**
	 * For each prime in {@link #ROCA_PRIMES}, at the same index, a mask with bit {@code r} set exactly when
	 * {@code r} is in the subgroup that 65537 generates modulo that prime.
	 */
	@NonNull
	private static final List<@NonNull BigInteger> ROCA_RESIDUE_MASKS = List.copyOf(rocaResidueMasks());

	private static final String KEY_ALGORITHM = "RSA";

	private RsaPublicKeys() {
		// Static helpers only.
	}

	/**
	 * Builds an RSA public key from its unsigned big-endian modulus and public exponent, such as a JSON Web Key's
	 * decoded {@code n} and {@code e}, under the key policy in the class documentation.
	 *
	 * @param modulus  the modulus {@code n}, minimal; not modified
	 * @param exponent the public exponent {@code e}, minimal; not modified
	 * @return the public key
	 * @throws KeyRejectedException if the policy refuses the key (see the class documentation), or
	 *                              {@link KeyRejectedException.Kind#MALFORMED} if the JCA provider refuses it after every
	 *                              check passed
	 */
	@NonNull
	public static RSAPublicKey fromComponents(byte @NonNull [] modulus,
																						byte @NonNull [] exponent) throws KeyRejectedException {
		requireNonNull(modulus);
		requireNonNull(exponent);

		if (!isMinimal(modulus) || !isMinimal(exponent))
			throw new KeyRejectedException(KeyRejectedException.Kind.MALFORMED);

		BigInteger n = new BigInteger(1, modulus);
		BigInteger e = new BigInteger(1, exponent);

		checkComponents(n, e);

		try {
			// A provider whose RSA key does not implement RSAPublicKey fails the cast, which is caught like any refusal.
			return (RSAPublicKey) KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(new RSAPublicKeySpec(n, e));
		} catch (GeneralSecurityException | RuntimeException exception) {
			throw new KeyRejectedException(KeyRejectedException.Kind.MALFORMED);
		}
	}

	/**
	 * Checks an RSA public key that did not come from {@link #fromComponents(byte[], byte[])}, such as one from a
	 * certificate or a PEM file, under the key policy in the class documentation (its integers are minimal by
	 * construction).
	 *
	 * @param key the key
	 * @throws KeyRejectedException if the policy refuses the key, or {@link KeyRejectedException.Kind#MALFORMED} if the
	 *                              key cannot report its modulus and exponent
	 */
	public static void checkPublicKey(@NonNull RSAPublicKey key) throws KeyRejectedException {
		requireNonNull(key);

		BigInteger n;
		BigInteger e;

		try {
			n = requireNonNull(key.getModulus());
			e = requireNonNull(key.getPublicExponent());
		} catch (RuntimeException exception) {
			// A key implementation outside the JDK may throw from its accessors or return null.
			throw new KeyRejectedException(KeyRejectedException.Kind.MALFORMED);
		}

		checkComponents(n, e);
	}

	/**
	 * Returns whether {@code modulus} carries the ROCA fingerprint: for every prime {@code p} in {@link #ROCA_PRIMES},
	 * {@code modulus mod p} lies in the subgroup that 65537 generates modulo {@code p}.
	 *
	 * @param modulus the modulus
	 * @return {@code true} if the modulus has the fingerprint
	 */
	public static boolean isRocaFingerprinted(@NonNull BigInteger modulus) {
		requireNonNull(modulus);

		for (int index = 0; index < ROCA_PRIMES.size(); ++index) {
			int residue = modulus.mod(BigInteger.valueOf(ROCA_PRIMES.get(index))).intValue();

			if (!ROCA_RESIDUE_MASKS.get(index).testBit(residue))
				return false;
		}

		return true;
	}

	/**
	 * Returns whether {@code length} could be the length of a signature under some allowed key: from
	 * {@value #MINIMUM_SIGNATURE_LENGTH} to {@value #MAXIMUM_SIGNATURE_LENGTH} bytes. This bound lets a protocol reject a
	 * malformed signature before it looks for a key. {@link SignatureVerifier} applies it before it looks at the key
	 * too, then checks the exact length, the key's modulus length.
	 *
	 * @param length a signature length, in bytes
	 * @return {@code true} if the length is within the bounds
	 */
	public static boolean isWithinSignatureLengthBounds(int length) {
		return length >= MINIMUM_SIGNATURE_LENGTH && length <= MAXIMUM_SIGNATURE_LENGTH;
	}

	private static void checkComponents(@NonNull BigInteger n,
																			@NonNull BigInteger e) throws KeyRejectedException {
		// An even modulus is never the product of two odd primes.
		if (n.signum() <= 0 || !n.testBit(0))
			throw new KeyRejectedException(KeyRejectedException.Kind.MALFORMED);

		if (n.bitLength() < MINIMUM_MODULUS_BITS || n.bitLength() > MAXIMUM_MODULUS_BITS)
			throw new KeyRejectedException(KeyRejectedException.Kind.RSA_KEY_SIZE);

		if (!e.testBit(0) || e.compareTo(MINIMUM_PUBLIC_EXPONENT) < 0 || e.compareTo(PUBLIC_EXPONENT_LIMIT) >= 0)
			throw new KeyRejectedException(KeyRejectedException.Kind.RSA_EXPONENT);

		if (isRocaFingerprinted(n))
			throw new KeyRejectedException(KeyRejectedException.Kind.WEAK);
	}

	/**
	 * Whether {@code value} is a minimal unsigned integer: at least one octet, and no leading zero octet unless the
	 * value is zero itself, which RFC 7518 section 2 writes as one zero octet.
	 */
	private static boolean isMinimal(byte @NonNull [] value) {
		return value.length == 1 || (value.length > 1 && value[0] != 0);
	}

	@NonNull
	private static List<@NonNull BigInteger> rocaResidueMasks() {
		List<BigInteger> masks = new ArrayList<>(ROCA_PRIMES.size());

		for (int prime : ROCA_PRIMES) {
			int generator = ROCA_GENERATOR % prime;
			BigInteger mask = BigInteger.ZERO;
			int residue = 1;

			// 65537 is prime and above every listed prime, so the generator is a unit and the powers return to 1.
			do {
				mask = mask.setBit(residue);
				residue = residue * generator % prime;
			} while (residue != 1);

			masks.add(mask);
		}

		return masks;
	}
}
