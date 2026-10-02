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
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * {@link RsaPublicKeys}: the RSA key policy of plan section 9.3 as amended by gate 8's M2-7, in its precedence order:
 * minimal Base64urlUInt integers (RFC 7518 section 2) and an odd modulus, 2048 to 16384 bits, an odd exponent in
 * {@code [65537, 2^32)}, and no ROCA fingerprint (CVE-2017-15361), tested against a modulus generated here with the
 * vulnerable structure.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class RsaPublicKeysTests {
	private static final byte[] MESSAGE = "Revetsec RSA key policy".getBytes(StandardCharsets.US_ASCII);
	private static final BigInteger F4 = BigInteger.valueOf(65_537);

	// A JDK key's minimal n and e rebuild the same key, which verifies the JDK's signature. A 2048-bit modulus has its
	// high bit set, so a signed read would make it negative; BigInteger(1, ...) keeps it positive (plan section 8).
	@Test
	void minimalComponentsRebuildTheJdksKey() throws Exception {
		KeyPair keyPair = Keys.rsa2048();
		RSAPublicKey jdkKey = (RSAPublicKey) keyPair.getPublic();
		byte[] n = unsigned(jdkKey.getModulus());
		byte[] e = unsigned(jdkKey.getPublicExponent());
		byte[] nCopy = n.clone();

		Assertions.assertTrue(n[0] < 0, "the modulus's first byte has its high bit set");

		RSAPublicKey key = RsaPublicKeys.fromComponents(n, e);

		Assertions.assertArrayEquals(nCopy, n, "the modulus bytes are not modified");
		Assertions.assertEquals(jdkKey.getModulus(), key.getModulus());
		Assertions.assertEquals(F4, key.getPublicExponent());
		Assertions.assertArrayEquals(jdkKey.getEncoded(), key.getEncoded());
		Assertions.assertEquals(VerifyResult.VALID, SignatureVerifier.verifyRsaPkcs1(HashAlgorithm.SHA_256, key, MESSAGE,
				sign("SHA256withRSA", keyPair.getPrivate())));
		RsaPublicKeys.checkPublicKey(key);
		RsaPublicKeys.checkPublicKey(jdkKey);
	}

	// M2-7: e odd and in [65537, 2^32). The floor was 3; e = 3 is the low-exponent forgery setting for a provider that
	// parses PKCS #1 v1.5 padding (Bleichenbacher, 2006). KeyFactory("RSA") accepts 65536 and 2^64 + 1 itself.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> exponentsOutsideTheOddRangeFrom65537To2Pow32AreRefused() throws GeneralSecurityException {
		byte[] n = unsigned(((RSAPublicKey) Keys.rsa2048().getPublic()).getModulus());
		BigInteger twoTo32 = BigInteger.ONE.shiftLeft(32);
		List<BigInteger> refused = List.of(BigInteger.ONE, BigInteger.valueOf(3), BigInteger.valueOf(17),
				BigInteger.valueOf(65_535), BigInteger.valueOf(65_536), BigInteger.valueOf(65_538),
				twoTo32.subtract(BigInteger.TWO), twoTo32, twoTo32.add(BigInteger.ONE), BigInteger.ONE.shiftLeft(64).add(
						BigInteger.ONE));
		List<BigInteger> accepted = List.of(F4, BigInteger.valueOf(65_539), BigInteger.ONE.shiftLeft(31).add(
				BigInteger.ONE), twoTo32.subtract(BigInteger.ONE));

		return Stream.concat(
				refused.stream().map(e -> DynamicTest.dynamicTest("refused: e = " + e, () -> assertRejected(
						KeyRejectedException.Kind.RSA_EXPONENT, n, unsigned(e)))),
				accepted.stream().map(e -> DynamicTest.dynamicTest("accepted: e = " + e, () -> Assertions.assertEquals(e,
						RsaPublicKeys.fromComponents(n, unsigned(e)).getPublicExponent()))));
	}

	// Plan section 9.3: 2048 to 16384 bits. KeyFactory("RSA") accepts a 512-bit modulus itself, and 16384 bits is its
	// own cap too.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> moduliOutside2048To16384BitsAreRefused() {
		return IntStream.of(512, 1024, 2047, 2048, 2049, 3072, 4096, 16_384, 16_385, 16_392)
				.mapToObj(bits -> DynamicTest.dynamicTest(bits + " bits", () -> {
					BigInteger modulus = syntheticModulus(bits);
					Assertions.assertFalse(RsaPublicKeys.isRocaFingerprinted(modulus));

					if (bits >= RsaPublicKeys.MINIMUM_MODULUS_BITS && bits <= RsaPublicKeys.MAXIMUM_MODULUS_BITS)
						Assertions.assertEquals(modulus, RsaPublicKeys.fromComponents(unsigned(modulus), unsigned(F4))
								.getModulus());
					else
						assertRejected(KeyRejectedException.Kind.RSA_KEY_SIZE, unsigned(modulus), unsigned(F4));
				}));
	}

	// RFC 7518 section 2: Base64urlUInt "MUST utilize the minimum number of octets needed to represent the value", and
	// zero is one zero octet. A leading zero octet changes the RFC 7638 thumbprint of the same key.
	@Test
	void nonMinimalIntegersAndAnEvenModulusAreMalformed() throws GeneralSecurityException {
		BigInteger modulus = ((RSAPublicKey) Keys.rsa2048().getPublic()).getModulus();
		byte[] n = unsigned(modulus);
		byte[] e = unsigned(F4);

		assertRejected(KeyRejectedException.Kind.MALFORMED, EcdsaSignaturesTests.concat(new byte[1], n), e);
		assertRejected(KeyRejectedException.Kind.MALFORMED, n, EcdsaSignaturesTests.concat(new byte[1], e));
		assertRejected(KeyRejectedException.Kind.MALFORMED, n, EcdsaSignaturesTests.concat(new byte[2], e));
		assertRejected(KeyRejectedException.Kind.MALFORMED, new byte[0], e);
		assertRejected(KeyRejectedException.Kind.MALFORMED, n, new byte[0]);
		// Zero is minimal as one zero octet: a zero modulus is even, and a zero exponent is below the floor.
		assertRejected(KeyRejectedException.Kind.MALFORMED, new byte[1], e);
		assertRejected(KeyRejectedException.Kind.RSA_EXPONENT, n, new byte[1]);
		// An even modulus is never a product of two odd primes; KeyFactory("RSA") accepts one.
		assertRejected(KeyRejectedException.Kind.MALFORMED, unsigned(modulus.clearBit(0)), e);
		assertRejected(KeyRejectedException.Kind.MALFORMED, unsigned(syntheticModulus(2048).clearBit(0)), e);
	}

	// Keys row precedence (checks 7, 8, 9 and 11): the first failing check names the refusal.
	@Test
	void theFirstFailingCheckNamesTheRefusal() throws GeneralSecurityException {
		byte[] small = unsigned(syntheticModulus(1024));
		byte[] roca = unsigned(Keys.roca().modulus);

		assertRejected(KeyRejectedException.Kind.MALFORMED, EcdsaSignaturesTests.concat(new byte[1], small), unsigned(
				BigInteger.valueOf(3)));
		assertRejected(KeyRejectedException.Kind.MALFORMED, unsigned(syntheticModulus(1024).clearBit(0)), unsigned(
				BigInteger.valueOf(3)));
		assertRejected(KeyRejectedException.Kind.RSA_KEY_SIZE, small, unsigned(BigInteger.valueOf(3)));
		assertRejected(KeyRejectedException.Kind.RSA_EXPONENT, roca, unsigned(BigInteger.valueOf(3)));
		assertRejected(KeyRejectedException.Kind.WEAK, roca, unsigned(F4));
	}

	// CVE-2017-15361 (ROCA): a key built from primes of the form k * M + (65537^a mod M) is a working RSA key that
	// the JDK accepts and verifies with; the fingerprint check refuses it, from its components and as an SPKI key.
	@Test
	void aGeneratedRocaStructuredKeyIsRefusedAsWeak() throws Exception {
		RocaKey roca = Keys.roca();
		RSAPublicKey jdkKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
				roca.modulus, F4));
		byte[] signature = sign("SHA256withRSA", roca.privateKey);
		Signature control = Signature.getInstance("SHA256withRSA");
		control.initVerify(jdkKey);
		control.update(MESSAGE);

		Assertions.assertEquals(2048, roca.modulus.bitLength());
		Assertions.assertTrue(control.verify(signature), "control: the JDK alone uses the key");
		Assertions.assertTrue(RsaPublicKeys.isRocaFingerprinted(roca.modulus));
		assertRejected(KeyRejectedException.Kind.WEAK, unsigned(roca.modulus), unsigned(F4));
		Assertions.assertEquals(KeyRejectedException.Kind.WEAK, Assertions.assertThrows(KeyRejectedException.class,
				() -> RsaPublicKeys.checkPublicKey(jdkKey)).getKind());
	}

	// Keys the JDK generates are not fingerprinted (a random modulus passes all 38 tests with probability ~4e-9).
	@Test
	void jdkGeneratedKeysAreNotFingerprinted() throws GeneralSecurityException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);

		for (int index = 0; index < 4; ++index)
			Assertions.assertFalse(RsaPublicKeys.isRocaFingerprinted(((RSAPublicKey) generator.generateKeyPair()
					.getPublic()).getModulus()));

		Assertions.assertFalse(RsaPublicKeys.isRocaFingerprinted(((RSAPublicKey) Keys.rsa2048().getPublic())
				.getModulus()));
	}

	// The fingerprint needs every one of the 38 residues in its subgroup: for each prime p and each residue r mod p, a
	// modulus that is r mod p and 1 mod every other prime is fingerprinted exactly when r is a power of 65537 mod p.
	// The subgroups are derived here by listing powers, independently of the class's bit masks.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> everyPrimeAndEveryResidueDecidesTheFingerprint() {
		List<BigInteger> primes = RsaPublicKeys.ROCA_PRIMES.stream().map(BigInteger::valueOf).toList();
		BigInteger product = primes.stream().reduce(BigInteger.ONE, BigInteger::multiply);
		// A large multiple of the product keeps every residue and makes the value modulus-sized.
		BigInteger offset = product.multiply(BigInteger.ONE.shiftLeft(2048 - product.bitLength()));

		return primes.stream().map(prime -> DynamicTest.dynamicTest("p = " + prime, () -> {
			int p = prime.intValueExact();
			Set<Integer> subgroup = new HashSet<>();
			for (int power = 0, value = 1; power < p; ++power, value = value * (65_537 % p) % p)
				subgroup.add(value);

			BigInteger cofactor = product.divide(prime);
			BigInteger idempotent = cofactor.multiply(cofactor.modInverse(prime)).mod(product);

			for (int residue = 0; residue < p; ++residue) {
				// 1 + (r - 1) * e is r mod p and 1 mod every other listed prime.
				BigInteger candidate = BigInteger.ONE.add(BigInteger.valueOf(residue - 1L).multiply(idempotent)).mod(product)
						.add(offset);

				Assertions.assertEquals(residue, candidate.mod(prime).intValueExact());
				Assertions.assertEquals(subgroup.contains(residue), RsaPublicKeys.isRocaFingerprinted(candidate),
						"residue " + residue);
			}
		}));
	}

	// Gate 8 pins the ROCA prime set: the odd primes from 3 to 167.
	@Test
	void theRocaPrimesAreTheThirtyEightOddPrimesFrom3To167() {
		List<Integer> expected = new ArrayList<>();
		for (int candidate = 3; candidate <= 167; candidate += 2)
			if (BigInteger.valueOf(candidate).isProbablePrime(64))
				expected.add(candidate);

		Assertions.assertEquals(expected, RsaPublicKeys.ROCA_PRIMES);
		Assertions.assertEquals(38, RsaPublicKeys.ROCA_PRIMES.size());
		Assertions.assertEquals(RsaPublicKeys.ROCA_PRIME_COUNT, RsaPublicKeys.ROCA_PRIMES.size());
		Assertions.assertThrows(UnsupportedOperationException.class, () -> RsaPublicKeys.ROCA_PRIMES.set(0, 5));
	}

	// Keys that did not come from components (certificates, PEM) get the same policy.
	@Test
	void keysFromOtherSourcesGetTheSamePolicy() throws GeneralSecurityException, KeyRejectedException {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		BigInteger modulus = ((RSAPublicKey) Keys.rsa2048().getPublic()).getModulus();
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024);

		assertCheckRejected(KeyRejectedException.Kind.RSA_KEY_SIZE, (RSAPublicKey) generator.generateKeyPair().getPublic());
		assertCheckRejected(KeyRejectedException.Kind.RSA_EXPONENT, (RSAPublicKey) keyFactory.generatePublic(
				new RSAPublicKeySpec(modulus, BigInteger.valueOf(3))));
		assertCheckRejected(KeyRejectedException.Kind.RSA_EXPONENT, (RSAPublicKey) keyFactory.generatePublic(
				new RSAPublicKeySpec(modulus, BigInteger.valueOf(65_536))));
		assertCheckRejected(KeyRejectedException.Kind.MALFORMED, (RSAPublicKey) keyFactory.generatePublic(
				new RSAPublicKeySpec(modulus.clearBit(0), F4)));
		assertCheckRejected(KeyRejectedException.Kind.MALFORMED, new UnusualRsaKey(modulus.negate(), F4, false));
		assertCheckRejected(KeyRejectedException.Kind.MALFORMED, new UnusualRsaKey(null, F4, false));
		assertCheckRejected(KeyRejectedException.Kind.MALFORMED, new UnusualRsaKey(modulus, null, false));
		assertCheckRejected(KeyRejectedException.Kind.MALFORMED, new UnusualRsaKey(modulus, F4, true));
		assertCheckRejected(KeyRejectedException.Kind.RSA_EXPONENT, new UnusualRsaKey(modulus, F4.negate(), false));
		RsaPublicKeys.checkPublicKey(new UnusualRsaKey(modulus, F4, false));
	}

	// M2-6: before a key is known, an RS* or PS* signature must be 256 to 2048 octets, the lengths of the allowed
	// moduli; the exact length is the key's.
	@Test
	void signatureLengthBoundsFollowTheModulusBounds() {
		Assertions.assertEquals(256, RsaPublicKeys.MINIMUM_SIGNATURE_LENGTH);
		Assertions.assertEquals(2048, RsaPublicKeys.MAXIMUM_SIGNATURE_LENGTH);
		Assertions.assertEquals(2048, RsaPublicKeys.MINIMUM_MODULUS_BITS);
		Assertions.assertEquals(16_384, RsaPublicKeys.MAXIMUM_MODULUS_BITS);
		Assertions.assertEquals(F4, RsaPublicKeys.MINIMUM_PUBLIC_EXPONENT);
		Assertions.assertEquals(BigInteger.ONE.shiftLeft(32), RsaPublicKeys.PUBLIC_EXPONENT_LIMIT);

		for (int length : new int[]{Integer.MIN_VALUE, -1, 0, 1, 2, 255, 2049, Integer.MAX_VALUE})
			Assertions.assertFalse(RsaPublicKeys.isWithinSignatureLengthBounds(length), () -> "" + length);
		for (int length : new int[]{256, 257, 384, 512, 1024, 2047, 2048})
			Assertions.assertTrue(RsaPublicKeys.isWithinSignatureLengthBounds(length), () -> "" + length);
	}

	// Deliberate null inputs verify runtime rejection.
	@SuppressWarnings("NullAway")
	@Test
	void rejectsNullArguments() {
		Assertions.assertThrows(NullPointerException.class, () -> RsaPublicKeys.fromComponents(nullValue(), new byte[1]));
		Assertions.assertThrows(NullPointerException.class, () -> RsaPublicKeys.fromComponents(new byte[1], nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> RsaPublicKeys.checkPublicKey(nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> RsaPublicKeys.isRocaFingerprinted(nullValue()));
	}

	/**
	 * An odd modulus of exactly {@code bits} bits with no special structure, for size checks that never sign.
	 */
	static @NonNull BigInteger syntheticModulus(int bits) {
		return BigInteger.ONE.shiftLeft(bits - 1).add(BigInteger.valueOf(0x5_2e_76_65_74L).shiftLeft(bits / 3))
				.add(BigInteger.valueOf(0x7365_6331L)).setBit(0);
	}

	/**
	 * {@code value} as minimal unsigned big-endian bytes (one zero byte for zero).
	 */
	static byte @NonNull [] unsigned(@NonNull BigInteger value) {
		byte[] bytes = value.toByteArray();
		return bytes.length > 1 && bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
	}

	private static byte @NonNull [] sign(@NonNull String algorithm, @NonNull PrivateKey privateKey) throws GeneralSecurityException {
		Signature signer = Signature.getInstance(algorithm);
		signer.initSign(privateKey);
		signer.update(MESSAGE);
		return signer.sign();
	}

	private static void assertRejected(KeyRejectedException.@NonNull Kind kind, byte @NonNull [] modulus, byte @NonNull [] exponent) {
		Assertions.assertEquals(kind, Assertions.assertThrows(KeyRejectedException.class,
				() -> RsaPublicKeys.fromComponents(modulus, exponent)).getKind());
	}

	private static void assertCheckRejected(KeyRejectedException.@NonNull Kind kind, @NonNull RSAPublicKey key) {
		Assertions.assertEquals(kind, Assertions.assertThrows(KeyRejectedException.class,
				() -> RsaPublicKeys.checkPublicKey(key)).getKind());
	}

	/**
	 * Hides a {@code null} from NullAway, for the tests that check null handling.
	 */
	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> @Nullable T nullValue() {
		return null;
	}

	/**
	 * A ROCA-structured RSA key: its modulus and a private key for signing.
	 */
	static final class RocaKey {
		final BigInteger modulus;
		final PrivateKey privateKey;

		private RocaKey(@NonNull BigInteger modulus, @NonNull PrivateKey privateKey) {
			this.modulus = modulus;
			this.privateKey = privateKey;
		}
	}

	/**
	 * Keys generated once per test run.
	 */
	static final class Keys {
		private static final KeyPair RSA_2048 = generateRsa2048();
		private static final RocaKey ROCA = generateRoca();

		private Keys() {
		}

		static @NonNull KeyPair rsa2048() {
			return RSA_2048;
		}

		static @NonNull RocaKey roca() {
			return ROCA;
		}

		private static @NonNull KeyPair generateRsa2048() {
			try {
				KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
				generator.initialize(2048);
				return generator.generateKeyPair();
			} catch (GeneralSecurityException exception) {
				throw new IllegalStateException(exception);
			}
		}

		/**
		 * Two 1024-bit primes of the form {@code k * M + (65537^a mod M)}, where {@code M} is 2 times the product of
		 * the 38 ROCA primes (Nemec et al., CCS 2017, section 2), from a fixed seed, and the 2048-bit key they make.
		 */
		private static @NonNull RocaKey generateRoca() {
			Random random = new Random(0x524f4341L);
			BigInteger primorial = RsaPublicKeys.ROCA_PRIMES.stream().map(BigInteger::valueOf)
					.reduce(BigInteger.TWO, BigInteger::multiply);

			while (true) {
				BigInteger p = rocaPrime(random, primorial);
				BigInteger q = rocaPrime(random, primorial);
				BigInteger modulus = p.multiply(q);
				BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

				if (modulus.bitLength() != 2048 || !phi.gcd(F4).equals(BigInteger.ONE) || p.equals(q))
					continue;

				try {
					PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateKeySpec(modulus,
							F4.modInverse(phi)));
					return new RocaKey(modulus, privateKey);
				} catch (GeneralSecurityException exception) {
					throw new IllegalStateException(exception);
				}
			}
		}

		/**
		 * A prime {@code k * M + (65537^a mod M)} in {@code (sqrt(2^2047), 2^1024)}, so that the product of two of them
		 * always has exactly 2048 bits. Drawing the multiplier from all 1024-bit products instead never ends here: the
		 * primorial's leading digits (about 1.14 * 2^219) put every such prime below 1.15 * 2^1023, and the product of
		 * two below 2^2047.
		 */
		private static @NonNull BigInteger rocaPrime(@NonNull Random random, @NonNull BigInteger primorial) {
			BigInteger floor = BigInteger.ONE.shiftLeft(2047).sqrt().add(BigInteger.ONE);
			BigInteger limit = BigInteger.ONE.shiftLeft(1024);
			// Multipliers in [smallest, smallest + span) keep k * M + residue inside (floor, limit) for any residue < M.
			BigInteger smallest = floor.divide(primorial).add(BigInteger.ONE);
			BigInteger span = limit.divide(primorial).subtract(smallest);

			while (true) {
				BigInteger residue = F4.modPow(BigInteger.valueOf(random.nextInt(1 << 20)), primorial);
				BigInteger offset = new BigInteger(span.bitLength(), random);

				if (offset.compareTo(span) >= 0)
					continue;

				BigInteger candidate = smallest.add(offset).multiply(primorial).add(residue);

				if (candidate.compareTo(floor) >= 0 && candidate.compareTo(limit) < 0 && candidate.isProbablePrime(64))
					return candidate;
			}
		}
	}

	/**
	 * An {@link RSAPublicKey} implementation outside the JDK, which may report nothing or throw.
	 */
	@SuppressWarnings("NullAway")
	static final class UnusualRsaKey implements RSAPublicKey {
		private static final long serialVersionUID = 1L;

		private final @Nullable BigInteger modulus;
		private final @Nullable BigInteger exponent;
		private final boolean throwing;

		UnusualRsaKey(@Nullable BigInteger modulus, @Nullable BigInteger exponent, boolean throwing) {
			this.modulus = modulus;
			this.exponent = exponent;
			this.throwing = throwing;
		}

		@Override
		public @NonNull BigInteger getModulus() {
			if (this.throwing)
				throw new IllegalStateException("A key implementation that throws.");
			return this.modulus;
		}

		@Override
		public @NonNull BigInteger getPublicExponent() {
			return this.exponent;
		}

		@Override
		public @NonNull String getAlgorithm() {
			return "RSA";
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
