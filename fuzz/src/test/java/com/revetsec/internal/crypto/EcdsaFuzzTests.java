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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.junit.jupiter.api.Assertions;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Coverage-guided checks for the fixed-length ECDSA path of {@code internal.crypto}: {@link EcdsaSignatures} and
 * {@link SignatureVerifier#verifyEcdsa} (M2 plan, G8-3 and INV-J5; exit criterion 6; CVE-2022-21449).
 * <p>
 * The oracles are written here: the length and range rule of RFC 7518 section 3.4 over each curve's order as the JDK
 * names the curve ({@code secp256r1}, {@code secp384r1}, {@code secp521r1}), never {@link EcCurve}'s own constants; an
 * X.690 DER reader (sections 8.1.3, 8.3 and 10.1) that accepts only the minimal encoding; and, for verdicts, the JDK's
 * own fixed-length engines ({@code SHAxxxwithECDSAinP1363Format}), which the main code never uses (M2-10's
 * {@code p1363-signature-name} rule). The JDK's fixed-length engine accepts signatures that are too short, so the
 * oracle applies the exact length first, as RFC 7518 does.
 * <p>
 * The keys are fuzz-only: two per curve and one Ed25519 key, generated when the class loads from a fixed
 * {@code SHA1PRNG} seed, so a run's keys never change.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public class EcdsaFuzzTests {
	private static final List<Curve> CURVES = List.of(Curve.named(EcCurve.P_256, "secp256r1", HashAlgorithm.SHA_256, 1),
			Curve.named(EcCurve.P_384, "secp384r1", HashAlgorithm.SHA_384, 2),
			Curve.named(EcCurve.P_521, "secp521r1", HashAlgorithm.SHA_512, 3));
	private static final List<HashAlgorithm> HASHES = List.of(HashAlgorithm.SHA_256, HashAlgorithm.SHA_384,
			HashAlgorithm.SHA_512);
	private static final Map<HashAlgorithm, String> FIXED_LENGTH_ENGINES = Map.of(
			HashAlgorithm.SHA_256, "SHA256withECDSAinP1363Format", HashAlgorithm.SHA_384, "SHA384withECDSAinP1363Format",
			HashAlgorithm.SHA_512, "SHA512withECDSAinP1363Format");
	private static final Map<HashAlgorithm, String> DER_ENGINES = Map.of(HashAlgorithm.SHA_256, "SHA256withECDSA",
			HashAlgorithm.SHA_384, "SHA384withECDSA", HashAlgorithm.SHA_512, "SHA512withECDSA");
	private static final PublicKey ED25519_KEY = generate("Ed25519", null, 4).getPublic();
	private static final byte[] MESSAGE = "Revetsec ECDSA fuzz message".getBytes(StandardCharsets.US_ASCII);
	private static final int MUTATIONS = 12;

	/**
	 * For every curve, {@link EcdsaSignatures#findShapeFailure} gives exactly the RFC 7518 section 3.4 verdict: the
	 * wrong length first, then {@code r} or {@code s} outside {@code [1, n - 1]}. {@link EcdsaSignatures#toDer} refuses
	 * a signature of the wrong length and otherwise gives the minimal DER {@code SEQUENCE} of the two {@code INTEGER}s,
	 * which the X.690 reader here reads back to the same {@code r} and {@code s}. {@link SignatureVerifier#verifyEcdsa}
	 * decides the shape before it looks at the key: with a key of another curve, or no EC key at all, a malformed
	 * signature keeps its shape result and any other signature is a mismatch. The input array is never modified.
	 *
	 * @param signature the fuzzed signature
	 */
	@FuzzTest(maxDuration = "5m")
	public void shapeCheckAndDerEncodingAgreeWithTheRangeRuleAndAnX690Reader(byte[] signature) {
		byte[] original = signature.clone();

		for (Curve curve : CURVES) {
			Optional<VerifyResult> expected = expectedShape(curve, signature);
			Assertions.assertEquals(expected, EcdsaSignatures.findShapeFailure(curve.ecCurve, signature),
					"the shape check disagrees with RFC 7518 section 3.4");

			if (signature.length != curve.signatureLength) {
				Assertions.assertThrows(IllegalArgumentException.class, () -> EcdsaSignatures.toDer(curve.ecCurve, signature),
						"toDer accepted a signature of the wrong length");
			} else {
				byte[] der = EcdsaSignatures.toDer(curve.ecCurve, signature);
				BigInteger[] integers = DerReader.readSignature(der);
				Assertions.assertEquals(curve.r(signature), integers[0], "the DER form does not hold r");
				Assertions.assertEquals(curve.s(signature), integers[1], "the DER form does not hold s");
			}

			PublicKey otherCurveKey = CURVES.get((CURVES.indexOf(curve) + 1) % CURVES.size()).keyPairs.get(0).getPublic();
			Assertions.assertEquals(expected.orElse(VerifyResult.MISMATCH),
					SignatureVerifier.verifyEcdsa(curve.ecCurve, curve.hash, otherCurveKey, MESSAGE, signature),
					"a key of another curve did not wait for the shape check, or verified");
			Assertions.assertEquals(expected.orElse(VerifyResult.MISMATCH),
					SignatureVerifier.verifyEcdsa(curve.ecCurve, curve.hash, ED25519_KEY, MESSAGE, signature),
					"a key that is not an EC key did not wait for the shape check, or verified");
		}

		Assertions.assertArrayEquals(original, signature, "the signature was modified");
	}

	/**
	 * {@link SignatureVerifier#verifyEcdsa} is {@link VerifyResult#VALID} exactly when the JDK's own fixed-length engine
	 * verifies a signature of the exact length with {@code r} and {@code s} in range, under a key on the named curve;
	 * otherwise it is the shape result, or {@link VerifyResult#MISMATCH} (the engine said no, or the key is not on the
	 * curve), or {@link VerifyResult#PROVIDER_FAILURE} only where the engine itself threw. Signatures come from the
	 * fuzzer, or from signing the fuzzed message and then damaging the result: a flipped bit, {@code r} or {@code s}
	 * set to 0, 1, {@code n - 1}, {@code n}, {@code n + 1}, the field prime or all ones, the high-S twin
	 * {@code n - s} (which is valid: ECDSA is malleable), swapped halves, a byte cut or added, halves padded to another
	 * curve's length, or the DER form. The curve and the hash are chosen separately, as the API allows.
	 *
	 * @param data the fuzzed choices
	 */
	@FuzzTest(maxDuration = "5m")
	public void verdictsAgreeWithTheJdksFixedLengthEngine(FuzzedDataProvider data) {
		Curve curve = data.pickValue(CURVES);
		HashAlgorithm hash = data.consumeBoolean() ? data.pickValue(HASHES) : curve.hash;
		KeyPair signer = data.pickValue(curve.keyPairs);
		byte[] message = data.consumeBytes(data.consumeInt(0, 512));
		byte[] signature;

		if (data.consumeBoolean()) {
			signature = data.consumeBytes(data.consumeInt(0, 140));
		} else {
			signature = mutated(curve, sign(FIXED_LENGTH_ENGINES.get(hash), signer.getPrivate(), message, data.consumeLong()),
					data, hash, signer.getPrivate(), message);
		}

		// Choice 0, which an exhausted input gives, is the signer's own key.
		PublicKey verifyingKey = switch (data.consumeInt(0, 3)) {
			case 1 -> curve.keyPairs.get(1 - curve.keyPairs.indexOf(signer)).getPublic();
			case 2 -> CURVES.get((CURVES.indexOf(curve) + 1) % CURVES.size()).keyPairs.get(0).getPublic();
			case 3 -> ED25519_KEY;
			default -> signer.getPublic();
		};

		byte[] messageCopy = message.clone();
		byte[] signatureCopy = signature.clone();
		VerifyResult actual = SignatureVerifier.verifyEcdsa(curve.ecCurve, hash, verifyingKey, message, signature);
		Assertions.assertArrayEquals(messageCopy, message, "the message was modified");
		Assertions.assertArrayEquals(signatureCopy, signature, "the signature was modified");

		Optional<VerifyResult> shape = expectedShape(curve, signature);

		if (shape.isPresent()) {
			Assertions.assertEquals(shape.get(), actual, "the shape result was not decided first");
			return;
		}

		if (!(verifyingKey instanceof ECPublicKey ecKey) || !curve.describes(ecKey.getParams())) {
			Assertions.assertEquals(VerifyResult.MISMATCH, actual, "a key off the curve was not a mismatch");
			return;
		}

		Boolean engine = fixedLengthVerdict(hash, verifyingKey, message, signature);

		if (engine == null)
			Assertions.assertNotEquals(VerifyResult.VALID, actual, "verified what the JDK's fixed-length engine refused");
		else
			Assertions.assertEquals(engine ? VerifyResult.VALID : VerifyResult.MISMATCH, actual,
					"the verdict disagrees with the JDK's fixed-length engine");
	}

	/**
	 * RFC 7518 section 3.4: exactly twice the coordinate length, then {@code 1 <= r, s <= n - 1}.
	 */
	private static Optional<VerifyResult> expectedShape(Curve curve, byte[] signature) {
		if (signature.length != curve.signatureLength)
			return Optional.of(VerifyResult.WRONG_LENGTH);

		BigInteger r = curve.r(signature);
		BigInteger s = curve.s(signature);

		if (r.signum() <= 0 || r.compareTo(curve.order) >= 0 || s.signum() <= 0 || s.compareTo(curve.order) >= 0)
			return Optional.of(VerifyResult.OUT_OF_RANGE);

		return Optional.empty();
	}

	/**
	 * The JDK's fixed-length engine: {@code true} or {@code false}, or {@code null} if it threw.
	 */
	private static Boolean fixedLengthVerdict(HashAlgorithm hash, PublicKey key, byte[] message, byte[] signature) {
		try {
			Signature engine = Signature.getInstance(FIXED_LENGTH_ENGINES.get(hash));
			engine.initVerify(key);
			engine.update(message);
			return engine.verify(signature);
		} catch (GeneralSecurityException | RuntimeException e) {
			return null;
		}
	}

	private static byte[] mutated(Curve curve, byte[] signature, FuzzedDataProvider data, HashAlgorithm hash,
																PrivateKey signer, byte[] message) {
		int length = curve.coordinateLength;
		BigInteger r = curve.r(signature);
		BigInteger s = curve.s(signature);

		return switch (data.consumeInt(0, MUTATIONS - 1)) {
			case 1 -> {
				byte[] flipped = signature.clone();
				int bit = data.consumeInt(0, flipped.length * 8 - 1);
				flipped[bit / 8] ^= (byte) (1 << (bit % 8));
				yield flipped;
			}
			case 2 -> curve.fixedLength(special(curve, data), s, length);
			case 3 -> curve.fixedLength(r, special(curve, data), length);
			case 4 -> curve.fixedLength(r, curve.order.subtract(s), length);
			case 5 -> curve.fixedLength(s, r, length);
			case 6 -> Arrays.copyOf(signature, signature.length - 1);
			case 7 -> Arrays.copyOf(signature, signature.length + 1);
			case 8 -> curve.fixedLength(r, s, length + 1);
			case 9 -> curve.fixedLength(r, s, CURVES.get((CURVES.indexOf(curve) + 1) % CURVES.size()).coordinateLength);
			case 10 -> curve.fixedLength(r, r, length);
			case 11 -> sign(DER_ENGINES.get(hash), signer, message, data.consumeLong());
			default -> signature;
		};
	}

	/**
	 * A value for {@code r} or {@code s} at or just past an edge of its range, or from the fuzzer.
	 */
	private static BigInteger special(Curve curve, FuzzedDataProvider data) {
		return switch (data.consumeInt(0, 7)) {
			case 0 -> BigInteger.ZERO;
			case 1 -> BigInteger.ONE;
			case 2 -> curve.order.subtract(BigInteger.ONE);
			case 3 -> curve.order;
			case 4 -> curve.order.add(BigInteger.ONE);
			case 5 -> curve.fieldPrime;
			case 6 -> BigInteger.ONE.shiftLeft(8 * curve.coordinateLength).subtract(BigInteger.ONE);
			default -> new BigInteger(1, data.consumeBytes(curve.coordinateLength));
		};
	}

	private static byte[] sign(String engineName, PrivateKey key, byte[] message, long seed) {
		try {
			Signature engine = Signature.getInstance(engineName);
			engine.initSign(key, seededRandom(seed));
			engine.update(message);
			return engine.sign();
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("The JDK could not sign with a fuzz-only key", e);
		}
	}

	private static SecureRandom seededRandom(long seed) {
		try {
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			random.setSeed(seed);
			return random;
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("The JDK has no SHA1PRNG", e);
		}
	}

	private static KeyPair generate(String algorithm, String curveName, long seed) {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);

			if (curveName != null)
				generator.initialize(new ECGenParameterSpec(curveName), seededRandom(seed));
			else
				generator.initialize(NamedParameterSpec.ED25519, seededRandom(seed));

			return generator.generateKeyPair();
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("The JDK could not generate a fuzz-only key", e);
		}
	}

	/**
	 * A curve as the JDK names it, with its order and field from the JDK's own parameters.
	 */
	@Immutable
	private static final class Curve {
		private final EcCurve ecCurve;
		private final ECParameterSpec parameters;
		private final BigInteger order;
		private final BigInteger fieldPrime;
		private final int coordinateLength;
		private final int signatureLength;
		private final HashAlgorithm hash;
		private final List<KeyPair> keyPairs;

		private Curve(EcCurve ecCurve, ECParameterSpec parameters, HashAlgorithm hash, List<KeyPair> keyPairs) {
			this.ecCurve = ecCurve;
			this.parameters = parameters;
			this.order = parameters.getOrder();
			this.fieldPrime = ((ECFieldFp) parameters.getCurve().getField()).getP();
			this.coordinateLength = (this.fieldPrime.bitLength() + 7) / 8;
			this.signatureLength = 2 * this.coordinateLength;
			this.hash = hash;
			this.keyPairs = List.copyOf(keyPairs);
		}

		private static Curve named(EcCurve ecCurve, String jdkName, HashAlgorithm hash, long seed) {
			try {
				AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
				parameters.init(new ECGenParameterSpec(jdkName));
				return new Curve(ecCurve, parameters.getParameterSpec(ECParameterSpec.class), hash,
						List.of(generate("EC", jdkName, 10 * seed), generate("EC", jdkName, 10 * seed + 1)));
			} catch (GeneralSecurityException e) {
				throw new IllegalStateException("The JDK does not name " + jdkName, e);
			}
		}

		private BigInteger r(byte[] signature) {
			return new BigInteger(1, Arrays.copyOfRange(signature, 0, this.coordinateLength));
		}

		private BigInteger s(byte[] signature) {
			return new BigInteger(1, Arrays.copyOfRange(signature, this.coordinateLength, 2 * this.coordinateLength));
		}

		/**
		 * {@code r || s}, each big-endian in {@code length} octets, keeping the low octets of a larger value.
		 */
		private byte[] fixedLength(BigInteger r, BigInteger s, int length) {
			byte[] signature = new byte[2 * length];
			put(r, signature, 0, length);
			put(s, signature, length, length);
			return signature;
		}

		private static void put(BigInteger value, byte[] target, int offset, int length) {
			byte[] bytes = value.toByteArray();

			for (int index = 0; index < length && index < bytes.length; ++index)
				target[offset + length - 1 - index] = bytes[bytes.length - 1 - index];
		}

		/**
		 * Whether {@code other} is this curve: the same field, coefficients, generator, order and cofactor.
		 */
		private boolean describes(ECParameterSpec other) {
			return other != null && other.getCurve().equals(this.parameters.getCurve())
					&& other.getGenerator().equals(this.parameters.getGenerator())
					&& other.getOrder().equals(this.parameters.getOrder())
					&& other.getCofactor() == this.parameters.getCofactor();
		}
	}

	/**
	 * A strict X.690 DER reader for {@code SEQUENCE { INTEGER, INTEGER }}: definite lengths in their shortest form, each
	 * {@code INTEGER} in its fewest octets and non-negative, and nothing after the {@code SEQUENCE}.
	 */
	@NotThreadSafe
	private static final class DerReader {
		private final byte[] der;
		private int position;

		private DerReader(byte[] der) {
			this.der = der;
		}

		private static BigInteger[] readSignature(byte[] der) {
			DerReader reader = new DerReader(der);
			Assertions.assertEquals(0x30, reader.next(), "the DER form is not a SEQUENCE");
			int length = reader.length();
			Assertions.assertEquals(der.length, reader.position + length, "the SEQUENCE length does not end the encoding");
			BigInteger r = reader.integer();
			BigInteger s = reader.integer();
			Assertions.assertEquals(der.length, reader.position, "the SEQUENCE holds more than two INTEGERs");
			return new BigInteger[]{r, s};
		}

		private int next() {
			Assertions.assertTrue(this.position < this.der.length, "the DER form ends early");
			return this.der[this.position++] & 0xFF;
		}

		/**
		 * X.690 sections 8.1.3 and 10.1: the short form below 128, else the long form in the fewest octets.
		 */
		private int length() {
			int first = next();

			if (first < 0x80)
				return first;

			int octets = first & 0x7F;
			Assertions.assertTrue(octets >= 1 && octets <= 3, "an indefinite or oversized length");
			int length = 0;

			for (int index = 0; index < octets; ++index) {
				int octet = next();
				Assertions.assertFalse(index == 0 && octet == 0, "a long-form length with a leading zero octet");
				length = (length << 8) | octet;
			}

			Assertions.assertTrue(length >= 0x80, "a long-form length that fits the short form");
			return length;
		}

		/**
		 * X.690 section 8.3: at least one content octet, and no leading 0x00 or 0xFF that the next octet makes redundant.
		 */
		private BigInteger integer() {
			Assertions.assertEquals(0x02, next(), "an element that is not an INTEGER");
			int length = length();
			Assertions.assertTrue(length >= 1 && this.position + length <= this.der.length, "a bad INTEGER length");
			byte[] content = Arrays.copyOfRange(this.der, this.position, this.position + length);
			this.position += length;

			if (content.length > 1) {
				Assertions.assertFalse(content[0] == 0 && (content[1] & 0x80) == 0, "an INTEGER with a redundant 0x00");
				Assertions.assertFalse(content[0] == (byte) 0xFF && (content[1] & 0x80) != 0,
						"an INTEGER with a redundant 0xFF");
			}

			BigInteger value = new BigInteger(content);
			Assertions.assertTrue(value.signum() >= 0, "a negative INTEGER");
			return value;
		}
	}
}
