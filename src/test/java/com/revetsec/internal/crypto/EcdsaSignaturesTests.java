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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.stream.Stream;

/**
 * {@link EcdsaSignatures}: the plan's ECDSA edge table (gate 8's G8-3, INV-J5) on P-256, P-384 and P-521, and the
 * minimal DER encoding (X.690 sections 8.3 and 10.1), checked by a strict DER reader in this class and byte for byte
 * against the JDK's own DER signatures. The fixed-length JDK signer is a test oracle only; main code never uses it.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class EcdsaSignaturesTests {
	static final byte[] MESSAGE = "Revetsec ECDSA edge table".getBytes(StandardCharsets.US_ASCII);

	// G8-3 and INV-J5: exact length, then 1 <= r, s <= n - 1, with no key and no JCA call; CVE-2022-21449 is r = s = 0.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> theEdgeTableGivesItsShapeResultWithoutAKey() {
		return Stream.of(EcCurve.values()).flatMap(curve -> {
			Fixture fixture = Fixture.forCurve(curve);
			int length = curve.getCoordinateLength();
			BigInteger n = curve.getOrder();
			BigInteger r = fixture.r;
			BigInteger s = fixture.s;
			BigInteger allOnes = BigInteger.ONE.shiftLeft(8 * length).subtract(BigInteger.ONE);
			List<Row> rows = new ArrayList<>();

			rows.add(new Row("valid", fixture.signature, null, VerifyResult.VALID));
			rows.add(new Row("high S (s' = n - s) is valid ECDSA", raw(curve, r, n.subtract(s)), null, VerifyResult.VALID));
			rows.add(new Row("r = 1, s = 1 (the lower bound)", raw(curve, BigInteger.ONE, BigInteger.ONE), null,
					VerifyResult.MISMATCH));
			rows.add(new Row("r = n - 1, s = n - 1 (the upper bound)",
					raw(curve, n.subtract(BigInteger.ONE), n.subtract(BigInteger.ONE)), null, VerifyResult.MISMATCH));
			rows.add(new Row("r = 0 (CVE-2022-21449)", raw(curve, BigInteger.ZERO, s), VerifyResult.OUT_OF_RANGE, null));
			rows.add(new Row("s = 0", raw(curve, r, BigInteger.ZERO), VerifyResult.OUT_OF_RANGE, null));
			rows.add(new Row("r = s = 0", raw(curve, BigInteger.ZERO, BigInteger.ZERO), VerifyResult.OUT_OF_RANGE, null));
			rows.add(new Row("all zero octets", new byte[curve.getSignatureLength()], VerifyResult.OUT_OF_RANGE, null));
			rows.add(new Row("r = n", raw(curve, n, s), VerifyResult.OUT_OF_RANGE, null));
			rows.add(new Row("s = n", raw(curve, r, n), VerifyResult.OUT_OF_RANGE, null));
			rows.add(new Row("r = n + 1", raw(curve, n.add(BigInteger.ONE), s), VerifyResult.OUT_OF_RANGE, null));
			rows.add(new Row("s = n + 1", raw(curve, r, n.add(BigInteger.ONE)), VerifyResult.OUT_OF_RANGE, null));
			rows.add(new Row("r = 2^(8L) - 1", raw(curve, allOnes, s), VerifyResult.OUT_OF_RANGE, null));
			rows.add(new Row("s = 2^(8L) - 1", raw(curve, r, allOnes), VerifyResult.OUT_OF_RANGE, null));

			// r + n and s + n fit in the fixed length only on P-521, whose order is far below 2^528.
			if (r.add(n).compareTo(allOnes) <= 0) {
				rows.add(new Row("r + n", raw(curve, r.add(n), s), VerifyResult.OUT_OF_RANGE, null));
				rows.add(new Row("s + n", raw(curve, r, s.add(n)), VerifyResult.OUT_OF_RANGE, null));
			}

			byte[] signature = fixture.signature;
			rows.add(new Row("empty", new byte[0], VerifyResult.WRONG_LENGTH, null));
			rows.add(new Row("one byte short", Arrays.copyOf(signature, signature.length - 1), VerifyResult.WRONG_LENGTH,
					null));
			rows.add(new Row("a trailing zero byte", Arrays.copyOf(signature, signature.length + 1),
					VerifyResult.WRONG_LENGTH, null));
			rows.add(new Row("each half zero-padded by one byte (a DER path without the check accepts it)",
					concat(new byte[1], Arrays.copyOfRange(signature, 0, length), new byte[1],
							Arrays.copyOfRange(signature, length, 2 * length)), VerifyResult.WRONG_LENGTH, null));
			rows.add(new Row("the other curves' lengths", new byte[2 * (length == 32 ? 48 : 32)],
					VerifyResult.WRONG_LENGTH, null));
			rows.add(new Row("the DER form of a valid signature", fixture.derSignature, VerifyResult.WRONG_LENGTH, null));

			return rows.stream().map(row -> DynamicTest.dynamicTest(curve.name() + ": " + row.name, () -> {
				Assertions.assertEquals(Optional.ofNullable(row.shapeFailure),
						EcdsaSignatures.findShapeFailure(curve, row.signature));

				VerifyResult expected = row.shapeFailure != null ? row.shapeFailure : row.verification;
				Assertions.assertEquals(expected, SignatureVerifier.verifyEcdsa(curve, fixture.hash, fixture.publicKey,
						MESSAGE, row.signature));
			}));
		});
	}

	// X.690 section 8.3.2: an INTEGER's content is minimal two's complement; section 10.1: definite lengths in the
	// fewest octets. Each value is read back by a strict reader and equals r and s.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> derEncodingIsMinimalAndRoundTrips() {
		return Stream.of(EcCurve.values()).map(curve -> DynamicTest.dynamicTest(curve.name(), () -> {
			BigInteger n = curve.getOrder();
			int length = curve.getCoordinateLength();
			Random random = new Random(curve.getCoordinateLength());
			List<BigInteger[]> pairs = new ArrayList<>();

			pairs.add(new BigInteger[]{BigInteger.ONE, BigInteger.ONE});
			pairs.add(new BigInteger[]{BigInteger.valueOf(0x7f), BigInteger.valueOf(0x80)});
			pairs.add(new BigInteger[]{BigInteger.valueOf(0xff), BigInteger.valueOf(0x100)});
			pairs.add(new BigInteger[]{n.subtract(BigInteger.ONE), n.subtract(BigInteger.ONE)});
			// Top bit set in a full-length half: the INTEGER needs a leading zero octet.
			pairs.add(new BigInteger[]{BigInteger.ONE.shiftLeft(8 * length - 1), BigInteger.ONE});
			// Values with leading zero octets in the fixed-length form: the INTEGER is shorter than the half.
			pairs.add(new BigInteger[]{BigInteger.ONE.shiftLeft(8 * length - 20), BigInteger.ONE.shiftLeft(8)});
			// Outside the range, which toDer does not check: zero and the largest fixed-length value.
			pairs.add(new BigInteger[]{BigInteger.ZERO, BigInteger.ONE.shiftLeft(8 * length).subtract(BigInteger.ONE)});

			for (int index = 0; index < 200; ++index)
				pairs.add(new BigInteger[]{new BigInteger(8 * length, random), new BigInteger(8 * length - random.nextInt(24),
						random)});

			for (BigInteger[] pair : pairs) {
				byte[] signature = raw(curve, pair[0], pair[1]);
				byte[] copy = signature.clone();
				byte[] der = EcdsaSignatures.toDer(curve, signature);

				Assertions.assertArrayEquals(copy, signature, "the input is not modified");
				Assertions.assertEquals(List.of(pair[0], pair[1]), readStrictDer(der), () -> pair[0] + ", " + pair[1]);
			}
		}));
	}

	// The JDK's DER signer emits minimal DER; decoding it to r || s and re-encoding gives the same bytes, and the
	// SEQUENCE takes the one-octet long form exactly when its content reaches 128 octets (only on P-521).
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> derEncodingEqualsTheJdksOwnDerSignatures() {
		return Stream.of(EcCurve.values()).map(curve -> DynamicTest.dynamicTest(curve.name(), () -> {
			Fixture fixture = Fixture.forCurve(curve);
			Signature signer = Signature.getInstance(fixture.hash.getEcdsaSignatureName());
			boolean sawLongForm = false;

			for (int index = 0; index < 64; ++index) {
				signer.initSign(fixture.keyPair.getPrivate());
				signer.update(MESSAGE);
				byte[] jdkDer = signer.sign();
				List<BigInteger> values = readStrictDer(jdkDer);
				byte[] signature = raw(curve, values.get(0), values.get(1));

				Assertions.assertArrayEquals(jdkDer, EcdsaSignatures.toDer(curve, signature));
				Assertions.assertEquals(Optional.empty(), EcdsaSignatures.findShapeFailure(curve, signature));
				sawLongForm |= (jdkDer[1] & 0xff) == 0x81;
			}

			Assertions.assertEquals(curve == EcCurve.P_521, sawLongForm);
			Assertions.assertArrayEquals(new byte[]{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02},
					EcdsaSignatures.toDer(curve, raw(curve, BigInteger.ONE, BigInteger.TWO)), "short form on every curve");
		}));
	}

	// X.690 sections 8.1.3.3 and 10.1: the short form covers lengths up to 127, and 128 needs the one-octet long form.
	// On P-521, 62- and 61-octet INTEGERs make a 127-octet SEQUENCE content, and two 62-octet INTEGERs make 128.
	@Test
	void derSequenceLengthTakesTheLongFormFromExactly128Octets() {
		EcCurve curve = EcCurve.P_521;
		// 2^494 has 495 bits, so its minimal INTEGER content is 62 octets with no sign padding; 2^486 needs 61.
		BigInteger sixtyTwoOctets = BigInteger.ONE.shiftLeft(8 * 62 - 2);
		BigInteger sixtyOneOctets = BigInteger.ONE.shiftLeft(8 * 61 - 2);

		byte[] shortForm = EcdsaSignatures.toDer(curve, raw(curve, sixtyTwoOctets, sixtyOneOctets));
		byte[] longForm = EcdsaSignatures.toDer(curve, raw(curve, sixtyTwoOctets, sixtyTwoOctets));

		Assertions.assertEquals(2 + 127, shortForm.length);
		Assertions.assertEquals(0x7f, shortForm[1] & 0xff);
		Assertions.assertEquals(List.of(sixtyTwoOctets, sixtyOneOctets), readStrictDer(shortForm));
		Assertions.assertEquals(3 + 128, longForm.length);
		Assertions.assertEquals(0x81, longForm[1] & 0xff);
		Assertions.assertEquals(0x80, longForm[2] & 0xff);
		Assertions.assertEquals(List.of(sixtyTwoOctets, sixtyTwoOctets), readStrictDer(longForm));
	}

	@Test
	void derEncodingRequiresTheCurvesSignatureLength() {
		for (EcCurve curve : EcCurve.values())
			for (int length : new int[]{0, curve.getSignatureLength() - 1, curve.getSignatureLength() + 1})
				Assertions.assertThrows(IllegalArgumentException.class, () -> EcdsaSignatures.toDer(curve, new byte[length]),
						() -> curve + " " + length);
	}

	// Deliberate null inputs verify runtime rejection.
	@SuppressWarnings("NullAway")
	@Test
	void rejectsNullArguments() {
		Assertions.assertThrows(NullPointerException.class, () -> EcdsaSignatures.findShapeFailure(nullValue(),
				new byte[64]));
		Assertions.assertThrows(NullPointerException.class, () -> EcdsaSignatures.findShapeFailure(EcCurve.P_256,
				nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> EcdsaSignatures.toDer(nullValue(), new byte[64]));
		Assertions.assertThrows(NullPointerException.class, () -> EcdsaSignatures.toDer(EcCurve.P_256, nullValue()));
	}

	/**
	 * The hash JOSE pairs with each curve (RFC 7518 section 3.4).
	 */
	static @NonNull HashAlgorithm hashFor(@NonNull EcCurve curve) {
		return switch (curve) {
			case P_256 -> HashAlgorithm.SHA_256;
			case P_384 -> HashAlgorithm.SHA_384;
			case P_521 -> HashAlgorithm.SHA_512;
		};
	}

	/**
	 * The fixed-length form {@code r || s} of two non-negative values that fit the curve's coordinate length.
	 */
	static byte @NonNull [] raw(@NonNull EcCurve curve, @NonNull BigInteger r, @NonNull BigInteger s) {
		return concat(fixed(r, curve.getCoordinateLength()), fixed(s, curve.getCoordinateLength()));
	}

	/**
	 * {@code value} as exactly {@code length} unsigned big-endian bytes.
	 */
	static byte @NonNull [] fixed(@NonNull BigInteger value, int length) {
		byte[] bytes = value.toByteArray();

		if (bytes.length > length) {
			Assertions.assertEquals(length + 1, bytes.length, "value too large for the fixed length");
			Assertions.assertEquals(0, bytes[0]);
			return Arrays.copyOfRange(bytes, 1, bytes.length);
		}

		byte[] padded = new byte[length];
		System.arraycopy(bytes, 0, padded, length - bytes.length, bytes.length);
		return padded;
	}

	static byte @NonNull [] concat(byte @NonNull [] @NonNull ... parts) {
		int length = 0;
		for (byte[] part : parts)
			length += part.length;

		byte[] joined = new byte[length];
		int position = 0;
		for (byte[] part : parts) {
			System.arraycopy(part, 0, joined, position, part.length);
			position += part.length;
		}

		return joined;
	}

	/**
	 * A strict DER reader for {@code SEQUENCE { INTEGER, INTEGER }} with non-negative values, which fails the test on
	 * anything X.690's DER rules forbid.
	 */
	static @NonNull List<@NonNull BigInteger> readStrictDer(byte @NonNull [] der) {
		Assertions.assertTrue(der.length >= 2, "too short");
		Assertions.assertEquals(0x30, der[0] & 0xff, "SEQUENCE tag");

		int position = 1;
		int contentLength;
		int first = der[position++] & 0xff;

		if (first < 0x80) {
			contentLength = first;
		} else {
			Assertions.assertEquals(0x81, first, "only the one-octet long form fits an ECDSA signature");
			contentLength = der[position++] & 0xff;
			Assertions.assertTrue(contentLength >= 0x80, "the long form is used only when the short form cannot be");
		}

		Assertions.assertEquals(der.length, position + contentLength, "no trailing or missing octets");

		List<BigInteger> values = new ArrayList<>();

		for (int index = 0; index < 2; ++index) {
			Assertions.assertEquals(0x02, der[position++] & 0xff, "INTEGER tag");
			int length = der[position++] & 0xff;
			Assertions.assertTrue(length > 0 && length < 0x80, "a non-empty INTEGER in the short form");
			byte[] content = Arrays.copyOfRange(der, position, position + length);
			position += length;
			Assertions.assertEquals(0, content[0] & 0x80, "a non-negative INTEGER");
			if (content.length > 1)
				Assertions.assertFalse(content[0] == 0 && (content[1] & 0x80) == 0, "a minimal INTEGER");
			values.add(new BigInteger(content));
		}

		Assertions.assertEquals(der.length, position);
		return values;
	}

	/**
	 * Hides a {@code null} from NullAway, for the tests that check null handling.
	 */
	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> @Nullable T nullValue() {
		return null;
	}

	/**
	 * A key pair on one curve, its hash, and one valid signature of {@link #MESSAGE} in both forms.
	 */
	static final class Fixture {
		final HashAlgorithm hash;
		final KeyPair keyPair;
		final PublicKey publicKey;
		final byte[] signature;
		final byte[] derSignature;
		final BigInteger r;
		final BigInteger s;

		private Fixture(@NonNull HashAlgorithm hash, @NonNull KeyPair keyPair, byte @NonNull [] signature, byte @NonNull [] derSignature, int length) {
			this.hash = hash;
			this.keyPair = keyPair;
			this.publicKey = keyPair.getPublic();
			this.signature = signature;
			this.derSignature = derSignature;
			this.r = new BigInteger(1, Arrays.copyOfRange(signature, 0, length));
			this.s = new BigInteger(1, Arrays.copyOfRange(signature, length, 2 * length));
		}

		static @NonNull Fixture forCurve(@NonNull EcCurve curve) {
			HashAlgorithm hash = hashFor(curve);

			try {
				KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
				generator.initialize(new ECGenParameterSpec(curve.getStandardName()));
				KeyPair keyPair = generator.generateKeyPair();
				// The fixed-length JDK signer is a test oracle; main code DER-encodes and uses SHAxxxwithECDSA.
				Signature signer = Signature.getInstance(hash.getEcdsaSignatureName() + "inP1363Format");
				signer.initSign(keyPair.getPrivate());
				signer.update(MESSAGE);
				byte[] signature = signer.sign();
				Signature derSigner = Signature.getInstance(hash.getEcdsaSignatureName());
				derSigner.initSign(keyPair.getPrivate());
				derSigner.update(MESSAGE);

				return new Fixture(hash, keyPair, signature, derSigner.sign(), curve.getCoordinateLength());
			} catch (GeneralSecurityException exception) {
				throw new IllegalStateException(exception);
			}
		}
	}

	/**
	 * One edge-table row: the shape check's result (null if the shape passes), and the full verification's result for
	 * a signature whose shape passes.
	 */
	private static final class Row {
		private final String name;
		private final byte[] signature;
		private final @Nullable VerifyResult shapeFailure;
		private final @Nullable VerifyResult verification;

		private Row(@NonNull String name, byte @NonNull [] signature, @Nullable VerifyResult shapeFailure,
								@Nullable VerifyResult verification) {
			this.name = name;
			this.signature = signature;
			this.shapeFailure = shapeFailure;
			this.verification = verification;
		}
	}
}
