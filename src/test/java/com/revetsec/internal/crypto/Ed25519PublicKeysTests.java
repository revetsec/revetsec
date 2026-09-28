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

import com.revetsec.internal.encoding.Base64Url;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * {@link Ed25519PublicKeys}: the RFC 8032 section 5.1.3 decoding in {@code BigInteger} and the small-order check
 * (gate 8's M2-7). The eight small-order points are derived here from the curve equation with this class's own
 * square roots and point addition, never typed in. A differential against the JDK shows that an encoding is refused
 * as malformed exactly when the JDK's own verifier cannot decode it.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class Ed25519PublicKeysTests {
	private static final HexFormat HEX = HexFormat.of();
	private static final BigInteger P = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));
	private static final BigInteger D = BigInteger.valueOf(-121_665).multiply(BigInteger.valueOf(121_666)
			.modInverse(P)).mod(P);
	private static final Point IDENTITY = new Point(BigInteger.ZERO, BigInteger.ONE);
	private static final byte[] SPKI_PREFIX = HEX.parseHex("302a300506032b6570032100");

	// RFC 8037 appendix A.1 (the public key "x") and A.4 (the EdDSA signature over its signing input), and RFC 8032
	// section 7.1 tests 1 to 3.
	@TestFactory
	Stream<DynamicTest> rfcPublicKeysDecodeAndVerifyTheirSignatures() throws Exception {
		Map<String, String[]> vectors = new LinkedHashMap<>();
		vectors.put("RFC 8037 A.4", new String[]{
				HEX.formatHex(Base64Url.decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")),
				HEX.formatHex("eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc".getBytes(StandardCharsets.US_ASCII)),
				HEX.formatHex(Base64Url.decode("hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvp"
						+ "Ar_MuM0KAg"))});
		vectors.put("RFC 8032 7.1 test 1", new String[]{
				"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
				"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f"
						+ "0595bbe24655141438e7a100b"});
		vectors.put("RFC 8032 7.1 test 2", new String[]{
				"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
				"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2ea"
						+ "eb4302aeeb00d291612bb0c00"});
		vectors.put("RFC 8032 7.1 test 3", new String[]{
				"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
				"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e"
						+ "9716ed28dc027beceea1ec40a"});

		return vectors.entrySet().stream().map(vector -> DynamicTest.dynamicTest(vector.getKey(), () -> {
			byte[] encoded = HEX.parseHex(vector.getValue()[0]);
			byte[] message = HEX.parseHex(vector.getValue()[1]);
			byte[] signature = HEX.parseHex(vector.getValue()[2]);
			byte[] encodedCopy = encoded.clone();
			EdECPublicKey key = Ed25519PublicKeys.fromEncoded(encoded);

			Assertions.assertArrayEquals(encodedCopy, encoded, "the encoding is not modified");
			Assertions.assertArrayEquals(EcdsaSignaturesTests.concat(SPKI_PREFIX, encoded), key.getEncoded());
			Assertions.assertEquals(VerifyResult.VALID, SignatureVerifier.verifyEd25519(key, message, signature));
			// The low bit of S (RFC 8032 section 5.1.6: the second half, little-endian) keeps S below L, so the JDK
			// answers false. A changed R may not decode, and the JDK then throws, which is PROVIDER_FAILURE.
			byte[] changedS = signature.clone();
			changedS[32] ^= 0x01;
			Assertions.assertEquals(VerifyResult.MISMATCH, SignatureVerifier.verifyEd25519(key, message, changedS));
			byte[] changedR = signature.clone();
			changedR[0] ^= 0x01;
			Assertions.assertNotEquals(VerifyResult.VALID, SignatureVerifier.verifyEd25519(key, message, changedR));
			Ed25519PublicKeys.checkPublicKey(key);
		}));
	}

	// RFC 8032 section 5.1.3: y < p, a square root for x^2 = (y^2 - 1) / (d*y^2 + 1), and never x = 0 with the sign bit
	// set. Each failure is malformed; the JDK loads all of these and fails only at verification.
	@TestFactory
	Stream<DynamicTest> encodingsThatDoNotDecodeAreMalformed() {
		Map<String, byte[]> encodings = new LinkedHashMap<>();
		encodings.put("y = 2 (x^2 is not a square)", encode(BigInteger.TWO, false));
		encodings.put("y = 2 with the sign bit", encode(BigInteger.TWO, true));
		encodings.put("y = 1 with the sign bit (x = 0)", encode(BigInteger.ONE, true));
		encodings.put("y = p - 1 with the sign bit (x = 0)", encode(P.subtract(BigInteger.ONE), true));
		encodings.put("y = p (non-canonical 0)", encode(P, false));
		encodings.put("y = p + 1 (non-canonical 1)", encode(P.add(BigInteger.ONE), false));
		encodings.put("y = 2^255 - 1", encode(BigInteger.TWO.pow(255).subtract(BigInteger.ONE), false));
		encodings.put("all 0xff", filled(0xff, 32));
		encodings.put("empty", new byte[0]);
		encodings.put("31 bytes", Arrays.copyOf(encode(BigInteger.TEN, false), 31));
		encodings.put("33 bytes", Arrays.copyOf(encode(BigInteger.TEN, false), 33));
		encodings.put("64 bytes", new byte[64]);

		return encodings.entrySet().stream().map(encoding -> DynamicTest.dynamicTest(encoding.getKey(), () ->
				Assertions.assertEquals(KeyRejectedException.Kind.MALFORMED, Assertions.assertThrows(
						KeyRejectedException.class, () -> Ed25519PublicKeys.fromEncoded(encoding.getValue())).getKind())));
	}

	// The eight small-order points, derived here: (0, 1) of order 1; (0, -1) of order 2; (+-sqrt(-1), 0) of order 4;
	// and the four points of order 8, whose double is an order-4 point, so y^2 = -x^2 and d*x^4 - 2*x^2 - 1 = 0.
	@Test
	void theDerivedSmallOrderPointsAreExactlyTheEightTorsionPoints() {
		List<Point> points = smallOrderPoints();
		List<Integer> orders = points.stream().map(Ed25519PublicKeysTests::order).sorted().toList();

		Assertions.assertEquals(List.of(1, 2, 4, 4, 8, 8, 8, 8), orders);
		Assertions.assertEquals(8, points.stream().map(Point::toString).collect(Collectors.toSet()).size());
		for (Point point : points)
			Assertions.assertTrue(point.isOnCurve(), point::toString);

		// The eight encodings as commonly published, checked against the derivation rather than trusted.
		Set<String> typed = new TreeSet<>(List.of(
				"0100000000000000000000000000000000000000000000000000000000000000",
				"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
				"0000000000000000000000000000000000000000000000000000000000000000",
				"0000000000000000000000000000000000000000000000000000000000000080",
				"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
				"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
				"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
				"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"));
		Assertions.assertEquals(typed, points.stream().map(point -> HEX.formatHex(point.encode()))
				.collect(Collectors.toCollection(TreeSet::new)));
	}

	// M2-7: every small-order point is weak. Negating x (flipping the sign bit) gives another small-order point, except
	// where x = 0, which RFC 8032 section 5.1.3 makes malformed.
	@TestFactory
	Stream<DynamicTest> smallOrderPointsAreWeak() {
		return smallOrderPoints().stream().map(point -> DynamicTest.dynamicTest("order " + order(point) + ": "
				+ HEX.formatHex(point.encode()), () -> {
			byte[] encoded = point.encode();
			byte[] flipped = encoded.clone();
			flipped[31] ^= (byte) 0x80;

			Assertions.assertEquals(KeyRejectedException.Kind.WEAK, Assertions.assertThrows(KeyRejectedException.class,
					() -> Ed25519PublicKeys.fromEncoded(encoded)).getKind());
			Assertions.assertEquals(point.x.signum() == 0 ? KeyRejectedException.Kind.MALFORMED
					: KeyRejectedException.Kind.WEAK, Assertions.assertThrows(KeyRejectedException.class,
					() -> Ed25519PublicKeys.fromEncoded(flipped)).getKind());
			Assertions.assertEquals(KeyRejectedException.Kind.WEAK, Assertions.assertThrows(KeyRejectedException.class,
					() -> Ed25519PublicKeys.checkPublicKey(rawJdkKey(encoded))).getKind());
		}));
	}

	// Why: under the identity key, R = identity and S = 0 verify for any message on the JDK, as the control shows on
	// the running JDK.
	@Test
	void theIdentityKeyWouldAcceptAForgedSignatureSoItIsRefused() throws GeneralSecurityException {
		byte[] identity = IDENTITY.encode();
		byte[] forged = EcdsaSignaturesTests.concat(identity, new byte[32]);
		Signature control = Signature.getInstance("Ed25519");
		control.initVerify(rawJdkKey(identity));
		control.update("any message at all".getBytes(StandardCharsets.US_ASCII));

		Assertions.assertTrue(control.verify(forged), "control: the JDK accepts the forgery under the identity key");
		Assertions.assertEquals(KeyRejectedException.Kind.WEAK, Assertions.assertThrows(KeyRejectedException.class,
				() -> Ed25519PublicKeys.fromEncoded(identity)).getKind());
	}

	// Differential: an encoding is malformed exactly when the JDK's verifier cannot decode it (InvalidKeyException at
	// initVerify); about half of all y values have no x. Every accepted key is the JDK's own point.
	@TestFactory
	Stream<DynamicTest> malformedExactlyWhenTheJdkCannotDecodeThePoint() {
		Random random = new Random(0x45643235L);

		return Stream.of(false, true).map(signBit -> DynamicTest.dynamicTest("sign bit " + signBit, () -> {
			int malformed = 0;

			for (int index = 0; index < 400; ++index) {
				byte[] encoded = new byte[32];
				random.nextBytes(encoded);
				encoded[31] = (byte) ((encoded[31] & 0x7f) | (signBit ? 0x80 : 0));
				PublicKey raw = rawJdkKey(encoded);
				boolean jdkDecodes;

				try {
					Signature.getInstance("Ed25519").initVerify(raw);
					jdkDecodes = true;
				} catch (InvalidKeyException exception) {
					jdkDecodes = false;
				}

				try {
					EdECPublicKey key = Ed25519PublicKeys.fromEncoded(encoded);
					Assertions.assertTrue(jdkDecodes, () -> HEX.formatHex(encoded));
					Assertions.assertEquals(((EdECPublicKey) raw).getPoint().getY(), key.getPoint().getY());
					Assertions.assertEquals(signBit, key.getPoint().isXOdd());
				} catch (KeyRejectedException exception) {
					Assertions.assertEquals(KeyRejectedException.Kind.MALFORMED, exception.getKind());
					Assertions.assertFalse(jdkDecodes, () -> HEX.formatHex(encoded));
					++malformed;
				}
			}

			int count = malformed;
			Assertions.assertTrue(count > 120 && count < 280, () -> count + " of 400 malformed");
		}));
	}

	// RFC 8032 section 5.1.3 step 3: about half of the decodable y values need the candidate root multiplied by
	// sqrt(-1). Either way the recovered x lies on the curve with the requested sign, which the small-order check
	// (and its denominators, never 0 on the curve) relies on.
	@Test
	void recoveredCoordinatesLieOnTheCurveWithTheRequestedSign() throws KeyRejectedException {
		Random random = new Random(0x52656376L);
		int decoded = 0;
		int neededSquareRootOfMinusOne = 0;

		for (int index = 0; index < 400; ++index) {
			BigInteger y = new BigInteger(255, random).mod(P);
			boolean xOdd = random.nextBoolean();
			BigInteger x;

			try {
				x = Ed25519PublicKeys.recoverX(y, xOdd);
			} catch (KeyRejectedException exception) {
				Assertions.assertEquals(KeyRejectedException.Kind.MALFORMED, exception.getKind());
				continue;
			}

			++decoded;
			Assertions.assertTrue(new Point(x, y).isOnCurve(), () -> y.toString(16));
			Assertions.assertEquals(xOdd, x.testBit(0), () -> y.toString(16));
			Assertions.assertTrue(x.signum() >= 0 && x.compareTo(P) < 0, () -> y.toString(16));

			// Independently of the class: the RFC's first candidate, (u / v)^((p + 3) / 8), squares to -x^2 here.
			BigInteger u = y.multiply(y).subtract(BigInteger.ONE).mod(P);
			BigInteger v = D.multiply(y).multiply(y).add(BigInteger.ONE).mod(P);
			BigInteger candidate = u.multiply(v.modInverse(P)).modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P);
			if (candidate.multiply(candidate).mod(P).compareTo(x.multiply(x).mod(P)) != 0)
				++neededSquareRootOfMinusOne;
		}

		int both = decoded;
		int second = neededSquareRootOfMinusOne;
		Assertions.assertTrue(both > 120 && second > 40 && both - second > 40, () -> both + " decoded, " + second
				+ " through sqrt(-1)");
	}

	// JDK-generated keys decode to the same point, verify the JDK's signatures, and pass the SPKI-key check; both signs
	// of x occur.
	@Test
	void jdkGeneratedKeysRoundTrip() throws GeneralSecurityException, KeyRejectedException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
		byte[] message = "Revetsec Ed25519".getBytes(StandardCharsets.US_ASCII);
		boolean sawOdd = false;
		boolean sawEven = false;

		for (int index = 0; index < 200; ++index) {
			KeyPair keyPair = generator.generateKeyPair();
			EdECPublicKey jdkKey = (EdECPublicKey) keyPair.getPublic();
			byte[] spki = jdkKey.getEncoded();
			byte[] encoded = Arrays.copyOfRange(spki, SPKI_PREFIX.length, spki.length);
			EdECPublicKey key = Ed25519PublicKeys.fromEncoded(encoded);
			Signature signer = Signature.getInstance("Ed25519");
			signer.initSign(keyPair.getPrivate());
			signer.update(message);

			Assertions.assertEquals(jdkKey.getPoint().getY(), key.getPoint().getY());
			Assertions.assertEquals(jdkKey.getPoint().isXOdd(), key.getPoint().isXOdd());
			Assertions.assertEquals(VerifyResult.VALID, SignatureVerifier.verifyEd25519(key, message, signer.sign()));
			Ed25519PublicKeys.checkPublicKey(jdkKey);
			sawOdd |= key.getPoint().isXOdd();
			sawEven |= !key.getPoint().isXOdd();
		}

		Assertions.assertTrue(sawOdd && sawEven);
	}

	// SPKI keys (certificates, PEM) are decoded and checked the same way; other curves and odd implementations are
	// refused with a checked exception (INV-G1).
	@Test
	void keysFromOtherSourcesAreDecodedAndChecked() throws GeneralSecurityException, KeyRejectedException {
		assertCheckRejected(KeyRejectedException.Kind.MALFORMED, rawJdkKey(encode(BigInteger.TWO, false)));
		assertCheckRejected(KeyRejectedException.Kind.MALFORMED, rawJdkKey(encode(BigInteger.ONE, true)));
		assertCheckRejected(KeyRejectedException.Kind.MALFORMED, (EdECPublicKey) KeyFactory.getInstance("Ed25519")
				.generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, new EdECPoint(false, P))));
		assertCheckRejected(KeyRejectedException.Kind.MALFORMED,
				(EdECPublicKey) KeyPairGenerator.getInstance("Ed448").generateKeyPair().getPublic());

		EdECPoint valid = ((EdECPublicKey) KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic())
				.getPoint();
		assertCheckRejected(KeyRejectedException.Kind.MALFORMED, new UnusualEdKey(NamedParameterSpec.X25519, valid,
				false));
		assertCheckRejected(KeyRejectedException.Kind.MALFORMED, new UnusualEdKey(null, valid, false));
		assertCheckRejected(KeyRejectedException.Kind.MALFORMED, new UnusualEdKey(NamedParameterSpec.ED25519, null,
				false));
		assertCheckRejected(KeyRejectedException.Kind.MALFORMED, new UnusualEdKey(NamedParameterSpec.ED25519, valid,
				true));
		assertCheckRejected(KeyRejectedException.Kind.MALFORMED, new UnusualEdKey(NamedParameterSpec.ED25519,
				new EdECPoint(false, BigInteger.ONE.negate()), false));
		assertCheckRejected(KeyRejectedException.Kind.WEAK, new UnusualEdKey(NamedParameterSpec.ED25519,
				new EdECPoint(false, BigInteger.ONE), false));
		Ed25519PublicKeys.checkPublicKey(new UnusualEdKey(NamedParameterSpec.ED25519, valid, false));
	}

	@Test
	void theLengthsAreFixed() {
		Assertions.assertEquals(32, Ed25519PublicKeys.KEY_LENGTH);
		Assertions.assertEquals(64, Ed25519PublicKeys.SIGNATURE_LENGTH);
		Assertions.assertEquals("Ed25519", Ed25519PublicKeys.ALGORITHM);
		Assertions.assertTrue(Ed25519PublicKeys.isEd25519(NamedParameterSpec.ED25519));
		Assertions.assertFalse(Ed25519PublicKeys.isEd25519(NamedParameterSpec.ED448));
		Assertions.assertFalse(Ed25519PublicKeys.isEd25519(new NamedParameterSpec("ed25519")));
	}

	@Test
	void rejectsNullArguments() {
		Assertions.assertThrows(NullPointerException.class, () -> Ed25519PublicKeys.fromEncoded(nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> Ed25519PublicKeys.checkPublicKey(nullValue()));
	}

	/**
	 * The RFC 8032 section 5.1.2 encoding of {@code y} (which may be out of range here) with the sign bit.
	 */
	static byte[] encode(BigInteger y, boolean xOdd) {
		byte[] bigEndian = EcdsaSignaturesTests.fixed(y, 32);
		byte[] encoded = new byte[32];
		for (int index = 0; index < 32; ++index)
			encoded[index] = bigEndian[31 - index];
		if (xOdd)
			encoded[31] |= (byte) 0x80;
		return encoded;
	}

	/**
	 * A key the JDK builds from an encoding without decoding it.
	 */
	static EdECPublicKey rawJdkKey(byte[] encoded) throws GeneralSecurityException {
		boolean xOdd = (encoded[31] & 0x80) != 0;
		byte[] bigEndian = new byte[32];
		for (int index = 0; index < 32; ++index)
			bigEndian[index] = encoded[31 - index];
		bigEndian[0] &= 0x7f;

		return (EdECPublicKey) KeyFactory.getInstance("Ed25519").generatePublic(new EdECPublicKeySpec(
				NamedParameterSpec.ED25519, new EdECPoint(xOdd, new BigInteger(1, bigEndian))));
	}

	/**
	 * The eight points of order dividing 8, derived from the curve equation.
	 */
	private static List<Point> smallOrderPoints() {
		BigInteger i = squareRoot(P.subtract(BigInteger.ONE));
		Assertions.assertNotNull(i, "-1 is a square modulo p, because p = 1 mod 4");

		List<Point> points = new ArrayList<>(List.of(IDENTITY, new Point(BigInteger.ZERO, P.subtract(BigInteger.ONE)),
				new Point(i, BigInteger.ZERO), new Point(P.subtract(i), BigInteger.ZERO)));
		BigInteger root = squareRoot(BigInteger.ONE.add(D).mod(P));
		Assertions.assertNotNull(root, "1 + d is a square, or the curve would have no points of order 8");
		BigInteger inverseD = D.modInverse(P);

		for (BigInteger candidate : List.of(BigInteger.ONE.add(root).multiply(inverseD).mod(P),
				BigInteger.ONE.subtract(root).multiply(inverseD).mod(P))) {
			BigInteger x = squareRoot(candidate);
			if (x == null)
				continue;
			BigInteger y = i.multiply(x).mod(P);
			points.add(new Point(x, y));
			points.add(new Point(x, P.subtract(y)));
			points.add(new Point(P.subtract(x), y));
			points.add(new Point(P.subtract(x), P.subtract(y)));
		}

		return points;
	}

	/**
	 * The smallest k in 1, 2, 4, 8 with [k]P = identity, by repeated addition; 0 if none.
	 */
	private static int order(Point point) {
		Point multiple = point;
		for (int k = 1; k <= 8; ++k) {
			if (multiple.isIdentity())
				return k;
			multiple = multiple.add(point);
		}
		return 0;
	}

	/**
	 * A square root modulo p by Tonelli-Shanks, or null if {@code value} is not a square.
	 */
	private static @Nullable BigInteger squareRoot(BigInteger value) {
		BigInteger a = value.mod(P);
		if (a.signum() == 0)
			return BigInteger.ZERO;
		BigInteger minusOne = P.subtract(BigInteger.ONE);
		if (a.modPow(minusOne.shiftRight(1), P).compareTo(BigInteger.ONE) != 0)
			return null;

		BigInteger q = minusOne;
		int s = 0;
		while (!q.testBit(0)) {
			q = q.shiftRight(1);
			++s;
		}

		BigInteger z = BigInteger.TWO;
		while (z.modPow(minusOne.shiftRight(1), P).compareTo(minusOne) != 0)
			z = z.add(BigInteger.ONE);

		int m = s;
		BigInteger c = z.modPow(q, P);
		BigInteger t = a.modPow(q, P);
		BigInteger r = a.modPow(q.add(BigInteger.ONE).shiftRight(1), P);

		while (t.compareTo(BigInteger.ONE) != 0) {
			int least = 0;
			BigInteger power = t;
			while (power.compareTo(BigInteger.ONE) != 0) {
				power = power.multiply(power).mod(P);
				++least;
			}
			BigInteger b = c.modPow(BigInteger.ONE.shiftLeft(m - least - 1), P);
			m = least;
			c = b.multiply(b).mod(P);
			t = t.multiply(c).mod(P);
			r = r.multiply(b).mod(P);
		}

		Assertions.assertEquals(a, r.multiply(r).mod(P));
		return r;
	}

	private static void assertCheckRejected(KeyRejectedException.Kind kind, EdECPublicKey key) {
		Assertions.assertEquals(kind, Assertions.assertThrows(KeyRejectedException.class,
				() -> Ed25519PublicKeys.checkPublicKey(key)).getKind());
	}

	private static byte[] filled(int value, int length) {
		byte[] bytes = new byte[length];
		Arrays.fill(bytes, (byte) value);
		return bytes;
	}

	/**
	 * Hides a {@code null} from NullAway, for the tests that check null handling.
	 */
	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> T nullValue() {
		return null;
	}

	/**
	 * An affine point on edwards25519 ({@code -x^2 + y^2 = 1 + d*x^2*y^2}), with this class's own addition law.
	 */
	private static final class Point {
		private final BigInteger x;
		private final BigInteger y;

		private Point(BigInteger x, BigInteger y) {
			this.x = x.mod(P);
			this.y = y.mod(P);
		}

		private boolean isOnCurve() {
			BigInteger xx = this.x.multiply(this.x);
			BigInteger yy = this.y.multiply(this.y);
			return yy.subtract(xx).subtract(BigInteger.ONE).subtract(D.multiply(xx).multiply(yy)).mod(P).signum() == 0;
		}

		private boolean isIdentity() {
			return this.x.signum() == 0 && this.y.compareTo(BigInteger.ONE) == 0;
		}

		// RFC 8032 section 5.1.4, affine form with a = -1.
		private Point add(Point other) {
			BigInteger product = D.multiply(this.x).multiply(other.x).multiply(this.y).multiply(other.y).mod(P);
			BigInteger x3 = this.x.multiply(other.y).add(this.y.multiply(other.x))
					.multiply(BigInteger.ONE.add(product).modInverse(P));
			BigInteger y3 = this.y.multiply(other.y).add(this.x.multiply(other.x))
					.multiply(BigInteger.ONE.subtract(product).mod(P).modInverse(P));
			return new Point(x3, y3);
		}

		private byte[] encode() {
			return Ed25519PublicKeysTests.encode(this.y, this.x.testBit(0));
		}

		@Override
		public String toString() {
			return this.x.toString(16) + "," + this.y.toString(16);
		}
	}

	/**
	 * An {@link EdECPublicKey} implementation outside the JDK, which may report nothing or throw.
	 */
	@SuppressWarnings("NullAway")
	static final class UnusualEdKey implements EdECPublicKey {
		private static final long serialVersionUID = 1L;

		private final transient @Nullable NamedParameterSpec parameters;
		private final transient @Nullable EdECPoint point;
		private final boolean throwing;

		UnusualEdKey(@Nullable NamedParameterSpec parameters, @Nullable EdECPoint point, boolean throwing) {
			this.parameters = parameters;
			this.point = point;
			this.throwing = throwing;
		}

		@Override
		public EdECPoint getPoint() {
			if (this.throwing)
				throw new IllegalStateException("A key implementation that throws.");
			return this.point;
		}

		@Override
		public NamedParameterSpec getParams() {
			return this.parameters;
		}

		@Override
		public String getAlgorithm() {
			return "Ed25519";
		}

		@Override
		public String getFormat() {
			return "X.509";
		}

		@Override
		public byte[] getEncoded() {
			return new byte[0];
		}
	}
}
