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

package com.revetsec.testing;

import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * JSON Web Keys (RFC 7517) for tests: the TEST ONLY fixture keys as JWK and JWK Set JSON in public and private form,
 * and the malformed, weak and unsupported keys Revetsec must skip (plan M2-7, "Keys").
 * <p>
 * <strong>Key types.</strong> RSA, EC on P-256, P-384 and P-521 (RFC 7518 section 6), and OKP (RFC 8037 section 2) on
 * Ed25519, Ed448, X25519 and X448: a JDK key pair of any of these becomes a JWK, so a test can write a real Ed448 or
 * X25519 key that Revetsec skips as an unsupported curve. {@link #octWithK(String)} writes a symmetric key, and
 * {@link #publicKeyPem(PublicKey)} a public key as PEM text, for algorithm-confusion fixtures.
 * <p>
 * <strong>The fixtures</strong> ({@link Fixture}) are the committed PEM keys under
 * {@code src/test/resources/fixtures/keys/} and {@code fixtures/pem/ed25519-key.pem}. They are public, so they belong
 * in tests only. Keys are read with the JDK alone, never through Revetsec's {@code Pem}.
 * <p>
 * <strong>The JWK text</strong> ({@link Builder}) is written member by member, in this order: {@code kty}, {@code crv},
 * the public members ({@code n} and {@code e}, or {@code x} and {@code y}, or {@code x}), the private members when
 * asked for ({@code d}, {@code p}, {@code q}, {@code dp}, {@code dq}, {@code qi}), then {@code kid}, {@code use},
 * {@code key_ops}, {@code alg}, {@code x5c} and {@code issuer} when set. RSA integers are minimal Base64urlUInt, and EC
 * coordinates and {@code d} have the curve's fixed length (RFC 7518 sections 6.2 and 6.3). {@link Builder#member}
 * replaces any member with raw JSON text, in place, or appends a new one, so a test can write any malformed key.
 * <p>
 * <strong>The malformed and weak keys</strong> the plan names come ready-made: a 31-octet EC {@code x}
 * ({@link #ecWithShortX()}), a leading-zero {@code n} ({@link #rsaWithLeadingZeroModulus()}), an even {@code e}
 * ({@link #rsaWithEvenExponent()}), a point off its curve ({@link #ecOffCurve()}), a small-order Ed25519 key
 * ({@link #ed25519SmallOrder()}), and a ROCA-fingerprinted RSA key ({@link #rocaFingerprintedRsaKeyPair()}).
 * Everything generated is deterministic and computed with {@link BigInteger} arithmetic written here, so it does not
 * share code with Revetsec's own curve checks.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class TestJsonWebKeys {
	/**
	 * The Ed25519 field prime, 2^255 − 19 (RFC 8032 section 5.1).
	 */
	public static final BigInteger ED25519_FIELD_PRIME = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));

	/**
	 * The order of the Ed25519 prime-order subgroup, 2^252 + 27742317777372353535851937790883648493 (RFC 8032
	 * section 5.1).
	 */
	public static final BigInteger ED25519_GROUP_ORDER =
			BigInteger.TWO.pow(252).add(new BigInteger("27742317777372353535851937790883648493"));

	/**
	 * The Ed25519 curve constant d = −121665/121666 mod p (RFC 8032 section 5.1).
	 */
	public static final BigInteger ED25519_D = BigInteger.valueOf(-121_665)
			.multiply(BigInteger.valueOf(121_666).modInverse(ED25519_FIELD_PRIME)).mod(ED25519_FIELD_PRIME);

	/**
	 * The RSA public exponent every fixture and generated RSA key uses.
	 */
	public static final BigInteger F4 = BigInteger.valueOf(65_537);

	/**
	 * The primes the ROCA fingerprint is tested against: the 38 odd primes from 3 to 167 (plan M2-7).
	 */
	public static final List<BigInteger> ROCA_PRIMES = rocaPrimes();

	private static final BigInteger SQRT_MINUS_ONE = BigInteger.TWO.modPow(
			ED25519_FIELD_PRIME.subtract(BigInteger.ONE).shiftRight(2), ED25519_FIELD_PRIME);
	private static final BigInteger THREE = BigInteger.valueOf(3);
	// The JWK curve names (RFC 7518 section 6.2.1.1) and the JDK names of the same curves.
	private static final List<Map.Entry<String, String>> NIST_CURVES = List.of(Map.entry("P-256", "secp256r1"),
			Map.entry("P-384", "secp384r1"), Map.entry("P-521", "secp521r1"));

	private TestJsonWebKeys() {
		// Static helpers only.
	}

	/**
	 * Starts a JWK for a fixture key, public members only unless {@link Builder#includePrivateMembers(Boolean)}.
	 *
	 * @param fixture the fixture
	 * @return a new builder
	 */
	public static Builder withFixture(Fixture fixture) {
		return withKeyPair(requireNonNull(fixture).getKeyPair());
	}

	/**
	 * Starts a JWK for a key pair, public members only unless {@link Builder#includePrivateMembers(Boolean)}.
	 *
	 * @param keyPair an RSA, EC (P-256, P-384 or P-521) or OKP (Ed25519, Ed448, X25519 or X448) key pair
	 * @return a new builder
	 * @throws IllegalArgumentException for any other key
	 */
	public static Builder withKeyPair(KeyPair keyPair) {
		requireNonNull(keyPair);
		return new Builder(publicMembers(keyPair.getPublic()), privateMembers(keyPair.getPrivate()));
	}

	/**
	 * Starts a JWK for a public key; it has no private members to include.
	 *
	 * @param publicKey an RSA, EC (P-256, P-384 or P-521) or OKP (Ed25519, Ed448, X25519 or X448) public key
	 * @return a new builder
	 * @throws IllegalArgumentException for any other key
	 */
	public static Builder withPublicKey(PublicKey publicKey) {
		return new Builder(publicMembers(requireNonNull(publicKey)), null);
	}

	/**
	 * Starts an Ed25519 JWK ({@code kty} OKP, {@code crv} Ed25519) with an arbitrary {@code x}, which need not decode
	 * to a curve point.
	 *
	 * @param x the {@code x} member's base64url text
	 * @return a new builder
	 */
	public static Builder ed25519WithX(String x) {
		Map<String, String> members = new LinkedHashMap<>();
		members.put("kty", JsonText.string("OKP"));
		members.put("crv", JsonText.string("Ed25519"));
		members.put("x", JsonText.string(requireNonNull(x)));
		return new Builder(members, null);
	}

	/**
	 * Starts a symmetric JWK ({@code kty} oct) with {@code k}, which Revetsec skips as {@code SYMMETRIC_KEY} (plan
	 * M2-7, key check 2).
	 *
	 * @param k the {@code k} member's text, such as {@code Sentinels.SYMMETRIC_KEY}
	 * @return a new builder
	 */
	public static Builder octWithK(String k) {
		Map<String, String> members = new LinkedHashMap<>();
		members.put("kty", JsonText.string("oct"));
		members.put("k", JsonText.string(requireNonNull(k)));
		return new Builder(members, null);
	}

	/**
	 * A JWK Set: {@code {"keys":[...]}}.
	 *
	 * @param keys each key's JSON text, in order
	 * @return the key set's JSON text
	 */
	public static String keySet(List<String> keys) {
		return JsonText.object(List.of(Map.entry("keys", JsonText.array(requireNonNull(keys)))));
	}

	/**
	 * A public key as PEM text, the way OpenSSL writes it: {@code -----BEGIN PUBLIC KEY-----}, the SubjectPublicKeyInfo
	 * DER in standard base64 at 64 characters a line, and {@code -----END PUBLIC KEY-----}, each line ending in
	 * {@code \n} (RFC 7468 section 13). For the algorithm-confusion fixtures that MAC a token with a public key's PEM
	 * bytes (plan M2 exit criterion 4).
	 *
	 * @param publicKey the key
	 * @return the PEM text
	 */
	public static String publicKeyPem(PublicKey publicKey) {
		String body = Base64.getMimeEncoder(64, new byte[]{'\n'})
				.encodeToString(requireNonNull(publicKey).getEncoded());
		return "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----\n";
	}

	/**
	 * A non-negative integer as Base64urlUInt: its minimal big-endian octets, base64url-encoded, with one zero octet
	 * for zero (RFC 7518 section 2).
	 *
	 * @param value the integer, zero or positive
	 * @return the encoded text
	 */
	public static String base64UrlUInt(BigInteger value) {
		return TestJws.base64Url(unsignedBytes(value));
	}

	/**
	 * A non-negative integer as exactly {@code octets} big-endian octets, base64url-encoded, as EC coordinates are
	 * (RFC 7518 section 6.2.1.2).
	 *
	 * @param value the integer
	 * @param octets the length
	 * @return the encoded text
	 */
	public static String base64UrlFixedLength(BigInteger value, Integer octets) {
		return TestJws.base64Url(fixedLengthBytes(value, octets));
	}

	/**
	 * The minimal big-endian octets of a non-negative integer, with one zero octet for zero.
	 *
	 * @param value the integer
	 * @return a new array
	 */
	public static byte[] unsignedBytes(BigInteger value) {
		requireNonNull(value);
		if (value.signum() < 0)
			throw new IllegalArgumentException("Negative: " + value);
		byte[] bytes = value.toByteArray();
		if (bytes.length > 1 && bytes[0] == 0) {
			byte[] trimmed = new byte[bytes.length - 1];
			System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
			return trimmed;
		}
		return bytes;
	}

	/**
	 * Exactly {@code octets} big-endian octets of a non-negative integer.
	 *
	 * @param value the integer
	 * @param octets the length
	 * @return a new array
	 * @throws IllegalArgumentException if the value does not fit
	 */
	public static byte[] fixedLengthBytes(BigInteger value, Integer octets) {
		requireNonNull(value);
		requireNonNull(octets);
		byte[] minimal = unsignedBytes(value);
		if (value.signum() == 0)
			return new byte[octets];
		if (minimal.length > octets)
			throw new IllegalArgumentException(value + " does not fit in " + octets + " octets");
		byte[] fixed = new byte[octets];
		System.arraycopy(minimal, 0, fixed, octets - minimal.length, minimal.length);
		return fixed;
	}

	/**
	 * A P-256 JWK whose {@code x} is encoded in 31 octets: the key of {@link #ecKeyPairWithLeadingZeroX()}, whose
	 * {@code x} has a leading zero octet, written minimally instead of at the curve's fixed 32 octets. RFC 7518 section
	 * 6.2.1.2 requires the full length, and RFC 7638 thumbprints depend on it.
	 *
	 * @return a new builder
	 */
	public static Builder ecWithShortX() {
		KeyPair keyPair = ecKeyPairWithLeadingZeroX();
		BigInteger x = ((ECPublicKey) keyPair.getPublic()).getW().getAffineX();
		return withKeyPair(keyPair).member("x", JsonText.string(base64UrlUInt(x)));
	}

	/**
	 * The {@link Fixture#IDP_SIGNING_RSA_2048} JWK with {@code n} carrying a leading zero octet, which Base64urlUInt
	 * forbids (RFC 7518 section 2).
	 *
	 * @return a new builder
	 */
	public static Builder rsaWithLeadingZeroModulus() {
		RSAPublicKey publicKey = (RSAPublicKey) Fixture.IDP_SIGNING_RSA_2048.getPublicKey();
		byte[] minimal = unsignedBytes(publicKey.getModulus());
		byte[] padded = new byte[minimal.length + 1];
		System.arraycopy(minimal, 0, padded, 1, minimal.length);
		return withFixture(Fixture.IDP_SIGNING_RSA_2048).member("n", JsonText.string(TestJws.base64Url(padded)));
	}

	/**
	 * The {@link Fixture#IDP_SIGNING_RSA_2048} JWK with another public exponent, written as Base64urlUInt.
	 *
	 * @param exponent the {@code e} to write, such as 1, 3, 65535, 65536 or 2^32
	 * @return a new builder
	 */
	public static Builder rsaWithExponent(BigInteger exponent) {
		return withFixture(Fixture.IDP_SIGNING_RSA_2048).member("e", JsonText.string(base64UrlUInt(exponent)));
	}

	/**
	 * The {@link Fixture#IDP_SIGNING_RSA_2048} JWK with the even exponent {@code e} = 65538.
	 *
	 * @return a new builder
	 */
	public static Builder rsaWithEvenExponent() {
		return rsaWithExponent(F4.add(BigInteger.ONE));
	}

	/**
	 * The {@link Fixture#IDP_SIGNING_EC_P256} JWK with {@code y} replaced by y + 1 mod p, at the fixed length: a point
	 * off the curve (invalid-curve attacks; the JDK's {@code KeyFactory} accepts it).
	 *
	 * @return a new builder
	 */
	public static Builder ecOffCurve() {
		ECPublicKey publicKey = (ECPublicKey) Fixture.IDP_SIGNING_EC_P256.getPublicKey();
		BigInteger p = fieldPrime(publicKey.getParams());
		BigInteger y = publicKey.getW().getAffineY().add(BigInteger.ONE).mod(p);
		return withFixture(Fixture.IDP_SIGNING_EC_P256).member("y", JsonText.string(base64UrlFixedLength(y, 32)));
	}

	/**
	 * An Ed25519 JWK whose {@code x} encodes the identity point (y = 1), which has order 1: with it, the signature
	 * R = identity, S = 0 verifies for every message on JDK 17 to 27 (plan M2-7).
	 *
	 * @return a new builder
	 */
	public static Builder ed25519SmallOrder() {
		return ed25519WithX(ed25519PublicKeyEncoding(BigInteger.ONE, false));
	}

	/**
	 * The 32-octet RFC 8032 section 5.1.2 encoding of an Ed25519 point from its y and the parity of its x, whether or
	 * not such a point exists: y little-endian, with the top bit of the last octet set when {@code xOdd}.
	 *
	 * @param y the y coordinate, 0 to 2^255 − 1 (values from p up are non-canonical)
	 * @param xOdd whether x is odd (the sign bit)
	 * @return the base64url of the 32 octets
	 */
	public static String ed25519PublicKeyEncoding(BigInteger y, Boolean xOdd) {
		requireNonNull(y);
		requireNonNull(xOdd);
		if (y.signum() < 0 || y.bitLength() > 255)
			throw new IllegalArgumentException("y does not fit in 255 bits: " + y);
		byte[] bigEndian = fixedLengthBytes(y, 32);
		byte[] littleEndian = new byte[32];
		for (int index = 0; index < 32; ++index)
			littleEndian[index] = bigEndian[31 - index];
		if (xOdd)
			littleEndian[31] |= (byte) 0x80;
		return TestJws.base64Url(littleEndian);
	}

	/**
	 * The x coordinate of the Ed25519 point with this y and sign bit, decoded per RFC 8032 section 5.1.3.
	 *
	 * @param y the y coordinate
	 * @param xOdd the sign bit
	 * @return x, or empty if the encoding does not decode: y ≥ p, x² = (y² − 1)/(d·y² + 1) is not a square mod p, or
	 * x = 0 with the sign bit set
	 */
	public static Optional<BigInteger> ed25519DecodeX(BigInteger y, Boolean xOdd) {
		requireNonNull(y);
		requireNonNull(xOdd);
		BigInteger p = ED25519_FIELD_PRIME;
		if (y.signum() < 0 || y.compareTo(p) >= 0)
			return Optional.empty();
		BigInteger ySquared = y.multiply(y).mod(p);
		BigInteger u = ySquared.subtract(BigInteger.ONE).mod(p);
		BigInteger v = ED25519_D.multiply(ySquared).add(BigInteger.ONE).mod(p);
		BigInteger xSquared = u.multiply(v.modInverse(p)).mod(p);
		BigInteger x = xSquared.modPow(p.add(THREE).shiftRight(3), p);
		if (!x.multiply(x).mod(p).equals(xSquared))
			x = x.multiply(SQRT_MINUS_ONE).mod(p);
		if (!x.multiply(x).mod(p).equals(xSquared))
			return Optional.empty();
		if (x.signum() == 0 && xOdd)
			return Optional.empty();
		if (x.testBit(0) != xOdd)
			x = p.subtract(x);
		return Optional.of(x);
	}

	/**
	 * The encodings of the eight Ed25519 points of small order (the torsion subgroup; the curve's cofactor is 8),
	 * derived here from the curve rather than typed in: a point Q of full order times the group order L leaves its
	 * order-8 component T, and the eight points are 0·T to 7·T.
	 *
	 * @return the eight {@code x} values as base64url, identity first, in the order 0·T to 7·T
	 */
	public static List<String> ed25519SmallOrderPublicKeys() {
		return SmallOrderHolder.ENCODINGS;
	}

	/**
	 * A deterministic P-256 key pair whose public {@code x} is below 2^248, so its fixed-length 32-octet encoding
	 * begins with a zero octet. It is found from a fixed starting scalar by adding the generator until x is small
	 * enough; the private scalar is not small.
	 *
	 * @return a new key pair, the same key every time
	 */
	public static KeyPair ecKeyPairWithLeadingZeroX() {
		ECParameterSpec parameters = TestJws.namedCurveParameters("secp256r1");
		ShortXHolder holder = ShortXHolder.INSTANCE;
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("EC");
			PublicKey publicKey = keyFactory.generatePublic(
					new ECPublicKeySpec(new ECPoint(holder.x, holder.y), parameters));
			PrivateKey privateKey = keyFactory.generatePrivate(new ECPrivateKeySpec(holder.scalar, parameters));
			return new KeyPair(publicKey, privateKey);
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("Unable to build the P-256 key with a leading zero x", e);
		}
	}

	/**
	 * A deterministic 2048-bit RSA key pair with {@code e} = 65537 whose modulus carries the ROCA fingerprint
	 * (CVE-2017-15361): N mod m lies in the subgroup generated by 65537 mod m for every prime m in
	 * {@link #ROCA_PRIMES}. Each prime has the form the flawed generator used, k·M + (65537^a mod M), here with M the
	 * product of those primes. The key is otherwise valid and signs normally.
	 *
	 * @return a new key pair, the same key every time
	 */
	public static KeyPair rocaFingerprintedRsaKeyPair() {
		RocaHolder holder = RocaHolder.INSTANCE;
		BigInteger p = holder.p;
		BigInteger q = holder.q;
		BigInteger n = p.multiply(q);
		BigInteger pMinusOne = p.subtract(BigInteger.ONE);
		BigInteger qMinusOne = q.subtract(BigInteger.ONE);
		BigInteger lambda = pMinusOne.divide(pMinusOne.gcd(qMinusOne)).multiply(qMinusOne);
		BigInteger d = F4.modInverse(lambda);
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(n, F4));
			PrivateKey privateKey = keyFactory.generatePrivate(new RSAPrivateCrtKeySpec(n, F4, d, p, q,
					d.mod(pMinusOne), d.mod(qMinusOne), q.modInverse(p)));
			return new KeyPair(publicKey, privateKey);
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("Unable to build the ROCA-fingerprinted RSA key", e);
		}
	}

	/**
	 * Whether {@code modulus} carries the ROCA fingerprint over {@link #ROCA_PRIMES}: an oracle written here, apart
	 * from Revetsec's own check.
	 *
	 * @param modulus an RSA modulus
	 * @return whether N mod m is a power of 65537 mod m for every prime m
	 */
	public static Boolean hasRocaFingerprint(BigInteger modulus) {
		requireNonNull(modulus);
		for (BigInteger prime : ROCA_PRIMES) {
			BigInteger residue = modulus.mod(prime);
			BigInteger generator = F4.mod(prime);
			BigInteger power = BigInteger.ONE;
			boolean found = false;
			// The subgroup has at most m − 1 elements, so m steps visit all of it.
			for (int step = 0; step < prime.intValueExact() && !found; ++step) {
				found = power.equals(residue);
				power = power.multiply(generator).mod(prime);
			}
			if (!found)
				return false;
		}
		return true;
	}

	/**
	 * Whether ({@code x}, {@code y}) satisfies y² = x³ + a·x + b over the curve's field.
	 *
	 * @param parameters the curve
	 * @param x the x coordinate
	 * @param y the y coordinate
	 * @return whether the point is on the curve (coordinates of p or more never are)
	 */
	public static Boolean isOnCurve(ECParameterSpec parameters, BigInteger x, BigInteger y) {
		requireNonNull(parameters);
		BigInteger p = fieldPrime(parameters);
		if (x.signum() < 0 || y.signum() < 0 || x.compareTo(p) >= 0 || y.compareTo(p) >= 0)
			return false;
		BigInteger left = y.multiply(y).mod(p);
		BigInteger right = x.pow(3).add(parameters.getCurve().getA().multiply(x)).add(parameters.getCurve().getB())
				.mod(p);
		return left.equals(right);
	}

	private static BigInteger fieldPrime(ECParameterSpec parameters) {
		return ((ECFieldFp) parameters.getCurve().getField()).getP();
	}

	private static Map<String, String> publicMembers(PublicKey publicKey) {
		Map<String, String> members = new LinkedHashMap<>();
		if (publicKey instanceof RSAPublicKey rsa) {
			members.put("kty", JsonText.string("RSA"));
			members.put("n", JsonText.string(base64UrlUInt(rsa.getModulus())));
			members.put("e", JsonText.string(base64UrlUInt(rsa.getPublicExponent())));
		} else if (publicKey instanceof ECPublicKey ec) {
			int octets = coordinateOctets(ec.getParams());
			members.put("kty", JsonText.string("EC"));
			members.put("crv", JsonText.string(curveName(ec.getParams())));
			members.put("x", JsonText.string(base64UrlFixedLength(ec.getW().getAffineX(), octets)));
			members.put("y", JsonText.string(base64UrlFixedLength(ec.getW().getAffineY(), octets)));
		} else if (publicKey instanceof EdECPublicKey ed) {
			// RFC 8032 sections 5.1.2 and 5.2.2: y little-endian, with x's parity in the last octet's top bit.
			String curve = ed.getParams().getName();
			int octets = switch (curve) {
				case "Ed25519" -> 32;
				case "Ed448" -> 57;
				default -> throw new IllegalArgumentException("Unsupported EdDSA curve: " + curve);
			};
			byte[] encoding = littleEndianBytes(ed.getPoint().getY(), octets);
			if (ed.getPoint().isXOdd())
				encoding[octets - 1] |= (byte) 0x80;
			members.put("kty", JsonText.string("OKP"));
			members.put("crv", JsonText.string(curve));
			members.put("x", JsonText.string(TestJws.base64Url(encoding)));
		} else if (publicKey instanceof XECPublicKey xec) {
			// RFC 7748 section 5: the u-coordinate, little-endian.
			String curve = xec.getParams() instanceof NamedParameterSpec named ? named.getName() : "";
			int octets = switch (curve) {
				case "X25519" -> 32;
				case "X448" -> 56;
				default -> throw new IllegalArgumentException("Unsupported XDH curve: " + xec.getParams());
			};
			members.put("kty", JsonText.string("OKP"));
			members.put("crv", JsonText.string(curve));
			members.put("x", JsonText.string(TestJws.base64Url(littleEndianBytes(xec.getU(), octets))));
		} else {
			throw new IllegalArgumentException("Unsupported public key: " + publicKey.getAlgorithm());
		}
		return members;
	}

	private static Map<String, String> privateMembers(PrivateKey privateKey) {
		Map<String, String> members = new LinkedHashMap<>();
		if (privateKey instanceof RSAPrivateCrtKey crt) {
			members.put("d", JsonText.string(base64UrlUInt(crt.getPrivateExponent())));
			members.put("p", JsonText.string(base64UrlUInt(crt.getPrimeP())));
			members.put("q", JsonText.string(base64UrlUInt(crt.getPrimeQ())));
			members.put("dp", JsonText.string(base64UrlUInt(crt.getPrimeExponentP())));
			members.put("dq", JsonText.string(base64UrlUInt(crt.getPrimeExponentQ())));
			members.put("qi", JsonText.string(base64UrlUInt(crt.getCrtCoefficient())));
		} else if (privateKey instanceof RSAPrivateKey rsa) {
			members.put("d", JsonText.string(base64UrlUInt(rsa.getPrivateExponent())));
		} else if (privateKey instanceof ECPrivateKey ec) {
			int octets = (ec.getParams().getOrder().bitLength() + 7) / 8;
			members.put("d", JsonText.string(base64UrlFixedLength(ec.getS(), octets)));
		} else if (privateKey instanceof EdECPrivateKey ed) {
			byte[] seed = ed.getBytes().orElseThrow(() -> new IllegalArgumentException("An EdDSA key without bytes"));
			members.put("d", JsonText.string(TestJws.base64Url(seed)));
		} else if (privateKey instanceof XECPrivateKey xec) {
			byte[] scalar = xec.getScalar().orElseThrow(() -> new IllegalArgumentException("An XDH key without bytes"));
			members.put("d", JsonText.string(TestJws.base64Url(scalar)));
		} else {
			throw new IllegalArgumentException("Unsupported private key: " + privateKey.getAlgorithm());
		}
		return members;
	}

	private static byte[] littleEndianBytes(BigInteger value, int octets) {
		byte[] bigEndian = fixedLengthBytes(value, octets);
		byte[] littleEndian = new byte[octets];
		for (int index = 0; index < octets; ++index)
			littleEndian[index] = bigEndian[octets - 1 - index];
		return littleEndian;
	}

	private static int coordinateOctets(ECParameterSpec parameters) {
		return (parameters.getCurve().getField().getFieldSize() + 7) / 8;
	}

	/**
	 * The JWK name of a NIST curve, matched on all of its parameters: a field size alone would also match other
	 * curves, such as secp256k1, whose points the JDK's {@code KeyFactory} accepts.
	 */
	private static String curveName(ECParameterSpec parameters) {
		for (Map.Entry<String, String> curve : NIST_CURVES) {
			ECParameterSpec named = TestJws.namedCurveParameters(curve.getValue());
			boolean same = parameters.getCurve().equals(named.getCurve())
					&& parameters.getGenerator().equals(named.getGenerator())
					&& parameters.getOrder().equals(named.getOrder())
					&& parameters.getCofactor() == named.getCofactor();
			if (same)
				return curve.getKey();
		}
		throw new IllegalArgumentException("Unsupported EC curve: not P-256, P-384 or P-521");
	}

	private static List<BigInteger> rocaPrimes() {
		List<BigInteger> primes = new ArrayList<>();
		for (int candidate = 3; candidate <= 167; candidate += 2)
			if (BigInteger.valueOf(candidate).isProbablePrime(64))
				primes.add(BigInteger.valueOf(candidate));
		return List.copyOf(primes);
	}

	private static BigInteger hashToInteger(String label) {
		try {
			return new BigInteger(1,
					MessageDigest.getInstance("SHA-256").digest(label.getBytes(StandardCharsets.UTF_8)));
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("Every JDK provides SHA-256", e);
		}
	}

	/**
	 * An affine point; {@code null} stands for the point at infinity (Weierstrass) where one is needed.
	 */
	@Immutable
	private static final class Point {
		private final BigInteger x;
		private final BigInteger y;

		private Point(BigInteger x, BigInteger y) {
			this.x = x;
			this.y = y;
		}
	}

	/**
	 * P + Q on y² = x³ + a·x + b over F_p, affine; {@code null} is the point at infinity.
	 */
	private static @Nullable Point weierstrassAdd(@Nullable Point first, @Nullable Point second, BigInteger p,
			BigInteger a) {
		if (first == null)
			return second;
		if (second == null)
			return first;
		BigInteger slope;
		if (first.x.equals(second.x)) {
			if (first.y.add(second.y).mod(p).signum() == 0)
				return null;
			slope = THREE.multiply(first.x).multiply(first.x).add(a)
					.multiply(BigInteger.TWO.multiply(first.y).modInverse(p)).mod(p);
		} else {
			slope = second.y.subtract(first.y).multiply(second.x.subtract(first.x).modInverse(p)).mod(p);
		}
		BigInteger x = slope.multiply(slope).subtract(first.x).subtract(second.x).mod(p);
		BigInteger y = slope.multiply(first.x.subtract(x)).subtract(first.y).mod(p);
		return new Point(x, y);
	}

	private static @Nullable Point weierstrassMultiply(BigInteger scalar, Point point, BigInteger p, BigInteger a) {
		@Nullable Point result = null;
		for (int bit = scalar.bitLength() - 1; bit >= 0; --bit) {
			result = weierstrassAdd(result, result, p, a);
			if (scalar.testBit(bit))
				result = weierstrassAdd(result, point, p, a);
		}
		return result;
	}

	/**
	 * P + Q on the twisted Edwards curve −x² + y² = 1 + d·x²·y² (Ed25519); the formula is complete, and the identity
	 * is (0, 1).
	 */
	private static Point edwardsAdd(Point first, Point second) {
		BigInteger p = ED25519_FIELD_PRIME;
		BigInteger t = ED25519_D.multiply(first.x).multiply(second.x).multiply(first.y).multiply(second.y).mod(p);
		BigInteger x = first.x.multiply(second.y).add(first.y.multiply(second.x))
				.multiply(BigInteger.ONE.add(t).modInverse(p)).mod(p);
		BigInteger y = first.y.multiply(second.y).add(first.x.multiply(second.x))
				.multiply(BigInteger.ONE.subtract(t).mod(p).modInverse(p)).mod(p);
		return new Point(x, y);
	}

	private static Point edwardsMultiply(BigInteger scalar, Point point) {
		Point result = new Point(BigInteger.ZERO, BigInteger.ONE);
		for (int bit = scalar.bitLength() - 1; bit >= 0; --bit) {
			result = edwardsAdd(result, result);
			if (scalar.testBit(bit))
				result = edwardsAdd(result, point);
		}
		return result;
	}

	private static boolean isEdwardsIdentity(Point point) {
		return point.x.signum() == 0 && point.y.equals(BigInteger.ONE);
	}

	/**
	 * The eight small-order encodings, computed once.
	 */
	@Immutable
	private static final class SmallOrderHolder {
		private static final List<String> ENCODINGS = compute();

		private static List<String> compute() {
			for (BigInteger y = THREE; ; y = y.add(BigInteger.ONE)) {
				Optional<BigInteger> x = ed25519DecodeX(y, false);
				if (x.isEmpty())
					continue;
				Point torsion = edwardsMultiply(ED25519_GROUP_ORDER, new Point(x.get(), y));
				Point fourTimes = edwardsAdd(edwardsAdd(torsion, torsion), edwardsAdd(torsion, torsion));
				if (isEdwardsIdentity(fourTimes))
					continue;
				List<String> encodings = new ArrayList<>(8);
				Point multiple = new Point(BigInteger.ZERO, BigInteger.ONE);
				for (int index = 0; index < 8; ++index) {
					encodings.add(ed25519PublicKeyEncoding(multiple.y, multiple.x.testBit(0)));
					multiple = edwardsAdd(multiple, torsion);
				}
				return List.copyOf(encodings);
			}
		}
	}

	/**
	 * The P-256 key with a leading zero octet in x, computed once.
	 */
	@Immutable
	private static final class ShortXHolder {
		// Declared before INSTANCE, which the constructor needs initialized.
		private static final BigInteger BOUND = BigInteger.TWO.pow(248);
		private static final ShortXHolder INSTANCE = new ShortXHolder();

		private final BigInteger scalar;
		private final BigInteger x;
		private final BigInteger y;

		private ShortXHolder() {
			ECParameterSpec parameters = TestJws.namedCurveParameters("secp256r1");
			BigInteger p = fieldPrime(parameters);
			BigInteger a = parameters.getCurve().getA();
			BigInteger order = parameters.getOrder();
			Point generator = new Point(parameters.getGenerator().getAffineX(), parameters.getGenerator().getAffineY());
			BigInteger k = hashToInteger("Revetsec TEST ONLY P-256 key with a leading zero octet in x").mod(order);
			@Nullable Point point = weierstrassMultiply(k, generator, p, a);
			while (point == null || point.x.compareTo(BOUND) >= 0) {
				point = weierstrassAdd(point, generator, p, a);
				k = k.add(BigInteger.ONE).mod(order);
			}
			Point found = requireNonNull(point);
			this.scalar = k;
			this.x = found.x;
			this.y = found.y;
		}
	}

	/**
	 * The ROCA-fingerprinted primes, computed once.
	 */
	@Immutable
	private static final class RocaHolder {
		private static final RocaHolder INSTANCE = new RocaHolder();

		private final BigInteger p;
		private final BigInteger q;

		private RocaHolder() {
			BigInteger product = BigInteger.ONE;
			for (BigInteger prime : ROCA_PRIMES)
				product = product.multiply(prime);
			this.p = fingerprintedPrime(product, 17, "p");
			this.q = fingerprintedPrime(product, 29, "q");
		}

		/**
		 * The first prime k·M + (65537^a mod M) at or after a hash-chosen k, with its top two bits set so the
		 * product of two has exactly 2,048 bits, and with p − 1 prime to 65537.
		 */
		private static BigInteger fingerprintedPrime(BigInteger product, int exponent, String label) {
			BigInteger residue = F4.modPow(BigInteger.valueOf(exponent), product);
			BigInteger lowest = BigInteger.TWO.pow(1023).add(BigInteger.TWO.pow(1022));
			BigInteger k = lowest.divide(product).add(BigInteger.ONE)
					.add(hashToInteger("Revetsec TEST ONLY ROCA prime " + label).shiftRight(64));
			while (true) {
				BigInteger candidate = k.multiply(product).add(residue);
				if (candidate.bitLength() != 1024)
					throw new IllegalStateException("The ROCA search left the 1024-bit range");
				if (candidate.testBit(0) && candidate.isProbablePrime(64)
						&& F4.gcd(candidate.subtract(BigInteger.ONE)).equals(BigInteger.ONE))
					return candidate;
				k = k.add(BigInteger.ONE);
			}
		}
	}

	/**
	 * The TEST ONLY fixture keys. Every one is public, so none may protect anything real (see the fixtures' README).
	 */
	@Immutable
	public enum Fixture {
		/**
		 * {@code idp-signing-rsa-2048}: RSA-2048, e = 65537.
		 */
		IDP_SIGNING_RSA_2048("idp-signing-rsa-2048", "RSA"),
		/**
		 * {@code idp-signing-rsa-3072}: RSA-3072.
		 */
		IDP_SIGNING_RSA_3072("idp-signing-rsa-3072", "RSA"),
		/**
		 * {@code idp-signing-ec-p256}: EC P-256.
		 */
		IDP_SIGNING_EC_P256("idp-signing-ec-p256", "EC"),
		/**
		 * {@code idp-signing-ec-p384}: EC P-384.
		 */
		IDP_SIGNING_EC_P384("idp-signing-ec-p384", "EC"),
		/**
		 * {@code idp-signing-ec-p521}: EC P-521.
		 */
		IDP_SIGNING_EC_P521("idp-signing-ec-p521", "EC"),
		/**
		 * {@code negative-attacker-rsa-2048}: a well-formed RSA-2048 key no test trusts.
		 */
		NEGATIVE_ATTACKER_RSA_2048("negative-attacker-rsa-2048", "RSA"),
		/**
		 * {@code negative-rsa-1024}: RSA-1024, below the 2048-bit minimum.
		 */
		NEGATIVE_RSA_1024("negative-rsa-1024", "RSA"),
		/**
		 * {@code negative-unconfigured-ec-p256}: a well-formed P-256 key no test configures.
		 */
		NEGATIVE_UNCONFIGURED_EC_P256("negative-unconfigured-ec-p256", "EC"),
		/**
		 * {@code sp-signing-rsa-2048}: RSA-2048.
		 */
		SP_SIGNING_RSA_2048("sp-signing-rsa-2048", "RSA"),
		/**
		 * {@code sp-encryption-rsa-2048}: RSA-2048 whose certificate allows only {@code keyEncipherment}.
		 */
		SP_ENCRYPTION_RSA_2048("sp-encryption-rsa-2048", "RSA"),
		/**
		 * {@code fixtures/pem/ed25519-key.pem}: Ed25519, with no certificate.
		 */
		ED25519(null, "Ed25519");

		private final @Nullable String name;
		private final String keyAlgorithm;

		Fixture(@Nullable String name, String keyAlgorithm) {
			this.name = name;
			this.keyAlgorithm = keyAlgorithm;
		}

		/**
		 * The JWK {@code kty} of this key.
		 *
		 * @return {@code RSA}, {@code EC} or {@code OKP}
		 */
		public String getKeyType() {
			return "Ed25519".equals(this.keyAlgorithm) ? "OKP" : this.keyAlgorithm;
		}

		/**
		 * The private key, read from its PKCS#8 PEM file.
		 *
		 * @return a new private key object
		 */
		public PrivateKey getPrivateKey() {
			String resource = this.name == null ? "/fixtures/pem/ed25519-key.pem"
					: "/fixtures/keys/" + this.name + "-key.pem";
			try {
				return KeyFactory.getInstance(this.keyAlgorithm)
						.generatePrivate(new PKCS8EncodedKeySpec(pemBody(resource, "PRIVATE KEY")));
			} catch (GeneralSecurityException e) {
				throw new IllegalStateException("Unable to load TEST ONLY key " + resource, e);
			}
		}

		/**
		 * The public key: from the certificate, or for {@link #ED25519} from {@code fixtures/pem/ed25519-public.pem}.
		 *
		 * @return a new public key object
		 */
		public PublicKey getPublicKey() {
			Optional<X509Certificate> certificate = getCertificate();
			if (certificate.isPresent())
				return certificate.get().getPublicKey();
			try {
				return KeyFactory.getInstance(this.keyAlgorithm)
						.generatePublic(new X509EncodedKeySpec(
								pemBody("/fixtures/pem/ed25519-public.pem", "PUBLIC KEY")));
			} catch (GeneralSecurityException e) {
				throw new IllegalStateException("Unable to load the TEST ONLY Ed25519 public key", e);
			}
		}

		/**
		 * The key pair.
		 *
		 * @return a new key pair
		 */
		public KeyPair getKeyPair() {
			return new KeyPair(getPublicKey(), getPrivateKey());
		}

		/**
		 * The self-signed certificate, for an {@code x5c}.
		 *
		 * @return the certificate, or empty for {@link #ED25519}
		 */
		public Optional<X509Certificate> getCertificate() {
			if (this.name == null)
				return Optional.empty();
			String resource = "/fixtures/keys/" + this.name + "-cert.pem";
			try (InputStream inputStream = new ByteArrayInputStream(pemBody(resource, "CERTIFICATE"))) {
				return Optional.of((X509Certificate) CertificateFactory.getInstance("X.509")
						.generateCertificate(inputStream));
			} catch (IOException | GeneralSecurityException e) {
				throw new IllegalStateException("Unable to load TEST ONLY certificate " + resource, e);
			}
		}

		private static byte[] pemBody(String resource, String label) {
			String text;
			try (@Nullable InputStream inputStream = TestJsonWebKeys.class.getResourceAsStream(resource)) {
				if (inputStream == null)
					throw new IllegalStateException("Missing TEST ONLY fixture " + resource);
				text = new String(inputStream.readAllBytes(), StandardCharsets.US_ASCII);
			} catch (IOException e) {
				throw new IllegalStateException("Unable to read TEST ONLY fixture " + resource, e);
			}
			String begin = "-----BEGIN " + label + "-----";
			String end = "-----END " + label + "-----";
			int start = text.indexOf(begin);
			int stop = text.indexOf(end);
			if (start < 0 || stop < start)
				throw new IllegalStateException(resource + " holds no " + label + " block");
			return Base64.getMimeDecoder().decode(text.substring(start + begin.length(), stop));
		}
	}

	/**
	 * Builds one JWK's JSON text (see the class description for the member order).
	 */
	@NotThreadSafe
	public static final class Builder {
		// Both keep insertion order.
		private final Map<String, String> keyMembers;
		private final @Nullable Map<String, String> privateMembers;
		private @Nullable String kid;
		private @Nullable String use;
		private @Nullable List<String> keyOps;
		private @Nullable String alg;
		private @Nullable List<X509Certificate> x5c;
		private @Nullable String issuer;
		private boolean includePrivateMembers;
		// In call order; a null value removes the member.
		private final Map<String, @Nullable String> overrides = new LinkedHashMap<>();

		private Builder(Map<String, String> keyMembers, @Nullable Map<String, String> privateMembers) {
			this.keyMembers = keyMembers;
			this.privateMembers = privateMembers;
		}

		/**
		 * The {@code kid} member.
		 *
		 * @param kid the key ID, or {@code null} for none
		 * @return this builder
		 */
		public Builder kid(@Nullable String kid) {
			this.kid = kid;
			return this;
		}

		/**
		 * The {@code use} member.
		 *
		 * @param use such as {@code sig} or {@code enc}, or {@code null} for none
		 * @return this builder
		 */
		public Builder use(@Nullable String use) {
			this.use = use;
			return this;
		}

		/**
		 * The {@code key_ops} member.
		 *
		 * @param keyOps such as {@code ["verify"]}, or {@code null} for none
		 * @return this builder
		 */
		public Builder keyOps(@Nullable List<String> keyOps) {
			this.keyOps = keyOps == null ? null : List.copyOf(keyOps);
			return this;
		}

		/**
		 * The {@code alg} member.
		 *
		 * @param alg such as {@code RS256}, or {@code null} for none
		 * @return this builder
		 */
		public Builder alg(@Nullable String alg) {
			this.alg = alg;
			return this;
		}

		/**
		 * The {@code x5c} member: each certificate's DER in standard base64, first the key's own.
		 *
		 * @param x5c the chain, or {@code null} for none
		 * @return this builder
		 */
		public Builder x5c(@Nullable List<X509Certificate> x5c) {
			this.x5c = x5c == null ? null : List.copyOf(x5c);
			return this;
		}

		/**
		 * The {@code issuer} member some IdPs publish on each key, such as Entra's (INV-C6, plan M2-11).
		 *
		 * @param issuer the issuer string, or {@code null} for none
		 * @return this builder
		 */
		public Builder issuer(@Nullable String issuer) {
			this.issuer = issuer;
			return this;
		}

		/**
		 * Whether to write the private members ({@code d}, and for RSA {@code p}, {@code q}, {@code dp}, {@code dq}
		 * and {@code qi}).
		 *
		 * @param includePrivateMembers whether to write them, or {@code null} for the default, {@code false}
		 * @return this builder
		 * @throws IllegalStateException at {@link #toJson()} if the builder has no private key
		 */
		public Builder includePrivateMembers(@Nullable Boolean includePrivateMembers) {
			this.includePrivateMembers = includePrivateMembers != null && includePrivateMembers;
			return this;
		}

		/**
		 * Sets a member to raw JSON text, replacing a generated member of that name where it stands, or appending a
		 * new member; the last call for a name wins.
		 *
		 * @param name the member name
		 * @param rawJsonValue the value as raw JSON text, such as {@code "\"AQAB\""}, {@code null} or {@code 123}
		 * @return this builder
		 */
		public Builder member(String name, String rawJsonValue) {
			this.overrides.put(requireNonNull(name), requireNonNull(rawJsonValue));
			return this;
		}

		/**
		 * Leaves a member out, generated or set; a later {@link #member(String, String)} adds it back.
		 *
		 * @param name the member name
		 * @return this builder
		 */
		public Builder withoutMember(String name) {
			this.overrides.put(requireNonNull(name), null);
			return this;
		}

		/**
		 * The JWK's JSON text.
		 *
		 * @return the JSON object text, with no whitespace
		 */
		public String toJson() {
			Map<String, String> members = new LinkedHashMap<>(this.keyMembers);
			if (this.includePrivateMembers) {
				if (this.privateMembers == null)
					throw new IllegalStateException("This key has no private members to include");
				members.putAll(this.privateMembers);
			}
			if (this.kid != null)
				members.put("kid", JsonText.string(this.kid));
			if (this.use != null)
				members.put("use", JsonText.string(this.use));
			if (this.keyOps != null)
				members.put("key_ops", JsonText.stringArray(this.keyOps));
			if (this.alg != null)
				members.put("alg", JsonText.string(this.alg));
			if (this.x5c != null)
				members.put("x5c", JsonText.stringArray(this.x5c.stream().map(Builder::standardBase64).toList()));
			if (this.issuer != null)
				members.put("issuer", JsonText.string(this.issuer));
			for (Map.Entry<String, @Nullable String> override : this.overrides.entrySet()) {
				@Nullable String value = override.getValue();
				if (value == null)
					members.remove(override.getKey());
				else
					members.put(override.getKey(), value);
			}
			List<Map.Entry<String, String>> entries = new ArrayList<>(members.entrySet());
			return JsonText.object(entries);
		}

		/**
		 * A JWK Set holding only this key.
		 *
		 * @return {@code {"keys":[...]}}
		 */
		public String toKeySetJson() {
			return keySet(List.of(toJson()));
		}

		private static String standardBase64(X509Certificate certificate) {
			try {
				return Base64.getEncoder().encodeToString(certificate.getEncoded());
			} catch (CertificateEncodingException e) {
				throw new IllegalStateException("Unable to encode a certificate", e);
			}
		}
	}
}
