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

import com.revetsec.json.JsonObject;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Makes compact JWS and JWT strings for tests (RFC 7515 section 7.1, RFC 7519 section 7.1), signed with JDK keys and
 * the JDK's own signature engines, never through Revetsec, so a Revetsec bug cannot hide in its own fixtures.
 * <p>
 * <strong>Well-formed tokens.</strong> {@link #withAlgorithm(Algorithm)} starts a token whose {@code alg} header is
 * that algorithm's wire value; {@link Builder#sign(Key)} or {@link Builder#sign(byte[])} signs it:
 * <pre>{@code
 * String token = TestJws.withAlgorithm(TestJws.Algorithm.RS256)
 *     .kid("rsa-1")
 *     .typ("JWT")
 *     .payload(claims.toJson())
 *     .sign(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());
 * }</pre>
 * RS* use PKCS#1 v1.5, PS* use RSASSA-PSS with the RFC 7518 section 3.5 parameters (MGF1 with the same hash, a salt
 * as long as the hash, trailer field 1), ES* use the JDK's fixed-length {@code R || S} form
 * ({@code SHAxxxwithECDSAinP1363Format}, which only test code may use; RFC 7518 section 3.4), Ed25519 and EdDSA use
 * {@code Ed25519} (RFC 8037 section 3.1), and HS* use {@code HmacSHAxxx} over a byte secret.
 * <p>
 * <strong>Anything else.</strong> A test can write any header: another {@code alg} string ({@link Builder#alg(String)},
 * for {@code none} or {@code rs256}), extra and duplicate members ({@link Builder#headerMember(String, String)}), a
 * whole header's JSON text ({@link Builder#header(String)}) or raw bytes ({@link Builder#headerBytes(byte[])}). The
 * signature can be real, raw bytes ({@link Builder#withSignature(byte[])}), raw segment text
 * ({@link Builder#withSignatureSegment(String)}) or empty ({@link Builder#unsigned()}). A signed token's
 * {@link Variant}s derive the hostile forms Revetsec must reject from it: a DER ECDSA signature, r or s of zero, the
 * group order or one more, 63 and 65 octets, extra segments, padding and non-canonical base64url.
 * <p>
 * PKCS#1 v1.5, Ed25519 and HMAC signatures are deterministic. ECDSA and PSS draw fresh randomness each time, so a
 * test must not depend on their bytes.
 * <p>
 * Text is encoded strictly. An unpaired surrogate has no UTF-8 form, and {@code String.getBytes} would silently write
 * {@code ?} in its place, so a header or payload that carries one fails with {@link IllegalArgumentException}: write
 * its JSON escape ({@code \}{@code ud800}) or pass the raw bytes instead. A signing input must be ASCII for the same
 * reason.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class TestJws {
	private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();
	static final String BASE64_URL_ALPHABET =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

	private TestJws() {
		// Static helpers only.
	}

	/**
	 * Starts a token whose {@code alg} header is {@code algorithm}'s wire value, and which {@link Builder#sign(Key)}
	 * or {@link Builder#sign(byte[])} signs with that algorithm.
	 *
	 * @param algorithm the signing algorithm
	 * @return a new builder
	 */
	public static Builder withAlgorithm(Algorithm algorithm) {
		return new Builder(requireNonNull(algorithm));
	}

	/**
	 * Starts a token with no signing algorithm and no {@code alg} header unless {@link Builder#alg(String)} sets one,
	 * for tokens whose signature a test supplies itself ({@code alg: none} among them).
	 *
	 * @return a new builder
	 */
	public static Builder builder() {
		return new Builder(null);
	}

	/**
	 * Canonical base64url without padding (RFC 7515 section 2).
	 *
	 * @param bytes the bytes
	 * @return the encoded text
	 */
	public static String base64Url(byte[] bytes) {
		return BASE64_URL.encodeToString(requireNonNull(bytes));
	}

	/**
	 * Canonical base64url without padding of {@code text}'s UTF-8 bytes.
	 *
	 * @param text the text
	 * @return the encoded text
	 * @throws IllegalArgumentException if {@code text} has an unpaired surrogate
	 */
	public static String base64Url(String text) {
		return base64Url(utf8(text));
	}

	/**
	 * {@code text}'s UTF-8 bytes, encoded strictly: unlike {@code String.getBytes}, an unpaired surrogate fails
	 * instead of becoming {@code ?}.
	 *
	 * @param text the text
	 * @return a new array
	 * @throws IllegalArgumentException if {@code text} has an unpaired surrogate
	 */
	static byte[] utf8(String text) {
		requireNonNull(text);
		try {
			ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder()
					.onMalformedInput(CodingErrorAction.REPORT)
					.onUnmappableCharacter(CodingErrorAction.REPORT)
					.encode(CharBuffer.wrap(text));
			byte[] bytes = new byte[encoded.remaining()];
			encoded.get(bytes);
			return bytes;
		} catch (CharacterCodingException e) {
			throw new IllegalArgumentException("An unpaired surrogate has no UTF-8 form; write its JSON escape or pass "
					+ "raw bytes", e);
		}
	}

	/**
	 * Joins segments with {@code .}, as the compact serialization does.
	 *
	 * @param segments the segments, in order
	 * @return the joined text
	 */
	public static String compact(String... segments) {
		for (String segment : segments)
			requireNonNull(segment);
		return String.join(".", segments);
	}

	/**
	 * {@code segment} followed by the {@code =} padding standard base64 would give it, or by one {@code =} when it
	 * needs none. The compact serialization never carries padding (RFC 7515 section 2).
	 *
	 * @param segment a base64url segment
	 * @return the padded text
	 */
	public static String padded(String segment) {
		requireNonNull(segment);
		int remainder = segment.length() % 4;
		return segment + (remainder == 0 ? "=" : "=".repeat(4 - remainder));
	}

	/**
	 * {@code segment} with the lowest unused bit of its last character set: a non-canonical encoding of the same
	 * bytes, which a lenient decoder accepts and a canonical one rejects (RFC 4648 section 3.5).
	 *
	 * @param segment a canonical base64url segment
	 * @return the non-canonical text
	 * @throws IllegalStateException if the segment's length is a multiple of 4, so its last character has no unused
	 * bits
	 */
	public static String withNonCanonicalTrailingBits(String segment) {
		requireNonNull(segment);
		int remainder = segment.length() % 4;
		if (remainder != 2 && remainder != 3)
			throw new IllegalStateException("A segment of " + segment.length() + " characters has no unused bits");
		int last = BASE64_URL_ALPHABET.indexOf(segment.charAt(segment.length() - 1));
		if (last < 0)
			throw new IllegalArgumentException("Not a base64url segment: " + segment);
		// Two characters carry 12 bits for 1 octet (4 unused); three carry 18 bits for 2 octets (2 unused).
		int unusedMask = remainder == 2 ? 0x0f : 0x03;
		if ((last & unusedMask) != 0)
			throw new IllegalArgumentException("The segment is already non-canonical: " + segment);
		return segment.substring(0, segment.length() - 1) + BASE64_URL_ALPHABET.charAt(last | 1);
	}

	/**
	 * A fixed-length ECDSA signature {@code R || S} (RFC 7518 section 3.4) with arbitrary values.
	 *
	 * @param r the first half, 0 to 256^octets − 1
	 * @param s the second half, 0 to 256^octets − 1
	 * @param coordinateOctets the length of each half: 32, 48 or 66 for P-256, P-384 and P-521
	 * @return a new array of {@code 2 × coordinateOctets} octets
	 */
	public static byte[] ecdsaSignature(BigInteger r, BigInteger s, Integer coordinateOctets) {
		requireNonNull(coordinateOctets);
		byte[] signature = new byte[2 * coordinateOctets];
		System.arraycopy(fixedLength(r, coordinateOctets), 0, signature, 0, coordinateOctets);
		System.arraycopy(fixedLength(s, coordinateOctets), 0, signature, coordinateOctets, coordinateOctets);
		return signature;
	}

	/**
	 * The first half, r, of a fixed-length ECDSA signature.
	 *
	 * @param signature {@code R || S}, of even length
	 * @return r
	 */
	public static BigInteger ecdsaR(byte[] signature) {
		requireEvenLength(signature);
		return new BigInteger(1, Arrays.copyOfRange(signature, 0, signature.length / 2));
	}

	/**
	 * The second half, s, of a fixed-length ECDSA signature.
	 *
	 * @param signature {@code R || S}, of even length
	 * @return s
	 */
	public static BigInteger ecdsaS(byte[] signature) {
		requireEvenLength(signature);
		return new BigInteger(1, Arrays.copyOfRange(signature, signature.length / 2, signature.length));
	}

	/**
	 * Re-encodes a fixed-length ECDSA signature as the ASN.1 DER {@code SEQUENCE { INTEGER r, INTEGER s }} that the
	 * JDK's {@code SHAxxxwithECDSA} engines produce and consume: the form an IdP that ignores RFC 7518 section 3.4
	 * sends.
	 *
	 * @param signature {@code R || S}, of even length
	 * @return a new array holding the DER encoding
	 */
	public static byte[] derEncodedEcdsaSignature(byte[] signature) {
		byte[] r = ecdsaR(signature).toByteArray();
		byte[] s = ecdsaS(signature).toByteArray();
		ByteArrayOutputStream content = new ByteArrayOutputStream();
		writeDer(content, 0x02, r);
		writeDer(content, 0x02, s);
		ByteArrayOutputStream sequence = new ByteArrayOutputStream();
		writeDer(sequence, 0x30, content.toByteArray());
		return sequence.toByteArray();
	}

	/**
	 * The order n of an ES* algorithm's curve, read from the JDK's named-curve parameters.
	 *
	 * @param algorithm ES256, ES384 or ES512
	 * @return n
	 */
	public static BigInteger curveOrder(Algorithm algorithm) {
		return curveParameters(algorithm).getOrder();
	}

	/**
	 * The JDK's parameters for an ES* algorithm's curve.
	 *
	 * @param algorithm ES256, ES384 or ES512
	 * @return the curve's field, coefficients, generator and order
	 */
	public static ECParameterSpec curveParameters(Algorithm algorithm) {
		requireNonNull(algorithm);
		if (algorithm.family != Family.EC)
			throw new IllegalArgumentException(algorithm + " is not an ECDSA algorithm");
		return namedCurveParameters(requireNonNull(algorithm.jcaCurve));
	}

	/**
	 * Signs {@code signingInput}'s ASCII bytes with the JDK engine for {@code algorithm}.
	 *
	 * @param algorithm the algorithm
	 * @param key a private key of the algorithm's family, or a secret key for HS*
	 * @param signingInput the text to sign, such as {@code header.payload}
	 * @return the signature (fixed-length {@code R || S} for ES*)
	 * @throws IllegalArgumentException if {@code signingInput} is not ASCII, which {@code String.getBytes} would
	 * silently turn into {@code ?}
	 */
	public static byte[] signature(Algorithm algorithm, Key key, String signingInput) {
		requireNonNull(algorithm);
		requireNonNull(key);
		requireNonNull(signingInput);
		if (!signingInput.chars().allMatch(character -> character < 0x80))
			throw new IllegalArgumentException("A signing input is ASCII: " + signingInput);
		byte[] input = signingInput.getBytes(StandardCharsets.US_ASCII);
		try {
			if (algorithm.family == Family.HMAC) {
				Mac mac = Mac.getInstance(algorithm.jcaName);
				mac.init(key);
				return mac.doFinal(input);
			}
			if (!(key instanceof PrivateKey privateKey))
				throw new IllegalArgumentException(algorithm + " signs with a private key, not " + key.getAlgorithm());
			Signature signature = Signature.getInstance(algorithm.jcaName);
			Optional<PSSParameterSpec> pssParameters = algorithm.getPssParameters();
			if (pssParameters.isPresent())
				signature.setParameter(pssParameters.get());
			signature.initSign(privateKey);
			signature.update(input);
			return signature.sign();
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("Unable to sign with " + algorithm, e);
		}
	}

	private static void requireEvenLength(byte[] signature) {
		requireNonNull(signature);
		if (signature.length == 0 || signature.length % 2 != 0)
			throw new IllegalArgumentException("An R || S signature has a positive, even length: " + signature.length);
	}

	private static byte[] fixedLength(BigInteger value, int octets) {
		requireNonNull(value);
		if (value.signum() < 0 || value.bitLength() > 8 * octets)
			throw new IllegalArgumentException("Does not fit in " + octets + " octets: " + value);
		byte[] minimal = value.toByteArray();
		byte[] fixed = new byte[octets];
		int copied = Math.min(minimal.length, octets);
		System.arraycopy(minimal, minimal.length - copied, fixed, octets - copied, copied);
		return fixed;
	}

	private static void writeDer(ByteArrayOutputStream output, int tag, byte[] content) {
		output.write(tag);
		int length = content.length;
		if (length < 0x80) {
			output.write(length);
		} else if (length <= 0xff) {
			output.write(0x81);
			output.write(length);
		} else {
			output.write(0x82);
			output.write(length >>> 8);
			output.write(length & 0xff);
		}
		output.writeBytes(content);
	}

	static ECParameterSpec namedCurveParameters(String jcaCurveName) {
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec(jcaCurveName));
			return parameters.getParameterSpec(ECParameterSpec.class);
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("The JDK has no curve " + jcaCurveName, e);
		}
	}

	/**
	 * A key family.
	 */
	@Immutable
	enum Family {
		RSA,
		EC,
		OKP,
		HMAC
	}

	/**
	 * The JWS algorithms the helper signs with (RFC 7518 section 3.1, RFC 8037, RFC 9864). The names mirror
	 * {@code com.revetsec.jose.JwsAlgorithm} but the helper keeps its own list, so the fixtures do not depend on the
	 * code under test.
	 */
	@Immutable
	public enum Algorithm {
		/**
		 * RSASSA-PKCS1-v1_5 with SHA-256.
		 */
		RS256("RS256", "SHA256withRSA", Family.RSA, null, null, null),
		/**
		 * RSASSA-PKCS1-v1_5 with SHA-384.
		 */
		RS384("RS384", "SHA384withRSA", Family.RSA, null, null, null),
		/**
		 * RSASSA-PKCS1-v1_5 with SHA-512.
		 */
		RS512("RS512", "SHA512withRSA", Family.RSA, null, null, null),
		/**
		 * RSASSA-PSS with SHA-256, MGF1 with SHA-256 and a 32-octet salt.
		 */
		PS256("PS256", "RSASSA-PSS", Family.RSA, null, null, "SHA-256"),
		/**
		 * RSASSA-PSS with SHA-384, MGF1 with SHA-384 and a 48-octet salt.
		 */
		PS384("PS384", "RSASSA-PSS", Family.RSA, null, null, "SHA-384"),
		/**
		 * RSASSA-PSS with SHA-512, MGF1 with SHA-512 and a 64-octet salt.
		 */
		PS512("PS512", "RSASSA-PSS", Family.RSA, null, null, "SHA-512"),
		/**
		 * ECDSA on P-256 with SHA-256; 64-octet signatures.
		 */
		ES256("ES256", "SHA256withECDSAinP1363Format", Family.EC, "P-256", "secp256r1", null),
		/**
		 * ECDSA on P-384 with SHA-384; 96-octet signatures.
		 */
		ES384("ES384", "SHA384withECDSAinP1363Format", Family.EC, "P-384", "secp384r1", null),
		/**
		 * ECDSA on P-521 with SHA-512; 132-octet signatures.
		 */
		ES512("ES512", "SHA512withECDSAinP1363Format", Family.EC, "P-521", "secp521r1", null),
		/**
		 * Ed25519, under its fully specified name (RFC 9864).
		 */
		ED25519("Ed25519", "Ed25519", Family.OKP, "Ed25519", null, null),
		/**
		 * Ed25519, under the polymorphic {@code EdDSA} name (RFC 8037).
		 */
		EDDSA("EdDSA", "Ed25519", Family.OKP, "Ed25519", null, null),
		/**
		 * HMAC with SHA-256; 32-octet tags.
		 */
		HS256("HS256", "HmacSHA256", Family.HMAC, null, null, null),
		/**
		 * HMAC with SHA-384; 48-octet tags.
		 */
		HS384("HS384", "HmacSHA384", Family.HMAC, null, null, null),
		/**
		 * HMAC with SHA-512; 64-octet tags.
		 */
		HS512("HS512", "HmacSHA512", Family.HMAC, null, null, null);

		private final String wireValue;
		private final String jcaName;
		private final Family family;
		private final @Nullable String curve;
		private final @Nullable String jcaCurve;
		// PS* only: the digest for the hash and MGF1. The salt is as long as the digest.
		private final @Nullable String pssDigest;

		Algorithm(String wireValue, String jcaName, Family family, @Nullable String curve, @Nullable String jcaCurve,
				@Nullable String pssDigest) {
			this.wireValue = wireValue;
			this.jcaName = jcaName;
			this.family = family;
			this.curve = curve;
			this.jcaCurve = jcaCurve;
			this.pssDigest = pssDigest;
		}

		/**
		 * The {@code alg} header value, such as {@code RS256} or {@code Ed25519}.
		 *
		 * @return the wire value
		 */
		public String getWireValue() {
			return this.wireValue;
		}

		/**
		 * The JDK algorithm name the helper signs with.
		 *
		 * @return the JCA name
		 */
		public String getJcaName() {
			return this.jcaName;
		}

		/**
		 * The JWK key type that signs with this algorithm: {@code RSA}, {@code EC}, {@code OKP} or {@code oct}.
		 *
		 * @return the {@code kty}
		 */
		public String getKeyType() {
			return switch (this.family) {
				case RSA -> "RSA";
				case EC -> "EC";
				case OKP -> "OKP";
				case HMAC -> "oct";
			};
		}

		/**
		 * The JWK curve name of an ES* or Ed25519 algorithm.
		 *
		 * @return {@code P-256}, {@code P-384}, {@code P-521} or {@code Ed25519}; empty for RSA and HMAC
		 */
		public Optional<String> getCurve() {
			return Optional.ofNullable(this.curve);
		}

		/**
		 * The PSS parameters a PS* algorithm signs with (RFC 7518 section 3.5): MGF1 with the same hash, a salt as long
		 * as the hash, and trailer field 1.
		 *
		 * @return new parameters, or empty for any other algorithm
		 */
		public Optional<PSSParameterSpec> getPssParameters() {
			@Nullable String digest = this.pssDigest;
			if (digest == null)
				return Optional.empty();
			int saltLength = switch (digest) {
				case "SHA-256" -> 32;
				case "SHA-384" -> 48;
				default -> 64;
			};
			return Optional.of(new PSSParameterSpec(digest, "MGF1", new MGF1ParameterSpec(digest), saltLength,
					PSSParameterSpec.TRAILER_FIELD_BC));
		}

		/**
		 * The signature length that does not depend on the key.
		 *
		 * @return 64, 96 or 132 for ES*, 64 for Ed25519 and EdDSA, 32, 48 or 64 for HS*; empty for RS* and PS*,
		 * whose signatures are as long as the modulus
		 */
		public Optional<Integer> getSignatureLength() {
			return switch (this) {
				case ES256, ED25519, EDDSA, HS512 -> Optional.of(64);
				case ES384 -> Optional.of(96);
				case ES512 -> Optional.of(132);
				case HS256 -> Optional.of(32);
				case HS384 -> Optional.of(48);
				case RS256, RS384, RS512, PS256, PS384, PS512 -> Optional.empty();
			};
		}

		/**
		 * The signature length with {@code key}.
		 *
		 * @param key a key of this algorithm's family
		 * @return the length in octets: the modulus length for RS* and PS*, {@link #getSignatureLength()} otherwise
		 */
		public Integer signatureLength(Key key) {
			requireNonNull(key);
			if (this.family == Family.RSA) {
				if (!(key instanceof RSAKey rsaKey))
					throw new IllegalArgumentException(this + " needs an RSA key");
				return (rsaKey.getModulus().bitLength() + 7) / 8;
			}
			return getSignatureLength().orElseThrow();
		}
	}

	/**
	 * Hostile forms of a signed token ({@link Signed#withVariant(Variant)}). The ECDSA-only variants throw
	 * {@link IllegalStateException} for any other algorithm.
	 */
	@Immutable
	public enum Variant {
		/**
		 * ECDSA only: the same signature as ASN.1 DER instead of {@code R || S} (RFC 7518 section 3.4), which the
		 * JDK's plain {@code SHAxxxwithECDSA} would accept.
		 */
		DER_SIGNATURE,
		/**
		 * ECDSA only: r = 0, s unchanged.
		 */
		R_ZERO,
		/**
		 * ECDSA only: s = 0, r unchanged.
		 */
		S_ZERO,
		/**
		 * ECDSA only: r = n, the curve order, s unchanged (CVE-2022-21449 family: r must lie in [1, n − 1]).
		 */
		R_EQUALS_ORDER,
		/**
		 * ECDSA only: s = n, r unchanged.
		 */
		S_EQUALS_ORDER,
		/**
		 * ECDSA only: r = n + 1, s unchanged.
		 */
		R_ORDER_PLUS_ONE,
		/**
		 * Every octet zero, at the signature's own length (for ECDSA, r = s = 0; CVE-2022-21449).
		 */
		ZERO_SIGNATURE,
		/**
		 * An empty signature segment: {@code header.payload.}.
		 */
		EMPTY_SIGNATURE,
		/**
		 * The signature without its last octet (63 octets for ES256 and Ed25519).
		 */
		ONE_OCTET_SHORT,
		/**
		 * The signature with a zero octet appended (65 octets for ES256 and Ed25519).
		 */
		ONE_OCTET_LONG,
		/**
		 * The lowest bit of the signature's last octet flipped: the right shape, the wrong value.
		 */
		FLIPPED_BIT,
		/**
		 * A fourth segment: {@code header.payload.signature.e30}.
		 */
		EXTRA_SEGMENT,
		/**
		 * Five segments, the shape of a JWE: {@code header.payload.signature.e30.e30}.
		 */
		FIVE_SEGMENTS,
		/**
		 * The header segment with {@code =} padding ({@link #padded(String)}).
		 */
		PADDED_HEADER,
		/**
		 * The payload segment with {@code =} padding.
		 */
		PADDED_PAYLOAD,
		/**
		 * The signature segment with {@code =} padding.
		 */
		PADDED_SIGNATURE,
		/**
		 * The signature segment with an unused trailing bit set ({@link #withNonCanonicalTrailingBits(String)}); throws
		 * {@link IllegalStateException} when the signature's length is a multiple of 3, as for ES384 and ES512.
		 */
		NON_CANONICAL_SIGNATURE,
		/**
		 * The signature segment's first character replaced with {@code +}, from the standard base64 alphabet.
		 */
		PLUS_IN_SIGNATURE,
		/**
		 * The signature segment's first character replaced with {@code /}, from the standard base64 alphabet.
		 */
		SLASH_IN_SIGNATURE
	}

	/**
	 * Builds one token. The header is, in order: {@code alg}, {@code kid} and {@code typ} (each when set), then every
	 * {@link #headerMember(String, String)} in the order added, unless {@link #header(String)} or
	 * {@link #headerBytes(byte[])} replaces it outright.
	 */
	@NotThreadSafe
	public static final class Builder {
		private final @Nullable Algorithm algorithm;
		private @Nullable String alg;
		private @Nullable String kid;
		private @Nullable String typ;
		private final List<Map.Entry<String, String>> headerMembers = new ArrayList<>();
		private byte @Nullable [] header;
		private byte[] payload = new byte[0];

		private Builder(@Nullable Algorithm algorithm) {
			this.algorithm = algorithm;
		}

		/**
		 * The {@code alg} header value, which need not name a real algorithm or the signing one ({@code none},
		 * {@code nOnE}, {@code rs256}).
		 *
		 * @param alg the value, or {@code null} for the default: the signing algorithm's wire value, or no
		 * {@code alg} member for {@link TestJws#builder()}
		 * @return this builder
		 */
		public Builder alg(@Nullable String alg) {
			this.alg = alg;
			return this;
		}

		/**
		 * The {@code kid} header value.
		 *
		 * @param kid the key ID, or {@code null} for none
		 * @return this builder
		 */
		public Builder kid(@Nullable String kid) {
			this.kid = kid;
			return this;
		}

		/**
		 * The {@code typ} header value.
		 *
		 * @param typ the type, such as {@code JWT}, or {@code null} for none
		 * @return this builder
		 */
		public Builder typ(@Nullable String typ) {
			this.typ = typ;
			return this;
		}

		/**
		 * Appends a header member after {@code alg}, {@code kid} and {@code typ}. The name may repeat, or repeat one of
		 * those three, which writes a duplicate member.
		 *
		 * @param name the member name
		 * @param rawJsonValue the member's value as raw JSON text, such as {@code "\"https://x.example/jwks\""},
		 * {@code 123} or {@code ["b64"]}
		 * @return this builder
		 * @throws IllegalArgumentException if {@code rawJsonValue} has an unpaired surrogate
		 */
		public Builder headerMember(String name, String rawJsonValue) {
			utf8(rawJsonValue);
			this.headerMembers.add(Map.entry(requireNonNull(name), rawJsonValue));
			return this;
		}

		/**
		 * The whole header as JSON text, encoded as UTF-8; it replaces {@code alg}, {@code kid}, {@code typ} and the
		 * header members.
		 *
		 * @param json the header text, or {@code null} to build the header from the other settings
		 * @return this builder
		 * @throws IllegalArgumentException if {@code json} has an unpaired surrogate
		 */
		public Builder header(@Nullable String json) {
			this.header = json == null ? null : utf8(json);
			return this;
		}

		/**
		 * The whole header as raw bytes, for headers that are not UTF-8 or carry a byte order mark.
		 *
		 * @param bytes the header bytes, or {@code null} to build the header from the other settings
		 * @return this builder
		 */
		public Builder headerBytes(byte @Nullable [] bytes) {
			this.header = bytes == null ? null : bytes.clone();
			return this;
		}

		/**
		 * The payload, encoded as UTF-8: a JWT's claims JSON, or any text.
		 *
		 * @param text the payload, or {@code null} for an empty one
		 * @return this builder
		 * @throws IllegalArgumentException if {@code text} has an unpaired surrogate
		 */
		public Builder payload(@Nullable String text) {
			this.payload = text == null ? new byte[0] : utf8(text);
			return this;
		}

		/**
		 * The payload as raw bytes.
		 *
		 * @param bytes the payload, or {@code null} for an empty one
		 * @return this builder
		 */
		public Builder payloadBytes(byte @Nullable [] bytes) {
			this.payload = bytes == null ? new byte[0] : bytes.clone();
			return this;
		}

		/**
		 * The payload as a JWT claims set: {@code claims.toJson()}.
		 *
		 * @param claims the claims
		 * @return this builder
		 */
		public Builder claims(JsonObject claims) {
			return payload(requireNonNull(claims).toJson());
		}

		/**
		 * The header segment: the base64url of the header bytes.
		 *
		 * @return the segment
		 */
		public String headerSegment() {
			return base64Url(headerBytes());
		}

		/**
		 * The payload segment.
		 *
		 * @return the segment
		 */
		public String payloadSegment() {
			return base64Url(this.payload);
		}

		/**
		 * The JWS signing input: {@code header.payload} (RFC 7515 section 5.1).
		 *
		 * @return the signing input
		 */
		public String signingInput() {
			return headerSegment() + "." + payloadSegment();
		}

		/**
		 * Signs with the builder's algorithm.
		 *
		 * @param key a private key of the algorithm's family (RS*, PS*, ES*, Ed25519, EdDSA), or a secret key (HS*)
		 * @return the compact serialization
		 * @throws IllegalStateException if the builder came from {@link TestJws#builder()}
		 */
		public String sign(Key key) {
			return signed(key).toCompactSerialization();
		}

		/**
		 * MACs with the builder's HS* algorithm over {@code secret}, which may be any non-empty bytes: a real secret,
		 * or the bytes of an RSA public key in an algorithm-confusion test.
		 *
		 * @param secret the HMAC key, at least one octet (the JDK refuses an empty key)
		 * @return the compact serialization
		 */
		public String sign(byte[] secret) {
			return signed(secret).toCompactSerialization();
		}

		/**
		 * {@link #sign(Key)}, keeping the parts.
		 *
		 * @param key a private key of the algorithm's family, or a secret key for HS*
		 * @return the signed token
		 */
		public Signed signed(Key key) {
			Algorithm signingAlgorithm = requireAlgorithm();
			String signingInput = signingInput();
			return new Signed(signingAlgorithm, signingInput, signature(signingAlgorithm, key, signingInput));
		}

		/**
		 * {@link #sign(byte[])}, keeping the parts.
		 *
		 * @param secret the HMAC key, at least one octet
		 * @return the signed token
		 */
		public Signed signed(byte[] secret) {
			Algorithm signingAlgorithm = requireAlgorithm();
			if (signingAlgorithm.family != Family.HMAC)
				throw new IllegalStateException(signingAlgorithm + " does not sign with a byte secret");
			return signed(new SecretKeySpec(requireNonNull(secret), signingAlgorithm.jcaName));
		}

		/**
		 * The token with {@code signature} as its signature, whatever the header says.
		 *
		 * @param signature the raw signature bytes, possibly empty
		 * @return the compact serialization
		 */
		public String withSignature(byte[] signature) {
			return signingInput() + "." + base64Url(requireNonNull(signature));
		}

		/**
		 * The token with {@code segment} as its signature segment, verbatim, even if it is not base64url.
		 *
		 * @param segment the signature segment text
		 * @return the compact serialization
		 */
		public String withSignatureSegment(String segment) {
			return signingInput() + "." + requireNonNull(segment);
		}

		/**
		 * The token with an empty signature: {@code header.payload.}.
		 *
		 * @return the compact serialization
		 */
		public String unsigned() {
			return signingInput() + ".";
		}

		private Algorithm requireAlgorithm() {
			if (this.algorithm == null)
				throw new IllegalStateException("A builder from TestJws.builder() has no signing algorithm");
			return this.algorithm;
		}

		private byte[] headerBytes() {
			if (this.header != null)
				return this.header.clone();
			List<Map.Entry<String, String>> members = new ArrayList<>();
			@Nullable String effectiveAlg = this.alg != null ? this.alg
					: this.algorithm != null ? this.algorithm.wireValue : null;
			if (effectiveAlg != null)
				members.add(Map.entry("alg", JsonText.string(effectiveAlg)));
			if (this.kid != null)
				members.add(Map.entry("kid", JsonText.string(this.kid)));
			if (this.typ != null)
				members.add(Map.entry("typ", JsonText.string(this.typ)));
			members.addAll(this.headerMembers);
			return utf8(JsonText.object(members));
		}
	}

	/**
	 * A signed token and its parts, from which the hostile {@link Variant}s derive.
	 */
	@Immutable
	public static final class Signed {
		private static final Set<Variant> ECDSA_ONLY_VARIANTS = Set.of(Variant.DER_SIGNATURE, Variant.R_ZERO,
				Variant.S_ZERO, Variant.R_EQUALS_ORDER, Variant.S_EQUALS_ORDER, Variant.R_ORDER_PLUS_ONE);

		private final Algorithm algorithm;
		private final String signingInput;
		private final byte[] signature;

		private Signed(Algorithm algorithm, String signingInput, byte[] signature) {
			this.algorithm = algorithm;
			this.signingInput = signingInput;
			this.signature = signature.clone();
		}

		/**
		 * The algorithm that signed it.
		 *
		 * @return the algorithm
		 */
		public Algorithm getAlgorithm() {
			return this.algorithm;
		}

		/**
		 * The signing input, {@code header.payload}.
		 *
		 * @return the signing input
		 */
		public String getSigningInput() {
			return this.signingInput;
		}

		/**
		 * The header segment.
		 *
		 * @return the segment
		 */
		public String getHeaderSegment() {
			return this.signingInput.substring(0, this.signingInput.indexOf('.'));
		}

		/**
		 * The payload segment.
		 *
		 * @return the segment
		 */
		public String getPayloadSegment() {
			return this.signingInput.substring(this.signingInput.indexOf('.') + 1);
		}

		/**
		 * The raw signature.
		 *
		 * @return a copy of the signature bytes
		 */
		public byte[] getSignature() {
			return this.signature.clone();
		}

		/**
		 * The signature segment.
		 *
		 * @return the segment
		 */
		public String getSignatureSegment() {
			return base64Url(this.signature);
		}

		/**
		 * The compact serialization, {@code header.payload.signature}.
		 *
		 * @return the token
		 */
		public String toCompactSerialization() {
			return this.signingInput + "." + getSignatureSegment();
		}

		/**
		 * The same header and payload with another signature.
		 *
		 * @param signature the raw signature bytes, possibly empty
		 * @return the compact serialization
		 */
		public String withSignature(byte[] signature) {
			return this.signingInput + "." + base64Url(requireNonNull(signature));
		}

		/**
		 * The same header and payload with another signature segment, verbatim.
		 *
		 * @param segment the signature segment text
		 * @return the compact serialization
		 */
		public String withSignatureSegment(String segment) {
			return this.signingInput + "." + requireNonNull(segment);
		}

		/**
		 * A hostile form of this token.
		 *
		 * @param variant the form
		 * @return the compact serialization
		 * @throws IllegalStateException if the variant does not apply to this algorithm or signature length
		 */
		public String withVariant(Variant variant) {
			requireNonNull(variant);
			if (ECDSA_ONLY_VARIANTS.contains(variant) && this.algorithm.family != Family.EC)
				throw new IllegalStateException(variant + " applies to ECDSA signatures, not " + this.algorithm);
			String header = getHeaderSegment();
			String payload = getPayloadSegment();
			String signatureSegment = getSignatureSegment();
			return switch (variant) {
				case DER_SIGNATURE -> withSignature(derEncodedEcdsaSignature(this.signature));
				case R_ZERO -> withEcdsa(BigInteger.ZERO, ecdsaS(this.signature));
				case S_ZERO -> withEcdsa(ecdsaR(this.signature), BigInteger.ZERO);
				case R_EQUALS_ORDER -> withEcdsa(curveOrder(this.algorithm), ecdsaS(this.signature));
				case S_EQUALS_ORDER -> withEcdsa(ecdsaR(this.signature), curveOrder(this.algorithm));
				case R_ORDER_PLUS_ONE ->
						withEcdsa(curveOrder(this.algorithm).add(BigInteger.ONE), ecdsaS(this.signature));
				case ZERO_SIGNATURE -> withSignature(new byte[this.signature.length]);
				case EMPTY_SIGNATURE -> withSignature(new byte[0]);
				case ONE_OCTET_SHORT -> withSignature(Arrays.copyOf(this.signature, this.signature.length - 1));
				case ONE_OCTET_LONG -> withSignature(Arrays.copyOf(this.signature, this.signature.length + 1));
				case FLIPPED_BIT -> {
					byte[] flipped = this.signature.clone();
					flipped[flipped.length - 1] ^= 1;
					yield withSignature(flipped);
				}
				case EXTRA_SEGMENT -> compact(header, payload, signatureSegment, "e30");
				case FIVE_SEGMENTS -> compact(header, payload, signatureSegment, "e30", "e30");
				case PADDED_HEADER -> compact(padded(header), payload, signatureSegment);
				case PADDED_PAYLOAD -> compact(header, padded(payload), signatureSegment);
				case PADDED_SIGNATURE -> withSignatureSegment(padded(signatureSegment));
				case NON_CANONICAL_SIGNATURE -> withSignatureSegment(withNonCanonicalTrailingBits(signatureSegment));
				case PLUS_IN_SIGNATURE -> withSignatureSegment("+" + signatureSegment.substring(1));
				case SLASH_IN_SIGNATURE -> withSignatureSegment("/" + signatureSegment.substring(1));
			};
		}

		private String withEcdsa(BigInteger r, BigInteger s) {
			return withSignature(ecdsaSignature(r, s, this.signature.length / 2));
		}

		@Override
		public String toString() {
			return "TestJws.Signed[" + toCompactSerialization() + "]";
		}
	}
}
