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

package com.revetsec.internal.pem;

import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.StandardBase64;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Strict PEM (RFC 7468) for the key and certificate conveniences (plan G10 and 8): {@code CERTIFICATE},
 * {@code PUBLIC KEY}, unencrypted PKCS#8 {@code PRIVATE KEY} and PKCS#1 {@code RSA PRIVATE KEY}.
 * <p>
 * <strong>Armor.</strong> The text must be exactly one block, optionally surrounded by SP, HT, CR and LF: a
 * {@code -----BEGIN <label>-----} line ending in LF or CRLF, Base64 lines, and a matching
 * {@code -----END <label>-----} line. Text before or after the block, a second block, and encapsulated headers are
 * rejected ({@link PemException.Kind#MALFORMED_ARMOR}). Inside the body only CR and LF are removed; the rest must be
 * canonical padded Base64 ({@link PemException.Kind#INVALID_BASE64}).
 * <p>
 * <strong>Rejected on purpose.</strong> SEC1 {@code EC PRIVATE KEY} blocks ({@link PemException.Kind#SEC1_PRIVATE_KEY})
 * and encrypted keys, both {@code ENCRYPTED PRIVATE KEY} and OpenSSL's legacy {@code Proc-Type: 4,ENCRYPTED} form
 * ({@link PemException.Kind#ENCRYPTED_PRIVATE_KEY}): password-based decryption on JDK 17 is unreliable, and the
 * messages point to {@code openssl pkcs8 -topk8 -nocrypt} or a PKCS#12 KeyStore instead.
 * <p>
 * <strong>DER.</strong> Every body must be exactly one {@code SEQUENCE} whose header uses a minimal definite length
 * ({@link PemException.Kind#MALFORMED_DER}), with nothing after it ({@link PemException.Kind#TRAILING_DATA}): the
 * JDK's certificate factory ignores trailing bytes, and so do JDK 17's key factories.
 * <ul>
 *   <li>A public key must be the one DER encoding of the key it holds ({@link PemException.Kind#NON_CANONICAL}). The
 *   fields of its {@code SubjectPublicKeyInfo} are read with the strict DER reader first, and the
 *   {@code subjectPublicKey} BIT STRING must have no unused bits, because every supported key is whole octets
 *   (RFC 3279, RFC 5480, RFC 8410). The JDK's own {@code getEncoded()} is not enough: it re-encodes only the outer
 *   structure and keeps the BIT STRING's contents as they arrived. So an RSA or EC key is also rebuilt from its
 *   values (modulus and exponent, or point and named curve) and that key's encoding must equal the input, which
 *   rejects BER, non-minimal or unsigned {@code INTEGER}s and other aliases inside the key. An EdDSA key's
 *   y-coordinate must be below the field prime (RFC 8032 sections 5.1.3 and 5.2.3), which the JDK checks only when
 *   the key is first used ({@link PemException.Kind#INVALID_KEY}).</li>
 *   <li>A certificate's {@code getEncoded()} must equal the input too, but the JDK's X.509 implementation returns the
 *   octets it consumed rather than a re-encoding. So this comparison proves that the JDK read exactly the input and
 *   nothing else; it does not make the certificate's inner encoding canonical. The JDK accepts some BER inside a
 *   certificate (a non-minimal or indefinite length in the {@code TBSCertificate}, for example), so two different
 *   encodings of one certificate can both parse, and a caller that compares certificates by their octets must
 *   allow for that.</li>
 *   <li>Private keys are not round-tripped: when the JDK re-encodes a key it drops RFC 5958's optional attributes
 *   (and, on 17 and 21, the version 2 public key), so valid keys would fail. The {@code OneAsymmetricKey} fields are
 *   read with the strict DER reader instead, and its {@code privateKey} octets must hold exactly one element of the
 *   algorithm's type, with nothing after it ({@link PemException.Kind#TRAILING_DATA}): the JDK ignores such bytes for
 *   EdDSA, and for EC before JDK 27.</li>
 * </ul>
 * <p>
 * <strong>Algorithms.</strong> Keys are RSA ({@code rsaEncryption} with NULL parameters, RFC 3279), EC
 * ({@code id-ecPublicKey} with a named curve, RFC 5480; explicit curve parameters are rejected) or EdDSA (Ed25519 and
 * Ed448 with absent parameters, RFC 8410). Anything else is {@link PemException.Kind#UNSUPPORTED_ALGORITHM}. Key size
 * and curve policy belong to the caller. A PKCS#1 key is wrapped into a PKCS#8 {@code PrivateKeyInfo} with a fixed
 * {@code AlgorithmIdentifier} before the JDK reads it.
 * <p>
 * Every JDK failure becomes a fixed-message {@link PemException}; JCA runtime exceptions are caught too (INV-G1).
 * Decoded private-key octets are zeroed before returning.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class Pem {
	private static final @NonNull String CERTIFICATE = "CERTIFICATE";
	private static final @NonNull String PUBLIC_KEY = "PUBLIC KEY";
	private static final @NonNull String PRIVATE_KEY = "PRIVATE KEY";
	private static final @NonNull String RSA_PRIVATE_KEY = "RSA PRIVATE KEY";
	private static final @NonNull String EC_PRIVATE_KEY = "EC PRIVATE KEY";
	private static final @NonNull String ENCRYPTED_PRIVATE_KEY = "ENCRYPTED PRIVATE KEY";

	private static final @NonNull Set<@NonNull String> CERTIFICATE_LABELS = Set.of(CERTIFICATE);
	private static final @NonNull Set<@NonNull String> PUBLIC_KEY_LABELS = Set.of(PUBLIC_KEY);
	private static final @NonNull Set<@NonNull String> PRIVATE_KEY_LABELS = Set.of(PRIVATE_KEY, RSA_PRIVATE_KEY);

	private static final @NonNull String BEGIN = "-----BEGIN ";
	private static final @NonNull String END = "-----END ";
	private static final @NonNull String DASHES = "-----";

	/**
	 * The content octets of the algorithm object identifiers, in lowercase hexadecimal.
	 */
	private static final @NonNull String RSA_ENCRYPTION = "2a864886f70d010101"; // 1.2.840.113549.1.1.1
	private static final @NonNull String ID_EC_PUBLIC_KEY = "2a8648ce3d0201"; // 1.2.840.10045.2.1
	private static final @NonNull String ID_ED25519 = "2b6570"; // 1.3.101.112
	private static final @NonNull String ID_ED448 = "2b6571"; // 1.3.101.113

	/**
	 * The field primes of edwards25519 and edwards448 (RFC 8032 sections 5.1 and 5.2).
	 */
	private static final @NonNull BigInteger ED25519_FIELD_PRIME = BigInteger.TWO.pow(255)
			.subtract(BigInteger.valueOf(19));
	private static final @NonNull BigInteger ED448_FIELD_PRIME = BigInteger.TWO.pow(448)
			.subtract(BigInteger.TWO.pow(224))
			.subtract(BigInteger.ONE);

	private Pem() {
	}

	/**
	 * Parses one {@code CERTIFICATE} block.
	 *
	 * @param pem the PEM text
	 * @return the certificate, whose {@link X509Certificate#getEncoded()} equals the block's DER
	 * @throws PemException if the text is not exactly one certificate block whose DER the JDK reads completely, with
	 *                      nothing after it
	 */
	public static @NonNull X509Certificate parseCertificate(@NonNull String pem) throws PemException {
		return parseCertificateDer(readBlock(pem, CERTIFICATE_LABELS).getDer());
	}

	/**
	 * Parses a DER certificate with the same checks as {@link #parseCertificate(String)}, for certificates that arrive
	 * without PEM armor, such as a JWK {@code x5c} entry or a SAML metadata {@code X509Certificate} after Base64
	 * decoding.
	 *
	 * @param der the DER octets; not modified
	 * @return the certificate, whose {@link X509Certificate#getEncoded()} equals {@code der}
	 * @throws PemException if {@code der} is not exactly one certificate that the JDK reads completely, with nothing
	 *                      after it
	 */
	public static @NonNull X509Certificate parseCertificateDer(byte @NonNull [] der) throws PemException {
		requireNonNull(der);
		requireSingleSequence(der);
		X509Certificate certificate;
		byte[] encoded;
		try {
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
			encoded = certificate.getEncoded();
		} catch (CertificateException | RuntimeException e) {
			throw new PemException(PemException.Kind.INVALID_CERTIFICATE);
		}
		requireRoundTrip(der, encoded);
		return certificate;
	}

	/**
	 * Parses one {@code PUBLIC KEY} block, an X.509 {@code SubjectPublicKeyInfo} (RFC 5280 section 4.1).
	 *
	 * @param pem the PEM text
	 * @return the key: an {@code RSAPublicKey}, {@code ECPublicKey} or {@code EdECPublicKey}
	 * @throws PemException if the text is not exactly one public key block of a supported algorithm, in the one DER
	 *                      encoding of its key
	 */
	public static @NonNull PublicKey parsePublicKey(@NonNull String pem) throws PemException {
		byte[] der = readBlock(pem, PUBLIC_KEY_LABELS).getDer();

		// SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
		Der.Element outer = requireSingleSequence(der);
		Der.Element algorithm = Der.read(der, outer.getStart(), outer.getEnd(), Der.SEQUENCE);
		Der.Element subjectPublicKey = Der.read(der, algorithm.getEnd(), outer.getEnd(), Der.BIT_STRING);
		if (subjectPublicKey.getEnd() != outer.getEnd() || subjectPublicKey.getLength() == 0)
			throw new PemException(PemException.Kind.MALFORMED_DER);
		// Every supported key is whole octets, so the first content octet (the unused-bit count) is 0. The JDK keeps a
		// nonzero count and only clears the padding bits, so an EC or RSA key with zero padding would parse, and
		// round-trip, as a second encoding of the same key.
		if (der[subjectPublicKey.getStart()] != 0)
			throw new PemException(PemException.Kind.NON_CANONICAL);
		String keyFactoryAlgorithm = keyFactoryAlgorithm(der, algorithm);

		PublicKey publicKey;
		byte[] encoded;
		byte @Nullable [] rebuilt;
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(keyFactoryAlgorithm);
			publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(der));
			encoded = publicKey.getEncoded();
			rebuilt = rebuiltEncoding(keyFactory, publicKey);
		} catch (GeneralSecurityException | RuntimeException e) {
			throw new PemException(PemException.Kind.INVALID_KEY);
		}
		requireRoundTrip(der, encoded);
		if (rebuilt != null)
			requireRoundTrip(der, rebuilt);
		if (publicKey instanceof EdECPublicKey edwardsKey)
			requireEdwardsYBelowTheFieldPrime(der, subjectPublicKey, edwardsKey);
		return publicKey;
	}

	/**
	 * The encoding of a key the JDK builds from {@code publicKey}'s values alone, or {@code null} for EdDSA, whose
	 * encoding is its octets. The JDK's {@code getEncoded()} returns the {@code subjectPublicKey} octets as they arrived,
	 * so only a key rebuilt from its values shows whether the input was the one DER encoding of it: BER lengths,
	 * non-minimal, zero-padded or unsigned {@code INTEGER}s and an exponent with leading zeros all rebuild to other
	 * octets.
	 */
	private static byte @Nullable [] rebuiltEncoding(@NonNull KeyFactory keyFactory, @NonNull PublicKey publicKey)
			throws GeneralSecurityException {
		if (publicKey instanceof RSAPublicKey rsaKey)
			return keyFactory.generatePublic(new RSAPublicKeySpec(rsaKey.getModulus(), rsaKey.getPublicExponent()))
					.getEncoded();
		if (publicKey instanceof ECPublicKey ecKey)
			return keyFactory.generatePublic(new ECPublicKeySpec(ecKey.getW(), ecKey.getParams())).getEncoded();
		return null;
	}

	/**
	 * RFC 8032 sections 5.1.3 and 5.2.3: decoding an EdDSA point fails if its y-coordinate, the key octets read
	 * little-endian with the top bit (the sign of x) cleared, is not below the field prime. The JDK accepts such a key
	 * and fails only when it is first used, so it is refused here ({@link PemException.Kind#INVALID_KEY}).
	 */
	private static void requireEdwardsYBelowTheFieldPrime(byte @NonNull [] der, Der.@NonNull Element subjectPublicKey,
																												 @NonNull EdECPublicKey edwardsKey) throws PemException {
		String curve = edwardsKey.getParams().getName();
		BigInteger prime;
		int length;
		if (NamedParameterSpec.ED25519.getName().equals(curve)) {
			prime = ED25519_FIELD_PRIME;
			length = 32;
		} else if (NamedParameterSpec.ED448.getName().equals(curve)) {
			prime = ED448_FIELD_PRIME;
			length = 57;
		} else {
			throw new PemException(PemException.Kind.UNSUPPORTED_ALGORITHM);
		}

		// The key octets follow the BIT STRING's unused-bit count.
		int start = subjectPublicKey.getStart() + 1;
		if (subjectPublicKey.getEnd() - start != length)
			throw new PemException(PemException.Kind.INVALID_KEY);
		byte[] bigEndian = new byte[length];
		for (int index = 0; index < length; ++index)
			bigEndian[index] = der[subjectPublicKey.getEnd() - 1 - index];
		bigEndian[0] &= 0x7F;
		if (new BigInteger(1, bigEndian).compareTo(prime) >= 0)
			throw new PemException(PemException.Kind.INVALID_KEY);
	}

	/**
	 * Parses one unencrypted private key block: PKCS#8 {@code PRIVATE KEY} (RFC 5958) or PKCS#1
	 * {@code RSA PRIVATE KEY} (RFC 8017 appendix A.1.2).
	 *
	 * @param pem the PEM text
	 * @return the key: an {@code RSAPrivateCrtKey}, {@code ECPrivateKey} or {@code EdECPrivateKey}
	 * @throws PemException if the text is not exactly one well-formed, unencrypted private key block of a supported
	 *                      algorithm
	 */
	public static @NonNull PrivateKey parsePrivateKey(@NonNull String pem) throws PemException {
		Block block = readBlock(pem, PRIVATE_KEY_LABELS);
		byte[] der = block.getDer();
		byte[] pkcs8 = der;
		try {
			if (block.getLabel().equals(RSA_PRIVATE_KEY)) {
				// RSAPrivateKey ::= SEQUENCE { version INTEGER, modulus INTEGER, ... }; the JDK checks the fields.
				Der.Element outer = requireSingleSequence(der);
				Der.read(der, outer.getStart(), outer.getEnd(), Der.INTEGER);
				pkcs8 = wrapPkcs1(der);
			}
			String keyFactoryAlgorithm = checkPrivateKeyInfo(pkcs8);
			try {
				return KeyFactory.getInstance(keyFactoryAlgorithm).generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
			} catch (GeneralSecurityException | RuntimeException e) {
				throw new PemException(PemException.Kind.INVALID_KEY);
			}
		} finally {
			Arrays.fill(der, (byte) 0);
			Arrays.fill(pkcs8, (byte) 0);
		}
	}

	/**
	 * Checks a PKCS#8 structure and returns the {@link KeyFactory} algorithm for it.
	 * <pre>
	 * OneAsymmetricKey ::= SEQUENCE {
	 *   version                   INTEGER (0 or 1),
	 *   privateKeyAlgorithm       AlgorithmIdentifier,
	 *   privateKey                OCTET STRING,
	 *   attributes            [0] IMPLICIT Attributes OPTIONAL,
	 *   publicKey             [1] IMPLICIT BIT STRING OPTIONAL }
	 * </pre>
	 */
	private static @NonNull String checkPrivateKeyInfo(byte @NonNull [] der) throws PemException {
		Der.Element outer = requireSingleSequence(der);
		Der.Element version = Der.read(der, outer.getStart(), outer.getEnd(), Der.INTEGER);
		if (version.getLength() != 1 || (der[version.getStart()] != 0 && der[version.getStart()] != 1))
			throw new PemException(PemException.Kind.MALFORMED_DER);
		Der.Element algorithm = Der.read(der, version.getEnd(), outer.getEnd(), Der.SEQUENCE);
		Der.Element privateKey = Der.read(der, algorithm.getEnd(), outer.getEnd(), Der.OCTET_STRING);
		int position = privateKey.getEnd();
		if (position < outer.getEnd() && (der[position] & 0xFF) == Der.CONTEXT_0_CONSTRUCTED)
			position = Der.read(der, position, outer.getEnd()).getEnd();
		if (position < outer.getEnd() && (der[position] & 0xFF) == Der.CONTEXT_1_PRIMITIVE)
			position = Der.read(der, position, outer.getEnd()).getEnd();
		if (position != outer.getEnd())
			throw new PemException(PemException.Kind.MALFORMED_DER);
		String keyFactoryAlgorithm = keyFactoryAlgorithm(der, algorithm);

		// The privateKey octets hold exactly one element: RSAPrivateKey (RFC 8017 appendix A.1.2) and ECPrivateKey
		// (RFC 5915 section 3) are SEQUENCEs, and CurvePrivateKey (RFC 8410 section 7) is an OCTET STRING. The JDK
		// ignores bytes after it for EdDSA on every JDK and for EC before 27, so the check cannot be left to it.
		int innerTag = keyFactoryAlgorithm.equals("EdDSA") ? Der.OCTET_STRING : Der.SEQUENCE;
		Der.Element inner = Der.read(der, privateKey.getStart(), privateKey.getEnd(), innerTag);
		if (inner.getEnd() != privateKey.getEnd())
			throw new PemException(PemException.Kind.TRAILING_DATA);
		return keyFactoryAlgorithm;
	}

	/**
	 * The {@link KeyFactory} algorithm for an {@code AlgorithmIdentifier} (RFC 5280 section 4.1.1.2), enforcing each
	 * algorithm's parameter rule.
	 */
	private static @NonNull String keyFactoryAlgorithm(byte @NonNull [] der, Der.@NonNull Element algorithm)
			throws PemException {
		Der.Element oid = Der.read(der, algorithm.getStart(), algorithm.getEnd(), Der.OBJECT_IDENTIFIER);
		Der.@Nullable Element parameters = null;
		if (oid.getEnd() < algorithm.getEnd()) {
			parameters = Der.read(der, oid.getEnd(), algorithm.getEnd());
			if (parameters.getEnd() != algorithm.getEnd())
				throw new PemException(PemException.Kind.MALFORMED_DER);
		}

		String oidHex = HexFormat.of().formatHex(der, oid.getStart(), oid.getEnd());
		if (oidHex.equals(RSA_ENCRYPTION)) {
			// RFC 3279 section 2.3.1: the parameters are NULL.
			if (parameters == null || parameters.getTag() != Der.NULL || parameters.getLength() != 0)
				throw new PemException(PemException.Kind.UNSUPPORTED_ALGORITHM);
			return "RSA";
		}
		if (oidHex.equals(ID_EC_PUBLIC_KEY)) {
			// RFC 5480 section 2.1.1: a namedCurve; explicit (specifiedCurve) and implicit parameters are refused.
			if (parameters == null || parameters.getTag() != Der.OBJECT_IDENTIFIER)
				throw new PemException(PemException.Kind.UNSUPPORTED_ALGORITHM);
			return "EC";
		}
		if (oidHex.equals(ID_ED25519) || oidHex.equals(ID_ED448)) {
			// RFC 8410 section 3: the parameters are absent.
			if (parameters != null)
				throw new PemException(PemException.Kind.UNSUPPORTED_ALGORITHM);
			return "EdDSA";
		}
		throw new PemException(PemException.Kind.UNSUPPORTED_ALGORITHM);
	}

	/**
	 * Wraps a PKCS#1 {@code RSAPrivateKey} as a PKCS#8 {@code PrivateKeyInfo}:
	 * {@code SEQUENCE { INTEGER 0, SEQUENCE { rsaEncryption, NULL }, OCTET STRING { RSAPrivateKey } }}.
	 */
	private static byte @NonNull [] wrapPkcs1(byte @NonNull [] pkcs1) {
		int octetString = 1 + Der.lengthOfLength(pkcs1.length) + pkcs1.length;
		int content = 3 + 15 + octetString;
		byte[] out = new byte[1 + Der.lengthOfLength(content) + content];
		int position = 0;
		out[position++] = (byte) Der.SEQUENCE;
		position = Der.putLength(out, position, content);
		position = put(out, position, Der.INTEGER, 0x01, 0x00);
		position = put(out, position, Der.SEQUENCE, 0x0D, Der.OBJECT_IDENTIFIER, 0x09,
				0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, Der.NULL, 0x00);
		out[position++] = (byte) Der.OCTET_STRING;
		position = Der.putLength(out, position, pkcs1.length);
		System.arraycopy(pkcs1, 0, out, position, pkcs1.length);
		return out;
	}

	private static int put(byte @NonNull [] out, int position, int @NonNull ... octets) {
		int next = position;
		for (int octet : octets)
			out[next++] = (byte) octet;
		return next;
	}

	/**
	 * Requires {@code der} to be one DER {@code SEQUENCE} and nothing else.
	 */
	private static Der.@NonNull Element requireSingleSequence(byte @NonNull [] der) throws PemException {
		Der.Element outer = Der.read(der, 0, der.length, Der.SEQUENCE);
		if (outer.getEnd() != der.length)
			throw new PemException(PemException.Kind.TRAILING_DATA);
		return outer;
	}

	private static void requireRoundTrip(byte @NonNull [] der, byte @Nullable [] encoded) throws PemException {
		if (!Arrays.equals(der, encoded))
			throw new PemException(PemException.Kind.NON_CANONICAL);
	}

	/**
	 * Reads exactly one block whose label is in {@code labels} and returns its label and decoded body.
	 */
	private static @NonNull Block readBlock(@NonNull String pem, @NonNull Set<@NonNull String> labels)
			throws PemException {
		requireNonNull(pem);
		int start = 0;
		int end = pem.length();
		while (start < end && isOuterWhitespace(pem.charAt(start)))
			++start;
		while (end > start && isOuterWhitespace(pem.charAt(end - 1)))
			--end;
		String text = pem.substring(start, end);

		if (!text.startsWith(BEGIN))
			throw new PemException(PemException.Kind.MALFORMED_ARMOR);
		int labelEnd = text.indexOf(DASHES, BEGIN.length());
		if (labelEnd < 0)
			throw new PemException(PemException.Kind.MALFORMED_ARMOR);
		String label = text.substring(BEGIN.length(), labelEnd);
		// RFC 7468 section 3: a label is printable ASCII on the BEGIN line itself.
		for (int index = 0; index < label.length(); ++index)
			if (label.charAt(index) < 0x20 || label.charAt(index) > 0x7E)
				throw new PemException(PemException.Kind.MALFORMED_ARMOR);
		if (!labels.contains(label)) {
			if (labels.contains(PRIVATE_KEY) && label.equals(EC_PRIVATE_KEY))
				throw new PemException(PemException.Kind.SEC1_PRIVATE_KEY);
			if (labels.contains(PRIVATE_KEY) && label.equals(ENCRYPTED_PRIVATE_KEY))
				throw new PemException(PemException.Kind.ENCRYPTED_PRIVATE_KEY);
			throw new PemException(PemException.Kind.UNSUPPORTED_LABEL);
		}

		// The BEGIN line ends with LF or CRLF.
		int bodyStart = labelEnd + DASHES.length();
		if (text.startsWith("\r\n", bodyStart))
			bodyStart += 2;
		else if (text.startsWith("\n", bodyStart))
			bodyStart += 1;
		else
			throw new PemException(PemException.Kind.MALFORMED_ARMOR);

		// The END line matches the BEGIN label and starts its own line.
		String footer = END + label + DASHES;
		int bodyEnd = text.length() - footer.length();
		if (bodyEnd < bodyStart || !text.startsWith(footer, bodyEnd)
				|| (bodyEnd > bodyStart && text.charAt(bodyEnd - 1) != '\n'))
			throw new PemException(PemException.Kind.MALFORMED_ARMOR);

		String body = text.substring(bodyStart, bodyEnd);
		// Another boundary inside means a second block or a stray line.
		if (body.contains(DASHES))
			throw new PemException(PemException.Kind.MALFORMED_ARMOR);
		// RFC 1421 encapsulated headers; OpenSSL's legacy encrypted keys start with Proc-Type: 4,ENCRYPTED.
		if (body.indexOf(':') >= 0) {
			if (labels.contains(PRIVATE_KEY) && body.startsWith("Proc-Type:"))
				throw new PemException(PemException.Kind.ENCRYPTED_PRIVATE_KEY);
			throw new PemException(PemException.Kind.MALFORMED_ARMOR);
		}

		StringBuilder base64 = new StringBuilder(body.length());
		for (int index = 0; index < body.length(); ++index) {
			char character = body.charAt(index);
			if (character != '\r' && character != '\n')
				base64.append(character);
		}
		try {
			return new Block(label, StandardBase64.decode(base64.toString()));
		} catch (EncodingException e) {
			throw new PemException(PemException.Kind.INVALID_BASE64);
		}
	}

	private static boolean isOuterWhitespace(char character) {
		return character == ' ' || character == '\t' || character == '\r' || character == '\n';
	}

	/**
	 * A block's label and decoded body.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 */
	private static final class Block {
		private final @NonNull String label;
		private final byte @NonNull [] der;

		private Block(@NonNull String label, byte @NonNull [] der) {
			this.label = label;
			this.der = der;
		}

		@NonNull String getLabel() {
			return this.label;
		}

		byte @NonNull [] getDer() {
			return this.der;
		}
	}
}
