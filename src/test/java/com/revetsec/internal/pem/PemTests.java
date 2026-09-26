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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Strict PEM for certificates and keys (RFC 7468; plan G10 and 8; exit criterion 6: PEM rejects trailing DER bytes,
 * SEC1 keys and encrypted keys, with fixed messages). Inputs are M0's {@code fixtures/keys/**} (read-only) and the
 * OpenSSL-made fixtures in {@code fixtures/pem/**}, whose README.txt records how each was generated; the rest are
 * built here from those.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class PemTests {
	private static final String SENTINEL = "RevetsecSentinel7f3a";

	/**
	 * M0's key fixtures (fixtures/keys/README.md): each has {@code <name>-key.pem} (PKCS#8) and
	 * {@code <name>-cert.pem}.
	 */
	private static final List<String> M0_KEYS = List.of("idp-signing-rsa-2048", "idp-signing-rsa-3072",
			"idp-signing-ec-p256", "idp-signing-ec-p384", "idp-signing-ec-p521", "negative-attacker-rsa-2048",
			"negative-rsa-1024", "negative-unconfigured-ec-p256", "sp-signing-rsa-2048", "sp-encryption-rsa-2048");

	/**
	 * The fixed message of every kind, spelled out separately from the production table.
	 */
	private static final Map<PemException.Kind, String> MESSAGES = Map.ofEntries(
			Map.entry(PemException.Kind.MALFORMED_ARMOR, "The PEM text is not exactly one well-formed block."),
			Map.entry(PemException.Kind.UNSUPPORTED_LABEL, "The PEM label is not supported by this operation."),
			Map.entry(PemException.Kind.SEC1_PRIVATE_KEY, "SEC1 EC PRIVATE KEY blocks are not supported; convert the "
					+ "key with openssl pkcs8 -topk8 -nocrypt, or load it from a PKCS#12 KeyStore."),
			Map.entry(PemException.Kind.ENCRYPTED_PRIVATE_KEY, "Encrypted private keys are not supported; decrypt "
					+ "the key with openssl pkcs8 -topk8 -nocrypt, or load it from a PKCS#12 KeyStore."),
			Map.entry(PemException.Kind.INVALID_BASE64, "The PEM body is not canonical Base64."),
			Map.entry(PemException.Kind.MALFORMED_DER,
					"The PEM body is not a well-formed DER structure of the expected type."),
			Map.entry(PemException.Kind.TRAILING_DATA, "The DER structure is followed by trailing bytes."),
			Map.entry(PemException.Kind.NON_CANONICAL, "The DER encoding does not round-trip."),
			Map.entry(PemException.Kind.UNSUPPORTED_ALGORITHM,
					"The key algorithm or its parameters are not supported."),
			Map.entry(PemException.Kind.INVALID_KEY, "The key could not be decoded."),
			Map.entry(PemException.Kind.INVALID_CERTIFICATE, "The certificate could not be decoded."));

	private static final String RSA_ALGORITHM = "300d06092a864886f70d0101010500"; // rsaEncryption, NULL
	private static final String RSA_OID = "06092a864886f70d010101";
	private static final String EC_OID = "06072a8648ce3d0201";
	private static final String ED25519_OID = "06032b6570";

	// Every M0 certificate parses, equals what the JDK parses from the same PEM, and round-trips.
	@TestFactory
	Stream<DynamicTest> parsesEveryM0Certificate() {
		return M0_KEYS.stream().map(name -> DynamicTest.dynamicTest(name, () -> {
			String pem = keysFixture(name + "-cert.pem");
			X509Certificate certificate = Pem.parseCertificate(pem);
			X509Certificate expected = (X509Certificate) CertificateFactory.getInstance("X.509")
					.generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
			Assertions.assertEquals(expected, certificate);
			Assertions.assertArrayEquals(der(pem), certificate.getEncoded());
			Assertions.assertEquals(certificate, Pem.parseCertificateDer(der(pem)));
		}));
	}

	// Every M0 PKCS#8 key parses to the key the JDK builds from the same DER, and it pairs with its certificate.
	// PEM parsing does no key policy: the negative RSA-1024 key parses too (the policy is the caller's).
	@TestFactory
	Stream<DynamicTest> parsesEveryM0Pkcs8PrivateKey() {
		return M0_KEYS.stream().map(name -> DynamicTest.dynamicTest(name, () -> {
			String pem = keysFixture(name + "-key.pem");
			PrivateKey key = Pem.parsePrivateKey(pem);
			String algorithm = name.contains("-ec-") ? "EC" : "RSA";
			Assertions.assertEquals(algorithm, key.getAlgorithm());
			if (algorithm.equals("EC"))
				Assertions.assertInstanceOf(ECPrivateKey.class, key);
			else
				Assertions.assertInstanceOf(RSAPrivateCrtKey.class, key);
			PrivateKey expected = KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der(pem)));
			Assertions.assertEquals(expected, key);
			assertPairs(key, Pem.parseCertificate(keysFixture(name + "-cert.pem")).getPublicKey());
		}));
	}

	// Plan G10: PKCS#1 RSA PRIVATE KEY is wrapped to PKCS#8 and gives the same key as the PKCS#8 form.
	@Test
	void parsesAPkcs1RsaPrivateKeyAsTheSameKeyAsItsPkcs8Form() throws Exception {
		PrivateKey pkcs1 = Pem.parsePrivateKey(pemFixture("rsa-2048-pkcs1-key.pem"));
		PrivateKey pkcs8 = Pem.parsePrivateKey(keysFixture("idp-signing-rsa-2048-key.pem"));
		Assertions.assertInstanceOf(RSAPrivateCrtKey.class, pkcs1);
		Assertions.assertEquals(pkcs8, pkcs1);
		Assertions.assertArrayEquals(pkcs8.getEncoded(), pkcs1.getEncoded());
		assertPairs(pkcs1, Pem.parseCertificate(keysFixture("idp-signing-rsa-2048-cert.pem")).getPublicKey());
	}

	@Test
	void parsesPublicKeysThatEqualTheirCertificatesKeys() throws Exception {
		PublicKey rsa = Pem.parsePublicKey(pemFixture("rsa-2048-public.pem"));
		Assertions.assertInstanceOf(RSAPublicKey.class, rsa);
		Assertions.assertEquals(Pem.parseCertificate(keysFixture("idp-signing-rsa-2048-cert.pem")).getPublicKey(), rsa);
		PublicKey ec = Pem.parsePublicKey(pemFixture("ec-p256-public.pem"));
		Assertions.assertInstanceOf(ECPublicKey.class, ec);
		Assertions.assertEquals(Pem.parseCertificate(keysFixture("idp-signing-ec-p256-cert.pem")).getPublicKey(), ec);
	}

	// RFC 8410: Ed25519 keys in PKCS#8 and SubjectPublicKeyInfo, with absent parameters.
	@Test
	void parsesAnEd25519KeyPair() throws Exception {
		PrivateKey privateKey = Pem.parsePrivateKey(pemFixture("ed25519-key.pem"));
		PublicKey publicKey = Pem.parsePublicKey(pemFixture("ed25519-public.pem"));
		Assertions.assertInstanceOf(EdECPrivateKey.class, privateKey);
		Assertions.assertInstanceOf(EdECPublicKey.class, publicKey);
		assertPairs(privateKey, publicKey);
	}

	// RFC 8410: Ed448 keys take the same path as Ed25519. The pair is generated by the JDK here, because no M0 or
	// fixture key uses the curve.
	@Test
	void parsesAnEd448KeyPairGeneratedByTheJdk() throws Exception {
		KeyPair keyPair = KeyPairGenerator.getInstance("Ed448").generateKeyPair();
		PrivateKey privateKey = Pem.parsePrivateKey(pem("PRIVATE KEY", keyPair.getPrivate().getEncoded()));
		PublicKey publicKey = Pem.parsePublicKey(pem("PUBLIC KEY", keyPair.getPublic().getEncoded()));
		Assertions.assertEquals(keyPair.getPublic(), publicKey);
		byte[] data = "Revetsec PEM pairing check".getBytes(StandardCharsets.US_ASCII);
		Signature signer = Signature.getInstance("Ed448");
		signer.initSign(privateKey);
		signer.update(data);
		Signature verifier = Signature.getInstance("Ed448");
		verifier.initVerify(publicKey);
		verifier.update(data);
		Assertions.assertTrue(verifier.verify(signer.sign()));
	}

	// RFC 5958 section 2: OneAsymmetricKey may carry [0] attributes and, in version 1 (v2), a [1] public key.
	@Test
	void acceptsOptionalAttributesAndAVersionTwoPublicKey() throws Exception {
		byte[] pkcs8 = der(pemFixture("ed25519-key.pem"));
		byte[] publicKeyInfo = der(pemFixture("ed25519-public.pem"));
		byte[] publicKey = tlv(0x81, Arrays.copyOfRange(publicKeyInfo, publicKeyInfo.length - 33,
				publicKeyInfo.length));
		byte[] fields = Arrays.copyOfRange(pkcs8, 2, pkcs8.length);
		byte[] versionTwo = fields.clone();
		versionTwo[2] = 1;
		EdECPrivateKey expected = (EdECPrivateKey) Pem.parsePrivateKey(pemFixture("ed25519-key.pem"));
		for (byte[] variant : List.of(tlv(0x30, fields, hex("a000")), tlv(0x30, versionTwo, publicKey),
				tlv(0x30, versionTwo, hex("a000"), publicKey))) {
			EdECPrivateKey key = (EdECPrivateKey) Pem.parsePrivateKey(pem("PRIVATE KEY", variant));
			Assertions.assertArrayEquals(expected.getBytes().orElseThrow(), key.getBytes().orElseThrow());
		}
	}

	// Plan 8: SEC1 is not read; the message points to PKCS#8 conversion.
	@Test
	void rejectsASec1EcPrivateKey() {
		String pem = pemFixture("ec-p256-sec1-key.pem");
		Assertions.assertTrue(pem.startsWith("-----BEGIN EC PRIVATE KEY-----"));
		assertRejected(PemException.Kind.SEC1_PRIVATE_KEY, pem, () -> Pem.parsePrivateKey(pem));
	}

	// Plan G10: encrypted PEM is rejected in both forms: PKCS#8 ENCRYPTED PRIVATE KEY and OpenSSL's legacy
	// Proc-Type: 4,ENCRYPTED header (RFC 1421), whichever private-key label carries it.
	@TestFactory
	Stream<DynamicTest> rejectsEncryptedPrivateKeys() {
		String legacyPkcs8 = """
				-----BEGIN PRIVATE KEY-----
				Proc-Type: 4,ENCRYPTED
				DEK-Info: AES-256-CBC,00

				MC4CAQAwBQYDK2VwBCIEIOG9q9ObT7F3ttdUMszR7OMyVY83QsWFZY4j9KOAcURS
				-----END PRIVATE KEY-----
				""";
		return Stream.of(pemFixture("rsa-2048-encrypted-pkcs8-key.pem"), pemFixture("rsa-2048-encrypted-pkcs1-key.pem"),
				legacyPkcs8).map(pem -> DynamicTest.dynamicTest(pem.substring(0, pem.indexOf('\n')), () ->
				assertRejected(PemException.Kind.ENCRYPTED_PRIVATE_KEY, pem, () -> Pem.parsePrivateKey(pem))));
	}

	// Encapsulated headers other than Proc-Type are malformed armor for private keys too.
	@Test
	void rejectsAPrivateKeyWithACommentHeader() {
		String pem = """
				-----BEGIN PRIVATE KEY-----
				Comment: %s

				MC4CAQAwBQYDK2VwBCIEIOG9q9ObT7F3ttdUMszR7OMyVY83QsWFZY4j9KOAcURS
				-----END PRIVATE KEY-----
				""".formatted(SENTINEL);
		assertRejected(PemException.Kind.MALFORMED_ARMOR, pem, () -> Pem.parsePrivateKey(pem));
	}

	// Plan 8: "the JDK ignores trailing DER bytes (observed)". The certificate factory accepts both fixtures, a
	// trailing zero byte and a second whole certificate after the first; Revetsec rejects both.
	@TestFactory
	Stream<DynamicTest> rejectsTrailingBytesAfterACertificateThatTheJdkIgnores() {
		return Stream.of("rsa-2048-cert-trailing-byte.pem", "rsa-2048-cert-appended-certificate.pem").map(name ->
				DynamicTest.dynamicTest(name, () -> {
					String pem = pemFixture(name);
					byte[] der = der(pem);
					X509Certificate lenient = (X509Certificate) CertificateFactory.getInstance("X.509")
							.generateCertificate(new ByteArrayInputStream(der));
					Assertions.assertTrue(lenient.getEncoded().length < der.length, "the JDK ignored the extra bytes");
					assertRejected(PemException.Kind.TRAILING_DATA, pem, () -> Pem.parseCertificate(pem));
					assertRejected(PemException.Kind.TRAILING_DATA, pem, () -> Pem.parseCertificateDer(der));
				}));
	}

	// JDK 17's key factories accept trailing bytes after SubjectPublicKeyInfo and PKCS#8 (21 and later reject them),
	// so the check cannot be left to the JDK.
	@TestFactory
	Stream<DynamicTest> rejectsTrailingBytesAfterEveryKeyForm() {
		return Stream.of(
				new Object[]{"PUBLIC KEY", der(pemFixture("rsa-2048-public.pem"))},
				new Object[]{"PRIVATE KEY", der(keysFixture("idp-signing-ec-p256-key.pem"))},
				new Object[]{"RSA PRIVATE KEY", der(pemFixture("rsa-2048-pkcs1-key.pem"))}
		).map(vector -> DynamicTest.dynamicTest((String) vector[0], () -> {
			String label = (String) vector[0];
			String pem = pem(label, concat((byte[]) vector[1], new byte[]{0}));
			assertRejected(PemException.Kind.TRAILING_DATA, pem, () -> parse(label, pem));
		}));
	}

	// RFC 5958 section 2 with RFC 8017 appendix A.1.2, RFC 5915 section 3 and RFC 8410 section 7: the privateKey
	// OCTET STRING holds exactly one RSAPrivateKey, ECPrivateKey or CurvePrivateKey. The JDK ignores bytes after an
	// EdDSA key on every JDK and after an EC key before 27, so without Revetsec's check the result would depend on
	// the JDK; Revetsec rejects them on every JDK.
	@TestFactory
	Stream<DynamicTest> rejectsTrailingBytesAfterTheKeyInsidePkcs8() {
		List<byte[]> extras = List.of(hex("00"), hex("0500"), hex("3000"),
				SENTINEL.getBytes(StandardCharsets.US_ASCII));
		return Stream.of(
				new Object[]{"RSA", der(keysFixture("idp-signing-rsa-2048-key.pem"))},
				new Object[]{"EC", der(keysFixture("idp-signing-ec-p256-key.pem"))},
				new Object[]{"Ed25519", der(pemFixture("ed25519-key.pem"))}
		).flatMap(vector -> extras.stream().map(extra -> DynamicTest.dynamicTest(
				vector[0] + " followed by " + HexFormat.of().formatHex(extra), () -> {
					byte[] pkcs8 = (byte[]) vector[1];
					// Control: the key rebuilt without the extra bytes still parses.
					Assertions.assertEquals(Pem.parsePrivateKey(pem("PRIVATE KEY", pkcs8)),
							Pem.parsePrivateKey(pem("PRIVATE KEY", withPrivateKeyOctets(pkcs8, new byte[0]))));
					String pem = pem("PRIVATE KEY", withPrivateKeyOctets(pkcs8, extra));
					assertRejected(PemException.Kind.TRAILING_DATA, pem, () -> Pem.parsePrivateKey(pem));
				})));
	}

	// RFC 3279, RFC 5480 and RFC 8410 parameter rules, and algorithms outside RSA, EC and EdDSA.
	@TestFactory
	Stream<DynamicTest> rejectsUnsupportedAlgorithmsAndParameters() {
		byte[] rsaSpki = der(pemFixture("rsa-2048-public.pem"));
		byte[] rsaBitString = Arrays.copyOfRange(rsaSpki, 19, rsaSpki.length);
		byte[] edSpki = der(pemFixture("ed25519-public.pem"));
		byte[] edBitString = Arrays.copyOfRange(edSpki, 9, edSpki.length);
		byte[] rsaPkcs8 = der(keysFixture("idp-signing-rsa-2048-key.pem"));
		byte[] rsaOctetString = Arrays.copyOfRange(rsaPkcs8, 22, rsaPkcs8.length);
		byte[] edPkcs8 = der(pemFixture("ed25519-key.pem"));
		byte[] edOctetString = Arrays.copyOfRange(edPkcs8, 12, edPkcs8.length);
		return Stream.of(
				new Object[]{"X25519 private key", "PRIVATE KEY", pemFixture("x25519-key.pem")},
				new Object[]{"EC private key, explicit curve", "PRIVATE KEY",
						pemFixture("ec-p256-explicit-parameters-key.pem")},
				new Object[]{"EC public key, explicit curve", "PUBLIC KEY",
						pemFixture("ec-p256-explicit-parameters-public.pem")},
				new Object[]{"EC public key, no curve", "PUBLIC KEY",
						pem("PUBLIC KEY", tlv(0x30, tlv(0x30, hex(EC_OID)), rsaBitString))},
				new Object[]{"RSA public key, parameters absent", "PUBLIC KEY",
						pem("PUBLIC KEY", tlv(0x30, tlv(0x30, hex(RSA_OID)), rsaBitString))},
				new Object[]{"RSA public key, NULL with contents", "PUBLIC KEY",
						pem("PUBLIC KEY", tlv(0x30, tlv(0x30, hex(RSA_OID), hex("050100")), rsaBitString))},
				new Object[]{"RSA private key, parameters absent", "PRIVATE KEY",
						pem("PRIVATE KEY", tlv(0x30, hex("020100"), tlv(0x30, hex(RSA_OID)), rsaOctetString))},
				new Object[]{"RSA private key, OID parameters", "PRIVATE KEY",
						pem("PRIVATE KEY", tlv(0x30, hex("020100"), tlv(0x30, hex(RSA_OID), hex(RSA_OID)),
								rsaOctetString))},
				new Object[]{"Ed25519 public key, NULL parameters", "PUBLIC KEY",
						pem("PUBLIC KEY", tlv(0x30, tlv(0x30, hex(ED25519_OID), hex("0500")), edBitString))},
				new Object[]{"Ed25519 private key, NULL parameters", "PRIVATE KEY",
						pem("PRIVATE KEY", tlv(0x30, hex("020100"), tlv(0x30, hex(ED25519_OID), hex("0500")),
								edOctetString))},
				new Object[]{"DSA public key", "PUBLIC KEY",
						pem("PUBLIC KEY", tlv(0x30, tlv(0x30, hex("06072a8648ce380401")), rsaBitString))},
				new Object[]{"RSASSA-PSS public key", "PUBLIC KEY",
						pem("PUBLIC KEY", tlv(0x30, tlv(0x30, hex("06092a864886f70d01010a")), rsaBitString))}
		).map(vector -> DynamicTest.dynamicTest((String) vector[0], () -> {
			String label = (String) vector[1];
			String pem = (String) vector[2];
			assertRejected(PemException.Kind.UNSUPPORTED_ALGORITHM, pem, () -> parse(label, pem));
		}));
	}

	// Public material must round-trip. With the unused-bits octet set to 1, the JDK clears the final padding bit before
	// it parses the key (the exponent becomes 65536) and keeps the count of 1 when it re-encodes, so the last octet
	// comes back as 0x00 instead of 0x01: the input is not the encoding of the key the JDK yields.
	@Test
	void rejectsAPublicKeyThatDoesNotRoundTrip() throws Exception {
		byte[] spki = der(pemFixture("rsa-2048-public.pem"));
		spki[23] = 1;
		Assertions.assertNotNull(KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(spki)),
				"the JDK accepts it");
		String pem = pem("PUBLIC KEY", spki);
		assertRejected(PemException.Kind.NON_CANONICAL, pem, () -> Pem.parsePublicKey(pem));
	}

	// RFC 3279, RFC 5480 and RFC 8410 keys are whole octets, so a subjectPublicKey BIT STRING has no unused bits. With
	// the padding bits cleared, the JDK accepts a count of 1 to 7 for RSA and EC and keeps it, so without this check an
	// EC key whose last octet has those bits clear (half of all keys) would have a second encoding. Pem refuses the
	// count itself, for EdDSA too, before any JDK sees the key.
	@TestFactory
	Stream<DynamicTest> rejectsAPublicKeyBitStringWithUnusedBits() {
		List<DynamicTest> tests = new ArrayList<>();
		for (Object[] fixture : List.of(new Object[]{"rsa-2048-public.pem", 23}, new Object[]{"ec-p256-public.pem", 25},
				new Object[]{"ed25519-public.pem", 11}))
			for (int unused = 1; unused <= 7; ++unused) {
				int unusedBits = unused;
				tests.add(DynamicTest.dynamicTest(fixture[0] + " with " + unused + " unused bits", () -> {
					byte[] spki = der(pemFixture((String) fixture[0]));
					int countOffset = (Integer) fixture[1];
					Assertions.assertEquals(0, spki[countOffset], "the unused-bits octet");
					spki[countOffset] = (byte) unusedBits;
					spki[spki.length - 1] &= (byte) (0xFF << unusedBits);
					String pem = pem("PUBLIC KEY", spki);
					assertRejected(PemException.Kind.NON_CANONICAL, pem, () -> Pem.parsePublicKey(pem));
				}));
			}
		return tests.stream();
	}

	// RFC 3279 section 2.3.1 and X.690 section 10.1: an RSA key is the one DER encoding of its modulus and exponent.
	// The JDK accepts each variant here as the same key and returns the input unchanged from getEncoded(), so only a
	// key rebuilt from the modulus and exponent shows it is not the DER encoding.
	@TestFactory
	Stream<DynamicTest> rejectsRsaPublicKeysThatAreNotTheDerEncodingOfTheirValues() {
		byte[] spki = der(pemFixture("rsa-2048-public.pem"));
		List<byte[]> integers = children(Arrays.copyOfRange(spki, 24, spki.length));
		byte[] modulus = content(integers.get(0));
		byte[] exponent = content(integers.get(1));
		Assertions.assertEquals(0, modulus[0], "a 2048-bit modulus carries a sign octet");
		byte[] canonical = concat(tlv(0x02, modulus), tlv(0x02, exponent));
		Assertions.assertArrayEquals(spki, rsaSpki(tlv(0x30, canonical)), "the fixture is rebuilt exactly");
		byte[] modulusLength = {0x00, (byte) (modulus.length >> 8), (byte) modulus.length};
		byte[] sequenceLength = {0x00, (byte) (canonical.length >> 8), (byte) canonical.length};

		return Stream.of(
				new Object[]{"exponent with leading zero octets",
						tlv(0x30, tlv(0x02, modulus), tlv(0x02, hex("0000"), exponent))},
				new Object[]{"modulus with an extra leading zero", tlv(0x30, tlv(0x02, hex("00"), modulus), tlv(0x02, exponent))},
				new Object[]{"modulus without its sign octet",
						tlv(0x30, tlv(0x02, Arrays.copyOfRange(modulus, 1, modulus.length)), tlv(0x02, exponent))},
				new Object[]{"RSAPublicKey with a non-minimal length", concat(hex("3083"), sequenceLength, canonical)},
				new Object[]{"RSAPublicKey with an indefinite length", concat(hex("3080"), canonical, hex("0000"))},
				new Object[]{"modulus with a non-minimal length",
						tlv(0x30, concat(hex("0283"), modulusLength, modulus), tlv(0x02, exponent))},
				new Object[]{"exponent with a non-minimal length",
						tlv(0x30, tlv(0x02, modulus), concat(hex("0281"), new byte[]{(byte) exponent.length}, exponent))}
		).map(vector -> DynamicTest.dynamicTest((String) vector[0], () -> {
			String pem = pem("PUBLIC KEY", rsaSpki((byte[]) vector[1]));
			assertRejected(PemException.Kind.NON_CANONICAL, pem, () -> Pem.parsePublicKey(pem));
		}));
	}

	// RFC 8032 sections 5.1.3 and 5.2.3: decoding an EdDSA public key fails when its y-coordinate (the octets read
	// little-endian with the sign of x cleared) is not below the field prime. The JDK accepts such a key and refuses it
	// only when it is first used, so Pem refuses it, while p - 1 still parses.
	@TestFactory
	Stream<DynamicTest> rejectsEdDsaPublicKeysWhoseYIsNotBelowTheFieldPrime() throws Exception {
		BigInteger p25519 = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));
		BigInteger p448 = BigInteger.TWO.pow(448).subtract(BigInteger.TWO.pow(224)).subtract(BigInteger.ONE);
		byte[] ed25519 = der(pemFixture("ed25519-public.pem"));
		byte[] ed448 = KeyPairGenerator.getInstance("Ed448").generateKeyPair().getPublic().getEncoded();
		List<DynamicTest> tests = new ArrayList<>();

		for (Object[] curve : List.of(new Object[]{"Ed25519", ed25519, p25519, 32},
				new Object[]{"Ed448", ed448, p448, 57})) {
			byte[] spki = (byte[]) curve[1];
			BigInteger prime = (BigInteger) curve[2];
			int length = (Integer) curve[3];
			byte[] allOnes = new byte[length];
			Arrays.fill(allOnes, (byte) 0xFF);
			allOnes[length - 1] = 0x7F;

			for (Object[] y : List.of(new Object[]{"y = p", littleEndian(prime, length), false},
					new Object[]{"y = p with the sign of x set", withSignBit(littleEndian(prime, length)), false},
					new Object[]{"y = the largest value below the sign bit", allOnes, false},
					new Object[]{"y = p - 1", littleEndian(prime.subtract(BigInteger.ONE), length), true}))
				tests.add(DynamicTest.dynamicTest(curve[0] + ", " + y[0], () -> {
					byte[] variant = spki.clone();
					System.arraycopy((byte[]) y[1], 0, variant, variant.length - length, length);
					String pem = pem("PUBLIC KEY", variant);
					if ((Boolean) y[2])
						Assertions.assertInstanceOf(EdECPublicKey.class, Pem.parsePublicKey(pem));
					else
						assertRejected(PemException.Kind.INVALID_KEY, pem, () -> Pem.parsePublicKey(pem));
				}));
		}
		return tests.stream();
	}

	// X.690 section 10.1: definite, minimal lengths only; one outer SEQUENCE; no BER.
	@TestFactory
	Stream<DynamicTest> rejectsDerThatIsNotStrict() {
		byte[] certificate = der(keysFixture("idp-signing-rsa-2048-cert.pem"));
		byte[] content = Arrays.copyOfRange(certificate, 4, certificate.length);
		byte[] length = Arrays.copyOfRange(certificate, 2, 4);
		return Stream.of(
				new Object[]{"empty body", new byte[0]},
				new Object[]{"one octet", hex("30")},
				new Object[]{"indefinite length", concat(hex("3080"), content, hex("0000"))},
				new Object[]{"long form for a short length", hex("30810502010002")},
				new Object[]{"long form with a leading zero", concat(hex("308300"), length, content)},
				new Object[]{"five length octets", concat(hex("30850000"), length, content)},
				new Object[]{"length octets cut off", hex("308201")},
				new Object[]{"length past the end", hex("3005020100")},
				new Object[]{"long length past the end", hex("3082ffff020100")},
				new Object[]{"high tag number form", hex("3f00")},
				new Object[]{"not a SEQUENCE", hex("0400")},
				new Object[]{"a bare INTEGER", hex("020100")}
		).map(vector -> DynamicTest.dynamicTest((String) vector[0], () -> {
			String pem = pem("CERTIFICATE", (byte[]) vector[1]);
			assertRejected(PemException.Kind.MALFORMED_DER, pem, () -> Pem.parseCertificate(pem));
		}));
	}

	// The key structures are checked field by field before the JDK sees them.
	@TestFactory
	Stream<DynamicTest> rejectsKeyStructuresOfTheWrongShape() {
		byte[] rsaSpki = der(pemFixture("rsa-2048-public.pem"));
		byte[] rsaBitString = Arrays.copyOfRange(rsaSpki, 19, rsaSpki.length);
		byte[] rsaPkcs8 = der(keysFixture("idp-signing-rsa-2048-key.pem"));
		byte[] rsaOctetString = Arrays.copyOfRange(rsaPkcs8, 22, rsaPkcs8.length);
		byte[] versionTwo = rsaPkcs8.clone();
		versionTwo[6] = 2;
		return Stream.of(
				new Object[]{"PKCS#8 version 2", "PRIVATE KEY", versionTwo},
				new Object[]{"PKCS#8 two-octet version", "PRIVATE KEY",
						tlv(0x30, hex("02020000"), hex(RSA_ALGORITHM), rsaOctetString)},
				new Object[]{"PKCS#8 without its key", "PRIVATE KEY", tlv(0x30, hex("020100"), hex(RSA_ALGORITHM))},
				new Object[]{"PKCS#8 key as BIT STRING", "PRIVATE KEY",
						tlv(0x30, hex("020100"), hex(RSA_ALGORITHM), rsaBitString)},
				new Object[]{"PKCS#8 extra field", "PRIVATE KEY",
						tlv(0x30, hex("020100"), hex(RSA_ALGORITHM), rsaOctetString, hex("020100"))},
				new Object[]{"PKCS#8 [1] before [0]", "PRIVATE KEY",
						tlv(0x30, hex("020101"), hex(RSA_ALGORITHM), rsaOctetString, hex("8100"), hex("a000"))},
				new Object[]{"PKCS#8 algorithm not a SEQUENCE", "PRIVATE KEY",
						tlv(0x30, hex("020100"), hex(RSA_OID), rsaOctetString)},
				new Object[]{"AlgorithmIdentifier without an OID", "PUBLIC KEY",
						tlv(0x30, tlv(0x30, hex("0500")), rsaBitString)},
				new Object[]{"AlgorithmIdentifier with two parameters", "PUBLIC KEY",
						tlv(0x30, tlv(0x30, hex(RSA_OID), hex("0500"), hex("0500")), rsaBitString)},
				new Object[]{"SubjectPublicKeyInfo extra field", "PUBLIC KEY",
						tlv(0x30, hex(RSA_ALGORITHM), rsaBitString, hex("0500"))},
				new Object[]{"SubjectPublicKeyInfo key as OCTET STRING", "PUBLIC KEY",
						tlv(0x30, hex(RSA_ALGORITHM), rsaOctetString)},
				new Object[]{"PKCS#1 not starting with an INTEGER", "RSA PRIVATE KEY", tlv(0x30, hex("0500"))},
				new Object[]{"PKCS#1 empty SEQUENCE", "RSA PRIVATE KEY", hex("3000")},
				new Object[]{"PKCS#8 empty privateKey", "PRIVATE KEY",
						tlv(0x30, hex("020100"), hex(RSA_ALGORITHM), hex("0400"))},
				new Object[]{"PKCS#8 RSA key not a SEQUENCE", "PRIVATE KEY",
						tlv(0x30, hex("020100"), hex(RSA_ALGORITHM), tlv(0x04, rsaOctetString))},
				new Object[]{"PKCS#8 Ed25519 key not an OCTET STRING", "PRIVATE KEY",
						tlv(0x30, hex("020100"), tlv(0x30, hex(ED25519_OID)), tlv(0x04, tlv(0x30, hex("0400"))))}
		).map(vector -> DynamicTest.dynamicTest((String) vector[0], () -> {
			String label = (String) vector[1];
			String pem = pem(label, (byte[]) vector[2]);
			assertRejected(PemException.Kind.MALFORMED_DER, pem, () -> parse(label, pem));
		}));
	}

	// Well-formed structures whose contents the JDK refuses get one fixed message, never the JDK's.
	@TestFactory
	Stream<DynamicTest> reportsMaterialTheJdkRejectsWithAFixedMessage() {
		byte[] ecSpki = der(pemFixture("ec-p256-public.pem"));
		byte[] ecBitString = Arrays.copyOfRange(ecSpki, 23, ecSpki.length);
		byte[] sentinel = SENTINEL.getBytes(StandardCharsets.US_ASCII);
		return Stream.of(
				new Object[]{"empty certificate SEQUENCE", "CERTIFICATE", hex("3000"),
						PemException.Kind.INVALID_CERTIFICATE},
				new Object[]{"a public key as a certificate", "CERTIFICATE", der(pemFixture("rsa-2048-public.pem")),
						PemException.Kind.INVALID_CERTIFICATE},
				new Object[]{"certificate holding the sentinel", "CERTIFICATE", tlv(0x30, tlv(0x04, sentinel)),
						PemException.Kind.INVALID_CERTIFICATE},
				new Object[]{"RSA public key of garbage", "PUBLIC KEY", tlv(0x30, hex(RSA_ALGORITHM), hex("03020000")),
						PemException.Kind.INVALID_KEY},
				new Object[]{"EC public key on an unknown curve", "PUBLIC KEY",
						tlv(0x30, tlv(0x30, hex(EC_OID), hex("06032a0304")), ecBitString),
						PemException.Kind.INVALID_KEY},
				new Object[]{"RSA private key of garbage", "PRIVATE KEY",
						tlv(0x30, hex("020100"), hex(RSA_ALGORITHM), tlv(0x04, hex("3000"))),
						PemException.Kind.INVALID_KEY},
				new Object[]{"PKCS#1 with only a version", "RSA PRIVATE KEY", tlv(0x30, hex("020100")),
						PemException.Kind.INVALID_KEY},
				new Object[]{"PKCS#1 holding the sentinel", "RSA PRIVATE KEY",
						tlv(0x30, hex("020100"), tlv(0x04, sentinel)), PemException.Kind.INVALID_KEY}
		).map(vector -> DynamicTest.dynamicTest((String) vector[0], () -> {
			String label = (String) vector[1];
			String pem = pem(label, (byte[]) vector[2]);
			assertRejected((PemException.Kind) vector[3], pem, () -> parse(label, pem));
		}));
	}

	// RFC 7468 armor, strictly: exactly one block, matching labels, boundary lines of their own, no headers.
	@TestFactory
	Stream<DynamicTest> rejectsMalformedArmor() {
		String pem = keysFixture("idp-signing-ec-p256-cert.pem");
		String body = pem.substring(pem.indexOf('\n') + 1, pem.indexOf("-----END"));
		return Stream.of(
				new String[]{"empty", ""},
				new String[]{"whitespace only", " \t\r\n"},
				new String[]{"text before BEGIN", "Bag Attributes\n" + pem},
				new String[]{"text after END", pem + "subject=CN=x\n"},
				new String[]{"two blocks", pem + pem},
				new String[]{"mismatched END label", "-----BEGIN CERTIFICATE-----\n" + body
						+ "-----END X509 CRL-----\n"},
				new String[]{"missing END", "-----BEGIN CERTIFICATE-----\n" + body},
				new String[]{"BEGIN without closing dashes", "-----BEGIN CERTIFICATE\n" + body
						+ "-----END CERTIFICATE-----\n"},
				new String[]{"BEGIN without any dashes after it", "-----BEGIN CERTIFICATE\n" + body},
				new String[]{"a label outside printable ASCII", "-----BEGIN CERTIFICAT\u00C9-----\n" + body
						+ "-----END CERTIFICAT\u00C9-----\n"},
				new String[]{"truncated after the BEGIN line", "-----BEGIN CERTIFICATE-----\nMIIB"},
				new String[]{"BEGIN line with trailing space", "-----BEGIN CERTIFICATE----- \n" + body
						+ "-----END CERTIFICATE-----\n"},
				new String[]{"body on the BEGIN line", "-----BEGIN CERTIFICATE-----" + body
						+ "-----END CERTIFICATE-----\n"},
				new String[]{"END not on its own line", "-----BEGIN CERTIFICATE-----\n" + body.strip()
						+ "-----END CERTIFICATE-----\n"},
				new String[]{"lowercase boundary", pem.replace("BEGIN CERTIFICATE", "begin certificate")},
				new String[]{"four dashes", pem.replace("-----BEGIN", "----BEGIN")},
				new String[]{"a comment header", "-----BEGIN CERTIFICATE-----\nComment: x\n\n" + body
						+ "-----END CERTIFICATE-----\n"},
				new String[]{"Proc-Type on a certificate", "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\n"
						+ body + "-----END CERTIFICATE-----\n"},
				new String[]{"stray boundary inside", "-----BEGIN CERTIFICATE-----\n" + body + "-----\n" + body
						+ "-----END CERTIFICATE-----\n"}
		).map(vector -> DynamicTest.dynamicTest(vector[0], () ->
				assertRejected(PemException.Kind.MALFORMED_ARMOR, vector[1], () -> Pem.parseCertificate(vector[1]))));
	}

	// RFC 7468 section 3 allows LF or CRLF line ends and surrounding whitespace; any line length is read.
	@Test
	void acceptsCrLfSurroundingWhitespaceAndAnyLineLength() throws Exception {
		String pem = keysFixture("idp-signing-ec-p256-cert.pem");
		byte[] der = der(pem);
		String unwrapped = "-----BEGIN CERTIFICATE-----\n" + Base64.getEncoder().encodeToString(der)
				+ "\n-----END CERTIFICATE-----";
		String mime = "-----BEGIN CERTIFICATE-----\r\n" + Base64.getMimeEncoder().encodeToString(der)
				+ "\r\n-----END CERTIFICATE-----\r\n";
		for (String variant : List.of(pem, pem.replace("\n", "\r\n"), " \t\r\n\n" + pem + "\n\n \t", unwrapped, mime))
			Assertions.assertArrayEquals(der, Pem.parseCertificate(variant).getEncoded());
	}

	// Inside the body only CR and LF are removed; the rest must be canonical padded Base64.
	@TestFactory
	Stream<DynamicTest> rejectsBodiesThatAreNotCanonicalBase64() {
		// The first M0 certificate whose DER length is not a multiple of three, so its encoding ends in padding and has
		// trailing bits that must be zero. Which one it is depends on the signatures, which change whenever the keys
		// are regenerated.
		byte[] der = M0_KEYS.stream().map(name -> der(keysFixture(name + "-cert.pem")))
				.filter(candidate -> candidate.length % 3 != 0)
				.findFirst()
				.orElseThrow(() -> new AssertionError("no M0 certificate's encoding ends in padding"));
		String base64 = Base64.getEncoder().encodeToString(der);
		String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		// The last character before the padding holds the trailing bits: four under "==", two under "=".
		int lastData = base64.length() - (base64.endsWith("==") ? 3 : 2);
		char last = base64.charAt(lastData);
		String nonCanonical = base64.substring(0, lastData) + alphabet.charAt(alphabet.indexOf(last) ^ 0x01)
				+ base64.substring(lastData + 1);
		Assertions.assertArrayEquals(der, Base64.getDecoder().decode(nonCanonical), "the JDK decoder accepts it");
		return Stream.of(
				new String[]{"space inside a line", base64.substring(0, 10) + " " + base64.substring(10)},
				new String[]{"tab inside a line", base64.substring(0, 10) + "\t" + base64.substring(10)},
				new String[]{"padding removed", base64.substring(0, base64.length() - 1)},
				new String[]{"base64url alphabet", base64.replace('/', '_').replace('+', '-')},
				new String[]{"a character outside the alphabet", "." + base64},
				new String[]{"non-zero trailing bits", nonCanonical},
				new String[]{"the sentinel", SENTINEL + "!"}
		).map(vector -> DynamicTest.dynamicTest(vector[0], () -> {
			String input = "-----BEGIN CERTIFICATE-----\n" + vector[1] + "\n-----END CERTIFICATE-----\n";
			assertRejected(PemException.Kind.INVALID_BASE64, input, () -> Pem.parseCertificate(input));
		}));
	}

	// Each operation accepts only its own labels. SEC1 and encrypted labels are explained only where a private key
	// was expected.
	@TestFactory
	Stream<DynamicTest> rejectsLabelsTheOperationDoesNotAccept() {
		return Stream.of(
				new String[]{"PRIVATE KEY", "CERTIFICATE"},
				new String[]{"PRIVATE KEY", "PUBLIC KEY"},
				new String[]{"PRIVATE KEY", "OPENSSH PRIVATE KEY"},
				new String[]{"PRIVATE KEY", "DSA PRIVATE KEY"},
				new String[]{"PRIVATE KEY", "EC PARAMETERS"},
				new String[]{"PRIVATE KEY", ""},
				new String[]{"CERTIFICATE", "PRIVATE KEY"},
				new String[]{"CERTIFICATE", "EC PRIVATE KEY"},
				new String[]{"CERTIFICATE", "ENCRYPTED PRIVATE KEY"},
				new String[]{"CERTIFICATE", "X509 CERTIFICATE"},
				new String[]{"CERTIFICATE", "TRUSTED CERTIFICATE"},
				new String[]{"CERTIFICATE", "CERTIFICATE REQUEST"},
				new String[]{"CERTIFICATE", "X509 CRL"},
				new String[]{"CERTIFICATE", "certificate"},
				new String[]{"PUBLIC KEY", "RSA PUBLIC KEY"},
				new String[]{"PUBLIC KEY", "CERTIFICATE"},
				new String[]{"PUBLIC KEY", "ENCRYPTED PRIVATE KEY"},
				new String[]{"PUBLIC KEY", SENTINEL}
		).map(vector -> DynamicTest.dynamicTest(vector[0] + " given \"" + vector[1] + "\"", () -> {
			String pem = pem(vector[1], der(keysFixture("idp-signing-ec-p256-cert.pem")));
			assertRejected(PemException.Kind.UNSUPPORTED_LABEL, pem, () -> parse(vector[0], pem));
		}));
	}

	@TestFactory
	Stream<DynamicTest> everyKindHasItsFixedOneSentenceMessageAndNoCause() {
		Assertions.assertEquals(EnumSet.allOf(PemException.Kind.class), MESSAGES.keySet());
		return Stream.of(PemException.Kind.values()).map(kind -> DynamicTest.dynamicTest(kind.name(), () -> {
			PemException exception = new PemException(kind);
			Assertions.assertEquals(MESSAGES.get(kind), kind.getMessage());
			Assertions.assertEquals(MESSAGES.get(kind), exception.getMessage());
			Assertions.assertEquals(kind, exception.getKind());
			Assertions.assertTrue(kind.getMessage().endsWith(".") && kind.getMessage().indexOf(". ") < 0);
			Assertions.assertEquals(PemException.class.getName() + ": " + MESSAGES.get(kind), exception.toString());
			// Suppression is disabled, and a cause can never be attached later.
			exception.addSuppressed(new IllegalStateException(SENTINEL));
			Assertions.assertEquals(0, exception.getSuppressed().length);
			Assertions.assertThrows(IllegalStateException.class,
					() -> exception.initCause(new IllegalStateException(SENTINEL)));
			Assertions.assertNull(exception.getCause());
		}));
	}

	@Test
	@SuppressWarnings("NullAway")
	void rejectsNullArgumentsWithNullPointerException() {
		Assertions.assertThrows(NullPointerException.class, () -> Pem.parseCertificate(null));
		Assertions.assertThrows(NullPointerException.class, () -> Pem.parseCertificateDer(null));
		Assertions.assertThrows(NullPointerException.class, () -> Pem.parsePublicKey(null));
		Assertions.assertThrows(NullPointerException.class, () -> Pem.parsePrivateKey(null));
	}

	private static Object parse(String label, String pem) throws PemException {
		return switch (label) {
			case "CERTIFICATE" -> Pem.parseCertificate(pem);
			case "PUBLIC KEY" -> Pem.parsePublicKey(pem);
			default -> Pem.parsePrivateKey(pem);
		};
	}

	/**
	 * Requires {@code action} to throw a {@link PemException} of {@code kind} with the fixed message, no cause,
	 * nothing suppressed, and no trace of the sentinel or of any recognizable line of {@code input} in its message,
	 * {@code toString()} or stack trace (R9).
	 */
	private static void assertRejected(PemException.Kind kind, String input, Executable action) {
		PemException exception = Assertions.assertThrows(PemException.class, action, () -> "expected " + kind);
		Assertions.assertEquals(kind, exception.getKind());
		Assertions.assertEquals(MESSAGES.get(kind), exception.getMessage());
		Assertions.assertNull(exception.getCause());
		Assertions.assertEquals(0, exception.getSuppressed().length);
		StringWriter stackTrace = new StringWriter();
		exception.printStackTrace(new PrintWriter(stackTrace));
		List<String> lines = input.lines().map(String::strip).filter(line -> line.length() >= 16)
				.collect(Collectors.toList());
		for (String rendering : List.of(String.valueOf(exception.getMessage()), exception.toString(),
				stackTrace.toString())) {
			Assertions.assertFalse(rendering.contains(SENTINEL), "a failure rendering contains the sentinel");
			for (String line : lines)
				Assertions.assertFalse(rendering.contains(line), "a failure rendering echoes the input");
		}
	}

	private static void assertPairs(PrivateKey privateKey, PublicKey publicKey) throws GeneralSecurityException {
		String algorithm;
		if (privateKey.getAlgorithm().equals("RSA"))
			algorithm = "SHA256withRSA";
		else if (privateKey.getAlgorithm().equals("EC"))
			algorithm = "SHA256withECDSA";
		else
			algorithm = "Ed25519";
		byte[] data = "Revetsec PEM pairing check".getBytes(StandardCharsets.US_ASCII);
		Signature signer = Signature.getInstance(algorithm);
		signer.initSign(privateKey);
		signer.update(data);
		byte[] signature = signer.sign();
		Signature verifier = Signature.getInstance(algorithm);
		verifier.initVerify(publicKey);
		verifier.update(data);
		Assertions.assertTrue(verifier.verify(signature), "the private key pairs with the public key");
	}

	private static String keysFixture(String name) {
		return resource("/fixtures/keys/" + name);
	}

	private static String pemFixture(String name) {
		return resource("/fixtures/pem/" + name);
	}

	private static String resource(String path) {
		try (InputStream input = Objects.requireNonNull(PemTests.class.getResourceAsStream(path), path)) {
			return new String(input.readAllBytes(), StandardCharsets.US_ASCII);
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	/**
	 * The DER inside a PEM text, decoded here with the JDK's lenient MIME decoder so the expectations do not depend
	 * on the code under test.
	 */
	private static byte[] der(String pem) {
		return Base64.getMimeDecoder().decode(pem.lines().filter(line -> !line.startsWith("-----"))
				.collect(Collectors.joining()));
	}

	private static String pem(String label, byte[] der) {
		return "-----BEGIN " + label + "-----\n"
				+ Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der) + (der.length == 0 ? "" : "\n")
				+ "-----END " + label + "-----\n";
	}

	private static byte[] hex(String hex) {
		return HexFormat.of().parseHex(hex);
	}

	/**
	 * An RSA SubjectPublicKeyInfo around {@code rsaPublicKey}, with no unused bits.
	 */
	private static byte[] rsaSpki(byte[] rsaPublicKey) {
		return tlv(0x30, hex(RSA_ALGORITHM), tlv(0x03, hex("00"), rsaPublicKey));
	}

	/**
	 * The content octets of one DER element.
	 */
	private static byte[] content(byte[] element) {
		int[] header = header(element, 0);
		return Arrays.copyOfRange(element, header[0], header[0] + header[1]);
	}

	/**
	 * {@code value} as {@code length} little-endian octets (RFC 8032 section 5.1.2).
	 */
	private static byte[] littleEndian(BigInteger value, int length) {
		byte[] bigEndian = value.toByteArray();
		byte[] result = new byte[length];
		for (int index = 0; index < length && index < bigEndian.length; ++index)
			result[index] = bigEndian[bigEndian.length - 1 - index];
		return result;
	}

	private static byte[] withSignBit(byte[] littleEndian) {
		byte[] result = littleEndian.clone();
		result[result.length - 1] |= (byte) 0x80;
		return result;
	}

	private static byte[] concat(byte[]... parts) {
		int length = 0;
		for (byte[] part : parts)
			length += part.length;
		byte[] result = new byte[length];
		int position = 0;
		for (byte[] part : parts) {
			System.arraycopy(part, 0, result, position, part.length);
			position += part.length;
		}
		return result;
	}

	/**
	 * {@code pkcs8} rebuilt with {@code extra} appended inside its {@code privateKey} OCTET STRING, after the key.
	 */
	private static byte[] withPrivateKeyOctets(byte[] pkcs8, byte[] extra) {
		List<byte[]> fields = children(pkcs8);
		byte[] key = children(fields.get(2)).get(0);
		fields.set(2, tlv(0x04, key, extra));
		return tlv(0x30, fields.toArray(new byte[0][]));
	}

	/**
	 * The elements inside one DER element, read here rather than with {@link Der}; the list can be modified.
	 */
	private static List<byte[]> children(byte[] element) {
		List<byte[]> children = new ArrayList<>();
		int[] outer = header(element, 0);
		int position = outer[0];
		while (position < outer[0] + outer[1]) {
			int[] child = header(element, position);
			children.add(Arrays.copyOfRange(element, position, child[0] + child[1]));
			position = child[0] + child[1];
		}
		return children;
	}

	/**
	 * The content offset and length of the element at {@code offset}: {start, length}.
	 */
	private static int[] header(byte[] der, int offset) {
		int first = der[offset + 1] & 0xFF;
		if (first < 0x80)
			return new int[]{offset + 2, first};
		int length = 0;
		for (int index = 0; index < (first & 0x7F); ++index)
			length = (length << 8) | (der[offset + 2 + index] & 0xFF);
		return new int[]{offset + 2 + (first & 0x7F), length};
	}

	/**
	 * One DER element with a minimal definite length, written here rather than with {@link Der}.
	 */
	private static byte[] tlv(int tag, byte[]... contents) {
		byte[] content = concat(contents);
		int length = content.length;
		byte[] header;
		if (length < 0x80)
			header = new byte[]{(byte) tag, (byte) length};
		else if (length < 0x100)
			header = new byte[]{(byte) tag, (byte) 0x81, (byte) length};
		else
			header = new byte[]{(byte) tag, (byte) 0x82, (byte) (length >> 8), (byte) length};
		return concat(header, content);
	}
}
