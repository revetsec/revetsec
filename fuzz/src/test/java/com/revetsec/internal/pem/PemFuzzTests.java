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

import com.code_intelligence.jazzer.junit.FuzzTest;
import org.junit.jupiter.api.Assertions;

import javax.annotation.concurrent.ThreadSafe;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Set;

/**
 * Coverage-guided checks for {@link Pem} (M1 plan, "Internal types" and exit criterion 6; INV-G1).
 * <p>
 * Seeds: the PEM test fixtures ({@code src/test/resources/fixtures/pem/} and {@code fixtures/keys/}, TEST ONLY
 * material, private keys included) are mapped into the text target's inputs directory by the fuzz pom, next to a
 * handful of hand-written armor variants. The DER target's inputs directory holds the DER bodies of ten of those same
 * fixtures, plus an empty input, an indefinite-length {@code SEQUENCE}, and PKCS#8 keys with a byte after the outer
 * {@code SEQUENCE} or inside the {@code privateKey} octets.
 * <p>
 * The DER framing that every path checks first, and the {@code privateKey} rule that the JDK does not enforce for
 * EdDSA (nor for EC before 27), are also checked with a DER reader written here from X.690. So a parser that stopped
 * enforcing either one fails the seed replay, even where the JDK or a later check would still reject the input with
 * another {@link PemException.Kind}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public class PemFuzzTests {
	private static final Set<String> KEY_ALGORITHMS = Set.of("RSA", "EC", "EdDSA", "Ed25519", "Ed448");
	private static final int SEQUENCE = 0x30;
	private static final int OCTET_STRING = 0x04;

	/**
	 * Every parser takes any text and either returns a value or throws {@link PemException} with its Kind's fixed
	 * message, no cause and nothing suppressed; no JDK exception escapes (INV-G1). The label sets are disjoint, so at
	 * most one of the three parsers accepts a text, and the other two reject it with
	 * {@link PemException.Kind#UNSUPPORTED_LABEL}. What is accepted is exactly one block of a supported algorithm, and
	 * it parses again, to an equal value with the same encoding, when re-armored from the JDK's own encoding. Its body
	 * is exactly one DER {@code SEQUENCE} with a minimal definite length and nothing after it, and a PKCS#8 body's
	 * {@code privateKey} octets hold exactly one element (exit 6: trailing DER bytes are rejected).
	 *
	 * @param input the fuzzed PEM text, read as ISO-8859-1 so every byte is one character
	 */
	@FuzzTest(maxDuration = "5m")
	public void pemParsersRejectOnlyWithPemExceptionAndAcceptAtMostOneLabel(byte[] input) {
		String pem = new String(input, StandardCharsets.ISO_8859_1);
		boolean certificate = certificate(pem) != null;
		boolean publicKey = publicKey(pem) != null;
		PrivateKey privateKey = privateKey(pem);
		int accepted = (certificate ? 1 : 0) + (publicKey ? 1 : 0) + (privateKey != null ? 1 : 0);

		Assertions.assertTrue(accepted <= 1, "more than one PEM parser accepted one text");

		if (accepted == 0)
			return;

		if (!certificate)
			requireKind(PemException.Kind.UNSUPPORTED_LABEL, () -> Pem.parseCertificate(pem));
		if (!publicKey)
			requireKind(PemException.Kind.UNSUPPORTED_LABEL, () -> Pem.parsePublicKey(pem));
		if (privateKey == null)
			requireKind(PemException.Kind.UNSUPPORTED_LABEL, () -> Pem.parsePrivateKey(pem));

		byte[] body = acceptedBody(pem);
		Assertions.assertNull(framingFailure(body), "an accepted block's body is not exactly one DER SEQUENCE");

		if (privateKey != null && pem.contains("-----BEGIN PRIVATE KEY-----"))
			requirePrivateKeyOctetsHoldOneElement(body, privateKey);
	}

	/**
	 * The DER checks behind every label, reached directly: {@link Pem#parseCertificateDer(byte[])} and the three PEM
	 * parsers on the same bytes armored as {@code CERTIFICATE}, {@code PUBLIC KEY}, {@code PRIVATE KEY} and
	 * {@code RSA PRIVATE KEY} throw only {@link PemException} with a fixed message, and the certificate parser gives the
	 * same outcome with and without armor (an equal certificate, or the same Kind). Every path reads the DER as one
	 * {@code SEQUENCE} first, so when an X.690 reader written here finds no {@code SEQUENCE} with a minimal definite
	 * length that fits, all five fail with {@link PemException.Kind#MALFORMED_DER}, and when bytes follow it, all five
	 * fail with {@link PemException.Kind#TRAILING_DATA} (exit 6). An accepted PKCS#8 key's {@code privateKey} octets hold
	 * exactly one element.
	 *
	 * @param der the fuzzed DER
	 */
	@FuzzTest(maxDuration = "5m")
	public void derParsersRejectOnlyWithPemExceptionAndAgreeWithTheirArmoredForms(byte[] der) {
		PemException.Kind framing = framingFailure(der);

		if (framing != null) {
			requireKind(framing, () -> Pem.parseCertificateDer(der.clone()));
			requireKind(framing, () -> Pem.parseCertificate(armor("CERTIFICATE", der)));
			requireKind(framing, () -> Pem.parsePublicKey(armor("PUBLIC KEY", der)));
			requireKind(framing, () -> Pem.parsePrivateKey(armor("PRIVATE KEY", der)));
			requireKind(framing, () -> Pem.parsePrivateKey(armor("RSA PRIVATE KEY", der)));
			return;
		}

		X509Certificate fromDer = null;
		PemException.Kind derFailure = null;

		try {
			fromDer = Pem.parseCertificateDer(der.clone());
			requireCertificateRoundTrip(fromDer);
			Assertions.assertArrayEquals(der, encoded(fromDer), "an accepted certificate's encoding is not its DER");
		} catch (PemException e) {
			requireFixedShape(e);
			derFailure = e.getKind();
		}

		X509Certificate fromPem = certificate(armor("CERTIFICATE", der));

		if (fromDer != null) {
			Assertions.assertEquals(fromDer, fromPem, "armor changed the certificate parser's result");
		} else {
			Assertions.assertNull(fromPem, "the armored certificate parsed where the DER did not");
			PemException.Kind expected = derFailure;
			requireKind(expected, () -> Pem.parseCertificate(armor("CERTIFICATE", der)));
		}

		publicKey(armor("PUBLIC KEY", der));
		PrivateKey pkcs8 = privateKey(armor("PRIVATE KEY", der));

		if (pkcs8 != null)
			requirePrivateKeyOctetsHoldOneElement(der, pkcs8);

		privateKey(armor("RSA PRIVATE KEY", der));
	}

	/**
	 * The Kind that the first DER step of every path must give, from X.690 section 8.1 and 10.1 written here:
	 * {@link PemException.Kind#MALFORMED_DER} unless the input starts with a {@code SEQUENCE} whose length is definite,
	 * minimal and inside the input; {@link PemException.Kind#TRAILING_DATA} if bytes follow it; {@code null} if the
	 * input is exactly one such {@code SEQUENCE}.
	 */
	private static PemException.Kind framingFailure(byte[] der) {
		if (der.length < 2 || (der[0] & 0xFF) != SEQUENCE)
			return PemException.Kind.MALFORMED_DER;

		int first = der[1] & 0xFF;
		int contentStart = 2;
		long length = first;

		if (first >= 0x80) {
			int count = first & 0x7F;

			// The indefinite form (count 0) is BER only; DER's long form is for lengths of 128 or more, in the fewest
			// octets, so its first octet is not zero. More than eight octets would not fit in a long, nor in memory.
			if (count == 0 || count > 8 || der.length - contentStart < count || der[contentStart] == 0)
				return PemException.Kind.MALFORMED_DER;

			length = 0;

			for (int index = 0; index < count; ++index)
				length = (length << 8) | (der[contentStart++] & 0xFF);

			if (length < 0x80)
				return PemException.Kind.MALFORMED_DER;
		}

		if (length > der.length - contentStart)
			return PemException.Kind.MALFORMED_DER;

		return contentStart + length < der.length ? PemException.Kind.TRAILING_DATA : null;
	}

	/**
	 * An accepted PKCS#8 key's {@code privateKey} octets hold exactly one element with nothing after it (RFC 5958
	 * section 2): an {@code RSAPrivateKey} or {@code ECPrivateKey} {@code SEQUENCE}, or an EdDSA
	 * {@code CurvePrivateKey} {@code OCTET STRING}. Walked with the reader below, not with {@link Pem}'s.
	 */
	private static void requirePrivateKeyOctetsHoldOneElement(byte[] pkcs8, PrivateKey key) {
		int[] outer = element(pkcs8, 0, pkcs8.length);
		int[] version = element(pkcs8, outer[1], outer[2]);
		int[] algorithm = element(pkcs8, version[2], outer[2]);
		int[] privateKey = element(pkcs8, algorithm[2], outer[2]);
		Assertions.assertEquals(OCTET_STRING, privateKey[0], "an accepted key's privateKey is not an OCTET STRING");

		int[] inner = element(pkcs8, privateKey[1], privateKey[2]);
		Assertions.assertEquals(key.getAlgorithm().startsWith("Ed") ? OCTET_STRING : SEQUENCE, inner[0],
				"an accepted key's privateKey octets hold the wrong type");
		Assertions.assertEquals(privateKey[2], inner[2], "an accepted key has bytes after its privateKey element");
	}

	/**
	 * The element at {@code offset} of a structure the parser accepted: its identifier octet and the bounds of its
	 * contents, from a definite length that must end by {@code limit}.
	 */
	private static int[] element(byte[] der, int offset, int limit) {
		Assertions.assertTrue(limit - offset >= 2, "an accepted key holds a truncated element");
		int tag = der[offset] & 0xFF;
		int first = der[offset + 1] & 0xFF;
		int start = offset + 2;
		long length = first;

		if (first >= 0x80) {
			int count = first & 0x7F;
			Assertions.assertTrue(count >= 1 && count <= 4 && limit - start >= count, "an accepted key holds a bad length");
			length = 0;

			for (int index = 0; index < count; ++index)
				length = (length << 8) | (der[start++] & 0xFF);
		}

		Assertions.assertTrue(length <= limit - start, "an accepted key holds an element longer than its parent");
		return new int[]{tag, start, start + (int) length};
	}

	/**
	 * The body of a block that a parser accepted, decoded here: the Base64 lines between the BEGIN and END lines.
	 */
	private static byte[] acceptedBody(String pem) {
		int bodyStart = pem.indexOf('\n', pem.indexOf("-----BEGIN ")) + 1;
		int bodyEnd = pem.lastIndexOf("-----END ");
		return Base64.getDecoder().decode(pem.substring(bodyStart, bodyEnd).replace("\r", "").replace("\n", ""));
	}

	/**
	 * Parses a certificate, returning {@code null} after a well-formed rejection.
	 */
	private static X509Certificate certificate(String pem) {
		X509Certificate certificate;

		try {
			certificate = Pem.parseCertificate(pem);
		} catch (PemException e) {
			requireFixedShape(e);
			return null;
		}

		requireCertificateRoundTrip(certificate);
		return certificate;
	}

	private static void requireCertificateRoundTrip(X509Certificate certificate) {
		byte[] encoded = encoded(certificate);

		try {
			X509Certificate reparsed = Pem.parseCertificate(armor("CERTIFICATE", encoded));
			Assertions.assertEquals(certificate, reparsed, "a re-armored certificate parsed to another certificate");
			Assertions.assertArrayEquals(encoded, encoded(Pem.parseCertificateDer(encoded)), "the DER path differs");
		} catch (PemException e) {
			Assertions.fail("an accepted certificate's own encoding was rejected: " + e.getKind());
		}
	}

	/**
	 * Parses a public key, returning {@code null} after a well-formed rejection.
	 */
	private static PublicKey publicKey(String pem) {
		PublicKey key;

		try {
			key = Pem.parsePublicKey(pem);
		} catch (PemException e) {
			requireFixedShape(e);
			return null;
		}

		Assertions.assertTrue(KEY_ALGORITHMS.contains(key.getAlgorithm()), "unexpected algorithm " + key.getAlgorithm());
		Assertions.assertEquals("X.509", key.getFormat(), "a public key is not X.509 encoded");

		try {
			PublicKey reparsed = Pem.parsePublicKey(armor("PUBLIC KEY", key.getEncoded()));
			Assertions.assertEquals(key, reparsed, "a re-armored public key parsed to another key");
			Assertions.assertArrayEquals(key.getEncoded(), reparsed.getEncoded(), "a public key's encoding changed");
		} catch (PemException e) {
			Assertions.fail("an accepted public key's own encoding was rejected: " + e.getKind());
		}

		return key;
	}

	/**
	 * Parses a private key, returning {@code null} after a well-formed rejection. The JDK's own PKCS#8 encoding of an
	 * accepted key is accepted too, and is a fixed point.
	 */
	private static PrivateKey privateKey(String pem) {
		PrivateKey key;

		try {
			key = Pem.parsePrivateKey(pem);
		} catch (PemException e) {
			requireFixedShape(e);
			return null;
		}

		Assertions.assertTrue(KEY_ALGORITHMS.contains(key.getAlgorithm()), "unexpected algorithm " + key.getAlgorithm());
		Assertions.assertEquals("PKCS#8", key.getFormat(), "a private key is not PKCS#8 encoded");

		try {
			PrivateKey reparsed = Pem.parsePrivateKey(armor("PRIVATE KEY", key.getEncoded()));
			Assertions.assertEquals(key.getAlgorithm(), reparsed.getAlgorithm(), "a private key changed algorithm");
			Assertions.assertArrayEquals(key.getEncoded(), reparsed.getEncoded(), "a private key's encoding changed");
		} catch (PemException e) {
			Assertions.fail("an accepted private key's own encoding was rejected: " + e.getKind());
		}

		return key;
	}

	private static void requireFixedShape(PemException exception) {
		Assertions.assertNotNull(exception.getKind(), "a PemException has no Kind");
		Assertions.assertEquals(exception.getKind().getMessage(), exception.getMessage(), "not the Kind's fixed message");
		Assertions.assertNull(exception.getCause(), "a PemException has a cause");
		Assertions.assertEquals(0, exception.getSuppressed().length, "a PemException has suppressed exceptions");
	}

	private static void requireKind(PemException.Kind expected, PemCall call) {
		try {
			call.run();
		} catch (PemException e) {
			requireFixedShape(e);
			Assertions.assertEquals(expected, e.getKind(), "a PEM parser failed with the wrong Kind");
			return;
		}

		Assertions.fail("a PEM parser accepted text it must reject with " + expected);
	}

	private static byte[] encoded(X509Certificate certificate) {
		try {
			return certificate.getEncoded();
		} catch (CertificateEncodingException e) {
			throw new IllegalStateException("An accepted certificate has no encoding.", e);
		}
	}

	/**
	 * RFC 7468 armor: the label's BEGIN line, Base64 in 64-character lines, and the END line, each ending in LF.
	 */
	private static String armor(String label, byte[] der) {
		String base64 = Base64.getEncoder().encodeToString(der);
		StringBuilder pem = new StringBuilder("-----BEGIN ").append(label).append("-----\n");

		for (int start = 0; start < base64.length(); start += 64)
			pem.append(base64, start, Math.min(base64.length(), start + 64)).append('\n');

		return pem.append("-----END ").append(label).append("-----\n").toString();
	}

	/**
	 * A parser call that may throw {@link PemException}.
	 */
	@FunctionalInterface
	private interface PemCall {
		void run() throws PemException;
	}
}
