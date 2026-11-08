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

package com.revetsec;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.revetsec.internal.crypto.EcCurve;
import com.revetsec.internal.crypto.EcPublicKeys;
import com.revetsec.internal.crypto.Ed25519PublicKeys;
import com.revetsec.internal.crypto.RsaPublicKeys;
import com.revetsec.internal.encoding.Der;
import com.revetsec.internal.pem.Pem;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;
import java.util.stream.Stream;

/** Exact M-K facade profile/ownership/budget cells; all fixtures and probe material are test-only. */
final class KeyImportsTests {
	private static final Duration BUDGET = Duration.ofSeconds(5);
	private static final String SENTINEL = "KeyImportSensitiveProviderSentinel";
	private record Material(@NonNull String family, @NonNull String certificate, @NonNull String publicKey, @NonNull String privateKey) { }
	private static final List<Material> MATERIALS = List.of(
			new Material("RSA", "keys/idp-signing-rsa-2048-cert.pem", "pem/rsa-2048-public.pem", "keys/idp-signing-rsa-2048-key.pem"),
			new Material("P256", "keys/idp-signing-ec-p256-cert.pem", "pem/ec-p256-public.pem", "keys/idp-signing-ec-p256-key.pem"),
			new Material("P384", "keys/idp-signing-ec-p384-cert.pem", "key-import/ec-p384-public.pem", "keys/idp-signing-ec-p384-key.pem"),
			new Material("ED25519", "key-import/ed25519-cert.pem", "pem/ed25519-public.pem", "pem/ed25519-key.pem"));

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> allTwentySixNominalOrdinaryFormatFamilyLanes() {
		List<DynamicTest> cases = new ArrayList<>();
		for (Material material : MATERIALS) for (String kind : List.of("certificate", "public", "private")) for (boolean pem : new boolean[] {true, false})
			cases.add(DynamicTest.dynamicTest(material.family + "/" + kind + "/" + (pem ? "PEM" : "DER"), () -> {
				String text = fixture(kind.equals("certificate") ? material.certificate : kind.equals("public") ? material.publicKey : material.privateKey);
				byte[] der = der(text), before = der.clone();
				try {
					if (kind.equals("certificate")) {
						X509Certificate certificate = pem ? KeyImports.certificateFromPem(text) : KeyImports.certificateFromDer(der);
						Assertions.assertTrue(Arrays.equals(der, certificate.getEncoded()), "ordinary certificate exact input"); profile(certificate.getPublicKey());
					} else if (kind.equals("public")) {
						PublicKey key = pem ? KeyImports.publicKeyFromPem(text) : KeyImports.publicKeyFromSpkiDer(der);
						Assertions.assertTrue(Arrays.equals(der, key.getEncoded()), "ordinary public exact SPKI"); profile(key);
					} else {
						PrivateKey key = pem ? KeyImports.privateKeyFromPem(text) : KeyImports.privateKeyFromPkcs8Der(der);
						KeyImports.checkKeyPair(key, KeyImports.publicKeyFromPem(fixture(material.publicKey)), BUDGET);
					}
					Assertions.assertTrue(Arrays.equals(before, der), "caller DER unchanged");
				} finally { clear(der); clear(before); }
			}));
		for (boolean pem : new boolean[] {true, false}) cases.add(DynamicTest.dynamicTest("RSA/PKCS1/" + (pem ? "PEM" : "DER"), () -> {
			String text = fixture("pem/rsa-2048-pkcs1-key.pem"); byte[] input = der(text), before = input.clone();
			try { KeyImports.checkKeyPair(pem ? KeyImports.privateKeyFromPem(text) : KeyImports.rsaPrivateKeyFromPkcs1Der(input),
					KeyImports.publicKeyFromPem(fixture(MATERIALS.get(0).publicKey)), BUDGET);
				Assertions.assertTrue(Arrays.equals(input, before), "PKCS1 caller input unchanged");
			} finally { clear(input); clear(before); }
		}));
		return cases.stream();
	}

	@Test
	@SuppressWarnings("NullAway") // Deliberate required-null misuse verifies the public rejection contract.
	void nullsAndEveryFixedExceptionReasonHaveTheDeclaredOwnershipAndDiagnostics() {
		for (Executable operation : List.<Executable>of(() -> KeyImports.certificateFromPem(null), () -> KeyImports.certificateFromDer(null),
				() -> KeyImports.publicKeyFromPem(null), () -> KeyImports.publicKeyFromSpkiDer(null), () -> KeyImports.privateKeyFromPem(null),
				() -> KeyImports.privateKeyFromPkcs8Der(null), () -> KeyImports.rsaPrivateKeyFromPkcs1Der(null),
				() -> KeyImports.checkKeyPair(null, null, BUDGET))) Assertions.assertThrows(NullPointerException.class, operation);
		for (KeyImportException.Reason reason : KeyImportException.Reason.values()) {
			KeyImportException failure = KeyImportException.fromReason(reason);
			Assertions.assertEquals(reason, failure.getReason()); Assertions.assertNull(failure.getCause());
			failure.addSuppressed(new IllegalStateException(SENTINEL)); Assertions.assertEquals(0, failure.getSuppressed().length);
			Assertions.assertFalse(failure.toString().contains(SENTINEL));
			Assertions.assertEquals(reason == KeyImportException.Reason.BUDGET_EXHAUSTED, failure.isTemporaryCondition());
		}
		Assertions.assertTrue(Arrays.stream(KeyImportException.class.getDeclaredConstructors()).allMatch(c -> java.lang.reflect.Modifier.isPrivate(c.getModifiers())));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> exactInputAndDecodedRepresentationBounds() {
		List<DynamicTest> cases = new ArrayList<>();
		for (String kind : List.of("certificate", "public", "private", "pkcs1")) for (int length : new int[] {0, 65_536, 65_537})
			cases.add(DynamicTest.dynamicTest("DER/" + kind + "/" + length, () -> {
				byte[] input = new byte[length], before = input.clone();
				reason(length > 65_536 ? KeyImportException.Reason.INPUT_TOO_LARGE : KeyImportException.Reason.MALFORMED_INPUT, () -> fromDer(kind, input));
				Assertions.assertTrue(Arrays.equals(input, before), "invalid caller input unchanged");
			}));
		for (String kind : List.of("certificate", "public", "private")) {
			String label = kind.equals("certificate") ? "CERTIFICATE" : kind.equals("public") ? "PUBLIC KEY" : "PRIVATE KEY";
			String ordinary = fixture(kind.equals("certificate") ? MATERIALS.get(0).certificate : kind.equals("public") ? MATERIALS.get(0).publicKey : MATERIALS.get(0).privateKey);
			cases.add(DynamicTest.dynamicTest("PEM/exact-text-bound/" + kind, () -> fromPem(kind, ordinary + " ".repeat(98_304 - ordinary.length()))));
			cases.add(DynamicTest.dynamicTest("PEM/over-text-bound/" + kind, () -> reason(KeyImportException.Reason.INPUT_TOO_LARGE,
					() -> fromPem(kind, ordinary + " ".repeat(98_305 - ordinary.length())))));
			for (int length : new int[] {65_536, 65_537}) cases.add(DynamicTest.dynamicTest("PEM/decoded-bound/" + kind + "/" + length, () ->
				reason(length > 65_536 ? KeyImportException.Reason.INPUT_TOO_LARGE : KeyImportException.Reason.MALFORMED_INPUT,
						() -> fromPem(kind, armor(label, new byte[length])))));
		}
		return cases.stream();
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> malformedArmorBase64WrongLabelsAndSelectedUnsupportedForms() {
		List<DynamicTest> cases = new ArrayList<>(); String ordinary = fixture(MATERIALS.get(0).publicKey);
		for (String malformed : List.of(ordinary + ordinary, SENTINEL + ordinary, ordinary + SENTINEL,
				ordinary.replace("END PUBLIC", "END PRIVATE"), ordinary.replace("BEGIN PUBLIC KEY-----\n", "BEGIN PUBLIC KEY----- \n"),
				"-----BEGIN PUBLIC KEY-----\nAA== \n-----END PUBLIC KEY-----\n", "-----BEGIN PUBLIC KEY-----\nAB==\n-----END PUBLIC KEY-----\n")) {
			int index = cases.size(); cases.add(DynamicTest.dynamicTest("armor/" + index, () -> reason(KeyImportException.Reason.MALFORMED_INPUT, () -> KeyImports.publicKeyFromPem(malformed))));
		}
		for (String path : List.of("pem/ec-p256-sec1-key.pem", "pem/rsa-2048-encrypted-pkcs1-key.pem", "pem/rsa-2048-encrypted-pkcs8-key.pem", "pem/x25519-key.pem", "pem/ec-p256-explicit-parameters-key.pem"))
			cases.add(DynamicTest.dynamicTest(path, () -> reason(KeyImportException.Reason.UNSUPPORTED_KEY, () -> KeyImports.privateKeyFromPem(fixture(path)))));
		for (String kind : List.of("certificate", "public", "private")) cases.add(DynamicTest.dynamicTest("wrong-label/" + kind, () -> reason(KeyImportException.Reason.UNSUPPORTED_KEY,
				() -> fromPem(kind, kind.equals("public") ? fixture(MATERIALS.get(0).certificate) : ordinary))));
		return cases.stream();
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> selectedStrengthCurvePointAndAlgorithmPolicy() {
		List<DynamicTest> cases = new ArrayList<>();
		for (String kind : List.of("certificate", "private")) cases.add(DynamicTest.dynamicTest("weak1024/" + kind, () -> reason(KeyImportException.Reason.KEY_REJECTED,
				() -> fromPem(kind, fixture("keys/negative-rsa-1024-" + (kind.equals("private") ? "key" : "cert") + ".pem")))));
		for (String kind : List.of("certificate", "private")) cases.add(DynamicTest.dynamicTest("P521/" + kind, () -> reason(KeyImportException.Reason.UNSUPPORTED_KEY,
				() -> fromPem(kind, fixture("keys/idp-signing-ec-p521-" + (kind.equals("private") ? "key" : "cert") + ".pem")))));
		for (String family : List.of("Ed448", "X25519", "RSASSA-PSS")) for (boolean privateKey : new boolean[] {false, true})
			cases.add(DynamicTest.dynamicTest(family + "/" + privateKey, () -> {
				KeyPairGenerator generator = KeyPairGenerator.getInstance(family); if (family.equals("RSASSA-PSS")) generator.initialize(2048);
				KeyPair pair = generator.generateKeyPair();
				reason(KeyImportException.Reason.UNSUPPORTED_KEY, () -> { if (privateKey) Assertions.assertNotNull(KeyImports.privateKeyFromPkcs8Der(pair.getPrivate().getEncoded())); else Assertions.assertNotNull(KeyImports.publicKeyFromSpkiDer(pair.getPublic().getEncoded())); });
			}));
		cases.add(DynamicTest.dynamicTest("off-curve-SPKI", () -> {
			byte[] bytes = der(fixture(MATERIALS.get(1).publicKey)); bytes[bytes.length - 1] ^= 1;
			reason(KeyImportException.Reason.KEY_REJECTED, () -> KeyImports.publicKeyFromSpkiDer(bytes));
		}));
		for (int point : new int[] {0, 1}) cases.add(DynamicTest.dynamicTest("small-order-Ed25519/" + point, () -> {
			byte[] bytes = der(fixture(MATERIALS.get(3).publicKey)); Arrays.fill(bytes, bytes.length - 32, bytes.length, (byte) 0); bytes[bytes.length - 32] = (byte) point;
			reason(KeyImportException.Reason.KEY_REJECTED, () -> KeyImports.publicKeyFromSpkiDer(bytes));
		}));
		return cases.stream();
	}


	@Test
	void certificateImportDoesNotEstablishSignatureTrustOrValidity() throws Exception {
		byte[] source = der(fixture(MATERIALS.get(0).certificate)); List<byte[]> certificate = children(source), tbs = children(certificate.get(0));
		int validity = (tbs.get(0)[0] & 0xff) == 0xa0 ? 4 : 3;
		tbs.set(validity, tlv(0x30, concat(tlv(0x17, "000101000000Z".getBytes(StandardCharsets.US_ASCII)), tlv(0x17, "000102000000Z".getBytes(StandardCharsets.US_ASCII)))));
		certificate.set(0, tlv(0x30, concat(tbs))); byte[] expiredWithBrokenSignature = tlv(0x30, concat(certificate));
		X509Certificate parsed = KeyImports.certificateFromDer(expiredWithBrokenSignature);
		Assertions.assertTrue(parsed.getNotAfter().toInstant().isBefore(java.time.Instant.parse("2001-01-01T00:00:00Z")));
		Assertions.assertThrows(java.security.cert.CertificateExpiredException.class, parsed::checkValidity);
		Assertions.assertThrows(GeneralSecurityException.class, () -> parsed.verify(parsed.getPublicKey()));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> noncanonicalRsaPublicKeyInnerSchemaIsRejectedThroughBothFacadeFormats() {
		List<DynamicTest> cases = new ArrayList<>(); List<byte[]> outer = children(der(fixture(MATERIALS.get(0).publicKey)));
		byte[] bits = content(outer.get(1)); List<byte[]> rsa = children(Arrays.copyOfRange(bits, 1, bits.length));
		for (int slot = 0; slot < 2; ++slot) for (String mode : List.of("redundant-zero", "negative")) {
			List<byte[]> changed = cloneFields(rsa); changed.set(slot, tlv(2, mode.equals("redundant-zero") ? concat(new byte[] {0}, content(rsa.get(slot))) : new byte[] {(byte) 0xff}));
			byte[] invalid = tlv(0x30, concat(outer.get(0), tlv(3, concat(new byte[] {0}, tlv(0x30, concat(changed))))));
			cases.add(DynamicTest.dynamicTest("public-RSA/" + slot + "/" + mode, () -> {
				Assertions.assertThrows(KeyImportException.class, () -> KeyImports.publicKeyFromSpkiDer(invalid));
				Assertions.assertThrows(KeyImportException.class, () -> KeyImports.publicKeyFromPem(armor("PUBLIC KEY", invalid)));
			}));
		}
		for (byte[] tail : List.of(tlv(2, new byte[] {1}), new byte[] {0})) {
			byte[] invalid = tlv(0x30, concat(outer.get(0), tlv(3, concat(new byte[] {0}, tlv(0x30, concat(concat(rsa), tail))))));
			cases.add(DynamicTest.dynamicTest("public-RSA/extra-tail/" + tail.length, () -> Assertions.assertThrows(KeyImportException.class, () -> KeyImports.publicKeyFromSpkiDer(invalid))));
		}
		byte[] invalidBits = bits.clone(); invalidBits[0] = 1; byte[] invalid = tlv(0x30, concat(outer.get(0), tlv(3, invalidBits)));
		cases.add(DynamicTest.dynamicTest("public-RSA/nonzero-unused-bits", () -> reason(KeyImportException.Reason.MALFORMED_INPUT, () -> KeyImports.publicKeyFromSpkiDer(invalid))));
		return cases.stream();
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> malformedAndNoncanonicalPrivateRsaSchemaAliasesAreRejected() {
		byte[] input = der(fixture("pem/rsa-2048-pkcs1-key.pem")); List<byte[]> fields = children(input);
		List<DynamicTest> cases = new ArrayList<>();
		for (int slot = 1; slot < 9; ++slot) for (String mode : List.of("redundant-zero", "negative", "zero")) {
			List<byte[]> changed = cloneFields(fields); byte[] content = content(fields.get(slot));
			changed.set(slot, tlv(2, mode.equals("redundant-zero") ? concat(new byte[] {0}, content) : mode.equals("negative") ? new byte[] {(byte) 0xff} : new byte[] {0}));
			byte[] malformed = tlv(0x30, concat(changed));
			cases.add(DynamicTest.dynamicTest("RSA/" + slot + "/" + mode, () -> {
				reason(KeyImportException.Reason.MALFORMED_INPUT, () -> KeyImports.rsaPrivateKeyFromPkcs1Der(malformed));
				reason(KeyImportException.Reason.MALFORMED_INPUT, () -> KeyImports.privateKeyFromPkcs8Der(pkcs8Rsa(malformed)));
				reason(KeyImportException.Reason.MALFORMED_INPUT, () -> KeyImports.privateKeyFromPem(armor("RSA PRIVATE KEY", malformed)));
			}));
		}
		for (byte[] version : List.of(new byte[] {0, 0}, new byte[] {(byte) 0xff})) {
			List<byte[]> changed = cloneFields(fields); changed.set(0, tlv(2, version)); byte[] invalid = tlv(0x30, concat(changed));
			cases.add(DynamicTest.dynamicTest("RSA/invalid-inner-version/" + version.length, () -> reason(KeyImportException.Reason.MALFORMED_INPUT, () -> KeyImports.rsaPrivateKeyFromPkcs1Der(invalid))));
		}
		for (byte[] tail : List.of(tlv(2, new byte[] {1}), new byte[] {0})) {
			byte[] malformed = tlv(0x30, concat(concat(fields), tail));
			cases.add(DynamicTest.dynamicTest("RSA/extra-tail/" + tail.length, () -> reason(KeyImportException.Reason.MALFORMED_INPUT, () -> KeyImports.rsaPrivateKeyFromPkcs1Der(malformed))));
		}
		List<byte[]> lowExponent = cloneFields(fields); lowExponent.set(2, tlv(2, new byte[] {3})); byte[] e3 = tlv(0x30, concat(lowExponent));
		cases.add(DynamicTest.dynamicTest("RSA/exponent-policy", () -> reason(KeyImportException.Reason.KEY_REJECTED, () -> KeyImports.rsaPrivateKeyFromPkcs1Der(e3))));
		return cases.stream();
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> ecScalarNamedParameterAndEmbeddedHintSchemaCells() {
		List<DynamicTest> cases = new ArrayList<>();
		for (Material material : MATERIALS.subList(1, 3)) {
			byte[] input = der(fixture(material.privateKey)); List<byte[]> outer = children(input), fields = children(content(outer.get(2)));
			EcCurve curve = material.family.equals("P256") ? EcCurve.P_256 : EcCurve.P_384;
			for (String mode : List.of("zero", "order", "over-order", "short", "long")) {
				List<byte[]> changed = cloneFields(fields); int width = curve.getCoordinateLength();
				byte[] scalar = mode.equals("zero") ? new byte[width] : mode.equals("short") ? new byte[width - 1] : mode.equals("long") ? new byte[width + 1]
						: unsigned(curve.getOrder().add(mode.equals("over-order") ? BigInteger.ONE : BigInteger.ZERO), width);
				changed.set(1, tlv(4, scalar)); byte[] invalid = replacePrivate(outer, tlv(0x30, concat(changed)));
				cases.add(DynamicTest.dynamicTest(material.family + "/scalar/" + mode, () -> reason(KeyImportException.Reason.KEY_REJECTED, () -> KeyImports.privateKeyFromPkcs8Der(invalid))));
			}
			byte[] matchingOid = HexFormat.of().parseHex(material.family.equals("P256") ? "06082a8648ce3d030107" : "06052b81040022");
			List<byte[]> matchingParameters = new ArrayList<>(fields.subList(0, 2)); matchingParameters.add(tlv(0xa0, matchingOid)); matchingParameters.addAll(fields.subList(2, fields.size()));
			byte[] matching = replacePrivate(outer, tlv(0x30, concat(matchingParameters)));
			cases.add(DynamicTest.dynamicTest(material.family + "/matching-inner-curve", () -> KeyImports.checkKeyPair(KeyImports.privateKeyFromPkcs8Der(matching), KeyImports.publicKeyFromPem(fixture(material.publicKey)), BUDGET)));
			byte[] wrongOid = HexFormat.of().parseHex(material.family.equals("P256") ? "06052b81040022" : "06082a8648ce3d030107");
			List<byte[]> wrongParameters = new ArrayList<>(fields.subList(0, 2)); wrongParameters.add(tlv(0xa0, wrongOid));
			byte[] invalidParameters = replacePrivate(outer, tlv(0x30, concat(wrongParameters)));
			cases.add(DynamicTest.dynamicTest(material.family + "/conflicting-inner-curve", () -> reason(KeyImportException.Reason.KEY_REJECTED, () -> KeyImports.privateKeyFromPkcs8Der(invalidParameters))));
			for (String mode : List.of("unused-bits", "compressed", "off-curve", "duplicate", "trailing")) {
				byte[] point = new byte[2 + 2 * curve.getCoordinateLength()]; point[1] = 4;
				ECPublicKey publicKey = (ECPublicKey) KeyImports.publicKeyFromPem(fixture(material.publicKey));
				System.arraycopy(unsigned(publicKey.getW().getAffineX(), curve.getCoordinateLength()), 0, point, 2, curve.getCoordinateLength());
				System.arraycopy(unsigned(publicKey.getW().getAffineY(), curve.getCoordinateLength()), 0, point, 2 + curve.getCoordinateLength(), curve.getCoordinateLength());
				if (mode.equals("unused-bits")) point[0] = 1;
				if (mode.equals("compressed")) point = new byte[] {0, 2, 1};
				if (mode.equals("off-curve")) point[point.length - 1] ^= 1;
				byte[] hint = tlv(0xa1, tlv(3, point)); List<byte[]> changed = new ArrayList<>(fields.subList(0, 2)); changed.add(hint);
				if (mode.equals("duplicate")) changed.add(hint); if (mode.equals("trailing")) changed.add(tlv(2, new byte[] {1}));
				byte[] invalid = replacePrivate(outer, tlv(0x30, concat(changed)));
				cases.add(DynamicTest.dynamicTest(material.family + "/hint/" + mode, () -> reason(mode.equals("duplicate") || mode.equals("trailing")
						? KeyImportException.Reason.MALFORMED_INPUT : KeyImportException.Reason.KEY_REJECTED, () -> KeyImports.privateKeyFromPkcs8Der(invalid))));
			}
		}
		return cases.stream();
	}

	@Test
	void anOnCurveEcPublicHintIsUntrustedMetadataUntilExplicitPairChecking() throws Exception {
		Material material = MATERIALS.get(1); List<byte[]> outer = children(der(fixture(material.privateKey)));
		List<byte[]> inner = children(content(outer.get(2))); ECPublicKey wrong = (ECPublicKey) KeyImports.certificateFromPem(fixture("keys/negative-unconfigured-ec-p256-cert.pem")).getPublicKey();
		byte[] point = concat(new byte[] {0, 4}, unsigned(wrong.getW().getAffineX(), 32), unsigned(wrong.getW().getAffineY(), 32));
		List<byte[]> changed = new ArrayList<>(inner.subList(0, 2)); changed.add(tlv(0xa1, tlv(3, point)));
		PrivateKey imported = KeyImports.privateKeyFromPkcs8Der(replacePrivate(outer, tlv(0x30, concat(changed))));
		reason(KeyImportException.Reason.KEY_PAIR_MISMATCH, () -> KeyImports.checkKeyPair(imported, wrong, BUDGET));
		KeyImports.checkKeyPair(imported, KeyImports.publicKeyFromPem(fixture(material.publicKey)), BUDGET);
	}

	@Test
	void ordinaryCanonicalAttributesAndRfc5958AreUnsupportedWithoutChangingLegacyPem() throws Exception {
		byte[] source = der(fixture(MATERIALS.get(3).privateKey)); List<byte[]> fields = children(source);
		byte[] attributes = tlv(0x30, concat(concat(fields), tlv(0xa0, new byte[0])));
		Assertions.assertNotNull(Pem.parsePrivateKey(armor("PRIVATE KEY", attributes)), "legacy attributes acceptance retained");
		reason(KeyImportException.Reason.UNSUPPORTED_KEY, () -> KeyImports.privateKeyFromPkcs8Der(attributes));
		List<byte[]> v1 = cloneFields(fields); v1.set(0, tlv(2, new byte[] {1}));
		byte[] point = der(fixture(MATERIALS.get(3).publicKey)); v1.add(tlv(0x81, concat(new byte[] {0}, Arrays.copyOfRange(point, point.length - 32, point.length))));
		byte[] asymmetric = tlv(0x30, concat(v1)); Assertions.assertNotNull(Pem.parsePrivateKey(armor("PRIVATE KEY", asymmetric)), "legacy v1 acceptance retained");
		reason(KeyImportException.Reason.UNSUPPORTED_KEY, () -> KeyImports.privateKeyFromPkcs8Der(asymmetric));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> outerAndInnerTrailingAndNonminimalEncodingControls() {
		List<DynamicTest> cases = new ArrayList<>();
		for (String kind : List.of("certificate", "public", "private", "pkcs1")) {
			String path = kind.equals("certificate") ? MATERIALS.get(0).certificate : kind.equals("public") ? MATERIALS.get(0).publicKey : kind.equals("private") ? MATERIALS.get(3).privateKey : "pem/rsa-2048-pkcs1-key.pem";
			byte[] input = der(fixture(path));
			for (String mode : List.of("trailing", "nonminimal-length", "indefinite", "wrong-tag")) {
				byte[] invalid;
				if (mode.equals("trailing")) invalid = concat(input, new byte[] {0});
				else if (mode.equals("nonminimal-length")) { byte[] body = content(input); invalid = concat(new byte[] {0x30, (byte) 0x84, 0, 0, (byte) (body.length >>> 8), (byte) body.length}, body); }
				else if (mode.equals("indefinite")) invalid = concat(new byte[] {0x30, (byte) 0x80}, content(input), new byte[] {0, 0});
				else { invalid = input.clone(); invalid[0] = 4; }
				cases.add(DynamicTest.dynamicTest(kind + "/" + mode, () -> reason(KeyImportException.Reason.MALFORMED_INPUT, () -> fromDer(kind, invalid))));
			}
		}
		return cases.stream();
	}


    @Test
    @SuppressWarnings("serial") // In-process unexportable test key metadata; never serialized or persisted.
    void unsupportedEcDomainMetadataRefusesBeforeAnyPrivateExport() throws Exception {
        ECPublicKey publicKey = (ECPublicKey) KeyImports.publicKeyFromPem(fixture(MATERIALS.get(1).publicKey));
        var selected = publicKey.getParams();
        var foreign = new java.security.spec.ECParameterSpec(selected.getCurve(), selected.getGenerator(), selected.getOrder().subtract(BigInteger.TWO), selected.getCofactor());
        var exports = new java.util.concurrent.atomic.AtomicInteger();
        java.security.interfaces.ECPrivateKey privateKey = new java.security.interfaces.ECPrivateKey() {
            @Override public @NonNull ECParameterSpec getParams() { return foreign; }
            @Override public @NonNull BigInteger getS() { return BigInteger.ONE; }
            @Override public @NonNull String getAlgorithm() { return "EC"; }
            @Override public @Nullable String getFormat() { return null; }
            @Override public byte @Nullable [] getEncoded() { exports.incrementAndGet(); throw new AssertionError("Private export forbidden"); }
        };
        reason(KeyImportException.Reason.UNSUPPORTED_KEY, () -> KeyImports.checkKeyPair(privateKey, publicKey, BUDGET));
        Assertions.assertEquals(0, exports.get());
    }

	@Test
	void importsNeverProbePairsAndCheckingUsesFreshIndependentSignaturesWithoutPrivateExport() throws Exception {
		withProvider(() -> {
			Material material = MATERIALS.get(0);
			PrivateKey imported = KeyImports.privateKeyFromPem(fixture(material.privateKey));
			PublicKey publicKey = KeyImports.publicKeyFromPem(fixture(material.publicKey)); Assertions.assertNotNull(KeyImports.certificateFromPem(fixture(material.certificate)));
			Assertions.assertEquals(0, State.signs); Assertions.assertEquals(0, State.verifies);
			SpyPrivate opaque = new SpyPrivate(imported); byte[] publicBytes = publicKey.getEncoded(), saved = publicBytes.clone();
			EncodingPublic mutable = new EncodingPublic(publicBytes, 0);
			KeyImports.checkKeyPair(opaque, mutable, BUDGET);
			Assertions.assertEquals(1, mutable.calls); Assertions.assertEquals(1, State.signs); Assertions.assertEquals(1, State.verifies);
			Assertions.assertTrue(Arrays.equals(publicBytes, saved), "caller public encoding unchanged");
			Assertions.assertTrue(allZero(State.challengeReference)); Assertions.assertTrue(allZero(State.signatureReference));
			byte[] first = java.util.Objects.requireNonNull(State.challengeCopy).clone(); KeyImports.checkKeyPair(opaque, publicKey, BUDGET);
			Assertions.assertFalse(Arrays.equals(first, State.challengeCopy), "fresh noncredential challenge for each check");
			Assertions.assertEquals(2, State.signs); Assertions.assertEquals(2, State.verifies); Assertions.assertEquals(0, opaque.exports);
		});
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> explicitSameFamilyWrongPairsAreDetected() {
		return MATERIALS.stream().map(material -> DynamicTest.dynamicTest(material.family, () -> {
			KeyPairGenerator generator = KeyPairGenerator.getInstance(material.family.equals("RSA") ? "RSA" : material.family.startsWith("P") ? "EC" : "Ed25519");
			if (material.family.startsWith("P")) generator.initialize(new ECGenParameterSpec(material.family.equals("P256") ? "secp256r1" : "secp384r1"));
			if (material.family.equals("RSA")) generator.initialize(2048);
			PrivateKey other = generator.generateKeyPair().getPrivate();
			reason(KeyImportException.Reason.KEY_PAIR_MISMATCH, () -> KeyImports.checkKeyPair(other, KeyImports.publicKeyFromPem(fixture(material.publicKey)), BUDGET));
		}));
	}


	@Test
	void exposedPrivateProfilesAndCrossCurveMismatchesFailWithoutPrivateExport() throws Exception {
		PublicKey rsa = KeyImports.publicKeyFromPem(fixture(MATERIALS.get(0).publicKey));
		reason(KeyImportException.Reason.KEY_REJECTED, () -> KeyImports.checkKeyPair(Pem.parsePrivateKey(fixture("keys/negative-rsa-1024-key.pem")), rsa, BUDGET));
		reason(KeyImportException.Reason.UNSUPPORTED_KEY, () -> KeyImports.checkKeyPair(Pem.parsePrivateKey(fixture("keys/idp-signing-ec-p521-key.pem")), rsa, BUDGET));
		reason(KeyImportException.Reason.UNSUPPORTED_KEY, () -> KeyImports.checkKeyPair(KeyPairGenerator.getInstance("Ed448").generateKeyPair().getPrivate(), rsa, BUDGET));
		reason(KeyImportException.Reason.KEY_PAIR_MISMATCH, () -> KeyImports.checkKeyPair(KeyImports.privateKeyFromPem(fixture(MATERIALS.get(2).privateKey)), KeyImports.publicKeyFromPem(fixture(MATERIALS.get(1).publicKey)), BUDGET));
		PrivateKey key = KeyImports.privateKeyFromPem(fixture(MATERIALS.get(0).privateKey));
		reason(KeyImportException.Reason.INPUT_TOO_LARGE, () -> KeyImports.checkKeyPair(key, new EncodingPublic(new byte[65_537], 0), BUDGET));
		try { Thread.currentThread().interrupt(); reason(KeyImportException.Reason.CANCELLED, () -> KeyImports.checkKeyPair(key, rsa, BUDGET)); Assertions.assertTrue(Thread.currentThread().isInterrupted()); }
		finally { Thread.interrupted(); }
	}

	@Test
	void originalBudgetInterruptionProviderFailureAndFailureCleanupArePreserved() throws Exception {
		withProvider(() -> {
			PrivateKey key = KeyImports.privateKeyFromPem(fixture(MATERIALS.get(0).privateKey)); PublicKey publicKey = KeyImports.publicKeyFromPem(fixture(MATERIALS.get(0).publicKey));
			for (Duration budget : List.of(Duration.ZERO, Duration.ofNanos(-1), Duration.ofSeconds(Long.MIN_VALUE)))
				reason(KeyImportException.Reason.BUDGET_EXHAUSTED, () -> KeyImports.checkKeyPair(key, publicKey, budget));
			Assertions.assertEquals(0, State.signs);
			State.mode = "slow-init"; reason(KeyImportException.Reason.BUDGET_EXHAUSTED, () -> KeyImports.checkKeyPair(key, publicKey, Duration.ofMillis(10)));
			Assertions.assertEquals(0, State.signs);
			State.reset(); reason(KeyImportException.Reason.BUDGET_EXHAUSTED, () -> KeyImports.checkKeyPair(key, new EncodingPublic(publicKey.getEncoded(), 40), Duration.ofMillis(10)));
			Assertions.assertEquals(0, State.signs);
			State.mode = "throw"; KeyImportException failure = reason(KeyImportException.Reason.OPERATION_UNAVAILABLE, () -> KeyImports.checkKeyPair(key, publicKey, BUDGET));
			Assertions.assertFalse(failure.toString().contains(SENTINEL)); Assertions.assertNull(failure.getCause()); Assertions.assertEquals(0, failure.getSuppressed().length);
			Assertions.assertTrue(allZero(State.challengeReference));
			State.reset(); State.mode = "interrupt";
			try { reason(KeyImportException.Reason.CANCELLED, () -> KeyImports.checkKeyPair(key, publicKey, BUDGET)); Assertions.assertTrue(Thread.currentThread().isInterrupted()); }
			finally { Thread.interrupted(); }
			Assertions.assertTrue(allZero(State.challengeReference)); Assertions.assertTrue(allZero(State.signatureReference));
			State.reset(); State.mode = "bad-signature";
			reason(KeyImportException.Reason.KEY_PAIR_MISMATCH, () -> KeyImports.checkKeyPair(key, publicKey, BUDGET));
			Assertions.assertEquals(1, State.signs); Assertions.assertEquals(1, State.verifies);
			Assertions.assertTrue(allZero(State.challengeReference)); Assertions.assertTrue(allZero(State.signatureReference));
		});
	}

	@Test
	void boundedSeededMutationNeverLeaksParserOrProviderExceptionsOrChangesCallerArrays() {
		Random random = new Random(20261105L); List<byte[]> seeds = List.of(der(fixture(MATERIALS.get(0).publicKey)), der(fixture(MATERIALS.get(1).privateKey)), der(fixture(MATERIALS.get(3).privateKey)), der(fixture("pem/rsa-2048-pkcs1-key.pem")));
		for (int i = 0; i < 2048; ++i) {
			int kind = i % seeds.size(); byte[] input = seeds.get(kind).clone(); input[random.nextInt(input.length)] ^= (byte) (1 << random.nextInt(8)); byte[] before = input.clone();
			try { fromDer(kind == 0 ? "public" : kind == 3 ? "pkcs1" : "private", input); }
			catch (KeyImportException expected) { Assertions.assertNull(expected.getCause()); Assertions.assertEquals(0, expected.getSuppressed().length); }
			Assertions.assertTrue(Arrays.equals(input, before), "mutation caller input unchanged"); clear(input); clear(before);
		}
	}

	private static void profile(@NonNull PublicKey key) throws Exception {
		if (key instanceof RSAPublicKey rsa) RsaPublicKeys.checkPublicKey(rsa);
		else if (key instanceof ECPublicKey ec) EcPublicKeys.checkPublicKey(EcCurve.findByParameterSpec(ec.getParams()).orElseThrow(), ec);
		else Ed25519PublicKeys.checkPublicKey((EdECPublicKey) key);
	}
	private static void fromDer(@NonNull String kind, byte @NonNull [] input) {
		Object imported = switch (kind) { case "certificate" -> KeyImports.certificateFromDer(input); case "public" -> KeyImports.publicKeyFromSpkiDer(input); case "private" -> KeyImports.privateKeyFromPkcs8Der(input); default -> KeyImports.rsaPrivateKeyFromPkcs1Der(input); }; Assertions.assertNotNull(imported);
	}
	private static void fromPem(@NonNull String kind, @NonNull String input) {
		Object imported = switch (kind) { case "certificate" -> KeyImports.certificateFromPem(input); case "public" -> KeyImports.publicKeyFromPem(input); default -> KeyImports.privateKeyFromPem(input); }; Assertions.assertNotNull(imported);
	}
	private static @NonNull KeyImportException reason(KeyImportException.@NonNull Reason reason, @NonNull Executable operation) {
		KeyImportException actual = Assertions.assertThrows(KeyImportException.class, operation); Assertions.assertEquals(reason, actual.getReason()); return actual;
	}
	private static @NonNull String fixture(@NonNull String name) {
		try (InputStream stream = KeyImportsTests.class.getResourceAsStream("/fixtures/" + name)) { return new String(java.util.Objects.requireNonNull(stream).readAllBytes(), StandardCharsets.US_ASCII); }
		catch (java.io.IOException failure) { throw new java.io.UncheckedIOException(failure); }
	}
	private static byte @NonNull [] der(@NonNull String pem) { return Base64.getMimeDecoder().decode(pem.substring(pem.indexOf("-----\n") + 6, pem.lastIndexOf("-----END"))); }
	private static @NonNull String armor(@NonNull String label, byte @NonNull [] der) { return "-----BEGIN " + label + "-----\n" + Base64.getEncoder().encodeToString(der) + "\n-----END " + label + "-----\n"; }
	private static @NonNull List<byte @NonNull []> children(byte @NonNull [] der) {
		Der.Element outer = Der.read(der, 0, der.length, 0x30); List<byte[]> children = new ArrayList<>(); int position = outer.getStart();
		while (position < outer.getEnd()) { Der.Element element = Der.read(der, position, outer.getEnd()); children.add(Arrays.copyOfRange(der, position, element.getEnd())); position = element.getEnd(); } return children;
	}
	private static byte @NonNull [] content(byte @NonNull [] tlv) { Der.Element element = Der.read(tlv, 0, tlv.length); return Arrays.copyOfRange(tlv, element.getStart(), element.getEnd()); }
	private static byte @NonNull [] replacePrivate(@NonNull List<byte @NonNull []> outer, byte @NonNull [] inner) { List<byte[]> changed = cloneFields(outer); changed.set(2, tlv(4, inner)); return tlv(0x30, concat(changed)); }
	private static @NonNull List<byte @NonNull []> cloneFields(@NonNull List<byte @NonNull []> input) { return new ArrayList<>(input.stream().map(byte[]::clone).toList()); }
	private static byte @NonNull [] pkcs8Rsa(byte @NonNull [] pkcs1) { return tlv(0x30, concat(tlv(2, new byte[] {0}), HexFormat.of().parseHex("300d06092a864886f70d0101010500"), tlv(4, pkcs1))); }
	private static byte @NonNull [] tlv(int tag, byte @NonNull [] content) { byte[] result = new byte[1 + Der.lengthOfLength(content.length) + content.length]; result[0] = (byte) tag; int start = Der.putLength(result, 1, content.length); System.arraycopy(content, 0, result, start, content.length); return result; }
	private static byte @NonNull [] concat(@NonNull List<byte @NonNull []> arrays) { return concat(arrays.toArray(byte[][]::new)); }
	private static byte @NonNull [] concat(byte @NonNull []@NonNull ... arrays) { int length = Arrays.stream(arrays).mapToInt(a -> a.length).sum(); byte[] result = new byte[length]; int position = 0; for (byte[] array : arrays) { System.arraycopy(array, 0, result, position, array.length); position += array.length; } return result; }
	private static byte @NonNull [] unsigned(@NonNull BigInteger value, int width) { byte[] encoded = value.toByteArray(), result = new byte[width]; int length = Math.min(encoded.length, width); System.arraycopy(encoded, encoded.length - length, result, width - length, length); return result; }
	private static void clear(byte @NonNull [] bytes) { Arrays.fill(bytes, (byte) 0); }
	private static boolean allZero(byte @Nullable [] bytes) { return bytes != null && Arrays.equals(bytes, new byte[bytes.length]); }
	private static void withProvider(@NonNull Executable operation) throws Exception {
		State.reset(); Provider provider = new ProbeProvider(); Security.insertProviderAt(provider, 1);
		try { operation.execute(); } catch (Exception failure) { throw failure; } catch (Throwable failure) { throw new AssertionError(failure); }
		finally { Security.removeProvider(provider.getName()); Thread.interrupted(); State.reset(); }
	}
	private static final class State {
		static int signs, verifies; static @NonNull String mode = "normal"; static byte @Nullable [] challengeReference, challengeCopy, signatureReference;
		static void reset() { signs = 0; verifies = 0; mode = "normal"; challengeReference = null; challengeCopy = null; signatureReference = null; }
	}
	public static final class ProbeProvider extends Provider {
		private static final long serialVersionUID = 1L;
		public ProbeProvider() { super("RevetsecKeyImportProbe", "1.0", "test-only independent signature probe"); put("Signature.SHA256withRSA", ProbeSignature.class.getName()); }
	}
	@SuppressWarnings("deprecation")
	public static final class ProbeSignature extends SignatureSpi {
		private final Signature delegate;
		public ProbeSignature() throws GeneralSecurityException { this.delegate = Signature.getInstance("SHA256withRSA", "SunRsaSign"); }
		@Override protected void engineInitVerify(@NonNull PublicKey key) throws InvalidKeyException { this.delegate.initVerify(key); }
		@Override protected void engineInitSign(@NonNull PrivateKey key) throws InvalidKeyException {
			if (State.mode.equals("slow-init")) pause(40);
			this.delegate.initSign(key instanceof SpyPrivate spy ? spy.underlying : key);
		}
		@Override protected void engineUpdate(byte value) throws SignatureException { this.delegate.update(value); }
		@Override protected void engineUpdate(byte @NonNull [] bytes, int offset, int length) throws SignatureException {
			State.challengeReference = bytes; State.challengeCopy = Arrays.copyOfRange(bytes, offset, offset + length); this.delegate.update(bytes, offset, length);
		}
		@Override protected byte @NonNull [] engineSign() throws SignatureException {
			++State.signs; if (State.mode.equals("throw")) throw new SignatureException(SENTINEL);
			byte[] result = this.delegate.sign(); if (State.mode.equals("bad-signature")) result[result.length - 1] ^= 1;
			State.signatureReference = result; if (State.mode.equals("interrupt")) Thread.currentThread().interrupt(); return result;
		}
		@Override protected boolean engineVerify(byte @NonNull [] signature) throws SignatureException { ++State.verifies; return this.delegate.verify(signature); }
		@Override protected void engineSetParameter(@NonNull String name, @NonNull Object value) { throw new UnsupportedOperationException(); }
		@Override protected @NonNull Object engineGetParameter(@NonNull String name) { throw new UnsupportedOperationException(); }
		@Override protected @Nullable AlgorithmParameters engineGetParameters() { return null; }
	}
	private static final class SpyPrivate implements PrivateKey {
		private static final long serialVersionUID = 1L; private final PrivateKey underlying; private int exports;
		private SpyPrivate(@NonNull PrivateKey underlying) { this.underlying = underlying; }
		@Override public @NonNull String getAlgorithm() { return "RSA"; }
		@Override public @NonNull String getFormat() { throw new AssertionError("private format not needed"); }
		@Override public byte @NonNull [] getEncoded() { ++this.exports; throw new AssertionError("private export forbidden"); }
	}
	private static final class EncodingPublic implements PublicKey {
		private static final long serialVersionUID = 1L; private final byte[] encoded; private final long pauseMillis; private int calls;
		private EncodingPublic(byte @NonNull [] encoded, long pauseMillis) { this.encoded = encoded; this.pauseMillis = pauseMillis; }
		@Override public @NonNull String getAlgorithm() { throw new AssertionError("public labels are not a key snapshot"); }
		@Override public @NonNull String getFormat() { return "X.509"; }
		@Override public byte @NonNull [] getEncoded() { ++this.calls; pause(this.pauseMillis); return this.calls == 1 ? this.encoded : new byte[0]; }
	}
	private static void pause(long millis) { try { Thread.sleep(millis); } catch (InterruptedException failure) { Thread.currentThread().interrupt(); } }
}
