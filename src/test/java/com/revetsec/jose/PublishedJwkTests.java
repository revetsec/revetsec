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

package com.revetsec.jose;

import com.revetsec.internal.crypto.EcCurve;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.testing.TestJwk.Fixture;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EdECPoint;
import java.security.spec.NamedParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class PublishedJwkTests {
	@Test
	void publishesEverySupportedAlgorithmAndRoundTripsThePublicMaterial() {
		for (JwsAlgorithm algorithm : List.of(JwsAlgorithm.RS256, JwsAlgorithm.RS384, JwsAlgorithm.RS512,
				JwsAlgorithm.PS256, JwsAlgorithm.PS384, JwsAlgorithm.PS512, JwsAlgorithm.ES256, JwsAlgorithm.ES384,
				JwsAlgorithm.ES512, JwsAlgorithm.ED25519, JwsAlgorithm.EDDSA)) {
			Fixture fixture = fixture(algorithm);
			PublishedJwk key = PublishedJwk.withPublicKey(fixture.getPublicKey()).keyId("published")
					.algorithm(algorithm).build();
			assertEquals(key.toJsonObject().toJson(), key.toJson());
			Jwk parsed = parse(key);
			assertEquals("published", parsed.getKeyId().orElseThrow());
			assertEquals(algorithm, parsed.getAlgorithm().orElseThrow());
			assertEquals(fixture.getKeyType(), parsed.getKeyType());
			assertEquals("sig", parsed.getUse().orElseThrow());
			assertEquals(parse(PublishedJwk.fromPublicKey(fixture.getPublicKey())).getThumbprintSha256(),
					parsed.getThumbprintSha256());
			assertFalse(key.toJsonObject().getMembers().containsKey("key_ops"));
			for (String secret : List.of("d", "p", "q", "dp", "dq", "qi", "oth", "k"))
				assertFalse(key.toJsonObject().getMembers().containsKey(secret));
		}
	}

	@Test
	void optionalMetadataIsAbsentByDefaultAndCanBeReplacedOrCleared() {
		PublishedJwk.Builder builder = PublishedJwk.withPublicKey(Fixture.IDP_SIGNING_RSA_2048.getPublicKey());
		PublishedJwk defaults = builder.build();
		assertTrue(defaults.getKeyId().isEmpty());
		assertTrue(defaults.getAlgorithm().isEmpty());
		assertEquals(Set.of("kty", "n", "e", "use"), defaults.toJsonObject().getMembers().keySet());
		PublishedJwk first = builder.keyId("first").algorithm(JwsAlgorithm.RS384)
				.certificateChain(List.of(Fixture.IDP_SIGNING_RSA_2048.getCertificate().orElseThrow())).build();
		PublishedJwk second = builder.keyId("second").algorithm(JwsAlgorithm.PS512).certificateChain(List.of()).build();
		PublishedJwk cleared = builder.keyId(null).algorithm(null).certificateChain(null).build();
		assertEquals("first", first.getKeyId().orElseThrow());
		assertEquals(JwsAlgorithm.RS384, first.getAlgorithm().orElseThrow());
		assertTrue(first.toJsonObject().getMembers().containsKey("x5c"));
		assertEquals("second", second.getKeyId().orElseThrow());
		assertEquals(JwsAlgorithm.PS512, second.getAlgorithm().orElseThrow());
		assertFalse(second.toJsonObject().getMembers().containsKey("x5c"));
		assertEquals(defaults.toJsonObject(), cleared.toJsonObject());
	}

	@Test
	void allIncompatibleAlgorithmsAreRejected() {
		for (Fixture fixture : List.of(Fixture.IDP_SIGNING_RSA_2048, Fixture.IDP_SIGNING_EC_P256,
				Fixture.IDP_SIGNING_EC_P384, Fixture.IDP_SIGNING_EC_P521, Fixture.ED25519)) {
			for (JwsAlgorithm algorithm : JwsAlgorithm.values()) {
				boolean compatible = switch (algorithm) {
					case RS256, RS384, RS512, PS256, PS384, PS512 -> fixture == Fixture.IDP_SIGNING_RSA_2048;
					case ES256 -> fixture == Fixture.IDP_SIGNING_EC_P256;
					case ES384 -> fixture == Fixture.IDP_SIGNING_EC_P384;
					case ES512 -> fixture == Fixture.IDP_SIGNING_EC_P521;
					case ED25519, EDDSA -> fixture == Fixture.ED25519;
					default -> false;
				};
				if (!compatible)
					assertThrows(IllegalArgumentException.class,
							() -> PublishedJwk.withPublicKey(fixture.getPublicKey()).algorithm(algorithm));
			}
		}
	}

	@SuppressWarnings("NullAway") // Required input rejection is intentional.
	@Test
	void publicKeyIsRequiredAndIdentifiersUseExistingBounds() {
		assertThrows(NullPointerException.class, () -> PublishedJwk.withPublicKey(null));
		assertThrows(NullPointerException.class, () -> PublishedJwk.fromPublicKey(null));
		for (String invalid : List.of("", "x".repeat(257), "\ud800", "\udc00"))
			assertThrows(IllegalArgumentException.class,
					() -> PublishedJwk.withPublicKey(Fixture.IDP_SIGNING_RSA_2048.getPublicKey()).keyId(invalid));
		for (String valid : List.of("x", "x".repeat(256), "😀".repeat(128), "\u0000"))
			assertEquals(valid, PublishedJwk.withPublicKey(Fixture.IDP_SIGNING_RSA_2048.getPublicKey())
					.keyId(valid).build().getKeyId().orElseThrow());
	}

	@Test
	void copiesPublicParametersBeforeReturningTheBuilderAndNeverReadsKeyEncoding() {
		MutableRsa key = new MutableRsa((RSAPublicKey) Fixture.IDP_SIGNING_RSA_2048.getPublicKey());
		PublishedJwk expected = PublishedJwk.fromPublicKey(key);
		PublishedJwk.Builder builder = PublishedJwk.withPublicKey(key);
		key.modulus = BigInteger.ONE;
		key.exponent = BigInteger.valueOf(3);
		assertEquals(expected.toJsonObject(), builder.build().toJsonObject());
		assertThrows(IllegalArgumentException.class, () -> PublishedJwk.fromPublicKey(key));
	}

	@Test
	void refusesWeakMalformedAndUnsupportedKeys() throws Exception {
		assertThrows(IllegalArgumentException.class,
				() -> PublishedJwk.fromPublicKey(Fixture.NEGATIVE_RSA_1024.getPublicKey()));
		MutableRsa rsa = new MutableRsa((RSAPublicKey) Fixture.IDP_SIGNING_RSA_2048.getPublicKey());
		rsa.exponent = BigInteger.valueOf(3);
		assertThrows(IllegalArgumentException.class, () -> PublishedJwk.fromPublicKey(rsa));
		rsa.exponent = BigInteger.valueOf(65_537);
		rsa.modulus = rsa.modulus.clearBit(0);
		assertThrows(IllegalArgumentException.class, () -> PublishedJwk.fromPublicKey(rsa));
		rsa.modulus = BigInteger.ONE.shiftLeft(16_384).add(BigInteger.ONE);
		assertThrows(IllegalArgumentException.class, () -> PublishedJwk.fromPublicKey(rsa));
		assertThrows(IllegalArgumentException.class, () -> PublishedJwk.fromPublicKey(new InvalidEc()));
		assertThrows(IllegalArgumentException.class, () -> PublishedJwk.fromPublicKey(new InvalidEd()));
		PublicKey ed448 = KeyPairGenerator.getInstance("Ed448").generateKeyPair().getPublic();
		assertThrows(IllegalArgumentException.class, () -> PublishedJwk.fromPublicKey(ed448));
		PublicKey dsa = KeyPairGenerator.getInstance("DSA").generateKeyPair().getPublic();
		assertThrows(IllegalArgumentException.class, () -> PublishedJwk.fromPublicKey(dsa));
	}

	@Test
	void certificateMetadataUsesStandardBase64AndBothDerivedThumbprints() throws Exception {
		for (Fixture fixture : List.of(Fixture.IDP_SIGNING_RSA_2048, Fixture.IDP_SIGNING_EC_P256,
				Fixture.IDP_SIGNING_EC_P384, Fixture.IDP_SIGNING_EC_P521)) {
			X509Certificate certificate = fixture.getCertificate().orElseThrow();
			PublishedJwk key = PublishedJwk.withPublicKey(fixture.getPublicKey())
					.certificateChain(List.of(certificate)).build();
			JsonObject json = key.toJsonObject();
			JsonArray chain = assertInstanceOf(JsonArray.class, json.getMembers().get("x5c"));
			assertEquals(List.of(JsonString.fromValue(Base64.getEncoder().encodeToString(certificate.getEncoded()))), chain.getElements());
			assertEquals(digest("SHA-1", certificate.getEncoded()), string(json, "x5t"));
			assertEquals(digest("SHA-256", certificate.getEncoded()), string(json, "x5t#S256"));
			assertEquals(parse(PublishedJwk.fromPublicKey(fixture.getPublicKey())).getThumbprintSha256(),
					parse(key).getThumbprintSha256());
		}
	}

	@Test
	void snapshotsCertificateObjectsAndCollectionsAtSetterTime() throws Exception {
		byte[] encoded = Fixture.IDP_SIGNING_RSA_2048.getCertificate().orElseThrow().getEncoded();
		EncodedCertificate certificate = new EncodedCertificate(encoded);
		List<X509Certificate> chain = new ArrayList<>(List.of(certificate));
		PublishedJwk.Builder builder = PublishedJwk.withPublicKey(Fixture.IDP_SIGNING_RSA_2048.getPublicKey())
				.certificateChain(chain);
		PublishedJwk expected = builder.build();
		Arrays.fill(encoded, (byte) 0);
		chain.clear();
		assertEquals(expected.toJsonObject(), builder.build().toJsonObject());
		assertEquals(1, parse(builder.build()).getUse().stream().count());
	}

	@Test
	void acceptsAnOrderedChainAndRejectsBrokenSignaturesAndWrongOrder() throws Exception {
		// These TEST ONLY fixtures use the existing IdP and SP signing keys; no new private keys are needed.
		X509Certificate leaf = certificate("publisher-leaf.pem");
		X509Certificate root = certificate("publisher-root.pem");
		PublishedJwk key = PublishedJwk.withPublicKey(leaf.getPublicKey()).algorithm(JwsAlgorithm.RS384)
				.certificateChain(List.of(leaf, root)).build();
		assertEquals(2, assertInstanceOf(JsonArray.class, key.toJsonObject().getMembers().get("x5c")).getElements().size());
		assertEquals(JwsAlgorithm.RS384, parse(key).getAlgorithm().orElseThrow());
		assertThrows(IllegalArgumentException.class, () -> PublishedJwk.withPublicKey(leaf.getPublicKey())
				.certificateChain(List.of(root, leaf)));
		byte[] damagedSignature = leaf.getEncoded();
		damagedSignature[damagedSignature.length - 1] ^= 1;
		assertThrows(IllegalArgumentException.class, () -> PublishedJwk.withPublicKey(leaf.getPublicKey())
				.certificateChain(List.of(new EncodedCertificate(damagedSignature), root)));
	}

	@Test
	void rejectsMismatchedMalformedOversizedDuplicateAndNonSigningCertificates() throws Exception {
		X509Certificate cert = Fixture.IDP_SIGNING_RSA_2048.getCertificate().orElseThrow();
		PublishedJwk.Builder builder = PublishedJwk.withPublicKey(cert.getPublicKey());
		assertThrows(IllegalArgumentException.class, () -> builder.certificateChain(List.of(
				Fixture.SP_SIGNING_RSA_2048.getCertificate().orElseThrow())));
		assertThrows(IllegalArgumentException.class, () -> builder.certificateChain(List.of(cert, cert)));
		assertThrows(IllegalArgumentException.class, () -> builder.certificateChain(java.util.Collections.nCopies(17, cert)));
		for (byte[] invalid : List.of(new byte[0], new byte[65_537], new byte[]{0x30, 0x01, 0x00},
				Arrays.copyOf(cert.getEncoded(), cert.getEncoded().length + 1)))
			assertThrows(IllegalArgumentException.class, () -> builder.certificateChain(List.of(new EncodedCertificate(invalid))));
		assertThrows(IllegalArgumentException.class, () -> PublishedJwk.withPublicKey(
				Fixture.SP_ENCRYPTION_RSA_2048.getPublicKey()).certificateChain(
				List.of(Fixture.SP_ENCRYPTION_RSA_2048.getCertificate().orElseThrow())));
		assertThrows(IllegalArgumentException.class, () -> builder.certificateChain(List.of(cert,
				Fixture.SP_SIGNING_RSA_2048.getCertificate().orElseThrow())));
	}

	@Test
	void descriptionsAndFailuresDoNotExposeConfiguredValues() {
		String identifier = "TEST-ONLY-secret-key-identifier";
		PublishedJwk key = PublishedJwk.withPublicKey(Fixture.IDP_SIGNING_RSA_2048.getPublicKey())
				.keyId(identifier).build();
		assertFalse(key.toString().contains(identifier));
		IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
				() -> PublishedJwk.withPublicKey(Fixture.IDP_SIGNING_RSA_2048.getPublicKey()).keyId(identifier.repeat(20)));
		assertFalse(error.toString().contains(identifier));
		assertEquals(null, error.getCause());
	}

	private static @NonNull Fixture fixture(@NonNull JwsAlgorithm algorithm) {
		return switch (algorithm) {
			case ES256 -> Fixture.IDP_SIGNING_EC_P256;
			case ES384 -> Fixture.IDP_SIGNING_EC_P384;
			case ES512 -> Fixture.IDP_SIGNING_EC_P521;
			case ED25519, EDDSA -> Fixture.ED25519;
			default -> Fixture.IDP_SIGNING_RSA_2048;
		};
	}

	private static @NonNull Jwk parse(@NonNull PublishedJwk key) {
		String document = "{\"keys\":[" + key.toJson() + "]}";
		JwksParseResult.Succeeded result = assertInstanceOf(JwksParseResult.Succeeded.class,
				Jwks.fromJsonResult(document));
		assertEquals(1, result.getJwks().getKeys().size());
		return result.getJwks().getKeys().get(0);
	}

	private static @NonNull String string(@NonNull JsonObject object, @NonNull String name) {
		return assertInstanceOf(JsonString.class, object.getMembers().get(name)).getValue();
	}

	private static @NonNull String digest(@NonNull String algorithm, byte @NonNull [] bytes) throws Exception {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance(algorithm).digest(bytes));
	}

	private static @NonNull X509Certificate certificate(@NonNull String name) throws Exception {
		try (InputStream stream = requireNonNull(PublishedJwkTests.class.getResourceAsStream("/fixtures/jwks/" + name))) {
			return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(stream);
		}
	}

	private static final class MutableRsa implements RSAPublicKey {
		private static final long serialVersionUID = 1L;
		private @NonNull BigInteger modulus;
		private @NonNull BigInteger exponent;
		private MutableRsa(@NonNull RSAPublicKey key) { this.modulus = key.getModulus(); this.exponent = key.getPublicExponent(); }
		@Override public @NonNull BigInteger getModulus() { return this.modulus; }
		@Override public @NonNull BigInteger getPublicExponent() { return this.exponent; }
		@Override public @NonNull String getAlgorithm() { return "RSA"; }
		@Override public @Nullable String getFormat() { throw new AssertionError("No key format read"); }
		@Override public byte @Nullable [] getEncoded() { throw new AssertionError("No key encoding read"); }
	}

	private static final class InvalidEc implements ECPublicKey {
		private static final long serialVersionUID = 1L;
		@Override public @NonNull ECPoint getW() { return ECPoint.POINT_INFINITY; }
		@Override public @NonNull ECParameterSpec getParams() { return EcCurve.P_256.getParameterSpec(); }
		@Override public @NonNull String getAlgorithm() { return "EC"; }
		@Override public @Nullable String getFormat() { return null; }
		@Override public byte @Nullable [] getEncoded() { throw new AssertionError("No key encoding read"); }
	}

	private static final class InvalidEd implements EdECPublicKey {
		private static final long serialVersionUID = 1L;
		@Override public @NonNull EdECPoint getPoint() { return new EdECPoint(false, BigInteger.ONE); }
		@Override public @NonNull NamedParameterSpec getParams() { return NamedParameterSpec.ED25519; }
		@Override public @NonNull String getAlgorithm() { return "Ed25519"; }
		@Override public @Nullable String getFormat() { return null; }
		@Override public byte @Nullable [] getEncoded() { throw new AssertionError("No key encoding read"); }
	}

	/** Only DER is authoritative: no metadata from the caller's certificate object may be used. */
	@SuppressWarnings("deprecation")
	private static final class EncodedCertificate extends X509Certificate {
		private static final long serialVersionUID = 1L;
		private final byte @NonNull [] encoded;
		private EncodedCertificate(byte @NonNull [] encoded) { this.encoded = encoded; }
		@Override public byte @NonNull [] getEncoded() { return this.encoded; }
		@Override public void checkValidity() { throw new AssertionError(); }
		@Override public void checkValidity(@NonNull Date date) { throw new AssertionError(); }
		@Override public int getVersion() { throw new AssertionError(); }
		@Override public @NonNull BigInteger getSerialNumber() { throw new AssertionError(); }
		@Override public @NonNull Principal getIssuerDN() { throw new AssertionError(); }
		@Override public @NonNull Principal getSubjectDN() { throw new AssertionError(); }
		@Override public @NonNull Date getNotBefore() { throw new AssertionError(); }
		@Override public @NonNull Date getNotAfter() { throw new AssertionError(); }
		@Override public byte @NonNull [] getTBSCertificate() { throw new AssertionError(); }
		@Override public byte @NonNull [] getSignature() { throw new AssertionError(); }
		@Override public @NonNull String getSigAlgName() { throw new AssertionError(); }
		@Override public @NonNull String getSigAlgOID() { throw new AssertionError(); }
		@Override public byte @Nullable [] getSigAlgParams() { throw new AssertionError(); }
		@Override public boolean @Nullable [] getIssuerUniqueID() { throw new AssertionError(); }
		@Override public boolean @Nullable [] getSubjectUniqueID() { throw new AssertionError(); }
		@Override public boolean @Nullable [] getKeyUsage() { throw new AssertionError(); }
		@Override public int getBasicConstraints() { throw new AssertionError(); }
		@Override public void verify(@NonNull PublicKey key) { throw new AssertionError(); }
		@Override public void verify(@NonNull PublicKey key, @NonNull String provider) { throw new AssertionError(); }
		@Override public @NonNull PublicKey getPublicKey() { throw new AssertionError(); }
		@Override public @NonNull String toString() { return "EncodedCertificate{TEST ONLY}"; }
		@Override public @Nullable Set<@NonNull String> getCriticalExtensionOIDs() { throw new AssertionError(); }
		@Override public @Nullable Set<@NonNull String> getNonCriticalExtensionOIDs() { throw new AssertionError(); }
		@Override public byte @Nullable [] getExtensionValue(@NonNull String oid) { throw new AssertionError(); }
		@Override public boolean hasUnsupportedCriticalExtension() { throw new AssertionError(); }
	}
}
