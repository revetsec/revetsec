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

import org.jspecify.annotations.NonNull;

import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Tests {@link TestJsonWebKeys}: each fixture's JWK rebuilds the same JDK key at the encodings RFC 7518 sections 6.2
 * and 6.3 and RFC 8037 section 2 require, and each malformed or weak key has exactly the defect it names (plan M2-7,
 * exit criterion 7): a 31-octet EC {@code x}, a leading-zero {@code n}, an even {@code e}, a point off its curve, the
 * eight Ed25519 small-order points, and a ROCA fingerprint (CVE-2017-15361). OKP keys on Ed448, X25519 and X448
 * carry the JDK's raw key bytes (RFC 8037 section 2), and public-key PEM text matches OpenSSL's. The checks here use
 * arithmetic and JDK calls of their own, never the helper's.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class TestJsonWebKeysTests {
	private static final byte[] MESSAGE = "Revetsec TEST ONLY message".getBytes(StandardCharsets.US_ASCII);
	private static final String ED25519_PKCS8_PREFIX = "302e020100300506032b657004220420";
	private static final String ED25519_SPKI_PREFIX = "302a300506032b6570032100";

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> everyFixtureKeyPairSignsAndVerifiesWithTheJdk() {
		return Arrays.stream(Fixture.values()).map(fixture -> DynamicTest.dynamicTest(fixture.name(), () -> {
			KeyPair keyPair = fixture.getKeyPair();
			Assertions.assertTrue(jdkSignsAndVerifies(keyPair));
			Assertions.assertEquals(fixture == Fixture.ED25519, fixture.getCertificate().isEmpty());
			Assertions.assertEquals(fixture.getKeyType(), switch (keyPair.getPublic().getAlgorithm()) {
				case "RSA" -> "RSA";
				case "EC" -> "EC";
				default -> "OKP";
			});
		}));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> publicJwksRebuildTheSameKeyAtTheRequiredEncodings() {
		return Arrays.stream(Fixture.values()).map(fixture -> DynamicTest.dynamicTest(fixture.name(), () -> {
			PublicKey publicKey = fixture.getPublicKey();
			JsonObject jwk = parse(TestJsonWebKeys.withFixture(fixture).toJson());

			switch (fixture.getKeyType()) {
				case "RSA" -> {
					Assertions.assertEquals(List.of("kty", "n", "e"), List.copyOf(jwk.getMembers().keySet()));
					byte[] n = decodeMember(jwk, "n");
					Assertions.assertNotEquals(0, n[0], "Base64urlUInt is minimal (RFC 7518 section 2)");
					Assertions.assertEquals("AQAB", string(jwk, "e"));
					PublicKey rebuilt = KeyFactory.getInstance("RSA").generatePublic(
							new RSAPublicKeySpec(new BigInteger(1, n), new BigInteger(1, decodeMember(jwk, "e"))));
					Assertions.assertEquals(publicKey, rebuilt);
				}
				case "EC" -> {
					Assertions.assertEquals(List.of("kty", "crv", "x", "y"), List.copyOf(jwk.getMembers().keySet()));
					ECParameterSpec parameters = ((ECPublicKey) publicKey).getParams();
					int octets = (parameters.getCurve().getField().getFieldSize() + 7) / 8;
					Assertions.assertEquals(Map.of(32, "P-256", 48, "P-384", 66, "P-521").get(octets),
							string(jwk, "crv"));
					byte[] x = decodeMember(jwk, "x");
					byte[] y = decodeMember(jwk, "y");
					Assertions.assertEquals(octets, x.length, "fixed-length coordinates (RFC 7518 section 6.2.1.2)");
					Assertions.assertEquals(octets, y.length);
					PublicKey rebuilt = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(
							new ECPoint(new BigInteger(1, x), new BigInteger(1, y)), parameters));
					Assertions.assertEquals(publicKey, rebuilt);
				}
				default -> {
					Assertions.assertEquals(List.of("kty", "crv", "x"), List.copyOf(jwk.getMembers().keySet()));
					Assertions.assertEquals("OKP", string(jwk, "kty"));
					Assertions.assertEquals("Ed25519", string(jwk, "crv"));
					byte[] encoded = publicKey.getEncoded();
					Assertions.assertArrayEquals(Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length),
							decodeMember(jwk, "x"), "x is the raw public key (RFC 8037 section 2)");
				}
			}
		}));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> privateJwksCarryMembersThatRebuildTheSamePrivateKey() {
		return Arrays.stream(Fixture.values()).map(fixture -> DynamicTest.dynamicTest(fixture.name(), () -> {
			PrivateKey privateKey = fixture.getPrivateKey();
			JsonObject jwk = parse(TestJsonWebKeys.withFixture(fixture).includePrivateMembers(true).kid("k").toJson());

			switch (fixture.getKeyType()) {
				case "RSA" -> {
					Assertions.assertEquals(List.of("kty", "n", "e", "d", "p", "q", "dp", "dq", "qi", "kid"),
							List.copyOf(jwk.getMembers().keySet()));
					PrivateKey rebuilt = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateCrtKeySpec(
							integer(jwk, "n"), integer(jwk, "e"), integer(jwk, "d"), integer(jwk, "p"),
							integer(jwk, "q"), integer(jwk, "dp"), integer(jwk, "dq"), integer(jwk, "qi")));
					RSAPrivateCrtKey expected = (RSAPrivateCrtKey) privateKey;
					RSAPrivateCrtKey actual = (RSAPrivateCrtKey) rebuilt;
					Assertions.assertEquals(expected.getModulus(), actual.getModulus());
					Assertions.assertEquals(expected.getPrivateExponent(), actual.getPrivateExponent());
					Assertions.assertEquals(expected.getPrimeP(), actual.getPrimeP());
					Assertions.assertEquals(expected.getPrimeQ(), actual.getPrimeQ());
					Assertions.assertEquals(expected.getCrtCoefficient(), actual.getCrtCoefficient());
					Assertions.assertTrue(jdkSignsAndVerifies(new KeyPair(fixture.getPublicKey(), rebuilt)));
				}
				case "EC" -> {
					Assertions.assertEquals(List.of("kty", "crv", "x", "y", "d", "kid"),
							List.copyOf(jwk.getMembers().keySet()));
					ECPrivateKey ec = (ECPrivateKey) privateKey;
					byte[] d = decodeMember(jwk, "d");
					Assertions.assertEquals((ec.getParams().getOrder().bitLength() + 7) / 8, d.length,
							"d has the order's length (RFC 7518 section 6.2.2.1)");
					Assertions.assertEquals(ec.getS(), new BigInteger(1, d));
				}
				default -> {
					Assertions.assertEquals(List.of("kty", "crv", "x", "d", "kid"),
							List.copyOf(jwk.getMembers().keySet()));
					byte[] seed = decodeMember(jwk, "d");
					PrivateKey rebuilt = KeyFactory.getInstance("Ed25519").generatePrivate(
							new PKCS8EncodedKeySpec(concat(HexFormat.of().parseHex(ED25519_PKCS8_PREFIX), seed)));
					Assertions.assertTrue(jdkSignsAndVerifies(new KeyPair(fixture.getPublicKey(), rebuilt)));
				}
			}
		}));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> x5cHoldsTheFixtureCertificateInStandardBase64() {
		return Arrays.stream(Fixture.values()).filter(fixture -> fixture != Fixture.ED25519)
				.map(fixture -> DynamicTest.dynamicTest(fixture.name(), () -> {
					X509Certificate certificate = fixture.getCertificate().orElseThrow();
					JsonObject jwk = parse(TestJsonWebKeys.withFixture(fixture).x5c(List.of(certificate)).toJson());
					List<JsonValue> chain = ((JsonArray) jwk.find("x5c").orElseThrow()).getElements();

					Assertions.assertEquals(1, chain.size());
					byte[] der = Base64.getDecoder().decode(((JsonString) chain.get(0)).getValue());
					X509Certificate decoded = (X509Certificate) CertificateFactory.getInstance("X.509")
							.generateCertificate(new ByteArrayInputStream(der));
					Assertions.assertEquals(certificate, decoded);
					Assertions.assertEquals(fixture.getPublicKey(), decoded.getPublicKey());
				}));
	}

	@Test
	void optionalMembersFollowTheKeyMembersAndOverridesReplaceInPlace() throws Exception {
		String json = TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P256)
				.issuer("https://login.microsoftonline.com/{tenantid}/v2.0")
				.x5c(List.of(Fixture.IDP_SIGNING_EC_P256.getCertificate().orElseThrow()))
				.alg("ES256")
				.keyOps(List.of("verify"))
				.use("sig")
				.kid("ec-1")
				.member("crv", "\"P-384\"")
				.member("extra", "null")
				.withoutMember("y")
				.member("issuer", "123")
				.toJson();
		JsonObject jwk = parse(json);

		Assertions.assertEquals(List.of("kty", "crv", "x", "kid", "use", "key_ops", "alg", "x5c", "issuer", "extra"),
				List.copyOf(jwk.getMembers().keySet()));
		Assertions.assertEquals("P-384", string(jwk, "crv"), "an override replaces a generated member in place");
		Assertions.assertTrue(json.contains("\"issuer\":123,\"extra\":null"), json);
		Assertions.assertTrue(json.contains("\"key_ops\":[\"verify\"]"), json);

		String restored = TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P256).withoutMember("y")
				.member("y", "\"AA\"").toJson();
		Assertions.assertEquals(List.of("kty", "crv", "x", "y"), List.copyOf(parse(restored).getMembers().keySet()),
				"the last call for a name wins, in the generated member's place");
		Assertions.assertEquals("AA", string(parse(restored), "y"));
		Assertions.assertFalse(parse(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P256).kid("k").kid(null)
				.toJson()).getMembers().containsKey("kid"), "null clears a setter");
	}

	@Test
	void includePrivateMembersNeedsAPrivateKey() {
		TestJsonWebKeys.Builder builder = TestJsonWebKeys.withPublicKey(Fixture.IDP_SIGNING_RSA_2048.getPublicKey())
				.includePrivateMembers(true);
		Assertions.assertThrows(IllegalStateException.class, builder::toJson);
		Assertions.assertFalse(builder.includePrivateMembers(null).toJson().contains("\"d\""));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> publicKeyPemMatchesWhatOpenSslWroteForTheSameKey() throws Exception {
		// The fixtures/pem public keys are `openssl pkey -pubout` of these fixtures (that directory's README). The
		// RSA and EC keys come from their certificates; the Ed25519 key, whose fixture reads ed25519-public.pem
		// itself, is derived here from its private seed instead, so the comparison is not circular.
		Map<String, PublicKey> openSslFiles = new LinkedHashMap<>();
		openSslFiles.put("rsa-2048-public.pem", Fixture.IDP_SIGNING_RSA_2048.getPublicKey());
		openSslFiles.put("ec-p256-public.pem", Fixture.IDP_SIGNING_EC_P256.getPublicKey());
		openSslFiles.put("ed25519-public.pem", ed25519KeyPairFromFixtureSeed().getPublic());
		return openSslFiles.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () -> {
			Assertions.assertEquals(resourceText("/fixtures/pem/" + entry.getKey()),
					TestJsonWebKeys.publicKeyPem(entry.getValue()));
		}));
	}

	@Test
	void theEd25519FixturePublicKeyIsTheOneItsPrivateSeedDerives() throws Exception {
		// RFC 8032 section 5.1.5: the public key follows from the 32-octet seed, which the JDK derives here.
		Assertions.assertEquals(Fixture.ED25519.getPublicKey(), ed25519KeyPairFromFixtureSeed().getPublic());
	}

	@Test
	void keySetsWrapTheKeysInOrder() throws Exception {
		String first = TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("a").toJson();
		String second = TestJsonWebKeys.withFixture(Fixture.ED25519).kid("b").toJson();

		Assertions.assertEquals("{\"keys\":[" + first + "," + second + "]}",
				TestJsonWebKeys.keySet(List.of(first, second)));
		Assertions.assertEquals("{\"keys\":[]}", TestJsonWebKeys.keySet(List.of()));
		Assertions.assertEquals("{\"keys\":[" + first + "]}",
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("a").toKeySetJson());
		Assertions.assertEquals(2, ((JsonArray) parse(TestJsonWebKeys.keySet(List.of(first, second))).find("keys")
				.orElseThrow()).getElements().size());
	}

	@Test
	void integersAreMinimalBase64UrlUIntAndCoordinatesFixedLength() {
		// RFC 7518 section 2: zero is a single zero octet; otherwise no leading zero octets.
		Assertions.assertEquals("AA", TestJsonWebKeys.base64UrlUInt(BigInteger.ZERO));
		Assertions.assertEquals("AQAB", TestJsonWebKeys.base64UrlUInt(TestJsonWebKeys.F4));
		Assertions.assertEquals("_w", TestJsonWebKeys.base64UrlUInt(BigInteger.valueOf(255)));
		Assertions.assertEquals("AQA", TestJsonWebKeys.base64UrlUInt(BigInteger.valueOf(256)));
		Assertions.assertEquals("AAAAAQ", TestJsonWebKeys.base64UrlFixedLength(BigInteger.ONE, 4));
		Assertions.assertEquals("AAAAAA", TestJsonWebKeys.base64UrlFixedLength(BigInteger.ZERO, 4));
		Assertions.assertArrayEquals(new byte[]{1, 0}, TestJsonWebKeys.unsignedBytes(BigInteger.valueOf(256)));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> TestJsonWebKeys.fixedLengthBytes(BigInteger.valueOf(256), 1));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> TestJsonWebKeys.unsignedBytes(BigInteger.ONE.negate()));
	}

	@Test
	void ecWithShortXWritesTheLeadingZeroCoordinateInThirtyOneOctets() throws Exception {
		// Plan M2 exit criterion 7: a 31-byte EC x (RFC 7518 section 6.2.1.2 requires the full 32).
		KeyPair keyPair = TestJsonWebKeys.ecKeyPairWithLeadingZeroX();
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		BigInteger x = publicKey.getW().getAffineX();
		byte[] canonical = decodeMember(parse(TestJsonWebKeys.withKeyPair(keyPair).toJson()), "x");
		JsonObject shortX = parse(TestJsonWebKeys.ecWithShortX().toJson());

		Assertions.assertTrue(x.bitLength() <= 248, "x has a leading zero octet");
		Assertions.assertEquals(32, canonical.length);
		Assertions.assertEquals(0, canonical[0]);
		Assertions.assertEquals(31, decodeMember(shortX, "x").length);
		Assertions.assertEquals(x, new BigInteger(1, decodeMember(shortX, "x")));
		Assertions.assertEquals(32, decodeMember(shortX, "y").length);
		Assertions.assertTrue(onWeierstrassCurve(publicKey.getParams(), x, publicKey.getW().getAffineY()));
		Assertions.assertTrue(jdkSignsAndVerifies(keyPair), "the private scalar matches the public point");
		BigInteger scalar = ((ECPrivateKey) keyPair.getPrivate()).getS();
		Assertions.assertTrue(scalar.bitLength() > 128, "not a toy scalar");
		Assertions.assertArrayEquals(keyPair.getPublic().getEncoded(),
				TestJsonWebKeys.ecKeyPairWithLeadingZeroX().getPublic().getEncoded(), "deterministic");
	}

	@Test
	void rsaWithLeadingZeroModulusPrefixesOneZeroOctetToTheSameModulus() throws Exception {
		BigInteger modulus = ((RSAPublicKey) Fixture.IDP_SIGNING_RSA_2048.getPublicKey()).getModulus();
		byte[] n = decodeMember(parse(TestJsonWebKeys.rsaWithLeadingZeroModulus().toJson()), "n");

		Assertions.assertEquals(257, n.length);
		Assertions.assertEquals(0, n[0]);
		Assertions.assertEquals(modulus, new BigInteger(1, n));
	}

	@Test
	void rsaExponentVariantsWriteMinimalExponents() throws Exception {
		Assertions.assertEquals(BigInteger.valueOf(65_538),
				integer(parse(TestJsonWebKeys.rsaWithEvenExponent().toJson()), "e"));
		Assertions.assertEquals("Aw",
				string(parse(TestJsonWebKeys.rsaWithExponent(BigInteger.valueOf(3)).toJson()), "e"));
		Assertions.assertEquals("AQAAAAA",
				string(parse(TestJsonWebKeys.rsaWithExponent(BigInteger.TWO.pow(32)).toJson()), "e"));
		Assertions.assertEquals("AQ", string(parse(TestJsonWebKeys.rsaWithExponent(BigInteger.ONE).toJson()), "e"));
	}

	@Test
	void ecKeysAreNamedOnlyForTheThreeNistCurvesMatchedOnEveryParameter() throws Exception {
		// RFC 7518 section 6.2.1.1 names P-256, P-384 and P-521. secp256k1 (SEC 2 section 2.4.1) also has a 256-bit
		// field, and the JDK's KeyFactory accepts its points, so a field size alone would label it P-256.
		BigInteger p = new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);
		BigInteger n = new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
		ECPoint generator = new ECPoint(
				new BigInteger("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16),
				new BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16));
		ECParameterSpec secp256k1 = new ECParameterSpec(
				new EllipticCurve(new ECFieldFp(p), BigInteger.ZERO, BigInteger.valueOf(7)), generator, n, 1);
		PublicKey secp256k1Key = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(generator, secp256k1));

		Assertions.assertEquals(256, ((ECPublicKey) secp256k1Key).getParams().getCurve().getField().getFieldSize());
		Assertions.assertThrows(IllegalArgumentException.class, () -> TestJsonWebKeys.withPublicKey(secp256k1Key));

		// The same P-256 values spelled out as explicit parameters still name P-256: the match is by value.
		ECPublicKey p256 = (ECPublicKey) Fixture.IDP_SIGNING_EC_P256.getPublicKey();
		ECParameterSpec named = p256.getParams();
		ECParameterSpec explicit = new ECParameterSpec(new EllipticCurve(
				new ECFieldFp(((ECFieldFp) named.getCurve().getField()).getP()), named.getCurve().getA(),
				named.getCurve().getB()), named.getGenerator(), named.getOrder(), named.getCofactor());
		PublicKey explicitKey = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(p256.getW(), explicit));
		Assertions.assertEquals(TestJsonWebKeys.withPublicKey(p256).toJson(),
				TestJsonWebKeys.withPublicKey(explicitKey).toJson());
	}

	@Test
	void isOnCurveRejectsCoordinatesOutsideTheField() {
		// SEC 1 section 3.2.2.1: 0 <= x, y < p. Adding p leaves the curve equation true mod p, so only the range check
		// rejects it.
		ECPublicKey publicKey = (ECPublicKey) Fixture.IDP_SIGNING_EC_P256.getPublicKey();
		ECParameterSpec parameters = publicKey.getParams();
		BigInteger p = ((ECFieldFp) parameters.getCurve().getField()).getP();
		BigInteger x = publicKey.getW().getAffineX();
		BigInteger y = publicKey.getW().getAffineY();

		Assertions.assertTrue(TestJsonWebKeys.isOnCurve(parameters, x, y));
		Assertions.assertTrue(onWeierstrassCurve(parameters, x.add(p), y), "the equation alone holds mod p");
		Assertions.assertFalse(TestJsonWebKeys.isOnCurve(parameters, x.add(p), y));
		Assertions.assertFalse(TestJsonWebKeys.isOnCurve(parameters, x, y.add(p)));
		Assertions.assertFalse(TestJsonWebKeys.isOnCurve(parameters, x.subtract(p), y));
		Assertions.assertFalse(TestJsonWebKeys.isOnCurve(parameters, x, y.subtract(p)));
	}

	@Test
	void ecOffCurveMovesTheFixturePointOffP256() throws Exception {
		ECPublicKey publicKey = (ECPublicKey) Fixture.IDP_SIGNING_EC_P256.getPublicKey();
		JsonObject jwk = parse(TestJsonWebKeys.ecOffCurve().toJson());
		BigInteger x = new BigInteger(1, decodeMember(jwk, "x"));
		BigInteger y = new BigInteger(1, decodeMember(jwk, "y"));

		Assertions.assertEquals(32, decodeMember(jwk, "y").length);
		Assertions.assertEquals(publicKey.getW().getAffineX(), x);
		Assertions.assertTrue(onWeierstrassCurve(publicKey.getParams(), x, publicKey.getW().getAffineY()));
		Assertions.assertFalse(onWeierstrassCurve(publicKey.getParams(), x, y), "(x, y + 1) is off the curve");
		Assertions.assertFalse(TestJsonWebKeys.isOnCurve(publicKey.getParams(), x, y));
		Assertions.assertTrue(TestJsonWebKeys.isOnCurve(publicKey.getParams(), x, publicKey.getW().getAffineY()));
	}

	@Test
	void theEightSmallOrderEd25519PointsAreDistinctCurvePointsOfOrderDividingEight() throws Exception {
		// RFC 8032 section 5.1: the cofactor is 8. The list is derived from the curve, not typed in (plan M2-7).
		List<String> encodings = TestJsonWebKeys.ed25519SmallOrderPublicKeys();
		BigInteger p = TestJsonWebKeys.ED25519_FIELD_PRIME;

		Assertions.assertEquals(8, encodings.size());
		Assertions.assertEquals(8, new HashSet<>(encodings).size());
		byte[] identity = new byte[32];
		identity[0] = 1;
		Assertions.assertEquals(TestJws.base64Url(identity), encodings.get(0), "the identity, y = 1");
		Assertions.assertEquals(encodings.get(0), string(parse(TestJsonWebKeys.ed25519SmallOrder().toJson()), "x"));
		Set<BigInteger> ys = new HashSet<>();
		int orderEight = 0;
		for (String encoding : encodings) {
			BigInteger[] point = decodePoint(encoding);
			Assertions.assertTrue(onEdwardsCurve(point), encoding);
			BigInteger[] twice = edwardsDouble(point);
			BigInteger[] fourTimes = edwardsDouble(twice);
			Assertions.assertTrue(isIdentity(edwardsDouble(fourTimes)), "8P is the identity: " + encoding);
			if (!isIdentity(fourTimes))
				++orderEight;
			ys.add(point[1]);
		}
		Assertions.assertEquals(4, orderEight, "the torsion group is cyclic of order 8");
		Assertions.assertTrue(ys.containsAll(List.of(BigInteger.ONE, p.subtract(BigInteger.ONE), BigInteger.ZERO)),
				"the identity, the point of order 2 and both points of order 4");
	}

	@Test
	void theSmallOrderIdentityKeyLetsTheJdkVerifyOneForgedSignatureForEveryMessage() throws Exception {
		// Plan M2-7: under the identity key, R = identity and S = 0 verify for any message on JDK 17 to 27, which is
		// why a small-order key is WEAK_KEY. This positive control shows the helper's key is that dangerous key.
		byte[] x = decodeMember(parse(TestJsonWebKeys.ed25519SmallOrder().toJson()), "x");
		PublicKey key = KeyFactory.getInstance("Ed25519").generatePublic(
				new X509EncodedKeySpec(concat(HexFormat.of().parseHex(ED25519_SPKI_PREFIX), x)));
		byte[] forged = Arrays.copyOf(x, 64);

		for (String message : List.of("", "any message", Sentinels.MARKER)) {
			Signature verifier = Signature.getInstance("Ed25519");
			verifier.initVerify(key);
			verifier.update(message.getBytes(StandardCharsets.UTF_8));
			Assertions.assertTrue(verifier.verify(forged), message);
		}
	}

	@Test
	void ed25519DecodingFollowsRfc8032Section513() {
		BigInteger p = TestJsonWebKeys.ED25519_FIELD_PRIME;
		EdECPublicKey fixture = (EdECPublicKey) Fixture.ED25519.getPublicKey();
		byte[] encoded = fixture.getEncoded();

		Assertions.assertEquals(TestJws.base64Url(Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length)),
				TestJsonWebKeys.ed25519PublicKeyEncoding(fixture.getPoint().getY(), fixture.getPoint().isXOdd()));
		BigInteger x = TestJsonWebKeys.ed25519DecodeX(fixture.getPoint().getY(), fixture.getPoint().isXOdd())
				.orElseThrow();
		Assertions.assertEquals(fixture.getPoint().isXOdd(), x.testBit(0));
		Assertions.assertTrue(onEdwardsCurve(new BigInteger[]{x, fixture.getPoint().getY()}));
		// Plan M2 exit criterion 7: an off-curve x (y = 2), and x = 0 with the sign bit set (y = 1 and y = p − 1).
		Assertions.assertTrue(TestJsonWebKeys.ed25519DecodeX(BigInteger.TWO, false).isEmpty());
		Assertions.assertTrue(TestJsonWebKeys.ed25519DecodeX(BigInteger.ONE, true).isEmpty());
		Assertions.assertTrue(TestJsonWebKeys.ed25519DecodeX(p.subtract(BigInteger.ONE), true).isEmpty());
		Assertions.assertEquals(BigInteger.ZERO, TestJsonWebKeys.ed25519DecodeX(BigInteger.ONE, false).orElseThrow());
		// Non-canonical: y from p up.
		Assertions.assertTrue(TestJsonWebKeys.ed25519DecodeX(p, false).isEmpty());
		Assertions.assertTrue(TestJsonWebKeys.ed25519DecodeX(p.add(BigInteger.ONE), false).isEmpty());
		byte[] fieldPrime = new byte[32];
		Arrays.fill(fieldPrime, (byte) 0xff);
		fieldPrime[0] = (byte) 0xed;
		fieldPrime[31] = 0x7f;
		Assertions.assertEquals(TestJws.base64Url(fieldPrime), TestJsonWebKeys.ed25519PublicKeyEncoding(p, false),
				"y = p encodes as 2^255 − 19, little-endian");
		byte[] identityWithSignBit = new byte[32];
		identityWithSignBit[0] = 1;
		identityWithSignBit[31] = (byte) 0x80;
		Assertions.assertEquals(TestJws.base64Url(identityWithSignBit),
				TestJsonWebKeys.ed25519PublicKeyEncoding(BigInteger.ONE, true), "the sign bit is the top bit");
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> TestJsonWebKeys.ed25519PublicKeyEncoding(BigInteger.TWO.pow(255), false));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> TestJsonWebKeys.ed25519PublicKeyEncoding(BigInteger.ONE.negate(), false));
		Assertions.assertTrue(TestJsonWebKeys.ed25519DecodeX(BigInteger.ONE.negate(), false).isEmpty());
	}

	@Test
	void theRocaKeyCarriesTheFingerprintAndTheFixtureKeysDoNot() throws Exception {
		// CVE-2017-15361; plan M2-7: N mod m is a power of 65537 mod m for the 38 odd primes 3 to 167.
		KeyPair keyPair = TestJsonWebKeys.rocaFingerprintedRsaKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();

		Assertions.assertEquals(38, TestJsonWebKeys.ROCA_PRIMES.size());
		Assertions.assertEquals(BigInteger.valueOf(3), TestJsonWebKeys.ROCA_PRIMES.get(0));
		Assertions.assertEquals(BigInteger.valueOf(167), TestJsonWebKeys.ROCA_PRIMES.get(37));
		Assertions.assertEquals(2048, publicKey.getModulus().bitLength());
		Assertions.assertEquals(TestJsonWebKeys.F4, publicKey.getPublicExponent());
		Assertions.assertTrue(publicKey.getModulus().testBit(0));
		Assertions.assertTrue(inSubgroupOfF4(publicKey.getModulus()), "the fingerprint, by subgroup order");
		Assertions.assertTrue(inSubgroupOfF4(privateKey.getPrimeP()));
		Assertions.assertTrue(inSubgroupOfF4(privateKey.getPrimeQ()));
		Assertions.assertTrue(TestJsonWebKeys.hasRocaFingerprint(publicKey.getModulus()));
		Assertions.assertTrue(jdkSignsAndVerifies(keyPair), "otherwise a working key");
		for (Fixture fixture : Fixture.values()) {
			if (fixture.getKeyType().equals("RSA")) {
				BigInteger modulus = ((RSAPublicKey) fixture.getPublicKey()).getModulus();
				Assertions.assertFalse(inSubgroupOfF4(modulus), fixture.name());
				Assertions.assertFalse(TestJsonWebKeys.hasRocaFingerprint(modulus), fixture.name());
			}
		}
		Assertions.assertEquals(publicKey.getModulus(),
				((RSAPublicKey) TestJsonWebKeys.rocaFingerprintedRsaKeyPair().getPublic()).getModulus(),
				"deterministic");
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> okpKeysOnOtherCurvesCarryTheRawKeysTheJdkEncodes() {
		// RFC 8037 section 2 and plan M2-7 key check 6 (exit criterion 7: Ed448 and X25519 are UNSUPPORTED_CURVE).
		Map<String, Integer> octets = new LinkedHashMap<>();
		octets.put("Ed448", 57);
		octets.put("X25519", 32);
		octets.put("X448", 56);
		return octets.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () -> {
			KeyPair keyPair = KeyPairGenerator.getInstance(entry.getKey()).generateKeyPair();
			JsonObject jwk = parse(TestJsonWebKeys.withKeyPair(keyPair).includePrivateMembers(true).toJson());
			int length = entry.getValue();
			byte[] publicEncoded = keyPair.getPublic().getEncoded();
			byte[] privateEncoded = keyPair.getPrivate().getEncoded();

			Assertions.assertEquals(List.of("kty", "crv", "x", "d"), List.copyOf(jwk.getMembers().keySet()));
			Assertions.assertEquals("OKP", string(jwk, "kty"));
			Assertions.assertEquals(entry.getKey(), string(jwk, "crv"));
			// The SubjectPublicKeyInfo and PKCS#8 encodings end with the raw key (RFC 8410 sections 4 and 7).
			Assertions.assertArrayEquals(Arrays.copyOfRange(publicEncoded, publicEncoded.length - length,
					publicEncoded.length), decodeMember(jwk, "x"));
			Assertions.assertArrayEquals(Arrays.copyOfRange(privateEncoded, privateEncoded.length - length,
					privateEncoded.length), decodeMember(jwk, "d"));
			Assertions.assertEquals(List.of("kty", "crv", "x"),
					List.copyOf(parse(TestJsonWebKeys.withPublicKey(keyPair.getPublic()).toJson()).getMembers()
							.keySet()));
		}));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> edwardsKeysCarryTheParityOfXInTheTopBitOfTheLastOctet() {
		// RFC 8032 sections 5.1.2 and 5.2.2. Keys come from fixed seeds, so every run meets both parities of x.
		Map<String, Integer> octets = new LinkedHashMap<>();
		octets.put("Ed25519", 32);
		octets.put("Ed448", 57);
		return octets.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () -> {
			int length = entry.getValue();
			Set<Boolean> parities = new HashSet<>();
			for (int seed = 0; seed < 64 && parities.size() < 2; ++seed) {
				KeyPair keyPair = keyPairFromSeed(entry.getKey(),
						Arrays.copyOf(sha512(entry.getKey() + " TEST ONLY seed " + seed), length));
				EdECPublicKey publicKey = (EdECPublicKey) keyPair.getPublic();
				byte[] encoded = publicKey.getEncoded();
				byte[] x = decodeMember(parse(TestJsonWebKeys.withKeyPair(keyPair).toJson()), "x");

				Assertions.assertArrayEquals(Arrays.copyOfRange(encoded, encoded.length - length, encoded.length), x);
				Assertions.assertEquals(publicKey.getPoint().isXOdd(), (x[length - 1] & 0x80) != 0);
				parities.add(publicKey.getPoint().isXOdd());
			}
			Assertions.assertEquals(2, parities.size(), "both parities of x were written");
		}));
	}

	@Test
	void keysOfOtherAlgorithmsAreRefused() throws Exception {
		KeyPair dsa = KeyPairGenerator.getInstance("DSA").generateKeyPair();

		Assertions.assertThrows(IllegalArgumentException.class, () -> TestJsonWebKeys.withKeyPair(dsa));
		Assertions.assertThrows(IllegalArgumentException.class, () -> TestJsonWebKeys.withPublicKey(dsa.getPublic()));
	}

	@Test
	void octWithKWritesASymmetricKey() throws Exception {
		JsonObject jwk = parse(TestJsonWebKeys.octWithK(Sentinels.SYMMETRIC_KEY).kid("hmac").alg("HS256").toJson());
		Assertions.assertEquals(List.of("kty", "k", "kid", "alg"), List.copyOf(jwk.getMembers().keySet()));
		Assertions.assertEquals("oct", string(jwk, "kty"));
		Assertions.assertEquals(Sentinels.SYMMETRIC_KEY, string(jwk, "k"));
	}

	@Test
	void ed25519WithXWritesAnyXVerbatim() throws Exception {
		JsonObject jwk = parse(TestJsonWebKeys.ed25519WithX("not base64url!").kid("k").toJson());
		Assertions.assertEquals(List.of("kty", "crv", "x", "kid"), List.copyOf(jwk.getMembers().keySet()));
		Assertions.assertEquals("not base64url!", string(jwk, "x"));
	}

	private static boolean jdkSignsAndVerifies(@NonNull KeyPair keyPair) throws Exception {
		String algorithm = switch (keyPair.getPublic().getAlgorithm()) {
			case "RSA" -> "SHA256withRSA";
			case "EC" -> "SHA256withECDSA";
			default -> "Ed25519";
		};
		Signature signer = Signature.getInstance(algorithm);
		signer.initSign(keyPair.getPrivate());
		signer.update(MESSAGE);
		byte[] signature = signer.sign();
		Signature verifier = Signature.getInstance(algorithm);
		verifier.initVerify(keyPair.getPublic());
		verifier.update(MESSAGE);
		return verifier.verify(signature);
	}

	/**
	 * Whether {@code value} mod m lies in the subgroup generated by 65537 mod m for every ROCA prime, tested by the
	 * subgroup's order t (Z_m^* is cyclic, so the subgroup of order t is exactly {r : r^t = 1}), unlike the helper's
	 * enumeration.
	 */
	private static boolean inSubgroupOfF4(@NonNull BigInteger value) {
		for (int prime = 3; prime <= 167; prime += 2) {
			BigInteger m = BigInteger.valueOf(prime);
			if (!m.isProbablePrime(64))
				continue;
			BigInteger generator = TestJsonWebKeys.F4.mod(m);
			int order = 1;
			for (BigInteger power = generator; !power.equals(BigInteger.ONE); power = power.multiply(generator).mod(m))
				++order;
			if (!value.mod(m).modPow(BigInteger.valueOf(order), m).equals(BigInteger.ONE))
				return false;
		}
		return true;
	}

	private static boolean onWeierstrassCurve(@NonNull ECParameterSpec parameters, @NonNull BigInteger x, @NonNull BigInteger y) {
		BigInteger p = ((ECFieldFp) parameters.getCurve().getField()).getP();
		BigInteger right = x.multiply(x).multiply(x).add(parameters.getCurve().getA().multiply(x))
				.add(parameters.getCurve().getB()).mod(p);
		return y.multiply(y).mod(p).equals(right);
	}

	/**
	 * Decodes an RFC 8032 point encoding by brute-force square root check, independently of the helper: x² is taken
	 * from the curve equation and x found with Euler's criterion and Tonelli-free exponentiation for p ≡ 5 (mod 8).
	 */
	private static @NonNull BigInteger @NonNull [] decodePoint(@NonNull String encoding) {
		byte[] littleEndian = Base64.getUrlDecoder().decode(encoding);
		boolean xOdd = (littleEndian[31] & 0x80) != 0;
		byte[] bigEndian = new byte[32];
		for (int index = 0; index < 32; ++index)
			bigEndian[index] = littleEndian[31 - index];
		bigEndian[0] &= 0x7f;
		BigInteger p = TestJsonWebKeys.ED25519_FIELD_PRIME;
		BigInteger y = new BigInteger(1, bigEndian);
		BigInteger ySquared = y.multiply(y).mod(p);
		BigInteger xSquared = ySquared.subtract(BigInteger.ONE)
				.multiply(TestJsonWebKeys.ED25519_D.multiply(ySquared).add(BigInteger.ONE).modInverse(p)).mod(p);
		// A square has x = xSquared^((p + 3) / 8) or that times 2^((p − 1) / 4).
		BigInteger candidate = xSquared.modPow(p.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), p);
		if (!candidate.multiply(candidate).mod(p).equals(xSquared))
			candidate = candidate.multiply(
					BigInteger.TWO.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), p)).mod(p);
		Assertions.assertEquals(xSquared, candidate.multiply(candidate).mod(p), "decodes: " + encoding);
		if (candidate.testBit(0) != xOdd)
			candidate = p.subtract(candidate).mod(p);
		return new BigInteger[]{candidate, y};
	}

	private static boolean onEdwardsCurve(@NonNull BigInteger @NonNull [] point) {
		BigInteger p = TestJsonWebKeys.ED25519_FIELD_PRIME;
		BigInteger xx = point[0].multiply(point[0]).mod(p);
		BigInteger yy = point[1].multiply(point[1]).mod(p);
		BigInteger left = yy.subtract(xx).mod(p);
		BigInteger right = BigInteger.ONE.add(TestJsonWebKeys.ED25519_D.multiply(xx).multiply(yy)).mod(p);
		return left.equals(right);
	}

	/**
	 * 2P on −x² + y² = 1 + d·x²·y², by the dedicated doubling formula (RFC 8032 section 5.1.4's doubling, in affine
	 * form): x3 = 2xy / (y² − x²), y3 = (y² + x²) / (2 − y² + x²).
	 */
	private static @NonNull BigInteger @NonNull [] edwardsDouble(@NonNull BigInteger @NonNull [] point) {
		BigInteger p = TestJsonWebKeys.ED25519_FIELD_PRIME;
		BigInteger x = point[0];
		BigInteger y = point[1];
		BigInteger xx = x.multiply(x).mod(p);
		BigInteger yy = y.multiply(y).mod(p);
		BigInteger x3 = BigInteger.TWO.multiply(x).multiply(y).multiply(yy.subtract(xx).mod(p).modInverse(p)).mod(p);
		BigInteger y3 = yy.add(xx).multiply(BigInteger.TWO.subtract(yy).add(xx).mod(p).modInverse(p)).mod(p);
		return new BigInteger[]{x3, y3};
	}

	private static boolean isIdentity(@NonNull BigInteger @NonNull [] point) {
		return point[0].signum() == 0 && point[1].equals(BigInteger.ONE);
	}

	private static @NonNull JsonObject parse(@NonNull String json) throws Exception {
		return (JsonObject) JsonCodec.parse(json.getBytes(StandardCharsets.UTF_8),
				JsonLimits.protocolDocument(1 << 20));
	}

	private static @NonNull String string(@NonNull JsonObject object, @NonNull String name) {
		return ((JsonString) object.find(name).orElseThrow()).getValue();
	}

	private static byte @NonNull [] decodeMember(@NonNull JsonObject object, @NonNull String name) {
		return Base64.getUrlDecoder().decode(string(object, name));
	}

	private static @NonNull BigInteger integer(@NonNull JsonObject object, @NonNull String name) {
		return new BigInteger(1, decodeMember(object, name));
	}

	private static @NonNull String resourceText(@NonNull String resource) throws IOException {
		try (InputStream inputStream = Objects.requireNonNull(
				TestJsonWebKeysTests.class.getResourceAsStream(resource), resource)) {
			return new String(inputStream.readAllBytes(), StandardCharsets.US_ASCII);
		}
	}

	private static @NonNull KeyPair ed25519KeyPairFromFixtureSeed() throws Exception {
		return keyPairFromSeed("Ed25519", ((EdECPrivateKey) Fixture.ED25519.getPrivateKey()).getBytes().orElseThrow());
	}

	/**
	 * A JDK EdDSA key pair whose private key is exactly {@code seed}: the key generator draws its seed from the
	 * random source in a single call (RFC 8032 sections 5.1.5 and 5.2.5), and this source returns {@code seed}.
	 */
	private static @NonNull KeyPair keyPairFromSeed(@NonNull String curve, byte @NonNull [] seed) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance(curve);
		generator.initialize(new NamedParameterSpec(curve), new FixedSecureRandom(seed));
		KeyPair keyPair = generator.generateKeyPair();
		Assertions.assertArrayEquals(seed, ((EdECPrivateKey) keyPair.getPrivate()).getBytes().orElseThrow());
		return keyPair;
	}

	private static byte @NonNull [] sha512(@NonNull String label) throws Exception {
		return MessageDigest.getInstance("SHA-512").digest(label.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * A random source that returns fixed bytes, for key generation from a known seed.
	 */
	private static final class FixedSecureRandom extends SecureRandom {
		private static final long serialVersionUID = 1L;

		private final byte[] bytes;

		private FixedSecureRandom(byte @NonNull [] bytes) {
			this.bytes = bytes.clone();
		}

		@Override
		public void nextBytes(byte @NonNull [] output) {
			if (output.length != this.bytes.length)
				throw new IllegalStateException("Asked for " + output.length + " bytes, not " + this.bytes.length);
			System.arraycopy(this.bytes, 0, output, 0, output.length);
		}
	}

	private static byte @NonNull [] concat(byte @NonNull [] first, byte @NonNull [] second) {
		byte[] result = Arrays.copyOf(first, first.length + second.length);
		System.arraycopy(second, 0, result, first.length, second.length);
		return result;
	}

}
