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

package com.revetsec.internal.jose;

import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.jose.JsonWebKeySkipReason;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.json.JsonObject;
import com.revetsec.testing.JsonText;
import com.revetsec.testing.TestJsonWebKeys;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.stream.Stream;

/**
 * {@link JwkParser}: the per-key rules of plan M2-7 ("Keys"), in their order, each refusal naming the first rule that
 * fails with its {@link JsonWebKeySkipReason}; RFC 7517 section 4 members, RFC 7518 section 6 key parameters, RFC 8037
 * section 2 OKP keys and RFC 7638 thumbprints over canonical members only (INV-J3, INV-J5, INV-C6).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JwkParserTests {
	/**
	 * The RSA key of RFC 7638 section 3.1 (also RFC 7517 appendix A.1), with its optional members.
	 */
	private static final String RFC_7638_RSA_JWK = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAF"
			+ "bWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lq"
			+ "t7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrd"
			+ "kt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\"e\":\"AQAB\","
			+ "\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";

	/**
	 * The Ed25519 public key of RFC 8037 appendix A.2.
	 */
	private static final String RFC_8037_OKP_JWK = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\","
			+ "\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";

	/**
	 * The P-256 public key of RFC 7517 appendix A.1, without its {@code use} of {@code enc}.
	 */
	private static final String RFC_7517_EC_JWK = "{\"kty\":\"EC\",\"crv\":\"P-256\","
			+ "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\","
			+ "\"kid\":\"1\"}";

	private static final List<Fixture> USABLE_FIXTURES = List.of(Fixture.IDP_SIGNING_RSA_2048,
			Fixture.IDP_SIGNING_RSA_3072, Fixture.IDP_SIGNING_EC_P256, Fixture.IDP_SIGNING_EC_P384,
			Fixture.IDP_SIGNING_EC_P521, Fixture.NEGATIVE_ATTACKER_RSA_2048, Fixture.NEGATIVE_UNCONFIGURED_EC_P256,
			Fixture.ED25519);

	// Every supported key type and curve parses, and the JCA key is the fixture's own key.
	@TestFactory
	Stream<DynamicTest> everySupportedKeyTypeAndCurveParsesToTheSameJcaKey() {
		return USABLE_FIXTURES.stream().map(fixture -> DynamicTest.dynamicTest(fixture.name(), () -> {
			VerificationKey key = parse(TestJsonWebKeys.withFixture(fixture).toJson());

			Assertions.assertEquals(fixture.getKeyType(), key.keyType());
			Assertions.assertArrayEquals(fixture.getPublicKey().getEncoded(), key.publicKey().getEncoded());
			Assertions.assertEquals(expectedCurve(fixture.getPublicKey()), key.curve());
			Assertions.assertNull(key.keyId());
			Assertions.assertNull(key.algorithm());
			Assertions.assertNull(key.use());
			Assertions.assertNull(key.issuer());
			Assertions.assertEquals(thumbprintOf(TestJsonWebKeys.withFixture(fixture).toJson()), key.thumbprintSha256());
		}));
	}

	// RFC 7638 section 3.1, RFC 8037 appendix A.3 and RFC 7517 appendix A.1: the published keys parse, and give the
	// published thumbprints (the EC value matches Rfc7638Tests' offline computation).
	@Test
	void rfcExampleKeysParseAndGiveTheirPublishedThumbprints() throws SkippedKeyException {
		VerificationKey rsa = parse(RFC_7638_RSA_JWK);
		Assertions.assertEquals("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", rsa.thumbprintSha256());
		Assertions.assertEquals("2011-04-29", rsa.keyId());
		Assertions.assertEquals(JwsAlgorithm.RS256, rsa.algorithm());
		Assertions.assertEquals(2048, ((RSAPublicKey) rsa.publicKey()).getModulus().bitLength());

		VerificationKey okp = parse(RFC_8037_OKP_JWK);
		Assertions.assertEquals("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", okp.thumbprintSha256());
		Assertions.assertEquals("Ed25519", okp.curve());

		VerificationKey ec = parse(RFC_7517_EC_JWK);
		Assertions.assertEquals("cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s", ec.thumbprintSha256());
		Assertions.assertEquals("P-256", ec.curve());
	}

	// RFC 7638 section 3: the thumbprint covers only the required members, whatever their order and whatever else the
	// key carries; a key that passes keeps its kid, alg, use and issuer members.
	@Test
	void thumbprintsCoverOnlyTheRequiredMembersAndOtherMembersAreKept() throws SkippedKeyException {
		String bare = TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P384).toJson();
		JsonObject object = jwk(bare);
		String reordered = JsonText.object(List.of(Map.entry("y", object.find("y").orElseThrow().toJson()),
				Map.entry("x", object.find("x").orElseThrow().toJson()), Map.entry("crv", "\"P-384\""),
				Map.entry("kty", "\"EC\""), Map.entry("x5t", "\"ignored\""),
				Map.entry("x5u", "\"https://ignored.example.com\""),
				Map.entry("cloud_instance_name", "\"ignored\""), Map.entry("ext", "true")));

		VerificationKey full = parse(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P384).kid("key-1").alg("ES384")
				.use("sig").keyOps(List.of("verify")).issuer("https://issuer.example.com").toJson());

		Assertions.assertEquals(parse(bare).thumbprintSha256(), parse(reordered).thumbprintSha256());
		Assertions.assertEquals(parse(bare).thumbprintSha256(), full.thumbprintSha256());
		Assertions.assertEquals("key-1", full.keyId());
		Assertions.assertEquals(JwsAlgorithm.ES384, full.algorithm());
		Assertions.assertEquals("sig", full.use());
		Assertions.assertEquals("https://issuer.example.com", full.issuer());
	}

	// Rule 1: kty must be present and a string.
	@TestFactory
	Stream<DynamicTest> aKeyTypeThatIsMissingOrNotAStringIsMalformed() {
		return rows(
				row("absent", rsa().withoutMember("kty").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("null", rsa().member("kty", "null").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("a number", rsa().member("kty", "1").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("an array", rsa().member("kty", "[\"RSA\"]").toJson(), JsonWebKeySkipReason.MALFORMED_KEY));
	}

	// Rule 2: RFC 7517 section 4.1's values are case-sensitive; oct is symmetric, and anything else is unsupported.
	@TestFactory
	Stream<DynamicTest> symmetricAndUnknownKeyTypesAreSkippedByType() {
		return rows(
				row("oct", TestJsonWebKeys.octWithK("GawgguFyGrWKav7AX4VKUg").toJson(), JsonWebKeySkipReason.SYMMETRIC_KEY),
				row("oct with alg HS256", TestJsonWebKeys.octWithK("GawgguFyGrWKav7AX4VKUg").alg("HS256").use("sig").toJson(),
						JsonWebKeySkipReason.SYMMETRIC_KEY),
				row("rsa", rsa().member("kty", "\"rsa\"").toJson(), JsonWebKeySkipReason.UNSUPPORTED_KEY_TYPE),
				row("Ec", ec().member("kty", "\"Ec\"").toJson(), JsonWebKeySkipReason.UNSUPPORTED_KEY_TYPE),
				row("okp", ed25519().member("kty", "\"okp\"").toJson(), JsonWebKeySkipReason.UNSUPPORTED_KEY_TYPE),
				row("OCT", rsa().member("kty", "\"OCT\"").toJson(), JsonWebKeySkipReason.UNSUPPORTED_KEY_TYPE),
				row("RSA with a trailing space", rsa().member("kty", "\"RSA \"").toJson(),
						JsonWebKeySkipReason.UNSUPPORTED_KEY_TYPE),
				row("empty", rsa().member("kty", "\"\"").toJson(), JsonWebKeySkipReason.UNSUPPORTED_KEY_TYPE));
	}

	// Rule 3: a key that publishes private or symmetric material is never used, not even for its public half, whatever
	// the member's value (JSON null included).
	@TestFactory
	Stream<DynamicTest> privateOrSymmetricMembersSkipTheKeyWhateverTheirValue() {
		List<DynamicTest> tests = new ArrayList<>();
		for (String name : List.of("d", "p", "q", "dp", "dq", "qi", "oth", "k"))
			for (String value : List.of("\"AQAB\"", "null", "1", "[]", "\"\""))
				tests.add(DynamicTest.dynamicTest(name + " = " + value, () -> assertSkipped(
						JsonWebKeySkipReason.PRIVATE_KEY_MEMBERS, rsa().member(name, value).toJson())));
		for (Fixture fixture : List.of(Fixture.IDP_SIGNING_RSA_2048, Fixture.IDP_SIGNING_EC_P521, Fixture.ED25519))
			tests.add(DynamicTest.dynamicTest(fixture.name() + " with its private members", () -> assertSkipped(
					JsonWebKeySkipReason.PRIVATE_KEY_MEMBERS, TestJsonWebKeys.withFixture(fixture)
							.includePrivateMembers(true).toJson())));
		return tests.stream();
	}

	// Rule 4 (RFC 7517 sections 4.2 and 4.3): use, when present, is exactly "sig"; key_ops, when present, is an array of
	// strings with "verify"; with both, key_ops holds only sign and verify, so the two agree.
	@TestFactory
	Stream<DynamicTest> useAndKeyOperationsMustAllowVerification() {
		return rows(
				row("use enc", rsa().use("enc").toJson(), JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY),
				row("use SIG", rsa().use("SIG").toJson(), JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY),
				row("use sig with a space", rsa().use("sig ").toJson(), JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY),
				row("use empty", rsa().use("").toJson(), JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY),
				row("use null", rsa().member("use", "null").toJson(), JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY),
				row("use a number", rsa().member("use", "1").toJson(), JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY),
				row("use an array", rsa().member("use", "[\"sig\"]").toJson(),
						JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY),
				row("key_ops encrypt", rsa().keyOps(List.of("encrypt")).toJson(),
						JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY),
				row("key_ops sign only", rsa().keyOps(List.of("sign")).toJson(), JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY),
				row("key_ops empty", rsa().keyOps(List.of()).toJson(), JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY),
				row("key_ops Verify", rsa().keyOps(List.of("Verify")).toJson(), JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY),
				row("key_ops as one string", rsa().member("key_ops", "\"verify\"").toJson(),
						JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY),
				row("key_ops with one comma-joined string", rsa().member("key_ops", "[\"sign, verify\"]").toJson(),
						JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY),
				row("key_ops with a number", rsa().member("key_ops", "[\"verify\",1]").toJson(),
						JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY),
				row("key_ops null", rsa().member("key_ops", "null").toJson(), JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY),
				row("use sig with key_ops verify and encrypt", rsa().use("sig").keyOps(List.of("verify", "encrypt"))
						.toJson(), JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY),
				row("use enc with key_ops verify", rsa().use("enc").keyOps(List.of("verify")).toJson(),
						JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY),
				row("use sig", rsa().use("sig").toJson(), null),
				row("key_ops verify", rsa().keyOps(List.of("verify")).toJson(), null),
				row("key_ops sign and verify", rsa().keyOps(List.of("sign", "verify")).toJson(), null),
				row("key_ops verify and encrypt without use", rsa().keyOps(List.of("verify", "encrypt")).toJson(), null),
				row("use sig with key_ops verify", rsa().use("sig").keyOps(List.of("verify")).toJson(), null),
				row("use sig with key_ops sign and verify", rsa().use("sig").keyOps(List.of("sign", "verify")).toJson(),
						null));
	}

	// Rule 5: alg, when present, must be a JwsAlgorithm wire value, compared exactly (Wycheproof's ES521, JWE
	// algorithms, none in any case, and a JSON value that is not a string all fail here).
	@TestFactory
	Stream<DynamicTest> algorithmsThatAreNotJwsAlgorithmsAreUnsupported() {
		return Stream.of("\"ES521\"", "\"RSA-OAEP\"", "\"RSA1_5\"", "\"none\"", "\"None\"", "\"rs256\"", "\"\"",
						"\"ES256K\"", "\"Ed448\"", "\"A256GCM\"", "256", "null", "true", "[\"RS256\"]")
				.map(alg -> DynamicTest.dynamicTest("alg " + alg, () -> assertSkipped(
						JsonWebKeySkipReason.UNSUPPORTED_ALGORITHM, rsa().member("alg", alg).toJson())));
	}

	// Rule 5: an alg for another key type, or for another supported curve, is a mismatch; every HMAC alg is one,
	// because a key set never supplies an HMAC key. Matching pairs keep their alg.
	@TestFactory
	Stream<DynamicTest> algorithmsForAnotherKeyTypeOrCurveAreMismatched() {
		List<DynamicTest> tests = new ArrayList<>();
		Map<String, TestJsonWebKeys.Builder> keys = Map.of("RSA", rsa(), "P-256", ec(),
				"P-384", TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P384),
				"P-521", TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P521), "Ed25519", ed25519());
		Map<String, List<JwsAlgorithm>> fits = Map.of(
				"RSA", List.of(JwsAlgorithm.RS256, JwsAlgorithm.RS384, JwsAlgorithm.RS512, JwsAlgorithm.PS256,
						JwsAlgorithm.PS384, JwsAlgorithm.PS512),
				"P-256", List.of(JwsAlgorithm.ES256),
				"P-384", List.of(JwsAlgorithm.ES384),
				"P-521", List.of(JwsAlgorithm.ES512),
				"Ed25519", List.of(JwsAlgorithm.ED25519, JwsAlgorithm.EDDSA));

		// In key order, so the dynamic tests have the same order and numbering in every JVM.
		for (Map.Entry<String, TestJsonWebKeys.Builder> key : new TreeMap<>(keys).entrySet())
			for (JwsAlgorithm algorithm : JwsAlgorithm.values()) {
				boolean fit = Objects.requireNonNull(fits.get(key.getKey())).contains(algorithm);
				String json = key.getValue().alg(algorithm.getWireValue()).toJson();
				tests.add(DynamicTest.dynamicTest(key.getKey() + " with " + algorithm.getWireValue(), () -> {
					if (fit)
						Assertions.assertEquals(algorithm, parse(json).algorithm());
					else
						assertSkipped(JsonWebKeySkipReason.ALGORITHM_MISMATCH, json);
				}));
			}

		return tests.stream();
	}

	// Rule 6: EC keys on P-256, P-384 and P-521 and OKP keys on Ed25519 only, by exact name. An alg for the curve
	// family does not rescue an unsupported curve: that is rule 6's, not a mismatch.
	@TestFactory
	Stream<DynamicTest> curvesRevetsecDoesNotSupportAreSkipped() throws GeneralSecurityException {
		String ed448 = TestJsonWebKeys.withKeyPair(generate("Ed448")).toJson();
		String x25519 = TestJsonWebKeys.withKeyPair(generate("X25519")).toJson();
		String x448 = TestJsonWebKeys.withKeyPair(generate("X448")).toJson();

		return rows(
				row("EC secp256k1", ec().member("crv", "\"secp256k1\"").toJson(), JsonWebKeySkipReason.UNSUPPORTED_CURVE),
				row("EC P-192", ec().member("crv", "\"P-192\"").toJson(), JsonWebKeySkipReason.UNSUPPORTED_CURVE),
				row("EC p-256", ec().member("crv", "\"p-256\"").toJson(), JsonWebKeySkipReason.UNSUPPORTED_CURVE),
				row("EC P256", ec().member("crv", "\"P256\"").toJson(), JsonWebKeySkipReason.UNSUPPORTED_CURVE),
				row("EC Ed25519", ec().member("crv", "\"Ed25519\"").toJson(), JsonWebKeySkipReason.UNSUPPORTED_CURVE),
				row("EC secp256k1 with ES256", ec().member("crv", "\"secp256k1\"").alg("ES256").toJson(),
						JsonWebKeySkipReason.UNSUPPORTED_CURVE),
				row("OKP ed25519", ed25519().member("crv", "\"ed25519\"").toJson(), JsonWebKeySkipReason.UNSUPPORTED_CURVE),
				row("OKP P-256", ed25519().member("crv", "\"P-256\"").toJson(), JsonWebKeySkipReason.UNSUPPORTED_CURVE),
				row("an Ed448 key", ed448, JsonWebKeySkipReason.UNSUPPORTED_CURVE),
				row("an Ed448 key with EdDSA", TestJsonWebKeys.withKeyPair(generate("Ed448")).alg("EdDSA").toJson(),
						JsonWebKeySkipReason.UNSUPPORTED_CURVE),
				row("an X25519 key", x25519, JsonWebKeySkipReason.UNSUPPORTED_CURVE),
				row("an X448 key", x448, JsonWebKeySkipReason.UNSUPPORTED_CURVE));
	}

	// Rule 7: kid is a string of 1 to 256 characters.
	@TestFactory
	Stream<DynamicTest> keyIdsAreStringsOfOneTo256Characters() {
		return rows(
				row("empty", rsa().kid("").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("257 characters", rsa().kid("k".repeat(257)).toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("null", rsa().member("kid", "null").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("a number", rsa().member("kid", "123").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("an array", rsa().member("kid", "[\"a\"]").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("1 character", rsa().kid("k").toJson(), null),
				row("256 characters", rsa().kid("k".repeat(256)).toJson(), null),
				row("control, bidirectional and non-ASCII characters", rsa().kid("a" + (char) 0 + "b" + (char) 0x202E + "c"
						+ (char) 0xE9).toJson(), null));
	}

	// Rule 7 and INV-C6: an issuer member that is present but not a non-empty string never counts as absent, which
	// would make the key usable for every issuer.
	@TestFactory
	Stream<DynamicTest> anIssuerMemberThatIsNotANonEmptyStringSkipsTheKey() {
		return rows(
				row("null", rsa().member("issuer", "null").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("123", rsa().member("issuer", "123").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("[]", rsa().member("issuer", "[]").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("an empty string", rsa().issuer("").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("an object", rsa().member("issuer", "{}").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("true", rsa().member("issuer", "true").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("an array of the issuer", rsa().member("issuer", "[\"https://issuer.example.com\"]").toJson(),
						JsonWebKeySkipReason.MALFORMED_KEY),
				row("a string", rsa().issuer("https://issuer.example.com").toJson(), null));
	}

	// Rule 7 for RSA (RFC 7518 sections 2 and 6.3.1): n and e are canonical unpadded base64url of minimal unsigned
	// integers, and n is odd.
	@TestFactory
	Stream<DynamicTest> rsaMembersMustBeMinimalCanonicalBase64UrlIntegers() {
		RSAPublicKey key = (RSAPublicKey) Fixture.IDP_SIGNING_RSA_2048.getPublicKey();
		String n = TestJsonWebKeys.base64UrlUInt(key.getModulus());

		return rows(
				row("n absent", rsa().withoutMember("n").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("e absent", rsa().withoutMember("e").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("n null", rsa().member("n", "null").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("n a number", rsa().member("n", "65537").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("e a number", rsa().member("e", "65537").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("n padded", rsa().member("n", JsonText.string(TestJws.padded(n))).toJson(),
						JsonWebKeySkipReason.MALFORMED_KEY),
				row("n with non-canonical trailing bits", rsa().member("n",
						JsonText.string(TestJws.withNonCanonicalTrailingBits(n))).toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("n in the standard alphabet", rsa().member("n", JsonText.string(Base64.getEncoder().withoutPadding()
						.encodeToString(TestJsonWebKeys.unsignedBytes(key.getModulus())))).toJson(),
						JsonWebKeySkipReason.MALFORMED_KEY),
				row("n with a leading zero octet", TestJsonWebKeys.rsaWithLeadingZeroModulus().toJson(),
						JsonWebKeySkipReason.MALFORMED_KEY),
				row("n even", rsa().member("n", JsonText.string(TestJsonWebKeys.base64UrlUInt(
						key.getModulus().subtract(BigInteger.ONE)))).toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("n empty", rsa().member("n", "\"\"").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("e empty", rsa().member("e", "\"\"").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("e with a leading zero octet", rsa().member("e", "\"AAEAAQ\"").toJson(),
						JsonWebKeySkipReason.MALFORMED_KEY),
				row("e padded", rsa().member("e", "\"AQAB=\"").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("the fixture", rsa().toJson(), null));
	}

	// Rule 7 for EC (RFC 7518 section 6.2.1): crv, x and y are present, and the coordinates are exactly the curve's
	// length, so a producer that trims leading zero octets (31-byte x) is refused rather than given a second thumbprint.
	@TestFactory
	Stream<DynamicTest> ecCoordinatesMustBeStringsOfTheCurvesExactLength() {
		ECPublicKey key = (ECPublicKey) Fixture.IDP_SIGNING_EC_P256.getPublicKey();
		ECPublicKey p384 = (ECPublicKey) Fixture.IDP_SIGNING_EC_P384.getPublicKey();
		byte[] x = TestJsonWebKeys.fixedLengthBytes(key.getW().getAffineX(), 32);
		byte[] longX = new byte[33];
		System.arraycopy(x, 0, longX, 1, 32);

		return rows(
				row("a 31-byte x", TestJsonWebKeys.ecWithShortX().toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("a 33-byte x", ec().member("x", JsonText.string(TestJws.base64Url(longX))).toJson(),
						JsonWebKeySkipReason.MALFORMED_KEY),
				row("P-384 coordinates on P-256", ec().member("x", JsonText.string(TestJsonWebKeys.base64UrlFixedLength(
						p384.getW().getAffineX(), 48))).member("y", JsonText.string(TestJsonWebKeys.base64UrlFixedLength(
						p384.getW().getAffineY(), 48))).toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("x absent", ec().withoutMember("x").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("y absent", ec().withoutMember("y").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("crv absent", ec().withoutMember("crv").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("crv a number", ec().member("crv", "256").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("y null", ec().member("y", "null").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("x padded", ec().member("x", JsonText.string(TestJws.padded(TestJws.base64Url(x)))).toJson(),
						JsonWebKeySkipReason.MALFORMED_KEY),
				row("the fixture", ec().toJson(), null));
	}

	// Rule 7 for Ed25519 (RFC 8037 section 2, RFC 8032 section 5.1.3): x is 32 octets that decode to a curve point, so
	// an undecodable key is refused here rather than failing at verification.
	@TestFactory
	Stream<DynamicTest> ed25519KeysMustDecodeToACurvePoint() {
		BigInteger p = TestJsonWebKeys.ED25519_FIELD_PRIME;
		// Controls: the oracle agrees that these do not decode.
		Assertions.assertTrue(TestJsonWebKeys.ed25519DecodeX(BigInteger.TWO, false).isEmpty());
		Assertions.assertTrue(TestJsonWebKeys.ed25519DecodeX(BigInteger.ONE, true).isEmpty());
		Assertions.assertTrue(TestJsonWebKeys.ed25519DecodeX(p.subtract(BigInteger.ONE), true).isEmpty());

		return rows(
				row("y = 2, off the curve", TestJsonWebKeys.ed25519WithX(TestJsonWebKeys.ed25519PublicKeyEncoding(
						BigInteger.TWO, false)).toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("y = 1 with the sign bit set", TestJsonWebKeys.ed25519WithX(TestJsonWebKeys.ed25519PublicKeyEncoding(
						BigInteger.ONE, true)).toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("y = p - 1 with the sign bit set", TestJsonWebKeys.ed25519WithX(
						TestJsonWebKeys.ed25519PublicKeyEncoding(p.subtract(BigInteger.ONE), true)).toJson(),
						JsonWebKeySkipReason.MALFORMED_KEY),
				row("y = p, not canonical", TestJsonWebKeys.ed25519WithX(TestJsonWebKeys.ed25519PublicKeyEncoding(p,
						false)).toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("31 octets", TestJsonWebKeys.ed25519WithX(TestJws.base64Url(new byte[31])).toJson(),
						JsonWebKeySkipReason.MALFORMED_KEY),
				row("33 octets", TestJsonWebKeys.ed25519WithX(TestJws.base64Url(new byte[33])).toJson(),
						JsonWebKeySkipReason.MALFORMED_KEY),
				row("x absent", ed25519().withoutMember("x").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("crv absent", ed25519().withoutMember("crv").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("the fixture", ed25519().toJson(), null));
	}

	// Rules 8 and 9 (plan 9.3, M2-7): 2048 to 16384 bits, and e odd from 65537 to below 2^32. KeyFactory("RSA") alone
	// accepts every one of these.
	@TestFactory
	Stream<DynamicTest> rsaModulusSizeAndExponentFollowTheKeyPolicy() {
		BigInteger twoTo32 = BigInteger.ONE.shiftLeft(32);
		BigInteger short2047 = BigInteger.ONE.shiftLeft(2046).setBit(0).setBit(1);
		BigInteger long16385 = BigInteger.ONE.shiftLeft(16384).setBit(0);

		return rows(
				row("RSA-1024", TestJsonWebKeys.withFixture(Fixture.NEGATIVE_RSA_1024).toJson(),
						JsonWebKeySkipReason.RSA_KEY_SIZE),
				row("an odd 2047-bit modulus", rsa().member("n", JsonText.string(TestJsonWebKeys.base64UrlUInt(short2047)))
						.toJson(), JsonWebKeySkipReason.RSA_KEY_SIZE),
				row("an odd 16385-bit modulus", rsa().member("n", JsonText.string(TestJsonWebKeys.base64UrlUInt(long16385)))
						.toJson(), JsonWebKeySkipReason.RSA_KEY_SIZE),
				row("e = 1", TestJsonWebKeys.rsaWithExponent(BigInteger.ONE).toJson(), JsonWebKeySkipReason.RSA_EXPONENT),
				row("e = 3", TestJsonWebKeys.rsaWithExponent(BigInteger.valueOf(3)).toJson(),
						JsonWebKeySkipReason.RSA_EXPONENT),
				row("e = 65535", TestJsonWebKeys.rsaWithExponent(BigInteger.valueOf(65_535)).toJson(),
						JsonWebKeySkipReason.RSA_EXPONENT),
				row("e = 65536", TestJsonWebKeys.rsaWithExponent(BigInteger.valueOf(65_536)).toJson(),
						JsonWebKeySkipReason.RSA_EXPONENT),
				row("e = 65538", TestJsonWebKeys.rsaWithEvenExponent().toJson(), JsonWebKeySkipReason.RSA_EXPONENT),
				row("e = 2^32", TestJsonWebKeys.rsaWithExponent(twoTo32).toJson(), JsonWebKeySkipReason.RSA_EXPONENT),
				row("e = 2^32 + 1", TestJsonWebKeys.rsaWithExponent(twoTo32.add(BigInteger.ONE)).toJson(),
						JsonWebKeySkipReason.RSA_EXPONENT),
				row("e = 65537", TestJsonWebKeys.rsaWithExponent(TestJsonWebKeys.F4).toJson(), null),
				row("e = 2^32 - 1", TestJsonWebKeys.rsaWithExponent(twoTo32.subtract(BigInteger.ONE)).toJson(), null),
				row("RSA-3072", TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_3072).toJson(), null));
	}

	// Rule 10 (INV-J5): the point is on its curve, with coordinates below the field prime.
	@TestFactory
	Stream<DynamicTest> ecPointsOffTheCurveAreSkipped() {
		ECPublicKey key = (ECPublicKey) Fixture.IDP_SIGNING_EC_P256.getPublicKey();
		BigInteger p = ((ECFieldFp) key.getParams().getCurve().getField()).getP();
		String zero = JsonText.string(TestJws.base64Url(new byte[32]));

		return rows(
				row("y + 1", TestJsonWebKeys.ecOffCurve().toJson(), JsonWebKeySkipReason.EC_POINT_NOT_ON_CURVE),
				row("x = p", ec().member("x", JsonText.string(TestJsonWebKeys.base64UrlFixedLength(p, 32))).toJson(),
						JsonWebKeySkipReason.EC_POINT_NOT_ON_CURVE),
				row("y = p - 1", ec().member("y", JsonText.string(TestJsonWebKeys.base64UrlFixedLength(
						p.subtract(BigInteger.ONE), 32))).toJson(), JsonWebKeySkipReason.EC_POINT_NOT_ON_CURVE),
				row("(0, 0)", ec().member("x", zero).member("y", zero).toJson(), JsonWebKeySkipReason.EC_POINT_NOT_ON_CURVE));
	}

	// Rule 11: a ROCA-fingerprinted modulus (CVE-2017-15361) and every Ed25519 point of small order, derived from the
	// curve by the test helper; with the identity key, R = identity, S = 0 verifies every message.
	@TestFactory
	Stream<DynamicTest> weakKeysAreSkipped() {
		KeyPair roca = TestJsonWebKeys.rocaFingerprintedRsaKeyPair();
		Assertions.assertTrue(TestJsonWebKeys.hasRocaFingerprint(((RSAPublicKey) roca.getPublic()).getModulus()));
		List<DynamicTest> tests = new ArrayList<>();
		tests.add(DynamicTest.dynamicTest("ROCA", () -> assertSkipped(JsonWebKeySkipReason.WEAK_KEY,
				TestJsonWebKeys.withKeyPair(roca).toJson())));
		List<String> smallOrder = TestJsonWebKeys.ed25519SmallOrderPublicKeys();
		Assertions.assertEquals(8, smallOrder.size());
		for (int index = 0; index < smallOrder.size(); ++index) {
			String x = smallOrder.get(index);
			tests.add(DynamicTest.dynamicTest(index + "T", () -> assertSkipped(JsonWebKeySkipReason.WEAK_KEY,
					TestJsonWebKeys.ed25519WithX(x).toJson())));
		}
		return tests.stream();
	}

	// Rule 12 (RFC 7517 section 4.7): the first x5c element is standard base64 of a certificate that parses strictly and
	// holds the same key; the rest of the chain is not examined.
	@TestFactory
	Stream<DynamicTest> x5cMustHoldTheSameKey() {
		X509Certificate rsaCertificate = Fixture.IDP_SIGNING_RSA_2048.getCertificate().orElseThrow();
		X509Certificate otherRsaCertificate = Fixture.SP_SIGNING_RSA_2048.getCertificate().orElseThrow();
		X509Certificate ecCertificate = Fixture.IDP_SIGNING_EC_P256.getCertificate().orElseThrow();
		X509Certificate p384Certificate = Fixture.IDP_SIGNING_EC_P384.getCertificate().orElseThrow();
		String rsaDer = standardBase64(rsaCertificate);

		return rows(
				row("the RSA key's own certificate", rsa().x5c(List.of(rsaCertificate)).toJson(), null),
				row("the EC key's own certificate", ec().x5c(List.of(ecCertificate)).toJson(), null),
				row("its own certificate, then anything", rsa().member("x5c", "[" + JsonText.string(rsaDer) + ",1,\"x\"]")
						.toJson(), null),
				row("another RSA key's certificate", rsa().x5c(List.of(otherRsaCertificate)).toJson(),
						JsonWebKeySkipReason.CERTIFICATE_MISMATCH),
				// e = 65539 passes the exponent rule, so only rule 12 tells this key from the certificate's (e = 65537).
				row("its modulus with another exponent", rsa().member("e", "\"AQAD\"").x5c(List.of(rsaCertificate)).toJson(),
						JsonWebKeySkipReason.CERTIFICATE_MISMATCH),
				row("its modulus with another exponent, without x5c", rsa().member("e", "\"AQAD\"").toJson(), null),
				row("another P-256 key's certificate", ec().x5c(List.of(Fixture.NEGATIVE_UNCONFIGURED_EC_P256
						.getCertificate().orElseThrow())).toJson(), JsonWebKeySkipReason.CERTIFICATE_MISMATCH),
				row("an EC certificate on an RSA key", rsa().x5c(List.of(ecCertificate)).toJson(),
						JsonWebKeySkipReason.CERTIFICATE_MISMATCH),
				row("a P-384 certificate on a P-256 key", ec().x5c(List.of(p384Certificate)).toJson(),
						JsonWebKeySkipReason.CERTIFICATE_MISMATCH),
				row("a string", rsa().member("x5c", JsonText.string(rsaDer)).toJson(),
						JsonWebKeySkipReason.CERTIFICATE_MISMATCH),
				row("an empty array", rsa().member("x5c", "[]").toJson(), JsonWebKeySkipReason.CERTIFICATE_MISMATCH),
				row("a number first", rsa().member("x5c", "[1," + JsonText.string(rsaDer) + "]").toJson(),
						JsonWebKeySkipReason.CERTIFICATE_MISMATCH),
				row("null", rsa().member("x5c", "null").toJson(), JsonWebKeySkipReason.CERTIFICATE_MISMATCH),
				row("base64url, not base64", rsa().member("x5c", "[" + JsonText.string(Base64.getUrlEncoder()
						.withoutPadding().encodeToString(der(rsaCertificate))) + "]").toJson(),
						JsonWebKeySkipReason.CERTIFICATE_MISMATCH),
				row("base64 of garbage", rsa().member("x5c", "[\"AAECAwQ=\"]").toJson(),
						JsonWebKeySkipReason.CERTIFICATE_MISMATCH),
				row("its certificate with a trailing byte", rsa().member("x5c", "[" + JsonText.string(Base64.getEncoder()
						.encodeToString(concat(der(rsaCertificate), new byte[1]))) + "]").toJson(),
						JsonWebKeySkipReason.CERTIFICATE_MISMATCH));
	}

	// The certificate comparison is by value, for every key type, and a key implementation that throws compares as
	// different.
	@Test
	void keysCompareByValueForTheCertificateCheck() throws Exception {
		PublicKey rsa = Fixture.IDP_SIGNING_RSA_2048.getPublicKey();
		PublicKey ec = Fixture.IDP_SIGNING_EC_P256.getPublicKey();
		PublicKey ed = Fixture.ED25519.getPublicKey();
		PublicKey rebuiltEd = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(ed.getEncoded()));

		Assertions.assertTrue(JwkParser.isSameKey(rsa, parse(TestJsonWebKeys.withFixture(
				Fixture.IDP_SIGNING_RSA_2048).toJson()).publicKey()));
		Assertions.assertTrue(JwkParser.isSameKey(ec, parse(ec().toJson()).publicKey()));
		Assertions.assertTrue(JwkParser.isSameKey(ed, rebuiltEd));
		Assertions.assertTrue(JwkParser.isSameKey(parse(ed25519().toJson()).publicKey(), ed));
		Assertions.assertFalse(JwkParser.isSameKey(ed, generate("Ed25519").getPublic()));
		Assertions.assertFalse(JwkParser.isSameKey(ed, generate("Ed448").getPublic()));
		Assertions.assertFalse(JwkParser.isSameKey(rsa, ec));
		Assertions.assertFalse(JwkParser.isSameKey(ec, rsa));
		Assertions.assertFalse(JwkParser.isSameKey(ed, rsa));
		Assertions.assertFalse(JwkParser.isSameKey(rsa, null));
		Assertions.assertFalse(JwkParser.isSameKey(ec, Fixture.IDP_SIGNING_EC_P384.getPublicKey()));
		Assertions.assertFalse(JwkParser.isSameKey(rsa, Fixture.SP_SIGNING_RSA_2048.getPublicKey()));
		Assertions.assertFalse(JwkParser.isSameKey(generate("X25519").getPublic(), generate("X25519").getPublic()));
		Assertions.assertFalse(JwkParser.isSameKey(rsa, new ThrowingRsaKey()));

		// Each part of each key's value counts: the RSA exponent with the same modulus, the EC point on the same curve,
		// and the sign of the Ed25519 x coordinate with the same y (the point -A).
		PublicKey otherExponent = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
				((RSAPublicKey) rsa).getModulus(), BigInteger.valueOf(3)));
		Assertions.assertFalse(JwkParser.isSameKey(rsa, otherExponent));
		Assertions.assertFalse(JwkParser.isSameKey(ec, Fixture.NEGATIVE_UNCONFIGURED_EC_P256.getPublicKey()));
		EdECPoint point = ((EdECPublicKey) ed).getPoint();
		PublicKey negated = KeyFactory.getInstance("Ed25519").generatePublic(new EdECPublicKeySpec(
				NamedParameterSpec.ED25519, new EdECPoint(!point.isXOdd(), point.getY())));
		Assertions.assertFalse(JwkParser.isSameKey(ed, negated));
	}

	// Rules run in order: each pair below breaks two rules, and the earlier one names the reason.
	@TestFactory
	Stream<DynamicTest> theFirstFailingRuleNamesTheReason() {
		KeyPair roca = TestJsonWebKeys.rocaFingerprintedRsaKeyPair();
		X509Certificate otherCertificate = Fixture.SP_SIGNING_RSA_2048.getCertificate().orElseThrow();

		return rows(
				row("1 before 3: no kty, and d", rsa().withoutMember("kty").member("d", "\"AQAB\"").toJson(),
						JsonWebKeySkipReason.MALFORMED_KEY),
				row("2 before 3: oct with k", TestJsonWebKeys.octWithK("GawgguFyGrWKav7AX4VKUg").toJson(),
						JsonWebKeySkipReason.SYMMETRIC_KEY),
				row("3 before 4: d, and use enc", rsa().member("d", "\"AQAB\"").use("enc").toJson(),
						JsonWebKeySkipReason.PRIVATE_KEY_MEMBERS),
				row("4 before 5: use enc, and alg RSA-OAEP", rsa().use("enc").alg("RSA-OAEP").toJson(),
						JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY),
				row("5 before 6: alg ES521, and crv secp256k1", ec().alg("ES521").member("crv", "\"secp256k1\"").toJson(),
						JsonWebKeySkipReason.UNSUPPORTED_ALGORITHM),
				// Such keys as they are usually published: secp256k1 with RFC 8812's ES256K, X25519 for ECDH-ES or use enc.
				row("5 before 6: alg ES256K, and crv secp256k1", ec().alg("ES256K").member("crv", "\"secp256k1\"").toJson(),
						JsonWebKeySkipReason.UNSUPPORTED_ALGORITHM),
				row("5 before 6: alg ECDH-ES, and crv X25519", ed25519().alg("ECDH-ES").member("crv", "\"X25519\"")
						.toJson(), JsonWebKeySkipReason.UNSUPPORTED_ALGORITHM),
				row("4 before 6: use enc, and crv X25519", ed25519().use("enc").member("crv", "\"X25519\"").toJson(),
						JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY),
				row("5 before 7: alg ES384 on P-256, and a 31-byte x", TestJsonWebKeys.ecWithShortX().alg("ES384").toJson(),
						JsonWebKeySkipReason.ALGORITHM_MISMATCH),
				row("6 before 7: crv secp256k1, and kid empty", ec().member("crv", "\"secp256k1\"").kid("").toJson(),
						JsonWebKeySkipReason.UNSUPPORTED_CURVE),
				row("7 before 8: RSA-1024 with an empty kid", TestJsonWebKeys.withFixture(Fixture.NEGATIVE_RSA_1024).kid("")
						.toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("7 before 8: RSA-1024 with a null issuer", TestJsonWebKeys.withFixture(Fixture.NEGATIVE_RSA_1024)
						.member("issuer", "null").toJson(), JsonWebKeySkipReason.MALFORMED_KEY),
				row("8 before 9: RSA-1024 with e = 3", TestJsonWebKeys.withFixture(Fixture.NEGATIVE_RSA_1024).member("e",
						JsonText.string(TestJsonWebKeys.base64UrlUInt(BigInteger.valueOf(3)))).toJson(),
						JsonWebKeySkipReason.RSA_KEY_SIZE),
				row("9 before 11: ROCA with e = 3", TestJsonWebKeys.withKeyPair(roca).member("e",
						JsonText.string(TestJsonWebKeys.base64UrlUInt(BigInteger.valueOf(3)))).toJson(),
						JsonWebKeySkipReason.RSA_EXPONENT),
				row("10 before 12: off the curve, with another key's certificate", TestJsonWebKeys.ecOffCurve()
						.x5c(List.of(otherCertificate)).toJson(), JsonWebKeySkipReason.EC_POINT_NOT_ON_CURVE),
				row("11 before 12: ROCA with another key's certificate", TestJsonWebKeys.withKeyPair(roca)
						.x5c(List.of(otherCertificate)).toJson(), JsonWebKeySkipReason.WEAK_KEY));
	}

	private static TestJsonWebKeys.Builder rsa() {
		return TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048);
	}

	private static TestJsonWebKeys.Builder ec() {
		return TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P256);
	}

	private static TestJsonWebKeys.Builder ed25519() {
		return TestJsonWebKeys.withFixture(Fixture.ED25519);
	}

	static JsonObject jwk(String json) {
		try {
			return (JsonObject) JsonCodec.parse(json.getBytes(StandardCharsets.UTF_8), JsonLimits.protocolDocument(
					4 * 1024 * 1024));
		} catch (Exception e) {
			throw new IllegalArgumentException("Not a JSON object: " + json, e);
		}
	}

	static VerificationKey parse(String json) throws SkippedKeyException {
		return JwkParser.parse(jwk(json));
	}

	static void assertSkipped(JsonWebKeySkipReason reason, String json) {
		SkippedKeyException exception = Assertions.assertThrows(SkippedKeyException.class, () -> parse(json));
		Assertions.assertEquals(reason, exception.getReason());
		Assertions.assertNull(exception.getCause());
		Assertions.assertEquals(0, exception.getStackTrace().length, "a skip records no stack trace");
		Assertions.assertFalse(String.valueOf(exception.getMessage()).contains("{"),
				"a skip's message never holds the key");
	}

	private static Stream<DynamicTest> rows(Row... rows) {
		return Stream.of(rows).map(row -> DynamicTest.dynamicTest(row.name(), () -> {
			JsonWebKeySkipReason reason = row.reason();
			if (reason == null)
				Assertions.assertNotNull(parse(row.json()));
			else
				assertSkipped(reason, row.json());
		}));
	}

	private static Row row(String name, String json, @Nullable JsonWebKeySkipReason reason) {
		return new Row(name, json, reason);
	}

	private record Row(String name, String json, @Nullable JsonWebKeySkipReason reason) {
	}

	private static @Nullable String expectedCurve(PublicKey publicKey) {
		if (publicKey instanceof ECPublicKey ec)
			return switch (ec.getParams().getCurve().getField().getFieldSize()) {
				case 256 -> "P-256";
				case 384 -> "P-384";
				default -> "P-521";
			};
		return publicKey.getAlgorithm().equals("RSA") ? null : "Ed25519";
	}

	/**
	 * RFC 7638 section 3, computed here apart from Rfc7638: the required members sorted by name, compact, then SHA-256
	 * and unpadded base64url.
	 */
	private static String thumbprintOf(String json) throws Exception {
		JsonObject object = jwk(json);
		String keyType = object.findString("kty").orElseThrow();
		List<String> names = switch (keyType) {
			case "RSA" -> List.of("e", "kty", "n");
			case "EC" -> List.of("crv", "kty", "x", "y");
			default -> List.of("crv", "kty", "x");
		};
		List<Map.Entry<String, String>> members = new ArrayList<>();
		for (String name : names)
			members.add(Map.entry(name, object.find(name).orElseThrow().toJson()));
		byte[] digest = MessageDigest.getInstance("SHA-256").digest(JsonText.object(members)
				.getBytes(StandardCharsets.UTF_8));
		return TestJws.base64Url(digest);
	}

	private static KeyPair generate(String algorithm) throws GeneralSecurityException {
		return KeyPairGenerator.getInstance(algorithm).generateKeyPair();
	}

	private static byte[] der(X509Certificate certificate) {
		try {
			return certificate.getEncoded();
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}

	private static String standardBase64(X509Certificate certificate) {
		return Base64.getEncoder().encodeToString(der(certificate));
	}

	private static byte[] concat(byte[] first, byte[] second) {
		byte[] joined = new byte[first.length + second.length];
		System.arraycopy(first, 0, joined, 0, first.length);
		System.arraycopy(second, 0, joined, first.length, second.length);
		return joined;
	}

	/**
	 * An RSA key implementation that throws from its accessors, as a provider outside the JDK might.
	 */
	private static final class ThrowingRsaKey implements RSAPublicKey {
		private static final long serialVersionUID = 1L;

		@Override
		public BigInteger getPublicExponent() {
			throw new IllegalStateException("unavailable");
		}

		@Override
		public String getAlgorithm() {
			return "RSA";
		}

		@Override
		public @Nullable String getFormat() {
			return null;
		}

		@Override
		public byte @Nullable [] getEncoded() {
			return null;
		}

		@Override
		public BigInteger getModulus() {
			throw new IllegalStateException("unavailable");
		}
	}
}
