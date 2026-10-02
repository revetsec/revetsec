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
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws.Algorithm;
import com.revetsec.testing.TestJws.Signed;
import com.revetsec.testing.TestJws.Variant;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Tests {@link TestJws}: every algorithm signs a signing input the JDK's own engines verify (RFC 7515 section 5.1,
 * RFC 7518 section 3, RFC 8037 section 3.1), the committed Ed25519 fixture is reproduced from the RFC 8037 key, and
 * each hostile variant writes exactly the defect it names (plan M2 exit criteria 1, 4 and 6; CVE-2022-21449).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class TestJwsTests {
	private static final Pattern CANONICAL_SEGMENT = Pattern.compile("[A-Za-z0-9_-]*");
	private static final String PAYLOAD = "{\"iss\":\"https://issuer.example\",\"sub\":\"248289761001\"}";
	private static final byte[] HMAC_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			.getBytes(StandardCharsets.US_ASCII);

	/**
	 * RFC 8037 appendix A.1's Ed25519 private key {@code d}.
	 */
	private static final String RFC_8037_PRIVATE_KEY = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";

	/**
	 * RFC 8037 appendix A.4's payload, "Example of Ed25519 signing".
	 */
	private static final String RFC_8037_PAYLOAD = "Example of Ed25519 signing";

	/**
	 * The JDK engine each algorithm must sign with (RFC 7518 sections 3.3 to 3.5, RFC 8037 section 3.1), written out
	 * here rather than read from the helper, so a wrong hash in the helper fails verification instead of agreeing
	 * with itself.
	 */
	private static final Map<Algorithm, String> JDK_ENGINES = jdkEngines();

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> everyAlgorithmSignsWhatTheJdkVerifies() {
		return Arrays.stream(Algorithm.values()).map(algorithm -> DynamicTest.dynamicTest(algorithm.name(), () -> {
			Signed signed = sign(algorithm);
			String token = signed.toCompactSerialization();
			String[] segments = token.split("\\.", -1);

			Assertions.assertEquals(3, segments.length, token);
			for (String segment : segments)
				Assertions.assertTrue(CANONICAL_SEGMENT.matcher(segment).matches(), segment);
			Assertions.assertEquals("{\"alg\":\"" + algorithm.getWireValue() + "\",\"kid\":\"k-1\",\"typ\":\"JWT\"}",
					decode(segments[0]));
			Assertions.assertEquals(PAYLOAD, decode(segments[1]));
			Assertions.assertEquals(segments[0] + "." + segments[1], signed.getSigningInput());
			Assertions.assertArrayEquals(signed.getSignature(), Base64.getUrlDecoder().decode(segments[2]));
			Assertions.assertEquals(algorithm.signatureLength(signingKey(algorithm)), signed.getSignature().length);
			Assertions.assertTrue(jdkVerifies(algorithm, signed.getSigningInput(), signed.getSignature()));
			Assertions.assertFalse(jdkVerifies(algorithm, signed.getSigningInput() + "x", signed.getSignature()),
					"the signature covers the signing input");
		}));
	}

	@Test
	void everyAlgorithmNamesTheJdkEngineForItsHash() {
		Assertions.assertEquals(Set.of(Algorithm.values()), JDK_ENGINES.keySet());
		for (Map.Entry<Algorithm, String> entry : JDK_ENGINES.entrySet())
			Assertions.assertEquals(entry.getValue(), entry.getKey().getJcaName(), entry.getKey().name());
	}

	@Test
	void reproducesTheCommittedEd25519FixtureAndRfc8037AppendixA4FromTheAppendixA1Key() throws Exception {
		// RFC 8037 A.4 signs {"alg":"EdDSA"}; the plan's committed fixture re-signs the payload under
		// {"alg":"Ed25519"}.
		byte[] prefix = HexFormat.of().parseHex("302e020100300506032b657004220420");
		byte[] seed = Base64.getUrlDecoder().decode(RFC_8037_PRIVATE_KEY);
		byte[] pkcs8 = new byte[prefix.length + seed.length];
		System.arraycopy(prefix, 0, pkcs8, 0, prefix.length);
		System.arraycopy(seed, 0, pkcs8, prefix.length, seed.length);
		PrivateKey key = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));

		Assertions.assertEquals("eyJhbGciOiJFZDI1NTE5In0.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc."
						+ "UxhIYLHGg39NVCLpQAVD_UcfOmnGSCzLFZoXYkLiIbFccmOb_qObsgjzLKsfJw-4NlccUgvYrEHrRbNV0HcZAQ",
				TestJws.withAlgorithm(Algorithm.ED25519).payload(RFC_8037_PAYLOAD).sign(key));
		Assertions.assertEquals("eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc."
						+ "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg",
				TestJws.withAlgorithm(Algorithm.EDDSA).payload(RFC_8037_PAYLOAD).sign(key));
	}

	@Test
	void pssSignaturesUseTheRfc7518Parameters() throws Exception {
		// RFC 7518 section 3.5: MGF1 with the same hash, a salt as long as the hash, trailer field 1.
		Map<Algorithm, List<Object>> expected = new LinkedHashMap<>();
		expected.put(Algorithm.PS256, List.of("SHA-256", 32));
		expected.put(Algorithm.PS384, List.of("SHA-384", 48));
		expected.put(Algorithm.PS512, List.of("SHA-512", 64));
		for (Map.Entry<Algorithm, List<Object>> entry : expected.entrySet()) {
			PSSParameterSpec parameters = entry.getKey().getPssParameters().orElseThrow();
			Assertions.assertEquals(entry.getValue().get(0), parameters.getDigestAlgorithm());
			Assertions.assertEquals("MGF1", parameters.getMGFAlgorithm());
			Assertions.assertEquals(entry.getValue().get(0),
					((MGF1ParameterSpec) parameters.getMGFParameters()).getDigestAlgorithm());
			Assertions.assertEquals(entry.getValue().get(1), parameters.getSaltLength());
			Assertions.assertEquals(1, parameters.getTrailerField());
		}
		Assertions.assertTrue(Algorithm.RS256.getPssParameters().isEmpty());
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> derVariantIsTheSameEcdsaSignatureInTheFormTheJdkPlainEngineAccepts() {
		// Plan M2 exit criterion 1 (a DER ES256 fixture): an IdP that sends DER instead of R || S (RFC 7518 section
		// 3.4).
		return Stream.of(Algorithm.ES256, Algorithm.ES384, Algorithm.ES512)
				.map(algorithm -> DynamicTest.dynamicTest(algorithm.name(), () -> {
					Signed signed = sign(algorithm);
					byte[] der = signature(signed.withVariant(Variant.DER_SIGNATURE));

					Assertions.assertEquals(0x30, der[0] & 0xff, "a DER SEQUENCE");
					Assertions.assertNotEquals(signed.getSignature().length, der.length);
					Signature plain = Signature.getInstance(engine(algorithm).replace("inP1363Format", ""));
					plain.initVerify(fixture(algorithm).getPublicKey());
					plain.update(signed.getSigningInput().getBytes(StandardCharsets.US_ASCII));
					Assertions.assertTrue(plain.verify(der));
				}));
	}

	@Test
	void derEncodingIsMinimalAndPadsAHighBitWithAZeroOctet() {
		// X.690 section 8.3.2: an INTEGER's content is minimal two's complement, so a positive value whose top bit is
		// set gains a leading zero octet, and leading zero octets otherwise go.
		byte[] highBit = TestJws.ecdsaSignature(BigInteger.TWO.pow(255), BigInteger.ONE, 32);
		Assertions.assertEquals("3026" + "022100" + "80" + "00".repeat(31) + "020101",
				HexFormat.of().formatHex(TestJws.derEncodedEcdsaSignature(highBit)));
		byte[] zeroR = TestJws.ecdsaSignature(BigInteger.ZERO, BigInteger.valueOf(0x7f), 32);
		Assertions.assertEquals("3006" + "020100" + "02017f",
				HexFormat.of().formatHex(TestJws.derEncodedEcdsaSignature(zeroR)));
		// A P-521 sequence is longer than 127 octets, so its length takes the long form (X.690 section 8.1.3.5).
		BigInteger n = TestJws.curveOrder(Algorithm.ES512);
		byte[] large = TestJws.ecdsaSignature(n.subtract(BigInteger.ONE), n.subtract(BigInteger.ONE), 66);
		byte[] minimal = n.subtract(BigInteger.ONE).toByteArray();
		Assertions.assertEquals(66, minimal.length, "n - 1 has 521 bits, so its top octet is 0x01 and needs no pad");
		Assertions.assertEquals("308188" + "0242" + HexFormat.of().formatHex(minimal) + "0242"
				+ HexFormat.of().formatHex(minimal), HexFormat.of().formatHex(TestJws.derEncodedEcdsaSignature(large)));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> ecdsaRangeVariantsSetROrSToExactlyTheNamedValue() {
		// Plan M2 exit criterion 6 and CVE-2022-21449: r = 0, r = n, s = n, r = n + 1 and all-zero signatures.
		List<DynamicTest> tests = new ArrayList<>();
		for (Algorithm algorithm : List.of(Algorithm.ES256, Algorithm.ES384, Algorithm.ES512)) {
			BigInteger n = TestJws.curveOrder(algorithm);
			Map<Variant, List<BigInteger>> cases = new LinkedHashMap<>();
			cases.put(Variant.R_ZERO, List.of(BigInteger.ZERO));
			cases.put(Variant.S_ZERO, List.of(BigInteger.ZERO));
			cases.put(Variant.R_EQUALS_ORDER, List.of(n));
			cases.put(Variant.S_EQUALS_ORDER, List.of(n));
			cases.put(Variant.R_ORDER_PLUS_ONE, List.of(n.add(BigInteger.ONE)));
			cases.put(Variant.ZERO_SIGNATURE, List.of(BigInteger.ZERO, BigInteger.ZERO));
			for (Map.Entry<Variant, List<BigInteger>> entry : cases.entrySet())
				tests.add(DynamicTest.dynamicTest(algorithm + " " + entry.getKey(), () -> {
					Signed signed = sign(algorithm);
					byte[] original = signed.getSignature();
					byte[] hostile = signature(signed.withVariant(entry.getKey()));
					BigInteger expected = entry.getValue().get(0);

					Assertions.assertEquals(original.length, hostile.length, "the length is unchanged");
					boolean changesS = entry.getKey() == Variant.S_ZERO || entry.getKey() == Variant.S_EQUALS_ORDER;
					Assertions.assertEquals(changesS ? TestJws.ecdsaR(original) : expected, TestJws.ecdsaR(hostile));
					Assertions.assertEquals(changesS ? expected
									: entry.getValue().size() == 2 ? BigInteger.ZERO : TestJws.ecdsaS(original),
							TestJws.ecdsaS(hostile));
				}));
		}
		return tests.stream();
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> lengthVariantsWriteSixtyThreeAndSixtyFiveOctetsForEs256AndEd25519() {
		return Stream.of(Algorithm.ES256, Algorithm.ED25519, Algorithm.EDDSA)
				.map(algorithm -> DynamicTest.dynamicTest(algorithm.name(), () -> {
					Signed signed = sign(algorithm);
					byte[] original = signed.getSignature();

					byte[] shorter = signature(signed.withVariant(Variant.ONE_OCTET_SHORT));
					byte[] longer = signature(signed.withVariant(Variant.ONE_OCTET_LONG));
					Assertions.assertEquals(63, shorter.length);
					Assertions.assertArrayEquals(Arrays.copyOf(original, 63), shorter);
					Assertions.assertEquals(65, longer.length);
					Assertions.assertArrayEquals(original, Arrays.copyOf(longer, 64));
					Assertions.assertEquals(0, longer[64]);
					Assertions.assertArrayEquals(new byte[64], signature(signed.withVariant(Variant.ZERO_SIGNATURE)));
					Assertions.assertEquals(signed.getSigningInput() + ".",
							signed.withVariant(Variant.EMPTY_SIGNATURE));
				}));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> aFlippedBitKeepsTheShapeAndFailsJdkVerification() {
		return Arrays.stream(Algorithm.values()).map(algorithm -> DynamicTest.dynamicTest(algorithm.name(), () -> {
			Signed signed = sign(algorithm);
			byte[] flipped = signature(signed.withVariant(Variant.FLIPPED_BIT));
			byte[] original = signed.getSignature();

			Assertions.assertEquals(original.length, flipped.length);
			Assertions.assertEquals(1, original[original.length - 1] ^ flipped[flipped.length - 1]);
			Assertions.assertArrayEquals(Arrays.copyOf(original, original.length - 1),
					Arrays.copyOf(flipped, flipped.length - 1));
			Assertions.assertFalse(jdkVerifies(algorithm, signed.getSigningInput(), flipped));
		}));
	}

	@Test
	void segmentVariantsWriteExtraSegmentsPaddingAndForeignCharacters() {
		// Plan M2 "JOSE semantics" steps 2 and 3: segment count and canonical base64url.
		Signed signed = sign(Algorithm.RS256);
		String header = signed.getHeaderSegment();
		String payload = signed.getPayloadSegment();
		String signature = signed.getSignatureSegment();

		Assertions.assertEquals(header + "." + payload + "." + signature + ".e30",
				signed.withVariant(Variant.EXTRA_SEGMENT));
		Assertions.assertEquals(4, signed.withVariant(Variant.FIVE_SEGMENTS).chars().filter(c -> c == '.').count());
		Assertions.assertEquals(TestJws.padded(header) + "." + payload + "." + signature,
				signed.withVariant(Variant.PADDED_HEADER));
		Assertions.assertEquals(header + "." + TestJws.padded(payload) + "." + signature,
				signed.withVariant(Variant.PADDED_PAYLOAD));
		Assertions.assertEquals(header + "." + payload + "." + TestJws.padded(signature),
				signed.withVariant(Variant.PADDED_SIGNATURE));
		Assertions.assertEquals(header + "." + payload + ".+" + signature.substring(1),
				signed.withVariant(Variant.PLUS_IN_SIGNATURE));
		Assertions.assertEquals(header + "." + payload + "./" + signature.substring(1),
				signed.withVariant(Variant.SLASH_IN_SIGNATURE));
	}

	@Test
	void paddingAddsWhatStandardBase64WouldOrOneEqualsSign() {
		Assertions.assertEquals("QQ==", TestJws.padded("QQ"));
		Assertions.assertEquals("QUI=", TestJws.padded("QUI"));
		Assertions.assertEquals("QUJD=", TestJws.padded("QUJD"));
		Assertions.assertEquals("=", TestJws.padded(""));
	}

	@Test
	void nonCanonicalTrailingBitsDecodeLenientlyToTheSameBytes() {
		// RFC 4648 section 3.5: a lenient decoder ignores the unused bits a canonical one requires to be zero.
		Signed signed = sign(Algorithm.RS256);
		String canonical = signed.getSignatureSegment();
		// 256 octets are 342 characters, whose last carries 2 data bits and 4 unused ones.
		String nonCanonical = split(signed.withVariant(Variant.NON_CANONICAL_SIGNATURE))[2];

		Assertions.assertNotEquals(canonical, nonCanonical);
		Assertions.assertEquals(canonical.substring(0, canonical.length() - 1),
				nonCanonical.substring(0, nonCanonical.length() - 1));
		Assertions.assertArrayEquals(signed.getSignature(), Base64.getUrlDecoder().decode(nonCanonical));
		Assertions.assertEquals("QR", TestJws.withNonCanonicalTrailingBits("QQ"));
		Assertions.assertEquals("QUJ", TestJws.withNonCanonicalTrailingBits("QUI"));
		Assertions.assertThrows(IllegalStateException.class, () -> TestJws.withNonCanonicalTrailingBits("QUJD"));
		Assertions.assertThrows(IllegalArgumentException.class, () -> TestJws.withNonCanonicalTrailingBits("QR"));
		Assertions.assertThrows(IllegalArgumentException.class, () -> TestJws.withNonCanonicalTrailingBits("Q+"),
				"not a base64url character");
		// ES384 signatures are 96 octets, 128 characters with no unused bits.
		Assertions.assertThrows(IllegalStateException.class,
				() -> sign(Algorithm.ES384).withVariant(Variant.NON_CANONICAL_SIGNATURE));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> ecdsaOnlyVariantsRefuseOtherAlgorithms() {
		List<Variant> ecdsaOnly = List.of(Variant.DER_SIGNATURE, Variant.R_ZERO, Variant.S_ZERO, Variant.R_EQUALS_ORDER,
				Variant.S_EQUALS_ORDER, Variant.R_ORDER_PLUS_ONE);
		Signed rsa = sign(Algorithm.RS256);
		return ecdsaOnly.stream().map(variant -> DynamicTest.dynamicTest(variant.name(), () ->
				Assertions.assertThrows(IllegalStateException.class, () -> rsa.withVariant(variant))));
	}

	@Test
	void writesArbitraryAlgStringsDuplicateMembersAndRawHeaders() {
		// Plan M2 exit criterion 4: every spelling of none, with and without a signature.
		String none = TestJws.builder().alg("nOnE").payload(PAYLOAD).unsigned();
		Assertions.assertEquals("{\"alg\":\"nOnE\"}", decode(split(none)[0]));
		Assertions.assertTrue(none.endsWith("."));
		Assertions.assertEquals("QUJD",
				split(TestJws.builder().alg("none").withSignature(new byte[]{'A', 'B', 'C'}))[2]);
		Assertions.assertEquals("{}", decode(split(TestJws.builder().unsigned())[0]), "no alg unless set");
		Assertions.assertEquals("", split(TestJws.builder().unsigned())[1], "an empty payload by default");

		String duplicated = TestJws.withAlgorithm(Algorithm.HS256).kid("a\"b").headerMember("alg", "\"RS256\"")
				.headerMember("jku", "\"https://attacker.example/jwks\"").headerMember("kid", "123").unsigned();
		Assertions.assertEquals("{\"alg\":\"HS256\",\"kid\":\"a\\\"b\",\"alg\":\"RS256\","
				+ "\"jku\":\"https://attacker.example/jwks\",\"kid\":123}", decode(split(duplicated)[0]));

		Assertions.assertEquals("{\"alg\":\"RS256\",\"crit\":[\"exp\"]}",
				decode(split(TestJws.withAlgorithm(Algorithm.ES256).header("{\"alg\":\"RS256\",\"crit\":[\"exp\"]}")
						.kid("ignored").unsigned())[0]));
		byte[] bom = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF, '{', '}'};
		Assertions.assertArrayEquals(bom, Base64.getUrlDecoder().decode(split(TestJws.builder().headerBytes(bom)
				.unsigned())[0]));
		byte[] payload = {(byte) 0xff, 0};
		Assertions.assertArrayEquals(payload,
				Base64.getUrlDecoder().decode(split(TestJws.builder().payloadBytes(payload).unsigned())[1]));
		Assertions.assertEquals("{\"alg\":\"HS256\",\"typ\":\"at+jwt\"}",
				decode(split(TestJws.withAlgorithm(Algorithm.HS256).typ("at+jwt").unsigned())[0]));
		Assertions.assertEquals("{\"alg\":\"rs256\"}",
				decode(split(TestJws.withAlgorithm(Algorithm.RS256).alg("rs256").alg(null).alg("rs256")
						.unsigned())[0]));
		Assertions.assertEquals("{\"alg\":\"RS256\"}",
				decode(split(TestJws.withAlgorithm(Algorithm.RS256).alg("rs256").alg(null).unsigned())[0]),
				"null restores the algorithm's own wire value");
	}

	@Test
	void writesControlCharactersAndUnpairedSurrogatesInHeaderValuesAsJsonEscapes() {
		Assertions.assertEquals("{\"kid\":\"a\\u000ab\\\\\"}",
				decode(split(TestJws.builder().kid("a\nb\\").unsigned())[0]));
		// An unpaired surrogate has no UTF-8 form, so it is escaped for the parser to see; a pair is written as is.
		Assertions.assertEquals("{\"kid\":\"x\\ud800y\\udc00\"}",
				decode(split(TestJws.builder().kid("x\uD800y\uDC00").unsigned())[0]));
		Assertions.assertEquals("{\"kid\":\"\uD83D\uDE00\"}",
				decode(split(TestJws.builder().kid("\uD83D\uDE00").unsigned())[0]));
	}

	@Test
	void textThatUtf8CannotEncodeFailsInsteadOfBecomingAQuestionMark() {
		// An unpaired surrogate has no UTF-8 form; String.getBytes would write '?' and the test would parse a
		// different, well-formed value from the one it wrote.
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> TestJws.builder().payload("{\"sub\":\"\uD800\"}"));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> TestJws.builder().header("{\"kid\":\"\uDC00\"}"));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> TestJws.builder().headerMember("kid", "\"x\uD800\""));
		Assertions.assertThrows(IllegalArgumentException.class, () -> TestJws.base64Url("\uD800"));
		Key key = signingKey(Algorithm.HS256);
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> TestJws.signature(Algorithm.HS256, key, "h\u00e9ader.payload"), "a signing input is ASCII");
		// A pair encodes, and the raw-bytes setters take anything.
		Assertions.assertEquals("\uD83D\uDE00", decode(split(TestJws.builder().payload("\uD83D\uDE00").unsigned())[1]));
		byte[] cesu = {(byte) 0xed, (byte) 0xa0, (byte) 0x80};
		Assertions.assertArrayEquals(cesu,
				Base64.getUrlDecoder().decode(split(TestJws.builder().payloadBytes(cesu).unsigned())[1]));
	}

	@Test
	void nullRestoresTheGeneratedHeaderAndAnEmptyPayload() {
		String generated = decode(split(TestJws.withAlgorithm(Algorithm.RS256).kid("k").header("{}").header(null)
				.unsigned())[0]);
		Assertions.assertEquals("{\"alg\":\"RS256\",\"kid\":\"k\"}", generated);
		Assertions.assertEquals(generated, decode(split(TestJws.withAlgorithm(Algorithm.RS256).kid("k")
				.headerBytes(new byte[]{'{', '}'}).headerBytes(null).unsigned())[0]));
		Assertions.assertEquals("", split(TestJws.builder().payload(PAYLOAD).payload(null).unsigned())[1]);
		Assertions.assertEquals("", split(TestJws.builder().payloadBytes(new byte[]{1}).payloadBytes(null)
				.unsigned())[1]);
		Signed signed = sign(Algorithm.ES256);
		Assertions.assertEquals(Algorithm.ES256, signed.getAlgorithm());
	}

	@Test
	void theHeaderSegmentsAgreeWithTheSignedToken() {
		TestJws.Builder builder = TestJws.withAlgorithm(Algorithm.RS256).kid("k").payload(PAYLOAD);
		Signed signed = builder.signed(signingKey(Algorithm.RS256));
		Assertions.assertEquals(builder.headerSegment(), signed.getHeaderSegment());
		Assertions.assertEquals(builder.payloadSegment(), signed.getPayloadSegment());
		Assertions.assertEquals(builder.signingInput(), signed.getSigningInput());
		Assertions.assertEquals(signed.getSigningInput() + ".AAE", signed.withSignature(new byte[]{0, 1}));
		Assertions.assertEquals(signed.getSigningInput() + ".x y", signed.withSignatureSegment("x y"));
		Assertions.assertEquals(builder.signingInput() + ".x y", builder.withSignatureSegment("x y"));
		Assertions.assertTrue(signed.toString().contains(signed.toCompactSerialization()));
	}

	@Test
	void claimsWritesTheJsonObjectAsThePayload() throws Exception {
		JsonObject claims = JsonObject.builder().put("iss", "https://issuer.example").put("exp", 1_300_819_380L)
				.build();
		String token = TestJws.withAlgorithm(Algorithm.RS256).claims(claims).sign(signingKey(Algorithm.RS256));
		JsonObject parsed = (JsonObject) JsonCodec.parse(Base64.getUrlDecoder().decode(split(token)[1]),
				JsonLimits.jose(65_536));
		Assertions.assertEquals(JsonString.fromValue("https://issuer.example"), parsed.getMembers().get("iss"));
		Assertions.assertEquals(claims, parsed);
	}

	@Test
	void hmacSignsOverAnyBytesSoAlgorithmConfusionFixturesCanUseAPublicKey() throws Exception {
		// Plan M2 exit criterion 4: HS256 MACed with the RSA public key's DER bytes.
		byte[] publicKeyDer = Fixture.IDP_SIGNING_RSA_2048.getPublicKey().getEncoded();
		Signed signed = TestJws.withAlgorithm(Algorithm.HS256).kid("rsa").payload(PAYLOAD).signed(publicKeyDer);

		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(new SecretKeySpec(publicKeyDer, "HmacSHA256"));
		Assertions.assertArrayEquals(mac.doFinal(signed.getSigningInput().getBytes(StandardCharsets.US_ASCII)),
				signed.getSignature());
		Assertions.assertEquals(signed.toCompactSerialization(),
				TestJws.withAlgorithm(Algorithm.HS256).kid("rsa").payload(PAYLOAD).sign(publicKeyDer),
				"HMAC is deterministic");
	}

	@Test
	void refusesToSignWithoutAnAlgorithmOrWithTheWrongKind() {
		PrivateKey rsa = (PrivateKey) signingKey(Algorithm.RS256);
		Assertions.assertThrows(IllegalStateException.class, () -> TestJws.builder().sign(rsa));
		Assertions.assertThrows(IllegalStateException.class, () -> TestJws.withAlgorithm(Algorithm.RS256)
				.sign(HMAC_SECRET));
		Assertions.assertThrows(IllegalArgumentException.class, () -> TestJws.withAlgorithm(Algorithm.RS256)
				.sign(new SecretKeySpec(HMAC_SECRET, "HmacSHA256")));
		Assertions.assertThrows(IllegalStateException.class, () -> TestJws.withAlgorithm(Algorithm.ES256).sign(rsa),
				"the JDK refuses an RSA key for ECDSA");
	}

	@Test
	void ecdsaHelpersRoundTripRAndSAtFixedLength() {
		BigInteger r = BigInteger.valueOf(7);
		BigInteger s = BigInteger.TWO.pow(255);
		byte[] signature = TestJws.ecdsaSignature(r, s, 32);

		Assertions.assertEquals(64, signature.length);
		Assertions.assertEquals(7, signature[31]);
		Assertions.assertEquals((byte) 0x80, signature[32]);
		Assertions.assertEquals(r, TestJws.ecdsaR(signature));
		Assertions.assertEquals(s, TestJws.ecdsaS(signature));
		Assertions.assertThrows(IllegalArgumentException.class, () -> TestJws.ecdsaSignature(BigInteger.TWO.pow(256),
				s, 32));
		Assertions.assertThrows(IllegalArgumentException.class, () -> TestJws.ecdsaSignature(BigInteger.ONE.negate(),
				s, 32));
		Assertions.assertThrows(IllegalArgumentException.class, () -> TestJws.ecdsaR(new byte[63]));
		Assertions.assertThrows(IllegalArgumentException.class, () -> TestJws.ecdsaS(new byte[0]));
	}

	@Test
	void curveOrdersComeFromTheJdkNamedCurves() {
		// SEC 2 section 2.4.2: the order of secp256r1.
		Assertions.assertEquals(new BigInteger(
						"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16),
				TestJws.curveOrder(Algorithm.ES256));
		Assertions.assertEquals(384, TestJws.curveOrder(Algorithm.ES384).bitLength());
		Assertions.assertEquals(521, TestJws.curveOrder(Algorithm.ES512).bitLength());
		Assertions.assertThrows(IllegalArgumentException.class, () -> TestJws.curveOrder(Algorithm.RS256));
	}

	@Test
	void algorithmsDescribeTheirKeysAndSignatureLengths() {
		Map<Algorithm, List<Object>> expected = new LinkedHashMap<>();
		expected.put(Algorithm.RS256, List.of("RS256", "RSA", ""));
		expected.put(Algorithm.PS512, List.of("PS512", "RSA", ""));
		expected.put(Algorithm.ES256, List.of("ES256", "EC", "P-256", 64));
		expected.put(Algorithm.ES384, List.of("ES384", "EC", "P-384", 96));
		expected.put(Algorithm.ES512, List.of("ES512", "EC", "P-521", 132));
		expected.put(Algorithm.ED25519, List.of("Ed25519", "OKP", "Ed25519", 64));
		expected.put(Algorithm.EDDSA, List.of("EdDSA", "OKP", "Ed25519", 64));
		expected.put(Algorithm.HS256, List.of("HS256", "oct", "", 32));
		expected.put(Algorithm.HS384, List.of("HS384", "oct", "", 48));
		expected.put(Algorithm.HS512, List.of("HS512", "oct", "", 64));
		for (Map.Entry<Algorithm, List<Object>> entry : expected.entrySet()) {
			Algorithm algorithm = entry.getKey();
			Assertions.assertEquals(entry.getValue().get(0), algorithm.getWireValue());
			Assertions.assertEquals(entry.getValue().get(1), algorithm.getKeyType());
			Assertions.assertEquals(entry.getValue().get(2), algorithm.getCurve().orElse(""));
			if (entry.getValue().size() == 4)
				Assertions.assertEquals(entry.getValue().get(3), algorithm.getSignatureLength().orElseThrow());
			else
				Assertions.assertTrue(algorithm.getSignatureLength().isEmpty());
		}
		Assertions.assertEquals(256, Algorithm.RS256.signatureLength(Fixture.IDP_SIGNING_RSA_2048.getPublicKey()));
		Assertions.assertEquals(384, Algorithm.PS256.signatureLength(Fixture.IDP_SIGNING_RSA_3072.getPrivateKey()));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> Algorithm.RS256.signatureLength(Fixture.IDP_SIGNING_EC_P256.getPublicKey()));
	}

	@Test
	void compactJoinsSegmentsWithDots() {
		Assertions.assertEquals("a.b.c", TestJws.compact("a", "b", "c"));
		Assertions.assertEquals("", TestJws.compact());
		Assertions.assertEquals("QUI", TestJws.base64Url("AB"));
	}

	private static @NonNull String engine(@NonNull Algorithm algorithm) {
		return Objects.requireNonNull(JDK_ENGINES.get(algorithm), algorithm::name);
	}

	private static @NonNull Map<@NonNull Algorithm, @NonNull String> jdkEngines() {
		Map<Algorithm, String> engines = new LinkedHashMap<>();
		engines.put(Algorithm.RS256, "SHA256withRSA");
		engines.put(Algorithm.RS384, "SHA384withRSA");
		engines.put(Algorithm.RS512, "SHA512withRSA");
		engines.put(Algorithm.PS256, "RSASSA-PSS");
		engines.put(Algorithm.PS384, "RSASSA-PSS");
		engines.put(Algorithm.PS512, "RSASSA-PSS");
		engines.put(Algorithm.ES256, "SHA256withECDSAinP1363Format");
		engines.put(Algorithm.ES384, "SHA384withECDSAinP1363Format");
		engines.put(Algorithm.ES512, "SHA512withECDSAinP1363Format");
		engines.put(Algorithm.ED25519, "Ed25519");
		engines.put(Algorithm.EDDSA, "Ed25519");
		engines.put(Algorithm.HS256, "HmacSHA256");
		engines.put(Algorithm.HS384, "HmacSHA384");
		engines.put(Algorithm.HS512, "HmacSHA512");
		return Map.copyOf(engines);
	}

	private static @NonNull Signed sign(@NonNull Algorithm algorithm) {
		TestJws.Builder builder = TestJws.withAlgorithm(algorithm).kid("k-1").typ("JWT").payload(PAYLOAD);
		return algorithm.getKeyType().equals("oct") ? builder.signed(HMAC_SECRET)
				: builder.signed(signingKey(algorithm));
	}

	private static @NonNull Key signingKey(@NonNull Algorithm algorithm) {
		return algorithm.getKeyType().equals("oct") ? new SecretKeySpec(HMAC_SECRET, engine(algorithm))
				: fixture(algorithm).getPrivateKey();
	}

	private static @NonNull Fixture fixture(@NonNull Algorithm algorithm) {
		return switch (algorithm) {
			case RS256, RS384, RS512, PS256, PS384, PS512 -> Fixture.IDP_SIGNING_RSA_2048;
			case ES256 -> Fixture.IDP_SIGNING_EC_P256;
			case ES384 -> Fixture.IDP_SIGNING_EC_P384;
			case ES512 -> Fixture.IDP_SIGNING_EC_P521;
			case ED25519, EDDSA -> Fixture.ED25519;
			case HS256, HS384, HS512 -> throw new IllegalArgumentException("HMAC has no fixture key");
		};
	}

	/**
	 * Verifies with the JDK's own engine, never through TestJws's signing path.
	 */
	private static boolean jdkVerifies(@NonNull Algorithm algorithm, @NonNull String signingInput, byte @NonNull [] signature)
			throws GeneralSecurityException {
		byte[] input = signingInput.getBytes(StandardCharsets.US_ASCII);
		String engine = engine(algorithm);
		if (algorithm.getKeyType().equals("oct")) {
			Mac mac = Mac.getInstance(engine);
			mac.init(new SecretKeySpec(HMAC_SECRET, engine));
			return MessageDigest.isEqual(mac.doFinal(input), signature);
		}
		KeyPair keyPair = fixture(algorithm).getKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		Signature verifier = Signature.getInstance(engine);
		if (algorithm.getPssParameters().isPresent())
			verifier.setParameter(algorithm.getPssParameters().get());
		verifier.initVerify(publicKey);
		verifier.update(input);
		try {
			return verifier.verify(signature);
		} catch (SignatureException e) {
			return false;
		}
	}

	private static byte @NonNull [] signature(@NonNull String token) {
		return Base64.getUrlDecoder().decode(split(token)[2]);
	}

	private static @NonNull String @NonNull [] split(@NonNull String token) {
		return token.split("\\.", -1);
	}

	private static @NonNull String decode(@NonNull String segment) {
		return new String(Base64.getUrlDecoder().decode(segment), StandardCharsets.UTF_8);
	}
}
