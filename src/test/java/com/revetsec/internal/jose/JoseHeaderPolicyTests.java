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

import org.jspecify.annotations.NonNull;

import com.revetsec.internal.json.AsciiCase;
import com.revetsec.jose.JoseException;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.testing.JsonText;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SplittableRandom;
import java.util.stream.Stream;

/**
 * {@link JoseHeaderPolicy}: the header checks P3 to P8 in their fixed order (plan "JOSE semantics", step 4; RFC 7515
 * sections 4 and 5.2; RFC 8725 sections 3.1, 3.2, 3.7, 3.10 and 3.11), and {@code typ} as a media type compared after
 * folding ASCII letters only, with {@code application/} implied (M2-4; RFC 7515 section 4.1.9, read 2026-09-28: typ
 * declares a media type, whose type and subtype are case-insensitive under RFC 2045, and a recipient treats a value
 * without {@code /} as if {@code application/} were prepended).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JoseHeaderPolicyTests {
	private static final JoseHeaderPolicy DEFAULT = JoseHeaderPolicy.fromSettings(65_536, Set.of(JwsAlgorithm.RS256),
			Set.of("JWT"), false);

	// A header that passes gives its alg, its kid and its typ as received, not normalized.
	@Test
	void aHeaderThatPassesGivesItsAlgorithmKidAndType() throws JoseFailure {
		Assertions.assertEquals(new JoseHeader(JwsAlgorithm.RS256, "k", "application/JWT"),
				DEFAULT.check(bytes("{\"alg\":\"RS256\",\"kid\":\"k\",\"typ\":\"application/JWT\"}")));
		Assertions.assertEquals(new JoseHeader(JwsAlgorithm.RS256, null, null),
				DEFAULT.check(bytes("{\"alg\":\"RS256\"}")));
		Assertions.assertEquals("JoseHeader{algorithm=RS256, keyIdPresent=true, typePresent=false}",
				new JoseHeader(JwsAlgorithm.RS256, "secret-kid", null).toString());
		Assertions.assertEquals("JoseHeader{algorithm=ES256, keyIdPresent=false, typePresent=true}",
				new JoseHeader(JwsAlgorithm.ES256, null, "JWT").toString());
	}

	// RFC 7515 section 5.2 step 3 and RFC 8725 section 3.7: the header is a strict UTF-8 JSON object; a BOM,
	// ill-formed UTF-8, a lone surrogate escape, a duplicate member, another JSON type, trailing text or nesting past
	// the depth limit is HEADER.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> aHeaderThatIsNotAStrictJsonObjectIsMalformed() {
		Map<String, byte[]> cases = new LinkedHashMap<>();
		cases.put("empty", new byte[0]);
		cases.put("an array", bytes("[\"RS256\"]"));
		cases.put("a string", bytes("\"RS256\""));
		cases.put("a number", bytes("256"));
		cases.put("null", bytes("null"));
		cases.put("trailing text", bytes("{\"alg\":\"RS256\"}x"));
		cases.put("two objects", bytes("{\"alg\":\"RS256\"}{}"));
		cases.put("a byte-order mark", concat(new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF},
				bytes("{\"alg\":\"RS256\"}")));
		cases.put("ill-formed UTF-8", concat(bytes("{\"alg\":\"RS256\",\"x\":\""), new byte[]{(byte) 0xC0, (byte) 0xAF},
				bytes("\"}")));
		cases.put("an encoded surrogate", concat(bytes("{\"alg\":\"RS256\",\"x\":\""), new byte[]{(byte) 0xED,
				(byte) 0xA0, (byte) 0x80}, bytes("\"}")));
		cases.put("a lone surrogate escape", bytes("{\"alg\":\"RS256\",\"x\":\"\\ud800\"}"));
		cases.put("a duplicate alg", bytes("{\"alg\":\"RS256\",\"alg\":\"RS256\"}"));
		cases.put("a duplicate alg after unescaping", bytes("{\"alg\":\"RS256\",\"\\u0061lg\":\"RS256\"}"));
		cases.put("a duplicate ignored member", bytes("{\"alg\":\"RS256\",\"x\":1,\"x\":1}"));
		cases.put("33 levels deep", bytes("{\"alg\":\"RS256\",\"x\":" + "[".repeat(32) + "]".repeat(32) + "}"));
		cases.put("1,000 levels deep", bytes("{\"alg\":\"RS256\",\"x\":" + "[".repeat(1_000) + "]".repeat(1_000) + "}"));
		cases.put("a single quote", bytes("{'alg':'RS256'}"));
		cases.put("a trailing comma", bytes("{\"alg\":\"RS256\",}"));

		return cases.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(),
				() -> assertFailure(JoseException.Reason.HEADER, DEFAULT, entry.getValue())));
	}

	// The depth limit is 32 (JSON_DEPTH_PROTOCOL): the header object and 31 nested arrays pass.
	@Test
	void aHeaderAtTheDepthLimitPasses() throws JoseFailure {
		Assertions.assertEquals(JwsAlgorithm.RS256, DEFAULT.check(bytes("{\"alg\":\"RS256\",\"x\":" + "[".repeat(31)
				+ "]".repeat(31) + "}")).algorithm());
	}

	// P4: alg missing or not a string is HEADER.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> anAlgThatIsMissingOrNotAStringIsMalformed() {
		return Stream.of("{}", "{\"alg\":null}", "{\"alg\":256}", "{\"alg\":[\"RS256\"]}", "{\"alg\":{}}",
				"{\"alg\":true}", "{\"ALG\":\"RS256\"}", "{\"typ\":\"JWT\"}").map(json -> DynamicTest.dynamicTest(json,
				() -> assertFailure(JoseException.Reason.HEADER, DEFAULT, bytes(json))));
	}

	// P4 (RFC 8725 sections 3.1 and 3.2; G8-2): alg must name an algorithm in the effective set exactly. none in any
	// case, a case or whitespace variant, the JWE and unsupported names, and an algorithm outside the set are
	// ALGORITHM_NOT_ALLOWED; the EdDSA/Ed25519 alias never applies to the allowlist.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> anAlgOutsideTheEffectiveSetIsNotAllowed() {
		Map<String, Set<JwsAlgorithm>> cases = new LinkedHashMap<>();
		for (String alg : List.of("none", "None", "NONE", "nOnE", "", "rs256", "Rs256", "RS256 ", " RS256", "RS256\u0000",
				"RS 256", "dir", "RSA1_5", "RSA-OAEP", "PBES2-HS256+A128KW", "ES256K", "ES521", "Ed448", "A128GCM", "HS256",
				"PS256", "ES256", "EdDSA", "Ed25519"))
			cases.put(alg + " under {RS256}", Set.of(JwsAlgorithm.RS256));
		cases.put("EdDSA under {Ed25519}", Set.of(JwsAlgorithm.ED25519));
		cases.put("Ed25519 under {EdDSA}", Set.of(JwsAlgorithm.EDDSA));
		cases.put("RS256 under {PS256}", Set.of(JwsAlgorithm.PS256));

		return cases.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () -> {
			String alg = entry.getKey().substring(0, entry.getKey().lastIndexOf(" under "));
			JoseHeaderPolicy policy = JoseHeaderPolicy.fromSettings(65_536, entry.getValue(), Set.of("JWT"), false);
			assertFailure(JoseException.Reason.ALGORITHM_NOT_ALLOWED, policy, bytes("{\"alg\":"
					+ JsonText.string(alg) + "}"));
		}));
	}

	// P5 (RFC 7515 section 4.1.11, RFC 7797): crit, b64 and zip are refused whatever their values, crit first, then
	// b64, then zip.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> criticalUnencodedAndCompressedHeadersAreUnsupported() {
		Map<String, JoseException.Reason> cases = new LinkedHashMap<>();
		for (String value : List.of("[\"exp\"]", "[]", "null", "\"b64\"", "[\"b64\"]"))
			cases.put("\"crit\":" + value, JoseException.Reason.CRITICAL_HEADER);
		cases.put("\"crit\":[\"b64\"],\"b64\":false", JoseException.Reason.CRITICAL_HEADER);
		for (String value : List.of("false", "true", "null"))
			cases.put("\"b64\":" + value, JoseException.Reason.UNENCODED_PAYLOAD);
		cases.put("\"zip\":\"DEF\",\"b64\":false", JoseException.Reason.UNENCODED_PAYLOAD);
		for (String value : List.of("\"DEF\"", "null", "0"))
			cases.put("\"zip\":" + value, JoseException.Reason.COMPRESSED_PAYLOAD);

		return cases.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () -> assertFailure(
				entry.getValue(), DEFAULT, bytes("{\"alg\":\"RS256\"," + entry.getKey() + "}"))));
	}

	// P6 (RFC 8725 section 3.10; CVE-2018-0114): a key or key location in the header is refused whatever its value,
	// and x5c, x5t and x5t#S256 are ignored.
	@Test
	void keyReferencesAreUntrustedAndCertificateHintsAreIgnored() throws JoseFailure {
		for (String member : List.of("\"jwk\":{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\"}", "\"jwk\":null",
				"\"jku\":\"https://attacker.example.com/jwks\"", "\"jku\":\"\"", "\"x5u\":\"https://attacker.example.com/c\"",
				"\"x5u\":1"))
			assertFailure(JoseException.Reason.UNTRUSTED_KEY_REFERENCE, DEFAULT, bytes("{\"alg\":\"RS256\"," + member + "}"));

		Assertions.assertEquals(JwsAlgorithm.RS256, DEFAULT.check(bytes("{\"alg\":\"RS256\",\"x5c\":[\"MIIB\"],"
				+ "\"x5t\":\"abc\",\"x5t#S256\":\"def\"}")).algorithm());
	}

	// P7 (RFC 8725 section 3.11; M2-4): typ absent passes unless a type is required; a typ that is not a string, or
	// does not normalize into the allowed set, is INVALID_TYPE.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> theTypeIsAMediaTypeComparedIgnoringAsciiCase() {
		Map<String, Boolean> cases = new LinkedHashMap<>();
		for (String type : List.of("JWT", "jwt", "Jwt", "application/jwt", "application/JWT", "APPLICATION/JWT"))
			cases.put(type, true);
		for (String type : List.of("at+jwt", "logout+jwt", "application/secevent+jwt", "application/at+jwt", "JOSE",
				"application/jose", "text/jwt", "jwt ", " jwt", "application/jwt; charset=utf-8", "application/jwt;",
				"application/", "/jwt", "", "application/jwt/x", "jw\u212at", "\u0130wt", "\uff2a\uff37\uff34"))
			cases.put(type, false);

		return cases.entrySet().stream().map(entry -> DynamicTest.dynamicTest("typ " + entry.getKey(), () -> {
			byte[] header = bytes("{\"alg\":\"RS256\",\"typ\":" + JsonText.string(entry.getKey())
					+ "}");
			if (entry.getValue())
				Assertions.assertEquals(entry.getKey(), DEFAULT.check(header).type());
			else
				assertFailure(JoseException.Reason.INVALID_TYPE, DEFAULT, header);
		}));
	}

	// P7: a typ of another JSON type is INVALID_TYPE, and a required type makes an absent typ INVALID_TYPE.
	@Test
	void aNonStringOrMissingRequiredTypeIsInvalid() throws JoseFailure {
		for (String value : List.of("null", "123", "[\"JWT\"]", "{}", "true"))
			assertFailure(JoseException.Reason.INVALID_TYPE, DEFAULT, bytes("{\"alg\":\"RS256\",\"typ\":" + value + "}"));

		JoseHeaderPolicy required = JoseHeaderPolicy.fromSettings(65_536, Set.of(JwsAlgorithm.RS256), Set.of("JWT"),
				true);
		assertFailure(JoseException.Reason.INVALID_TYPE, required, bytes("{\"alg\":\"RS256\"}"));
		Assertions.assertEquals("jwt", required.check(bytes("{\"alg\":\"RS256\",\"typ\":\"jwt\"}")).type());

		Assertions.assertTrue(DEFAULT.allowsType(null));
		Assertions.assertFalse(required.allowsType(null));
		Assertions.assertTrue(required.allowsType("application/JWT"));

		JoseHeaderPolicy none = JoseHeaderPolicy.fromSettings(65_536, Set.of(JwsAlgorithm.RS256), Set.of(), false);
		Assertions.assertNull(none.check(bytes("{\"alg\":\"RS256\"}")).type());
		assertFailure(JoseException.Reason.INVALID_TYPE, none, bytes("{\"alg\":\"RS256\",\"typ\":\"JWT\"}"));

		JoseHeaderPolicy accessToken = JoseHeaderPolicy.fromSettings(65_536, Set.of(JwsAlgorithm.RS256),
				Set.of("at+jwt"), true);
		Assertions.assertEquals("application/AT+JWT", accessToken.check(bytes("{\"alg\":\"RS256\","
				+ "\"typ\":\"application/AT+JWT\"}")).type());
		assertFailure(JoseException.Reason.INVALID_TYPE, accessToken, bytes("{\"alg\":\"RS256\",\"typ\":\"JWT\"}"));
	}

	// P8 (RFC 7519 section 7.2 step 8): cty, whatever its value, is a nested token, which is not processed.
	@Test
	void aContentTypeIsANestedToken() {
		for (String value : List.of("\"JWT\"", "\"jwt\"", "\"text/plain\"", "null", "1"))
			assertFailure(JoseException.Reason.NESTED_TOKEN, DEFAULT, bytes("{\"alg\":\"RS256\",\"cty\":" + value + "}"));
	}

	// The kid, when present, is a string of 1 to 256 characters (RFC 7515 section 4.1.4), else HEADER.
	@Test
	void theKidIsAStringOfOneTo256Characters() throws JoseFailure {
		for (String kid : List.of("\"\"", "null", "1", "[\"k\"]", "{}", "\"" + "k".repeat(257) + "\""))
			assertFailure(JoseException.Reason.HEADER, DEFAULT, bytes("{\"alg\":\"RS256\",\"kid\":" + kid + "}"));

		Assertions.assertEquals("k", DEFAULT.check(bytes("{\"alg\":\"RS256\",\"kid\":\"k\"}")).keyId());
		Assertions.assertEquals("k".repeat(256), DEFAULT.check(bytes("{\"alg\":\"RS256\",\"kid\":\"" + "k".repeat(256)
				+ "\"}")).keyId());
		Assertions.assertEquals(" \u00e9\\\"", DEFAULT.check(bytes("{\"alg\":\"RS256\",\"kid\":\" \u00e9\\\\\\\"\"}"))
				.keyId());
	}

	// The checks run in a fixed order, and the first failure names the reason: the JSON, alg, crit/b64/zip, the key
	// references, typ, cty, then kid.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> theFirstFailingCheckNamesTheReason() {
		Map<String, JoseException.Reason> cases = new LinkedHashMap<>();
		cases.put("{\"crit\":[],\"jwk\":{},\"typ\":1,\"cty\":1,\"kid\":1}", JoseException.Reason.HEADER);
		cases.put("{\"alg\":\"none\",\"crit\":[],\"jwk\":{},\"typ\":1,\"cty\":1,\"kid\":1}",
				JoseException.Reason.ALGORITHM_NOT_ALLOWED);
		cases.put("{\"alg\":\"RS256\",\"crit\":[],\"jwk\":{},\"typ\":1,\"cty\":1,\"kid\":1}",
				JoseException.Reason.CRITICAL_HEADER);
		cases.put("{\"alg\":\"RS256\",\"zip\":\"DEF\",\"jwk\":{},\"typ\":1,\"cty\":1,\"kid\":1}",
				JoseException.Reason.COMPRESSED_PAYLOAD);
		cases.put("{\"alg\":\"RS256\",\"jku\":\"u\",\"typ\":1,\"cty\":1,\"kid\":1}",
				JoseException.Reason.UNTRUSTED_KEY_REFERENCE);
		cases.put("{\"alg\":\"RS256\",\"typ\":\"at+jwt\",\"cty\":1,\"kid\":1}", JoseException.Reason.INVALID_TYPE);
		cases.put("{\"alg\":\"RS256\",\"cty\":\"JWT\",\"kid\":1}", JoseException.Reason.NESTED_TOKEN);
		cases.put("{\"kid\":1,\"alg\":\"RS256\"}", JoseException.Reason.HEADER);

		return cases.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getValue() + ": " + entry.getKey(),
				() -> assertFailure(entry.getValue(), DEFAULT, bytes(entry.getKey()))));
	}

	// RFC 7515 section 4: members the policy does not name are ignored, whatever they hold.
	@Test
	void otherMembersAreIgnored() throws JoseFailure {
		Assertions.assertEquals(new JoseHeader(JwsAlgorithm.RS256, null, null), DEFAULT.check(bytes("{\"alg\":\"RS256\","
				+ "\"exp\":1,\"iss\":\"x\",\"enc\":\"A128GCM\",\"epk\":{},\"nonce\":[1,2],\"Crit\":[],\"JKU\":\"u\"}")));
	}

	// The settings: at least one algorithm; each allowed type a media type without parameters; a required type only
	// when one is allowed; a length within the JOSE profile's range. Types are stored normalized.
	@Test
	void settingsOutOfRangeAreRefused() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> JoseHeaderPolicy.fromSettings(65_536, Set.of(),
				Set.of("JWT"), false));
		Assertions.assertThrows(IllegalArgumentException.class, () -> JoseHeaderPolicy.fromSettings(65_536,
				Set.of(JwsAlgorithm.RS256), Set.of("application/jwt; charset=utf-8"), false));
		Assertions.assertThrows(IllegalArgumentException.class, () -> JoseHeaderPolicy.fromSettings(65_536,
				Set.of(JwsAlgorithm.RS256), Set.of(""), false));
		Assertions.assertThrows(IllegalArgumentException.class, () -> JoseHeaderPolicy.fromSettings(65_536,
				Set.of(JwsAlgorithm.RS256), Set.of(), true));
		Assertions.assertThrows(IllegalArgumentException.class, () -> JoseHeaderPolicy.fromSettings(0,
				Set.of(JwsAlgorithm.RS256), Set.of("JWT"), false));
		Assertions.assertThrows(IllegalArgumentException.class, () -> JoseHeaderPolicy.fromSettings(1_048_577,
				Set.of(JwsAlgorithm.RS256), Set.of("JWT"), false));
		Set<String> withNull = new HashSet<>(Arrays.asList("JWT", null));
		Assertions.assertThrows(NullPointerException.class, () -> JoseHeaderPolicy.fromSettings(65_536,
				Set.of(JwsAlgorithm.RS256), withNull, false));

		JoseHeaderPolicy policy = JoseHeaderPolicy.fromSettings(1_048_576, Set.of(JwsAlgorithm.HS256, JwsAlgorithm.RS256),
				Set.of("JWT", "application/jwt", "At+Jwt"), true);
		Assertions.assertEquals(Set.of("application/jwt", "application/at+jwt"), policy.getAllowedTypes());
		Assertions.assertEquals(Set.of(JwsAlgorithm.HS256, JwsAlgorithm.RS256), policy.getAllowedAlgorithms());
		Assertions.assertEquals(1_048_576, policy.getMaximumTokenLength());
		Assertions.assertEquals(1_048_576, policy.getJsonLimits().getMaxInputBytes());
		Assertions.assertTrue(policy.isTypeRequired());
		Assertions.assertEquals("JoseHeaderPolicy{maximumTokenLength=1048576, allowedAlgorithms=[RS256, HS256], "
				+ "allowedTypes=[application/at+jwt, application/jwt], typeRequired=true}", policy.toString());
	}

	// normalizeType implies application/ and folds ASCII letters only; anything that is not a type/subtype pair of
	// RFC 9110 tokens is empty.
	@Test
	void normalizeTypeImpliesApplicationAndFoldsAsciiOnly() {
		Assertions.assertEquals(Optional.of("application/jwt"), JoseHeaderPolicy.normalizeType("JWT"));
		Assertions.assertEquals(Optional.of("application/secevent+jwt"),
				JoseHeaderPolicy.normalizeType("Application/SecEvent+JWT"));
		Assertions.assertEquals(Optional.of("text/plain"), JoseHeaderPolicy.normalizeType("TEXT/PLAIN"));
		Assertions.assertEquals(Optional.of("application/!#$%&'*+-.^_`|~"),
				JoseHeaderPolicy.normalizeType("!#$%&'*+-.^_`|~"));
		// Both ends of each tchar range, in the type and in the subtype: a, z, A, Z, 0 and 9 (RFC 9101's type has a z).
		Assertions.assertEquals(Optional.of("application/oauth-authz-req+jwt"),
				JoseHeaderPolicy.normalizeType("oauth-authz-req+jwt"));
		Assertions.assertEquals(Optional.of("azaz09/azaz09"), JoseHeaderPolicy.normalizeType("AZaz09/AZaz09"));
		for (String edge : List.of("a", "z", "A", "Z", "0", "9"))
			Assertions.assertEquals(Optional.of("application/" + AsciiCase.fold(edge)), JoseHeaderPolicy.normalizeType(edge),
					edge);
		Assertions.assertEquals(Optional.of("z/9"), JoseHeaderPolicy.normalizeType("Z/9"));
		Assertions.assertEquals(Optional.of("0/a"), JoseHeaderPolicy.normalizeType("0/A"));
		for (String type : List.of("", "/", "a/", "/b", "a/b/c", "a b", "a;b", "a/b;c=d", "a\tb", "\u212a", "a/\u00e9",
				"a\"b", "a(b)", "a,b", "a@b", "a=b", "a{b}", "a:b", "a?b", "a[b]", "a\\b"))
			Assertions.assertEquals(Optional.empty(), JoseHeaderPolicy.normalizeType(type), type);
	}

	// INV-G1: arbitrary header bytes either pass or throw JoseFailure; nothing else escapes.
	@Test
	void arbitraryHeaderBytesNeverEscapeAsAnythingButJoseFailure() {
		SplittableRandom random = new SplittableRandom(7L);
		List<String> fragments = List.of("{", "}", "[", "]", "\"alg\"", "\"RS256\"", ":", ",", "\"typ\"", "\"JWT\"",
				"\"kid\"", "\"crit\"", "null", "1e999999", "\"\\ud800\"", "\"\\u0000\"", "-0", "true");

		for (int round = 0; round < 20_000; ++round) {
			StringBuilder text = new StringBuilder();
			int count = random.nextInt(12);
			for (int index = 0; index < count; ++index)
				text.append(fragments.get(random.nextInt(fragments.size())));
			byte[] header = bytes(text.toString());
			if (random.nextInt(10) == 0 && header.length > 0)
				header[random.nextInt(header.length)] = (byte) random.nextInt(256);

			try {
				DEFAULT.check(header);
			} catch (JoseFailure expected) {
				Assertions.assertNotNull(expected.getReason());
			}
		}
	}

	private static byte @NonNull [] bytes(@NonNull String text) {
		return text.getBytes(StandardCharsets.UTF_8);
	}

	private static byte @NonNull [] concat(byte @NonNull [] @NonNull ... parts) {
		int length = 0;
		for (byte[] part : parts)
			length += part.length;
		byte[] result = new byte[length];
		int offset = 0;
		for (byte[] part : parts) {
			System.arraycopy(part, 0, result, offset, part.length);
			offset += part.length;
		}
		return result;
	}

	private static void assertFailure(JoseException.@NonNull Reason reason,
																		@NonNull JoseHeaderPolicy policy,
																		byte @NonNull [] header) {
		JoseFailure failure = Assertions.assertThrows(JoseFailure.class, () -> policy.check(header));
		Assertions.assertEquals(reason, failure.getReason());
	}
}
