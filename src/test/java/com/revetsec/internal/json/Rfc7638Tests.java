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

package com.revetsec.internal.json;

import org.jspecify.annotations.NonNull;

import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.stream.Stream;

import static com.revetsec.internal.json.JsonFailures.SENTINEL;
import static com.revetsec.internal.json.JsonFailures.assertFieldRejected;
import static com.revetsec.internal.json.JsonFailures.utf8;

/**
 * JWK thumbprint input (RFC 7638; M1 plan exit criterion 4).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class Rfc7638Tests {
	/**
	 * The RSA key of RFC 7638 section 3.1 (also RFC 7517 appendix A.1), with its non-required members.
	 */
	private static final String RSA_JWK = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4"
			+ "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6"
			+ "Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bF"
			+ "TWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\"e\":\"AQAB\","
			+ "\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";

	/**
	 * The Ed25519 public key of RFC 8037 appendix A.2, as used by A.3.
	 */
	private static final String OKP_JWK = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\","
			+ "\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";

	/**
	 * The P-256 public key of RFC 7517 appendix A.1, with its non-required members.
	 */
	private static final String EC_JWK = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6"
			+ "KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}";

	// RFC 7638 section 3.1: the example key's required members, in order, and its SHA-256 thumbprint.
	@Test
	void reproducesTheRfc7638RsaThumbprint() throws Exception {
		byte[] canonical = Rfc7638.canonicalJwk(jwk(RSA_JWK));

		Assertions.assertTrue(new String(canonical, StandardCharsets.UTF_8).startsWith("{\"e\":\"AQAB\",\"kty\":\"RSA\","
				+ "\"n\":\"0vx7agoebGcQ"));
		Assertions.assertEquals("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", thumbprint(canonical));
	}

	// RFC 8037 appendix A.3: the Ed25519 key's thumbprint.
	@Test
	void reproducesTheRfc8037OkpThumbprint() throws Exception {
		byte[] canonical = Rfc7638.canonicalJwk(jwk(OKP_JWK));

		Assertions.assertEquals("{\"crv\":\"Ed25519\",\"kty\":\"OKP\","
				+ "\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}", new String(canonical, StandardCharsets.UTF_8));
		Assertions.assertEquals("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", thumbprint(canonical));
	}

	// Exit criterion 4: the EC member set (crv, kty, x, y). The expected bytes and thumbprint were produced offline
	// with Python 3.14.6's json.dumps(sort_keys=True, separators=(',', ':')) over the required members, then SHA-256
	// and unpadded base64url, on 2026-09-24. The oct row was checked the same way.
	@Test
	void matchesPythonSortedJsonForEcAndOctKeys() throws Exception {
		byte[] ec = Rfc7638.canonicalJwk(jwk(EC_JWK));

		Assertions.assertEquals("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
				+ "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}", new String(ec, StandardCharsets.UTF_8));
		Assertions.assertEquals("cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s", thumbprint(ec));

		byte[] oct = Rfc7638.canonicalJwk(jwk("{\"kid\":\"hmac\",\"kty\":\"oct\",\"k\":\"GawgguFyGrWKav7AX4VKUg\","
				+ "\"alg\":\"HS256\"}"));
		Assertions.assertEquals("{\"k\":\"GawgguFyGrWKav7AX4VKUg\",\"kty\":\"oct\"}", new String(oct,
				StandardCharsets.UTF_8));
		Assertions.assertEquals("k1JnWRfC-5zzmL72vXIuBgTLfVROXBakS4OmGcrMCoc", thumbprint(oct));
	}

	// RFC 7638 section 3.2: only the required members count, so member order and extra members (private ones
	// included) do not change the result.
	@Test
	void ignoresMemberOrderAndNonRequiredMembers() throws Exception {
		JsonObject reordered = JsonObject.builder()
				.put("kid", "other")
				.put("x", "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
				.put("d", SENTINEL)
				.put("kty", "OKP")
				.put("use", "sig")
				.put("key_ops", JsonArray.emptyInstance())
				.put("crv", "Ed25519")
				.build();

		Assertions.assertArrayEquals(Rfc7638.canonicalJwk(jwk(OKP_JWK)), Rfc7638.canonicalJwk(reordered));
		Assertions.assertFalse(new String(Rfc7638.canonicalJwk(reordered), StandardCharsets.UTF_8).contains(SENTINEL));
	}

	// RFC 7638 section 3.3: values are copied as they are and encoded as UTF-8; non-ASCII characters need no escape.
	@Test
	void encodesValuesAsUtf8WithoutEscaping() throws Exception {
		JsonObject jwk = JsonObject.builder().put("kty", "oct").put("k", "caf\u00E9/\uD83D\uDE80").build();

		Assertions.assertArrayEquals(utf8("{\"k\":\"caf\u00E9/\uD83D\uDE80\",\"kty\":\"oct\"}"), Rfc7638.canonicalJwk(jwk));
	}

	// RFC 7638 sections 3.2 and 3.3: a missing kty or required member, a value that is not a string, an unknown or
	// differently cased key type, and a value JSON would have to escape (for which no thumbprint is defined) are
	// rejected with a fixed message that never echoes the key.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> rejectsKeysWithoutAWellDefinedThumbprint() {
		return Stream.of(
				new Object[]{"no kty", "{\"n\":\"" + SENTINEL + "\",\"e\":\"AQAB\"}", JsonFieldException.Kind.MISSING},
				new Object[]{"RSA without n", "{\"kty\":\"RSA\",\"e\":\"" + SENTINEL + "\"}",
						JsonFieldException.Kind.MISSING},
				new Object[]{"EC without y", "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + SENTINEL + "\"}",
						JsonFieldException.Kind.MISSING},
				new Object[]{"oct without k", "{\"kty\":\"oct\",\"kid\":\"" + SENTINEL + "\"}",
						JsonFieldException.Kind.MISSING},
				new Object[]{"kty is a number", "{\"kty\":1,\"k\":\"" + SENTINEL + "\"}", JsonFieldException.Kind.WRONG_TYPE},
				new Object[]{"e is an array", "{\"kty\":\"RSA\",\"n\":\"" + SENTINEL + "\",\"e\":[\"AQAB\"]}",
						JsonFieldException.Kind.WRONG_TYPE},
				new Object[]{"x is null", "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":null,\"kid\":\"" + SENTINEL + "\"}",
						JsonFieldException.Kind.WRONG_TYPE},
				new Object[]{"lowercase rsa", "{\"kty\":\"rsa\",\"n\":\"" + SENTINEL + "\",\"e\":\"AQAB\"}",
						JsonFieldException.Kind.UNSUPPORTED},
				new Object[]{"unknown kty", "{\"kty\":\"" + SENTINEL + "\"}", JsonFieldException.Kind.UNSUPPORTED},
				new Object[]{"a quotation mark in n", "{\"kty\":\"RSA\",\"n\":\"a\\\"" + SENTINEL + "\",\"e\":\"AQAB\"}",
						JsonFieldException.Kind.UNSUPPORTED},
				new Object[]{"a backslash in k", "{\"kty\":\"oct\",\"k\":\"" + SENTINEL + "\\\\\"}",
						JsonFieldException.Kind.UNSUPPORTED},
				new Object[]{"a control character in crv", "{\"kty\":\"EC\",\"crv\":\"P-256\\n\",\"x\":\"" + SENTINEL
						+ "\",\"y\":\"y\"}", JsonFieldException.Kind.UNSUPPORTED},
				new Object[]{"the last control character (U+001F) in x", "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\""
						+ SENTINEL + "\\u001F\"}", JsonFieldException.Kind.UNSUPPORTED})
				.map(row -> DynamicTest.dynamicTest((String) row[0], () -> {
					JsonObject key = jwk((String) row[1]);
					assertFieldRejected((JsonFieldException.Kind) row[2], () -> Rfc7638.canonicalJwk(key));
				}));
	}

	// R15: a null key is misuse.
	// Deliberate null inputs verify runtime rejection.
	@SuppressWarnings("NullAway")
	@Test
	void rejectsANullKey() {
		JsonObject noKey = JsonFailures.nullValue();

		Assertions.assertThrows(NullPointerException.class, () -> Rfc7638.canonicalJwk(noKey));
	}

	// The characters RFC 7638 section 3.3 leaves undefined are exactly those JSON must escape; DEL and U+2028 are
	// copied.
	@Test
	void copiesCharactersJsonDoesNotEscape() throws Exception {
		JsonObject jwk = JsonObject.builder().put("kty", "oct").put("k", "\u007F\u2028 ").build();

		Assertions.assertEquals("{\"k\":\"\u007F\u2028 \",\"kty\":\"oct\"}",
				new String(Rfc7638.canonicalJwk(jwk), StandardCharsets.UTF_8));
		Assertions.assertEquals(JsonString.fromValue("\u007F\u2028 "), jwk.getMembers().get("k"));
	}

	private static @NonNull JsonObject jwk(@NonNull String json) throws JsonParseException {
		return (JsonObject) JsonCodec.parse(utf8(json), JsonLimits.jose(64 * 1_024));
	}

	private static @NonNull String thumbprint(byte @NonNull [] canonical) throws NoSuchAlgorithmException {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256")
				.digest(canonical));
	}
}
