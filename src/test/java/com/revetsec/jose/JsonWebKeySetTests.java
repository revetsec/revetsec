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

import com.revetsec.ErrorCategory;
import com.revetsec.testing.JsonText;
import com.revetsec.testing.TestJsonWebKeys;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * {@link JsonWebKeySet} and {@link JsonWebKey}: the public view of a parsed key set (RFC 7517 section 5): usable keys
 * in document order, document failures as {@link MalformedJoseInputException} with
 * {@link JoseException.Reason#KEY_SET}, the default JWKS body and key-count limits, value equality that includes the
 * hidden JWK {@code issuer} member (plan M2-5, INV-C6), and a {@code toString} that escapes the key ID.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JsonWebKeySetTests {
	private static final String RSA = TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("rsa").alg("RS256")
			.use("sig").toJson();
	private static final String EC = TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P384).kid("ec").toJson();
	private static final String ED25519 = TestJsonWebKeys.withFixture(Fixture.ED25519).kid("ed").alg("EdDSA").toJson();
	private static final String OCT = TestJsonWebKeys.octWithK("GawgguFyGrWKav7AX4VKUg").kid("oct").toJson();

	// RFC 7517 section 5: the usable keys, in document order, with their public facts; skipped keys are simply absent.
	@Test
	void fromJsonGivesTheUsableKeysInDocumentOrder() {
		JsonWebKeySet keySet = JsonWebKeySet.fromJson(TestJsonWebKeys.keySet(List.of(RSA, OCT, EC, ED25519)));
		List<JsonWebKey> keys = keySet.getKeys();

		Assertions.assertEquals(3, keys.size());
		Assertions.assertEquals(List.of(Optional.of("rsa"), Optional.of("ec"), Optional.of("ed")),
				keys.stream().map(JsonWebKey::getKeyId).toList());
		Assertions.assertEquals(List.of("RSA", "EC", "OKP"), keys.stream().map(JsonWebKey::getKeyType).toList());
		Assertions.assertEquals(List.of(Optional.empty(), Optional.of("P-384"), Optional.of("Ed25519")),
				keys.stream().map(JsonWebKey::getCurve).toList());
		Assertions.assertEquals(List.of(Optional.of(JwsAlgorithm.RS256), Optional.empty(), Optional.of(JwsAlgorithm.EDDSA)),
				keys.stream().map(JsonWebKey::getAlgorithm).toList());
		Assertions.assertEquals(List.of(Optional.of("sig"), Optional.empty(), Optional.empty()),
				keys.stream().map(JsonWebKey::getUse).toList());
		for (JsonWebKey key : keys)
			Assertions.assertEquals(43, key.getThumbprintSha256().length());
		Assertions.assertThrows(UnsupportedOperationException.class, () -> keys.remove(0));
		Assertions.assertEquals(List.of(), JsonWebKeySet.fromJson(TestJsonWebKeys.keySet(List.of(OCT))).getKeys());
	}

	// Document failures are MalformedJoseInputException with KEY_SET: MALFORMED_INPUT, not transient, no cause, and a
	// fixed message that never holds the document.
	@TestFactory
	Stream<DynamicTest> documentFailuresAreMalformedInputWithTheKeySetReason() {
		return Stream.of("", "{", "[]", "{}", "{\"keys\":{}}", "{\"keys\":[1]}", "{\"keys\":[],\"keys\":[]}",
						"{\"keys\":[\"" + (char) 0xD800 + "\"]}")
				.map(document -> DynamicTest.dynamicTest(JsonText.string(document), () -> {
					MalformedJoseInputException exception = Assertions.assertThrows(MalformedJoseInputException.class,
							() -> JsonWebKeySet.fromJson(document));
					Assertions.assertEquals(JoseException.Reason.KEY_SET, exception.getReason());
					Assertions.assertEquals(ErrorCategory.MALFORMED_INPUT, exception.getCategory());
					Assertions.assertFalse(exception.isTransient());
					Assertions.assertNull(exception.getCause());
					Assertions.assertEquals("The JSON Web Key Set document is malformed.", exception.getMessage());
				}));
	}

	// The default limits of a remote source apply: 100 keys counting every element, and 256 KiB of UTF-8.
	@Test
	@SuppressWarnings("NullAway")
	void theDefaultLimitsAre100KeysAnd256KiB() {
		Assertions.assertEquals(List.of(), JsonWebKeySet.fromJson(TestJsonWebKeys.keySet(Collections.nCopies(100, OCT)))
				.getKeys());
		Assertions.assertThrows(MalformedJoseInputException.class, () -> JsonWebKeySet.fromJson(TestJsonWebKeys.keySet(
				Collections.nCopies(101, OCT))));

		String base = "{\"keys\":[" + RSA + "],\"pad\":\"\"}";
		int limit = 256 * 1024;
		String atLimit = base.replace("\"pad\":\"\"", "\"pad\":\"" + "a".repeat(limit - base.length()) + "\"");
		Assertions.assertEquals(limit, atLimit.getBytes(StandardCharsets.UTF_8).length);
		Assertions.assertEquals(1, JsonWebKeySet.fromJson(atLimit).getKeys().size());
		Assertions.assertThrows(MalformedJoseInputException.class, () -> JsonWebKeySet.fromJson(atLimit.replace(
				"\"pad\":\"", "\"pad\":\"a")));
		Assertions.assertThrows(NullPointerException.class, () -> JsonWebKeySet.fromJson(null));
	}

	// Plan M2-5: key sets compare by their ordered keys, and keys by thumbprint, kid, alg, use and the JWK issuer member
	// (which changes which tokens the key may verify), with a hash from the thumbprint.
	@Test
	void keySetsAndKeysCompareByValue() {
		JsonWebKeySet first = JsonWebKeySet.fromJson(TestJsonWebKeys.keySet(List.of(RSA, EC)));
		JsonWebKeySet second = JsonWebKeySet.fromJson(TestJsonWebKeys.keySet(List.of(RSA, OCT, EC)));
		JsonWebKeySet reordered = JsonWebKeySet.fromJson(TestJsonWebKeys.keySet(List.of(EC, RSA)));

		Assertions.assertEquals(first, second);
		Assertions.assertEquals(first.hashCode(), second.hashCode());
		Assertions.assertNotEquals(first, reordered);

		JsonWebKey key = only(RSA);
		Assertions.assertEquals(key, only(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("rsa")
				.alg("RS256").use("sig").member("x5t", "\"ignored\"").toJson()));
		Assertions.assertEquals(key.hashCode(), only(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).toJson())
				.hashCode(), "the hash depends on the thumbprint only");
		for (String other : List.of(
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("other").alg("RS256").use("sig").toJson(),
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("rsa").alg("PS256").use("sig").toJson(),
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("rsa").alg("RS256").toJson(),
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("rsa").alg("RS256").use("sig")
						.issuer("https://issuer.example.com").toJson(),
				TestJsonWebKeys.withFixture(Fixture.SP_SIGNING_RSA_2048).kid("rsa").alg("RS256").use("sig").toJson()))
			Assertions.assertNotEquals(key, only(other), other);
		Assertions.assertNotEquals(key, key.toString());
	}

	// A key's toString shows its public facts; the kid comes from the key set's author, so characters that could forge
	// or hide log text are escaped, and the issuer member is not shown.
	@Test
	void toStringShowsPublicFactsWithTheKeyIdEscaped() {
		String kid = "a\nb\"c\\d" + (char) 0x202E + "e" + (char) 0x85 + "f" + (char) 0x2066 + "g" + (char) 0xE9;
		JsonWebKey key = only(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P256).kid(kid).alg("ES256")
				.issuer("https://issuer.example.com").toJson());
		String description = key.toString();

		Assertions.assertEquals("JsonWebKey{kid=\"a\\u000Ab\\u0022c\\u005Cd\\u202Ee\\u0085f\\u2066g" + (char) 0xE9
				+ "\", kty=EC, "
				+ "crv=P-256, alg=ES256, thumbprint=" + key.getThumbprintSha256() + "}", description);
		Assertions.assertFalse(description.contains("issuer"));
		Assertions.assertEquals("JsonWebKey{kty=RSA, thumbprint=" + only(TestJsonWebKeys.withFixture(
				Fixture.IDP_SIGNING_RSA_2048).toJson()).getThumbprintSha256() + "}", only(TestJsonWebKeys.withFixture(
				Fixture.IDP_SIGNING_RSA_2048).toJson()).toString());
		Assertions.assertTrue(JsonWebKeySet.fromJson(TestJsonWebKeys.keySet(List.of(RSA))).toString()
				.startsWith("JsonWebKeySet{keys=[JsonWebKey{kid=\"rsa\""));
		Assertions.assertEquals("x" + (char) 0xD83D + (char) 0xDE00, JsonWebKey.escape("x" + (char) 0xD83D
				+ (char) 0xDE00), "a surrogate pair is a character, not escaped");
		Assertions.assertEquals("\\uDE00\\uD83D", JsonWebKey.escape("" + (char) 0xDE00 + (char) 0xD83D));
	}

	// The kid escape covers every character class that could forge or hide log text (C0 and C1 controls, DEL, quote,
	// backslash, the line and paragraph separators, the bidirectional controls and marks, and unpaired surrogates),
	// and nothing else.
	@Test
	void theKidEscapeCoversEveryCharacterThatCouldForgeLogText() {
		for (char character : new char[]{0x00, 0x1F, 0x7F, 0x80, 0x9F, '"', '\\', 0x2028, 0x2029, 0x202A, 0x202E, 0x2066,
				0x2069, 0x200E, 0x200F, 0x061C})
			Assertions.assertEquals(String.format(Locale.ROOT, "a\\u%04Xb", (int) character), JsonWebKey.escape("a"
					+ character + "b"), Integer.toHexString(character));
		for (char character : new char[]{0x20, 0x7E, 0xA0, 0x2027, 0x202F, 0x2065, 0x206A, 0x200D, 0x2010, 0x061B})
			Assertions.assertEquals("a" + character + "b", JsonWebKey.escape("a" + character + "b"),
					Integer.toHexString(character));

		Assertions.assertEquals("a\\uD800", JsonWebKey.escape("a" + (char) 0xD800));
		Assertions.assertEquals("\\uD800a", JsonWebKey.escape((char) 0xD800 + "a"));
		Assertions.assertEquals("\\uDC00a", JsonWebKey.escape((char) 0xDC00 + "a"));
		Assertions.assertEquals("a\\uDC00", JsonWebKey.escape("a" + (char) 0xDC00));
	}

	// Equality holds for the same instance and never for another type.
	@Test
	void equalityIsReflexiveAndTypeSafe() {
		JsonWebKeySet set = JsonWebKeySet.fromJson(TestJsonWebKeys.keySet(List.of(RSA)));
		JsonWebKey key = set.getKeys().get(0);
		Object sameSet = set;
		Object sameKey = key;

		Assertions.assertEquals(set, sameSet);
		Assertions.assertEquals(key, sameKey);
		Assertions.assertNotEquals(set, key);
		Assertions.assertNotEquals(key, set);
	}

	private static JsonWebKey only(String keyJson) {
		List<JsonWebKey> keys = JsonWebKeySet.fromJson(TestJsonWebKeys.keySet(List.of(keyJson))).getKeys();
		Assertions.assertEquals(1, keys.size(), keyJson);
		return keys.get(0);
	}
}
