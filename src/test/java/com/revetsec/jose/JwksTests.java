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

import org.jspecify.annotations.NonNull;

import com.revetsec.testing.JsonText;
import com.revetsec.testing.TestJwk;
import com.revetsec.testing.TestJwk.Fixture;
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
 * {@link Jwks} and {@link Jwk}: the public view of a parsed key set (RFC 7517 section 5): usable keys
 * in document order, document failures as {@link JwksParseResult.Rejected} with
 * {@link JoseException.Reason#KEY_SET}, the default JWKS body and key-count limits, value equality that includes the
 * hidden JWK {@code issuer} member (plan M2-5, INV-C6), and a {@code toString} that escapes the key ID.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JwksTests {
	private static final String RSA = TestJwk.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("rsa").alg("RS256")
			.use("sig").toJson();
	private static final String EC = TestJwk.withFixture(Fixture.IDP_SIGNING_EC_P384).kid("ec").toJson();
	private static final String ED25519 = TestJwk.withFixture(Fixture.ED25519).kid("ed").alg("EdDSA").toJson();
	private static final String OCT = TestJwk.octWithK("GawgguFyGrWKav7AX4VKUg").kid("oct").toJson();

	// RFC 7517 section 5: the usable keys, in document order, with their public facts; skipped keys are simply absent.
	@Test
	void fromJsonResultGivesTheUsableKeysInDocumentOrder() {
		Jwks keySet = JwtFixtures.assertParsedJwks(TestJwk.keySet(List.of(RSA, OCT, EC, ED25519)));
		List<Jwk> keys = keySet.getKeys();

		Assertions.assertEquals(3, keys.size());
		Assertions.assertEquals(List.of(Optional.of("rsa"), Optional.of("ec"), Optional.of("ed")),
				keys.stream().map(Jwk::getKeyId).toList());
		Assertions.assertEquals(List.of("RSA", "EC", "OKP"), keys.stream().map(Jwk::getKeyType).toList());
		Assertions.assertEquals(List.of(Optional.empty(), Optional.of("P-384"), Optional.of("Ed25519")),
				keys.stream().map(Jwk::getCurve).toList());
		Assertions.assertEquals(List.of(Optional.of(JwsAlgorithm.RS256), Optional.empty(), Optional.of(JwsAlgorithm.EDDSA)),
				keys.stream().map(Jwk::getAlgorithm).toList());
		Assertions.assertEquals(List.of(Optional.of("sig"), Optional.empty(), Optional.empty()),
				keys.stream().map(Jwk::getUse).toList());
		for (Jwk key : keys)
			Assertions.assertEquals(43, key.getThumbprintSha256().length());
		Assertions.assertThrows(UnsupportedOperationException.class, () -> keys.remove(0));
		Assertions.assertEquals(List.of(), JwtFixtures.assertParsedJwks(TestJwk.keySet(List.of(OCT))).getKeys());
	}

	// Document failures have the fixed KEY_SET reason and no document or untrusted diagnostic text.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> documentFailuresAreMalformedInputWithTheKeySetReason() {
		return Stream.of("", "{", "[]", "{}", "{\"keys\":{}}", "{\"keys\":[1]}", "{\"keys\":[],\"keys\":[]}",
						"{\"keys\":[\"" + (char) 0xD800 + "\"]}")
				.map(document -> DynamicTest.dynamicTest(JsonText.string(document), () -> {
					JwksParseResult.Rejected rejected = Assertions.assertInstanceOf(JwksParseResult.Rejected.class,
							Jwks.fromJsonResult(document));
					Assertions.assertEquals(JoseException.Reason.KEY_SET, rejected.getReason());
					if (document.length() >= 8) Assertions.assertFalse(rejected.toString().contains(document));
				}));
	}

	// The default limits of a remote source apply: 100 keys counting every element, and 256 KiB of UTF-8.
	@Test
	@SuppressWarnings("NullAway")
	void theDefaultLimitsAre100KeysAnd256KiB() {
		Assertions.assertEquals(List.of(), JwtFixtures.assertParsedJwks(TestJwk.keySet(Collections.nCopies(100, OCT)))
				.getKeys());
		Assertions.assertEquals(JoseException.Reason.KEY_SET, Assertions.assertInstanceOf(JwksParseResult.Rejected.class,
				Jwks.fromJsonResult(TestJwk.keySet(Collections.nCopies(101, OCT)))).getReason());

		String base = "{\"keys\":[" + RSA + "],\"pad\":\"\"}";
		int limit = 256 * 1024;
		String atLimit = base.replace("\"pad\":\"\"", "\"pad\":\"" + "a".repeat(limit - base.length()) + "\"");
		Assertions.assertEquals(limit, atLimit.getBytes(StandardCharsets.UTF_8).length);
		Assertions.assertEquals(1, JwtFixtures.assertParsedJwks(atLimit).getKeys().size());
		Assertions.assertEquals(JoseException.Reason.KEY_SET, Assertions.assertInstanceOf(JwksParseResult.Rejected.class,
				Jwks.fromJsonResult(atLimit.replace("\"pad\":\"", "\"pad\":\"a"))).getReason());
		Assertions.assertThrows(NullPointerException.class, () -> Jwks.fromJsonResult(null));
	}

	// Plan M2-5: key sets compare by their ordered keys, and keys by thumbprint, kid, alg, use and the JWK issuer member
	// (which changes which tokens the key may verify), with a hash from the thumbprint.
	@Test
	void keySetsAndKeysCompareByValue() {
		Jwks first = JwtFixtures.assertParsedJwks(TestJwk.keySet(List.of(RSA, EC)));
		Jwks second = JwtFixtures.assertParsedJwks(TestJwk.keySet(List.of(RSA, OCT, EC)));
		Jwks reordered = JwtFixtures.assertParsedJwks(TestJwk.keySet(List.of(EC, RSA)));

		Assertions.assertEquals(first, second);
		Assertions.assertEquals(first.hashCode(), second.hashCode());
		Assertions.assertNotEquals(first, reordered);

		Jwk key = only(RSA);
		Assertions.assertEquals(key, only(TestJwk.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("rsa")
				.alg("RS256").use("sig").member("x5t", "\"ignored\"").toJson()));
		Assertions.assertEquals(key.hashCode(), only(TestJwk.withFixture(Fixture.IDP_SIGNING_RSA_2048).toJson())
				.hashCode(), "the hash depends on the thumbprint only");
		for (String other : List.of(
				TestJwk.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("other").alg("RS256").use("sig").toJson(),
				TestJwk.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("rsa").alg("PS256").use("sig").toJson(),
				TestJwk.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("rsa").alg("RS256").toJson(),
				TestJwk.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("rsa").alg("RS256").use("sig")
						.issuer("https://issuer.example.com").toJson(),
				TestJwk.withFixture(Fixture.SP_SIGNING_RSA_2048).kid("rsa").alg("RS256").use("sig").toJson()))
			Assertions.assertNotEquals(key, only(other), other);
		Assertions.assertNotEquals(key, key.toString());
	}

	// A key's toString shows its public facts; the kid comes from the key set's author, so characters that could forge
	// or hide log text are escaped, and the issuer member is not shown.
	@Test
	void toStringShowsPublicFactsWithTheKeyIdEscaped() {
		String kid = "a\nb\"c\\d" + (char) 0x202E + "e" + (char) 0x85 + "f" + (char) 0x2066 + "g" + (char) 0xE9;
		Jwk key = only(TestJwk.withFixture(Fixture.IDP_SIGNING_EC_P256).kid(kid).alg("ES256")
				.issuer("https://issuer.example.com").toJson());
		String description = key.toString();

		Assertions.assertEquals("Jwk{kid=\"a\\u000Ab\\u0022c\\u005Cd\\u202Ee\\u0085f\\u2066g" + (char) 0xE9
				+ "\", kty=EC, "
				+ "crv=P-256, alg=ES256, thumbprint=" + key.getThumbprintSha256() + "}", description);
		Assertions.assertFalse(description.contains("issuer"));
		Assertions.assertEquals("Jwk{kty=RSA, thumbprint=" + only(TestJwk.withFixture(
				Fixture.IDP_SIGNING_RSA_2048).toJson()).getThumbprintSha256() + "}", only(TestJwk.withFixture(
				Fixture.IDP_SIGNING_RSA_2048).toJson()).toString());
		Assertions.assertTrue(JwtFixtures.assertParsedJwks(TestJwk.keySet(List.of(RSA))).toString()
				.startsWith("Jwks{keys=[Jwk{kid=\"rsa\""));
		Assertions.assertEquals("x" + (char) 0xD83D + (char) 0xDE00, Jwk.escape("x" + (char) 0xD83D
				+ (char) 0xDE00), "a surrogate pair is a character, not escaped");
		Assertions.assertEquals("\\uDE00\\uD83D", Jwk.escape("" + (char) 0xDE00 + (char) 0xD83D));
	}

	// The kid escape covers every character class that could forge or hide log text (C0 and C1 controls, DEL, quote,
	// backslash, the line and paragraph separators, the bidirectional controls and marks, and unpaired surrogates),
	// and nothing else.
	@Test
	void theKidEscapeCoversEveryCharacterThatCouldForgeLogText() {
		for (char character : new char[]{0x00, 0x1F, 0x7F, 0x80, 0x9F, '"', '\\', 0x2028, 0x2029, 0x202A, 0x202E, 0x2066,
				0x2069, 0x200E, 0x200F, 0x061C})
			Assertions.assertEquals(String.format(Locale.ROOT, "a\\u%04Xb", (int) character), Jwk.escape("a"
					+ character + "b"), Integer.toHexString(character));
		for (char character : new char[]{0x20, 0x7E, 0xA0, 0x2027, 0x202F, 0x2065, 0x206A, 0x200D, 0x2010, 0x061B})
			Assertions.assertEquals("a" + character + "b", Jwk.escape("a" + character + "b"),
					Integer.toHexString(character));

		Assertions.assertEquals("a\\uD800", Jwk.escape("a" + (char) 0xD800));
		Assertions.assertEquals("\\uD800a", Jwk.escape((char) 0xD800 + "a"));
		Assertions.assertEquals("\\uDC00a", Jwk.escape((char) 0xDC00 + "a"));
		Assertions.assertEquals("a\\uDC00", Jwk.escape("a" + (char) 0xDC00));
	}

	// Equality holds for the same instance and never for another type.
	@Test
	void equalityIsReflexiveAndTypeSafe() {
		Jwks set = JwtFixtures.assertParsedJwks(TestJwk.keySet(List.of(RSA)));
		Jwk key = set.getKeys().get(0);
		Object sameSet = set;
		Object sameKey = key;

		Assertions.assertEquals(set, sameSet);
		Assertions.assertEquals(key, sameKey);
		Assertions.assertNotEquals(set, key);
		Assertions.assertNotEquals(key, set);
	}

	private static @NonNull Jwk only(@NonNull String keyJson) {
		List<Jwk> keys = JwtFixtures.assertParsedJwks(TestJwk.keySet(List.of(keyJson))).getKeys();
		Assertions.assertEquals(1, keys.size(), keyJson);
		return keys.get(0);
	}
}
