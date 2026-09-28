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

import com.revetsec.jose.JoseException;
import com.revetsec.jose.JsonWebKeySkipReason;
import com.revetsec.testing.JsonText;
import com.revetsec.testing.TestJsonWebKeys;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * {@link JwkSetParser}: document failures reject the whole JSON Web Key Set (RFC 7517 section 5, plan "Keys"), while
 * a key that breaks a rule is skipped with its position and reason and never fails the set; the size and key-count
 * limits (G5-4's JWKS rows); and the text and byte paths agree.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JwkSetParserTests {
	private static final int MAXIMUM_BYTES = 256 * 1024;
	private static final int MAXIMUM_KEYS = 100;
	private static final int FOUR_MIB = 4 * 1024 * 1024;

	private static final String RSA = TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("rsa").toJson();
	private static final String EC = TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P256).kid("ec").toJson();
	private static final String ED25519 = TestJsonWebKeys.withFixture(Fixture.ED25519).kid("ed").toJson();
	private static final String OCT = TestJsonWebKeys.octWithK("GawgguFyGrWKav7AX4VKUg").kid("oct").toJson();
	private static final String ENCRYPTION = TestJsonWebKeys.withFixture(Fixture.SP_ENCRYPTION_RSA_2048).kid("enc")
			.use("enc").alg("RSA-OAEP").toJson();

	// RFC 7517 section 5: usable keys come back in document order, and each skipped key with its zero-based position in
	// "keys" and its reason; the set as a whole is not failed by them.
	@Test
	void usableKeysKeepDocumentOrderAndSkipsKeepTheirPositions() throws JoseFailure {
		ParsedKeySet parsed = parse(TestJsonWebKeys.keySet(List.of(RSA, OCT, EC, ENCRYPTION, ED25519)));

		Assertions.assertEquals(List.of("rsa", "ec", "ed"), parsed.keys().stream().map(VerificationKey::keyId).toList());
		Assertions.assertEquals(List.of(new ParsedKeySet.Skip(1, JsonWebKeySkipReason.SYMMETRIC_KEY),
				new ParsedKeySet.Skip(3, JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY)), parsed.skips());
		Assertions.assertEquals(5, parsed.elementCount());
	}

	// Plan M2-8: an identity provider may revoke every key, so a set whose keys are all skipped, or an empty keys
	// array, is a valid, empty key set rather than a document failure.
	@Test
	void aSetWithNoUsableKeyIsValidAndEmpty() throws JoseFailure {
		ParsedKeySet allSkipped = parse(TestJsonWebKeys.keySet(List.of(OCT, ENCRYPTION)));
		Assertions.assertEquals(List.of(), allSkipped.keys());
		Assertions.assertEquals(2, allSkipped.skips().size());

		ParsedKeySet empty = parse("{\"keys\":[]}");
		Assertions.assertEquals(List.of(), empty.keys());
		Assertions.assertEquals(List.of(), empty.skips());
		Assertions.assertEquals(0, empty.elementCount());
	}

	// RFC 7517 section 5: members other than "keys" are ignored, as is whitespace.
	@Test
	void otherMembersOfTheDocumentAreIgnored() throws JoseFailure {
		ParsedKeySet parsed = parse(" {\"issuer\":\"x\",\n\"keys\" : [ " + RSA + " ], \"extra\":{\"keys\":1}}\r\n");

		Assertions.assertEquals(1, parsed.keys().size());
		Assertions.assertEquals(List.of(), parsed.skips());
	}

	// Document failures (plan "Keys"): not strict JSON, not an object, no keys array, an element of keys that is not
	// an object; each fails the whole set as KEY_SET, even with usable keys beside it.
	@TestFactory
	Stream<DynamicTest> documentFailuresRejectTheWholeSet() {
		String deep = "{\"keys\":[{\"kty\":\"RSA\",\"x\":" + "[".repeat(40) + "]".repeat(40) + "}]}";

		return Stream.of(
						Map.entry("empty text", ""),
						Map.entry("whitespace only", "  "),
						Map.entry("not JSON", "{\"keys\":["),
						Map.entry("trailing content", "{\"keys\":[]} []"),
						Map.entry("a single quote", "{'keys':[]}"),
						Map.entry("JSON null", "null"),
						Map.entry("an array", "[" + RSA + "]"),
						Map.entry("a string", "\"keys\""),
						Map.entry("no keys member", "{}"),
						Map.entry("Keys in another case", "{\"Keys\":[" + RSA + "]}"),
						Map.entry("keys an object", "{\"keys\":" + RSA + "}"),
						Map.entry("keys null", "{\"keys\":null}"),
						Map.entry("keys a string", "{\"keys\":\"" + RSA.replace("\"", "\\\"") + "\"}"),
						Map.entry("a number among the keys", "{\"keys\":[" + RSA + ",1]}"),
						Map.entry("null among the keys", "{\"keys\":[" + RSA + ",null]}"),
						Map.entry("an array among the keys", "{\"keys\":[" + RSA + ",[]]}"),
						Map.entry("a string among the keys", "{\"keys\":[\"" + "x" + "\"," + RSA + "]}"),
						Map.entry("keys twice", "{\"keys\":[],\"keys\":[" + RSA + "]}"),
						Map.entry("a member twice in a key", "{\"keys\":[" + RSA.replace("{\"kty\":\"RSA\",",
								"{\"kty\":\"RSA\",\"kty\":\"RSA\",") + "]}"),
						Map.entry("a leading byte-order mark", (char) 0xFEFF + "{\"keys\":[]}"),
						Map.entry("nesting deeper than 32", deep))
				.map(row -> DynamicTest.dynamicTest(row.getKey(), () -> {
					assertKeySetFailure(() -> JwkSetParser.parse(row.getValue(), MAXIMUM_BYTES, MAXIMUM_KEYS));
					assertKeySetFailure(() -> JwkSetParser.parse(row.getValue().getBytes(StandardCharsets.UTF_8),
							MAXIMUM_BYTES, MAXIMUM_KEYS));
				}));
	}

	// The byte path takes a response body, which may be anything: ill-formed UTF-8 is a document failure.
	@Test
	void illFormedUtf8IsADocumentFailure() {
		byte[] prefix = "{\"keys\":[],\"x\":\"".getBytes(StandardCharsets.UTF_8);
		for (byte[] bad : List.of(new byte[]{(byte) 0xC0, (byte) 0x80}, new byte[]{(byte) 0xED, (byte) 0xA0, (byte) 0x80},
				new byte[]{(byte) 0xFF}, new byte[]{(byte) 0xE2, (byte) 0x82})) {
			byte[] document = new byte[prefix.length + bad.length + 2];
			System.arraycopy(prefix, 0, document, 0, prefix.length);
			System.arraycopy(bad, 0, document, prefix.length, bad.length);
			document[document.length - 2] = '"';
			document[document.length - 1] = '}';
			assertKeySetFailure(() -> JwkSetParser.parse(document, MAXIMUM_BYTES, MAXIMUM_KEYS));
		}
	}

	// The text path encodes as strict UTF-8, so text with an unpaired surrogate has no encoding and is a document
	// failure rather than a replacement character.
	@Test
	void textWithAnUnpairedSurrogateIsADocumentFailure() {
		for (char surrogate : new char[]{(char) 0xD800, (char) 0xDFFF})
			assertKeySetFailure(() -> JwkSetParser.parse("{\"keys\":[],\"x\":\"" + surrogate + "\"}", MAXIMUM_BYTES,
					MAXIMUM_KEYS));
	}

	// The key limit counts every element of "keys", usable or not, and is checked before any key is parsed.
	@Test
	void theKeyLimitCountsEveryElement() throws JoseFailure {
		List<String> three = List.of(RSA, OCT, ENCRYPTION);
		ParsedKeySet atLimit = JwkSetParser.parse(TestJsonWebKeys.keySet(three), MAXIMUM_BYTES, 3);
		Assertions.assertEquals(3, atLimit.elementCount());

		List<String> four = List.of(OCT, OCT, OCT, OCT);
		assertKeySetFailure(() -> JwkSetParser.parse(TestJsonWebKeys.keySet(four), MAXIMUM_BYTES, 3));
		assertKeySetFailure(() -> JwkSetParser.parse(TestJsonWebKeys.keySet(Collections.nCopies(101, "{}")),
				MAXIMUM_BYTES, MAXIMUM_KEYS));
		Assertions.assertEquals(100, JwkSetParser.parse(TestJsonWebKeys.keySet(Collections.nCopies(100, "{}")),
				MAXIMUM_BYTES, MAXIMUM_KEYS).skips().size());
		// A non-object element beyond the limit still fails as a document, whichever check comes first.
		assertKeySetFailure(() -> JwkSetParser.parse("{\"keys\":[1,2]}", MAXIMUM_BYTES, 1));
	}

	// The size limit is in UTF-8 bytes: a document exactly at the limit passes and one byte more fails, on both paths,
	// and text whose UTF-16 length fits but whose UTF-8 encoding does not fails too.
	@Test
	void theSizeLimitIsInUtf8Bytes() throws JoseFailure {
		String base = "{\"keys\":[" + RSA + "],\"pad\":\"\"}";
		int limit = base.length() + 100;
		String atLimit = pad(base, 100, 'a');
		Assertions.assertEquals(limit, atLimit.getBytes(StandardCharsets.UTF_8).length);

		Assertions.assertEquals(1, JwkSetParser.parse(atLimit, limit, MAXIMUM_KEYS).keys().size());
		Assertions.assertEquals(1, JwkSetParser.parse(atLimit.getBytes(StandardCharsets.UTF_8), limit, MAXIMUM_KEYS)
				.keys().size());

		String overLimit = pad(base, 101, 'a');
		assertKeySetFailure(() -> JwkSetParser.parse(overLimit, limit, MAXIMUM_KEYS));
		assertKeySetFailure(() -> JwkSetParser.parse(overLimit.getBytes(StandardCharsets.UTF_8), limit, MAXIMUM_KEYS));

		// 60 two-byte characters: 60 UTF-16 code units, 120 UTF-8 bytes.
		String wide = pad(base, 60, (char) 0xE9);
		Assertions.assertTrue(wide.length() <= limit);
		assertKeySetFailure(() -> JwkSetParser.parse(wide, limit, MAXIMUM_KEYS));
		Assertions.assertEquals(1, JwkSetParser.parse(pad(base, 50, (char) 0xE9), limit, MAXIMUM_KEYS).keys().size());
	}

	// The limits come from validated settings, so a value outside the profile's range is a programming error.
	@Test
	@SuppressWarnings("NullAway")
	void limitsOutsideTheirRangesAreProgrammingErrors() {
		byte[] bytes = "{\"keys\":[]}".getBytes(StandardCharsets.UTF_8);

		Assertions.assertThrows(IllegalArgumentException.class, () -> JwkSetParser.parse(bytes, MAXIMUM_BYTES, 0));
		Assertions.assertThrows(IllegalArgumentException.class, () -> JwkSetParser.parse(bytes, 0, MAXIMUM_KEYS));
		Assertions.assertThrows(IllegalArgumentException.class, () -> JwkSetParser.parse(bytes, FOUR_MIB + 1,
				MAXIMUM_KEYS));
		Assertions.assertThrows(IllegalArgumentException.class, () -> JwkSetParser.parse("{\"keys\":[]}", MAXIMUM_BYTES,
				0));
		Assertions.assertThrows(IllegalArgumentException.class, () -> JwkSetParser.parse("{\"keys\":[]}", 0,
				MAXIMUM_KEYS));
		Assertions.assertThrows(NullPointerException.class, () -> JwkSetParser.parse((String) null, MAXIMUM_BYTES,
				MAXIMUM_KEYS));
		Assertions.assertThrows(NullPointerException.class, () -> JwkSetParser.parse((byte[]) null, MAXIMUM_BYTES,
				MAXIMUM_KEYS));
	}

	// A set with every kind of skip reports each one in order, and the byte and text paths agree.
	@Test
	void everySkipReasonIsReportedInOrderOnBothPaths() throws JoseFailure {
		List<String> keys = new ArrayList<>();
		keys.add(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).withoutMember("kty").toJson());
		keys.add(JsonText.object(List.of(Map.entry("kty", "\"RSA2\""))));
		keys.add(OCT);
		keys.add(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).includePrivateMembers(true).toJson());
		keys.add(ENCRYPTION);
		keys.add(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).alg("RSA-OAEP").toJson());
		keys.add(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P256).alg("ES384").toJson());
		keys.add(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P256).member("crv", "\"secp256k1\"").toJson());
		keys.add(TestJsonWebKeys.withFixture(Fixture.NEGATIVE_RSA_1024).toJson());
		keys.add(TestJsonWebKeys.rsaWithEvenExponent().toJson());
		keys.add(TestJsonWebKeys.ecOffCurve().toJson());
		keys.add(TestJsonWebKeys.ed25519SmallOrder().toJson());
		keys.add(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).x5c(List.of(Fixture.SP_SIGNING_RSA_2048
				.getCertificate().orElseThrow())).toJson());
		keys.add(RSA);
		String document = TestJsonWebKeys.keySet(keys);

		ParsedKeySet fromText = JwkSetParser.parse(document, MAXIMUM_BYTES, MAXIMUM_KEYS);
		ParsedKeySet fromBytes = JwkSetParser.parse(document.getBytes(StandardCharsets.UTF_8), MAXIMUM_BYTES,
				MAXIMUM_KEYS);

		List<JsonWebKeySkipReason> reasons = fromText.skips().stream().map(ParsedKeySet.Skip::reason).toList();
		Assertions.assertEquals(List.of(JsonWebKeySkipReason.MALFORMED_KEY, JsonWebKeySkipReason.UNSUPPORTED_KEY_TYPE,
				JsonWebKeySkipReason.SYMMETRIC_KEY, JsonWebKeySkipReason.PRIVATE_KEY_MEMBERS,
				JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY, JsonWebKeySkipReason.UNSUPPORTED_ALGORITHM,
				JsonWebKeySkipReason.ALGORITHM_MISMATCH, JsonWebKeySkipReason.UNSUPPORTED_CURVE,
				JsonWebKeySkipReason.RSA_KEY_SIZE, JsonWebKeySkipReason.RSA_EXPONENT,
				JsonWebKeySkipReason.EC_POINT_NOT_ON_CURVE, JsonWebKeySkipReason.WEAK_KEY,
				JsonWebKeySkipReason.CERTIFICATE_MISMATCH), reasons);
		Assertions.assertEquals(List.of(JsonWebKeySkipReason.values()), reasons, "every reason, in declaration order");
		Assertions.assertEquals(List.of(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12),
				fromText.skips().stream().map(ParsedKeySet.Skip::index).toList());
		Assertions.assertEquals(fromText, fromBytes);
		Assertions.assertEquals(1, fromText.keys().size());
	}

	// ParsedKeySet copies its lists, and a skip's position cannot be negative.
	@Test
	void parsedKeySetsAreImmutableValues() throws JoseFailure {
		List<ParsedKeySet.Skip> skips = new ArrayList<>(List.of(new ParsedKeySet.Skip(0,
				JsonWebKeySkipReason.WEAK_KEY)));
		ParsedKeySet parsed = new ParsedKeySet(List.of(), skips);
		skips.clear();

		Assertions.assertEquals(1, parsed.skips().size());
		Assertions.assertThrows(UnsupportedOperationException.class, () -> parsed.skips().clear());
		Assertions.assertThrows(IllegalArgumentException.class, () -> new ParsedKeySet.Skip(-1,
				JsonWebKeySkipReason.WEAK_KEY));
		Assertions.assertEquals(parse(TestJsonWebKeys.keySet(List.of(RSA, OCT))),
				parse(TestJsonWebKeys.keySet(List.of(RSA, OCT))));
	}

	private static ParsedKeySet parse(String document) throws JoseFailure {
		return JwkSetParser.parse(document, MAXIMUM_BYTES, MAXIMUM_KEYS);
	}

	private static void assertKeySetFailure(ThrowingParse parse) {
		JoseFailure failure = Assertions.assertThrows(JoseFailure.class, parse::run);
		Assertions.assertEquals(JoseException.Reason.KEY_SET, failure.getReason());
		Assertions.assertNull(failure.getCause());
		Assertions.assertEquals(0, failure.getStackTrace().length);
	}

	/**
	 * {@code base} with {@code count} copies of {@code filler} inside its empty {@code pad} string.
	 */
	private static String pad(String base, int count, char filler) {
		return base.replace("\"pad\":\"\"", "\"pad\":\"" + String.valueOf(filler).repeat(count) + "\"");
	}

	@FunctionalInterface
	private interface ThrowingParse {
		void run() throws JoseFailure;
	}
}
