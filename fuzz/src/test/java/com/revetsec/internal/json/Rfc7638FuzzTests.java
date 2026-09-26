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

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.revetsec.internal.json.JsonFieldException.Kind;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.junit.jupiter.api.Assertions;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Coverage-guided checks for {@link Rfc7638#canonicalJwk(JsonObject)}, the input of every JWK thumbprint (RFC 7638
 * section 3; exit criterion 4).
 * <p>
 * Seeds: the core JSON corpus and JSONTestSuite, mapped in by the fuzz pom as for the codec target (the corpus holds
 * a JWKS with RSA, EC and OKP keys), plus hand-written single JWKs in this method's inputs directory: one per key
 * type, one per failure (lowercase {@code kty}, a missing or non-string member, a value JSON must escape), and the
 * characters on either side of the escape rule (U+001F must be escaped; a space and U+007F need not be).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public class Rfc7638FuzzTests {
	private static final JsonLimits PROTOCOL = JsonLimits.protocolDocument(
			JsonLimits.PROTOCOL_DOCUMENT_INPUT_BYTES_CAP);
	private static final JsonLimits MAXIMUM = JsonFuzzSupport.maximumCaps();
	private static final Map<String, List<String>> REQUIRED_MEMBERS = Map.of(
			"RSA", List.of("e", "kty", "n"),
			"EC", List.of("crv", "kty", "x", "y"),
			"OKP", List.of("crv", "kty", "x"),
			"oct", List.of("k", "kty"));

	/**
	 * For every object in the parsed document, {@code canonicalJwk} gives exactly what an independent encoder gives:
	 * the key type's required members (RFC 7638 section 3.2; RFC 7518 section 6; RFC 8037 section 2) in
	 * lexicographic order, each value a JSON string written as is, with no whitespace; or, in the same order of checks,
	 * {@link JsonFieldException} with the same {@link Kind} and its fixed message: {@code MISSING}, {@code WRONG_TYPE},
	 * or {@code UNSUPPORTED} for an unknown {@code kty} or a value JSON must escape (section 3.3). Nothing else is
	 * thrown (INV-G1). The result ignores member order and every other member, and it is a fixed point: it parses as a
	 * JWK whose canonical form is itself.
	 *
	 * @param input the fuzzed document
	 */
	@FuzzTest(maxDuration = "5m")
	public void canonicalJwkAgreesWithAnIndependentEncoder(byte[] input) throws JsonParseException {
		JsonValue document;

		try {
			document = JsonCodec.parse(input, PROTOCOL);
		} catch (JsonParseException e) {
			JsonFuzzSupport.requireFixedShape(e, input.length);
			return;
		}

		List<JsonObject> objects = new ArrayList<>();
		collectObjects(document, objects);

		for (JsonObject jwk : objects) {
			Expected expected = expectedCanonicalForm(jwk);
			byte[] actual = canonicalJwkOrNull(jwk, expected);

			if (actual == null)
				continue;

			Assertions.assertArrayEquals(expected.canonical, actual, "canonicalJwk differs from the independent encoder");
			Assertions.assertArrayEquals(actual, canonicalJwkOrNull(reversed(jwk), expected),
					"canonicalJwk depends on member order");

			// The canonical form is a JWK itself, with only the required members, and its own canonical form.
			JsonValue reparsed = JsonCodec.parse(actual, MAXIMUM);
			Assertions.assertTrue(reparsed instanceof JsonObject, "the canonical form is not a JSON object");
			Assertions.assertEquals(expected.members, new ArrayList<>(((JsonObject) reparsed).getMembers().keySet()),
					"the canonical form does not hold exactly the required members in order");
			Assertions.assertArrayEquals(actual, canonicalJwkOrNull((JsonObject) reparsed, expected),
					"the canonical form is not a fixed point");
		}
	}

	/**
	 * Runs {@code canonicalJwk}, requiring a failure to be the expected {@link Kind} with its fixed message.
	 *
	 * @return the canonical bytes, or {@code null} after the expected failure
	 */
	private static byte[] canonicalJwkOrNull(JsonObject jwk, Expected expected) {
		try {
			byte[] canonical = Rfc7638.canonicalJwk(jwk);
			Assertions.assertNull(expected.failure, () -> "accepted a JWK the oracle rejects with " + expected.failure);
			return canonical;
		} catch (JsonFieldException e) {
			JsonFuzzSupport.requireFixedShape(e);
			Assertions.assertEquals(expected.failure, e.getKind(), "canonicalJwk failed with the wrong Kind");
			return null;
		}
	}

	/**
	 * The independent encoder: RFC 7638 section 3 applied directly, in the order of checks {@link Rfc7638} documents
	 * ({@code kty} first, then each required member in lexicographic order).
	 */
	private static Expected expectedCanonicalForm(JsonObject jwk) {
		Map<String, JsonValue> members = jwk.getMembers();
		JsonValue keyType = members.get("kty");

		if (keyType == null)
			return Expected.failing(Kind.MISSING);

		if (!(keyType instanceof JsonString keyTypeString))
			return Expected.failing(Kind.WRONG_TYPE);

		List<String> required = REQUIRED_MEMBERS.get(keyTypeString.getValue());

		if (required == null)
			return Expected.failing(Kind.UNSUPPORTED);

		StringBuilder canonical = new StringBuilder("{");

		for (String name : required) {
			JsonValue value = members.get(name);

			if (value == null)
				return Expected.failing(Kind.MISSING);

			if (!(value instanceof JsonString string))
				return Expected.failing(Kind.WRONG_TYPE);

			for (char character : string.getValue().toCharArray())
				if (character < 0x20 || character == '"' || character == '\\')
					return Expected.failing(Kind.UNSUPPORTED);

			if (canonical.length() > 1)
				canonical.append(',');

			canonical.append('"').append(name).append("\":\"").append(string.getValue()).append('"');
		}

		return new Expected(null, canonical.append('}').toString().getBytes(StandardCharsets.UTF_8), required);
	}

	private static JsonObject reversed(JsonObject jwk) {
		List<Map.Entry<String, JsonValue>> members = new ArrayList<>(jwk.getMembers().entrySet());
		Collections.reverse(members);
		LinkedHashMap<String, JsonValue> reversed = new LinkedHashMap<>();

		for (Map.Entry<String, JsonValue> member : members)
			reversed.put(member.getKey(), member.getValue());

		return JsonObject.fromMembers(reversed);
	}

	/**
	 * Every object in the document, at any depth: a JWKS's keys, and any object a mutation produces.
	 */
	private static void collectObjects(JsonValue value, List<JsonObject> objects) {
		if (value instanceof JsonObject object) {
			objects.add(object);

			for (JsonValue member : object.getMembers().values())
				collectObjects(member, objects);
		} else if (value instanceof JsonArray array) {
			for (JsonValue element : array.getElements())
				collectObjects(element, objects);
		}
	}

	/**
	 * What the independent encoder expects: a failure Kind, or the canonical bytes and member names.
	 */
	@Immutable
	private static final class Expected {
		private final Kind failure;
		private final byte[] canonical;
		private final List<String> members;

		private Expected(Kind failure, byte[] canonical, List<String> members) {
			this.failure = failure;
			this.canonical = canonical;
			this.members = members;
		}

		private static Expected failing(Kind failure) {
			return new Expected(failure, new byte[0], List.of());
		}
	}
}
