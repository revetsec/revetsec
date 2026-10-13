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

import com.revetsec.internal.json.JsonParseException.Kind;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import com.revetsec.testing.Sentinels;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.IntStream;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Independent assertions for the direct parser outcome and number-token lexical evidence. */
final class JsonParseResultTests {
	private static final @NonNull JsonLimits LIMITS = new JsonLimits(256, 4, 20, 16, 12, 20, false);

	@Test
	void everyRejectionKindHasItsIndependentExpectedByteOffset() {
		rejected(Kind.INPUT_SIZE, 4, utf8(" false"), new JsonLimits(4, 4, 20, 16, 12, 20, false));
		rejected(Kind.BOM, 0, new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF, '0'}, LIMITS);
		rejected(Kind.INVALID_UTF8, 1, new byte[]{'"', (byte) 0xC0, (byte) 0xAF, '"'}, LIMITS);
		rejected(Kind.SYNTAX, 3, utf8("[1,]"), LIMITS);
		rejected(Kind.UNPAIRED_SURROGATE, 1, utf8("\"\\uD800\""), LIMITS);
		rejected(Kind.DUPLICATE_MEMBER, 7, utf8("{\"a\":1,\"a\":2}"), LIMITS);
		rejected(Kind.DEPTH, 4, utf8("[[[[0]]]]"), LIMITS);
		rejected(Kind.NODES, 5, utf8("[0,0,0]"), new JsonLimits(256, 4, 3, 16, 12, 20, false));
		rejected(Kind.STRING_LENGTH, 0, utf8("\"12345\""), new JsonLimits(256, 4, 20, 4, 12, 20, false));
		rejected(Kind.NUMBER_LENGTH, 0, utf8("1234567890123"), LIMITS);
		rejected(Kind.EXPONENT, 0, utf8("1e21"), LIMITS);
	}

	@Test
	void precedenceAndEarlyFailureOffsetsRemainTheExistingWireContract() {
		JsonLimits fourBytes = new JsonLimits(4, 4, 20, 16, 12, 20, false);
		rejected(Kind.INPUT_SIZE, 4, new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF, (byte) 0xC0, '0'}, fourBytes);
		rejected(Kind.BOM, 0, new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF, (byte) 0xC0}, fourBytes);
		rejected(Kind.INVALID_UTF8, 1, new byte[]{'}', (byte) 0xC0}, LIMITS);
		rejected(Kind.DUPLICATE_MEMBER, 7, utf8("{\"a\":1,\"a\":]}"), LIMITS);
		rejected(Kind.SYNTAX, 5, utf8("\"\\u12X4\""), LIMITS);
		rejected(Kind.SYNTAX, 5, utf8("\"\\u12"), LIMITS);
		rejected(Kind.UNPAIRED_SURROGATE, 1, utf8("\"\\uD800\\uXX00\""), LIMITS);
		rejected(Kind.NUMBER_LENGTH, 0, utf8("1e-6"), new JsonLimits(256, 4, 20, 16, 6, 20, false));
	}

	@Test
	void scimProfilePreservesAsciiCaseDuplicateChecksAtEveryLevel() {
		JsonLimits scim = JsonLimits.scim(256, 1_000);
		String input = """
				{"a":{"X":1,"x":2}}""";
		rejected(Kind.DUPLICATE_MEMBER, 12, utf8(input), scim);
		JsonDocument exact = document(input, LIMITS);
		assertEquals(input, exact.getValue().toJson());
		// SCIM folding is ASCII-only: these distinct Unicode member names remain distinct.
		assertInstanceOf(JsonParseResult.Succeeded.class, JsonCodec.parseResult(utf8("{\"\u00c4\":1,\"\u00e4\":2}"), scim));
	}

	@Test
	void equalNumericValuesKeepFourIndependentLexicalFlagCombinations() {
		JsonDocument parsed = document("[1,1.0,1E0,1.00e+0]", LIMITS);
		List<JsonValue> numbers = ((JsonArray) parsed.getValue()).getElements();
		boolean[] fractions = {false, true, false, true};
		boolean[] exponents = {false, false, true, true};

		for (int index = 0; index < numbers.size(); ++index) {
			JsonNumber number = (JsonNumber) numbers.get(index);
			assertEquals(numbers.get(0), number);
			assertEquals(numbers.get(0).hashCode(), number.hashCode());
			JsonNumberSyntax syntax = parsed.numberSyntax(number).orElseThrow();
			assertEquals(fractions[index], syntax.hadFraction());
			assertEquals(exponents[index], syntax.hadExponent());
		}
	}

	@Test
	void lexicalEvidenceFollowsNodesAcrossNestingButNeverEqualOutsideNodes() {
		JsonDocument parsed = document("{\"a\":[-0,{\"b\":0.0E-0}]}", LIMITS);
		JsonObject root = (JsonObject) parsed.getValue();
		JsonArray array = (JsonArray) requireNonNull(root.getMembers().get("a"));
		JsonNumber integer = (JsonNumber) array.getElements().get(0);
		JsonObject nested = (JsonObject) array.getElements().get(1);
		JsonNumber fractionalExponent = (JsonNumber) requireNonNull(nested.getMembers().get("b"));
		assertFalse(parsed.numberSyntax(integer).orElseThrow().hadFraction());
		assertFalse(parsed.numberSyntax(integer).orElseThrow().hadExponent());
		assertTrue(parsed.numberSyntax(fractionalExponent).orElseThrow().hadFraction());
		assertTrue(parsed.numberSyntax(fractionalExponent).orElseThrow().hadExponent());
		assertEquals(integer, fractionalExponent);
		assertTrue(parsed.numberSyntax(JsonNumber.fromValue(BigDecimal.ZERO)).isEmpty());
		assertTrue(parsed.numberSyntax((JsonNumber) document("0", LIMITS).getValue()).isEmpty());
	}

	@Test
	void carrierCopiesItsIdentityMapWithoutCollapsingEqualValuedKeys() {
		JsonNumber integer = JsonNumber.fromValue(1L);
		JsonNumber fraction = JsonNumber.fromValue(new BigDecimal("1.0"));
		IdentityHashMap<JsonNumber, JsonNumberSyntax> source = new IdentityHashMap<>();
		source.put(integer, JsonNumberSyntax.from(false, false));
		source.put(fraction, JsonNumberSyntax.from(true, false));
		JsonDocument parsed = new JsonDocument(JsonArray.fromElements(List.of(integer, fraction)), source);
		source.clear();
		assertFalse(parsed.numberSyntax(integer).orElseThrow().hadFraction());
		assertTrue(parsed.numberSyntax(fraction).orElseThrow().hadFraction());
	}

	@Test
	void byteInputIsNotRetainedByTheCompleteDocument() {
		byte[] input = utf8("{\"n\":1.0}");
		JsonParseResult.Succeeded parsed = assertInstanceOf(JsonParseResult.Succeeded.class,
				JsonCodec.parseResult(input, LIMITS));
		java.util.Arrays.fill(input, (byte) 0);
		assertEquals("{\"n\":1.0}", parsed.getDocument().getValue().toJson());
		JsonNumber number = (JsonNumber) requireNonNull(((JsonObject) parsed.getDocument().getValue()).getMembers().get("n"));
		assertTrue(parsed.getDocument().numberSyntax(number).orElseThrow().hadFraction());
	}

	@Test
	void lexicalEvidenceLookupAndIndependentParsesAreSafeAcrossThreads() {
		JsonDocument parsed = document("[1,1.0,1e0,1.0e0]", LIMITS);
		JsonArray array = (JsonArray) parsed.getValue();
		IntStream.range(0, 256).parallel().forEach(index -> {
			int slot = index % 4;
			JsonNumberSyntax syntax = parsed.numberSyntax((JsonNumber) array.getElements().get(slot)).orElseThrow();
			assertEquals(slot == 1 || slot == 3, syntax.hadFraction());
			assertEquals(slot >= 2, syntax.hadExponent());
			assertEquals(parsed.getValue(), document("[1,1.0,1e0,1.0e0]", LIMITS).getValue());
		});
	}

	@Test
	void outcomeShapeCannotRetainInputFailuresOrPartiallyParsedValues() {
		assertTrue(JsonParseResult.class.isSealed());
		assertEquals(Set.of(JsonParseResult.Succeeded.class, JsonParseResult.Rejected.class),
				Set.of(JsonParseResult.class.getPermittedSubclasses()));
		for (Class<?> outcome : JsonParseResult.class.getPermittedSubclasses()) {
			assertTrue(Modifier.isFinal(outcome.getModifiers()));
			for (var constructor : outcome.getDeclaredConstructors())
				assertTrue(Modifier.isPrivate(constructor.getModifiers()));
			for (var field : outcome.getDeclaredFields()) {
				assertTrue(Modifier.isFinal(field.getModifiers()));
				assertTrue(Modifier.isPrivate(field.getModifiers()));
				assertFalse(Throwable.class.isAssignableFrom(field.getType()));
				assertNotEquals(byte[].class, field.getType());
			}
		}
		assertEquals(Map.of("kind", Kind.class, "byteOffset", int.class),
				java.util.Arrays.stream(JsonParseResult.Rejected.class.getDeclaredFields()).collect(
						java.util.stream.Collectors.toMap(java.lang.reflect.Field::getName, java.lang.reflect.Field::getType)));
	}

	@Test
	void resultAndDocumentDiagnosticsRedactAcceptedAndRejectedSecrets() {
		String secret = Sentinels.secret("json-direct-result");
		JsonParseResult accepted = JsonCodec.parseResult(utf8("\"" + secret + "\""), JsonLimits.protocolDocument(256));
		JsonDocument parsed = ((JsonParseResult.Succeeded) accepted).getDocument();
		JsonParseResult rejected = JsonCodec.parseResult(utf8("[\"" + secret + "\",]"), JsonLimits.protocolDocument(256));
		assertInstanceOf(JsonParseResult.Rejected.class, rejected);
		Sentinels.assertAbsent(accepted);
		Sentinels.assertAbsent(parsed);
		Sentinels.assertAbsent(rejected);
		assertEquals(secret, ((JsonString) parsed.getValue()).getValue());
	}

	@Test
	@SuppressWarnings("NullAway")
	void nonnullContractsFailAsProgrammingErrorsBeforeParsing() {
		assertThrows(NullPointerException.class, () -> JsonCodec.parseResult(null, LIMITS));
		assertThrows(NullPointerException.class, () -> JsonCodec.parseResult(utf8("0"), null));
		assertThrows(NullPointerException.class, () -> document("0", LIMITS).numberSyntax(null));
	}

	private static void rejected(@NonNull Kind kind, int offset, byte @NonNull [] input, @NonNull JsonLimits limits) {
		JsonParseResult.Rejected result = assertInstanceOf(JsonParseResult.Rejected.class, JsonCodec.parseResult(input, limits));
		assertEquals(kind, result.getKind());
		assertEquals(offset, result.getByteOffset());
		assertTrue(result.getByteOffset() >= 0 && result.getByteOffset() <= input.length);
		// The throwing compatibility API must translate the same direct result without changing its contract.
		JsonParseException wrapper = JsonFailures.assertRejected(kind, offset, input, limits);
		assertEquals(result.getKind(), wrapper.getKind());
		assertEquals(result.getByteOffset(), wrapper.getByteOffset());
	}

	private static @NonNull JsonDocument document(@NonNull String input, @NonNull JsonLimits limits) {
		return assertInstanceOf(JsonParseResult.Succeeded.class, JsonCodec.parseResult(utf8(input), limits)).getDocument();
	}

	private static byte @NonNull [] utf8(@NonNull String input) {
		return input.getBytes(StandardCharsets.UTF_8);
	}
}
