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
import com.revetsec.internal.Limits;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.internal.json.JsonParseException.Kind;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonNull;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.junit.jupiter.api.Assertions;

import javax.annotation.concurrent.ThreadSafe;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Coverage-guided checks for {@link JsonCodec#parse(byte[], JsonLimits)} under every profile (M1 plan, gate 7 and
 * exit criteria 1, 2 and 18).
 * <p>
 * Seeds: the core JSON corpus ({@code src/test/resources/com/revetsec/internal/json/corpus/parse} and
 * {@code round-trip}, the 25 files ported from Soklet plus the protocol-shaped ones) and every JSONTestSuite
 * {@code test_parsing} file, mapped into each method's {@code JsonCodecFuzzTestsInputs/<method>/} directory by the fuzz
 * pom. Neither is copied into the fuzz module; their SHA-256 manifests are checked by the core build.
 * <p>
 * The profiles: {@code protocolDocument} at its 4 MiB cap, {@code jose} at 1 KiB (so {@link Kind#INPUT_SIZE} is
 * reachable), {@code scim} at its 10 MiB cap with the node floor of 1,000 (so {@link Kind#NODES} is reachable with
 * inputs of a few KiB), a synthetic tight profile far below the registry floors ({@link JsonFuzzSupport#tightLimits()},
 * so {@link Kind#STRING_LENGTH} and every other structural limit are a few bytes away), and the package-private
 * maximum-cap profile. Work is bounded by the profile: the parse target asserts that an accepted document stays inside
 * every limit of its profile, measured on the value and on the number texts, and libFuzzer's {@code -timeout} stops a
 * slow input (25 s under ClusterFuzzLite, which reports a timeout only when its {@code REPORT_TIMEOUTS} setting is on).
 * <p>
 * Further hand-written seeds sit one past a limit: 33 and 65 nested arrays, 1,001 nodes, a string of 7 code units (or
 * of 4 supplementary characters) for the tight profile, and numbers whose text, written exponent, adjusted exponent or
 * canonical form is one over its limit. Each one kills a planted off-by-one in the matching codec check.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public class JsonCodecFuzzTests {
	private static final JsonLimits PROTOCOL = JsonLimits.protocolDocument(
			JsonLimits.PROTOCOL_DOCUMENT_INPUT_BYTES_CAP);
	private static final JsonLimits JOSE = JsonLimits.jose(1_024);
	private static final JsonLimits SCIM = JsonLimits.scim(JsonLimits.SCIM_INPUT_BYTES_CAP,
			Math.toIntExact(Limits.SCIM_JSON_NODES.getFloor()));
	private static final JsonLimits SCIM_WITH_EXACT_NAMES = JsonFuzzSupport.exactNameTwinOf(SCIM);
	private static final JsonLimits TIGHT = JsonFuzzSupport.tightLimits();
	private static final JsonLimits MAXIMUM = JsonFuzzSupport.maximumCaps();
	private static final List<JsonLimits> PROFILES = List.of(PROTOCOL, JOSE, SCIM, TIGHT, MAXIMUM);
	private static final int MAXIMUM_NEAR_MISS_OBJECTS = 8;
	/**
	 * For each lowercase ASCII letter, the non-ASCII letters that {@code Character.toLowerCase} or
	 * {@code toUpperCase} relate to it: dotless i and dotted capital I, the Kelvin sign, the long s. An ASCII-only fold
	 * must keep them apart from the ASCII letter (G7-7).
	 */
	private static final Map<Character, String> UNICODE_CASE_LOOKALIKES = Map.of(
			'i', "\u0131\u0130",
			'k', "\u212A",
			's', "\u017F");

	/**
	 * Only {@link JsonParseException} escapes, with a fixed message and an offset inside the input, so
	 * {@link IllegalArgumentException} (misuse only, G7-3) never escapes {@code parse} (G7-6, exit 18, INV-G1). The
	 * pre-tokenizing checks run in their documented order and agree with the JDK: {@link Kind#INPUT_SIZE} exactly
	 * when the input is over the profile's limit, then {@link Kind#BOM} exactly for a leading EF BB BF, then
	 * {@link Kind#INVALID_UTF8} exactly when the JDK's strict decoder rejects the input, at the offset where it stops.
	 * An accepted document satisfies every limit of its profile, on the value (depth, nodes, string length, digits,
	 * canonical number length, adjusted exponent) and on the text (each number's length and written exponent), holds
	 * only exact {@code BigDecimal} numbers and well-formed strings, and is accepted with an equal value by the
	 * maximum-cap profile, which every other profile is inside.
	 *
	 * @param input the fuzzed document
	 */
	@FuzzTest(maxDuration = "5m")
	public void parseRejectsOnlyWithJsonParseExceptionAndAcceptsOnlyValuesInsideTheProfile(byte[] input) {
		int jdkMalformedOffset = jdkStrictUtf8MalformedOffset(input);
		JsonValue maximumValue = null;
		boolean maximumAccepted = false;

		// The maximum-cap profile runs last, so the check below can compare the others' values with its value.
		for (int index = PROFILES.size() - 1; index >= 0; --index) {
			JsonLimits limits = PROFILES.get(index);
			JsonValue value;

			try {
				value = JsonCodec.parse(input, limits);
			} catch (JsonParseException e) {
				JsonFuzzSupport.requireFixedShape(e, input.length);
				requirePreTokenizingOrder(e, input, limits, jdkMalformedOffset);
				continue;
			}

			Assertions.assertTrue(input.length <= limits.getMaxInputBytes(), "accepted input over the byte limit");
			Assertions.assertFalse(startsWithByteOrderMark(input), "accepted a leading byte-order mark");
			Assertions.assertEquals(-1, jdkMalformedOffset, "accepted input the JDK's strict decoder rejects");
			requireInsideProfile(value, limits, input.length);
			requireNumberTextsInsideProfile(input, limits);

			if (limits == MAXIMUM) {
				maximumValue = value;
				maximumAccepted = true;
			} else {
				Assertions.assertTrue(maximumAccepted, "a profile accepted input that the maximum-cap profile rejected");
				Assertions.assertEquals(maximumValue, value, "two profiles parsed one input to different values");
			}
		}
	}

	/**
	 * A value any profile accepts round-trips through {@code toJson()} under the maximum-cap profile (G7-4, G7-6, exit
	 * 18): the serialized text parses back to an equal value with an equal hash, and serializing that value gives
	 * byte-identical text, so the canonical form is a fixed point. The serialized text also parses under the profile
	 * that accepted the input whenever it fits that profile's byte limit, because the codec bounds a number's
	 * canonical form, not only its text.
	 *
	 * @param input the fuzzed document
	 */
	@FuzzTest(maxDuration = "5m")
	public void acceptedValuesRoundTripUnderTheMaximumCapProfile(byte[] input) throws JsonParseException {
		for (JsonLimits limits : PROFILES) {
			JsonValue value;

			try {
				value = JsonCodec.parse(input, limits);
			} catch (JsonParseException e) {
				JsonFuzzSupport.requireFixedShape(e, input.length);
				continue;
			}

			byte[] serialized = JsonCodec.toUtf8Bytes(value);
			Assertions.assertEquals(value.toJson(), new String(serialized, StandardCharsets.UTF_8),
					"toJson() and toUtf8Bytes() disagree");

			// Any JsonParseException here is a finding: the maximum-cap profile must accept every accepted value.
			JsonValue reparsed = JsonCodec.parse(serialized, MAXIMUM);
			Assertions.assertEquals(value, reparsed, "the round trip changed the value");
			Assertions.assertEquals(value.hashCode(), reparsed.hashCode(), "the round trip changed the hash");
			Assertions.assertArrayEquals(serialized, JsonCodec.toUtf8Bytes(reparsed),
					"the canonical form is not a fixed point");

			if (serialized.length <= limits.getMaxInputBytes())
				Assertions.assertEquals(value, JsonCodec.parse(serialized, limits),
						"the canonical form left the profile that accepted the input");
		}
	}

	/**
	 * Whatever the SCIM profile accepts, the same limits with exact name comparison (the protocol profiles' rule,
	 * "exact" in {@link JsonLimits}) accept with an equal value (G7-7, the WP-8 row). More precisely, SCIM accepts
	 * exactly when the exact-name twin accepts a value in which no object holds two names that differ only in ASCII
	 * case, as measured by an independent fold; when SCIM rejects for any other reason, the twin rejects with the same
	 * {@link Kind} at the same offset; and a SCIM {@link Kind#DUPLICATE_MEMBER} is never after the twin's own failure.
	 * <p>
	 * A byte-level fuzzer rarely writes two names that differ only in case, so each object the twin accepts (up to
	 * eight) is also checked with one more member whose name is a near miss of its first name with a letter: that
	 * letter with its ASCII case flipped, which SCIM must reject, and the non-ASCII letters that Unicode case mapping
	 * folds onto it ({@code ı}, {@code İ}, the Kelvin sign, the long s), which SCIM must keep distinct (exit 3).
	 *
	 * @param input the fuzzed document
	 */
	@FuzzTest(maxDuration = "5m")
	public void scimAcceptsOnlyWhatTheExactNameProfileAccepts(byte[] input) {
		JsonValue exactValue = requireScimAgreesWithExactNames(input);

		if (exactValue == null)
			return;

		List<JsonObject> objects = new ArrayList<>();
		collectObjects(exactValue, objects);

		for (JsonObject object : objects.subList(0, Math.min(objects.size(), MAXIMUM_NEAR_MISS_OBJECTS))) {
			for (String nearMiss : nearMissNames(object)) {
				LinkedHashMap<String, JsonValue> members = new LinkedHashMap<>(object.getMembers());

				if (members.putIfAbsent(nearMiss, JsonNull.defaultInstance()) == null)
					requireScimAgreesWithExactNames(JsonCodec.toUtf8Bytes(JsonObject.fromMembers(members)));
			}
		}
	}

	/**
	 * The SCIM-versus-exact characterization for one document.
	 *
	 * @return the exact-name profile's value, or {@code null} if it rejected the document
	 */
	private static JsonValue requireScimAgreesWithExactNames(byte[] input) {
		JsonValue scimValue = null;
		JsonParseException scimFailure = null;
		JsonValue exactValue = null;
		JsonParseException exactFailure = null;

		try {
			scimValue = JsonCodec.parse(input, SCIM);
		} catch (JsonParseException e) {
			JsonFuzzSupport.requireFixedShape(e, input.length);
			scimFailure = e;
		}

		try {
			exactValue = JsonCodec.parse(input, SCIM_WITH_EXACT_NAMES);
		} catch (JsonParseException e) {
			JsonFuzzSupport.requireFixedShape(e, input.length);
			exactFailure = e;
		}

		if (scimFailure == null) {
			Assertions.assertNull(exactFailure, "SCIM accepted input that the exact-name profile rejected");
			Assertions.assertEquals(exactValue, scimValue, "SCIM and the exact-name profile parsed different values");
			Assertions.assertFalse(JsonFuzzSupport.shapeOf(scimValue).hasAsciiCaseVariantNames(),
					"SCIM accepted member names that differ only in ASCII case");
		} else if (scimFailure.getKind() != Kind.DUPLICATE_MEMBER) {
			Assertions.assertNotNull(exactFailure, "SCIM rejected input for a reason the exact-name profile missed");
			Assertions.assertEquals(scimFailure.getKind(), exactFailure.getKind(), "the two profiles disagree on Kind");
			Assertions.assertEquals(scimFailure.getByteOffset(), exactFailure.getByteOffset(),
					"the two profiles disagree on the offset");
		} else if (exactFailure == null) {
			Assertions.assertTrue(JsonFuzzSupport.shapeOf(exactValue).hasAsciiCaseVariantNames(),
					"SCIM reported a duplicate that no ASCII case fold explains");
		} else {
			Assertions.assertTrue(exactFailure.getByteOffset() >= scimFailure.getByteOffset(),
					"the exact-name profile failed before SCIM's duplicate member");
		}

		return exactValue;
	}

	/**
	 * Near misses of an object's first member name that holds a letter: the first such letter with its ASCII case
	 * flipped, and each non-ASCII letter that Unicode case mapping relates to it.
	 */
	private static List<String> nearMissNames(JsonObject object) {
		for (String name : object.getMembers().keySet()) {
			for (int index = 0; index < name.length(); ++index) {
				char letter = name.charAt(index);
				boolean upper = letter >= 'A' && letter <= 'Z';

				if (!upper && !(letter >= 'a' && letter <= 'z'))
					continue;

				char lower = upper ? (char) (letter + ('a' - 'A')) : letter;
				List<String> nearMisses = new ArrayList<>();
				nearMisses.add(withCharacter(name, index, upper ? lower : (char) (letter - ('a' - 'A'))));

				for (char lookalike : UNICODE_CASE_LOOKALIKES.getOrDefault(lower, "").toCharArray())
					nearMisses.add(withCharacter(name, index, lookalike));

				return nearMisses;
			}
		}

		return List.of();
	}

	private static String withCharacter(String name, int index, char character) {
		return name.substring(0, index) + character + name.substring(index + 1);
	}

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
	 * Requires a rejection to respect the documented order of the checks made before tokenizing.
	 */
	private static void requirePreTokenizingOrder(JsonParseException exception, byte[] input, JsonLimits limits,
																								int jdkMalformedOffset) {
		Kind kind = exception.getKind();

		if (input.length > limits.getMaxInputBytes()) {
			Assertions.assertEquals(Kind.INPUT_SIZE, kind, "an oversized input was not INPUT_SIZE");
			Assertions.assertEquals(limits.getMaxInputBytes(), exception.getByteOffset(), "INPUT_SIZE offset");
			return;
		}

		Assertions.assertNotEquals(Kind.INPUT_SIZE, kind, "INPUT_SIZE for an input within the limit");

		if (startsWithByteOrderMark(input)) {
			Assertions.assertEquals(Kind.BOM, kind, "a leading byte-order mark was not BOM");
			Assertions.assertEquals(0, exception.getByteOffset(), "BOM offset");
			return;
		}

		Assertions.assertNotEquals(Kind.BOM, kind, "BOM without a leading byte-order mark");

		if (jdkMalformedOffset >= 0) {
			Assertions.assertEquals(Kind.INVALID_UTF8, kind, "input the JDK rejects was not INVALID_UTF8");
			Assertions.assertEquals(jdkMalformedOffset, exception.getByteOffset(),
					"INVALID_UTF8 offset differs from where the JDK's strict decoder stops");
			return;
		}

		Assertions.assertNotEquals(Kind.INVALID_UTF8, kind, "INVALID_UTF8 for input the JDK decodes");
	}

	/**
	 * Requires an accepted value to lie inside every limit of its profile, measured by an independent walker.
	 */
	private static void requireInsideProfile(JsonValue value, JsonLimits limits, int inputLength) {
		JsonFuzzSupport.Shape shape = JsonFuzzSupport.shapeOf(value);

		Assertions.assertTrue(shape.getDepth() <= limits.getMaxDepth(), "accepted a value deeper than the profile");
		Assertions.assertTrue(shape.getNodes() <= limits.getMaxNodes(), "accepted more nodes than the profile");
		// Every value takes at least one byte of text, so the work of building it is linear in the input.
		Assertions.assertTrue(shape.getNodes() <= inputLength, "more values than input bytes");
		Assertions.assertTrue(shape.getLongestString() <= limits.getMaxStringLength(), "accepted a string too long");
		Assertions.assertTrue(shape.getLongestCanonicalNumber() <= limits.getMaxNumberLength(),
				"accepted a number whose canonical form is too long");
		Assertions.assertTrue(shape.getMostDigits() <= limits.getMaxNumberLength(), "accepted too many digits");
		Assertions.assertTrue(shape.getLargestAdjustedExponent() <= limits.getMaxExponentMagnitude(),
				"accepted an exponent too large");
		Assertions.assertFalse(shape.hasInexactNumberClass(), "a parsed number is a BigDecimal subclass");

		if (limits.isAsciiCaseVariantNamesRejected())
			Assertions.assertFalse(shape.hasAsciiCaseVariantNames(), "SCIM accepted ASCII case-variant names");

		requireWellFormedStrings(value);
	}

	/**
	 * Requires every number in an accepted document to satisfy the profile's limits on its written text, which the
	 * parsed value no longer shows (JsonLimits: the number limit bounds the text as well as the canonical form, and the
	 * exponent limit bounds the written exponent as well as the adjusted one). A plain lexer written here finds the
	 * numbers: outside strings, a number is a maximal run of {@code -+.0-9eE} that starts with {@code -} or a digit. So
	 * {@code 1e000...01} with 1,025 characters, or {@code 100e-10001}, whose values are small, must still be rejected.
	 */
	private static void requireNumberTextsInsideProfile(byte[] input, JsonLimits limits) {
		int index = 0;

		while (index < input.length) {
			byte octet = input[index];

			if (octet == '"') {
				// The document was accepted, so every string is closed; a backslash escapes the byte after it.
				for (++index; input[index] != '"'; ++index)
					if (input[index] == '\\')
						++index;

				++index;
			} else if (octet == '-' || (octet >= '0' && octet <= '9')) {
				int start = index;

				while (index < input.length && isNumberText(input[index]))
					++index;

				requireNumberTextInsideProfile(new String(input, start, index - start, StandardCharsets.US_ASCII), limits);
			} else {
				++index;
			}
		}
	}

	private static void requireNumberTextInsideProfile(String number, JsonLimits limits) {
		Assertions.assertTrue(number.length() <= limits.getMaxNumberLength(),
				"accepted a number whose text is longer than the profile allows");
		int exponent = Math.max(number.indexOf('e'), number.indexOf('E'));

		if (exponent < 0)
			return;

		// The magnitude of the written exponent: its digits without a sign or leading zeros.
		int digits = exponent + 1;

		if (digits < number.length() && (number.charAt(digits) == '+' || number.charAt(digits) == '-'))
			++digits;

		while (digits < number.length() - 1 && number.charAt(digits) == '0')
			++digits;

		String magnitude = number.substring(digits);
		Assertions.assertTrue(magnitude.length() <= 9 && Integer.parseInt(magnitude) <= limits.getMaxExponentMagnitude(),
				"accepted a written exponent larger than the profile allows");
	}

	private static boolean isNumberText(byte octet) {
		return (octet >= '0' && octet <= '9') || octet == '-' || octet == '+' || octet == '.' || octet == 'e'
				|| octet == 'E';
	}

	private static void requireWellFormedStrings(JsonValue value) {
		if (value instanceof JsonObject object) {
			for (Map.Entry<String, JsonValue> member : object.getMembers().entrySet()) {
				Assertions.assertTrue(StrictUtf8.isWellFormed(member.getKey()), "a member name is not well-formed");
				requireWellFormedStrings(member.getValue());
			}
		} else if (value instanceof JsonArray array) {
			for (JsonValue element : array.getElements())
				requireWellFormedStrings(element);
		} else if (value instanceof JsonString string) {
			Assertions.assertTrue(StrictUtf8.isWellFormed(string.getValue()), "a string is not well-formed");
		}
	}

	private static boolean startsWithByteOrderMark(byte[] input) {
		return input.length >= 3 && input[0] == (byte) 0xEF && input[1] == (byte) 0xBB && input[2] == (byte) 0xBF;
	}

	/**
	 * The offset at which the JDK's strict UTF-8 decoder reports the first malformed sequence, or -1 if it decodes
	 * the whole input: the independent oracle for {@link Kind#INVALID_UTF8}.
	 */
	private static int jdkStrictUtf8MalformedOffset(byte[] input) {
		CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
				.onMalformedInput(CodingErrorAction.REPORT)
				.onUnmappableCharacter(CodingErrorAction.REPORT);
		ByteBuffer bytes = ByteBuffer.wrap(input);
		// UTF-8 never decodes to more UTF-16 code units than it has bytes.
		CharBuffer characters = CharBuffer.allocate(input.length);
		CoderResult decoded = decoder.decode(bytes, characters, true);
		CoderResult result = decoded.isUnderflow() ? decoder.flush(characters) : decoded;

		if (result.isUnderflow())
			return -1;

		Assertions.assertTrue(result.isError(), () -> "unexpected decoder result " + result);
		return bytes.position();
	}
}
