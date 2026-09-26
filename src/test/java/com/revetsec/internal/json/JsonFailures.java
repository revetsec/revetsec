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

import com.revetsec.testing.Sentinels;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.function.Executable;

import javax.annotation.concurrent.ThreadSafe;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * Assertions shared by the {@code internal.json} tests: the exact kind, the byte offset, the fixed message written out
 * literally (so a changed message fails here, not only a changed kind), no cause, nothing suppressed, and no echo of
 * the input in any rendering (R9, checked with {@link Sentinels}).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
final class JsonFailures {
	/**
	 * A sentinel secret that tests embed in rejected inputs.
	 */
	static final String SENTINEL = Sentinels.secret("json-input");

	/**
	 * The fixed message of every parse failure, spelled out separately from the production table.
	 */
	static final Map<JsonParseException.Kind, String> PARSE_MESSAGES = Map.ofEntries(
			Map.entry(JsonParseException.Kind.SYNTAX, "The JSON input is not well-formed."),
			Map.entry(JsonParseException.Kind.INVALID_UTF8, "The JSON input is not well-formed UTF-8."),
			Map.entry(JsonParseException.Kind.BOM, "The JSON input starts with a byte-order mark."),
			Map.entry(JsonParseException.Kind.UNPAIRED_SURROGATE,
					"A JSON string contains an unpaired surrogate escape."),
			Map.entry(JsonParseException.Kind.DUPLICATE_MEMBER, "A JSON object contains a duplicate member name."),
			Map.entry(JsonParseException.Kind.DEPTH, "The JSON input is nested too deeply."),
			Map.entry(JsonParseException.Kind.NODES, "The JSON input contains too many values."),
			Map.entry(JsonParseException.Kind.STRING_LENGTH, "A JSON string is too long."),
			Map.entry(JsonParseException.Kind.NUMBER_LENGTH, "A JSON number is too long."),
			Map.entry(JsonParseException.Kind.EXPONENT, "A JSON number's exponent is too large."),
			Map.entry(JsonParseException.Kind.INPUT_SIZE, "The JSON input is too large."));

	/**
	 * The fixed message of every field failure.
	 */
	static final Map<JsonFieldException.Kind, String> FIELD_MESSAGES = Map.of(
			JsonFieldException.Kind.MISSING, "A required JSON member is missing.",
			JsonFieldException.Kind.WRONG_TYPE, "A JSON member has the wrong type.",
			JsonFieldException.Kind.OUT_OF_RANGE, "A JSON member's value is out of range.",
			JsonFieldException.Kind.UNSUPPORTED, "A JSON member's value is not supported.");

	/**
	 * Means "any offset" to {@link #assertRejected(JsonParseException.Kind, int, byte[], JsonLimits)}.
	 */
	static final int ANY_OFFSET = -1;

	private JsonFailures() {
	}

	static byte[] utf8(String text) {
		return text.getBytes(StandardCharsets.UTF_8);
	}

	/**
	 * Parses {@code input}, which must be rejected with {@code kind} at {@code offset} (unless {@link #ANY_OFFSET}), the
	 * fixed message, no cause, nothing suppressed and no sentinel in any rendering.
	 */
	static JsonParseException assertRejected(JsonParseException.Kind kind, int offset, byte[] input,
																					 JsonLimits limits) {
		JsonParseException exception = Assertions.assertThrows(JsonParseException.class,
				() -> JsonCodec.parse(input, limits), () -> "expected " + kind + " for " + describe(input));
		Assertions.assertEquals(kind, exception.getKind(), () -> "kind for " + describe(input));

		if (offset != ANY_OFFSET)
			Assertions.assertEquals(offset, exception.getByteOffset(), () -> "offset for " + describe(input));

		Assertions.assertTrue(exception.getByteOffset() >= 0 && exception.getByteOffset() <= input.length,
				() -> "offset outside the input for " + describe(input));
		assertFixedAndSilent(exception, requireNonNull(PARSE_MESSAGES.get(kind)));
		return exception;
	}

	static JsonParseException assertRejected(JsonParseException.Kind kind, int offset, String input,
																					 JsonLimits limits) {
		return assertRejected(kind, offset, utf8(input), limits);
	}

	/**
	 * Runs {@code action}, which must throw a {@link JsonFieldException} of {@code kind} with the fixed message, no
	 * cause, nothing suppressed and no sentinel in any rendering.
	 */
	static JsonFieldException assertFieldRejected(JsonFieldException.Kind kind, Executable action) {
		JsonFieldException exception = Assertions.assertThrows(JsonFieldException.class, action);
		Assertions.assertEquals(kind, exception.getKind());
		assertFixedAndSilent(exception, requireNonNull(FIELD_MESSAGES.get(kind)));
		return exception;
	}

	private static void assertFixedAndSilent(Exception exception, String message) {
		Assertions.assertEquals(message, exception.getMessage());
		Assertions.assertNull(exception.getCause());
		Assertions.assertEquals(0, exception.getSuppressed().length);
		exception.addSuppressed(new IllegalStateException(SENTINEL));
		Assertions.assertEquals(0, exception.getSuppressed().length, "suppression must be disabled");
		Sentinels.assertAbsent(exception);
	}

	/**
	 * Hides a {@code null} from NullAway, for the tests that check null handling (R15).
	 */
	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	static <T> T nullValue() {
		return null;
	}

	/**
	 * A printable description of a test input for assertion messages (test output only).
	 */
	static String describe(byte[] input) {
		StringBuilder description = new StringBuilder("\"");
		int shown = Math.min(input.length, 80);

		for (int index = 0; index < shown; ++index) {
			int octet = input[index] & 0xFF;

			if (octet >= 0x20 && octet < 0x7F)
				description.append((char) octet);
			else
				description.append(String.format(Locale.ROOT, "\\x%02X", octet));
		}

		return description.append(shown < input.length ? "...\" (" + input.length + " bytes)" : "\"").toString();
	}
}
