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

package com.revetsec.internal.encoding;

import org.jspecify.annotations.NonNull;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.function.Executable;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Locale;
import java.util.Map;

/**
 * Assertions shared by the {@code internal.encoding} tests: the exact {@link EncodingException.Kind}, the fixed
 * message written out literally (so a changed message fails here, not only a changed kind), no cause, no suppressed
 * exceptions, and no echo of the input (R9).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class EncodingFailures {
	/**
	 * A marker embedded in malformed inputs; no rendering of a failure may contain it.
	 */
	static final String SENTINEL = "RevetsecSentinel7f3a";

	/**
	 * The fixed message of every kind, spelled out separately from the production table.
	 */
	static final Map<EncodingException.Kind, String> MESSAGES = Map.of(
			EncodingException.Kind.INVALID_CHARACTER, "The input contains a character outside the permitted alphabet.",
			EncodingException.Kind.INVALID_LENGTH, "The input length is not a valid encoded length.",
			EncodingException.Kind.PADDING, "The input padding is missing, misplaced or not permitted.",
			EncodingException.Kind.NON_CANONICAL, "The input is not in canonical form.",
			EncodingException.Kind.MALFORMED_PERCENT_ENCODING, "The input contains a malformed percent-encoded octet.",
			EncodingException.Kind.INVALID_UTF8, "The input is not well-formed UTF-8.",
			EncodingException.Kind.UNPAIRED_SURROGATE, "The input contains an unpaired surrogate.");

	private EncodingFailures() {
	}

	/**
	 * Runs {@code action}, which must throw an {@link EncodingException} of {@code kind} with the fixed message, no
	 * cause, nothing suppressed, and no trace of {@code input} (when it is long enough to be recognizable) or of
	 * {@link #SENTINEL} in its message, {@code toString()} or stack trace.
	 */
	static @NonNull EncodingException assertRejected(EncodingException.@NonNull Kind kind, @NonNull String input, @NonNull Executable action) {
		EncodingException exception = Assertions.assertThrows(EncodingException.class, action,
				() -> "expected " + kind + " for " + describe(input));
		Assertions.assertEquals(kind, exception.getKind(), () -> "kind for " + describe(input));
		Assertions.assertEquals(MESSAGES.get(kind), exception.getMessage());
		Assertions.assertNull(exception.getCause());
		Assertions.assertEquals(0, exception.getSuppressed().length);
		assertNoEcho(exception, input);
		return exception;
	}

	static void assertNoEcho(@NonNull Throwable throwable, @NonNull String input) {
		StringWriter stackTrace = new StringWriter();
		throwable.printStackTrace(new PrintWriter(stackTrace));
		for (String rendering : new String[]{String.valueOf(throwable.getMessage()), throwable.toString(),
				stackTrace.toString()}) {
			Assertions.assertFalse(rendering.contains(SENTINEL), "a failure rendering contains the sentinel");
			// Short inputs such as "%" or "=" can occur in any sentence by chance; long ones cannot.
			if (input.length() >= 12)
				Assertions.assertFalse(rendering.contains(input), "a failure rendering echoes the input");
		}
	}

	/**
	 * A printable description of a test input for assertion messages (test output only).
	 */
	static @NonNull String describe(@NonNull String input) {
		StringBuilder description = new StringBuilder("\"");
		input.codePoints().forEach(codePoint -> {
			if (codePoint >= 0x20 && codePoint < 0x7F)
				description.appendCodePoint(codePoint);
			else
				description.append(String.format(Locale.ROOT, "\\u{%X}", codePoint));
		});
		return description.append('"').toString();
	}
}
