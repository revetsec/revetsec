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

import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonBoolean;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * Serializes the public JSON model as compact JSON text: the implementation of {@code JsonValue.toJson()}, ported from
 * the writer in Soklet's {@code McpJsonCodec}:
 * <ul>
 *   <li>No insignificant whitespace; object members in insertion order.</li>
 *   <li>Numbers in the canonical form of {@link java.math.BigDecimal#toString()} (G7-4): {@code 1e2} becomes
 *   {@code 1E+2} and {@code -0} becomes {@code 0}. Never the plain form, which a large exponent would expand.</li>
 *   <li>Strings escape only what RFC 8259 requires: {@code "}, {@code \} and U+0000 to U+001F, with the
 *   two-character escapes where they exist and otherwise {@code \}{@code u00xx} in lowercase hexadecimal. Every
 *   other character, U+2028, U+2029 and U+007F included, is written as itself.</li>
 * </ul>
 * The writer has no limits of its own. The model's invariants (G7-6) bound its recursion to 64 levels and each
 * number's length, and guarantee that every string is well-formed UTF-16, so no content makes it throw, and
 * {@link #toUtf8Bytes(JsonValue)} can use {@link String#getBytes(java.nio.charset.Charset)}, which would otherwise
 * replace an unpaired surrogate with {@code ?}. The writer does not bound its output: a value that holds the same
 * child in several places is written once per occurrence, so the output length follows the expanded tree, not the
 * number of objects, and output longer than the JDK's maximum {@code String} length throws
 * {@link OutOfMemoryError}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class JsonWriter {
	private static final String HEX_DIGITS = "0123456789abcdef";

	private JsonWriter() {
	}

	/**
	 * Serializes a value as JSON text.
	 *
	 * @param value the value
	 * @return the compact JSON text
	 * @throws NullPointerException if {@code value} is {@code null}
	 */
	public static @NonNull String toJson(@NonNull JsonValue value) {
		requireNonNull(value);
		StringBuilder output = new StringBuilder();
		write(output, value);
		return output.toString();
	}

	/**
	 * Serializes a value as UTF-8 JSON text.
	 *
	 * @param value the value
	 * @return the UTF-8 bytes of {@link #toJson(JsonValue)}
	 * @throws NullPointerException if {@code value} is {@code null}
	 */
	public static byte @NonNull [] toUtf8Bytes(@NonNull JsonValue value) {
		// The model holds no unpaired surrogate, so the JDK's encoder never substitutes a character here.
		return toJson(value).getBytes(StandardCharsets.UTF_8);
	}

	/**
	 * Appends {@code value} as a JSON string literal, quotes included.
	 */
	static void writeString(@NonNull StringBuilder output, @NonNull String value) {
		output.append('"');
		int length = value.length();
		int runStart = 0;

		for (int index = 0; index < length; ++index) {
			char character = value.charAt(index);

			if (character >= 0x20 && character != '"' && character != '\\')
				continue;

			output.append(value, runStart, index);
			runStart = index + 1;

			switch (character) {
				case '"' -> output.append("\\\"");
				case '\\' -> output.append("\\\\");
				case '\b' -> output.append("\\b");
				case '\f' -> output.append("\\f");
				case '\n' -> output.append("\\n");
				case '\r' -> output.append("\\r");
				case '\t' -> output.append("\\t");
				default -> output.append("\\u00").append(HEX_DIGITS.charAt(character >>> 4))
						.append(HEX_DIGITS.charAt(character & 0x0F));
			}
		}

		output.append(value, runStart, length).append('"');
	}

	private static void write(@NonNull StringBuilder output, @NonNull JsonValue value) {
		if (value instanceof JsonObject object) {
			output.append('{');
			boolean first = true;

			for (Map.Entry<@NonNull String, @NonNull JsonValue> member : object.getMembers().entrySet()) {
				if (!first)
					output.append(',');

				writeString(output, member.getKey());
				output.append(':');
				write(output, member.getValue());
				first = false;
			}

			output.append('}');
		} else if (value instanceof JsonArray array) {
			output.append('[');
			List<@NonNull JsonValue> elements = array.getElements();

			for (int index = 0; index < elements.size(); ++index) {
				if (index > 0)
					output.append(',');

				write(output, elements.get(index));
			}

			output.append(']');
		} else if (value instanceof JsonString string) {
			writeString(output, string.getValue());
		} else if (value instanceof JsonNumber number) {
			output.append(number.getValue().toString());
		} else if (value instanceof JsonBoolean bool) {
			output.append(bool.getValue().booleanValue() ? "true" : "false");
		} else {
			// JsonValue is sealed, so this is JsonNull.
			output.append("null");
		}
	}
}
