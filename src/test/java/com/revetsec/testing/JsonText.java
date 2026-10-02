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

package com.revetsec.testing;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * JSON text for the JOSE test helpers and the tests that use them, written independently of Revetsec's own JSON codec
 * so a codec bug cannot hide in the fixtures it is tested against. Tests use it for the raw JSON values that
 * {@link TestJws.Builder#headerMember(String, String)} and {@link TestJsonWebKeys.Builder#member(String, String)} take.
 * <p>
 * Member values are raw JSON text that the caller supplies, so a helper can write anything a hostile producer might:
 * a duplicate member, a number where a string belongs, {@code null}. Only names and {@link #string(String)} values
 * are escaped.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class JsonText {
	private JsonText() {
		// Static helpers only.
	}

	/**
	 * A JSON string literal (RFC 8259 section 7): {@code "} and {@code \} are escaped with a backslash, the other
	 * characters below U+0020 and every unpaired surrogate as {@code \}{@code uXXXX}, and everything else is written as
	 * is. An unpaired surrogate has no UTF-8 encoding, so writing it raw would turn it into {@code ?}; escaped, it
	 * reaches the parser under test.
	 *
	 * @param value the string
	 * @return the quoted literal
	 */
	public static @NonNull String string(@NonNull String value) {
		requireNonNull(value);
		StringBuilder builder = new StringBuilder(value.length() + 2).append('"');
		for (int index = 0; index < value.length(); ++index) {
			char character = value.charAt(index);
			boolean paired = Character.isHighSurrogate(character) && index + 1 < value.length()
					&& Character.isLowSurrogate(value.charAt(index + 1));
			if (paired) {
				builder.append(character).append(value.charAt(++index));
			} else if (character == '"' || character == '\\') {
				builder.append('\\').append(character);
			} else if (character < 0x20 || Character.isSurrogate(character)) {
				builder.append(String.format(Locale.ROOT, "\\u%04x", (int) character));
			} else {
				builder.append(character);
			}
		}
		return builder.append('"').toString();
	}

	/**
	 * A JSON object from members in order. A name may repeat, which writes a duplicate member.
	 *
	 * @param members each member's name and raw JSON value text
	 * @return the object text, with no whitespace
	 */
	public static @NonNull String object(@NonNull List<Map.@NonNull Entry<@NonNull String, @NonNull String>> members) {
		requireNonNull(members);
		StringBuilder builder = new StringBuilder().append('{');
		for (Map.Entry<String, String> member : members) {
			if (builder.length() > 1)
				builder.append(',');
			builder.append(string(member.getKey())).append(':').append(requireNonNull(member.getValue()));
		}
		return builder.append('}').toString();
	}

	/**
	 * A JSON array of raw element text.
	 *
	 * @param elements each element's raw JSON text
	 * @return the array text, with no whitespace
	 */
	public static @NonNull String array(@NonNull List<@NonNull String> elements) {
		requireNonNull(elements);
		return "[" + String.join(",", elements) + "]";
	}

	/**
	 * A JSON array of strings.
	 *
	 * @param values the strings
	 * @return the array text
	 */
	public static @NonNull String stringArray(@NonNull List<@NonNull String> values) {
		requireNonNull(values);
		return array(values.stream().map(JsonText::string).toList());
	}
}
