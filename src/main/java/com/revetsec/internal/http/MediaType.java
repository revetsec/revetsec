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

package com.revetsec.internal.http;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * A parsed {@code Content-Type} field value (RFC 9110 section 8.3.1).
 * <p>
 * The grammar is exact:
 * <pre>
 * media-type      = type "/" subtype parameters
 * parameters      = *( OWS ";" OWS [ parameter ] )
 * parameter       = parameter-name "=" parameter-value
 * parameter-value = ( token / quoted-string )
 * </pre>
 * Type, subtype and parameter names are tokens (RFC 9110 section 5.6.2) and are stored in ASCII lower case, because
 * they compare case-insensitively. Whitespace is allowed only as OWS (space and horizontal tab) around the field
 * value and around each {@code ;}, never around {@code /} or {@code =}. A quoted-string value is stored unquoted,
 * with its quoted pairs resolved, so {@code charset="utf-8"} and {@code charset=utf-8} are the same parameter.
 * <p>
 * Stricter than the RFC in one way: a parameter name that appears twice, in any case, makes the value malformed,
 * because the two occurrences could be read differently (for example two charsets).
 * <p>
 * {@link #toString()} renders the type, subtype and parameter names, never parameter values.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public final class MediaType {
	/**
	 * The one charset Revetsec accepts on a checked response (M1 plan, G6-7), in lower case.
	 */
	public static final String UTF_8_CHARSET = "utf-8";

	private static final String CHARSET_PARAMETER = "charset";

	@NonNull
	private final String type;
	@NonNull
	private final String subtype;
	/**
	 * Never modified after construction; names are lower case and unique.
	 */
	@NonNull
	private final Map<@NonNull String, @NonNull String> parameters;

	private MediaType(@NonNull String type,
										@NonNull String subtype,
										@NonNull Map<@NonNull String, @NonNull String> parameters) {
		this.type = type;
		this.subtype = subtype;
		this.parameters = Collections.unmodifiableMap(parameters);
	}

	/**
	 * Parses a {@code Content-Type} field value.
	 *
	 * @param fieldValue the field value, as the JDK reports it; leading and trailing OWS are ignored
	 * @return the media type, or empty if the value does not match the grammar or repeats a parameter name
	 * @throws NullPointerException if {@code fieldValue} is {@code null}
	 */
	@NonNull
	public static Optional<MediaType> parse(@NonNull String fieldValue) {
		requireNonNull(fieldValue);

		int start = 0;
		int end = fieldValue.length();

		while (start < end && isOws(fieldValue.charAt(start)))
			++start;

		while (end > start && isOws(fieldValue.charAt(end - 1)))
			--end;

		int typeEnd = tokenEnd(fieldValue, start, end);

		if (typeEnd == start || typeEnd >= end || fieldValue.charAt(typeEnd) != '/')
			return Optional.empty();

		int subtypeStart = typeEnd + 1;
		int subtypeEnd = tokenEnd(fieldValue, subtypeStart, end);

		if (subtypeEnd == subtypeStart)
			return Optional.empty();

		Map<String, String> parameters = new LinkedHashMap<>();
		int index = subtypeEnd;

		while (index < end) {
			index = owsEnd(fieldValue, index, end);

			if (index >= end || fieldValue.charAt(index) != ';')
				return Optional.empty();

			index = owsEnd(fieldValue, index + 1, end);

			// An empty parameter ("a/b;", "a/b; ;c=d") is allowed by the grammar.
			if (index >= end || fieldValue.charAt(index) == ';')
				continue;

			int nameEnd = tokenEnd(fieldValue, index, end);

			if (nameEnd == index || nameEnd >= end || fieldValue.charAt(nameEnd) != '=')
				return Optional.empty();

			String name = asciiLowerCase(fieldValue.substring(index, nameEnd));
			int valueStart = nameEnd + 1;
			String value;

			if (valueStart < end && fieldValue.charAt(valueStart) == '"') {
				StringBuilder unquoted = new StringBuilder();
				int quotedEnd = quotedStringEnd(fieldValue, valueStart, end, unquoted);

				if (quotedEnd < 0)
					return Optional.empty();

				value = unquoted.toString();
				index = quotedEnd;
			} else {
				int valueEnd = tokenEnd(fieldValue, valueStart, end);

				if (valueEnd == valueStart)
					return Optional.empty();

				value = fieldValue.substring(valueStart, valueEnd);
				index = valueEnd;
			}

			if (parameters.putIfAbsent(name, value) != null)
				return Optional.empty();
		}

		return Optional.of(new MediaType(asciiLowerCase(fieldValue.substring(start, typeEnd)),
				asciiLowerCase(fieldValue.substring(subtypeStart, subtypeEnd)), parameters));
	}

	/**
	 * The type, in lower case, such as {@code application}.
	 *
	 * @return the type
	 */
	@NonNull
	public String getType() {
		return this.type;
	}

	/**
	 * The subtype, in lower case, such as {@code jwk-set+json}.
	 *
	 * @return the subtype
	 */
	@NonNull
	public String getSubtype() {
		return this.subtype;
	}

	/**
	 * The type and subtype without parameters, in lower case, such as {@code application/json}.
	 *
	 * @return the essence
	 */
	@NonNull
	public String getEssence() {
		return this.type + "/" + this.subtype;
	}

	/**
	 * The parameters, by lower-case name, in the order they appeared; quoted values are unquoted.
	 *
	 * @return an unmodifiable map
	 */
	@NonNull
	public Map<@NonNull String, @NonNull String> getParameters() {
		return this.parameters;
	}

	/**
	 * The {@code charset} parameter's value as sent (unquoted), if present.
	 *
	 * @return the charset, or empty
	 */
	@NonNull
	public Optional<String> getCharset() {
		return Optional.ofNullable(this.parameters.get(CHARSET_PARAMETER));
	}

	/**
	 * Whether the charset is absent or {@code utf-8} in any ASCII case (M1 plan, G6-7).
	 *
	 * @return {@code true} if a UTF-8 JSON or JWT parser may read the body
	 */
	public boolean hasUtf8OrNoCharset() {
		@Nullable String charset = this.parameters.get(CHARSET_PARAMETER);
		return charset == null || UTF_8_CHARSET.equals(asciiLowerCase(charset));
	}

	/**
	 * Compares type, subtype and parameters; names are already lower case, and values compare exactly.
	 *
	 * @param object the other object
	 * @return whether {@code object} is an equal media type
	 */
	@Override
	public boolean equals(@Nullable Object object) {
		if (this == object)
			return true;

		if (!(object instanceof MediaType other))
			return false;

		return this.type.equals(other.type) && this.subtype.equals(other.subtype)
				&& this.parameters.equals(other.parameters);
	}

	/**
	 * A hash of type, subtype and parameters.
	 *
	 * @return the hash code
	 */
	@Override
	public int hashCode() {
		return Objects.hash(this.type, this.subtype, this.parameters);
	}

	/**
	 * Describes this media type without parameter values.
	 *
	 * @return the essence and the parameter names
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{essence=" + getEssence() + ", parameterNames=" + this.parameters.keySet()
				+ "}";
	}

	/**
	 * ASCII-only lower-casing: header text is ISO-8859-1, and only ASCII letters fold (RFC 9110 section 5.6.2).
	 */
	@NonNull
	static String asciiLowerCase(@NonNull String value) {
		@Nullable StringBuilder lowerCase = null;

		for (int i = 0; i < value.length(); ++i) {
			char c = value.charAt(i);

			if (c >= 'A' && c <= 'Z') {
				if (lowerCase == null)
					lowerCase = new StringBuilder(value);

				lowerCase.setCharAt(i, (char) (c + ('a' - 'A')));
			}
		}

		return lowerCase == null ? value : lowerCase.toString();
	}

	/**
	 * OWS: space or horizontal tab (RFC 9110 section 5.6.3).
	 */
	static boolean isOws(char c) {
		return c == ' ' || c == '\t';
	}

	/**
	 * tchar (RFC 9110 section 5.6.2).
	 */
	static boolean isTokenCharacter(char c) {
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
			return true;

		return switch (c) {
			case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' -> true;
			default -> false;
		};
	}

	/**
	 * The index after the run of tchar starting at {@code start}; {@code start} itself when there is none.
	 */
	static int tokenEnd(@NonNull String value, int start, int end) {
		int index = start;

		while (index < end && isTokenCharacter(value.charAt(index)))
			++index;

		return index;
	}

	/**
	 * The index after the run of OWS starting at {@code start}.
	 */
	static int owsEnd(@NonNull String value, int start, int end) {
		int index = start;

		while (index < end && isOws(value.charAt(index)))
			++index;

		return index;
	}

	/**
	 * Reads a quoted-string starting at the opening quote (RFC 9110 section 5.6.4), appending its unquoted text;
	 * returns the index after the closing quote, or -1 if it is malformed or unterminated.
	 */
	static int quotedStringEnd(@NonNull String value, int openingQuote, int end,
														 @NonNull StringBuilder unquoted) {
		int index = openingQuote + 1;

		while (index < end) {
			char c = value.charAt(index);

			if (c == '"')
				return index + 1;

			if (c == '\\') {
				// quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )
				if (index + 1 >= end || !isQuotedPairCharacter(value.charAt(index + 1)))
					return -1;

				unquoted.append(value.charAt(index + 1));
				index += 2;
				continue;
			}

			if (!isQuotedTextCharacter(c))
				return -1;

			unquoted.append(c);
			++index;
		}

		return -1;
	}

	/**
	 * qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text.
	 */
	private static boolean isQuotedTextCharacter(char c) {
		return c == '\t' || c == ' ' || c == 0x21 || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E)
				|| (c >= 0x80 && c <= 0xFF);
	}

	/**
	 * HTAB / SP / VCHAR / obs-text.
	 */
	private static boolean isQuotedPairCharacter(char c) {
		return c == '\t' || c == ' ' || (c >= 0x21 && c <= 0x7E) || (c >= 0x80 && c <= 0xFF);
	}
}
