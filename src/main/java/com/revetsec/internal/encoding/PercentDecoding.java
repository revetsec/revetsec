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

import javax.annotation.concurrent.ThreadSafe;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;

/**
 * Strict percent-decoding (RFC 3986 section 2.1) with UTF-8 as the character encoding (RFC 3986 section 2.5, R7).
 * <p>
 * The input is turned into octets first: each {@code %XX} (two ASCII hexadecimal digits, either case) becomes one
 * octet, and every other character becomes its own UTF-8 octets. The octet sequence is then decoded with
 * {@link StrictUtf8}. So:
 * <ul>
 *   <li>a {@code %} without two hexadecimal digits after it is rejected
 *   ({@link EncodingException.Kind#MALFORMED_PERCENT_ENCODING}); only ASCII digits count, never the other Unicode
 *   digits {@link Character#digit(char, int)} accepts;</li>
 *   <li>octets that are not well-formed UTF-8 are rejected ({@link EncodingException.Kind#INVALID_UTF8}), never
 *   replaced with U+FFFD as {@code URLDecoder} does, so no two different inputs decode to the same string by
 *   substitution;</li>
 *   <li>an unpaired surrogate in the input is rejected ({@link EncodingException.Kind#UNPAIRED_SURROGATE}).</li>
 * </ul>
 * {@code +} is an ordinary character here. {@link FormUrlEncoding#decode(String)} is the variant that reads it as a
 * space. No other character is rejected: which characters may appear unencoded is the caller's rule, not the
 * decoder's.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class PercentDecoding {
	private PercentDecoding() {
	}

	/**
	 * Percent-decodes {@code encoded} as UTF-8, leaving {@code +} as it is.
	 *
	 * @param encoded the encoded text
	 * @return the decoded text
	 * @throws EncodingException   if an escape is malformed, the octets are not well-formed UTF-8, or the input has
	 *                             an unpaired surrogate
	 * @throws ArithmeticException if the decoded octets would number more than {@link Integer#MAX_VALUE}, which takes
	 *                             an input of roughly 715 million characters or more
	 */
	public static @NonNull String decode(@NonNull String encoded) throws EncodingException {
		return decode(encoded, false);
	}

	/**
	 * Percent-decodes {@code encoded} as UTF-8, reading {@code +} as a space when {@code plusIsSpace} is set
	 * ({@code application/x-www-form-urlencoded}).
	 */
	static @NonNull String decode(@NonNull String encoded, boolean plusIsSpace) throws EncodingException {
		requireNonNull(encoded);
		int length = encoded.length();

		// First pass: validate every escape and surrogate, and size the octet buffer exactly.
		long octets = 0;
		boolean transformed = false;
		for (int index = 0; index < length; ) {
			char character = encoded.charAt(index);
			if (character == '%') {
				if (index + 2 >= length || hexValue(encoded.charAt(index + 1)) < 0
						|| hexValue(encoded.charAt(index + 2)) < 0)
					throw new EncodingException(EncodingException.Kind.MALFORMED_PERCENT_ENCODING);
				octets += 1;
				index += 3;
				transformed = true;
			} else if (character == '+' && plusIsSpace) {
				octets += 1;
				index += 1;
				transformed = true;
			} else if (StrictUtf8.isPairStart(encoded, index)) {
				octets += 4;
				index += 2;
			} else if (Character.isSurrogate(character)) {
				throw new EncodingException(EncodingException.Kind.UNPAIRED_SURROGATE);
			} else {
				octets += StrictUtf8.utf8Length(character);
				index += 1;
			}
		}

		// Well-formed UTF-16 with nothing to decode is its own decoding.
		if (!transformed)
			return encoded;

		byte[] bytes = new byte[Math.toIntExact(octets)];
		try {
			int position = 0;
			for (int index = 0; index < length; ) {
				char character = encoded.charAt(index);
				if (character == '%') {
					bytes[position++] = (byte) ((hexValue(encoded.charAt(index + 1)) << 4)
							| hexValue(encoded.charAt(index + 2)));
					index += 3;
				} else if (character == '+' && plusIsSpace) {
					bytes[position++] = ' ';
					index += 1;
				} else if (Character.isHighSurrogate(character)) {
					// The first pass has proven that a low surrogate follows.
					position = StrictUtf8.put(bytes, position, Character.toCodePoint(character,
							encoded.charAt(index + 1)));
					index += 2;
				} else {
					position = StrictUtf8.put(bytes, position, character);
					index += 1;
				}
			}
			return StrictUtf8.decode(bytes);
		} finally {
			Arrays.fill(bytes, (byte) 0);
		}
	}

	/**
	 * The value of an ASCII hexadecimal digit, or -1 for any other character.
	 */
	static int hexValue(char character) {
		if (character >= '0' && character <= '9')
			return character - '0';
		if (character >= 'A' && character <= 'F')
			return character - 'A' + 10;
		if (character >= 'a' && character <= 'f')
			return character - 'a' + 10;
		return -1;
	}
}
