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
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

import static java.util.Objects.requireNonNull;

/**
 * Strict UTF-8 in both directions (RFC 3629): malformed input is reported, never replaced.
 * <p>
 * The JDK's convenience methods are lenient in ways that matter for security code. {@code String.getBytes(UTF_8)}
 * silently encodes an unpaired surrogate as {@code ?}, and {@code new String(bytes, UTF_8)} maps every malformed
 * sequence to U+FFFD, so two different inputs can produce the same result. This class throws
 * {@link EncodingException} instead.
 * <ul>
 *   <li>Encoding checks that the string is well-formed UTF-16 and sizes the output exactly before writing it.</li>
 *   <li>Decoding uses the JDK's {@link CharsetDecoder} with {@link CodingErrorAction#REPORT}. It rejects overlong
 *   forms, encoded surrogates (CESU-8), code points above U+10FFFF, the bytes C0, C1 and F5 to FF, stray continuation
 *   bytes and truncated sequences. It accepts every well-formed sequence, including NUL, noncharacters and U+FEFF,
 *   which it keeps: it never strips a byte-order mark.</li>
 * </ul>
 * Temporary buffers are zeroed before returning, so no stray copy of the text is left in a buffer Revetsec owns.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class StrictUtf8 {
	private StrictUtf8() {
	}

	/**
	 * Encodes a string as UTF-8.
	 *
	 * @param value the string to encode
	 * @return a new array holding exactly the UTF-8 octets of {@code value}
	 * @throws EncodingException   with {@link EncodingException.Kind#UNPAIRED_SURROGATE} if {@code value} is not
	 *                             well-formed UTF-16
	 * @throws ArithmeticException if the octets would number more than {@link Integer#MAX_VALUE}, which takes a
	 *                             string of roughly 715 million characters or more
	 */
	public static byte @NonNull [] encode(@NonNull String value) throws EncodingException {
		requireNonNull(value);
		byte[] bytes = new byte[encodedLength(value)];
		int position = 0;
		int length = value.length();
		for (int index = 0; index < length; ++index) {
			char character = value.charAt(index);
			// encodedLength has rejected every unpaired surrogate, so a high surrogate here starts a pair.
			int codePoint = Character.isHighSurrogate(character)
					? Character.toCodePoint(character, value.charAt(++index)) : character;
			position = put(bytes, position, codePoint);
		}
		return bytes;
	}

	/**
	 * Decodes UTF-8 octets.
	 *
	 * @param bytes the octets to decode; not modified
	 * @return the decoded string
	 * @throws EncodingException with {@link EncodingException.Kind#INVALID_UTF8} if the octets are not well-formed
	 *                           UTF-8
	 */
	public static @NonNull String decode(byte @NonNull [] bytes) throws EncodingException {
		requireNonNull(bytes);
		return decode(bytes, 0, bytes.length);
	}

	/**
	 * Decodes a range of UTF-8 octets.
	 *
	 * @param bytes  the array holding the octets; not modified
	 * @param offset the index of the first octet
	 * @param length the number of octets
	 * @return the decoded string
	 * @throws EncodingException         with {@link EncodingException.Kind#INVALID_UTF8} if the octets are not
	 *                                   well-formed UTF-8
	 * @throws IndexOutOfBoundsException if the range is not inside {@code bytes}
	 */
	public static @NonNull String decode(byte @NonNull [] bytes, int offset, int length) throws EncodingException {
		requireNonNull(bytes);
		Objects.checkFromIndexSize(offset, length, bytes.length);

		// UTF-8 never decodes to more UTF-16 code units than it has octets, so the output cannot overflow.
		char[] chars = new char[length];
		try {
			CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
					.onMalformedInput(CodingErrorAction.REPORT)
					.onUnmappableCharacter(CodingErrorAction.REPORT);
			CharBuffer output = CharBuffer.wrap(chars);
			// With endOfInput true, a truncated final sequence is reported as malformed, not left unread.
			CoderResult result = decoder.decode(ByteBuffer.wrap(bytes, offset, length), output, true);
			if (result.isUnderflow())
				result = decoder.flush(output);
			if (!result.isUnderflow())
				throw new EncodingException(EncodingException.Kind.INVALID_UTF8);
			return new String(chars, 0, output.position());
		} finally {
			Arrays.fill(chars, '\0');
		}
	}

	/**
	 * Returns whether a string is well-formed UTF-16, that is, whether {@link #encode(String)} would accept it.
	 *
	 * @param value the string to check
	 * @return {@code true} if every surrogate in {@code value} is part of a high-low pair
	 */
	public static boolean isWellFormed(@NonNull String value) {
		requireNonNull(value);
		int length = value.length();
		for (int index = 0; index < length; ++index) {
			char character = value.charAt(index);
			if (isPairStart(value, index))
				++index;
			else if (Character.isSurrogate(character))
				return false;
		}
		return true;
	}

	/**
	 * The exact UTF-8 length of {@code value}.
	 *
	 * @throws EncodingException with {@link EncodingException.Kind#UNPAIRED_SURROGATE} if {@code value} is not
	 *                           well-formed UTF-16
	 */
	static int encodedLength(@NonNull String value) throws EncodingException {
		long length = 0;
		int characters = value.length();
		for (int index = 0; index < characters; ++index) {
			char character = value.charAt(index);
			if (isPairStart(value, index)) {
				length += 4;
				++index;
			} else if (Character.isSurrogate(character)) {
				throw new EncodingException(EncodingException.Kind.UNPAIRED_SURROGATE);
			} else {
				length += utf8Length(character);
			}
		}
		// Only a string of several hundred million characters overflows; fail rather than wrap.
		return Math.toIntExact(length);
	}

	/**
	 * Whether a surrogate pair starts at {@code index}.
	 */
	static boolean isPairStart(@NonNull String value, int index) {
		return Character.isHighSurrogate(value.charAt(index)) && index + 1 < value.length()
				&& Character.isLowSurrogate(value.charAt(index + 1));
	}

	/**
	 * The number of UTF-8 octets for a BMP character that is not a surrogate (a surrogate pair takes four).
	 */
	static int utf8Length(char character) {
		if (character < 0x80)
			return 1;
		return character < 0x800 ? 2 : 3;
	}

	/**
	 * Writes the UTF-8 octets of a code point that is not a surrogate at {@code position} and returns the position
	 * after them. The caller has sized {@code bytes} for it.
	 */
	static int put(byte @NonNull [] bytes, int position, int codePoint) {
		int next = position;
		if (codePoint < 0x80) {
			bytes[next++] = (byte) codePoint;
		} else if (codePoint < 0x800) {
			bytes[next++] = (byte) (0xC0 | (codePoint >> 6));
			bytes[next++] = (byte) (0x80 | (codePoint & 0x3F));
		} else if (codePoint < 0x10000) {
			bytes[next++] = (byte) (0xE0 | (codePoint >> 12));
			bytes[next++] = (byte) (0x80 | ((codePoint >> 6) & 0x3F));
			bytes[next++] = (byte) (0x80 | (codePoint & 0x3F));
		} else {
			bytes[next++] = (byte) (0xF0 | (codePoint >> 18));
			bytes[next++] = (byte) (0x80 | ((codePoint >> 12) & 0x3F));
			bytes[next++] = (byte) (0x80 | ((codePoint >> 6) & 0x3F));
			bytes[next++] = (byte) (0x80 | (codePoint & 0x3F));
		}
		return next;
	}
}
