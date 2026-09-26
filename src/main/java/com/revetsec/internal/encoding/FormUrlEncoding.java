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
 * {@code application/x-www-form-urlencoded} names and values as OAuth uses them (RFC 6749 Appendix B, R7).
 * <p>
 * <strong>Encoding</strong> converts the string to UTF-8 with {@link StrictUtf8}, keeps the octets for
 * {@code A-Z}, {@code a-z}, {@code 0-9}, {@code *}, {@code -}, {@code .} and {@code _}, writes a space as
 * {@code +}, and writes every other octet as {@code %XX} with uppercase hexadecimal digits. For well-formed input the
 * result is exactly what {@code URLEncoder.encode(value, UTF_8)} returns. Unlike {@code URLEncoder}, which silently
 * writes an unpaired surrogate as {@code %3F}, it rejects one with
 * {@link EncodingException.Kind#UNPAIRED_SURROGATE}.
 * <p>
 * <strong>Decoding</strong> reads {@code +} as a space and then percent-decodes strictly, as
 * {@link PercentDecoding} describes; an encoded {@code %2B} stays a plus sign.
 * <p>
 * The Appendix B example: the six code points U+0020, U+0025, U+0026, U+002B, U+00A3 and U+20AC encode as
 * {@code +%25%26%2B%C2%A3%E2%82%AC}, and that decodes back to them.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class FormUrlEncoding {
	private static final @NonNull String HEX_DIGITS = "0123456789ABCDEF";

	private FormUrlEncoding() {
	}

	/**
	 * Encodes a name or value.
	 *
	 * @param value the text to encode
	 * @return the encoded text
	 * @throws EncodingException   with {@link EncodingException.Kind#UNPAIRED_SURROGATE} if {@code value} is not
	 *                             well-formed UTF-16
	 * @throws ArithmeticException if the UTF-8 octets or the encoded text would be longer than
	 *                             {@link Integer#MAX_VALUE}, which takes a string of hundreds of millions of
	 *                             characters
	 */
	public static @NonNull String encode(@NonNull String value) throws EncodingException {
		requireNonNull(value);
		// The value may be a client secret (RFC 6749 section 2.3.1), so both temporary buffers are zeroed.
		byte[] bytes = StrictUtf8.encode(value);
		try {
			long length = 0;
			for (byte octet : bytes)
				length += (isUnreserved(octet & 0xFF) || octet == ' ') ? 1 : 3;
			char[] chars = new char[Math.toIntExact(length)];
			try {
				int position = 0;
				for (byte octet : bytes) {
					int unsigned = octet & 0xFF;
					if (isUnreserved(unsigned)) {
						chars[position++] = (char) unsigned;
					} else if (unsigned == ' ') {
						chars[position++] = '+';
					} else {
						chars[position++] = '%';
						chars[position++] = HEX_DIGITS.charAt(unsigned >> 4);
						chars[position++] = HEX_DIGITS.charAt(unsigned & 0x0F);
					}
				}
				return new String(chars);
			} finally {
				Arrays.fill(chars, '\0');
			}
		} finally {
			Arrays.fill(bytes, (byte) 0);
		}
	}

	/**
	 * Decodes a name or value, reading {@code +} as a space.
	 *
	 * @param encoded the encoded text
	 * @return the decoded text
	 * @throws EncodingException   if an escape is malformed, the octets are not well-formed UTF-8, or the input has
	 *                             an unpaired surrogate
	 * @throws ArithmeticException if the decoded octets would number more than {@link Integer#MAX_VALUE}, which takes
	 *                             an input of roughly 715 million characters or more
	 */
	public static @NonNull String decode(@NonNull String encoded) throws EncodingException {
		return PercentDecoding.decode(encoded, true);
	}

	private static boolean isUnreserved(int octet) {
		return (octet >= 'A' && octet <= 'Z') || (octet >= 'a' && octet <= 'z') || (octet >= '0' && octet <= '9')
				|| octet == '*' || octet == '-' || octet == '.' || octet == '_';
	}
}
