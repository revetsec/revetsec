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
import java.util.Base64;

import static java.util.Objects.requireNonNull;

/**
 * Canonical unpadded base64url (RFC 4648 section 5), as JOSE (RFC 7515 section 2, INV-J7) and the StateSealer wire
 * format use it.
 * <p>
 * Decoding is strict and runs in three steps (plan 8):
 * <ol>
 *   <li>the alphabet: only {@code A-Z}, {@code a-z}, {@code 0-9}, {@code -} and {@code _}, so padding
 *   ({@link EncodingException.Kind#PADDING}), the standard alphabet's {@code +} and {@code /}, whitespace and every
 *   non-ASCII character ({@link EncodingException.Kind#INVALID_CHARACTER}) are rejected, and a length of 4n + 1
 *   ({@link EncodingException.Kind#INVALID_LENGTH});</li>
 *   <li>decode;</li>
 *   <li>re-encode and compare, which rejects non-zero trailing bits
 *   ({@link EncodingException.Kind#NON_CANONICAL}).</li>
 * </ol>
 * So each octet string has exactly one accepted encoding. The empty string decodes to no octets. Callers bound the
 * input length before decoding (R8).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class Base64Url {
	private static final Base64.@NonNull Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
	private static final Base64.@NonNull Decoder DECODER = Base64.getUrlDecoder();

	private Base64Url() {
	}

	/**
	 * Encodes octets as unpadded base64url.
	 *
	 * @param bytes the octets to encode; not modified
	 * @return the canonical encoding
	 */
	public static @NonNull String encode(byte @NonNull [] bytes) {
		requireNonNull(bytes);
		return ENCODER.encodeToString(bytes);
	}

	/**
	 * Decodes canonical unpadded base64url.
	 *
	 * @param encoded the encoded text
	 * @return a new array holding the decoded octets
	 * @throws EncodingException if {@code encoded} is not the canonical unpadded base64url encoding of any octet
	 *                           string
	 */
	public static byte @NonNull [] decode(@NonNull String encoded) throws EncodingException {
		requireNonNull(encoded);
		int length = encoded.length();
		byte[] ascii = new byte[length];
		try {
			for (int index = 0; index < length; ++index) {
				char character = encoded.charAt(index);
				if (character == '=')
					throw new EncodingException(EncodingException.Kind.PADDING);
				if (!isAlphabet(character))
					throw new EncodingException(EncodingException.Kind.INVALID_CHARACTER);
				ascii[index] = (byte) character;
			}
			if (length % 4 == 1)
				throw new EncodingException(EncodingException.Kind.INVALID_LENGTH);
			return Base64Canonical.decode(DECODER, ENCODER, ascii);
		} finally {
			Arrays.fill(ascii, (byte) 0);
		}
	}

	/**
	 * Whether {@code character} is in the base64url alphabet (padding excluded).
	 *
	 * @param character the character to check
	 * @return {@code true} for {@code A-Z}, {@code a-z}, {@code 0-9}, {@code -} and {@code _}
	 */
	public static boolean isAlphabet(char character) {
		return Base64Canonical.isAsciiAlphanumeric(character) || character == '-' || character == '_';
	}
}
