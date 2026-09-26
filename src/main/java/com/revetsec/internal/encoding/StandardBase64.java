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
 * Canonical padded standard Base64 (RFC 4648 section 4), with no line breaks and no whitespace.
 * <p>
 * {@code SealingKey} uses it for its 44-character, 32-byte keys, {@link SamlBase64} after stripping line breaks, and
 * {@code internal.pem} for PEM bodies. Decoding is strict:
 * <ol>
 *   <li>the alphabet: only {@code A-Z}, {@code a-z}, {@code 0-9}, {@code +} and {@code /}, followed by at most two
 *   {@code =} ({@link EncodingException.Kind#INVALID_CHARACTER}, {@link EncodingException.Kind#PADDING});</li>
 *   <li>the length: a multiple of four, so padding is required ({@link EncodingException.Kind#INVALID_LENGTH} for
 *   4n + 1, {@link EncodingException.Kind#PADDING} otherwise);</li>
 *   <li>decode, then re-encode and compare, which rejects non-zero trailing bits
 *   ({@link EncodingException.Kind#NON_CANONICAL}).</li>
 * </ol>
 * So each octet string has exactly one accepted encoding. The empty string decodes to no octets.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class StandardBase64 {
	private static final Base64.@NonNull Encoder ENCODER = Base64.getEncoder();
	private static final Base64.@NonNull Decoder DECODER = Base64.getDecoder();

	private StandardBase64() {
	}

	/**
	 * Encodes octets as padded standard Base64 with no line breaks.
	 *
	 * @param bytes the octets to encode; not modified
	 * @return the canonical encoding
	 */
	public static @NonNull String encode(byte @NonNull [] bytes) {
		requireNonNull(bytes);
		return ENCODER.encodeToString(bytes);
	}

	/**
	 * Decodes canonical padded standard Base64.
	 *
	 * @param encoded the encoded text, with no whitespace
	 * @return a new array holding the decoded octets
	 * @throws EncodingException if {@code encoded} is not the canonical padded Base64 encoding of any octet string
	 */
	public static byte @NonNull [] decode(@NonNull String encoded) throws EncodingException {
		requireNonNull(encoded);
		int length = encoded.length();
		byte[] ascii = new byte[length];
		try {
			int padding = 0;
			for (int index = 0; index < length; ++index) {
				char character = encoded.charAt(index);
				if (character == '=')
					++padding;
				else if (padding > 0)
					throw new EncodingException(EncodingException.Kind.PADDING);
				else if (!isAlphabet(character))
					throw new EncodingException(EncodingException.Kind.INVALID_CHARACTER);
				ascii[index] = (byte) character;
			}
			if (padding > 2)
				throw new EncodingException(EncodingException.Kind.PADDING);
			if (length % 4 == 1)
				throw new EncodingException(EncodingException.Kind.INVALID_LENGTH);
			if (length % 4 != 0)
				throw new EncodingException(EncodingException.Kind.PADDING);
			return Base64Canonical.decode(DECODER, ENCODER, ascii);
		} finally {
			Arrays.fill(ascii, (byte) 0);
		}
	}

	/**
	 * Whether {@code character} is in the standard Base64 alphabet (padding excluded).
	 *
	 * @param character the character to check
	 * @return {@code true} for {@code A-Z}, {@code a-z}, {@code 0-9}, {@code +} and {@code /}
	 */
	public static boolean isAlphabet(char character) {
		return Base64Canonical.isAsciiAlphanumeric(character) || character == '+' || character == '/';
	}
}
