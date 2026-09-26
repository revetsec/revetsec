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

/**
 * The shared last two steps of every strict Base64 decoder here: decode, then re-encode and compare (plan 8,
 * INV-J7).
 * <p>
 * The JDK decoders ignore non-zero trailing bits, so several inputs decode to the same octets ({@code Zg} and
 * {@code Zh} both decode to {@code f}). Re-encoding the result and requiring the input back rejects every such
 * alias, whatever the cause. The callers have already checked the alphabet, the padding and the length, so the JDK
 * decoder only ever sees input it accepts.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
final class Base64Canonical {
	private Base64Canonical() {
	}

	/**
	 * Decodes {@code ascii} and returns the octets only if re-encoding them with {@code encoder} gives
	 * {@code ascii} back. {@code ascii} is not modified, and the temporary re-encoding is zeroed.
	 *
	 * @throws EncodingException with {@link EncodingException.Kind#NON_CANONICAL} if the input is not the canonical
	 *                           encoding of its octets
	 */
	static byte @NonNull [] decode(Base64.@NonNull Decoder decoder, Base64.@NonNull Encoder encoder,
			byte @NonNull [] ascii) throws EncodingException {
		byte[] decoded;
		try {
			decoded = decoder.decode(ascii);
		} catch (IllegalArgumentException e) {
			// Unreachable after the callers' alphabet, padding and length checks; kept so that no
			// IllegalArgumentException can ever escape a decoder.
			throw new EncodingException(EncodingException.Kind.NON_CANONICAL);
		}

		byte[] reencoded = encoder.encode(decoded);
		try {
			if (!Arrays.equals(reencoded, ascii)) {
				Arrays.fill(decoded, (byte) 0);
				throw new EncodingException(EncodingException.Kind.NON_CANONICAL);
			}
			return decoded;
		} finally {
			Arrays.fill(reencoded, (byte) 0);
		}
	}

	/**
	 * Whether {@code character} is an ASCII letter or digit, the alphabet both Base64 variants share.
	 */
	static boolean isAsciiAlphanumeric(char character) {
		return (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z')
				|| (character >= '0' && character <= '9');
	}
}
