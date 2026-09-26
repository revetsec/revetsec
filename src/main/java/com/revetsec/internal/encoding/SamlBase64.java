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
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;

import static java.util.Objects.requireNonNull;

/**
 * Base64 as SAML's HTTP-POST binding carries it (SAML Bindings section 3.5.4): standard Base64, often wrapped into
 * lines.
 * <p>
 * Decoding removes only SP (U+0020), HT (U+0009), CR (U+000D) and LF (U+000A), wherever they appear, and then
 * applies the strict {@link StandardBase64} decoder (plan 8). Every other character outside the Base64 alphabet,
 * other whitespace included (form feed, vertical tab, NEL, no-break space, U+2028), is rejected:
 * {@link EncodingException.Kind#INVALID_CHARACTER}, or {@link EncodingException.Kind#PADDING} when it follows a
 * {@code =}, because {@link StandardBase64} checks for misplaced padding first. Revetsec never uses the JDK's MIME
 * decoder, which silently skips characters outside the alphabet, so a signed message could carry bytes the decoder
 * never looked at.
 * <p>
 * The caller bounds the raw parameter length before decoding (G5-5).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class SamlBase64 {
	private SamlBase64() {
	}

	/**
	 * Decodes a SAML POST-binding Base64 value.
	 *
	 * @param encoded the parameter value, possibly wrapped with SP, HT, CR or LF
	 * @return a new array holding the decoded octets
	 * @throws EncodingException if, once SP, HT, CR and LF are removed, {@code encoded} is not canonical padded
	 *                           standard Base64
	 */
	public static byte @NonNull [] decode(@NonNull String encoded) throws EncodingException {
		requireNonNull(encoded);
		int length = encoded.length();
		@Nullable StringBuilder stripped = null;
		for (int index = 0; index < length; ++index) {
			char character = encoded.charAt(index);
			if (isStrippable(character)) {
				if (stripped == null)
					stripped = new StringBuilder(length).append(encoded, 0, index);
			} else if (stripped != null) {
				stripped.append(character);
			}
		}
		return StandardBase64.decode(stripped == null ? encoded : stripped.toString());
	}

	private static boolean isStrippable(char character) {
		return character == ' ' || character == '\t' || character == '\r' || character == '\n';
	}
}
