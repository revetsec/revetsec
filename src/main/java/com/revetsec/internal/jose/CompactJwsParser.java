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

package com.revetsec.internal.jose;

import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.jose.JoseException;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.nio.charset.StandardCharsets;

import static java.util.Objects.requireNonNull;

/**
 * Splits and decodes a JWS compact serialization (RFC 7515 section 7.1; plan "JOSE semantics", steps 1 to 3, P1 and
 * P2). It interprets nothing: the header is decoded but not parsed, and the payload is decoded only to check its
 * encoding.
 * <ol>
 *   <li><strong>Size.</strong> A token longer than the maximum length is {@link JoseException.Reason#TOKEN_TOO_LARGE},
 *   before any character is examined.</li>
 *   <li><strong>Serialization.</strong> A token that starts with <code>{</code> is the JWS JSON serialization
 *   ({@link JoseException.Reason#JSON_SERIALIZATION}). Otherwise one pass over the characters counts the dots and
 *   checks that every other character is in the base64url alphabet, with no split before the count, so the work is
 *   linear in the length. Any other character is {@link JoseException.Reason#TOKEN_SYNTAX}. Four dots are the JWE
 *   compact serialization ({@link JoseException.Reason#ENCRYPTED_TOKEN}); any count but two, or an empty header
 *   segment, is {@link JoseException.Reason#TOKEN_SYNTAX}. An empty payload or signature segment passes here: RFC 7515
 *   allows an empty payload, and every algorithm refuses an empty signature by its length.</li>
 *   <li><strong>Encoding.</strong> Every segment, the payload included, must be canonical unpadded base64url
 *   ({@link Base64Url}); otherwise {@link JoseException.Reason#TOKEN_SYNTAX}.</li>
 * </ol>
 * An unexpected {@link RuntimeException} is {@link JoseException.Reason#TOKEN_SYNTAX} too (INV-G1).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class CompactJwsParser {
	private CompactJwsParser() {
		// Static helpers only.
	}

	/**
	 * Splits and decodes a compact serialization.
	 *
	 * @param compactSerialization the token, untrusted
	 * @param maximumLength        the longest token accepted, in characters
	 * @return the decoded segments
	 * @throws NullPointerException if {@code compactSerialization} is {@code null}
	 * @throws JoseFailure          {@link JoseException.Reason#TOKEN_TOO_LARGE},
	 *                              {@link JoseException.Reason#JSON_SERIALIZATION},
	 *                              {@link JoseException.Reason#ENCRYPTED_TOKEN} or
	 *                              {@link JoseException.Reason#TOKEN_SYNTAX}
	 */
	@NonNull
	public static CompactJws parse(@NonNull String compactSerialization,
																 int maximumLength) throws JoseFailure {
		requireNonNull(compactSerialization);

		// Step 1: the length alone, before any character is read.
		if (compactSerialization.length() > maximumLength)
			throw new JoseFailure(JoseException.Reason.TOKEN_TOO_LARGE);

		try {
			return split(compactSerialization);
		} catch (RuntimeException e) {
			throw new JoseFailure(JoseException.Reason.TOKEN_SYNTAX);
		}
	}

	@NonNull
	private static CompactJws split(@NonNull String compactSerialization) throws JoseFailure {
		int length = compactSerialization.length();

		// Step 2: the JSON serialization, then one pass over every character.
		if (length > 0 && compactSerialization.charAt(0) == '{')
			throw new JoseFailure(JoseException.Reason.JSON_SERIALIZATION);

		int dots = 0;
		int firstDot = -1;
		int secondDot = -1;

		for (int index = 0; index < length; ++index) {
			char character = compactSerialization.charAt(index);

			if (character == '.') {
				if (dots == 0)
					firstDot = index;
				else if (dots == 1)
					secondDot = index;
				++dots;
			} else if (!Base64Url.isAlphabet(character)) {
				throw new JoseFailure(JoseException.Reason.TOKEN_SYNTAX);
			}
		}

		if (dots == 4)
			throw new JoseFailure(JoseException.Reason.ENCRYPTED_TOKEN);
		if (dots != 2 || firstDot == 0)
			throw new JoseFailure(JoseException.Reason.TOKEN_SYNTAX);

		// Step 3: canonical base64url for every segment.
		byte[] header = decode(compactSerialization.substring(0, firstDot));
		byte[] payload = decode(compactSerialization.substring(firstDot + 1, secondDot));
		byte[] signature = decode(compactSerialization.substring(secondDot + 1));
		// Every character before the second dot is ASCII, so this is the received signing input byte for byte.
		byte[] signingInput = compactSerialization.substring(0, secondDot).getBytes(StandardCharsets.US_ASCII);

		return new CompactJws(compactSerialization, header, payload, signature, signingInput);
	}

	private static byte @NonNull [] decode(@NonNull String segment) throws JoseFailure {
		try {
			return Base64Url.decode(segment);
		} catch (EncodingException e) {
			throw new JoseFailure(JoseException.Reason.TOKEN_SYNTAX);
		}
	}
}
