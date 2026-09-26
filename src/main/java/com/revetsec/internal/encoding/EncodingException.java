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

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;

import static java.util.Objects.requireNonNull;

/**
 * Checked failure of an {@code internal.encoding} codec on untrusted input (M1 plan, G6-2).
 * <p>
 * The message is the fixed sentence of its {@link Kind} and never contains any part of the input, so the exception
 * is safe to log (R9). It has no cause, and suppression is disabled. Entry points translate it into the protocol's
 * own exception; it never escapes the library.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@NotThreadSafe
public final class EncodingException extends Exception {
	private static final long serialVersionUID = 1L;

	/**
	 * Why the input was rejected.
	 */
	private final @NonNull Kind kind;

	/**
	 * What was wrong with the input. Each kind has one fixed message.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 */
	@Immutable
	public enum Kind {
		/**
		 * A character is outside the codec's alphabet (for example {@code +} in base64url, or whitespace where none is
		 * stripped).
		 */
		INVALID_CHARACTER("The input contains a character outside the permitted alphabet."),
		/**
		 * The length cannot be produced by the encoding (for example a Base64 length of 4n + 1).
		 */
		INVALID_LENGTH("The input length is not a valid encoded length."),
		/**
		 * Base64 padding is missing, misplaced or excessive, or present where the encoding forbids it.
		 */
		PADDING("The input padding is missing, misplaced or not permitted."),
		/**
		 * The input decodes, but re-encoding the result does not reproduce it (for example non-zero trailing bits).
		 */
		NON_CANONICAL("The input is not in canonical form."),
		/**
		 * A {@code %} is not followed by two ASCII hexadecimal digits.
		 */
		MALFORMED_PERCENT_ENCODING("The input contains a malformed percent-encoded octet."),
		/**
		 * The octets are not well-formed UTF-8 (overlong, surrogate, out of range, truncated or a stray continuation
		 * byte).
		 */
		INVALID_UTF8("The input is not well-formed UTF-8."),
		/**
		 * A string contains a high surrogate without a following low surrogate, or a low surrogate without a
		 * preceding high surrogate.
		 */
		UNPAIRED_SURROGATE("The input contains an unpaired surrogate.");

		private final @NonNull String message;

		Kind(@NonNull String message) {
			this.message = message;
		}

		/**
		 * The fixed message for this kind.
		 *
		 * @return the message, which never contains input
		 */
		public @NonNull String getMessage() {
			return this.message;
		}
	}

	EncodingException(@NonNull Kind kind) {
		super(requireNonNull(kind).getMessage(), null, false, true);
		this.kind = kind;
	}

	/**
	 * Why the input was rejected.
	 *
	 * @return the kind of failure
	 */
	public @NonNull Kind getKind() {
		return this.kind;
	}
}
