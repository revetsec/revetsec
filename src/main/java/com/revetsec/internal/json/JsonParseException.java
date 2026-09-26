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

package com.revetsec.internal.json;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;

import static java.util.Objects.requireNonNull;

/**
 * Checked failure of {@link JsonCodec#parse(byte[], JsonLimits)} on untrusted input (M1 plan, G7-3 and G6-2).
 * <p>
 * It carries a {@link Kind} and the byte offset where the codec detected the problem. The message is the fixed
 * sentence of its kind: it never contains any part of the input, and not even the offset, so the exception is safe to
 * log (R9). It has no cause, and suppression is disabled. Entry points translate it into the protocol's own
 * exception; it never escapes the library.
 * <p>
 * <strong>Offsets</strong> count bytes of the input, from 0:
 * <ul>
 *   <li>{@link Kind#INPUT_SIZE}: the input-size limit, the offset of the first byte past it;</li>
 *   <li>{@link Kind#BOM}: 0;</li>
 *   <li>{@link Kind#INVALID_UTF8}: the first byte of the first ill-formed sequence;</li>
 *   <li>{@link Kind#UNPAIRED_SURROGATE}: the backslash of the {@code \}{@code u} escape that is not paired;</li>
 *   <li>{@link Kind#DUPLICATE_MEMBER}: the opening quotation mark of the repeated name;</li>
 *   <li>{@link Kind#DEPTH} and {@link Kind#NODES}: the first byte of the value that exceeds the limit;</li>
 *   <li>{@link Kind#STRING_LENGTH}: the opening quotation mark of the string;</li>
 *   <li>{@link Kind#NUMBER_LENGTH} and {@link Kind#EXPONENT}: the first byte of the number;</li>
 *   <li>{@link Kind#SYNTAX}: the byte where the grammar failed, or the input length if the input ended early.</li>
 * </ul>
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@NotThreadSafe
public final class JsonParseException extends Exception {
	private static final long serialVersionUID = 1L;

	/**
	 * Why the input was rejected.
	 */
	private final @NonNull Kind kind;

	/**
	 * The byte offset where the codec detected the problem.
	 */
	private final int byteOffset;

	/**
	 * What was wrong with the input. Each kind has one fixed message.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 */
	@Immutable
	public enum Kind {
		/**
		 * The input is not RFC 8259 JSON: an unexpected or missing character, an unescaped control character in a
		 * string, an invalid escape or number, whitespace other than SP, HT, CR and LF, a non-ASCII character outside
		 * a string, empty input, or trailing content.
		 */
		SYNTAX("The JSON input is not well-formed."),
		/**
		 * The input is not well-formed UTF-8 (overlong forms, encoded surrogates, code points above U+10FFFF, the bytes
		 * C0, C1 and F5 to FF, stray continuation bytes and truncated sequences). The whole input is checked before
		 * any of it is tokenized.
		 */
		INVALID_UTF8("The JSON input is not well-formed UTF-8."),
		/**
		 * The input starts with a UTF-8 byte-order mark (EF BB BF), which RFC 8259 section 8.1 forbids a sender to add.
		 */
		BOM("The JSON input starts with a byte-order mark."),
		/**
		 * A string or member name escapes a low surrogate that does not follow an escaped high surrogate, or a high
		 * surrogate that is not followed at once by an escaped low surrogate (whatever follows it: another escape, a
		 * plain character, or the end of the string). A surrogate encoded directly in UTF-8 (the bytes ED A0 80 to
		 * ED BF BF) is {@link #INVALID_UTF8} instead, because the whole input is checked as UTF-8 first.
		 */
		UNPAIRED_SURROGATE("A JSON string contains an unpaired surrogate escape."),
		/**
		 * An object repeats a member name (compared after unescaping), or, under the SCIM profile, has two names that
		 * differ only in ASCII case.
		 */
		DUPLICATE_MEMBER("A JSON object contains a duplicate member name."),
		/**
		 * The input nests deeper than the profile allows (M1 plan G7-6: the root is at depth 1, and each contained
		 * value is one deeper than its container).
		 */
		DEPTH("The JSON input is nested too deeply."),
		/**
		 * The input holds more values than the profile allows. Every value counts, the root and containers included;
		 * member names do not.
		 */
		NODES("The JSON input contains too many values."),
		/**
		 * A string or member name, after unescaping, is longer than the profile allows, counted in UTF-16 code units.
		 */
		STRING_LENGTH("A JSON string is too long."),
		/**
		 * A number's text, or its canonical form ({@code BigDecimal.toString()}), is longer than the profile allows,
		 * in characters.
		 */
		NUMBER_LENGTH("A JSON number is too long."),
		/**
		 * A number's written exponent or adjusted decimal exponent is larger in magnitude than the profile allows.
		 */
		EXPONENT("A JSON number's exponent is too large."),
		/**
		 * The input has more bytes than the profile allows. Nothing else was read.
		 */
		INPUT_SIZE("The JSON input is too large.");

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

	JsonParseException(@NonNull Kind kind, int byteOffset) {
		super(requireNonNull(kind).getMessage(), null, false, true);
		this.kind = kind;
		this.byteOffset = byteOffset;
	}

	/**
	 * Why the input was rejected.
	 *
	 * @return the kind of failure
	 */
	public @NonNull Kind getKind() {
		return this.kind;
	}

	/**
	 * Where the codec detected the problem (see the class documentation for each kind).
	 *
	 * @return a byte offset into the input, from 0
	 */
	public int getByteOffset() {
		return this.byteOffset;
	}
}
