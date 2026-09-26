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

import com.revetsec.internal.json.JsonParseException.Kind;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonBoolean;
import com.revetsec.json.JsonNull;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Strict, bounded UTF-8 JSON codec (RFC 8259) that parses straight into the public {@code com.revetsec.json} model
 * (M1 plan, gate 7). Ported from Soklet's {@code McpJsonCodec}; the {@code String} input path, the output-byte and
 * raw-token limits and the MCP-specific profiles were dropped.
 * <p>
 * <strong>Order of checks.</strong> {@link #parse(byte[], JsonLimits)} rejects, in this order:
 * <ol>
 *   <li>input longer than the profile's byte limit ({@link Kind#INPUT_SIZE}), before reading any of it;</li>
 *   <li>a leading UTF-8 byte-order mark ({@link Kind#BOM});</li>
 *   <li>input that is not well-formed UTF-8 anywhere (Unicode Table 3-7: overlong forms, encoded surrogates, code
 *   points above U+10FFFF, the bytes C0, C1 and F5 to FF, stray continuation bytes and truncated sequences), before
 *   any of it is tokenized ({@link Kind#INVALID_UTF8});</li>
 *   <li>then, while tokenizing, grammar errors and every structural limit.</li>
 * </ol>
 * <strong>Grammar.</strong> Strict RFC 8259: any value may be the root; whitespace is only SP, HT, CR and LF;
 * trailing content is rejected; numbers follow the RFC grammar exactly (no leading zeros, no {@code +}, no bare
 * {@code .}); strings must escape every control character. NUL (as {@code \}{@code u0000}) and Unicode
 * noncharacters are accepted, as JSONTestSuite requires, which diverges from I-JSON (RFC 7493) by design.
 * <p>
 * <strong>Model invariants.</strong> The codec checks every invariant of the public model itself, with a
 * {@link Kind}, before it calls a factory: depth ({@link Kind#DEPTH}), unpaired surrogates
 * ({@link Kind#UNPAIRED_SURROGATE}; the UTF-8 check already excludes encoded ones), number digits
 * ({@link Kind#NUMBER_LENGTH}, since a number's text is at least as long as its digits) and exponents
 * ({@link Kind#EXPONENT}), and duplicate names ({@link Kind#DUPLICATE_MEMBER}). No profile limit exceeds a model cap
 * ({@link JsonLimits}), so {@link IllegalArgumentException} never escapes {@code parse}.
 * <p>
 * <strong>Duplicates</strong> are compared after unescaping, and detected before the member's value is parsed. The
 * SCIM profile also rejects names that differ only in ASCII case, through {@link AsciiCase} (G7-7).
 * <p>
 * <strong>Work</strong> is linear in the input, with two bounded exceptions. {@link BigDecimal} arithmetic runs on
 * numbers of at most the profile's number length. Duplicate names are found through hash lookups, and names whose
 * {@link String#hashCode()} values collide fall back to {@link java.util.HashMap}'s tree bins, so an object whose
 * {@code n} names all collide costs O(n log n) name comparisons rather than O(n) (M1 measured about 130 ms for 99,000
 * colliding names in 3.8 MB). Recursion is bounded by the profile's depth (at most 64). No number is ever expanded to
 * its plain form.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class JsonCodec {
	private JsonCodec() {
	}

	/**
	 * Parses UTF-8 JSON text under a profile.
	 * <p>
	 * The caller must not modify {@code input} during the call; it is read in place, not copied.
	 *
	 * @param input  the UTF-8 JSON text
	 * @param limits the profile
	 * @return the value, which satisfies every invariant of the public model
	 * @throws NullPointerException if an argument is {@code null}
	 * @throws JsonParseException   if the input is rejected; its message never contains the input
	 */
	public static @NonNull JsonValue parse(byte @NonNull [] input, @NonNull JsonLimits limits)
			throws JsonParseException {
		requireNonNull(input);
		requireNonNull(limits);

		if (input.length > limits.getMaxInputBytes())
			throw new JsonParseException(Kind.INPUT_SIZE, limits.getMaxInputBytes());

		if (input.length >= 3 && input[0] == (byte) 0xEF && input[1] == (byte) 0xBB && input[2] == (byte) 0xBF)
			throw new JsonParseException(Kind.BOM, 0);

		int illFormed = firstIllFormedUtf8Offset(input);

		if (illFormed >= 0)
			throw new JsonParseException(Kind.INVALID_UTF8, illFormed);

		return new Parser(input, limits).parseDocument();
	}

	/**
	 * Serializes a value as compact UTF-8 JSON text (see {@link JsonWriter}).
	 *
	 * @param value the value
	 * @return the UTF-8 JSON text
	 * @throws NullPointerException if {@code value} is {@code null}
	 */
	public static byte @NonNull [] toUtf8Bytes(@NonNull JsonValue value) {
		return JsonWriter.toUtf8Bytes(value);
	}

	/**
	 * The offset of the first byte of the first ill-formed UTF-8 sequence (Unicode Table 3-7), or -1 if the input is
	 * well-formed. This is the offset at which the JDK's strict decoder stops.
	 */
	static int firstIllFormedUtf8Offset(byte @NonNull [] input) {
		int length = input.length;
		int index = 0;

		while (index < length) {
			int lead = input[index] & 0xFF;

			if (lead < 0x80) {
				++index;
				continue;
			}

			int continuationBytes;
			int secondMinimum = 0x80;
			int secondMaximum = 0xBF;

			if (lead >= 0xC2 && lead <= 0xDF) {
				continuationBytes = 1;
			} else if (lead >= 0xE0 && lead <= 0xEF) {
				continuationBytes = 2;

				if (lead == 0xE0)
					secondMinimum = 0xA0; // overlong
				else if (lead == 0xED)
					secondMaximum = 0x9F; // U+D800 to U+DFFF
			} else if (lead >= 0xF0 && lead <= 0xF4) {
				continuationBytes = 3;

				if (lead == 0xF0)
					secondMinimum = 0x90; // overlong
				else if (lead == 0xF4)
					secondMaximum = 0x8F; // above U+10FFFF
			} else {
				return index;
			}

			if (index + 1 >= length)
				return index;

			int second = input[index + 1] & 0xFF;

			if (second < secondMinimum || second > secondMaximum)
				return index;

			for (int offset = 2; offset <= continuationBytes; ++offset) {
				if (index + offset >= length)
					return index;

				int continuation = input[index + offset] & 0xFF;

				if (continuation < 0x80 || continuation > 0xBF)
					return index;
			}

			index += continuationBytes + 1;
		}

		return -1;
	}

	/**
	 * The length of {@code value.toString()}, computed from its precision, scale and adjusted exponent without
	 * building the string (Soklet's {@code canonicalNumberLength}).
	 */
	static long canonicalNumberLength(@NonNull BigDecimal value, long adjustedExponent) {
		int sign = value.signum() < 0 ? 1 : 0;
		int precision = value.precision();
		int scale = value.scale();

		// BigDecimal.toString() uses plain notation only when the scale is not negative and the adjusted exponent is
		// at least -6, so it never pads with more than six zeros.
		if (scale >= 0 && adjustedExponent >= -6) {
			if (scale == 0)
				return sign + (long) precision;

			if (adjustedExponent >= 0)
				return sign + (long) precision + 1;

			return sign + (long) precision - adjustedExponent + 1;
		}

		long significand = precision == 1 ? 1 : precision + 1L;
		return sign + significand + 2 + decimalDigitCount(Math.abs(adjustedExponent));
	}

	private static int decimalDigitCount(long value) {
		int digits = 1;
		long remaining = value;

		while (remaining >= 10) {
			remaining /= 10;
			++digits;
		}

		return digits;
	}

	/**
	 * One parse of well-formed UTF-8 input. Every failure is a {@link JsonParseException} with a byte offset.
	 */
	@NotThreadSafe
	private static final class Parser {
		private final byte @NonNull [] input;
		@NonNull
		private final JsonLimits limits;
		/**
		 * Reused for every string that contains an escape.
		 */
		@NonNull
		private final StringBuilder builder;
		private int position;
		private int nodes;

		private Parser(byte @NonNull [] input, @NonNull JsonLimits limits) {
			this.input = input;
			this.limits = limits;
			this.builder = new StringBuilder();
		}

		@NonNull
		private JsonValue parseDocument() throws JsonParseException {
			skipWhitespace();
			JsonValue value = parseValue(1);
			skipWhitespace();

			if (this.position < this.input.length)
				throw new JsonParseException(Kind.SYNTAX, this.position);

			return value;
		}

		/**
		 * Parses the value at the current position (whitespace already skipped). {@code depth} is Soklet's count: the
		 * root is 1 and each contained value one more, which gives the G7-6 depth of the root as its maximum.
		 */
		@NonNull
		private JsonValue parseValue(int depth) throws JsonParseException {
			if (this.position >= this.input.length)
				throw new JsonParseException(Kind.SYNTAX, this.input.length);

			int start = this.position;
			int octet = this.input[start] & 0xFF;

			if (!startsValue(octet))
				throw new JsonParseException(Kind.SYNTAX, start);

			if (depth > this.limits.getMaxDepth())
				throw new JsonParseException(Kind.DEPTH, start);

			if (++this.nodes > this.limits.getMaxNodes())
				throw new JsonParseException(Kind.NODES, start);

			return switch (octet) {
				case '{' -> parseObject(depth);
				case '[' -> parseArray(depth);
				case '"' -> JsonString.fromValue(parseString());
				case 't' -> {
					parseLiteral("true");
					yield JsonBoolean.trueInstance();
				}
				case 'f' -> {
					parseLiteral("false");
					yield JsonBoolean.falseInstance();
				}
				case 'n' -> {
					parseLiteral("null");
					yield JsonNull.defaultInstance();
				}
				default -> parseNumber();
			};
		}

		private static boolean startsValue(int octet) {
			return octet == '{' || octet == '[' || octet == '"' || octet == 't' || octet == 'f' || octet == 'n'
					|| octet == '-' || isDigit(octet);
		}

		@NonNull
		private JsonObject parseObject(int depth) throws JsonParseException {
			++this.position; // '{'
			skipWhitespace();

			if (peek('}')) {
				++this.position;
				return JsonObject.emptyInstance();
			}

			LinkedHashMap<@NonNull String, @NonNull JsonValue> members = new LinkedHashMap<>();
			@Nullable Set<@NonNull String> foldedNames = this.limits.isAsciiCaseVariantNamesRejected()
					? new HashSet<>() : null;

			while (true) {
				if (!peek('"'))
					throw syntaxErrorHere();

				int nameStart = this.position;
				String name = parseString();
				// Folding maps equal names to equal names, so the folded check also catches exact duplicates.
				boolean duplicate = foldedNames == null ? members.containsKey(name)
						: !foldedNames.add(AsciiCase.fold(name));

				if (duplicate)
					throw new JsonParseException(Kind.DUPLICATE_MEMBER, nameStart);

				skipWhitespace();
				expect(':');
				skipWhitespace();
				members.put(name, parseValue(depth + 1));
				skipWhitespace();

				if (peek('}')) {
					++this.position;
					return JsonObject.fromMembers(members);
				}

				expect(',');
				skipWhitespace();
			}
		}

		@NonNull
		private JsonArray parseArray(int depth) throws JsonParseException {
			++this.position; // '['
			skipWhitespace();

			if (peek(']')) {
				++this.position;
				return JsonArray.emptyInstance();
			}

			List<@NonNull JsonValue> elements = new ArrayList<>();

			while (true) {
				elements.add(parseValue(depth + 1));
				skipWhitespace();

				if (peek(']')) {
					++this.position;
					return JsonArray.fromElements(elements);
				}

				expect(',');
				skipWhitespace();
			}
		}

		/**
		 * Parses the string whose opening quotation mark is at the current position. The input is well-formed UTF-8,
		 * so a lead byte always starts a complete sequence.
		 */
		@NonNull
		private String parseString() throws JsonParseException {
			int quote = this.position;
			int runStart = ++this.position;
			int maxLength = this.limits.getMaxStringLength();
			long length = 0; // UTF-16 code units so far
			boolean escaped = false;

			while (true) {
				if (this.position >= this.input.length)
					throw new JsonParseException(Kind.SYNTAX, this.input.length);

				int octet = this.input[this.position] & 0xFF;

				if (octet == '"') {
					String value;

					if (escaped) {
						appendRun(runStart, this.position);
						value = this.builder.toString();
					} else {
						value = new String(this.input, runStart, this.position - runStart, StandardCharsets.UTF_8);
					}

					++this.position;
					return value;
				}

				if (octet == '\\') {
					if (!escaped) {
						escaped = true;
						this.builder.setLength(0);
					}

					appendRun(runStart, this.position);
					length += parseEscape();
					runStart = this.position;
				} else if (octet < 0x20) {
					throw new JsonParseException(Kind.SYNTAX, this.position);
				} else if (octet < 0x80) {
					++this.position;
					++length;
				} else if (octet >= 0xF0) {
					// A supplementary code point: two UTF-16 code units.
					this.position += 4;
					length += 2;
				} else {
					this.position += octet >= 0xE0 ? 3 : 2;
					++length;
				}

				if (length > maxLength)
					throw new JsonParseException(Kind.STRING_LENGTH, quote);
			}
		}

		private void appendRun(int start, int end) {
			if (end > start)
				this.builder.append(new String(this.input, start, end - start, StandardCharsets.UTF_8));
		}

		/**
		 * Parses the escape whose backslash is at the current position and appends what it stands for.
		 *
		 * @return the number of UTF-16 code units appended (1, or 2 for an escaped surrogate pair)
		 */
		private int parseEscape() throws JsonParseException {
			int backslash = this.position;
			++this.position;

			if (this.position >= this.input.length)
				throw new JsonParseException(Kind.SYNTAX, this.input.length);

			int octet = this.input[this.position] & 0xFF;
			++this.position;

			if (octet == 'u')
				return parseUnicodeEscape(backslash);

			char character = switch (octet) {
				case '"' -> '"';
				case '\\' -> '\\';
				case '/' -> '/';
				case 'b' -> '\b';
				case 'f' -> '\f';
				case 'n' -> '\n';
				case 'r' -> '\r';
				case 't' -> '\t';
				default -> throw new JsonParseException(Kind.SYNTAX, this.position - 1);
			};

			this.builder.append(character);
			return 1;
		}

		/**
		 * Parses the four hexadecimal digits after {@code \}{@code u}. An escaped high surrogate must be followed at
		 * once by an escaped low surrogate, and an escaped low surrogate must follow an escaped high one; anything else
		 * is {@link Kind#UNPAIRED_SURROGATE} at the unpaired escape's backslash.
		 */
		private int parseUnicodeEscape(int backslash) throws JsonParseException {
			char first = (char) parseHexDigits();

			if (Character.isLowSurrogate(first))
				throw new JsonParseException(Kind.UNPAIRED_SURROGATE, backslash);

			if (!Character.isHighSurrogate(first)) {
				this.builder.append(first);
				return 1;
			}

			int second = escapedLowSurrogateAt(this.position);

			if (second < 0)
				throw new JsonParseException(Kind.UNPAIRED_SURROGATE, backslash);

			this.position += 6;
			this.builder.append(first).append((char) second);
			return 2;
		}

		private int parseHexDigits() throws JsonParseException {
			int value = 0;

			for (int count = 0; count < 4; ++count) {
				if (this.position >= this.input.length)
					throw new JsonParseException(Kind.SYNTAX, this.input.length);

				int digit = hexDigit(this.input[this.position] & 0xFF);

				if (digit < 0)
					throw new JsonParseException(Kind.SYNTAX, this.position);

				value = value * 16 + digit;
				++this.position;
			}

			return value;
		}

		/**
		 * The low surrogate escaped by the six bytes at {@code offset}, or -1 if they are not a well-formed
		 * {@code \}{@code u} escape of a low surrogate.
		 */
		private int escapedLowSurrogateAt(int offset) {
			if (offset + 6 > this.input.length || this.input[offset] != '\\' || this.input[offset + 1] != 'u')
				return -1;

			int value = 0;

			for (int index = offset + 2; index < offset + 6; ++index) {
				int digit = hexDigit(this.input[index] & 0xFF);

				if (digit < 0)
					return -1;

				value = value * 16 + digit;
			}

			return Character.isLowSurrogate((char) value) ? value : -1;
		}

		/**
		 * Parses a number: {@code -? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?} (RFC 8259 section 6). The
		 * text length and the written exponent are bounded while scanning, so no work is done on an oversized number;
		 * the adjusted exponent and the canonical length are checked once the value exists.
		 */
		@NonNull
		private JsonNumber parseNumber() throws JsonParseException {
			int start = this.position;

			if (peek('-'))
				advanceInNumber(start);

			if (peek('0')) {
				advanceInNumber(start);
			} else {
				requireDigit();
				skipDigits(start);
			}

			if (peek('.')) {
				advanceInNumber(start);
				requireDigit();
				skipDigits(start);
			}

			if (peek('e') || peek('E')) {
				advanceInNumber(start);

				if (peek('+') || peek('-'))
					advanceInNumber(start);

				requireDigit();
				int maxExponent = this.limits.getMaxExponentMagnitude();
				int writtenExponent = 0;

				while (this.position < this.input.length && isDigit(this.input[this.position])) {
					// Never overflows: it stops as soon as the magnitude passes the limit, which is at most 100,000.
					writtenExponent = writtenExponent * 10 + (this.input[this.position] - '0');

					if (writtenExponent > maxExponent)
						throw new JsonParseException(Kind.EXPONENT, start);

					advanceInNumber(start);
				}
			}

			BigDecimal value = new BigDecimal(new String(this.input, start, this.position - start,
					StandardCharsets.US_ASCII));
			long adjustedExponent = (long) value.precision() - value.scale() - 1;

			if (Math.abs(adjustedExponent) > this.limits.getMaxExponentMagnitude())
				throw new JsonParseException(Kind.EXPONENT, start);

			// So the number's canonical form, which toJson() writes, parses under the same profile.
			if (canonicalNumberLength(value, adjustedExponent) > this.limits.getMaxNumberLength())
				throw new JsonParseException(Kind.NUMBER_LENGTH, start);

			return JsonNumber.fromValue(value);
		}

		private void advanceInNumber(int start) throws JsonParseException {
			++this.position;

			if (this.position - start > this.limits.getMaxNumberLength())
				throw new JsonParseException(Kind.NUMBER_LENGTH, start);
		}

		private void requireDigit() throws JsonParseException {
			if (this.position >= this.input.length || !isDigit(this.input[this.position]))
				throw syntaxErrorHere();
		}

		private void skipDigits(int start) throws JsonParseException {
			while (this.position < this.input.length && isDigit(this.input[this.position]))
				advanceInNumber(start);
		}

		private void parseLiteral(@NonNull String literal) throws JsonParseException {
			for (int index = 0; index < literal.length(); ++index) {
				if (this.position >= this.input.length)
					throw new JsonParseException(Kind.SYNTAX, this.input.length);

				if (this.input[this.position] != literal.charAt(index))
					throw new JsonParseException(Kind.SYNTAX, this.position);

				++this.position;
			}
		}

		private void expect(char expected) throws JsonParseException {
			if (!peek(expected))
				throw syntaxErrorHere();

			++this.position;
		}

		private boolean peek(char expected) {
			return this.position < this.input.length && this.input[this.position] == expected;
		}

		private void skipWhitespace() {
			while (this.position < this.input.length) {
				byte octet = this.input[this.position];

				if (octet != ' ' && octet != '\t' && octet != '\r' && octet != '\n')
					return;

				++this.position;
			}
		}

		/**
		 * A syntax error at the current byte, or at the end of the input if it ended early.
		 */
		@NonNull
		private JsonParseException syntaxErrorHere() {
			return new JsonParseException(Kind.SYNTAX, Math.min(this.position, this.input.length));
		}

		private static boolean isDigit(int octet) {
			return octet >= '0' && octet <= '9';
		}

		private static int hexDigit(int octet) {
			if (octet >= '0' && octet <= '9')
				return octet - '0';

			if (octet >= 'a' && octet <= 'f')
				return octet - 'a' + 10;

			if (octet >= 'A' && octet <= 'F')
				return octet - 'A' + 10;

			return -1;
		}
	}
}
