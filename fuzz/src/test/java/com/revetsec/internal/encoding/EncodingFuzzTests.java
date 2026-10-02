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

import org.jspecify.annotations.Nullable;

import org.jspecify.annotations.NonNull;

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.revetsec.internal.encoding.EncodingException.Kind;
import org.junit.jupiter.api.Assertions;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.ByteArrayOutputStream;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Coverage-guided checks for {@code internal.encoding} (M1 plan section 8 rows; exit criterion 6; INV-G1, INV-J7).
 * <p>
 * Each decoder is compared with an oracle written here from its specification (RFC 4648, RFC 3629, RFC 3986 section
 * 2.1, RFC 6749 Appendix B), not from its code: the oracle predicts either the exact result or the exact
 * {@link Kind}, and the target requires both to match. Every {@link EncodingException} must carry its Kind's fixed
 * message, with no cause.
 * <p>
 * {@code StrictUtf8.encode}, {@code PercentDecoding.decode}, {@code FormUrlEncoding.encode},
 * {@code FormUrlEncoding.decode} and {@code QueryParameters.parse} throw {@link ArithmeticException} for inputs of
 * hundreds of millions of characters, where a length would pass {@link Integer#MAX_VALUE} (see their Javadoc). Fuzz
 * inputs are bounded by libFuzzer's {@code -max_len}, far below that, so the targets do not allow it: any
 * {@link ArithmeticException} here is a finding.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public class EncodingFuzzTests {
	private static final String URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	private static final String STANDARD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	/**
	 * {@link Base64Url}, {@link StandardBase64} and {@link SamlBase64} accept exactly the canonical encodings RFC 4648
	 * sections 4 and 5 define (the alphabet, padding required or refused, no 4n + 1 length, zero trailing bits), so each
	 * octet string has exactly one accepted encoding (INV-J7), and they reject the rest with the Kind of the first
	 * failed check. {@code SamlBase64} is {@code StandardBase64} after removing SP, HT, CR and LF only. Every encoding
	 * decodes back to its octets, a line-wrapped one through {@code SamlBase64} too.
	 *
	 * @param input the fuzzed text (read as ISO-8859-1, so every byte is one character) and octets
	 */
	@FuzzTest(maxDuration = "5m")
	public void base64DecodersAcceptExactlyTheCanonicalEncodings(byte @NonNull [] input) {
		String text = new String(input, StandardCharsets.ISO_8859_1);

		requireOutcome(expectedBase64(text, URL_ALPHABET, false), () -> Base64Url.decode(text));
		requireOutcome(expectedBase64(text, STANDARD_ALPHABET, true), () -> StandardBase64.decode(text));
		requireOutcome(expectedBase64(withoutSamlWhitespace(text), STANDARD_ALPHABET, true),
				() -> SamlBase64.decode(text));

		try {
			String url = Base64Url.encode(input);
			String standard = StandardBase64.encode(input);
			Assertions.assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(input), url, "base64url");
			Assertions.assertEquals(Base64.getEncoder().encodeToString(input), standard, "standard Base64");
			Assertions.assertArrayEquals(input, Base64Url.decode(url), "base64url round trip");
			Assertions.assertArrayEquals(input, StandardBase64.decode(standard), "standard Base64 round trip");
			Assertions.assertArrayEquals(input, SamlBase64.decode(wrapped(standard, input.length)), "SAML round trip");
		} catch (EncodingException e) {
			Assertions.fail("a canonical encoding was rejected: " + e.getKind());
		}
	}

	/**
	 * The UTF-8, percent, form and query codecs match their oracles exactly (RFC 3629; RFC 3986 section 2.1; RFC 6749
	 * Appendix B): {@link StrictUtf8} accepts exactly well-formed UTF-8 and well-formed UTF-16, and never substitutes;
	 * {@link PercentDecoding} and {@link FormUrlEncoding#decode(String)} give the oracle's string or the Kind of the
	 * first failed check, and agree with {@link URLDecoder} wherever they accept; {@link FormUrlEncoding#encode(String)}
	 * equals {@link URLEncoder} for well-formed input and round-trips; and {@link QueryParameters} keeps every
	 * parameter, in order, and survives a re-encoding.
	 *
	 * @param input the fuzzed octets, also read as text in which CESU-8 surrogate sequences become unpaired surrogates
	 */
	@FuzzTest(maxDuration = "5m")
	public void urlAndUtf8CodecsMatchTheirOraclesExactly(byte @NonNull [] input) {
		String jdkStrict = jdkStrictUtf8(input);
		requireOutcome(jdkStrict == null ? Expected.failing(Kind.INVALID_UTF8) : Expected.string(jdkStrict),
				() -> StrictUtf8.decode(input));

		String text = textWithSurrogates(input);
		boolean wellFormed = isWellFormed(text);
		Assertions.assertEquals(wellFormed, StrictUtf8.isWellFormed(text), "isWellFormed disagrees");
		requireOutcome(wellFormed ? Expected.bytes(text.getBytes(StandardCharsets.UTF_8))
				: Expected.failing(Kind.UNPAIRED_SURROGATE), () -> StrictUtf8.encode(text));

		Expected percent = expectedPercentDecoding(text, false);
		requireOutcome(percent, () -> PercentDecoding.decode(text));
		Expected form = expectedPercentDecoding(text, true);
		requireOutcome(form, () -> FormUrlEncoding.decode(text));

		if (form.failure == null)
			Assertions.assertEquals(URLDecoder.decode(text, StandardCharsets.UTF_8), form.string,
					"FormUrlEncoding.decode disagrees with URLDecoder on input it accepts");

		requireFormEncoding(text, wellFormed);
		requireQuery(text);
	}

	private static void requireFormEncoding(@NonNull String text, boolean wellFormed) {
		String encoded;

		try {
			encoded = FormUrlEncoding.encode(text);
		} catch (EncodingException e) {
			requireFixedShape(e);
			Assertions.assertFalse(wellFormed, "encode rejected well-formed text");
			Assertions.assertEquals(Kind.UNPAIRED_SURROGATE, e.getKind(), "encode failed with the wrong Kind");
			return;
		}

		Assertions.assertTrue(wellFormed, "encode accepted an unpaired surrogate");
		Assertions.assertEquals(URLEncoder.encode(text, StandardCharsets.UTF_8), encoded, "encode differs from URLEncoder");

		try {
			Assertions.assertEquals(text, FormUrlEncoding.decode(encoded), "form encoding did not round-trip");
		} catch (EncodingException e) {
			Assertions.fail("decode rejected encode's output: " + e.getKind());
		}
	}

	/**
	 * {@link QueryParameters#parse(String)} gives exactly the oracle's parameters (split on {@code &}, empty pieces
	 * skipped, the first {@code =} separating name from value, both form-decoded) or the Kind of the first piece that
	 * fails; accepted parameters survive re-encoding, and the lookups agree with the list.
	 */
	private static void requireQuery(@NonNull String text) {
		List<String[]> expected = new ArrayList<>();
		Kind expectedFailure = null;

		for (String piece : text.split("&", -1)) {
			if (piece.isEmpty())
				continue;

			int separator = piece.indexOf('=');
			Expected name = expectedPercentDecoding(separator < 0 ? piece : piece.substring(0, separator), true);
			Expected value = separator < 0 ? Expected.string("")
					: expectedPercentDecoding(piece.substring(separator + 1), true);
			expectedFailure = name.failure != null ? name.failure : value.failure;

			if (expectedFailure != null)
				break;

			expected.add(new String[]{name.string, value.string});
		}

		QueryParameters parameters;

		try {
			parameters = QueryParameters.parse(text);
		} catch (EncodingException e) {
			requireFixedShape(e);
			Assertions.assertEquals(expectedFailure, e.getKind(), "QueryParameters failed with the wrong Kind");
			return;
		}

		Assertions.assertNull(expectedFailure, "QueryParameters accepted a malformed query");
		Assertions.assertEquals(expected.size(), parameters.getParameters().size(), "QueryParameters lost parameters");
		StringBuilder reencoded = new StringBuilder();
		Map<String, List<String>> byName = new LinkedHashMap<>();

		for (int index = 0; index < expected.size(); ++index) {
			QueryParameters.Parameter parameter = parameters.getParameters().get(index);
			Assertions.assertEquals(expected.get(index)[0], parameter.getName(), "a parameter name differs");
			Assertions.assertEquals(expected.get(index)[1], parameter.getValue(), "a parameter value differs");
			Assertions.assertEquals("Parameter{name=<redacted>, value=<redacted>}", parameter.toString(), "toString()");
			byName.computeIfAbsent(parameter.getName(), name -> new ArrayList<>()).add(parameter.getValue());

			try {
				reencoded.append(index == 0 ? "" : "&").append(FormUrlEncoding.encode(parameter.getName())).append('=')
						.append(FormUrlEncoding.encode(parameter.getValue()));
			} catch (EncodingException e) {
				Assertions.fail("a decoded parameter could not be encoded: " + e.getKind());
			}
		}

		Assertions.assertEquals(byName, parameters.getValuesByName(), "getValuesByName() disagrees with the list");

		for (Map.Entry<String, List<String>> entry : byName.entrySet())
			Assertions.assertEquals(entry.getValue(), parameters.getValues(entry.getKey()), "getValues() disagrees");

		try {
			List<QueryParameters.Parameter> again = QueryParameters.parse(reencoded.toString()).getParameters();
			Assertions.assertEquals(expected.size(), again.size(), "re-encoded parameters changed in number");

			for (int index = 0; index < again.size(); ++index) {
				Assertions.assertEquals(expected.get(index)[0], again.get(index).getName(), "re-encoded name");
				Assertions.assertEquals(expected.get(index)[1], again.get(index).getValue(), "re-encoded value");
			}
		} catch (EncodingException e) {
			Assertions.fail("re-encoded parameters were rejected: " + e.getKind());
		}
	}

	/**
	 * The RFC 4648 oracle: the Kind of the first failed check, in the order the decoders document, or the octets.
	 */
	private static @NonNull Expected expectedBase64(@NonNull String text, @NonNull String alphabet, boolean paddingRequired) {
		int padding = 0;

		for (int index = 0; index < text.length(); ++index) {
			char character = text.charAt(index);

			if (character == '=') {
				if (!paddingRequired)
					return Expected.failing(Kind.PADDING);

				++padding;
			} else if (padding > 0) {
				return Expected.failing(Kind.PADDING);
			} else if (alphabet.indexOf(character) < 0) {
				return Expected.failing(Kind.INVALID_CHARACTER);
			}
		}

		if (padding > 2)
			return Expected.failing(Kind.PADDING);

		if (text.length() % 4 == 1)
			return Expected.failing(Kind.INVALID_LENGTH);

		if (paddingRequired && text.length() % 4 != 0)
			return Expected.failing(Kind.PADDING);

		// The last significant character must have zero trailing bits: 4 of them before "==" or after a 2-character
		// final group, 2 of them before "=" or after a 3-character final group.
		int significant = text.length() - padding;
		int finalGroup = significant % 4;

		if (finalGroup == 2 || finalGroup == 3) {
			int value = alphabet.indexOf(text.charAt(significant - 1));
			int zeroBits = finalGroup == 2 ? 4 : 2;

			if ((value & ((1 << zeroBits) - 1)) != 0)
				return Expected.failing(Kind.NON_CANONICAL);
		}

		return Expected.bytes(decodeBase64(text.substring(0, significant), alphabet));
	}

	/**
	 * Decodes unpadded Base64 text over {@code alphabet} by hand, six bits per character.
	 */
	private static byte @NonNull [] decodeBase64(@NonNull String text, @NonNull String alphabet) {
		ByteArrayOutputStream octets = new ByteArrayOutputStream();
		int buffer = 0;
		int bits = 0;

		for (int index = 0; index < text.length(); ++index) {
			buffer = (buffer << 6) | alphabet.indexOf(text.charAt(index));
			bits += 6;

			if (bits >= 8) {
				bits -= 8;
				octets.write((buffer >> bits) & 0xFF);
			}
		}

		return octets.toByteArray();
	}

	private static @NonNull String withoutSamlWhitespace(@NonNull String text) {
		StringBuilder stripped = new StringBuilder(text.length());

		for (int index = 0; index < text.length(); ++index) {
			char character = text.charAt(index);

			if (character != ' ' && character != '\t' && character != '\r' && character != '\n')
				stripped.append(character);
		}

		return stripped.toString();
	}

	/**
	 * Base64 wrapped as SAML senders do: a leading space, then lines of a width derived from the input, separated by
	 * CRLF, LF or a tab in turn.
	 */
	private static @NonNull String wrapped(@NonNull String base64, int seed) {
		int width = 1 + seed % 76;
		String[] separators = {"\r\n", "\n", "\t"};
		StringBuilder wrapped = new StringBuilder(" ");

		for (int start = 0; start < base64.length(); start += width)
			wrapped.append(base64, start, Math.min(base64.length(), start + width))
					.append(separators[(start / width) % separators.length]);

		return wrapped.toString();
	}

	/**
	 * The percent-decoding oracle (RFC 3986 section 2.1 with UTF-8): scan in order, failing on the first malformed
	 * escape ({@link Kind#MALFORMED_PERCENT_ENCODING}: {@code %} not followed by two ASCII hex digits) or unpaired
	 * surrogate; then decode the octets strictly ({@link Kind#INVALID_UTF8}).
	 */
	private static @NonNull Expected expectedPercentDecoding(@NonNull String text, boolean plusIsSpace) {
		ByteArrayOutputStream octets = new ByteArrayOutputStream();

		for (int index = 0; index < text.length(); ++index) {
			char character = text.charAt(index);

			if (character == '%') {
				if (index + 2 >= text.length() || hexValue(text.charAt(index + 1)) < 0
						|| hexValue(text.charAt(index + 2)) < 0)
					return Expected.failing(Kind.MALFORMED_PERCENT_ENCODING);

				octets.write(hexValue(text.charAt(index + 1)) * 16 + hexValue(text.charAt(index + 2)));
				index += 2;
			} else if (character == '+' && plusIsSpace) {
				octets.write(' ');
			} else if (Character.isHighSurrogate(character) && index + 1 < text.length()
					&& Character.isLowSurrogate(text.charAt(index + 1))) {
				octets.writeBytes(text.substring(index, index + 2).getBytes(StandardCharsets.UTF_8));
				++index;
			} else if (Character.isSurrogate(character)) {
				return Expected.failing(Kind.UNPAIRED_SURROGATE);
			} else {
				octets.writeBytes(String.valueOf(character).getBytes(StandardCharsets.UTF_8));
			}
		}

		String decoded = jdkStrictUtf8(octets.toByteArray());
		return decoded == null ? Expected.failing(Kind.INVALID_UTF8) : Expected.string(decoded);
	}

	private static int hexValue(char character) {
		if (character >= '0' && character <= '9')
			return character - '0';
		if (character >= 'a' && character <= 'f')
			return character - 'a' + 10;
		if (character >= 'A' && character <= 'F')
			return character - 'A' + 10;
		return -1;
	}

	/**
	 * The JDK's strict UTF-8 decoding, or {@code null} if the octets are not well-formed UTF-8.
	 */
	private static @Nullable String jdkStrictUtf8(byte @NonNull [] octets) {
		try {
			CharBuffer decoded = StandardCharsets.UTF_8.newDecoder()
					.onMalformedInput(CodingErrorAction.REPORT)
					.onUnmappableCharacter(CodingErrorAction.REPORT)
					.decode(ByteBuffer.wrap(octets));
			String string = decoded.toString();
			// A second, lenient oracle: well-formed UTF-8 is exactly what survives a replacing round trip unchanged.
			Assertions.assertArrayEquals(octets, new String(octets, StandardCharsets.UTF_8)
					.getBytes(StandardCharsets.UTF_8), "the JDK's strict and lenient UTF-8 disagree");
			return string;
		} catch (CharacterCodingException e) {
			Assertions.assertFalse(Arrays.equals(octets, new String(octets, StandardCharsets.UTF_8)
					.getBytes(StandardCharsets.UTF_8)), "the JDK's strict and lenient UTF-8 disagree");
			return null;
		}
	}

	/**
	 * Reads octets as text so that fuzzing reaches every UTF-16 code unit: well-formed UTF-8 sequences, and also
	 * three-byte sequences for U+D800 to U+DFFF (CESU-8), become their characters, so unpaired surrogates appear; any
	 * other octet becomes the ISO-8859-1 character of the same value.
	 */
	private static @NonNull String textWithSurrogates(byte @NonNull [] octets) {
		StringBuilder text = new StringBuilder(octets.length);
		int index = 0;

		while (index < octets.length) {
			int lead = octets[index] & 0xFF;

			if (lead >= 0xC2 && lead <= 0xDF && continuations(octets, index, 1)) {
				text.append((char) (((lead & 0x1F) << 6) | (octets[index + 1] & 0x3F)));
				index += 2;
			} else if (lead >= 0xE0 && lead <= 0xEF && continuations(octets, index, 2)) {
				int character = ((lead & 0x0F) << 12) | ((octets[index + 1] & 0x3F) << 6) | (octets[index + 2] & 0x3F);

				if (character < 0x800) {
					text.append((char) lead);
					index += 1;
				} else {
					text.append((char) character);
					index += 3;
				}
			} else if (lead >= 0xF0 && lead <= 0xF4 && continuations(octets, index, 3)) {
				int codePoint = ((lead & 0x07) << 18) | ((octets[index + 1] & 0x3F) << 12)
						| ((octets[index + 2] & 0x3F) << 6) | (octets[index + 3] & 0x3F);

				if (codePoint < 0x10000 || codePoint > 0x10FFFF) {
					text.append((char) lead);
					index += 1;
				} else {
					text.appendCodePoint(codePoint);
					index += 4;
				}
			} else {
				text.append((char) lead);
				index += 1;
			}
		}

		return text.toString();
	}

	private static boolean continuations(byte @NonNull [] octets, int lead, int count) {
		if (lead + count >= octets.length)
			return false;

		for (int index = lead + 1; index <= lead + count; ++index)
			if ((octets[index] & 0xC0) != 0x80)
				return false;

		return true;
	}

	/**
	 * Well-formed UTF-16 by the Character API alone.
	 */
	private static boolean isWellFormed(@NonNull String text) {
		for (int index = 0; index < text.length(); ++index) {
			char character = text.charAt(index);

			if (Character.isHighSurrogate(character) && index + 1 < text.length()
					&& Character.isLowSurrogate(text.charAt(index + 1)))
				++index;
			else if (Character.isSurrogate(character))
				return false;
		}

		return true;
	}

	private static void requireOutcome(@NonNull Expected expected, @NonNull Codec codec) {
		Object actual;

		try {
			actual = codec.run();
		} catch (EncodingException e) {
			requireFixedShape(e);
			Assertions.assertEquals(expected.failure, e.getKind(), "a codec failed with the wrong Kind");
			return;
		}

		Assertions.assertNull(expected.failure, () -> "a codec accepted input its oracle rejects with "
				+ expected.failure);

		if (expected.bytes != null)
			Assertions.assertArrayEquals(expected.bytes, (byte[]) actual, "a codec returned the wrong octets");
		else
			Assertions.assertEquals(expected.string, actual, "a codec returned the wrong string");
	}

	private static void requireFixedShape(@NonNull EncodingException exception) {
		Assertions.assertNotNull(exception.getKind(), "an EncodingException has no Kind");
		Assertions.assertEquals(exception.getKind().getMessage(), exception.getMessage(), "not the Kind's fixed message");
		Assertions.assertNull(exception.getCause(), "an EncodingException has a cause");
		Assertions.assertEquals(0, exception.getSuppressed().length, "an EncodingException has suppressed exceptions");
	}

	/**
	 * A codec call that may throw {@link EncodingException}.
	 */
	@FunctionalInterface
	private interface Codec {
		@NonNull Object run() throws EncodingException;
	}

	/**
	 * What an oracle predicts: a failure Kind, or octets, or a string.
	 */
	@Immutable
	private static final class Expected {
		private final Kind failure;
		private final byte[] bytes;
		private final String string;

		private Expected(@Nullable Kind failure, byte @Nullable [] bytes, @Nullable String string) {
			this.failure = failure;
			this.bytes = bytes;
			this.string = string;
		}

		private static @NonNull Expected failing(@NonNull Kind failure) {
			return new Expected(failure, null, null);
		}

		private static @NonNull Expected bytes(byte @NonNull [] bytes) {
			return new Expected(null, bytes, null);
		}

		private static @NonNull Expected string(@NonNull String string) {
			return new Expected(null, null, string);
		}
	}
}
