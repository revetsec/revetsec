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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;
import java.util.stream.Stream;

/**
 * SAML HTTP-POST binding Base64 (SAML Bindings section 3.5.4; plan 8; exit criterion 6: only SP, HT, CR and LF are
 * stripped, then the strict standard decoder applies).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class SamlBase64Tests {
	private static final String RESPONSE = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "
			+ "ID=\"_a75adf55-01d7-40cc-929f-dbd8372ebdfc\" Version=\"2.0\" IssueInstant=\"2026-09-24T00:00:00Z\"/>";

	@Test
	void decodesUnwrappedStandardBase64() throws EncodingException {
		byte[] xml = RESPONSE.getBytes(StandardCharsets.UTF_8);
		Assertions.assertArrayEquals(xml, SamlBase64.decode(Base64.getEncoder().encodeToString(xml)));
	}

	// IdPs commonly wrap at 64 or 76 characters, with CRLF or LF.
	@Test
	void decodesMimeStyleLinesWrappedWithCrLf() throws EncodingException {
		byte[] bytes = new byte[700];
		new Random(0x5EED_0004L).nextBytes(bytes);
		String wrapped = Base64.getMimeEncoder().encodeToString(bytes);
		Assertions.assertTrue(wrapped.contains("\r\n"));
		Assertions.assertArrayEquals(bytes, SamlBase64.decode(wrapped));
		Assertions.assertArrayEquals(bytes, SamlBase64.decode(wrapped.replace("\r\n", "\n")));
	}

	// Only SP, HT, CR and LF are removed, wherever they are: around the value, between characters and inside the
	// padding.
	@TestFactory
	Stream<DynamicTest> stripsSpaceTabCarriageReturnAndLineFeedAnywhere() {
		return Stream.of(" Zm9vYmFy", "Zm9vYmFy\r\n", "\tZm9v\tYmFy\t", "Zm 9v Ym Fy", "Z\nm\r9\tv YmFy",
				"Zm9vYg=\n=", "Zm9vYg= =", "\r\n\r\nZm9vYmFy\r\n\r\n").map(input -> DynamicTest.dynamicTest(
				EncodingFailures.describe(input), () -> {
					byte[] expected = input.contains("Yg")
							? "foob".getBytes(StandardCharsets.US_ASCII) : "foobar".getBytes(StandardCharsets.US_ASCII);
					Assertions.assertArrayEquals(expected, SamlBase64.decode(input));
				}));
	}

	// Every other whitespace character is outside the alphabet: form feed, vertical tab, NEL, no-break space, the
	// line and paragraph separators, the ideographic space, the byte-order mark and NUL.
	@TestFactory
	Stream<DynamicTest> rejectsEveryOtherWhitespaceCharacter() {
		return rejections(EncodingException.Kind.INVALID_CHARACTER, "Zm9v\fYmFy", "Zm9v\u000BYmFy",
				"Zm9v\u0085YmFy", "Zm9v\u00A0YmFy", "Zm9v\u2028YmFy", "Zm9v\u2029YmFy", "Zm9v\u3000YmFy",
				"\uFEFFZm9vYmFy", "Zm9v\u0000YmFy", "Zm9v\u001CYmFy");
	}

	// The strict decoder checks for misplaced padding before the alphabet, so the same characters after a '=' are
	// rejected as PADDING, as the class documentation says. A plain space there is stripped, not rejected.
	@TestFactory
	Stream<DynamicTest> rejectsOtherWhitespaceAfterAnEqualsSignAsPadding() {
		return rejections(EncodingException.Kind.PADDING, "Zg==\u000B", "Zg==\f", "Zg==\u00A0", "Zg==\u0085",
				"Zg==\u2028", "Zg==!", "Zg=\u000B=", "Zg==\r\n\u000B", "Zg== \u000B");
	}

	// The JDK MIME decoder silently skips characters outside the alphabet, so bytes an attacker adds would never be
	// looked at; Revetsec rejects them (plan 8, 14.6 mime-base64-decoder rule).
	@TestFactory
	Stream<DynamicTest> rejectsWhatTheMimeDecoderSilentlySkips() {
		return Stream.of("Zm9v!YmFy", "Zm9v<YmFy>", "Zm9v.YmFy", "Zm9v%YmFy", "Zm9v\u00E9YmFy").map(input ->
				DynamicTest.dynamicTest(EncodingFailures.describe(input), () -> {
					Assertions.assertArrayEquals("foobar".getBytes(StandardCharsets.US_ASCII),
							Base64.getMimeDecoder().decode(input), "the JDK MIME decoder accepts it");
					EncodingFailures.assertRejected(EncodingException.Kind.INVALID_CHARACTER, input,
							() -> SamlBase64.decode(input));
				}));
	}

	// After stripping, the strict decoder's rules all apply: padding, the standard alphabet only, the length and
	// canonical trailing bits.
	@Test
	void appliesTheStrictDecoderAfterStripping() {
		EncodingFailures.assertRejected(EncodingException.Kind.PADDING, "Zm9v\r\nYg", () -> SamlBase64.decode(
				"Zm9v\r\nYg"));
		EncodingFailures.assertRejected(EncodingException.Kind.INVALID_CHARACTER, "Zm9v\r\n-_8=",
				() -> SamlBase64.decode("Zm9v\r\n-_8="));
		EncodingFailures.assertRejected(EncodingException.Kind.INVALID_LENGTH, "Zm9v\r\nY",
				() -> SamlBase64.decode("Zm9v\r\nY"));
		EncodingFailures.assertRejected(EncodingException.Kind.NON_CANONICAL, "Zm9v\r\nYh==",
				() -> SamlBase64.decode("Zm9v\r\nYh=="));
		EncodingFailures.assertRejected(EncodingException.Kind.PADDING, "Zg==\r\nZg==",
				() -> SamlBase64.decode("Zg==\r\nZg=="));
	}

	@Test
	void decodesEmptyAndWhitespaceOnlyInputToNoOctets() throws EncodingException {
		Assertions.assertArrayEquals(new byte[0], SamlBase64.decode(""));
		Assertions.assertArrayEquals(new byte[0], SamlBase64.decode(" \t\r\n"));
	}

	// R9: the message is fixed; a sentinel inside rejected input never reaches any rendering.
	@Test
	void failuresNeverEchoTheInput() {
		String input = "PHNhbWxwOlJlc3BvbnNl\r\n" + EncodingFailures.SENTINEL + "\u000B";
		EncodingFailures.assertRejected(EncodingException.Kind.INVALID_CHARACTER, input,
				() -> SamlBase64.decode(input));
	}

	@Test
	@SuppressWarnings("NullAway")
	void rejectsANullArgumentWithNullPointerException() {
		Assertions.assertThrows(NullPointerException.class, () -> SamlBase64.decode(null));
	}

	private static Stream<DynamicTest> rejections(EncodingException.Kind kind, String... inputs) {
		return Stream.of(inputs).map(input -> DynamicTest.dynamicTest(EncodingFailures.describe(input),
				() -> EncodingFailures.assertRejected(kind, input, () -> SamlBase64.decode(input))));
	}
}
