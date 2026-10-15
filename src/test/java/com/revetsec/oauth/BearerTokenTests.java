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

package com.revetsec.oauth;

import org.jspecify.annotations.NonNull;

import org.junit.jupiter.api.Test;
import java.util.AbstractList;
import java.util.Arrays;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

final class BearerTokenTests {
	@Test void absentIsDifferentFromMalformed() {
		assertTrue((BearerToken.fromAuthorizationHeaderValuesResult(List.of()) instanceof BearerTokenResult.Absent));
		for (String value : List.of("", " ", "Bearer", "Bearer ", "Bearer  ", "Basic abc", "BEARER\tabc",
				" Bearer abc", "Bearer abc ", "Bearer abc\t", "Bearer a b", "Bearer =", "Bearer a=b", "Bearer a,b",
				"Bearer a\r\nInjected: x", "Bearer λ", "Bearer a\u0000", "Bearer a\u007F")) {
			BearerTokenResult.Malformed error = assertInstanceOf(BearerTokenResult.Malformed.class, BearerToken.fromAuthorizationHeaderValuesResult(List.of(value)), value);
			assertEquals("Malformed", error.getClass().getSimpleName());
			assertEquals("BearerTokenResult{outcome=Malformed, data=<redacted>}", error.toString());
		}
	}
	@Test void validGrammarPreservesOpaqueTextAndRedactsIt() {
		String raw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/====";
		for (String scheme : List.of("Bearer ", "bEaReR ", "BEARER    ")) {
			BearerToken token = assertInstanceOf(BearerTokenResult.Present.class, BearerToken.fromAuthorizationHeaderValuesResult(List.of(scheme + raw))).getToken();
			assertEquals(raw, token.value()); assertFalse(token.toString().contains(raw));
			assertNotEquals(token, assertInstanceOf(BearerTokenResult.Present.class, BearerToken.fromAuthorizationHeaderValuesResult(List.of(scheme + raw))).getToken());
		}
	}
	@Test void everyAsciiCharacterIsCheckedAgainstTheWireGrammar() {
		String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/";
		for (int c = 0; c < 128; c++) {
			String field = "Bearer a" + (char)c + "b";
			if (alphabet.indexOf(c) >= 0) assertEquals(field.substring(7),
					assertInstanceOf(BearerTokenResult.Present.class, BearerToken.fromAuthorizationHeaderValuesResult(List.of(field))).getToken().value());
			else assertInstanceOf(BearerTokenResult.Malformed.class, BearerToken.fromAuthorizationHeaderValuesResult(List.of(field)));
		}
	}
	@Test void duplicatesAreRejectedBeforeAccessingOrCopyingValues() {
		assertInstanceOf(BearerTokenResult.Malformed.class, BearerToken.fromAuthorizationHeaderValuesResult(
				List.of("Bearer a", "Bearer a")));
		assertInstanceOf(BearerTokenResult.Malformed.class, BearerToken.fromAuthorizationHeaderValuesResult(
				List.of("Bearer a", "bearer b")));
		List<String> unreadable = new AbstractList<>() {
			@Override public int size() { return 2; }
			@Override public @NonNull String get(int index) { throw new AssertionError("Multiple fields must not be read."); }
		};
		assertInstanceOf(BearerTokenResult.Malformed.class, BearerToken.fromAuthorizationHeaderValuesResult(unreadable));
	}
	@Test void independentCredentialAndPrefixCapsHoldAtTheirEdges() {
		for (int size : List.of(8_192, 65_536, 1_048_576)) {
			String raw = "a".repeat(size);
			assertEquals(size, assertInstanceOf(BearerTokenResult.Present.class, BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer " + raw), size)).getToken().value().length());
			assertInstanceOf(BearerTokenResult.Malformed.class, BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer " + raw + "a"), size));
			assertEquals(size, assertInstanceOf(BearerTokenResult.Present.class, BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer" + " ".repeat(58) + raw), size)).getToken().value().length());
		}
		assertEquals(65_536, assertInstanceOf(BearerTokenResult.Present.class, BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer " + "a".repeat(65_536)))).getToken().value().length());
		assertInstanceOf(BearerTokenResult.Malformed.class, BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer " + "a".repeat(65_537))));
		assertInstanceOf(BearerTokenResult.Malformed.class, BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer" + " ".repeat(59) + "a")));
		assertInstanceOf(BearerTokenResult.Malformed.class, BearerToken.fromAuthorizationHeaderValuesResult(List.of("Basic " + "a".repeat(70_000))));
		for (int size : List.of(-1, 0, 8_191, 1_048_577, Integer.MAX_VALUE))
			assertThrows(IllegalArgumentException.class, () -> BearerToken.fromAuthorizationHeaderValuesResult(List.of(), size));
	}
	// Deliberate programmer misuse of required nonnull inputs.
	@SuppressWarnings("NullAway")
	@Test void programmerNullsDoNotBecomeCredentialVerdicts() {
		assertThrows(NullPointerException.class, () -> BearerToken.fromAuthorizationHeaderValuesResult(null));
		assertThrows(NullPointerException.class, () -> BearerToken.fromAuthorizationHeaderValuesResult(List.of(), null));
		assertThrows(NullPointerException.class, () -> BearerToken.fromAuthorizationHeaderValuesResult(Arrays.asList((String)null)));
	}
}
