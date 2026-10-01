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

import com.revetsec.ErrorCategory;
import org.junit.jupiter.api.Test;
import java.util.AbstractList;
import java.util.Arrays;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

final class BearerTokenTests {
	@Test void absentIsDifferentFromMalformed() {
		assertTrue(BearerToken.fromAuthorizationHeaderValues(List.of()).isEmpty());
		for (String value : List.of("", " ", "Bearer", "Bearer ", "Bearer  ", "Basic abc", "BEARER\tabc",
				" Bearer abc", "Bearer abc ", "Bearer abc\t", "Bearer a b", "Bearer =", "Bearer a=b", "Bearer a,b",
				"Bearer a\r\nInjected: x", "Bearer λ", "Bearer a\u0000", "Bearer a\u007F")) {
			AccessTokenValidationException error = assertThrows(AccessTokenValidationException.class,
					() -> BearerToken.fromAuthorizationHeaderValues(List.of(value)), value);
			assertEquals(AccessTokenValidationException.Reason.MALFORMED_REQUEST, error.getReason());
			assertEquals(ErrorCategory.MALFORMED_INPUT, error.getCategory());
			assertEquals(BearerError.INVALID_REQUEST, error.getBearerError());
			assertEquals(400, error.getBearerError().getStatusCode());
			assertNull(error.getCause()); assertFalse(error.isTransient());
		}
	}
	@Test void validGrammarPreservesOpaqueTextAndRedactsIt() {
		String raw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/====";
		for (String scheme : List.of("Bearer ", "bEaReR ", "BEARER    ")) {
			BearerToken token = BearerToken.fromAuthorizationHeaderValues(List.of(scheme + raw)).orElseThrow();
			assertEquals(raw, token.value()); assertFalse(token.toString().contains(raw));
			assertNotEquals(token, BearerToken.fromAuthorizationHeaderValues(List.of(scheme + raw)).orElseThrow());
		}
	}
	@Test void everyAsciiCharacterIsCheckedAgainstTheWireGrammar() {
		String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/";
		for (int c = 0; c < 128; c++) {
			String field = "Bearer a" + (char)c + "b";
			if (alphabet.indexOf(c) >= 0) assertEquals(field.substring(7),
					BearerToken.fromAuthorizationHeaderValues(List.of(field)).orElseThrow().value());
			else assertThrows(AccessTokenValidationException.class, () -> BearerToken.fromAuthorizationHeaderValues(List.of(field)));
		}
	}
	@Test void duplicatesAreRejectedBeforeAccessingOrCopyingValues() {
		assertThrows(AccessTokenValidationException.class, () -> BearerToken.fromAuthorizationHeaderValues(
				List.of("Bearer a", "Bearer a")));
		assertThrows(AccessTokenValidationException.class, () -> BearerToken.fromAuthorizationHeaderValues(
				List.of("Bearer a", "bearer b")));
		List<String> unreadable = new AbstractList<>() {
			@Override public int size() { return 2; }
			@Override public String get(int index) { throw new AssertionError("Multiple fields must not be read."); }
		};
		assertThrows(AccessTokenValidationException.class, () -> BearerToken.fromAuthorizationHeaderValues(unreadable));
	}
	@Test void independentCredentialAndPrefixCapsHoldAtTheirEdges() {
		for (int size : List.of(8_192, 65_536, 1_048_576)) {
			String raw = "a".repeat(size);
			assertEquals(size, BearerToken.fromAuthorizationHeaderValues(List.of("Bearer " + raw), size).orElseThrow().value().length());
			assertThrows(AccessTokenValidationException.class,
					() -> BearerToken.fromAuthorizationHeaderValues(List.of("Bearer " + raw + "a"), size));
			assertEquals(size, BearerToken.fromAuthorizationHeaderValues(List.of("Bearer" + " ".repeat(58) + raw), size).orElseThrow().value().length());
		}
		assertEquals(65_536, BearerToken.fromAuthorizationHeaderValues(List.of("Bearer " + "a".repeat(65_536))).orElseThrow().value().length());
		assertThrows(AccessTokenValidationException.class, () -> BearerToken.fromAuthorizationHeaderValues(List.of("Bearer " + "a".repeat(65_537))));
		assertThrows(AccessTokenValidationException.class, () -> BearerToken.fromAuthorizationHeaderValues(List.of("Bearer" + " ".repeat(59) + "a")));
		assertThrows(AccessTokenValidationException.class, () -> BearerToken.fromAuthorizationHeaderValues(List.of("Basic " + "a".repeat(70_000))));
		for (int size : List.of(-1, 0, 8_191, 1_048_577, Integer.MAX_VALUE))
			assertThrows(IllegalArgumentException.class, () -> BearerToken.fromAuthorizationHeaderValues(List.of(), size));
	}
	// Deliberate programmer misuse of required nonnull inputs.
	@SuppressWarnings("NullAway")
	@Test void programmerNullsDoNotBecomeCredentialVerdicts() {
		assertThrows(NullPointerException.class, () -> BearerToken.fromAuthorizationHeaderValues(null));
		assertThrows(NullPointerException.class, () -> BearerToken.fromAuthorizationHeaderValues(List.of(), null));
		assertThrows(NullPointerException.class, () -> BearerToken.fromAuthorizationHeaderValues(Arrays.asList((String)null)));
	}
}
