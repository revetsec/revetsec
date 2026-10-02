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

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class AuthorizationResponseTests {
	@Test
	void decodesQueryExactlyOnceAndKeepsExtras() {
		AuthorizationResponse response = AuthorizationResponse.fromQueryString(
				"code=a%2Bb&state=s%2Bt&iss=https%3A%2F%2Fissuer.example&custom=first&custom=second");
		assertEquals("a+b", response.getCode().orElseThrow());
		assertEquals("s+t", response.getState().orElseThrow());
		assertEquals("https://issuer.example", response.getIssuer().orElseThrow());
		assertEquals(List.of("first", "second"), response.getParameters().get("custom"));
		assertEquals(AuthorizationRequestOptions.ResponseMode.QUERY, response.getResponseMode());
		assertFalse(response.toString().contains("a+b"));
		assertThrows(UnsupportedOperationException.class,
				() -> response.getParameters().put("other", List.of("value")));
	}

	@Test
	void duplicateSingletonAndCodeErrorAreMalformed() {
		for (String query : List.of("state=a&state=b", "code=a&code=b", "iss=a&iss=b",
				"error=a&error=b", "code=a&error=access_denied")) {
			OAuthResponseException error = assertThrows(OAuthResponseException.class,
					() -> AuthorizationResponse.fromQueryString(query));
			assertEquals(OAuthException.Reason.CALLBACK_MALFORMED, error.getReason());
		}
	}

	@Test
	void formPostUsesUtf8AndRejectsQueryProtocolCollision() {
		byte[] body = "code=a%2Bb&state=abc&user=%7B%22name%22%3A%22x%22%7D"
				.getBytes(StandardCharsets.UTF_8);
		AuthorizationResponse response = AuthorizationResponse.fromFormBody(body, StandardCharsets.UTF_8, "tracking=1");
		assertEquals(AuthorizationRequestOptions.ResponseMode.FORM_POST, response.getResponseMode());
		assertEquals("a+b", response.getCode().orElseThrow());
		assertEquals("{\"name\":\"x\"}", java.util.Objects.requireNonNull(
				response.getParameters().get("user")).get(0));
		assertEquals(List.of("1"), response.getParameters().get("tracking"));
		assertThrows(OAuthResponseException.class,
				() -> AuthorizationResponse.fromFormBody(body, StandardCharsets.UTF_8, "state=evil"));
		assertThrows(OAuthResponseException.class,
				() -> AuthorizationResponse.fromFormBody(body, StandardCharsets.ISO_8859_1, null));
		assertThrows(OAuthResponseException.class,
				() -> AuthorizationResponse.fromFormBody(new byte[] {(byte) 0xC3, (byte) 0x28},
						StandardCharsets.UTF_8, null));
	}

	@Test
	void routeSuppliedModeAndPerFlowCookieName() {
		AuthorizationResponse response = AuthorizationResponse.fromParameters(
				Map.of("state", List.of("abc")), null, AuthorizationRequestOptions.ResponseMode.FORM_POST);
		assertEquals(AuthorizationRequestOptions.ResponseMode.FORM_POST, response.getResponseMode());
		assertEquals("__Host-revetsec-oauth-ba7816bf8f01cfea", response.getPerFlowCookieName());
		assertTrue(AuthorizationResponse.fromQueryString("code=x").getState().isEmpty());
		assertThrows(IllegalArgumentException.class,
				() -> AuthorizationResponse.fromQueryString("code=x").getPerFlowCookieName());
	}

	@Test
	void errorDescriptionIsBoundedAndContainsOnlyNqschar() {
		AuthorizationResponse response = AuthorizationResponse.fromQueryString(
				"state=s&error=access_denied&error_description=%0D%0A%C2%A3%22%5C"
						+ "x".repeat(1_100));
		String safe = response.getErrorDescription().orElseThrow();
		assertEquals(1_024, safe.length());
		assertTrue(safe.startsWith("?????"));
		assertFalse(safe.contains("\r"));
		assertFalse(safe.contains("\n"));
		assertFalse(safe.contains("£"));
	}
	@Test
	void rawMimeOverloadValidatesEnvelopeThenPreservesDuplicateAndChannelChecks() {
		byte[] body = "code=a%2Bb&state=abc&extra=x&extra=y".getBytes(StandardCharsets.UTF_8);
		for (String mime : List.of("application/x-www-form-urlencoded", "Application/X-WWW-Form-Urlencoded; Charset=\"UTF-8\"", " application/x-www-form-urlencoded; charset=utf-8; x=\"a,b\" ")) {
			AuthorizationResponse result = AuthorizationResponse.fromFormBody(body, List.of(mime), "tracking=1");
			assertEquals("a+b", result.getCode().orElseThrow());
			assertEquals(List.of("x", "y"), result.getParameters().get("extra"));
			assertEquals(List.of("1"), result.getParameters().get("tracking"));
			assertEquals(AuthorizationRequestOptions.ResponseMode.FORM_POST, result.getResponseMode());
		}
		for (List<String> fields : List.of(List.<String>of(), List.of(""), List.of("application/json"),
				List.of("application/x-www-form-urlencoded", "application/x-www-form-urlencoded"),
				List.of("application/x-www-form-urlencoded; charset=utf-8; CHARSET=utf-8"),
				List.of("application/x-www-form-urlencoded; charset=iso-8859-1"),
				List.of("application/x-www-form-urlencoded; charset="), List.of("application/x-www-form-urlencoded; x=\"λ\""),
				List.of("application/x-www-form-urlencoded, application/json"), List.of("application/x-www-form-urlencoded\r\nInjected:x")))
			assertEquals(OAuthException.Reason.CALLBACK_MALFORMED, assertThrows(OAuthResponseException.class,
					() -> AuthorizationResponse.fromFormBody(body, fields, null)).getReason());
		for (String encoded : List.of("code=a&code=b", "state=a&state=b", "code=a&error=denied"))
			assertThrows(OAuthResponseException.class, () -> AuthorizationResponse.fromFormBody(encoded.getBytes(StandardCharsets.UTF_8), List.of("application/x-www-form-urlencoded"), null));
		assertThrows(OAuthResponseException.class, () -> AuthorizationResponse.fromFormBody(body, List.of("application/x-www-form-urlencoded"), "state=evil"));
		assertThrows(OAuthResponseException.class, () -> AuthorizationResponse.fromFormBody(new byte[]{(byte)0xC3}, List.of("application/x-www-form-urlencoded"), null));
		assertThrows(OAuthResponseException.class, () -> AuthorizationResponse.fromFormBody(new byte[32769], List.of("application/x-www-form-urlencoded"), null));
	}

	@Test
	void rawMimeSizeAndCardinalityAreBoundedBeforeParserAllocation() {
		byte[] body = "state=abc".getBytes(StandardCharsets.UTF_8);
		String prefix = "application/x-www-form-urlencoded; x=\"";
		for (int size : List.of(8191, 8192)) {
			String field = prefix + "a".repeat(size-prefix.length()-1) + "\"";
			assertEquals("abc", AuthorizationResponse.fromFormBody(body, List.of(field), null).getState().orElseThrow());
		}
		String oversized = prefix + "a".repeat(8193-prefix.length()-1) + "\"";
		assertEquals(OAuthException.Reason.CALLBACK_MALFORMED, assertThrows(OAuthResponseException.class,
				() -> AuthorizationResponse.fromFormBody(body, List.of(oversized), null)).getReason());
		StringBuilder parameters = new StringBuilder("application/x-www-form-urlencoded");
		for (int index=0; index<2000; index++) parameters.append(";p").append(index).append("=a");
		assertThrows(OAuthResponseException.class, () -> AuthorizationResponse.fromFormBody(body, List.of(parameters.toString()), null));
		List<String> unreadable = new java.util.AbstractList<>() {
			@Override public int size() { return 2; }
			@Override public @NonNull String get(int index) { throw new AssertionError("Cardinality must precede field access."); }
		};
		assertThrows(OAuthResponseException.class, () -> AuthorizationResponse.fromFormBody(body, unreadable, null));
	}

	// Deliberate programmer misuse, with a cast to select the new overload.
	@SuppressWarnings("NullAway")
	@Test void rawMimeRequiredNullInputsAreProgrammingErrors() {
		byte[] body = "state=abc".getBytes(StandardCharsets.UTF_8);

		assertThrows(NullPointerException.class, () -> AuthorizationResponse.fromFormBody(body, (List<String>) null, null));
		assertThrows(NullPointerException.class, () -> AuthorizationResponse.fromFormBody(body, java.util.Arrays.asList((String)null), null));
		assertThrows(NullPointerException.class, () -> AuthorizationResponse.fromFormBody(null, List.of("application/x-www-form-urlencoded"), null));
	}

}
