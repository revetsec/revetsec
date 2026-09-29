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
}
