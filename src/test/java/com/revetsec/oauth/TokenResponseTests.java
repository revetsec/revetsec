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

import com.revetsec.internal.http.RawResponse;
import org.junit.jupiter.api.Test;

import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class TokenResponseTests {
	private static final Instant START = Instant.parse("2026-09-28T12:00:00Z");

	@Test
	void successUsesRequestScopesAndHidesAllTokenMembers() {
		TokenResponse response = TokenResponseParser.parse(raw(200, "{" +
				"\"access_token\":\"abc+/==\",\"token_type\":\"bearer\"," +
				"\"expires_in\":\"60\",\"refresh_token\":\"refresh-secret\"," +
				"\"id_token\":\"id-secret\",\"ext_expires_in\":300}" , Map.of()),
				START, Set.of("requested"));
		assertEquals("Bearer abc+/==", response.getAccessToken().getAuthorizationHeaderValue());
		assertEquals(START.plusSeconds(60), response.getExpiresAt().orElseThrow());
		assertEquals(START, response.getReceivedAt());
		assertTrue(response.getScope().isEmpty());
		assertEquals(Set.of("requested"), response.getGrantedScopes().orElseThrow());
		assertEquals("refresh-secret", response.getRefreshToken().orElseThrow().getValue());
		assertTrue(response.getParameter("ext_expires_in").isPresent());
		for (String hidden : List.of("access_token", "token_type", "expires_in", "refresh_token", "id_token", "scope"))
			assertTrue(response.getParameter(hidden).isEmpty());
		assertFalse(response.toString().contains("abc"));
		assertFalse(response.toJsonObject().toJson().contains("id-secret"));
	}

	@Test
	void oidcPayloadKeepsIdTokenInternalUntilValidation() {
		TokenEndpointPayload payload = TokenResponseParser.parsePayload(raw(200,
				"{\"access_token\":\"access-secret\",\"token_type\":\"Bearer\",\"id_token\":\"id-secret\"}",
				Map.of()), START, Set.of("openid"));
		assertEquals("id-secret", payload.idToken());
		assertFalse(payload.toString().contains("id-secret"));
		assertFalse(payload.toString().contains("access-secret"));
		TokenResponse released = payload.toTokenResponse();
		assertTrue(released.getParameter("id_token").isEmpty());
		assertFalse(released.toString().contains("id-secret"));
	}

	@Test
	void twoHundredWithErrorIsRemoteErrorAndNoSecretLeaks() {
		OAuthErrorResponseException error = assertThrows(OAuthErrorResponseException.class, () ->
				TokenResponseParser.parse(raw(200,
						"{\"error\":\"invalid_grant\",\"error_description\":\"secret prose\"}", Map.of()),
						START, null));
		assertEquals(200, error.getStatus());
		assertEquals("invalid_grant", error.getErrorCode().orElseThrow());
		assertFalse(error.toString().contains("secret prose"));
	}

	@Test
	void expiresInGrammarAndRequiredFieldsAreStrict() {
		for (String expires : List.of("-1", "1.0", "1e2", "\"+1\"", "\"1.0\"", "\"1e2\"",
				"61999999999999999", "\"61999999999999999\""))
			assertThrows(OAuthResponseException.class, () -> TokenResponseParser.parse(raw(200,
					"{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"expires_in\":" + expires + "}",
					Map.of()), START, Set.of()));
		assertThrows(OAuthResponseException.class, () -> TokenResponseParser.parse(raw(200,
				"{\"access_token\":\"a\"}", Map.of()), START, null));
		assertThrows(OAuthResponseException.class, () -> TokenResponseParser.parse(raw(200,
				"{\"token_type\":\"Bearer\"}", Map.of()), START, null));
		assertThrows(OAuthResponseException.class, () -> TokenResponseParser.parse(raw(200,
				"{\"access_token\":\"a\",\"access_token\":\"b\",\"token_type\":\"Bearer\"}",
				Map.of()), START, null));
	}

	@Test
	void rejectedBearerHeaderAndNonTwoHundredStatus() {
		assertThrows(IllegalStateException.class, () -> new AccessToken("bad\r\nHeader: x", "Bearer", null)
				.getAuthorizationHeaderValue());
		assertThrows(IllegalStateException.class, () -> new AccessToken("abc", "DPoP", null)
				.getAuthorizationHeaderValue());
		OAuthErrorResponseException error = assertThrows(OAuthErrorResponseException.class, () ->
				TokenResponseParser.parse(raw(503, "unavailable", Map.of("Retry-After", List.of("5"))), START, null));
		assertEquals(503, error.getStatus());
		assertTrue(error.isTransient());
		assertEquals(Duration.ofSeconds(5), error.getRetryAfter().orElseThrow());
	}

	@Test
	void tokenTypeAndExpiryFollowTheResponseGrammar() {
		for (String type : List.of("bearer", "BEARER")) {
			TokenResponse response = TokenResponseParser.parse(raw(200,
					"{\"access_token\":\"abc\",\"token_type\":\"" + type + "\",\"expires_in\":3600}",
					Map.of()), START, Set.of("original"));
			assertTrue(response.getAccessToken().isBearer());
			assertEquals("Bearer abc", response.getAccessToken().getAuthorizationHeaderValue());
			assertEquals(START.plusSeconds(3_600), response.getExpiresAt().orElseThrow());
		}
		TokenResponse other = TokenResponseParser.parse(raw(200,
				"{\"access_token\":\"abc\",\"token_type\":\"bot\",\"expires_in\":\"3599\","
					+ "\"scope\":\"subset\"}", Map.of()), START, Set.of("original"));
		assertFalse(other.getAccessToken().isBearer());
		assertThrows(IllegalStateException.class, other.getAccessToken()::getAuthorizationHeaderValue);
		assertEquals(START.plusSeconds(3_599), other.getExpiresAt().orElseThrow());
		assertEquals(Set.of("subset"), other.getGrantedScopes().orElseThrow());
		assertEquals("subset", other.getScope().orElseThrow());
		assertTrue(TokenResponseParser.parse(raw(200,
				"{\"access_token\":\"abc\",\"token_type\":\"Bearer\"}", Map.of()), START, null)
				.getExpiresAt().isEmpty());
	}

	@Test
	void accessTokenRejectsControlAndNonAsciiCharactersAtParseTime() {
		for (String token : List.of("line\\r\\nnext", "caf\\u00e9")) {
			String body = "{\"access_token\":\"" + token + "\",\"token_type\":\"Bearer\"}";
			assertEquals(OAuthException.Reason.DOCUMENT_MALFORMED,
					assertThrows(OAuthResponseException.class, () -> TokenResponseParser.parse(
							raw(200, body, Map.of()), START, null)).getReason());
		}
	}

	private static @NonNull RawResponse raw(int status, @NonNull String body, @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> fields) {
		return new RawResponse(status, HttpHeaders.of(fields, (name, value) -> true),
				body.getBytes(StandardCharsets.UTF_8), null, false, Duration.ZERO);
	}
}
