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

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.internal.http.RawResponse;
import org.junit.jupiter.api.Assertions;

import javax.annotation.concurrent.ThreadSafe;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/** Fuzzes the M3 browser and authorization-server input boundaries without network or fixture keys. */
@ThreadSafe
public class OAuthFuzzTests {
	private static final String ISSUER = "https://issuer.example";
	private static final Instant START = Instant.parse("2026-09-28T12:00:00Z");

	/**
	 * A parsed callback never selects one of several singleton protocol values, and cannot echo its raw input from
	 * {@code toString()}. The only rejected-input exception is an OAuth malformed-response exception.
	 *
	 * @param input raw callback query bytes
	 */
	@FuzzTest(maxDuration = "5m")
	public void callbackKeepsSingletonsAndRedactsInput(byte @NonNull [] input) {
		String query = new String(input, StandardCharsets.ISO_8859_1);
		try {
			AuthorizationResponse response = AuthorizationResponse.fromQueryString(query);
			for (String name : List.of("code", "state", "iss", "error", "error_description", "error_uri"))
				Assertions.assertTrue(response.getParameters().getOrDefault(name, List.of()).size() <= 1);
			Assertions.assertFalse(response.getCode().isPresent() && response.getError().isPresent());
			Assertions.assertEquals("AuthorizationResponse{parameters=<redacted>}", response.toString());
		} catch (OAuthResponseException rejected) {
			Assertions.assertEquals(OAuthException.Reason.CALLBACK_MALFORMED, rejected.getReason());
			Assertions.assertNull(rejected.getCause());
		}
	}

	/**
	 * Successful token documents expose only printable access-token values and keep every token member out of their
	 * generic JSON view. Invalid documents and OAuth errors stay within the typed exception family.
	 *
	 * @param input token-response body bytes
	 */
	@FuzzTest(maxDuration = "5m")
	public void tokenJsonKeepsSecretsOutOfGenericMembers(byte @NonNull [] input) {
		RawResponse raw = new RawResponse(200, HttpHeaders.of(Map.of(), (name, value) -> true), input.clone(),
				null, false, Duration.ZERO);
		try {
			TokenResponse response = TokenResponseParser.parse(raw, START, null);
			String token = response.getAccessToken().getValue();
			for (int index = 0; index < token.length(); index++)
				Assertions.assertTrue(token.charAt(index) >= 0x20 && token.charAt(index) <= 0x7E);
			for (String name : List.of("access_token", "token_type", "refresh_token", "id_token", "scope"))
				Assertions.assertTrue(response.getParameter(name).isEmpty());
			Assertions.assertEquals("TokenResponse{tokens=<redacted>}", response.toString());
		} catch (OAuthResponseException | OAuthErrorResponseException rejected) {
			Assertions.assertNull(rejected.getCause());
		}
	}

	/**
	 * Accepted metadata must retain the exact requested issuer. Endpoint URI safety is checked by the client when it
	 * loads the document. Malformed or mismatched documents fail with a typed fixed-message exception.
	 *
	 * @param input metadata JSON bytes
	 */
	@FuzzTest(maxDuration = "5m")
	public void metadataRequiresExactIssuer(byte @NonNull [] input) {
		String json = new String(input, StandardCharsets.ISO_8859_1);
		try {
			AuthorizationServerMetadata metadata = AuthorizationServerMetadata.fromJson(ISSUER, json);
			Assertions.assertEquals(ISSUER, metadata.getIssuer());
			Assertions.assertNotNull(metadata.getAuthorizationEndpoint());
			Assertions.assertNotNull(metadata.getTokenEndpoint());
			Assertions.assertTrue(metadata.isRemotelyDiscovered());
		} catch (OAuthResponseException | OAuthValidationException rejected) {
			Assertions.assertNull(rejected.getCause());
		}
	}

	/**
	 * Form encoding a Java string and parsing it again must preserve the value exactly, including reserved characters
	 * and Unicode. Each fuzz byte is mapped to one Latin-1 code point so there are no malformed surrogate pairs.
	 *
	 * @param input form value bytes
	 */
	@FuzzTest(maxDuration = "5m")
	public void formBodyRoundTripsUnicodeAndReservedCharacters(byte @NonNull [] input) throws Exception {
		String value = new String(input, StandardCharsets.ISO_8859_1);
		String body = new OAuthRequestWriter().add("value", value).body();
		Assertions.assertEquals(List.of(value), QueryParameters.parse(body).getValues("value"));
		Assertions.assertFalse(body.contains("\r"));
		Assertions.assertFalse(body.contains("\n"));
	}
}
