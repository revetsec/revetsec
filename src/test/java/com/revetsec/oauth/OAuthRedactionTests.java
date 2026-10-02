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

import com.revetsec.SealingKey;
import com.revetsec.internal.http.RawResponse;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestSealers;
import com.revetsec.testing.TestTls;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class OAuthRedactionTests {
	private static final String CLIENT_SECRET = "m3_client_secret_9Qa";
	private static final String ACCESS_TOKEN = "m3_access_token_2Bx";
	private static final String REFRESH_TOKEN = "m3_refresh_token_4Cy";
	private static final String RAW_PROSE = "m3_raw_response_6Dz";

	@Test
	void carriersExceptionsStackTracesAndObserversDoNotRenderSecrets() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.withStatus(400)
					.header("Content-Type", "application/json")
					.body("{\"error\":\"invalid_grant\",\"error_description\":\"" + RAW_PROSE + "\"}")
					.build()));
			List<String> observed = new ArrayList<>();
			OAuthObserver observer = new OAuthObserver() {
				@Override public void didFailEndpoint(@NonNull OAuthEndpoint endpoint, @NonNull URI uri,
						@NonNull OAuthException failure, @NonNull Duration elapsed) {
					observed.add(endpoint + " " + uri + " " + failure);
				}
			};
			AuthorizationServerMetadata metadata = AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString())
					.authorizationEndpoint(server.uri("/authorize"))
					.tokenEndpoint(server.uri("/token")).build();
			ClientAuthentication authentication = ClientAuthentication.fromClientSecretPost(CLIENT_SECRET);
			OAuthClient client = OAuthClient.withAuthorizationServerMetadata(metadata).clientId("client")
					.clientAuthentication(authentication).redirectUri(URI.create("https://app.example/callback"))
					.httpClient(TestTls.httpClient()).observer(observer).build();
			PendingAuthorization pending = client.beginAuthorization().getPendingAuthorization();
			String state = pending.state();
			String verifier = pending.verifier();
			String nonce = java.util.Objects.requireNonNull(pending.nonce());
			OAuthErrorResponseException failure = assertThrows(OAuthErrorResponseException.class,
					() -> client.requestClientCredentialsToken(TokenRequestOptions.builder().build()));
			assertEquals("invalid_grant", failure.getErrorCode().orElseThrow());
			assertTrue(server.getRequests("/token").get(0).getBodyAsString().contains(CLIENT_SECRET));
			assertEquals(1, observed.size());
			StringWriter stack = new StringWriter();
			failure.printStackTrace(new PrintWriter(stack));
			RawResponse raw = new RawResponse(200, HttpHeaders.of(Map.of(), (name, value) -> true),
					("{\"access_token\":\"" + ACCESS_TOKEN + "\",\"refresh_token\":\"" + REFRESH_TOKEN
							+ "\",\"token_type\":\"Bearer\"}").getBytes(StandardCharsets.UTF_8),
					null, false, Duration.ZERO);
			TokenResponse tokens = TokenResponseParser.parse(raw, Instant.parse("2026-09-28T12:00:00Z"), null);
			SealingKey key = TestSealers.fixedKey("redaction");
			String keyValue = Base64.getEncoder().encodeToString(TestSealers.fixedKeyBytes("redaction"));
			AuthorizationResponse callback = AuthorizationResponse.fromQueryString("state=" + state + "&code=code-secret");
			String rendered = String.join(" ", authentication.toString(), client.toString(), pending.toString(),
					callback.toString(), tokens.toString(), tokens.getAccessToken().toString(),
					tokens.getRefreshToken().orElseThrow().toString(), key.toString(), failure.toString(),
					stack.toString(), observed.toString(), tokens.toJsonObject().toJson());
			for (String secret : List.of(CLIENT_SECRET, ACCESS_TOKEN, REFRESH_TOKEN, RAW_PROSE,
					state, verifier, nonce, keyValue, "code-secret"))
				assertFalse(rendered.contains(secret), () -> "A secret was rendered in an OAuth diagnostic surface.");
		}
	}
}
