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

import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestTls;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class RefreshAndRevocationTests {
	@Test
	void refreshUsesOnePostAndExposesReplacementToken() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", TestHttpsServer.Script.fromSequence(List.of(
					json(200, "{\"access_token\":\"access-one\",\"token_type\":\"Bearer\","
							+ "\"refresh_token\":\"replacement\",\"expires_in\":60}"),
					json(200, "{\"access_token\":\"access-two\",\"token_type\":\"Bearer\"}"))));
			OAuthClient client = client(server);
			TokenResponse replacement = client.refresh(RefreshToken.fromValue("old-refresh"),
					TokenRequestOptions.builder().scopes(Set.of("narrow")).build());
			assertTrue(replacement.getApplicationData().isEmpty());
			assertEquals("replacement", replacement.getRefreshToken().orElseThrow().getValue());
			assertEquals(Set.of("narrow"), replacement.getGrantedScopes().orElseThrow());
			QueryParameters first = QueryParameters.parse(server.getRequests("/token").get(0).getBodyAsString());
			assertEquals(List.of("refresh_token"), first.getValues("grant_type"));
			assertEquals(List.of("old-refresh"), first.getValues("refresh_token"));
			assertEquals(List.of("narrow"), first.getValues("scope"));
			TokenResponse noReplacement = client.refresh(replacement.getRefreshToken().orElseThrow(),
					TokenRequestOptions.builder().build());
			assertTrue(noReplacement.getRefreshToken().isEmpty());
			assertTrue(noReplacement.getGrantedScopes().isEmpty());
			QueryParameters second = QueryParameters.parse(server.getRequests("/token").get(1).getBodyAsString());
			assertEquals(List.of("replacement"), second.getValues("refresh_token"));
			assertFalse(second.getValuesByName().containsKey("scope"));
			assertEquals(2, server.getHitCount("/token"));
		}
	}

	@Test
	void refreshFailureAndRevocationFailureNeverRetryAndRevocationIgnoresBody() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", TestHttpsServer.Script.fromResponse(json(503,
					"{\"error\":\"temporarily_unavailable\"}")));
			server.script("/revoke", TestHttpsServer.Script.fromSequence(List.of(
					json(200, "this is deliberately not JSON"),
					json(400, "{\"error\":\"unsupported_token_type\"}"),
					json(503, "{\"error\":\"server_error\"}"))));
			OAuthClient client = client(server);
			assertThrows(OAuthErrorResponseException.class, () -> client.refresh(
					RefreshToken.fromValue("old-refresh"), TokenRequestOptions.builder().build()));
			assertEquals(1, server.getHitCount("/token"));
			client.revoke("old-refresh", TokenTypeHint.REFRESH_TOKEN);
			QueryParameters form = QueryParameters.parse(server.getRequests("/revoke").get(0).getBodyAsString());
			assertEquals(List.of("old-refresh"), form.getValues("token"));
			assertEquals(List.of("refresh_token"), form.getValues("token_type_hint"));
			assertEquals("Basic Y2xpZW50OnNlY3JldA==",
					server.getRequests("/revoke").get(0).getHeader("Authorization").orElseThrow());
			OAuthErrorResponseException unsupported = assertThrows(OAuthErrorResponseException.class,
					() -> client.revoke("another-refresh", TokenTypeHint.REFRESH_TOKEN));
			assertEquals(400, unsupported.getStatus());
			assertEquals("unsupported_token_type", unsupported.getErrorCode().orElseThrow());
			OAuthErrorResponseException unavailable = assertThrows(OAuthErrorResponseException.class,
					() -> client.revoke("third-refresh", TokenTypeHint.REFRESH_TOKEN));
			assertEquals(503, unavailable.getStatus());
			assertTrue(unavailable.isTransient());
			assertEquals(3, server.getHitCount("/revoke"));
		}
	}

	private static @NonNull OAuthClient client(@NonNull TestHttpsServer server) {
		AuthorizationServerMetadata metadata = AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString())
				.authorizationEndpoint(server.uri("/authorize"))
				.tokenEndpoint(server.uri("/token"))
				.revocationEndpoint(server.uri("/revoke"))
				.build();
		return OAuthClient.withAuthorizationServerMetadata(metadata).clientId("client")
				.clientAuthentication(ClientAuthentication.fromClientSecretBasic("secret"))
				.redirectUri(URI.create("https://app.example/callback"))
				.httpClient(TestTls.httpClient()).build();
	}

	private static TestHttpsServer.@NonNull Response json(int status, @NonNull String body) {
		return TestHttpsServer.Response.withStatus(status).header("Content-Type", "application/json")
				.body(body).build();
	}
}
