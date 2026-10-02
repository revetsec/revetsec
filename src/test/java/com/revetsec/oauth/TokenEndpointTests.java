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
import com.revetsec.internal.Limits;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestTls;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class TokenEndpointTests {
	private static final URI CALLBACK = URI.create("https://app.example/callback?fixed=1");

	@Test
	void codeExchangeSendsExactRedirectVerifierAndRepeatedResources() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", TestHttpsServer.Script.fromResponse(json(200,
					"{\"access_token\":\"token-value\",\"token_type\":\"Bearer\",\"expires_in\":60}")));
			OAuthClient client = client(server);
			AuthorizationRedirect redirect = client.beginAuthorization(AuthorizationRequestOptions.builder()
					.resources(List.of(URI.create("https://api.example/a"), URI.create("https://api.example/b")))
					.scopes(Set.of("one")).applicationData(Map.of("returnTo", "/account")).build());
			QueryParameters begin = QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery());
			String state = begin.getValues("state").get(0);
			String sealed = redirect.getPendingAuthorization().toSealedForm(
					com.revetsec.testing.TestSealers.fromFixedKey(), "provider");
			TokenResponse tokens = client.completeAuthorization(
					AuthorizationResponse.fromQueryString("state=" + state + "&code=one-time-code"),
					PendingAuthorizationSource.fromSealedForm(sealed,
							com.revetsec.testing.TestSealers.fromFixedKey(), "provider"), CALLBACK);
			assertEquals("token-value", tokens.getAccessToken().getValue());
			assertEquals(Set.of("one"), tokens.getGrantedScopes().orElseThrow());
			assertEquals(Map.of("returnTo", "/account"), tokens.getApplicationData());
			assertEquals(1, server.getHitCount("/token"));
			TestHttpsServer.RecordedRequest request = server.getRequests("/token").get(0);
			assertEquals("POST", request.getMethod());
			assertEquals(null, request.getUri().getRawQuery());
			assertEquals("application/x-www-form-urlencoded", request.getHeader("Content-Type").orElseThrow());
			assertEquals("application/json", request.getHeader("Accept").orElseThrow());
			assertTrue(request.getUri().toString().indexOf("secret") < 0);
			QueryParameters form = QueryParameters.parse(request.getBodyAsString());
			assertEquals(List.of("authorization_code"), form.getValues("grant_type"));
			assertEquals(List.of("one-time-code"), form.getValues("code"));
			assertEquals(List.of(CALLBACK.toString()), form.getValues("redirect_uri"));
			assertEquals(List.of("https://api.example/a", "https://api.example/b"), form.getValues("resource"));
			String verifier = form.getValues("code_verifier").get(0);
			assertTrue(verifier.matches("[A-Za-z0-9_-]{43}"));
			String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256")
					.digest(verifier.getBytes(StandardCharsets.US_ASCII)));
			assertEquals(challenge, begin.getValues("code_challenge").get(0));
		}
	}

	@Test
	void twoHundredErrorAndUncertainFailureAreNeverRetried() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", TestHttpsServer.Script.fromResponse(json(200,
					"{\"error\":\"invalid_grant\"}")));
			OAuthClient client = client(server);
			assertEquals("invalid_grant", assertThrows(OAuthErrorResponseException.class, () ->
					client.requestClientCredentialsToken(TokenRequestOptions.builder().build()))
					.getErrorCode().orElseThrow());
			assertEquals(1, server.getHitCount("/token"));
			server.script("/token", TestHttpsServer.Script.fromResponse(json(503,
					"{\"error\":\"server_error\"}")));
			assertThrows(OAuthErrorResponseException.class, () ->
					client.requestClientCredentialsToken(TokenRequestOptions.builder().build()));
			assertEquals(2, server.getHitCount("/token"));
		}
	}

	@Test
	void nonTwoHundredErrorsAndSyntheticGithubTwoHundredErrorAreTyped() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			String githubBody;
			try (var stream = TokenEndpointTests.class.getResourceAsStream(
					"/com/revetsec/oauth/github-200-error-synthetic.json")) {
				githubBody = new String(java.util.Objects.requireNonNull(stream).readAllBytes(), StandardCharsets.UTF_8);
			}
			server.script("/token", TestHttpsServer.Script.fromSequence(List.of(
					json(400, "{\"error\":\"invalid_grant\"}"),
					TestHttpsServer.Response.withStatus(401).header("Content-Type", "application/json")
							.header("WWW-Authenticate", "Basic realm=\"test\"")
							.body("{\"error\":\"invalid_client\"}").build(),
					json(200, githubBody))));
			OAuthClient client = client(server);
			List<String> errors = List.of("invalid_grant", "invalid_client", "bad_verification_code");
			List<Integer> statuses = List.of(400, 401, 200);
			for (int index = 0; index < errors.size(); index++) {
				OAuthErrorResponseException error = assertThrows(OAuthErrorResponseException.class,
						() -> client.requestClientCredentialsToken(TokenRequestOptions.builder().build()));
				assertEquals(errors.get(index), error.getErrorCode().orElseThrow());
				assertEquals(statuses.get(index), error.getStatus());
			}
			assertEquals(3, server.getHitCount("/token"));
		}
	}

	@Test
	void publicClientCannotRequestClientCredentials() {
		AuthorizationServerMetadata metadata = AuthorizationServerMetadata.withIssuer("https://issuer.example")
				.authorizationEndpoint(URI.create("https://issuer.example/authorize"))
				.tokenEndpoint(URI.create("https://issuer.example/token")).build();
		OAuthClient publicClient = OAuthClient.withAuthorizationServerMetadata(metadata).clientId("public")
				.clientAuthentication(ClientAuthentication.noneInstance()).build();
		assertThrows(IllegalStateException.class,
				() -> publicClient.requestClientCredentialsToken(TokenRequestOptions.builder().build()));
	}

	@Test
	void clientCredentialsScopeOverrideControlsFormAndGrantedScopes() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", TestHttpsServer.Script.fromResponse(json(200,
					"{\"access_token\":\"token-value\",\"token_type\":\"Bearer\"}")));
			OAuthClient client = client(server);
			TokenResponse scoped = client.requestClientCredentialsToken(
					TokenRequestOptions.builder().scopes(Set.of("requested")).build());
			assertEquals(Set.of("requested"), scoped.getGrantedScopes().orElseThrow());
			QueryParameters first = QueryParameters.parse(server.getRequests("/token").get(0).getBodyAsString());
			assertEquals(List.of("requested"), first.getValues("scope"));
			TokenResponse empty = client.requestClientCredentialsToken(
					TokenRequestOptions.builder().scopes(Set.of()).build());
			assertEquals(Set.of(), empty.getGrantedScopes().orElseThrow());
			QueryParameters second = QueryParameters.parse(server.getRequests("/token").get(1).getBodyAsString());
			assertTrue(!second.getValuesByName().containsKey("scope"));
		}
	}

	@Test
	void htmlFailureRetainsStatusAndRetryAfterWithoutEchoingBody() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.withStatus(502)
					.header("Content-Type", "text/html")
					.header("Retry-After", "120")
					.body("<html>private echoed credential</html>").build()));
			OAuthErrorResponseException error = assertThrows(OAuthErrorResponseException.class,
					() -> client(server).requestClientCredentialsToken(TokenRequestOptions.builder().build()));
			assertEquals(502, error.getStatus());
			assertTrue(error.isTransient());
			assertEquals(java.time.Duration.ofSeconds(120), error.getRetryAfter().orElseThrow());
			assertTrue(error.getErrorCode().isEmpty());
			assertTrue(!error.toString().contains("private echoed credential"));
			assertEquals(1, server.getHitCount("/token"));
			server.script("/token", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.withStatus(200)
					.header("Content-Type", "text/html").body("<html>not JSON</html>").build()));
			assertEquals(OAuthException.Reason.UNEXPECTED_CONTENT_TYPE,
					assertThrows(OAuthResponseException.class, () -> client(server)
							.requestClientCredentialsToken(TokenRequestOptions.builder().build())).getReason());
		}
	}

	@Test
	void tokenRedirectIsNeverFollowedAndRedirectingClientIsRejected() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.withStatus(302)
					.header("Location", server.uri("/redirect-target").toString()).build()));
			server.script("/redirect-target", TestHttpsServer.Script.fromResponse(json(200,
					"{\"access_token\":\"wrong\",\"token_type\":\"Bearer\"}")));
			assertEquals(OAuthException.Reason.REDIRECT_NOT_FOLLOWED,
					assertThrows(OAuthResponseException.class, () -> client(server)
							.requestClientCredentialsToken(TokenRequestOptions.builder().build())).getReason());
			assertEquals(1, server.getHitCount("/token"));
			assertEquals(0, server.getHitCount("/redirect-target"));
			AuthorizationServerMetadata metadata = AuthorizationServerMetadata
					.withIssuer(server.getBaseUri().toString())
					.authorizationEndpoint(server.uri("/authorize"))
					.tokenEndpoint(server.uri("/token")).build();
			assertThrows(IllegalArgumentException.class, () -> OAuthClient.withAuthorizationServerMetadata(metadata)
					.clientId("client").clientAuthentication(ClientAuthentication.fromClientSecretBasic("secret"))
					.httpClient(TestTls.httpClientBuilder().followRedirects(HttpClient.Redirect.ALWAYS).build()).build());
		}
	}

	@Test
	void oversizedFixedAndChunkedTokenBodiesAreRejectedBeforeJsonParsing() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			byte[] body = new byte[Limits.HTTP_RESPONSE_BODY_SIZE.getDefaultIntValue() + 1];
			Arrays.fill(body, (byte) 'x');
			OAuthClient client = client(server);
			for (TestHttpsServer.Framing framing : TestHttpsServer.Framing.values()) {
				server.script("/token", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.withStatus(200)
						.header("Content-Type", "application/json").body(body).framing(framing).build()));
				assertEquals(OAuthException.Reason.TOO_LARGE,
						assertThrows(OAuthResponseException.class, () -> client.requestClientCredentialsToken(
								TokenRequestOptions.builder().build())).getReason());
			}
			assertEquals(2, server.getHitCount("/token"));
		}
	}

	@Test
	void chunkedSlowDripStopsAtTheOverallDeadline() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", exchange -> {
				var http = exchange.getHttpExchange();
				http.getResponseHeaders().add("Content-Type", "application/json");
				http.sendResponseHeaders(200, 0);
				http.getResponseBody().write("{".getBytes(StandardCharsets.US_ASCII));
				http.getResponseBody().flush();
				exchange.awaitServerClose();
			});
			AuthorizationServerMetadata metadata = AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString())
					.authorizationEndpoint(server.uri("/authorize"))
					.tokenEndpoint(server.uri("/token")).build();
			OAuthClient client = OAuthClient.withAuthorizationServerMetadata(metadata).clientId("client")
					.clientAuthentication(ClientAuthentication.fromClientSecretBasic("secret"))
					.httpClient(TestTls.httpClient()).requestTimeout(Duration.ofSeconds(1))
					.totalDeadline(Duration.ofSeconds(1)).build();
			assertEquals(OAuthException.Reason.NETWORK_FAILURE,
					assertThrows(OAuthTransportException.class, () -> client.requestClientCredentialsToken(
							TokenRequestOptions.builder().build())).getReason());
			assertEquals(1, server.getHitCount("/token"));
		}
	}

	private static @NonNull OAuthClient client(@NonNull TestHttpsServer server) {
		AuthorizationServerMetadata metadata = AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString())
				.authorizationEndpoint(server.uri("/authorize?existing=1"))
				.tokenEndpoint(server.uri("/token"))
				.build();
		return OAuthClient.withAuthorizationServerMetadata(metadata).clientId("client")
				.clientAuthentication(ClientAuthentication.fromClientSecretBasic("secret"))
				.redirectUri(CALLBACK).scopes(Set.of("client-default"))
				.httpClient(TestTls.httpClient()).build();
	}

	private static TestHttpsServer.@NonNull Response json(int status, @NonNull String body) {
		return TestHttpsServer.Response.withStatus(status).header("Content-Type", "application/json")
				.body(body).build();
	}
}
