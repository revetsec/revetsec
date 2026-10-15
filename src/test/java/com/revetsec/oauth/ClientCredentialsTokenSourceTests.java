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

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import org.jspecify.annotations.NonNull;

import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestTls;
import com.revetsec.testing.RewindableClock;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class ClientCredentialsTokenSourceTests {
	@Test
	void clockRollbackInvalidatesCachedClientCredentialsToken() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", TestHttpsServer.Script.fromSequence(List.of(json("first"), json("replacement"))));
			RewindableClock clock = RewindableClock.fromInstant(Instant.parse("2026-09-28T12:00:00Z"));
			OAuthClient client = OAuthClient.withAuthorizationServerMetadata(
					AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString())
							.authorizationEndpoint(server.uri("/auth")).tokenEndpoint(server.uri("/token")).build())
					.clientId("client").clientAuthentication(ClientAuthentication.fromClientSecretBasic("secret"))
					.httpClient(TestTls.httpClient()).clock(clock).build();
			ClientCredentialsTokenSource source = ClientCredentialsTokenSource.withClient(client).build();
			AccessToken first = assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken();
			clock.advance(Duration.ofSeconds(5));
			assertSame(first, assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken());
			clock.rewind(Duration.ofSeconds(1));
			AccessToken replacement = assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken();
			assertEquals("replacement", replacement.getValue());
			assertEquals(2, server.getHitCount("/token"));
			clock.advance(Duration.ofSeconds(1));
			assertSame(replacement, assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken());
			assertEquals(2, server.getHitCount("/token"));
		}
	}

	@Test
	void explicitEmptyResourcesClearClientDefaultsForDirectAndCachedRequests() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", TestHttpsServer.Script.fromSequence(List.of(
					json("default"), json("source-cleared"), json("direct-cleared"))));
			OAuthClient client = OAuthClient.withAuthorizationServerMetadata(
					AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString())
							.authorizationEndpoint(server.uri("/auth")).tokenEndpoint(server.uri("/token")).build())
					.clientId("client").clientAuthentication(ClientAuthentication.fromClientSecretBasic("secret"))
					.resources(List.of(URI.create("https://api.example/default")))
					.httpClient(TestTls.httpClient()).build();
			assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, ClientCredentialsTokenSource.withClient(client).build().getAccessTokenResult()).getAccessToken();
			assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, ClientCredentialsTokenSource.withClient(client).resources(List.of()).build().getAccessTokenResult()).getAccessToken();
			assertInstanceOf(OAuthTokenRequestResult.Succeeded.class, client.requestClientCredentialsResult(TokenRequestOptions.builder().resources(List.of()).build())).getTokens();
			assertEquals(List.of("https://api.example/default"), QueryParameters.parse(
					server.getRequests("/token").get(0).getBodyAsString()).getValues("resource"));
			for (int index : List.of(1, 2))
				assertEquals(List.of(), QueryParameters.parse(server.getRequests("/token").get(index)
						.getBodyAsString()).getValues("resource"));
		}
	}
	@Test
	void sourceCanSendBoundedProviderSpecificTokenParameters() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", TestHttpsServer.Script.fromResponse(json("token")));
			OAuthClient client = OAuthClient.withAuthorizationServerMetadata(
					AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString())
							.authorizationEndpoint(server.uri("/auth")).tokenEndpoint(server.uri("/token")).build())
					.clientId("client").clientAuthentication(ClientAuthentication.fromClientSecretBasic("secret"))
					.httpClient(TestTls.httpClient()).build();
			ClientCredentialsTokenSource source = ClientCredentialsTokenSource.withClient(client)
					.additionalParameters(java.util.Map.of("audience", "https://api.example/resource")).build();
			assertEquals("token", assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken().getValue());
			assertEquals(List.of("https://api.example/resource"), QueryParameters.parse(
					server.getRequests("/token").get(0).getBodyAsString()).getValues("audience"));
			assertThrows(IllegalArgumentException.class, () -> ClientCredentialsTokenSource.withClient(client)
					.additionalParameters(java.util.Map.of("grant_type", "password")));
		}
	}

	@Test
	void failedEarlyRenewalServesOnlyUntilExpiryAndInvalidationForcesReplacement() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", TestHttpsServer.Script.fromSequence(List.of(
					jsonWithExpiry("first", 60),
					TestHttpsServer.Response.withStatus(503).header("Content-Type", "application/json")
							.body("{\"error\":\"server_error\"}").build(),
					jsonWithExpiry("replacement", 60))));
			TestClock clock = TestClock.fromInstant(Instant.parse("2026-09-28T12:00:00Z"));
			OAuthClient client = OAuthClient.withAuthorizationServerMetadata(
					AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString())
							.authorizationEndpoint(server.uri("/auth")).tokenEndpoint(server.uri("/token")).build())
					.clientId("client").clientAuthentication(ClientAuthentication.fromClientSecretBasic("secret"))
					.httpClient(TestTls.httpClient()).clock(clock).build();
			ClientCredentialsTokenSource source = ClientCredentialsTokenSource.withClient(client).build();
			AccessToken first = assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken();
			clock.advance(Duration.ofSeconds(40));
			assertSame(first, assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken());
			assertEquals(2, server.getHitCount("/token"));
			clock.advance(Duration.ofSeconds(20));
			assertThrows(OAuthException.class, source::getAccessTokenResult);
			assertEquals(2, server.getHitCount("/token"));
			source.invalidate(first);
			assertEquals("replacement", assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken().getValue());
			assertEquals(3, server.getHitCount("/token"));
		}
	}

	@Test
	void clockRollbackCannotServeOldTokenDuringRenewalBackoff() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", TestHttpsServer.Script.fromSequence(List.of(
					jsonWithExpiry("first", 60),
					TestHttpsServer.Response.withStatus(503).header("Content-Type", "application/json")
							.body("{\"error\":\"server_error\"}").build())));
			RewindableClock clock = RewindableClock.fromInstant(Instant.parse("2026-09-28T12:00:00Z"));
			OAuthClient client = OAuthClient.withAuthorizationServerMetadata(
					AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString())
							.authorizationEndpoint(server.uri("/auth")).tokenEndpoint(server.uri("/token")).build())
					.clientId("client").clientAuthentication(ClientAuthentication.fromClientSecretBasic("secret"))
					.httpClient(TestTls.httpClient()).clock(clock).build();
			ClientCredentialsTokenSource source = ClientCredentialsTokenSource.withClient(client).build();
			AccessToken first = assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken();
			clock.advance(Duration.ofSeconds(40));
			assertSame(first, assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken());
			clock.rewind(Duration.ofSeconds(1));
			assertThrows(OAuthException.class, source::getAccessTokenResult);
			assertEquals(2, server.getHitCount("/token"));
		}
	}
	@Test
	void validCachedTokenIsAvailableWhileEarlyRenewalIsInFlight() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", TestHttpsServer.Script.fromResponse(jsonWithExpiry("first", 60)));
			TestClock clock = TestClock.fromInstant(Instant.parse("2026-09-28T12:00:00Z"));
			OAuthClient client = OAuthClient.withAuthorizationServerMetadata(
					AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString())
							.authorizationEndpoint(server.uri("/auth")).tokenEndpoint(server.uri("/token")).build())
					.clientId("client").clientAuthentication(ClientAuthentication.fromClientSecretBasic("secret"))
					.httpClient(TestTls.httpClient()).clock(clock).build();
			ClientCredentialsTokenSource source = ClientCredentialsTokenSource.withClient(client).build();
			AccessToken first = assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken();
			TestHttpsServer.HeldScript held = TestHttpsServer.HeldScript.fromResponse(jsonWithExpiry("second", 60));
			server.script("/token", held);
			clock.advance(Duration.ofSeconds(40));
			ExecutorService executor = Executors.newFixedThreadPool(2);
			try {
				Future<AccessToken> renewal = executor.submit(() -> assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken());
				assertTrue(held.awaitHeldCount(1, Duration.ofSeconds(2)));
				Future<AccessToken> concurrent = executor.submit(() -> assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken());
				assertSame(first, concurrent.get(1, TimeUnit.SECONDS));
				held.release();
				assertEquals("second", renewal.get(3, TimeUnit.SECONDS).getValue());
			} finally { held.release(); executor.shutdownNow(); }
		}
	}

	@Test
	void invalidateThenHundredCallersShareOneReplacementPost() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", TestHttpsServer.Script.fromSequence(List.of(
					json("first"), json("second"))));
			OAuthClient client = OAuthClient.withAuthorizationServerMetadata(
					AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString())
							.authorizationEndpoint(server.uri("/auth")).tokenEndpoint(server.uri("/token")).build())
					.clientId("client").clientAuthentication(ClientAuthentication.fromClientSecretBasic("secret"))
					.httpClient(TestTls.httpClient()).build();
			ClientCredentialsTokenSource source = ClientCredentialsTokenSource.withClient(client).build();
			AccessToken first = assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken();
			assertEquals("first", first.getValue());
			source.invalidate(first);
			int callers = 100;
			CountDownLatch start = new CountDownLatch(1);
			ExecutorService executor = Executors.newFixedThreadPool(callers);
			try {
				List<Future<AccessToken>> results = new ArrayList<>();
				for (int i = 0; i < callers; i++)
					results.add(executor.submit(() -> { start.await(); return assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken(); }));
				start.countDown();
				AccessToken second = results.get(0).get();
				assertEquals("second", second.getValue());
				for (Future<AccessToken> result : results) assertSame(second, result.get());
				assertEquals(2, server.getHitCount("/token"));
				source.invalidate(first);
				assertSame(second, assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, source.getAccessTokenResult()).getAccessToken());
			} finally {
				executor.shutdownNow();
			}
		}
	}

	@Test
	void builderRejectsFallbackAboveMaximum() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OAuthClient client = OAuthClient.withAuthorizationServerMetadata(
					AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString())
							.authorizationEndpoint(server.uri("/auth")).tokenEndpoint(server.uri("/token")).build())
					.clientId("client").clientAuthentication(ClientAuthentication.fromClientSecretBasic("secret"))
					.httpClient(TestTls.httpClient()).build();
			assertThrows(IllegalArgumentException.class, () -> ClientCredentialsTokenSource.withClient(client)
					.fallbackCacheDuration(Duration.ofHours(1)).maximumCacheDuration(Duration.ofMinutes(1)).build());
		}
	}

	private static TestHttpsServer.@NonNull Response json(@NonNull String token) {
		return jsonWithExpiry(token, 300);
	}

	private static TestHttpsServer.@NonNull Response jsonWithExpiry(@NonNull String token, int expiresIn) {
		return TestHttpsServer.Response.withStatus(200).header("Content-Type", "application/json")
				.body("{\"access_token\":\"" + token + "\",\"token_type\":\"Bearer\",\"expires_in\":" + expiresIn + "}")
				.build();
	}
}
