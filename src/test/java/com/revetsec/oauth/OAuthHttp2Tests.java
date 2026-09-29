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

import com.revetsec.testing.OAuthHttp2Server;
import com.revetsec.testing.TestTls;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class OAuthHttp2Tests {
	@Test
	void injectedJdkClientUsesAlpnHttp2ForTokenPost() throws Exception {
		try (OAuthHttp2Server server = OAuthHttp2Server.start(0)) {
			HttpClient http2 = TestTls.httpClientBuilder().version(HttpClient.Version.HTTP_2).build();
			HttpResponse<String> probe = http2.send(HttpRequest.newBuilder(server.uri("/probe"))
					.timeout(Duration.ofSeconds(10)).GET().build(), HttpResponse.BodyHandlers.ofString());
			assertEquals(HttpClient.Version.HTTP_2, probe.version());
			AuthorizationServerMetadata metadata = AuthorizationServerMetadata.withIssuer(server.uri("").toString())
					.authorizationEndpoint(server.uri("/authorize"))
					.tokenEndpoint(server.uri("/token"))
					.build();
			OAuthClient client = OAuthClient.withAuthorizationServerMetadata(metadata).clientId("service")
					.clientAuthentication(ClientAuthentication.fromClientSecretBasic("secret"))
					.httpClient(http2).allowInsecureLoopback(true).build();
			assertEquals("ok", client.requestClientCredentialsToken(TokenRequestOptions.builder().build())
					.getAccessToken().getValue());
			assertEquals(2, server.getRequestCount());
		}
	}

	@Test
	void closingLargeHttp2BodyDoesNotBlockNextRequest() throws Exception {
		try (OAuthHttp2Server server = OAuthHttp2Server.start(17 * 1_024 * 1_024)) {
			HttpClient http2 = TestTls.httpClientBuilder().version(HttpClient.Version.HTTP_2).build();
			HttpResponse<java.io.InputStream> first = http2.send(HttpRequest.newBuilder(server.uri("/large"))
					.timeout(Duration.ofSeconds(20)).GET().build(), HttpResponse.BodyHandlers.ofInputStream());
			assertEquals(HttpClient.Version.HTTP_2, first.version());
			first.body().close();
			HttpResponse<java.io.InputStream> second = http2.send(HttpRequest.newBuilder(server.uri("/after"))
					.timeout(Duration.ofSeconds(20)).GET().build(), HttpResponse.BodyHandlers.ofInputStream());
			assertEquals(HttpClient.Version.HTTP_2, second.version());
			second.body().close();
			assertTrue(server.getRequestCount() >= 2);
			assertTrue(server.awaitNoOpenStreams(Duration.ofSeconds(5)));
			System.out.println("h2-large-body: jdk=" + Runtime.version().feature()
					+ " resets=" + server.getResetCount() + " connections=" + server.getConnectionCount()
					+ " openStreams=" + server.getOpenStreamCount());
		}
	}

	@Test
	void malformedStatusFailsAndLaterRequestCompletes() throws Exception {
		try (OAuthHttp2Server server = OAuthHttp2Server.startWithMalformedFirstStatus()) {
			HttpClient http2 = TestTls.httpClientBuilder().version(HttpClient.Version.HTTP_2).build();
			Exception failure = assertThrows(Exception.class, () -> http2.send(HttpRequest.newBuilder(server.uri("/malformed"))
					.timeout(Duration.ofSeconds(10)).GET().build(), HttpResponse.BodyHandlers.ofString()));
			HttpResponse<String> later = http2.send(HttpRequest.newBuilder(server.uri("/later"))
					.timeout(Duration.ofSeconds(10)).GET().build(), HttpResponse.BodyHandlers.ofString());
			assertEquals(200, later.statusCode());
			System.out.println("h2-malformed-status: jdk=" + Runtime.version().feature()
					+ " exception=" + failure.getClass().getSimpleName()
					+ " requests=" + server.getRequestCount() + " connections=" + server.getConnectionCount());
		}
	}

	@Test
	void oversizedTokenBodyIsBoundedAndLaterExchangeCompletes() throws Exception {
		try (OAuthHttp2Server server = OAuthHttp2Server.start(17 * 1_024 * 1_024)) {
			HttpClient http2 = TestTls.httpClientBuilder().version(HttpClient.Version.HTTP_2).build();
			AuthorizationServerMetadata metadata = AuthorizationServerMetadata.withIssuer(server.uri("").toString())
					.authorizationEndpoint(server.uri("/authorize"))
					.tokenEndpoint(server.uri("/token"))
					.build();
			OAuthClient client = OAuthClient.withAuthorizationServerMetadata(metadata).clientId("service")
					.clientAuthentication(ClientAuthentication.fromClientSecretBasic("secret"))
					.httpClient(http2).allowInsecureLoopback(true)
					.requestTimeout(Duration.ofSeconds(10)).totalDeadline(Duration.ofSeconds(15)).build();
			assertEquals(OAuthException.Reason.TOO_LARGE,
					assertThrows(OAuthResponseException.class, () -> client.requestClientCredentialsToken(
							TokenRequestOptions.builder().build())).getReason());
			assertEquals(OAuthException.Reason.TOO_LARGE,
					assertThrows(OAuthResponseException.class, () -> client.requestClientCredentialsToken(
							TokenRequestOptions.builder().build())).getReason());
			assertTrue(server.awaitNoOpenStreams(Duration.ofSeconds(5)));
			assertEquals(0, server.getOpenStreamCount());
			System.out.println("h2-bounded-body: jdk=" + Runtime.version().feature()
					+ " resets=" + server.getResetCount() + " connections=" + server.getConnectionCount()
					+ " openStreams=" + server.getOpenStreamCount());
		}
	}

	@Test
	void stalledHttp2BodyTimesOutClosesStreamAndLeavesConnectionUsable() throws Exception {
		try (OAuthHttp2Server server = OAuthHttp2Server.startWithStalledFirstBody()) {
			HttpClient http2 = TestTls.httpClientBuilder().version(HttpClient.Version.HTTP_2).build();
			AuthorizationServerMetadata metadata = AuthorizationServerMetadata.withIssuer(server.uri("").toString())
					.authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token")).build();
			OAuthClient client = OAuthClient.withAuthorizationServerMetadata(metadata).clientId("service")
					.clientAuthentication(ClientAuthentication.fromClientSecretBasic("secret"))
					.httpClient(http2).allowInsecureLoopback(true)
					.requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(2)).build();
			long started = System.nanoTime();
			assertEquals(OAuthException.Reason.NETWORK_FAILURE,
					assertThrows(OAuthTransportException.class, () -> client.requestClientCredentialsToken(
							TokenRequestOptions.builder().build())).getReason());
			assertTrue(System.nanoTime() - started < Duration.ofSeconds(5).toNanos());
			assertEquals("ok", client.requestClientCredentialsToken(TokenRequestOptions.builder().build())
					.getAccessToken().getValue());
			assertTrue(server.awaitNoOpenStreams(Duration.ofSeconds(5)));
			assertEquals(0, server.getOpenStreamCount());
			assertEquals(2, server.getRequestCount());
			System.out.println("h2-stalled-body: jdk=" + Runtime.version().feature()
					+ " resets=" + server.getResetCount() + " connections=" + server.getConnectionCount()
					+ " openStreams=" + server.getOpenStreamCount());
		}
	}
}
