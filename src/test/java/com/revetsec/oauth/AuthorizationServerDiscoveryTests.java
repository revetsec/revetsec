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

import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.FormUrlEncoding;
import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.testing.RewindableClock;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestSealers;
import com.revetsec.testing.TestTls;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class AuthorizationServerDiscoveryTests {
	private static final String RFC_PATH = "/.well-known/oauth-authorization-server/tenant";
	private static final String OIDC_INSERTED = "/.well-known/openid-configuration/tenant";
	private static final String OIDC_APPENDED = "/tenant/.well-known/openid-configuration";
	private static final URI CALLBACK = URI.create("https://app.example/callback");

	@Test
	void trailingIssuerSlashIsRemovedOnlyForInsertedWellKnownPaths() {
		assertEquals(List.of(
				URI.create("https://issuer.example/.well-known/oauth-authorization-server/tenant"),
				URI.create("https://issuer.example/.well-known/openid-configuration/tenant"),
				URI.create("https://issuer.example/tenant/.well-known/openid-configuration")),
				AuthorizationServerCache.candidates(URI.create("https://issuer.example/tenant/")));
	}

	@Test
	void pathIssuerUsesMcpOrderAndCachesSuccessfulDocument() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			String issuer = server.uri("/tenant").toString();
			server.script(OIDC_INSERTED, TestHttpsServer.Script.fromResponse(
					TestHttpsServer.Response.fromStatus(405)));
			server.script(OIDC_APPENDED, TestHttpsServer.Script.fromResponse(json(200, metadata(server, issuer,
					server.uri("/token-a")))));
			OAuthClient client = OAuthClient.withIssuer(issuer).clientId("client")
					.clientAuthentication(ClientAuthentication.noneInstance()).redirectUri(CALLBACK)
					.httpClient(TestTls.httpClient()).build();
			assertTrue(server.getRequests().isEmpty());
			client.warmUp();
			client.warmUp();
			assertEquals(1, server.getHitCount(RFC_PATH));
			assertEquals(1, server.getHitCount(OIDC_INSERTED));
			assertEquals(1, server.getHitCount(OIDC_APPENDED));
		}
	}

	@Test
	void discoveryStopsAfterTwoFreshnessDrivenFlightsInOneCooldownWindow() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			String issuer = server.uri("/tenant").toString();
			server.script(RFC_PATH, TestHttpsServer.Script.fromResponse(json(200,
					metadata(server, issuer, server.uri("/token")))));
			RewindableClock clock = RewindableClock.fromInstant(Instant.parse("2026-09-28T12:00:00Z"));
			OAuthClient client = OAuthClient.withIssuer(issuer).clientId("client")
					.clientAuthentication(ClientAuthentication.noneInstance())
					.httpClient(TestTls.httpClient()).clock(clock)
					.minimumTimeToLive(Duration.ofSeconds(30)).defaultTimeToLive(Duration.ofSeconds(30))
					.maximumTimeToLive(Duration.ofMinutes(1)).discoveryCooldown(Duration.ofSeconds(10)).build();
			client.warmUp();
			clock.advance(Duration.ofSeconds(31));
			client.warmUp();
			clock.advance(Duration.ofSeconds(31));
			assertEquals(OAuthException.Reason.ATTEMPT_LIMIT,
					assertThrows(OAuthTransportException.class, client::warmUp).getReason());
			assertEquals(2, server.getHitCount(RFC_PATH));
		}
	}

	@Test
	void failedDiscoveryIsBackedOffWithoutAnotherAuthorizationServerRequest() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			String issuer = server.uri("/tenant").toString();
			server.script(RFC_PATH, TestHttpsServer.Script.fromResponse(json(503,
					"{\"error\":\"temporarily_unavailable\"}")));
			OAuthClient client = OAuthClient.withIssuer(issuer).clientId("client")
					.clientAuthentication(ClientAuthentication.noneInstance())
					.httpClient(TestTls.httpClient()).discoveryCooldown(Duration.ofSeconds(10)).build();
			for (int attempt = 0; attempt < 2; attempt++)
				assertEquals(503, assertThrows(OAuthErrorResponseException.class, client::warmUp).getStatus());
			assertEquals(1, server.getHitCount(RFC_PATH));
		}
	}

	@Test
	void invalidSuccessfulDocumentTerminatesFallback() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			String issuer = server.uri("/tenant").toString();
			server.script(RFC_PATH, TestHttpsServer.Script.fromResponse(json(200,
					metadata(server, "https://other.example", server.uri("/token")))));
			server.script(OIDC_INSERTED, TestHttpsServer.Script.fromResponse(json(200,
					metadata(server, issuer, server.uri("/token")))));
			OAuthClient client = OAuthClient.withIssuer(issuer).clientId("client")
					.clientAuthentication(ClientAuthentication.noneInstance()).httpClient(TestTls.httpClient()).build();
			assertEquals(OAuthException.Reason.ISSUER_MISMATCH,
					assertThrows(OAuthValidationException.class, client::warmUp).getReason());
			assertEquals(1, server.getHitCount(RFC_PATH));
			assertEquals(0, server.getHitCount(OIDC_INSERTED));
		}
	}

	@Test
	void metadataRedirectIsNeverFollowedOrTreatedAsFallback() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			String issuer = server.uri("/tenant").toString();
			server.script(RFC_PATH, TestHttpsServer.Script.fromRedirect(302, server.uri("/target").toString()));
			server.script("/target", TestHttpsServer.Script.fromResponse(json(200,
					metadata(server, issuer, server.uri("/token")))));
			OAuthClient client = OAuthClient.withIssuer(issuer).clientId("client")
					.clientAuthentication(ClientAuthentication.noneInstance())
					.httpClient(TestTls.httpClient()).build();
			assertEquals(OAuthException.Reason.REDIRECT_NOT_FOLLOWED,
					assertThrows(OAuthResponseException.class, client::warmUp).getReason());
			assertEquals(1, server.getHitCount(RFC_PATH));
			assertEquals(0, server.getHitCount("/target"));
			assertEquals(0, server.getHitCount(OIDC_INSERTED));
		}
	}

	@Test
	void changedTokenEndpointAfterBeginFailsBeforeCodePost() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			String issuer = server.uri("/tenant").toString();
			RewindableClock clock = RewindableClock.fromInstant(Instant.parse("2026-09-28T12:00:00Z"));
			server.script(RFC_PATH, TestHttpsServer.Script.fromResponse(json(200,
					metadata(server, issuer, server.uri("/token-a")))));
			OAuthClient client = OAuthClient.withIssuer(issuer).clientId("client")
					.clientAuthentication(ClientAuthentication.noneInstance()).redirectUri(CALLBACK)
					.httpClient(TestTls.httpClient()).clock(clock)
					.minimumTimeToLive(Duration.ofSeconds(30)).defaultTimeToLive(Duration.ofSeconds(30))
					.maximumTimeToLive(Duration.ofMinutes(1)).discoveryCooldown(Duration.ofSeconds(1)).build();
			AuthorizationRedirect redirect = client.beginAuthorization();
			StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("discovery"))
					.clock(clock).build();
			String sealed = redirect.getPendingAuthorization().toSealedForm(sealer, "provider");
			String state = QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()).getValues("state").get(0);
			clock.advance(Duration.ofSeconds(31));
			server.script(RFC_PATH, TestHttpsServer.Script.fromResponse(json(200,
					metadata(server, issuer, server.uri("/token-b")))));
			assertEquals(OAuthException.Reason.METADATA_ENDPOINT_DRIFT,
					assertThrows(OAuthValidationException.class, () -> client.completeAuthorization(
							AuthorizationResponse.fromQueryString("state=" + state + "&code=secret-code"),
							PendingAuthorizationSource.fromSealedForm(sealed, sealer, "provider"), CALLBACK))
							.getReason());
			assertEquals(0, server.getHitCount("/token-a"));
			assertEquals(0, server.getHitCount("/token-b"));
			assertEquals(2, server.getHitCount(RFC_PATH));
		}
	}

	@Test
	void freshClientRejectsMissingAdvertisedIssuerBeforeAnyDiscoveryRequest() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			AuthorizationServerMetadata google;
			try (InputStream input = AuthorizationServerDiscoveryTests.class.getResourceAsStream(
					"/fixtures/google/2026-09-28/openid-configuration.json")) {
				google = AuthorizationServerMetadata.fromJson("https://accounts.google.com",
						new String(java.util.Objects.requireNonNull(input).readAllBytes(), StandardCharsets.UTF_8));
			}
			assertTrue(google.isAuthorizationResponseIssuerSupported());
			String issuer = server.uri("/tenant").toString();
			String document = metadata(server, issuer, server.uri("/token"));
			document = document.substring(0, document.length() - 1)
					+ ",\"authorization_response_iss_parameter_supported\":"
					+ google.isAuthorizationResponseIssuerSupported() + "}";
			server.script(RFC_PATH, TestHttpsServer.Script.fromResponse(json(200, document)));
			RewindableClock clock = RewindableClock.fromInstant(Instant.parse("2026-09-28T12:00:00Z"));
			OAuthClient first = OAuthClient.withIssuer(issuer).clientId("client")
					.clientAuthentication(ClientAuthentication.noneInstance()).redirectUri(CALLBACK)
					.httpClient(TestTls.httpClient()).clock(clock)
					.minimumTimeToLive(Duration.ofSeconds(30)).defaultTimeToLive(Duration.ofSeconds(30))
					.maximumTimeToLive(Duration.ofMinutes(1)).discoveryCooldown(Duration.ofSeconds(1)).build();
			PendingAuthorization pending = first.beginAuthorization().getPendingAuthorization();
			StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("google-iss"))
					.clock(clock).build();
			String sealed = pending.toSealedForm(sealer, "provider");
			clock.advance(Duration.ofSeconds(31));
			OAuthClient fresh = OAuthClient.withIssuer(issuer).clientId("client")
					.clientAuthentication(ClientAuthentication.noneInstance()).redirectUri(CALLBACK)
					.httpClient(TestTls.httpClient()).clock(clock).build();
			int before = server.getRequests().size();
			assertEquals(OAuthException.Reason.ISSUER_MISSING,
					assertThrows(OAuthValidationException.class, () -> fresh.completeAuthorization(
							AuthorizationResponse.fromQueryString("state=" + pending.state() + "&code=code"),
							PendingAuthorizationSource.fromSealedForm(sealed, sealer, "provider"), CALLBACK))
							.getReason());
			assertEquals(before, server.getRequests().size());
			assertEquals(0, server.getHitCount("/token"));
		}
	}

	private static @NonNull String metadata(@NonNull TestHttpsServer server, @NonNull String issuer, @NonNull URI tokenEndpoint) {
		return "{\"issuer\":\"" + issuer + "\",\"authorization_endpoint\":\""
				+ server.uri("/authorize") + "\",\"token_endpoint\":\"" + tokenEndpoint + "\"}";
	}

	private static TestHttpsServer.@NonNull Response json(int status, @NonNull String body) {
		return TestHttpsServer.Response.withStatus(status).header("Content-Type", "application/json")
				.body(body).build();
	}
    @Test void discoveredUnsafeOptionalResourceEndpointsBlockBrowserClientWarmUp() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            String issuer=server.uri("/tenant").toString();
            for(String field:new String[]{"jwks_uri","introspection_endpoint"}) {
                String base=metadata(server,issuer,server.uri("/token"));
                server.script(RFC_PATH,TestHttpsServer.Script.fromResponse(json(200,base.substring(0,base.length()-1)+",\""+field+"\":\"http://10.0.0.1/private\"}")));
                OAuthClient client=OAuthClient.withIssuer(issuer).clientId("client").clientAuthentication(ClientAuthentication.noneInstance()).httpClient(TestTls.httpClient()).build();
                assertEquals(OAuthException.Reason.METADATA_INVALID,assertThrows(OAuthValidationException.class,client::warmUp).getReason());
                assertEquals(0,server.getHitCount("/token"));
            }
            assertEquals(2,server.getHitCount(RFC_PATH));
        }
    }

}
