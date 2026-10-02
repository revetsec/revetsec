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

import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.oidc.OidcClient;
import com.revetsec.oidc.OidcProviderMetadata;
import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestTls;
import org.junit.jupiter.api.Test;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class OAuthBuilderConventionTests {
	private static final URI RESOURCE = URI.create("https://api.example/default");
	private static final URI CALLBACK = URI.create("https://app.example/callback");

	@Test
	void authorizationNullResetsInheritanceWhileExplicitEmptyClearsOverrides() throws Exception {
		OAuthClient client = builder(metadata("https://issuer.example")).scopes(Set.of("client-scope"))
				.resources(List.of(RESOURCE)).redirectUri(CALLBACK).build();
		AuthorizationRequestOptions reset = AuthorizationRequestOptions.builder().scopes(Set.of("other"))
				.scopes(null).resources(List.of(URI.create("https://api.example/other"))).resources(null)
				.responseMode(AuthorizationRequestOptions.ResponseMode.FORM_POST).responseMode(null)
				.applicationData(Map.of("returnTo", "/account")).applicationData(null)
				.additionalParameters(Map.of("extension", "override")).additionalParameters(null).build();
		AuthorizationRedirect redirect = client.beginAuthorization(reset);
		QueryParameters inherited = QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery());
		assertEquals(List.of("client-scope"), inherited.getValues("scope"));
		assertEquals(List.of(RESOURCE.toString()), inherited.getValues("resource"));
		assertEquals(List.of(), inherited.getValues("response_mode"));
		assertEquals(List.of(), inherited.getValues("extension"));
		assertEquals(Map.of(), redirect.getPendingAuthorization().getApplicationData());
		QueryParameters empty = QueryParameters.parse(client.beginAuthorization(AuthorizationRequestOptions.builder()
				.scopes(Set.of()).resources(List.of()).build()).getAuthorizationUri().getRawQuery());
		assertEquals(List.of(), empty.getValues("scope"));
		assertEquals(List.of(), empty.getValues("resource"));
		QueryParameters defaultsCleared = QueryParameters.parse(builder(metadata("https://issuer.example"))
				.scopes(Set.of("old")).scopes(null).resources(List.of(RESOURCE)).resources(null)
				.redirectUri(CALLBACK).build().beginAuthorization().getAuthorizationUri().getRawQuery());
		assertEquals(List.of(), defaultsCleared.getValues("scope"));
		assertEquals(List.of(), defaultsCleared.getValues("resource"));
	}

	@Test
	void tokenAndCachedSourceResetsPreserveGrantAndResourceRequestSemantics() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", TestHttpsServer.Script.fromResponse(token("received", 300)));
			OAuthClient client = builder(metadata(server.getBaseUri().toString())).httpClient(TestTls.httpClient())
					.scopes(Set.of("client-scope")).resources(List.of(RESOURCE)).build();
			TokenRequestOptions reset = TokenRequestOptions.builder().scopes(Set.of("other")).scopes(null)
					.resources(List.of(URI.create("https://api.example/other"))).resources(null)
					.additionalParameters(Map.of("extension", "old")).additionalParameters(null).build();
			assertEquals("received", client.requestClientCredentialsToken(reset).getAccessToken().getValue());
			assertEquals("received", client.requestClientCredentialsToken(TokenRequestOptions.builder()
					.scopes(Set.of()).resources(List.of()).build()).getAccessToken().getValue());
			assertEquals("received", ClientCredentialsTokenSource.withClient(client).scopes(Set.of("other"))
					.scopes(null).resources(List.of()).resources(null).build().getAccessToken().getValue());
			assertEquals("received", ClientCredentialsTokenSource.withClient(client).scopes(Set.of())
					.resources(List.of()).build().getAccessToken().getValue());
			assertEquals("received", client.refresh(RefreshToken.fromValue("refresh"), reset)
					.getAccessToken().getValue());
			for (int index : List.of(0, 2)) {
				QueryParameters form = QueryParameters.parse(server.getRequests("/token").get(index).getBodyAsString());
				assertEquals(List.of("client-scope"), form.getValues("scope"));
				assertEquals(List.of(RESOURCE.toString()), form.getValues("resource"));
				assertEquals(List.of(), form.getValues("extension"));
			}
			for (int index : List.of(1, 3)) {
				QueryParameters form = QueryParameters.parse(server.getRequests("/token").get(index).getBodyAsString());
				assertEquals(List.of(), form.getValues("scope"));
				assertEquals(List.of(), form.getValues("resource"));
			}
			QueryParameters refresh = QueryParameters.parse(server.getRequests("/token").get(4).getBodyAsString());
			assertEquals(List.of("refresh_token"), refresh.getValues("grant_type"));
			assertEquals(List.of(), refresh.getValues("scope"));
			assertEquals(List.of(), refresh.getValues("resource"));
		}
	}

	@Test
	void cacheDurationResetsRestoreFallbackRenewalAndMaximumBounds() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", TestHttpsServer.Script.fromSequence(List.of(token("first", null), token("renewed", null), token("long", 200000))));
			TestClock clock = TestClock.fromInstant(Instant.parse("2026-09-30T12:00:00Z"));
			OAuthClient client = builder(metadata(server.getBaseUri().toString())).httpClient(TestTls.httpClient()).clock(clock).build();
			ClientCredentialsTokenSource source = ClientCredentialsTokenSource.withClient(client)
					.fallbackCacheDuration(Duration.ofSeconds(10)).fallbackCacheDuration(null)
					.maximumCacheDuration(Duration.ofMinutes(1)).maximumCacheDuration(null)
					.renewBefore(Duration.ZERO).renewBefore(null).build();
			AccessToken first = source.getAccessToken();
			clock.advance(Duration.ofSeconds(239));
			assertSame(first, source.getAccessToken());
			clock.advance(Duration.ofSeconds(1));
			assertEquals("renewed", source.getAccessToken().getValue());
			ClientCredentialsTokenSource capped = ClientCredentialsTokenSource.withClient(client)
					.maximumCacheDuration(Duration.ofMinutes(1)).maximumCacheDuration(null).build();
			AccessToken longToken = capped.getAccessToken();
			clock.advance(Duration.ofMinutes(2));
			assertSame(longToken, capped.getAccessToken());
			assertEquals(3, server.getHitCount("/token"));
			assertThrows(IllegalArgumentException.class, () -> ClientCredentialsTokenSource.withClient(client)
					.maximumCacheDuration(Duration.ofMinutes(1)).fallbackCacheDuration(null).build());
		}
	}

	@Test
	void pendingStoreResetsRemainBoundedAndRestoreSystemClock() {
		Instant now = Instant.parse("2026-09-30T12:00:00Z");
		TestClock clock = TestClock.fromInstant(now);
		InMemoryPendingAuthorizationStore store = InMemoryPendingAuthorizationStore.builder()
				.maximumLiveEntries(16).maximumLiveEntries(null).maximumChargedBytes(65536L).maximumChargedBytes(null)
				.maximumOpaqueRecordBytes(1024).maximumOpaqueRecordBytes(null).clock(clock).build();
		for (int index = 0; index < 1024; index++) store.save("binding", "state-" + index, "x".repeat(2000), now.plusSeconds(60));
		assertThrows(PendingAuthorizationStoreException.class, () -> store.save("binding", "overflow", "x", now.plusSeconds(60)));
		assertThrows(IllegalArgumentException.class, () -> store.save("binding", "too-large", "x".repeat(8193), now.plusSeconds(60)));
		clock.advance(Duration.ofSeconds(60));
		assertTrue(store.consume("binding", "state-0").isEmpty());
		store.save("binding", "fresh", "x", now.plusSeconds(120));
		assertEquals("x", store.consume("binding", "fresh").orElseThrow());
		InMemoryPendingAuthorizationStore byteBound = InMemoryPendingAuthorizationStore.builder()
				.maximumChargedBytes(65536L).maximumChargedBytes(null).clock(clock).build();
		for (int index = 0; index < 511; index++) byteBound.save("binding", "bytes-" + index, "x".repeat(8192), now.plusSeconds(120));
		assertThrows(PendingAuthorizationStoreException.class, () -> byteBound.save("binding", "bytes-511", "x".repeat(8192), now.plusSeconds(120)));
		InMemoryPendingAuthorizationStore system = InMemoryPendingAuthorizationStore.builder()
				.clock(Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)).clock(null).build();
		assertThrows(IllegalArgumentException.class, () -> system.save("binding", "expired", "x", Instant.now().minusSeconds(1)));
	}

	@Test
	void clientSecurityAndTimingResetsRestoreDefaultsWithoutIo() throws Exception {
		AtomicInteger observed = new AtomicInteger();
		OAuthObserver observer = new OAuthObserver() {
			@Override public void didBeginAuthorization(@NonNull URI endpoint) { observed.incrementAndGet(); }
		};
		OAuthClient client = builder(metadata("https://issuer.example"))
				.redirectUri(CALLBACK).observer(observer).observer(null)
				.requirePkceAdvertised(true).requirePkceAdvertised(null)
				.issuerParameterPolicy(IssuerParameterPolicy.REQUIRED).issuerParameterPolicy(null)
				.pendingAuthorizationLifetime(Duration.ofMinutes(1)).pendingAuthorizationLifetime(null)
				.requestTimeout(Duration.ofMinutes(1)).requestTimeout(null).totalDeadline(Duration.ofSeconds(1)).totalDeadline(null)
				.minimumTimeToLive(Duration.ofHours(1)).minimumTimeToLive(null)
				.defaultTimeToLive(Duration.ofHours(1)).defaultTimeToLive(null)
				.maximumTimeToLive(Duration.ofMinutes(1)).maximumTimeToLive(null)
				.discoveryCooldown(Duration.ofMinutes(1)).discoveryCooldown(null)
				.clock(Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)).clock(null).build();
		Instant before = Instant.now();
		PendingAuthorization pending = client.beginAuthorization().getPendingAuthorization();
		assertFalse(pending.getCreatedAt().isBefore(before));
		assertEquals(Duration.ofMinutes(15), Duration.between(pending.getCreatedAt(), pending.getExpiresAt()));
		assertFalse(pending.issuerRequired());
		assertEquals(0, observed.get());
		assertThrows(IllegalArgumentException.class, () -> builder(metadata("http://127.0.0.1:18080"))
				.allowInsecureLoopback(true).allowInsecureLoopback(null).build());
		assertEquals("10.0.0.1", builder(metadata("https://10.0.0.1"))
				.outboundUriPolicy(OutboundUriPolicy.publicAddressesOnlyInstance()).outboundUriPolicy(null)
				.redirectUri(CALLBACK).build().beginAuthorization().getAuthorizationUri().getHost());
	}

	@Test
	void requiredResetsAndInvalidValuesUseDistinctLocalFailures() {
		assertThrows(IllegalStateException.class, () -> OAuthClient.withIssuer("https://issuer.example").build());
		assertThrows(IllegalStateException.class, () -> builder(metadata("https://issuer.example")).clientId(null).build());
		assertThrows(IllegalStateException.class, () -> builder(metadata("https://issuer.example")).clientAuthentication(null).build());
		assertThrows(IllegalArgumentException.class, () -> builder(metadata("https://issuer.example")).clientId(""));
		assertThrows(IllegalStateException.class, () -> AuthorizationServerMetadata.withIssuer("https://issuer.example").build());
		assertThrows(IllegalStateException.class, () -> OidcClient.withIssuer("https://issuer.example").clientId("client").build());
		assertThrows(IllegalArgumentException.class, () -> OidcClient.withIssuer("https://issuer.example").clientId("").redirectUri(CALLBACK).build());
		assertThrows(IllegalStateException.class, () -> OidcProviderMetadata.withIssuer("https://issuer.example").build());
		assertThrows(IllegalStateException.class, () -> OidcProviderMetadata.withIssuer("https://issuer.example").jwksUri(URI.create("https://issuer.example/keys")).build());
		AuthorizationServerMetadata reset = AuthorizationServerMetadata.withIssuer("https://issuer.example")
				.authorizationEndpoint(URI.create("https://issuer.example/auth")).tokenEndpoint(URI.create("https://issuer.example/token"))
				.authorizationResponseIssuerSupported(true).authorizationResponseIssuerSupported(null).build();
		assertEquals(Boolean.FALSE, reset.isAuthorizationResponseIssuerSupported());
		assertEquals(Boolean.FALSE, reset.isRemotelyDiscovered());
		assertEquals(OAuthException.Reason.DOCUMENT_MALFORMED, assertThrows(OAuthResponseException.class,
				() -> AuthorizationServerMetadata.fromJson("https://issuer.example", "{\"issuer\":\"https://issuer.example\"}")).getReason());
	}

	private static @NonNull AuthorizationServerMetadata metadata(@NonNull String issuer) {
		return AuthorizationServerMetadata.withIssuer(issuer).authorizationEndpoint(URI.create(issuer + "/auth"))
				.tokenEndpoint(URI.create(issuer + "/token")).build();
	}

	private static OAuthClient.@NonNull Builder builder(@NonNull AuthorizationServerMetadata metadata) {
		return OAuthClient.withAuthorizationServerMetadata(metadata).clientId("client").clientAuthentication(ClientAuthentication.fromClientSecretBasic("test-secret"));
	}

	private static TestHttpsServer.@NonNull Response token(@NonNull String value, @Nullable Integer expiry) {
		return TestHttpsServer.Response.withStatus(200).header("Content-Type", "application/json")
				.body("{\"access_token\":\"" + value + "\",\"token_type\":\"Bearer\"" + (expiry == null ? "" : ",\"expires_in\":" + expiry) + "}").build();
	}
}
