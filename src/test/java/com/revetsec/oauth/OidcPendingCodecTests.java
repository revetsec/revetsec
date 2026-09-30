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

import com.revetsec.oidc.*;
import com.revetsec.internal.oauth.OidcTransactionAccess;
import com.revetsec.jose.*;
import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.testing.*;
import org.junit.jupiter.api.Test;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.net.URI;
import java.time.*;
import java.util.*;
import java.util.stream.Stream;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

final class OidcPendingCodecTests {
	private static final Instant NOW = Instant.parse("2026-09-29T12:00:00Z");
	private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
	private static final URI CALLBACK = URI.create("https://rp.example/callback");
	@Test
	void v1OauthStillRoundTripsAndV2AuthenticatesOidcOptions() {
		AuthorizationServerMetadata metadata = AuthorizationServerMetadata.withIssuer("https://op.example")
				.authorizationEndpoint(URI.create("https://op.example/authorize")).tokenEndpoint(URI.create("https://op.example/token")).build();
		PendingAuthorization oauth = OAuthClient.withAuthorizationServerMetadata(metadata).clientId("client")
				.clientAuthentication(ClientAuthentication.noneInstance()).redirectUri(CALLBACK).clock(CLOCK).build().beginAuthorization().getPendingAuthorization();
		String v1 = PendingAuthorizationCodec.encode(oauth, null); assertTrue(v1.contains("\"v\":1"));
		assertEquals("oauth", PendingAuthorizationCodec.decode(v1).pending().kind());
		PendingAuthorization oidc = oidcClient().beginAuthentication(OidcAuthenticationOptions.builder().maxAge(Duration.ZERO)
				.requiredAcrValues(Set.of("urn:mfa")).prompt("login").applicationData(Map.of("app", "sentinel")).build()).getPendingAuthorization();
		String v2 = PendingAuthorizationCodec.encode(oidc, "digest"); assertTrue(v2.contains("\"v\":2"));
		PendingAuthorizationCodec.Decoded decoded = PendingAuthorizationCodec.decode(v2);
		assertEquals("digest", decoded.bindingDigest()); assertEquals("oidc", decoded.pending().kind());
		assertEquals(oidc.nonce(), decoded.pending().nonce()); assertEquals(Duration.ZERO, decoded.pending().maxAge());
		assertEquals(Set.of("urn:mfa"), decoded.pending().acrValues()); assertEquals("login", decoded.pending().prompt());
		assertEquals(Map.of("app", "sentinel"), decoded.pending().getApplicationData());
	}
	@TestFactory
	Stream<DynamicTest> malformedAuthenticatedOidcRecordsFailBeforeAnyProviderRequest() {
		return Stream.of("legacy version", "missing nonce", "empty nonce", "negative age", "fractional age", "string age", "missing acr", "duplicate acr", "invalid acr", "wrong acr type", "bad prompt", "non-openid scope")
				.map(name -> DynamicTest.dynamicTest(name, () -> {
					OidcClient client = oidcClient(); PendingAuthorization pending = client.beginAuthentication(OidcAuthenticationOptions.builder().maxAge(Duration.ZERO).requiredAcrValues(Set.of("urn:mfa")).prompt("login").build()).getPendingAuthorization();
					String encoded = PendingAuthorizationCodec.encode(pending, PendingAuthorizationCodec.bindingDigest("browser"));
					String altered = switch (name) {
						case "legacy version" -> encoded.replace("\"v\":2", "\"v\":1");
						case "missing nonce" -> encoded.replace("\"nonce\":", "\"removed_nonce\":");
						case "empty nonce" -> encoded.replace(pending.nonce(), "");
						case "negative age" -> encoded.replace("\"max_age\":0", "\"max_age\":-1");
						case "fractional age" -> encoded.replace("\"max_age\":0", "\"max_age\":0.5");
						case "string age" -> encoded.replace("\"max_age\":0", "\"max_age\":\"0\"");
						case "missing acr" -> encoded.replace("\"acr_values\":", "\"removed_acr\":");
						case "duplicate acr" -> encoded.replace("[\"urn:mfa\"]", "[\"urn:mfa\",\"urn:mfa\"]");
						case "invalid acr" -> encoded.replace("[\"urn:mfa\"]", "[\"has space\"]");
						case "wrong acr type" -> encoded.replace("[\"urn:mfa\"]", "false");
						case "bad prompt" -> encoded.replace("\"prompt\":\"login\"", "\"prompt\":\"none login\"");
						default -> encoded.replace("[\"openid\"]", "[\"email\"]");
					};
					assertNotEquals(encoded, altered); AtomicReference<String> saved = new AtomicReference<>(altered);
					PendingAuthorizationStore store = new PendingAuthorizationStore() {
						@Override public void save(String binding, String state, String record, Instant expiry) { saved.set(record); }
						@Override public Optional<String> consume(String binding, String state) { return Optional.ofNullable(saved.getAndSet(null)); }
					};
					assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_INVALID, assertThrows(OAuthValidationException.class,
							() -> client.completeAuthentication(AuthorizationResponse.fromQueryString("state=" + pending.state() + "&code=sentinel-code"), PendingAuthorizationSource.fromStore(store, "browser"), CALLBACK)).getReason());
				}));
	}
	@Test
	void noPublicBridgeInstallationOrDoubleReleaseIsAllowed() {
		OidcTransactionAccess.Operations installed = OidcTransactionAccess.get();
		assertThrows(IllegalStateException.class, () -> OidcTransactionAccess.set(installed));
		OidcTransactionAccess.Operations impostor = new OidcTransactionAccess.Operations() {
			@Override public void checkHmacAuthentication(ClientAuthentication a, Set<com.revetsec.jose.JwsAlgorithm> b) { throw new AssertionError(); }
			@Override public OAuthException endpointFailure(OAuthException.Reason reason) { throw new AssertionError(); }
			@Override public OAuthException endpointExchangeFailure(com.revetsec.internal.http.HttpExchangeException failure) { throw new AssertionError(); }
			@Override public OAuthException endpointStatusFailure(int status, @Nullable Duration retryAfter) { throw new AssertionError(); }
			@Override public OidcTransactionAccess.RefreshCompletion refresh(OAuthClient client, RefreshToken token, TokenRequestOptions options, AuthorizationServerMetadata metadata, com.revetsec.internal.http.Deadline deadline, Set<com.revetsec.jose.JwsAlgorithm> hmac) { throw new AssertionError(); }

			@Override public AuthorizationRedirect begin(OAuthClient client, AuthorizationRequestOptions options, AuthorizationServerMetadata metadata, @Nullable Duration maxAge, Set<String> acr) { throw new AssertionError(); }
			@Override public OidcTransactionAccess.Completion complete(OAuthClient client, AuthorizationResponse response, PendingAuthorizationSource source, URI callback, java.util.function.Function<com.revetsec.internal.http.Deadline, AuthorizationServerMetadata> metadata, com.revetsec.internal.http.Deadline deadline, Set<com.revetsec.jose.JwsAlgorithm> hmac) { throw new AssertionError(); }
		};
		assertThrows(IllegalArgumentException.class, () -> OidcTransactionAccess.set(impostor));
		TokenEndpointPayload payload = new TokenEndpointPayload("sentinel-access", "Bearer", null, null, "sentinel-id", true, null, Set.of(), NOW, com.revetsec.json.JsonObject.fromMembers(Map.of()));
		OidcTransactionAccess.Completion completion = new OidcTransactionAccess.Completion(payload.idToken(), payload.accessToken(), payload.tokenType(), "sentinel-code", "sentinel-nonce", null, Set.of(), payload::toTokenResponse);
		assertFalse(completion.toString().contains("sentinel")); assertEquals("sentinel-access", completion.releaseTokens().getAccessToken().getValue());
		assertThrows(IllegalStateException.class, completion::releaseTokens);
		OidcTransactionAccess.RefreshCompletion refreshed = new OidcTransactionAccess.RefreshCompletion(payload.idToken(), true, payload.accessToken(), payload.tokenType(), payload::toTokenResponse);
		assertFalse(refreshed.toString().contains("sentinel")); assertTrue(refreshed.idTokenPresent());
		assertEquals("sentinel-access", refreshed.releaseTokens().getAccessToken().getValue());
		assertThrows(IllegalStateException.class, refreshed::releaseTokens);
		com.revetsec.internal.jose.JwtValidationAccess.Operations jwt = com.revetsec.internal.jose.JwtValidationAccess.get();
		assertThrows(IllegalStateException.class, () -> com.revetsec.internal.jose.JwtValidationAccess.set(jwt));
		assertThrows(IllegalArgumentException.class, () -> com.revetsec.internal.jose.JwtValidationAccess.set(new com.revetsec.internal.jose.JwtValidationAccess.Operations() {
			@Override public com.revetsec.jose.Jwt validate(com.revetsec.jose.JwtValidator v, String c, java.util.function.LongSupplier d) { throw new AssertionError(); }
			@Override public com.revetsec.jose.Jwt validateUserInfo(com.revetsec.jose.JwtValidator v, String c, java.util.function.LongSupplier d) { throw new AssertionError(); }
			@Override public com.revetsec.jose.Jwt validateOidc(com.revetsec.jose.JwtValidator v, String c, Set<com.revetsec.jose.JwsAlgorithm> a, byte[] s, java.util.function.LongSupplier d, Runnable u) { throw new AssertionError(); }
			@Override public void warmUp(com.revetsec.jose.RemoteJsonWebKeySource source, java.util.function.LongSupplier d) { throw new AssertionError(); }
		}));
	}
	private static OidcClient oidcClient() {
		return OidcClient.withProviderMetadata(OidcProviderMetadata.withIssuer("https://op.example")
				.authorizationEndpoint(URI.create("https://op.example/authorize")).tokenEndpoint(URI.create("https://op.example/token"))
				.jwksUri(URI.create("https://op.example/jwks")).build()).clientId("client").redirectUri(CALLBACK).clock(CLOCK).build();
	}
}
