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
	@NonNull Stream<@NonNull DynamicTest> malformedAuthenticatedOidcRecordsFailBeforeAnyProviderRequest() {
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
						@Override public void save(@NonNull String binding, @NonNull String state, @NonNull String record, @NonNull Instant expiry) { saved.set(record); }
						@Override public @NonNull Optional<@NonNull String> consume(@NonNull String binding, @NonNull String state) { return Optional.ofNullable(saved.getAndSet(null)); }
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
   @Override public @NonNull VerifiedAccessToken validateAccessToken(@NonNull JwtAccessTokenValidator validator,@NonNull BearerToken token,com.revetsec.internal.http.@NonNull Deadline deadline) {throw new AssertionError();}
   @Override public @NonNull String bearerValue(@NonNull BearerToken token) {throw new AssertionError();}
			@Override public void checkHmacAuthentication(@NonNull ClientAuthentication a, @NonNull Set<com.revetsec.jose.@NonNull JwsAlgorithm> b) { throw new AssertionError(); }
			@Override public @NonNull OAuthException endpointFailure(OAuthException.@NonNull Reason reason) { throw new AssertionError(); }
			@Override public @NonNull OAuthException endpointExchangeFailure(com.revetsec.internal.http.@NonNull HttpExchangeException failure) { throw new AssertionError(); }
			@Override public @NonNull OAuthException endpointStatusFailure(int status, @Nullable Duration retryAfter) { throw new AssertionError(); }
			@Override public OidcTransactionAccess.@NonNull RefreshCompletion refresh(@NonNull OAuthClient client, @NonNull RefreshToken token, @NonNull TokenRequestOptions options, @NonNull AuthorizationServerMetadata metadata, com.revetsec.internal.http.@NonNull Deadline deadline, @NonNull Set<com.revetsec.jose.@NonNull JwsAlgorithm> hmac) { throw new AssertionError(); }

			@Override public @NonNull AuthorizationRedirect begin(@NonNull OAuthClient client, @NonNull AuthorizationRequestOptions options, @NonNull AuthorizationServerMetadata metadata, @Nullable Duration maxAge, @NonNull Set<@NonNull String> acr) { throw new AssertionError(); }
			@Override public OidcTransactionAccess.@NonNull Completion complete(@NonNull OAuthClient client, @NonNull AuthorizationResponse response, @NonNull PendingAuthorizationSource source, @NonNull URI callback, java.util.function.@NonNull Function<com.revetsec.internal.http.@NonNull Deadline, @NonNull AuthorizationServerMetadata> metadata, com.revetsec.internal.http.@NonNull Deadline deadline, @NonNull Set<com.revetsec.jose.@NonNull JwsAlgorithm> hmac) { throw new AssertionError(); }
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
			@Override public com.revetsec.jose.@NonNull Jwt validate(com.revetsec.jose.@NonNull JwtValidator v, @NonNull String c, java.util.function.@NonNull LongSupplier d) { throw new AssertionError(); }
			@Override public com.revetsec.jose.@NonNull Jwt validatePrepared(com.revetsec.jose.@NonNull JwtValidator v, com.revetsec.internal.jose.@NonNull PreparedJws p, java.util.function.@NonNull LongSupplier d) { throw new AssertionError(); }
			@Override public com.revetsec.jose.@NonNull Jwt validateIssuerRevocation(com.revetsec.jose.@NonNull JwtValidator v, @NonNull String c, java.util.function.@NonNull LongSupplier d) { throw new AssertionError(); }
			@Override public com.revetsec.jose.@NonNull Jwt validateUserInfo(com.revetsec.jose.@NonNull JwtValidator v, @NonNull String c, java.util.function.@NonNull LongSupplier d) { throw new AssertionError(); }
			@Override public com.revetsec.jose.@NonNull Jwt validateOidc(com.revetsec.jose.@NonNull JwtValidator v, @NonNull String c, @NonNull Set<com.revetsec.jose.@NonNull JwsAlgorithm> a, byte @NonNull [] s, java.util.function.@NonNull LongSupplier d, @NonNull Runnable u) { throw new AssertionError(); }
			@Override public com.revetsec.jose.@NonNull Jwt validateMicrosoftEntra(com.revetsec.jose.@NonNull JwtValidator v, @NonNull String c, java.util.function.@NonNull LongSupplier d) { throw new AssertionError(); }
			@Override public com.revetsec.jose.@NonNull Jwt validateMicrosoftEntraUserInfo(com.revetsec.jose.@NonNull JwtValidator v, @NonNull String c, @NonNull String i, java.util.function.@NonNull LongSupplier d) { throw new AssertionError(); }
			@Override public void warmUp(com.revetsec.jose.@NonNull RemoteJsonWebKeySource source, java.util.function.@NonNull LongSupplier d) { throw new AssertionError(); }
		}));
	}
	private static @NonNull OidcClient oidcClient() {
		return OidcClient.withProviderMetadata(OidcProviderMetadata.withIssuer("https://op.example")
				.authorizationEndpoint(URI.create("https://op.example/authorize")).tokenEndpoint(URI.create("https://op.example/token"))
				.jwksUri(URI.create("https://op.example/jwks")).build()).clientId("client").redirectUri(CALLBACK).clock(CLOCK).build();
	}
}
