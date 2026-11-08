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

package com.revetsec.oidc;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.jose.Jwks;
import com.revetsec.jose.JwksParseResult;
import com.revetsec.jose.StaticJwksSource;
import com.revetsec.json.JsonObject;
import com.revetsec.oauth.AuthorizationRedirect;
import com.revetsec.oauth.AuthorizationResponse;
import com.revetsec.oauth.AuthorizationResponseParseResult;
import com.revetsec.oauth.PendingAuthorizationSource;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestJwk;
import com.revetsec.testing.TestJws;
import com.revetsec.testing.TestSealers;
import com.revetsec.testing.TestTls;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/** Genuine completed authentication/refresh fixture. No parse-only identity or reflective proof construction. */
final class OidcLogoutFixtures {
	static final Instant NOW = Instant.parse("2026-11-05T12:00:00Z");
	static final URI LOGIN = URI.create("https://rp.example/login/callback"), LOGOUT = URI.create("https://rp.example/logout/callback");
	private OidcLogoutFixtures() { }
	record Login(@NonNull OidcAuthentication authentication, @NonNull String nonce, @NonNull String compact) { }
	static @NonNull OidcProviderMetadata metadata(@NonNull TestHttpsServer server, @Nullable URI endpoint) {
		return OidcProviderMetadata.withIssuer(server.getBaseUri().toString()).authorizationEndpoint(server.uri("/authorize"))
				.tokenEndpoint(server.uri("/token")).jwksUri(server.uri("/jwks")).endSessionEndpoint(endpoint).build();
	}
	static OidcClient.@NonNull Builder builder(@NonNull TestHttpsServer server, @NonNull Clock clock) { return builder(server, clock, server.uri("/logout")); }
	static OidcClient.@NonNull Builder builder(@NonNull TestHttpsServer server, @NonNull Clock clock, @Nullable URI endpoint) {
		return configured(server, clock, endpoint);
	}
	static @NonNull StaticJwksSource keys(@Nullable String issuer) {
		String keys = TestJwk.withFixture(TestJwk.Fixture.IDP_SIGNING_RSA_2048).kid("key").alg("RS256").issuer(issuer).toKeySetJson();
		return StaticJwksSource.fromJwks(assertInstanceOf(JwksParseResult.Succeeded.class, Jwks.fromJsonResult(keys)).getJwks());
	}
	private static OidcClient.@NonNull Builder configured(@NonNull TestHttpsServer server, @NonNull Clock clock, @Nullable URI endpoint) {
		return OidcClient.withProviderMetadata(metadata(server, endpoint)).clientId("client").redirectUri(LOGIN)
				.postLogoutRedirectUri(LOGOUT).clock(clock).jwksSource(keys(null)).httpClient(TestTls.httpClient());
	}
	static @NonNull Login login(@NonNull TestHttpsServer server, @NonNull OidcClient client, @NonNull Clock clock) throws Exception { return login(server, client, clock, ""); }
	static @NonNull Login login(@NonNull TestHttpsServer server, @NonNull OidcClient client, @NonNull Clock clock, @NonNull String padding) throws Exception {
		return login(server, client, clock, (now, nonce) -> token(server, now, nonce, "TEST-ONLY-original-sid", padding));
	}
	static @NonNull Login login(@NonNull TestHttpsServer server, @NonNull OidcClient client, @NonNull Clock clock, java.util.function.@NonNull BiFunction<@NonNull Instant, @NonNull String, @NonNull String> tokens) throws Exception {
		AuthorizationRedirect redirect = client.beginAuthentication(); QueryParameters query = QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery());
		String nonce = query.getValues("nonce").get(0); String token = tokens.apply(clock.instant(), nonce);
		respond(server, token); StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("logout-login")).clock(clock).build();
		OidcAuthentication authentication = assertInstanceOf(OidcAuthenticationResult.Succeeded.class, client.completeAuthenticationResult(
				assertInstanceOf(AuthorizationResponseParseResult.Succeeded.class, AuthorizationResponse.fromQueryStringResult("state=" + query.getValues("state").get(0) + "&code=TEST-ONLY-code")).getResponse(),
				PendingAuthorizationSource.fromSealedForm(redirect.getPendingAuthorization().toSealedForm(sealer, "logout-login"), sealer, "logout-login"), LOGIN)).getAuthentication();
		return new Login(authentication, nonce, token);
	}
	static @NonNull String token(@NonNull TestHttpsServer server, @NonNull Instant now, @Nullable String nonce, @NonNull String sid, @NonNull String padding) {
		JsonObject.Builder claims = JsonObject.builder().put("iss", server.getBaseUri().toString()).put("sub", "TEST-ONLY-logout-subject")
				.put("aud", "client").put("iat", now.getEpochSecond()).put("exp", now.plusSeconds(300).getEpochSecond()).put("auth_time", NOW.getEpochSecond()).put("sid", sid);
		if (nonce != null) claims.put("nonce", nonce); if (!padding.isEmpty()) claims.put("padding", padding);
		return TestJws.withAlgorithm(TestJws.Algorithm.RS256).kid("key").payload(claims.build().toJson()).sign(TestJwk.Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());
	}
	static void respond(@NonNull TestHttpsServer server, @Nullable String token) {
		JsonObject.Builder response = JsonObject.builder().put("access_token", "TEST-ONLY-logout-access").put("token_type", "Bearer").put("refresh_token", "TEST-ONLY-logout-refresh");
		if (token != null) response.put("id_token", token);
		server.script("/token", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200, response.build().toJson())));
	}
	static final class MutableClock extends Clock {
		final AtomicReference<Instant> value = new AtomicReference<>(NOW);
		@Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
		@Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
		@Override public @NonNull Instant instant() { return java.util.Objects.requireNonNull(this.value.get()); }
		void set(@NonNull Instant value) { this.value.set(value); }
	}
}
