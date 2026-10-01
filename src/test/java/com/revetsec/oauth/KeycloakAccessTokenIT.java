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
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import java.net.URI;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Actual pinned Keycloak at+jwt opt-in, explicit untyped profile and JSON introspection. */
final class KeycloakAccessTokenIT {
	private static @Nullable ResourceProviderFixturesIT fixture;
	@BeforeAll static void start() throws Exception { fixture = ResourceProviderFixturesIT.fromKeycloak(); }
	@AfterAll static void stop() throws Exception { if (fixture != null) fixture.close(); }
	private static @NonNull ResourceProviderFixturesIT provider() { return requireNonNull(fixture); }
	private static @NonNull OAuthClient client(@NonNull String id, @Nullable OAuthObserver observer) {
		return provider().client(id, ResourceProviderFixturesIT.KEYCLOAK_SECRET, observer);
	}
	@Test void enabledAccessTokenHeaderAndClientIdMapperPassStrictCodeFlow() throws Exception {
		OAuthClient oauth = client("resource-strict", null); TokenResponse tokens = provider().codeFlow(oauth, false);
		AccessTokenValidationResult result = provider().validator().validateResult(ResourceProviderFixturesIT.bearer(tokens));
		if (result instanceof AccessTokenValidationResult.Rejected rejection)
			throw new AssertionError("Real Keycloak strict token rejected: " + rejection.getReason() + "/" + rejection.getJoseReason());
		VerifiedAccessToken proof = assertInstanceOf(AccessTokenValidationResult.Succeeded.class, result).getAccessToken();
		assertEquals(provider().issuer(), proof.getIssuer()); assertEquals("resource-strict", proof.getClientId().orElseThrow());
		assertTrue(proof.getScopes().contains("read")); assertFalse(proof.getScopes().contains("write"));
		assertTrue(proof.getSubject().isPresent()); assertTrue(proof.getAudiences().contains(ResourceProviderFixturesIT.RESOURCE));
	}
	@Test void enabledAccessTokenHeaderPassesStrictClientCredentials() {
		TokenResponse tokens = client("resource-strict", null).requestClientCredentialsToken(TokenRequestOptions.builder().scopes(Set.of("read")).build());
		VerifiedAccessToken proof = assertInstanceOf(AccessTokenValidationResult.Succeeded.class,
				provider().validator().validateResult(ResourceProviderFixturesIT.bearer(tokens))).getAccessToken();
		assertEquals("resource-strict", proof.getClientId().orElseThrow()); assertTrue(proof.getExpiresAt().isPresent());
		assertTrue(proof.getScopes().contains("read")); assertFalse(proof.getScopes().contains("write"));
	}
	@Test void disabledAccessTokenHeaderNeedsNamedCompatibilityAndExtraClaim() {
		TokenResponse tokens = client("resource-untyped", null).requestClientCredentialsToken(TokenRequestOptions.builder().scopes(Set.of("read")).build());
		BearerToken bearer = ResourceProviderFixturesIT.bearer(tokens);
		assertInstanceOf(AccessTokenValidationResult.Rejected.class, provider().validator().validateResult(bearer));
		JwtAccessTokenValidator compatible = JwtAccessTokenValidator.withIssuer(provider().issuer()).expectedAudiences(Set.of(ResourceProviderFixturesIT.RESOURCE))
				.compatibility(AccessTokenCompatibilityMode.UNTYPED_ACCESS_TOKENS).requiredClaims(Set.of("azp"))
				.httpClient(provider().httpClient()).allowInsecureLoopback(true).build();
		VerifiedAccessToken proof = compatible.validate(bearer); assertEquals("resource-untyped", assertInstanceOf(com.revetsec.json.JsonString.class, proof.getClaims().getMembers().get("azp")).getValue());
		assertTrue(proof.getScopes().contains("read")); assertFalse(proof.getScopes().contains("write"));
	}
	@Test void introspectionAudienceCheckSendsFreshPostEachTime() {
		AtomicInteger posts = new AtomicInteger(); OAuthClient oauth = client("resource-strict", counter(posts));
		BearerToken bearer = ResourceProviderFixturesIT.bearer(oauth.requestClientCredentialsToken(TokenRequestOptions.builder().scopes(Set.of("read")).build()));
		TokenIntrospectionClient introspection = TokenIntrospectionClient.withOAuthClient(oauth).expectedAudiences(Set.of(ResourceProviderFixturesIT.RESOURCE)).build();
		assertInstanceOf(AccessTokenValidationResult.Succeeded.class, introspection.validateResult(bearer));
		assertInstanceOf(AccessTokenValidationResult.Succeeded.class, introspection.validateResult(bearer)); assertEquals(2, posts.get());
		TokenIntrospectionClient wrong = TokenIntrospectionClient.withOAuthClient(oauth).expectedAudiences(Set.of("https://other.example.test/mcp")).build();
		assertEquals(AccessTokenValidationException.Reason.AUDIENCE_MISMATCH,
				assertInstanceOf(AccessTokenValidationResult.Rejected.class, wrong.validateResult(bearer)).getReason()); assertEquals(3, posts.get());
	}
	@Test void revokedCodeFlowSessionReturnsInactiveOnEveryPost() throws Exception {
		AtomicInteger posts = new AtomicInteger(); OAuthClient oauth = client("resource-strict", counter(posts));
		TokenResponse tokens = provider().codeFlow(oauth, false); BearerToken bearer = ResourceProviderFixturesIT.bearer(tokens);
		TokenIntrospectionClient introspection = TokenIntrospectionClient.withOAuthClient(oauth).expectedAudiences(Set.of(ResourceProviderFixturesIT.RESOURCE)).build();
		assertTrue(introspection.validate(bearer).getAudiences().contains(ResourceProviderFixturesIT.RESOURCE)); oauth.revoke(tokens.getRefreshToken().orElseThrow().getValue(), TokenTypeHint.REFRESH_TOKEN);
		for (int i = 0; i < 2; i++) assertEquals(AccessTokenValidationException.Reason.INACTIVE,
				assertInstanceOf(AccessTokenValidationResult.Rejected.class, introspection.validateResult(bearer)).getReason());
		assertEquals(3, posts.get());
	}
	@Test void strictJwtWrongAudienceRejectsBeforeProofRelease() {
		assertWrongAudience("resource-strict", false);
	}
	@Test void namedCompatibilityStillRejectsWrongAudienceBeforeProofRelease() {
		assertWrongAudience("resource-untyped", true);
	}
	private static void assertWrongAudience(@NonNull String clientId, boolean untyped) {
		TokenResponse tokens = client(clientId, null).requestClientCredentialsToken(TokenRequestOptions.builder().scopes(Set.of("read")).build());
		JwtAccessTokenValidator.Builder builder = JwtAccessTokenValidator.withIssuer(provider().issuer())
				.expectedAudiences(Set.of("https://other.example.test/mcp")).httpClient(provider().httpClient()).allowInsecureLoopback(true);
		if (untyped) assertSame(builder, builder.compatibility(AccessTokenCompatibilityMode.UNTYPED_ACCESS_TOKENS).requiredClaims(Set.of("azp")));
		AccessTokenValidationResult.Rejected result = assertInstanceOf(AccessTokenValidationResult.Rejected.class,
				builder.build().validateResult(ResourceProviderFixturesIT.bearer(tokens)));
		assertEquals(AccessTokenValidationException.Reason.JWT_REJECTED, result.getReason());
		assertEquals(java.util.Optional.of(com.revetsec.jose.JoseException.Reason.AUDIENCE_MISMATCH), result.getJoseReason());
	}

	private static @NonNull OAuthObserver counter(@NonNull AtomicInteger posts) {
		return new OAuthObserver() {
			@Override public void willRequestEndpoint(@NonNull OAuthEndpoint endpoint, @NonNull URI uri) {
				if (endpoint == OAuthEndpoint.INTROSPECTION) posts.incrementAndGet();
			}
		};
	}
}
