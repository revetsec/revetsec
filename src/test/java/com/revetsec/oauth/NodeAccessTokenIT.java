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
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Actual pinned node-provider JWT resource indicators and uncached JSON introspection. */
final class NodeAccessTokenIT {
	private static @Nullable ResourceProviderFixturesIT fixture;
	@BeforeAll static void start() throws Exception { fixture = ResourceProviderFixturesIT.fromNode(); }
	@AfterAll static void stop() throws Exception { if (fixture != null) fixture.close(); }
	private static @NonNull ResourceProviderFixturesIT provider() { return requireNonNull(fixture); }
	private static @NonNull OAuthClient client(@Nullable OAuthObserver observer) {
		return provider().client(ResourceProviderFixturesIT.NODE_CLIENT, ResourceProviderFixturesIT.NODE_SECRET, observer);
	}
	@Test void authorizationCodeResourceIndicatorReturnsStrictProof() throws Exception {
		TokenResponse tokens = provider().codeFlow(client(null), true);
		VerifiedAccessToken checked = assertInstanceOf(AccessTokenValidationResult.Succeeded.class, provider().validator().validateResult(ResourceProviderFixturesIT.bearer(tokens))).getAccessToken();
		assertEquals(provider().issuer(), checked.getIssuer()); assertEquals("test-user", checked.getSubject().orElseThrow());
		assertEquals(ResourceProviderFixturesIT.NODE_CLIENT, checked.getClientId().orElseThrow());
		assertTrue(checked.getAudiences().contains(ResourceProviderFixturesIT.RESOURCE)); assertEquals(Set.of("read"), checked.getScopes());
		assertTrue(checked.getExpiresAt().isPresent());
	}
	@Test void clientCredentialsResourceIndicatorReturnsSuccessResult() {
		TokenResponse tokens = provider().nodeCredentials(client(null));
		AccessTokenValidationResult result = provider().validator().validateResult(ResourceProviderFixturesIT.bearer(tokens));
		VerifiedAccessToken checked = assertInstanceOf(AccessTokenValidationResult.Succeeded.class, result).getAccessToken();
		assertEquals(ResourceProviderFixturesIT.NODE_CLIENT, checked.getSubject().orElseThrow());
		assertEquals(ResourceProviderFixturesIT.NODE_CLIENT, checked.getClientId().orElseThrow());
		assertEquals(Set.of("read"), checked.getScopes()); assertFalse(result.toString().contains(tokens.getAccessToken().getValue()));
	}
	@Test void jwtWrongAudienceReturnsRejectedResultWithoutProof() {
		TokenResponse tokens = provider().nodeCredentials(client(null));
		JwtAccessTokenValidator wrong = JwtAccessTokenValidator.withIssuer(provider().issuer()).expectedAudiences(Set.of("https://other.example.test/mcp"))
				.httpClient(provider().httpClient()).allowInsecureLoopback(true).build();
		AccessTokenValidationResult.Rejected result = assertInstanceOf(AccessTokenValidationResult.Rejected.class,
				wrong.validateResult(ResourceProviderFixturesIT.bearer(tokens)));
		assertEquals(AccessTokenValidationException.Reason.JWT_REJECTED, result.getReason());
		assertEquals(java.util.Optional.of(com.revetsec.jose.JoseException.Reason.AUDIENCE_MISMATCH), result.getJoseReason());
		assertEquals(BearerError.INVALID_TOKEN, result.getBearerError());
	}
	@Test void introspectionChecksAudienceAndPostsForEveryValidation() {
		AtomicInteger posts = new AtomicInteger(); OAuthClient oauth = client(counter(posts));
		TokenResponse tokens = provider().nodeOpaqueCredentials(oauth);
		TokenIntrospectionClient introspection = TokenIntrospectionClient.withOAuthClient(oauth).expectedAudiences(Set.of(ResourceProviderFixturesIT.INTROSPECTION_RESOURCE)).build();
		BearerToken bearer = ResourceProviderFixturesIT.bearer(tokens);
		VerifiedAccessToken first = assertInstanceOf(AccessTokenValidationResult.Succeeded.class, introspection.validateResult(bearer)).getAccessToken(); VerifiedAccessToken second = assertInstanceOf(AccessTokenValidationResult.Succeeded.class, introspection.validateResult(bearer)).getAccessToken();
		assertEquals(2, posts.get()); assertNotSame(first, second); assertEquals(Set.of("read"), first.getScopes());
		assertEquals(provider().issuer(), first.getIssuer()); assertTrue(first.getAudiences().contains(ResourceProviderFixturesIT.INTROSPECTION_RESOURCE));
		TokenIntrospectionClient wrong = TokenIntrospectionClient.withOAuthClient(oauth).expectedAudiences(Set.of("https://other.example.test/mcp")).build();
		assertEquals(AccessTokenValidationException.Reason.AUDIENCE_MISMATCH,
				assertInstanceOf(AccessTokenValidationResult.Rejected.class, wrong.validateResult(bearer)).getReason()); assertEquals(3, posts.get());
	}
	@Test void revocationTurnsIntrospectionInactiveWithoutCaching() {
		AtomicInteger posts = new AtomicInteger(); OAuthClient oauth = client(counter(posts));
		TokenResponse tokens = provider().nodeOpaqueCredentials(oauth); BearerToken bearer = ResourceProviderFixturesIT.bearer(tokens);
		TokenIntrospectionClient introspection = TokenIntrospectionClient.withOAuthClient(oauth).expectedAudiences(Set.of(ResourceProviderFixturesIT.INTROSPECTION_RESOURCE)).build();
		assertInstanceOf(AccessTokenValidationResult.Succeeded.class, introspection.validateResult(bearer));
		assertInstanceOf(OAuthRevocationResult.Succeeded.class, oauth.revokeResult(tokens.getAccessToken().getValue(), TokenTypeHint.ACCESS_TOKEN));
		for (int i = 0; i < 2; i++) assertEquals(AccessTokenValidationException.Reason.INACTIVE,
				assertInstanceOf(AccessTokenValidationResult.Rejected.class, introspection.validateResult(bearer)).getReason());
		assertEquals(3, posts.get());
	}
	@Test void structuredJwtIntrospectionIsProviderFailureRatherThanCredentialRejection() {
		OAuthClient oauth = client(null); TokenResponse tokens = provider().nodeCredentials(oauth);
		TokenIntrospectionClient introspection = TokenIntrospectionClient.withOAuthClient(oauth)
				.expectedAudiences(Set.of(ResourceProviderFixturesIT.RESOURCE)).build();
		AccessTokenValidationResult.RejectedEndpoint failure = assertInstanceOf(AccessTokenValidationResult.RejectedEndpoint.class,
				introspection.validateResult(ResourceProviderFixturesIT.bearer(tokens)));
		assertEquals(OAuthEndpointError.UNSUPPORTED_TOKEN_TYPE, failure.getError());
	}

	@Test void actualProviderKeyRotationRefreshesSameValidatorAndCache() throws Exception {
		AtomicInteger fetches = new AtomicInteger();
		JwtAccessTokenValidator validator = JwtAccessTokenValidator.withIssuer(provider().issuer())
				.expectedAudiences(Set.of(ResourceProviderFixturesIT.RESOURCE)).httpClient(provider().httpClient())
				.allowInsecureLoopback(true).observer(new AccessTokenObserver() {
					@Override public void willFetchJwks(@NonNull URI uri) { fetches.incrementAndGet(); }
				}).build();
		OAuthClient oauth = client(null); TokenResponse first = provider().nodeCredentials(oauth);
		BearerToken oldBearer = ResourceProviderFixturesIT.bearer(first);
		VerifiedAccessToken before = assertInstanceOf(AccessTokenValidationResult.Succeeded.class, validator.validateResult(oldBearer)).getAccessToken(); assertEquals(1, fetches.get());
		provider().restartNode();
		TokenResponse second = provider().nodeCredentials(oauth);
		VerifiedAccessToken after = assertInstanceOf(AccessTokenValidationResult.Succeeded.class, validator.validateResult(ResourceProviderFixturesIT.bearer(second))).getAccessToken();
		assertEquals(2, fetches.get(), "same cached JWKS source refreshes for the actual new provider key");
		assertEquals(before.getIssuer(), after.getIssuer()); assertEquals(before.getAudiences(), after.getAudiences());
		assertNotEquals(before.getClaims().getMembers().get("jti"), after.getClaims().getMembers().get("jti"));
		assertInstanceOf(AccessTokenValidationResult.Rejected.class, validator.validateResult(oldBearer));
		assertEquals(2, fetches.get(), "the unknown-key cooldown does not refetch removed old signing keys");
	}
	@Test void unconfiguredResourceIndicatorFailsAtActualProvider() {
		AtomicReference<OAuthErrorResponseException> endpointFailure = new AtomicReference<>();
		OAuthClient oauth = client(new OAuthObserver() {
			@Override public void didFailEndpoint(@NonNull OAuthEndpoint endpoint, @NonNull URI uri,
					@NonNull OAuthException failure, @NonNull Duration elapsed) {
				if (endpoint == OAuthEndpoint.TOKEN && failure instanceof OAuthErrorResponseException error)
					endpointFailure.set(error);
			}
		});
		OAuthTokenRequestResult.Rejected failure = assertInstanceOf(OAuthTokenRequestResult.Rejected.class, oauth
				.requestClientCredentialsResult(TokenRequestOptions.builder().resources(java.util.List.of(URI.create("https://other.example.test/mcp")))
						.scopes(Set.of("read")).build()));
		// The result remains fixed and redacted; the observer confirms the actual provider's RFC 8707 code.
		assertEquals(OAuthEndpointError.UNRECOGNIZED, failure.getError());
		assertEquals(java.util.Optional.of("invalid_target"), requireNonNull(endpointFailure.get()).getErrorCode());
	}

	private static @NonNull OAuthObserver counter(@NonNull AtomicInteger posts) {
		return new OAuthObserver() {
			@Override public void willRequestEndpoint(@NonNull OAuthEndpoint endpoint, @NonNull URI uri) {
				if (endpoint == OAuthEndpoint.INTROSPECTION) posts.incrementAndGet();
			}
		};
	}
}
