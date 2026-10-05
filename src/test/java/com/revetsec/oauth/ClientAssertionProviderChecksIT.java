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

import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.JwsSigner;
import com.revetsec.json.*;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.function.Executable;
import static org.junit.jupiter.api.Assertions.*;

/** Profile-only actual providers; public registrations are built from original JCA keys, independently of Revetsec. */
final class ClientAssertionProviderChecksIT implements AutoCloseable {
	private final boolean node;
	private final @NonNull ResourceProviderFixturesIT fixture;
	private final @NonNull Map<@NonNull String, @NonNull KeyPair> keys = new HashMap<>();
	private final @NonNull AuthorizationServerMetadata metadata;

	ClientAssertionProviderChecksIT(boolean node) throws Exception {
		this.node = node;
		var registrations = new ArrayList<JsonValue>();
		JsonObject keycloakTemplate;
		try (var input = Objects.requireNonNull(getClass().getResourceAsStream("/interop/m5/keycloak-resource-realm.json"))) {
			keycloakTemplate = (JsonObject) ((JsonArray) ((JsonObject) JsonCodec.parse(input.readAllBytes(),
					JsonLimits.protocolDocument(1024 * 1024))).getMembers().get("clients")).getElements().get(0);
		}
		for (JwsAlgorithm algorithm : List.of(JwsAlgorithm.RS256, JwsAlgorithm.RS384, JwsAlgorithm.PS256)) {
			for (ClientAssertionAudience audience : ClientAssertionAudience.values()) {
				String id = clientId(algorithm, audience); KeyPair pair = generateKey(); this.keys.put(id, pair);
				RSAPublicKey rsa = (RSAPublicKey) pair.getPublic();
				// No signer projection or Revetsec JWK utility participates in registration.
				JsonObject jwks = JsonObject.builder().put("keys", JsonArray.fromElements(List.of(JsonObject.builder()
						.put("kty", "RSA").put("kid", id).put("use", "sig").put("alg", algorithm.getWireValue())
						.put("n", unsigned(rsa.getModulus())).put("e", unsigned(rsa.getPublicExponent())).build()))).build();
				if (node) registrations.add(JsonObject.builder().put("client_id", id)
						.put("redirect_uris", strings(List.of(ResourceProviderFixturesIT.CALLBACK.toString())))
						.put("grant_types", strings(List.of("authorization_code", "refresh_token", "client_credentials")))
						.put("response_types", strings(List.of("code"))).put("jwks", jwks)
						.put("token_endpoint_auth_method", "private_key_jwt").put("token_endpoint_auth_signing_alg", algorithm.getWireValue())
						.put("introspection_endpoint_auth_method", "private_key_jwt").put("introspection_endpoint_auth_signing_alg", algorithm.getWireValue())
						.put("revocation_endpoint_auth_method", "private_key_jwt").put("revocation_endpoint_auth_signing_alg", algorithm.getWireValue()).build());
				else {
					JsonObject renamed = (JsonObject) JsonCodec.parse(json(keycloakTemplate).replace("resource-strict", id)
							.getBytes(StandardCharsets.UTF_8), JsonLimits.protocolDocument(1024 * 1024));
					var client = JsonObject.builder();
					for (var entry : renamed.getMembers().entrySet()) {
						if (Set.of("secret", "clientAuthenticatorType", "attributes").contains(entry.getKey())) continue;
						client.put(entry.getKey(), entry.getValue());
					}
					var attributes = JsonObject.builder();
					((JsonObject) renamed.getMembers().get("attributes")).getMembers().forEach(attributes::put);
					attributes.put("use.jwks.url", "false").put("use.jwks.string", "true").put("jwks.string", json(jwks))
							.put("token.endpoint.auth.signing.alg", algorithm.getWireValue());
					registrations.add(client.put("clientAuthenticatorType", "client-jwt").put("attributes", attributes.build()).build());
				}
			}
		}
		this.fixture = node ? ResourceProviderFixturesIT.fromNode(JsonArray.fromElements(registrations))
				: ResourceProviderFixturesIT.fromKeycloak(JsonArray.fromElements(registrations));
		try {
			var response = this.fixture.httpClient().send(HttpRequest.newBuilder(URI.create(this.fixture.issuer()
					+ "/.well-known/openid-configuration")).timeout(Duration.ofSeconds(10)).GET().build(), HttpResponse.BodyHandlers.ofString());
			assertEquals(200, response.statusCode());
			AuthorizationServerMetadata discovered = AuthorizationServerMetadata.fromJson(this.fixture.issuer(), response.body());
			assertTrue(discovered.getTokenEndpointAuthMethodsSupported().orElseThrow().contains("private_key_jwt"));
			assertTrue(discovered.getTokenEndpointAuthSigningAlgValuesSupported().orElseThrow().containsAll(Set.of("RS256", "RS384", "PS256")));
			// Only absent role fields receive trusted fixture registration settings; discovery's present values are retained.
			this.metadata = AuthorizationServerMetadata.withIssuer(discovered.getIssuer())
					.authorizationEndpoint(discovered.getAuthorizationEndpoint()).tokenEndpoint(discovered.getTokenEndpoint())
					.jwksUri(discovered.getJwksUri().orElseThrow()).revocationEndpoint(discovered.getRevocationEndpoint().orElseThrow())
					.introspectionEndpoint(discovered.getIntrospectionEndpoint().orElseThrow())
					.codeChallengeMethodsSupported(discovered.getCodeChallengeMethodsSupported().orElse(null))
					.authorizationResponseIssuerSupported(discovered.isAuthorizationResponseIssuerSupported())
					.tokenEndpointAuthMethodsSupported(discovered.getTokenEndpointAuthMethodsSupported().orElseThrow())
					.tokenEndpointAuthSigningAlgValuesSupported(discovered.getTokenEndpointAuthSigningAlgValuesSupported().orElseThrow())
					.revocationEndpointAuthMethodsSupported(discovered.getRevocationEndpointAuthMethodsSupported().orElse(Set.of("private_key_jwt")))
					.revocationEndpointAuthSigningAlgValuesSupported(discovered.getRevocationEndpointAuthSigningAlgValuesSupported().orElse(Set.of("RS256", "RS384", "PS256")))
					.introspectionEndpointAuthMethodsSupported(discovered.getIntrospectionEndpointAuthMethodsSupported().orElse(Set.of("private_key_jwt")))
					.introspectionEndpointAuthSigningAlgValuesSupported(discovered.getIntrospectionEndpointAuthSigningAlgValuesSupported().orElse(Set.of("RS256", "RS384", "PS256"))).build();
			System.out.println("M6 assertion provider=" + (node ? "node9.12.2" : "keycloak26.7.4")
					+ " revocation-methods-discovered=" + discovered.getRevocationEndpointAuthMethodsSupported().isPresent()
					+ " revocation-algs-discovered=" + discovered.getRevocationEndpointAuthSigningAlgValuesSupported().isPresent()
					+ " introspection-methods-discovered=" + discovered.getIntrospectionEndpointAuthMethodsSupported().isPresent()
					+ " introspection-algs-discovered=" + discovered.getIntrospectionEndpointAuthSigningAlgValuesSupported().isPresent());
		} catch (Exception | AssertionError failure) { this.fixture.close(); throw failure; }
	}

	void check(@NonNull JwsAlgorithm algorithm, @NonNull ClientAssertionAudience audience) throws Exception {
		String id = clientId(algorithm, audience); KeyPair pair = Objects.requireNonNull(this.keys.get(id));
		AtomicInteger lookups = new AtomicInteger(), posts = new AtomicInteger(), compatibility = new AtomicInteger();
		ClientAssertionSigningKey key = key(pair, algorithm, id);
		OAuthClient client = client(id, audience, budget -> { assertTrue(!budget.isNegative() && !budget.isZero()); lookups.incrementAndGet(); return key; }, new OAuthObserver() {
			@Override public void willRequestEndpoint(@NonNull OAuthEndpoint endpoint, @NonNull URI uri) { posts.incrementAndGet(); }
			@Override public void didUseClientAssertionAudience(@NonNull ClientAssertionAudience mode) { assertEquals(audience, mode); compatibility.incrementAndGet(); }
		});
		TokenRequestOptions credentials = TokenRequestOptions.builder().scopes(Set.of("read"))
				.resources(this.node ? List.of(URI.create(ResourceProviderFixturesIT.INTROSPECTION_RESOURCE)) : List.of()).build();
		TokenResponse service = client.requestClientCredentialsToken(credentials);
		assertFalse(service.getAccessToken().getValue().isEmpty()); assertEquals(1, lookups.get()); assertEquals(1, posts.get());
		TokenResponse code = this.fixture.codeFlow(client, this.node, this.node ? Set.of("openid", "read", "offline_access") : Set.of("openid", "read"));
		assertTrue(code.getRefreshToken().isPresent()); assertEquals(2, lookups.get()); assertEquals(2, posts.get());
		TokenResponse refreshed = client.refresh(code.getRefreshToken().orElseThrow(), TokenRequestOptions.builder()
				.resources(this.node ? List.of(URI.create(ResourceProviderFixturesIT.RESOURCE)) : List.of()).build());
		assertFalse(refreshed.getAccessToken().getValue().isEmpty()); assertEquals(3, lookups.get()); assertEquals(3, posts.get());
		String resource = this.node ? ResourceProviderFixturesIT.INTROSPECTION_RESOURCE : ResourceProviderFixturesIT.RESOURCE;
		TokenIntrospectionClient introspection = TokenIntrospectionClient.withOAuthClient(client).expectedAudiences(Set.of(resource)).build();
		BearerToken bearer = ResourceProviderFixturesIT.bearer(service);
		assertEquals(id, introspection.validate(bearer).getClientId().orElseThrow());
		assertEquals(id, introspection.validate(bearer).getClientId().orElseThrow());
		assertEquals(5, lookups.get()); assertEquals(5, posts.get());
		if (!this.node && audience == ClientAssertionAudience.TOKEN_ENDPOINT) {
			// Keycloak's pinned validator omits the revocation URL; never substitute the token URL or fall back.
			assertInvalidClient(() -> client.revoke(code.getRefreshToken().orElseThrow().getValue(), TokenTypeHint.REFRESH_TOKEN));
			assertEquals(6, lookups.get()); assertEquals(6, posts.get());
			assertEquals(id, introspection.validate(bearer).getClientId().orElseThrow());
			assertEquals(7, lookups.get()); assertEquals(7, posts.get());
		} else {
			client.revoke(this.node ? service.getAccessToken().getValue() : code.getRefreshToken().orElseThrow().getValue(),
					this.node ? TokenTypeHint.ACCESS_TOKEN : TokenTypeHint.REFRESH_TOKEN);
			assertEquals(6, lookups.get()); assertEquals(6, posts.get());
			BearerToken revoked = this.node ? bearer : ResourceProviderFixturesIT.bearer(refreshed);
			for (int attempt = 0; attempt < 2; attempt++) assertEquals(AccessTokenValidationException.Reason.INACTIVE,
					assertInstanceOf(AccessTokenValidationResult.Rejected.class, introspection.validateResult(revoked)).getReason());
			assertEquals(8, lookups.get()); assertEquals(8, posts.get());
		}
		assertEquals(audience == ClientAssertionAudience.TOKEN_ENDPOINT ? posts.get() : 0, compatibility.get());
		// A self-consistent but unregistered pair must reach and fail the actual provider, once, without fallback.
		KeyPair wrong = generateKey(); AtomicInteger wrongPosts = new AtomicInteger();
		OAuthObserver counter = new OAuthObserver() {
			@Override public void willRequestEndpoint(@NonNull OAuthEndpoint endpoint, @NonNull URI uri) { wrongPosts.incrementAndGet(); }
		};
		OAuthClient wrongClient = client(id, audience, ClientAssertionKeyProvider.fromKey(key(wrong, algorithm, id)), counter);
		assertInvalidClient(() -> wrongClient.requestClientCredentialsToken(credentials)); assertEquals(1, wrongPosts.get());
		OAuthClient wrongRevocation = !this.node && audience == ClientAssertionAudience.TOKEN_ENDPOINT
				? client(id, ClientAssertionAudience.ISSUER, ClientAssertionKeyProvider.fromKey(key(wrong, algorithm, id)), counter) : wrongClient;
		// Use an accepted audience in the Keycloak negative so its known audience deviation cannot mask the wrong key.
		assertInvalidClient(() -> wrongRevocation.revoke(service.getAccessToken().getValue(), TokenTypeHint.ACCESS_TOKEN)); assertEquals(2, wrongPosts.get());
		TokenIntrospectionClient wrongIntrospection = TokenIntrospectionClient.withOAuthClient(wrongClient).expectedAudiences(Set.of(resource)).build();
		assertInvalidClient(() -> wrongIntrospection.validateResult(bearer)); assertEquals(3, wrongPosts.get());
		// Correct pair with a different algorithm is also rejected by independent registration policy.
		JwsAlgorithm other = algorithm == JwsAlgorithm.RS256 ? JwsAlgorithm.PS256 : JwsAlgorithm.RS256;
		OAuthClient wrongAlgorithm = client(id, audience, ClientAssertionKeyProvider.fromKey(key(pair, other, id)), counter);
		assertInvalidClient(() -> wrongAlgorithm.requestClientCredentialsToken(credentials)); assertEquals(4, wrongPosts.get());
		System.out.println("M6 provider=" + (this.node ? "node" : "keycloak") + " alg=" + algorithm.getWireValue()
				+ " audience=" + audience + " roles=token,code,refresh,introspection,revocation negative-key=3 negative-alg=1"
				+ " revocation=" + (!this.node && audience == ClientAssertionAudience.TOKEN_ENDPOINT ? "invalid_client-qualified-deviation" : "accepted"));
	}
	private @NonNull OAuthClient client(@NonNull String id, @NonNull ClientAssertionAudience audience,
			@NonNull ClientAssertionKeyProvider provider, @NonNull OAuthObserver observer) {
		return OAuthClient.withAuthorizationServerMetadata(this.metadata).clientId(id)
				.clientAuthentication(ClientAuthentication.withPrivateKeyJwt(provider).audience(audience).build())
				.redirectUri(ResourceProviderFixturesIT.CALLBACK).httpClient(this.fixture.httpClient()).allowInsecureLoopback(true).observer(observer).build();
	}
	private static @NonNull ClientAssertionSigningKey key(@NonNull KeyPair pair, @NonNull JwsAlgorithm algorithm, @NonNull String id) {
		return ClientAssertionSigningKey.withSigner(JwsSigner.fromRsaKeyPair(pair.getPrivate(), pair.getPublic(), algorithm)).keyId(id).build();
	}
	private static void assertInvalidClient(@NonNull Executable operation) {
		assertEquals(Optional.of("invalid_client"), assertThrows(OAuthErrorResponseException.class, operation).getErrorCode());
	}
	private static @NonNull KeyPair generateKey() throws Exception { KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); return generator.generateKeyPair(); }
	private static @NonNull String clientId(@NonNull JwsAlgorithm algorithm, @NonNull ClientAssertionAudience audience) { return "m6-" + algorithm.getWireValue().toLowerCase(Locale.ROOT) + "-" + audience.name().toLowerCase(Locale.ROOT); }
	private static @NonNull String unsigned(@NonNull BigInteger integer) {
		byte[] bytes = integer.toByteArray();
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes);
	}
	private static @NonNull JsonArray strings(@NonNull List<@NonNull String> values) { return JsonArray.fromElements(values.stream().map(JsonString::fromValue).toList()); }
	private static @NonNull String json(@NonNull JsonValue value) { return new String(JsonCodec.toUtf8Bytes(value), StandardCharsets.UTF_8); }
	@Override public void close() throws java.io.IOException { this.fixture.close(); }
}
