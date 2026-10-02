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

import com.revetsec.ErrorCategory;
import com.revetsec.internal.Limits;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.JwsSigner;
import com.revetsec.json.JsonObject;
import com.revetsec.oidc.OidcClient;
import com.revetsec.oidc.OidcProviderMetadata;
import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestJsonWebKeys;
import com.revetsec.testing.TestTls;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.stream.Stream;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import static org.junit.jupiter.api.Assertions.*;
import static com.revetsec.oauth.Phase2Fixtures.*;

/** Approved M6-B: real emitted requests, independent signatures, role policy and caller-thread failure boundaries. */
final class ClientAssertionTests {
	private static final TestJsonWebKeys.@NonNull Fixture KEY = TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048;
	private static final @NonNull String CLIENT = "TEST-ONLY-client-é";

	@SuppressWarnings("NullAway") // Deliberately violates required-null contracts to verify public boundary rejection.
	@Test void keyAndAuthenticationBuildersAreLocalAndDefensivelyCopyAllIdentifiers() {
		JwsSigner signer = signer(JwsAlgorithm.PS256);
		assertThrows(NullPointerException.class, () -> ClientAssertionSigningKey.withSigner(null));
		assertThrows(NullPointerException.class, () -> ClientAuthentication.withPrivateKeyJwt(null));
		assertThrows(NullPointerException.class, () -> ClientAssertionKeyProvider.fromKey(null));
		assertThrows(IllegalStateException.class, () -> ClientAssertionSigningKey.withSigner(signer).build());
		for (String invalid : List.of("", "x".repeat(257), "\ud800", "\udc00"))
			assertThrows(IllegalArgumentException.class, () -> ClientAssertionSigningKey.withSigner(signer).keyId(invalid));
		for (int length : List.of(0, 31, 33)) assertThrows(IllegalArgumentException.class,
				() -> ClientAssertionSigningKey.withSigner(signer).certificateSha256Thumbprint(new byte[length]));
		byte[] digest = new byte[32]; digest[0] = 7;
		ClientAssertionSigningKey.Builder builder = ClientAssertionSigningKey.withSigner(signer).keyId("\"é😀").certificateSha256Thumbprint(digest);
		ClientAssertionSigningKey first = builder.build(); digest[0] = 9;
		byte[] output = first.getCertificateSha256Thumbprint().orElseThrow(); assertEquals(7, output[0]); output[0] = 11;
		assertEquals(7, first.getCertificateSha256Thumbprint().orElseThrow()[0]);
		ClientAssertionSigningKey cleared = builder.keyId(null).certificateSha256Thumbprint(null).keyId("new").build();
		assertTrue(cleared.getCertificateSha256Thumbprint().isEmpty()); assertNotEquals(first.getKeyId(), cleared.getKeyId());
		AtomicInteger reads = new AtomicInteger();
		ClientAssertionKeyProvider provider = budget -> { reads.incrementAndGet(); return first; };
		ClientAuthentication defaults = ClientAuthentication.fromPrivateKeyJwt(provider);
		ClientAuthentication reset = ClientAuthentication.withPrivateKeyJwt(provider).audience(ClientAssertionAudience.TOKEN_ENDPOINT)
				.audience(null).assertionLifetime(Duration.ofSeconds(1)).assertionLifetime(null).build();
		assertEquals(defaults.assertionAudience(), reset.assertionAudience()); assertEquals(Duration.ofSeconds(60), reset.assertionLifetime());
		for (Duration value : List.of(Duration.ZERO, Duration.ofSeconds(301), Duration.ofSeconds(-1), Duration.ofMillis(1500)))
			assertThrows(IllegalArgumentException.class, () -> ClientAuthentication.withPrivateKeyJwt(provider).assertionLifetime(value));
		assertEquals(Duration.ofSeconds(300), ClientAuthentication.withPrivateKeyJwt(provider).assertionLifetime(Duration.ofSeconds(300)).build().assertionLifetime());
		assertSame(first, ClientAssertionKeyProvider.fromKey(first).getSigningKey(Duration.ofSeconds(1)));
		assertEquals(0, reads.get());
		for (Object value : List.of(first, builder, defaults, ClientAuthentication.withPrivateKeyJwt(provider))) assertFalse(value.toString().contains("é"));
		assertThrows(IllegalArgumentException.class, () -> TokenRequestOptions.builder().additionalParameters(Map.of("client_assertion", "injected")));
		assertThrows(IllegalArgumentException.class, () -> TokenRequestOptions.builder().additionalParameters(Map.of("client_assertion_type", "injected")));
	}

	@TestFactory @NonNull Stream<@NonNull DynamicTest> allAlgorithmsAndAudiencesAuthenticateEveryPostRoleAndGrant() {
		return Stream.of(JwsAlgorithm.PS256, JwsAlgorithm.RS256, JwsAlgorithm.RS384).flatMap(algorithm ->
				Stream.of(ClientAssertionAudience.values()).map(audience -> DynamicTest.dynamicTest(algorithm+"/"+audience, () -> {
			try (TestHttpsServer server = TestHttpsServer.start()) {
				AtomicInteger keys = new AtomicInteger(); Events events = new Events();
				ClientAssertionSigningKey key = ClientAssertionSigningKey.withSigner(signer(algorithm)).keyId("key-é")
						.certificateSha256Thumbprint(new byte[32]).build();
				ClientAuthentication auth = ClientAuthentication.withPrivateKeyJwt(budget -> {
					assertTrue(!budget.isZero() && !budget.isNegative()); keys.incrementAndGet(); return key;
				}).audience(audience).build();
				OAuthClient client = client( metadata(server), auth).observer(events).redirectUri(server.uri("/callback")).build();
				assertEquals(0, keys.get()); assertEquals(audience == ClientAssertionAudience.TOKEN_ENDPOINT ? 1 : 0, events.enabled.get());
				response(server, "/token", 200, "application/json", tokens());
				client.requestClientCredentialsToken(TokenRequestOptions.builder().build());
				client.refresh(RefreshToken.fromValue("TEST-ONLY-refresh"), TokenRequestOptions.builder().build());
				AuthorizationRedirect redirect = client.beginAuthorization();
				AuthorizationResponse callback = AuthorizationResponse.fromQueryString("code=TEST-ONLY-code&state="+
						java.net.URLEncoder.encode(redirect.getPendingAuthorization().state(), StandardCharsets.UTF_8));
				client.completeAuthorization(callback, source(redirect.getPendingAuthorization()), server.uri("/callback"));
				response(server, "/revoke", 200, "application/json", "{}"); client.revoke("TEST-ONLY-access", TokenTypeHint.ACCESS_TOKEN);
				response(server, "/inspect", 200, "application/json", active());
				assertNotNull(TokenIntrospectionClient.withOAuthClient(client).expectedAudiences(Set.of(AUD)).observer(events).build().validate(bearer("TEST-ONLY-opaque")));
				assertEquals(5, keys.get()); assertEquals(5, events.will.get()); assertEquals(5, events.did.get()); assertEquals(0, events.failed.get());
				assertEquals(audience == ClientAssertionAudience.TOKEN_ENDPOINT ? 5 : 0, events.used.get());
				Set<String> identifiers = new HashSet<>();
				for (String path : List.of("/token", "/revoke", "/inspect")) for (var request : server.getRequests(path)) {
					Map<String,String> form = form(request.getBodyAsString());
					assertTrue(request.getHeader("Authorization").isEmpty()); assertFalse(form.containsKey("client_secret"));
					assertEquals(CLIENT, form.get("client_id"));
					assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", form.get("client_assertion_type"));
					String compact = form.get("client_assertion"); assertNotNull(compact); verify(compact, algorithm);
					JsonObject header = segment(compact, 0); JsonObject claims = segment(compact, 1);
					assertEquals(Set.of("alg", "typ", "kid", "x5t#S256"), header.getMembers().keySet());
					assertEquals(audience == ClientAssertionAudience.ISSUER ? "client-authentication+jwt" : "JWT", header.findString("typ").orElseThrow());
					assertEquals("key-é", header.findString("kid").orElseThrow());
					assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]), header.findString("x5t#S256").orElseThrow());
					assertEquals(Set.of("iss","sub","aud","iat","nbf","exp","jti"), claims.getMembers().keySet());
					assertEquals(CLIENT, claims.findString("iss").orElseThrow()); assertEquals(CLIENT, claims.findString("sub").orElseThrow());
					assertEquals(audience == ClientAssertionAudience.ISSUER ? server.getBaseUri().toString() : server.uri(path).toString(), claims.findString("aud").orElseThrow());
					assertEquals(NOW.getEpochSecond(), claims.findLong("iat").orElseThrow()); assertEquals(claims.findLong("iat"), claims.findLong("nbf"));
					assertEquals(NOW.getEpochSecond()+60, claims.findLong("exp").orElseThrow());
					String jti = claims.findString("jti").orElseThrow(); assertEquals(32, Base64.getUrlDecoder().decode(jti).length); assertTrue(identifiers.add(jti));
				}
			}
		}))); 
	}

	@TestFactory @NonNull Stream<@NonNull DynamicTest> rolePoliciesDistinguishAbsentEmptyUnknownAndExcludedBeforeKeyLookup() {
		return Stream.of("token-absent", "token-empty", "token-exclude", "revoke-absent", "revoke-empty", "revoke-exclude", "intro-empty", "intro-exclude", "alg-empty", "alg-exclude", "alg-unknown")
				.map(mode -> DynamicTest.dynamicTest(mode, () -> {
			try (TestHttpsServer server = TestHttpsServer.start()) {
				AtomicInteger reads = new AtomicInteger(); Events events = new Events();
				AuthorizationServerMetadata.Builder metadata = metadataBuilder(server);
				if (mode.startsWith("token")) metadata = metadata.tokenEndpointAuthMethodsSupported(mode.endsWith("absent") ? null : mode.endsWith("empty") ? Set.of() : Set.of("client_secret_basic"));
				if (mode.startsWith("revoke")) metadata = metadata.revocationEndpointAuthMethodsSupported(mode.endsWith("absent") ? null : mode.endsWith("empty") ? Set.of() : Set.of("client_secret_post"));
				if (mode.startsWith("intro")) metadata = metadata.introspectionEndpointAuthMethodsSupported(mode.endsWith("empty") ? Set.of() : Set.of("client_secret_basic"));
				if (mode.startsWith("alg")) metadata = metadata.tokenEndpointAuthSigningAlgValuesSupported(mode.endsWith("empty") ? Set.of() : Set.of(mode.endsWith("unknown") ? "future" : "RS384"));
				OAuthClient client = client( metadata.build(), authentication(reads)).observer(events).build();
				OAuthConfigurationException failure = assertThrows(OAuthConfigurationException.class, () -> {
					if (mode.startsWith("revoke")) client.revoke("token", TokenTypeHint.ACCESS_TOKEN);
					else if (mode.startsWith("intro")) assertNotNull(TokenIntrospectionClient.withOAuthClient(client).expectedAudiences(Set.of(AUD)).build().validateResult(bearer("token")));
					else client.requestClientCredentialsToken(TokenRequestOptions.builder().build());
				});
				assertEquals(OAuthException.Reason.CLIENT_ASSERTION_ENDPOINT_MISMATCH, failure.getReason());
				assertEquals(mode.equals("alg-exclude") || mode.equals("alg-unknown") ? 1 : 0, reads.get());
				assertSame(failure, events.failure.get()); assertEquals(1, events.preparedFailed.get()); assertEquals(0, events.will.get()); assertEquals(0, events.failed.get()); assertEquals(0, server.getRequests().size());
			}
		}));
	}

	@Test void absentSigningAlgorithmsUseExplicitSnapshotAndUnknownMetadataSurvivesProjection() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			AuthorizationServerMetadata metadata = metadataBuilder(server).tokenEndpointAuthSigningAlgValuesSupported(null)
					.revocationEndpointAuthSigningAlgValuesSupported(null).introspectionEndpointAuthSigningAlgValuesSupported(null).build();
			response(server, "/token",200,"application/json",tokens()); client(metadata,authentication(new AtomicInteger())).build().requestClientCredentialsToken(TokenRequestOptions.builder().build());
			String json = "{\"issuer\":\"https://issuer.example\",\"authorization_endpoint\":\"https://issuer.example/a\",\"token_endpoint\":\"https://issuer.example/t\","
					+"\"jwks_uri\":\"https://issuer.example/j\",\"subject_types_supported\":[\"public\"],\"id_token_signing_alg_values_supported\":[\"RS256\"],\"response_types_supported\":[\"code\"],"
					+"\"token_endpoint_auth_signing_alg_values_supported\":[\"future\"],\"revocation_endpoint_auth_methods_supported\":[],\"revocation_endpoint_auth_signing_alg_values_supported\":[\"RS384\"],\"introspection_endpoint_auth_signing_alg_values_supported\":[\"PS256\"]}";
			AuthorizationServerMetadata parsed = AuthorizationServerMetadata.fromJson(ISSUER,json); OidcProviderMetadata oidc = OidcProviderMetadata.fromJson(ISSUER,json);
			assertEquals(Set.of("future"), parsed.getTokenEndpointAuthSigningAlgValuesSupported().orElseThrow()); assertEquals(parsed.getTokenEndpointAuthSigningAlgValuesSupported(),oidc.getTokenEndpointAuthSigningAlgValuesSupported());
			assertEquals(Optional.of(Set.of()), oidc.getRevocationEndpointAuthMethodsSupported());
			assertEquals(parsed.getRevocationEndpointAuthSigningAlgValuesSupported(),oidc.getRevocationEndpointAuthSigningAlgValuesSupported());
			assertEquals(parsed.getIntrospectionEndpointAuthSigningAlgValuesSupported(),oidc.getIntrospectionEndpointAuthSigningAlgValuesSupported());
			OidcProviderMetadata reset = OidcProviderMetadata.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/a")).tokenEndpoint(URI.create(ISSUER+"/t")).jwksUri(URI.create(ISSUER+"/j"))
					.tokenEndpointAuthSigningAlgValuesSupported(Set.of("RS384")).tokenEndpointAuthSigningAlgValuesSupported(null)
					.revocationEndpointAuthMethodsSupported(Set.of()).revocationEndpointAuthMethodsSupported(null)
					.revocationEndpointAuthSigningAlgValuesSupported(Set.of("RS384")).revocationEndpointAuthSigningAlgValuesSupported(null)
					.introspectionEndpointAuthMethodsSupported(Set.of("private_key_jwt")).introspectionEndpointAuthMethodsSupported(null)
					.introspectionEndpointAuthSigningAlgValuesSupported(Set.of()).introspectionEndpointAuthSigningAlgValuesSupported(null).build();
			assertTrue(reset.getTokenEndpointAuthSigningAlgValuesSupported().isEmpty()); assertTrue(reset.getRevocationEndpointAuthMethodsSupported().isEmpty());
			assertTrue(reset.getRevocationEndpointAuthSigningAlgValuesSupported().isEmpty()); assertTrue(reset.getIntrospectionEndpointAuthSigningAlgValuesSupported().isEmpty()); assertTrue(reset.getIntrospectionEndpointAuthMethodsSupported().isEmpty());
			for (String invalid : List.of("null", "true", "[\"PS256\",\"PS256\"]", "[\"\"]")) assertThrows(OAuthResponseException.class,
					() -> AuthorizationServerMetadata.fromJson(ISSUER,json.replace("[\"future\"]",invalid)));
		}
	}

	@SuppressWarnings("NullAway") // Deliberately broken application provider; production must reject its null result.
	@TestFactory @NonNull Stream<@NonNull DynamicTest> providerNullThrowAndInterruptRemainFixedInfrastructureFailures() {
		return Stream.of("null", "runtime", "error", "interrupt", "fatal").map(mode -> DynamicTest.dynamicTest(mode, () -> {
			try (TestHttpsServer server = TestHttpsServer.start()) {
				Events events = new Events(); AtomicInteger reads = new AtomicInteger();
				ClientAssertionKeyProvider provider = budget -> {
					reads.incrementAndGet();
					switch (mode) {
						case "runtime" -> throw new IllegalStateException("TEST-ONLY-private-secret");
						case "error" -> throw new AssertionError("TEST-ONLY-private-secret");
						case "fatal" -> throw new OutOfMemoryError("TEST-ONLY-fatal");
						case "interrupt" -> { Thread.currentThread().interrupt(); throw new IllegalStateException("TEST-ONLY-private-secret"); }
						default -> { return null; }
					}
				};
				OAuthClient client = client(metadata(server),ClientAuthentication.fromPrivateKeyJwt(provider)).observer(events).build();
				try {
					if (mode.equals("fatal")) { assertThrows(OutOfMemoryError.class, () -> client.requestClientCredentialsToken(TokenRequestOptions.builder().build())); assertEquals(0,events.preparedFailed.get()); }
					else {
						OAuthException failure = assertThrows(OAuthException.class, () -> client.requestClientCredentialsToken(TokenRequestOptions.builder().build()));
						assertEquals(mode.equals("interrupt") ? OAuthException.Reason.INTERRUPTED : OAuthException.Reason.CLIENT_ASSERTION_KEY_UNAVAILABLE, failure.getReason());
						assertNull(failure.getCause()); assertSame(failure,events.failure.get()); assertEquals(1,events.preparedFailed.get()); assertFalse(failure.toString().contains("TEST-ONLY"));
						if (mode.equals("interrupt")) assertTrue(Thread.currentThread().isInterrupted());
					}
				} finally { Thread.interrupted(); }
				assertEquals(1,reads.get()); assertEquals(0,events.will.get()); assertEquals(0,server.getRequests().size());
			}
		}));
	}

	@TestFactory @NonNull Stream<@NonNull DynamicTest> originalBudgetClockExpiryAndRegressionRejectBeforeTransport() {
		return Stream.of("provider-budget", "will-budget", "will-expiry", "clock-regression", "clock-range", "claims-cap", "invalid-text", "invalid-clock").map(mode -> DynamicTest.dynamicTest(mode, () -> {
			try (TestHttpsServer server = TestHttpsServer.start()) {
				Events events = new Events(); TestClock clock = TestClock.fromInstant(NOW); AtomicInteger reads = new AtomicInteger();
				ClientAssertionKeyProvider provider = budget -> {
					reads.incrementAndGet(); if (mode.equals("provider-budget")) pause(1100);
					return key(JwsAlgorithm.PS256);
				};
				Clock selected = mode.equals("clock-range") ? Clock.fixed(Instant.MAX,ZoneOffset.UTC) : mode.equals("clock-regression") ? new Clock() {
					private final AtomicInteger calls = new AtomicInteger();
					@Override public @NonNull Instant instant() { return this.calls.getAndIncrement() == 0 ? NOW : NOW.minusSeconds(1); }
					@Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
					@Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
				} : mode.equals("invalid-clock") ? new Clock() {
					@Override public @NonNull Instant instant() { throw new IllegalStateException("TEST-ONLY-clock"); }
					@Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
					@Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
				} : clock;
				OAuthObserver observer = new OAuthObserver() {
					@Override public void willRequestEndpoint(@NonNull OAuthEndpoint role, @NonNull URI uri) {
						events.willRequestEndpoint(role,uri);
						if (mode.equals("will-budget")) pause(1100);
						if (mode.equals("will-expiry")) clock.advance(Duration.ofSeconds(1));
					}
					@Override public void didFailEndpoint(@NonNull OAuthEndpoint role,@NonNull URI uri,@NonNull OAuthException failure,@NonNull Duration elapsed) { events.didFailEndpoint(role,uri,failure,elapsed); }
					@Override public void didFailClientAssertionPreparation(@NonNull OAuthEndpoint role,@NonNull OAuthException failure) { events.didFailClientAssertionPreparation(role,failure); }
				};
				OAuthClient client = client(metadata(server),ClientAuthentication.withPrivateKeyJwt(provider).assertionLifetime(Duration.ofSeconds(1)).build())
						.clock(selected).observer(observer).clientId(mode.equals("claims-cap") ? "x".repeat(40_000) : mode.equals("invalid-text") ? "\ud800" : CLIENT)
						.requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(1)).build();
				OAuthException failure = assertThrows(OAuthException.class, () -> client.requestClientCredentialsToken(TokenRequestOptions.builder().build()));
				assertSame(failure,events.failure.get()); assertEquals(1,reads.get()); assertEquals(0,server.getRequests().size());
				boolean afterWill = mode.startsWith("will"); assertEquals(afterWill ? 1 : 0,events.will.get()); assertEquals(afterWill ? 1 : 0,events.failed.get()); assertEquals(afterWill ? 0 : 1,events.preparedFailed.get());
				assertEquals(mode.endsWith("budget") ? OAuthException.Reason.NETWORK_FAILURE : OAuthException.Reason.CLIENT_ASSERTION_SIGNING_FAILED,failure.getReason());
			}
		}));
	}

	@Test void roleOnlyIntrospectionAndExplicitOverrideNeverFetchBrowserMetadataOrInheritAnotherEndpointPolicy() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			AtomicInteger reads = new AtomicInteger();
			OAuthClient client = OAuthClient.withIssuer(server.getBaseUri().toString()).clientId(CLIENT).clientAuthentication(authentication(reads)).httpClient(TestTls.httpClient()).clock(CLOCK).build();
			response(server,"/inspect",200,"application/json",active());
			TokenIntrospectionClient explicit = TokenIntrospectionClient.withOAuthClient(client).introspectionEndpoint(server.uri("/inspect")).expectedAudiences(Set.of(AUD)).build();
			explicit.warmUp(); assertEquals(0,reads.get()); assertEquals(0,server.getRequests().size()); assertNotNull(explicit.validate(bearer("opaque"))); assertEquals(1,reads.get());
			String json = "{\"issuer\":\""+server.getBaseUri()+"\",\"introspection_endpoint\":\""+server.uri("/inspect")+"\",\"introspection_endpoint_auth_signing_alg_values_supported\":[\"PS256\"],\"id_token_signing_alg_values_supported\":[\"HS256\"]}";
			response(server,"/.well-known/oauth-authorization-server",200,"application/json",json);
			TokenIntrospectionClient discovered = TokenIntrospectionClient.withOAuthClient(client).expectedAudiences(Set.of(AUD)).build();
			discovered.warmUp(); assertEquals(1,reads.get()); assertNotNull(discovered.validate(bearer("opaque"))); assertEquals(2,reads.get());
			assertEquals(1,server.getHitCount("/.well-known/oauth-authorization-server"));
			AuthorizationServerMetadata other = metadataBuilder(server).introspectionEndpoint(server.uri("/other"))
					.introspectionEndpointAuthMethodsSupported(Set.of()).introspectionEndpointAuthSigningAlgValuesSupported(Set.of("RS384")).build();
			OAuthClient configured = client(other,authentication(reads)).build();
			assertNotNull(TokenIntrospectionClient.withOAuthClient(configured).introspectionEndpoint(server.uri("/inspect")).expectedAudiences(Set.of(AUD)).build().validate(bearer("opaque"))); assertEquals(3,reads.get());
			assertThrows(OAuthConfigurationException.class, () -> TokenIntrospectionClient.withOAuthClient(configured).expectedAudiences(Set.of(AUD)).build().validateResult(bearer("opaque"))); assertEquals(3,reads.get());
		}
	}

	@TestFactory @NonNull Stream<@NonNull DynamicTest> allRolesRejectCrossOriginEndpointsAndPresentCrossOriginTokenBeforeKeys() {
		return Stream.of("token", "revoke", "inspect", "inspect-token").flatMap(role -> Stream.of("scheme", "host", "port").map(part -> DynamicTest.dynamicTest(role+"/"+part, () -> {
			try (TestHttpsServer server = TestHttpsServer.start()) {
				AtomicInteger reads = new AtomicInteger(); Events events = new Events();
				URI foreign = URI.create(part.equals("scheme") ? "http://127.0.0.1:"+server.getBaseUri().getPort()+"/foreign" : part.equals("host") ? "https://foreign.example/foreign" : "https://127.0.0.1:"+(server.getBaseUri().getPort()+1)+"/foreign");
				AuthorizationServerMetadata.Builder b = metadataBuilder(server);
				if (role.equals("token") || role.equals("inspect-token")) b = b.tokenEndpoint(foreign);
				else if (role.equals("revoke")) b = b.revocationEndpoint(foreign); else b = b.introspectionEndpoint(foreign);
				OAuthClient client = client(b.build(),authentication(reads)).allowInsecureLoopback(true).observer(events).build();
				OAuthConfigurationException failure = assertThrows(OAuthConfigurationException.class, () -> {
					if (role.startsWith("inspect")) assertNotNull(TokenIntrospectionClient.withOAuthClient(client).expectedAudiences(Set.of(AUD)).build().validateResult(bearer("opaque")));
					else if (role.equals("revoke")) client.revoke("opaque",TokenTypeHint.ACCESS_TOKEN); else client.requestClientCredentialsToken(TokenRequestOptions.builder().build());
				});
				assertEquals(OAuthException.Reason.CLIENT_ASSERTION_ENDPOINT_MISMATCH,failure.getReason()); assertEquals(0,reads.get()); assertEquals(0,events.will.get()); assertSame(failure,events.failure.get()); assertEquals(0,server.getRequests().size());
			}
		})));
	}

	@Test void sameOriginUsesAsciiCaseAndEffectivePortWhilePreservingExactAudienceQuery() throws Exception {
		assertTrue(ClientAssertionPreparation.sameOrigin(URI.create("https://EXAMPLE.com/issuer"),URI.create("https://example.com:443/path?q=%2F")));
		assertFalse(ClientAssertionPreparation.sameOrigin(URI.create("https://example.com"),URI.create("https://example.com:444")));
		assertTrue(ClientAssertionPreparation.sameOrigin(URI.create("http://localhost"),URI.create("http://LOCALHOST:80/a")));
		try (TestHttpsServer server = TestHttpsServer.start()) {
			URI endpoint = URI.create(server.uri("/inspect")+"?q=%2F&x=a%20b");
			response(server,"/inspect",200,"application/json",active());
			OAuthClient client = client(metadata(server),ClientAuthentication.withPrivateKeyJwt(budget -> key(JwsAlgorithm.PS256)).audience(ClientAssertionAudience.TOKEN_ENDPOINT).build()).build();
			assertNotNull(TokenIntrospectionClient.withOAuthClient(client).introspectionEndpoint(endpoint).expectedAudiences(Set.of(AUD)).build().validate(bearer("opaque")));
			assertEquals(endpoint.toString(),segment(java.util.Objects.requireNonNull(form(server.getRequests("/inspect").get(0).getBodyAsString()).get("client_assertion")),1).findString("aud").orElseThrow());
		}
	}

	@Test void signingFailuresAreMappedAndNeverBecomeInvalidCredentialResults() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			for (boolean mismatch : List.of(false,true)) {
				PrivateKey privateKey = mismatch ? KEY.getPrivateKey() : new PrivateKey() {
					private static final long serialVersionUID = 1L;
					@Override public @NonNull String getAlgorithm() { return "RSA"; }
					@Override public @Nullable String getFormat() { return null; }
					@Override public byte @Nullable [] getEncoded() { return null; }
				};
				JwsSigner signer = JwsSigner.fromRsaKeyPair(privateKey,mismatch ? TestJsonWebKeys.Fixture.NEGATIVE_ATTACKER_RSA_2048.getPublicKey() : KEY.getPublicKey(),JwsAlgorithm.RS256);
				Events events = new Events();
				OAuthClient client = client(metadata(server),ClientAuthentication.fromPrivateKeyJwt(ClientAssertionKeyProvider.fromKey(ClientAssertionSigningKey.withSigner(signer).keyId("TEST-ONLY-key").build()))).observer(events).build();
				OAuthConfigurationException failure = assertThrows(OAuthConfigurationException.class, () -> TokenIntrospectionClient.withOAuthClient(client).expectedAudiences(Set.of(AUD)).build().validateResult(bearer("opaque")));
				assertEquals(mismatch ? OAuthException.Reason.CLIENT_ASSERTION_KEY_PAIR_MISMATCH : OAuthException.Reason.CLIENT_ASSERTION_SIGNING_FAILED,failure.getReason());
				assertEquals(ErrorCategory.CONFIGURATION,failure.getCategory()); assertFalse(failure.isTransient()); assertNull(failure.getCause()); assertSame(failure,events.failure.get()); assertEquals(0,events.will.get());
			}
		}
	}

	@Test void cacheLeaderUsesOneSnapshotWaitersAndHitsNoneAndLaterPostsRotate() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			AtomicInteger reads = new AtomicInteger();
			ClientAssertionKeyProvider provider = budget -> ClientAssertionSigningKey.withSigner(signer(reads.getAndIncrement() == 0 ? JwsAlgorithm.PS256 : JwsAlgorithm.RS384)).keyId("key-"+reads.get()).build();
			OAuthClient client = client(metadataBuilder(server).tokenEndpointAuthSigningAlgValuesSupported(Set.of("PS256","RS384")).build(),ClientAuthentication.fromPrivateKeyJwt(provider)).build();
			TestHttpsServer.HeldScript held = TestHttpsServer.HeldScript.fromResponse(TestHttpsServer.Response.fromJson(200,tokens())); server.script("/token",held);
			ClientCredentialsTokenSource source = ClientCredentialsTokenSource.withClient(client).build(); ExecutorService pool = Executors.newFixedThreadPool(3);
			try {
				Future<AccessToken> leader = pool.submit(source::getAccessToken); assertTrue(held.awaitHeldCount(1,Duration.ofSeconds(5)));
				AtomicReference<Thread> waiterThread = new AtomicReference<>(); CountDownLatch entered = new CountDownLatch(1);
				Future<AccessToken> waiter = pool.submit(() -> { waiterThread.set(Thread.currentThread()); entered.countDown(); return source.getAccessToken(); });
				assertTrue(entered.await(5,TimeUnit.SECONDS)); awaitWaitingForToken(java.util.Objects.requireNonNull(waiterThread.get()));
				assertFalse(waiter.isDone()); assertEquals(1,reads.get()); held.release();
				assertSame(leader.get(5,TimeUnit.SECONDS),waiter.get(5,TimeUnit.SECONDS)); source.getAccessToken(); assertEquals(1,reads.get()); assertEquals(1,server.getHitCount("/token"));
				response(server,"/token",200,"application/json",tokens()); client.requestClientCredentialsToken(TokenRequestOptions.builder().build()); assertEquals(2,reads.get());
				String first = java.util.Objects.requireNonNull(form(server.getRequests("/token").get(0).getBodyAsString()).get("client_assertion")); String second = java.util.Objects.requireNonNull(form(server.getRequests("/token").get(1).getBodyAsString()).get("client_assertion"));
				assertEquals("key-1",segment(first,0).findString("kid").orElseThrow()); assertEquals("key-2",segment(second,0).findString("kid").orElseThrow());
				assertEquals("RS384",segment(second,0).findString("alg").orElseThrow()); assertNotEquals(segment(first,1).findString("jti"),segment(second,1).findString("jti"));
			} finally { held.release(); pool.shutdownNow(); assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS)); }
		}
	}

	@Test void privateKeyHmacBuildRejectsBeforeProviderAndPublicPendingRejectionHasNoPreparationEvent() throws Exception {
		AtomicInteger reads = new AtomicInteger(); ClientAuthentication auth = authentication(reads);
		OidcProviderMetadata oidc = OidcProviderMetadata.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/a"))
				.tokenEndpoint(URI.create(ISSUER+"/t")).jwksUri(URI.create(ISSUER+"/j")).idTokenSigningAlgValuesSupported(Set.of("HS256","RS256")).build();
		assertThrows(IllegalArgumentException.class, () -> OidcClient.withProviderMetadata(oidc).clientId(CLIENT).clientAuthentication(auth)
				.idTokenSigningAlgorithms(Set.of(JwsAlgorithm.HS256)).compatibility(Set.of(com.revetsec.oidc.OidcCompatibilityMode.HMAC_ID_TOKENS)).redirectUri(URI.create("https://app.example/callback")).build());
		assertEquals(0,reads.get());
		try (TestHttpsServer server = TestHttpsServer.start()) {
			Events events = new Events(); OAuthClient client = client(metadata(server),auth).observer(events).redirectUri(server.uri("/callback")).build();
			AuthorizationRedirect redirect = client.beginAuthorization();
			assertInstanceOf(AuthorizationCompletionResult.Rejected.class,client.completeAuthorizationResult(AuthorizationResponse.fromQueryString("code=bad&state=bad"),source(redirect.getPendingAuthorization()),server.uri("/callback")));
			assertEquals(0,reads.get()); assertEquals(0,events.preparedFailed.get()); assertEquals(0,events.will.get());
		}
	}

	@Test void exhaustedOriginalDeadlineAndInterruptionAreCheckedBeforeKeyLookup() {
		AtomicInteger reads = new AtomicInteger(); OAuthClient client = OAuthClient.withAuthorizationServerMetadata(AuthorizationServerMetadata.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/a")).tokenEndpoint(URI.create(ISSUER+"/t")).build()).clientId(CLIENT).clientAuthentication(authentication(reads)).build();
		ResourceServerMetadata target = new ResourceServerMetadata(ISSUER,URI.create(ISSUER+"/t"),Set.of("private_key_jwt"),null,null);
		assertEquals(OAuthException.Reason.NETWORK_FAILURE,assertThrows(OAuthTransportException.class, () -> ClientAssertionPreparation.prepare(authentication(reads),CLIENT,target,OAuthEndpoint.TOKEN,client.resourceSettings(),new SecureRandom(),Deadline.fromNow(Duration.ZERO))).getReason());
		try { Thread.currentThread().interrupt(); assertEquals(OAuthException.Reason.INTERRUPTED,assertThrows(OAuthTransportException.class, () -> ClientAssertionPreparation.prepare(authentication(reads),CLIENT,target,OAuthEndpoint.TOKEN,client.resourceSettings(),new SecureRandom(),Deadline.fromNow(Duration.ofSeconds(1)))).getReason()); assertTrue(Thread.currentThread().isInterrupted()); }
		finally { Thread.interrupted(); }
		assertEquals(0,reads.get());
	}

	@TestFactory @NonNull Stream<@NonNull DynamicTest> signingAlgorithmPolicyIsSpecificToRevocationAndIntrospection() {
		return Stream.of("revoke", "intro").flatMap(role -> Stream.of("empty","exclude").map(policy -> DynamicTest.dynamicTest(role+"/"+policy, () -> {
			try (TestHttpsServer server = TestHttpsServer.start()) {
				AtomicInteger reads = new AtomicInteger(); Events events = new Events(); Set<String> algorithms = policy.equals("empty") ? Set.of() : Set.of("RS384");
				AuthorizationServerMetadata.Builder metadata = metadataBuilder(server);
				if (role.equals("revoke")) metadata = metadata.revocationEndpointAuthSigningAlgValuesSupported(algorithms); else metadata = metadata.introspectionEndpointAuthSigningAlgValuesSupported(algorithms);
				OAuthClient client = client(metadata.build(),authentication(reads)).observer(events).build();
				assertThrows(OAuthConfigurationException.class, () -> {
					if (role.equals("revoke")) client.revoke("token",TokenTypeHint.ACCESS_TOKEN); else assertNotNull(TokenIntrospectionClient.withOAuthClient(client).expectedAudiences(Set.of(AUD)).build().validateResult(bearer("token")));
				});
				assertEquals(policy.equals("empty") ? 0 : 1,reads.get()); assertEquals(1,events.preparedFailed.get()); assertEquals(0,events.will.get()); assertEquals(0,server.getRequests().size());
			}
		})));
	}
	@Test void assertionPreparationTimeCannotExtendTokenLifetimeAndMinimumLifetimeUsesWholeSeconds() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			TestClock clock = TestClock.fromInstant(NOW.plusNanos(500_000_000));
			ClientAuthentication auth = ClientAuthentication.withPrivateKeyJwt(budget -> { clock.advance(Duration.ofSeconds(10)); return key(JwsAlgorithm.PS256); }).assertionLifetime(Duration.ofSeconds(1)).build();
			response(server,"/token",200,"application/json",tokens());
			TokenResponse token = client(metadata(server),auth).clock(clock).build().requestClientCredentialsToken(TokenRequestOptions.builder().build());
			JsonObject claims = segment(java.util.Objects.requireNonNull(form(server.getRequests("/token").get(0).getBodyAsString()).get("client_assertion")),1);
			assertEquals(NOW.getEpochSecond()+10,claims.findLong("iat").orElseThrow()); assertEquals(NOW.getEpochSecond()+11,claims.findLong("exp").orElseThrow());
			assertEquals(Optional.of(NOW.plusSeconds(310).plusNanos(500_000_000)),token.getExpiresAt());
		}
	}
	@SuppressWarnings("NullAway") // Deliberately violates required-null contracts to verify public boundary rejection.
	@Test void configurationReasonPartitionsAreCauseFreeAndOtherLeavesCannotConstructThem() {
		Set<OAuthException.Reason> selected = Set.of(OAuthException.Reason.CLIENT_ASSERTION_KEY_UNAVAILABLE,OAuthException.Reason.CLIENT_ASSERTION_SIGNING_FAILED,
				OAuthException.Reason.CLIENT_ASSERTION_KEY_PAIR_MISMATCH,OAuthException.Reason.CLIENT_ASSERTION_ENDPOINT_MISMATCH,OAuthException.Reason.ISSUER_POLICY_UNAVAILABLE);
		for (OAuthException.Reason reason : OAuthException.Reason.values()) {
			if (selected.contains(reason)) {
				OAuthConfigurationException failure = OAuthConfigurationException.fromReason(reason); assertEquals(reason,failure.getReason()); assertEquals(ErrorCategory.CONFIGURATION,failure.getCategory()); assertFalse(failure.isTransient()); assertNull(failure.getCause());
				assertThrows(IllegalArgumentException.class, () -> OAuthTransportException.fromReason(reason,null));
				assertThrows(IllegalArgumentException.class, () -> OAuthValidationException.fromReason(reason));
				assertThrows(IllegalArgumentException.class, () -> OAuthResponseException.fromReason(reason));
			} else assertThrows(IllegalArgumentException.class, () -> OAuthConfigurationException.fromReason(reason));
		}
		assertThrows(NullPointerException.class, () -> OAuthConfigurationException.fromReason(null));
	}
	@Test void preparationAndCompatibilityHookFailuresAreContainedAndObserversAreDeduplicated() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			Events events = new Events(); OAuthObserver throwing = new OAuthObserver() {
				@Override public void didEnableClientAssertionAudience(@NonNull ClientAssertionAudience audience) { throw new IllegalStateException("TEST-ONLY-hook"); }
				@Override public void didUseClientAssertionAudience(@NonNull ClientAssertionAudience audience) { throw new AssertionError("TEST-ONLY-hook"); }
				@Override public void didFailClientAssertionPreparation(@NonNull OAuthEndpoint role,@NonNull OAuthException failure) { throw new IllegalStateException("TEST-ONLY-hook"); }
			};
			ClientAuthentication bad = ClientAuthentication.withPrivateKeyJwt(budget -> { throw new IllegalStateException("TEST-ONLY-key"); }).audience(ClientAssertionAudience.TOKEN_ENDPOINT).build();
			OAuthClient client = client(metadata(server),bad).observer(throwing).build();
			OAuthConfigurationException failure = assertThrows(OAuthConfigurationException.class, () -> TokenIntrospectionClient.withOAuthClient(client).expectedAudiences(Set.of(AUD)).observer(events).build().validateResult(bearer("opaque")));
			assertSame(failure,events.failure.get()); assertEquals(1,events.used.get()); assertEquals(1,events.preparedFailed.get()); assertEquals(0,events.will.get()); assertEquals(0,server.getRequests().size());
		}
	}
	@Test void discoveredIntrospectionAlgorithmAndTokenOriginPoliciesArePreservedBeforeProvider() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			for (String suffix : List.of(",\"introspection_endpoint_auth_signing_alg_values_supported\":[\"RS384\"]", ",\"token_endpoint\":\"https://foreign.example/token\"")) {
				String json = "{\"issuer\":\""+server.getBaseUri()+"\",\"introspection_endpoint\":\""+server.uri("/inspect")+"\""+suffix+"}";
				response(server,"/.well-known/oauth-authorization-server",200,"application/json",json);
				AtomicInteger reads = new AtomicInteger(); Events events = new Events();
				OAuthClient client = OAuthClient.withIssuer(server.getBaseUri().toString()).clientId(CLIENT).clientAuthentication(authentication(reads)).httpClient(TestTls.httpClient()).observer(events).clock(CLOCK).build();
				OAuthConfigurationException failure = assertThrows(OAuthConfigurationException.class, () -> TokenIntrospectionClient.withOAuthClient(client).expectedAudiences(Set.of(AUD)).build().validateResult(bearer("opaque")));
				assertEquals(suffix.contains("RS384") ? 1 : 0,reads.get()); assertSame(failure,events.failure.get()); assertEquals(1,events.preparedFailed.get()); assertEquals(1,events.will.get()); assertEquals(0,server.getHitCount("/inspect"));
			}
		}
	}
	@TestFactory @NonNull Stream<@NonNull DynamicTest> equivalentExplicitIntrospectionEndpointRetainsConfiguredRoleRestrictions() {
		return Stream.of("https://ISSUER.EXAMPLE/inspect", "https://issuer.example:443/inspect", "https://issuer.example/in%73pect?q=%2f").map(configured -> DynamicTest.dynamicTest(configured, () -> {
			AtomicInteger reads = new AtomicInteger(); Events events = new Events();
			AuthorizationServerMetadata metadata = AuthorizationServerMetadata.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/a"))
					.tokenEndpoint(URI.create(ISSUER+"/t")).introspectionEndpoint(URI.create(configured)).introspectionEndpointAuthMethodsSupported(Set.of()).build();
			OAuthClient client = OAuthClient.withAuthorizationServerMetadata(metadata).clientId(CLIENT).clientAuthentication(ClientAuthentication.fromPrivateKeyJwt(budget -> { reads.incrementAndGet(); throw new IllegalStateException("TEST-ONLY-key"); })).observer(events).build();
			// URI equality retains exact path/query meaning but compares escape hex, host case and effective origin port.
			URI override = URI.create(configured.contains("%73") ? ISSUER+"/in%73pect?q=%2F" : ISSUER+"/inspect");
			OAuthConfigurationException failure = assertThrows(OAuthConfigurationException.class, () -> TokenIntrospectionClient.withOAuthClient(client).introspectionEndpoint(override).expectedAudiences(Set.of(AUD)).build().validateResult(bearer("opaque")));
			assertEquals(OAuthException.Reason.CLIENT_ASSERTION_ENDPOINT_MISMATCH,failure.getReason()); assertEquals(0,reads.get()); assertEquals(1,events.preparedFailed.get()); assertEquals(0,events.will.get());
		}));
	}

	private static void awaitWaitingForToken(@NonNull Thread thread) throws InterruptedException {
		long end = System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
		while (System.nanoTime()<end) {
			if (Arrays.stream(thread.getStackTrace()).anyMatch(frame -> frame.getClassName().equals(ClientCredentialsTokenSource.class.getName()) && frame.getMethodName().equals("await"))) return;
			Thread.sleep(1);
		}
		fail("The contender never entered the token wait path.");
	}

	private static @NonNull PendingAuthorizationSource source(@NonNull PendingAuthorization pending) {
		InMemoryPendingAuthorizationStore store = InMemoryPendingAuthorizationStore.builder().clock(CLOCK).build();
		pending.saveTo(store,"browser"); return PendingAuthorizationSource.fromStore(store,"browser");
	}
	private static @NonNull JwsSigner signer(@NonNull JwsAlgorithm algorithm) { return JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(),KEY.getPublicKey(),algorithm); }
	private static @NonNull ClientAssertionSigningKey key(@NonNull JwsAlgorithm algorithm) { return ClientAssertionSigningKey.withSigner(signer(algorithm)).keyId("key").build(); }
	private static @NonNull ClientAuthentication authentication(@NonNull AtomicInteger reads) { return ClientAuthentication.fromPrivateKeyJwt(budget -> { reads.incrementAndGet(); return key(JwsAlgorithm.PS256); }); }
	private static AuthorizationServerMetadata.@NonNull Builder metadataBuilder(@NonNull TestHttpsServer server) {
		return AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString()).authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token"))
				.revocationEndpoint(server.uri("/revoke")).introspectionEndpoint(server.uri("/inspect")).tokenEndpointAuthMethodsSupported(Set.of("private_key_jwt"))
				.revocationEndpointAuthMethodsSupported(Set.of("private_key_jwt")).introspectionEndpointAuthMethodsSupported(Set.of("private_key_jwt"))
				.tokenEndpointAuthSigningAlgValuesSupported(Set.of("PS256","RS256","RS384")).revocationEndpointAuthSigningAlgValuesSupported(Set.of("PS256","RS256","RS384"))
				.introspectionEndpointAuthSigningAlgValuesSupported(Set.of("PS256","RS256","RS384"));
	}
	private static @NonNull AuthorizationServerMetadata metadata(@NonNull TestHttpsServer server) { return metadataBuilder(server).build(); }
	private static OAuthClient.@NonNull Builder client(@NonNull AuthorizationServerMetadata metadata,@NonNull ClientAuthentication auth) {
		return OAuthClient.withAuthorizationServerMetadata(metadata).clientId(CLIENT).clientAuthentication(auth).httpClient(TestTls.httpClient()).clock(CLOCK);
	}
	private static @NonNull String tokens() { return "{\"access_token\":\"TEST-ONLY-access\",\"token_type\":\"Bearer\",\"expires_in\":300}"; }
	private static @NonNull JsonObject segment(@NonNull String compact,int part) throws Exception { return (JsonObject) JsonCodec.parse(Base64.getUrlDecoder().decode(compact.split("\\.",-1)[part]),JsonLimits.protocolDocument(64*1024)); }
	private static @NonNull Map<@NonNull String,@NonNull String> form(@NonNull String body) {
		Map<String,String> values = new LinkedHashMap<>();
		for (String pair : body.split("&",-1)) { String[] parts = pair.split("=",2); assertNull(values.put(URLDecoder.decode(parts[0],StandardCharsets.UTF_8),URLDecoder.decode(parts[1],StandardCharsets.UTF_8)),"No duplicate credentials"); }
		return values;
	}
	private static void verify(@NonNull String compact,@NonNull JwsAlgorithm algorithm) throws Exception {
		String[] parts = compact.split("\\.",-1); Signature verifier = Signature.getInstance(switch (algorithm) { case PS256 -> "RSASSA-PSS"; case RS256 -> "SHA256withRSA"; case RS384 -> "SHA384withRSA"; default -> throw new AssertionError(); });
		if (algorithm == JwsAlgorithm.PS256) verifier.setParameter(new PSSParameterSpec("SHA-256","MGF1",MGF1ParameterSpec.SHA256,32,1));
		verifier.initVerify(KEY.getPublicKey()); verifier.update((parts[0]+"."+parts[1]).getBytes(StandardCharsets.US_ASCII)); assertTrue(verifier.verify(Base64.getUrlDecoder().decode(parts[2])));
	}
	private static void pause(long millis) { try { Thread.sleep(millis); } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); } }
	private static final class Events implements AccessTokenObserver {
		final AtomicInteger enabled = new AtomicInteger(), used = new AtomicInteger(), will = new AtomicInteger(), did = new AtomicInteger(), failed = new AtomicInteger(), preparedFailed = new AtomicInteger();
		final AtomicReference<OAuthException> failure = new AtomicReference<>();
		@Override public void didEnableClientAssertionAudience(@NonNull ClientAssertionAudience audience) { assertEquals(ClientAssertionAudience.TOKEN_ENDPOINT,audience); this.enabled.incrementAndGet(); }
		@Override public void didUseClientAssertionAudience(@NonNull ClientAssertionAudience audience) { assertEquals(ClientAssertionAudience.TOKEN_ENDPOINT,audience); this.used.incrementAndGet(); }
		@Override public void willRequestEndpoint(@NonNull OAuthEndpoint role,@NonNull URI uri) { this.will.incrementAndGet(); }
		@Override public void didRequestEndpoint(@NonNull OAuthEndpoint role,@NonNull URI uri,@NonNull Integer status,@NonNull Duration elapsed) { this.did.incrementAndGet(); }
		@Override public void didFailEndpoint(@NonNull OAuthEndpoint role,@NonNull URI uri,@NonNull OAuthException exception,@NonNull Duration elapsed) { this.failed.incrementAndGet(); this.failure.set(exception); }
		@Override public void didFailClientAssertionPreparation(@NonNull OAuthEndpoint role,@NonNull OAuthException exception) { this.preparedFailed.incrementAndGet(); this.failure.set(exception); }
	}
}
