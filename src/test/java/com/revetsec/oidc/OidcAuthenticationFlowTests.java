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

import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.internal.oauth.OidcTransactionAccess;
import com.revetsec.jose.*;
import com.revetsec.oauth.*;
import com.revetsec.testing.*;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws.Algorithm;
import com.revetsec.json.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import org.jspecify.annotations.Nullable;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

final class OidcAuthenticationFlowTests {
	private static final URI CALLBACK = URI.create("https://rp.example/callback");
	private static final Instant NOW = Instant.parse("2026-09-29T12:00:00Z");
	private static final String ACCESS = "TEST-ONLY-access-sentinel";
	private static final String REFRESH = "TEST-ONLY-refresh-sentinel";
	private static final String CODE = "TEST-ONLY-code-sentinel";
	private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

	@Test
	void buildAndBeginDoNoIoAndEveryFlowGetsFreshSecretsAndOneOpenidScope() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcClient client = builder(server).scopes(Set.of("openid", "email")).build();
			assertEquals(0, server.getRequests().size());
			AuthorizationRedirect first = client.beginAuthentication(OidcAuthenticationOptions.builder()
					.scopes(Set.of("openid", "profile")).maxAge(Duration.ZERO).requiredAcrValues(Set.of("urn:2", "urn:1"))
					.prompt("login consent").loginHint("person+hint@example.test").applicationData(Map.of("return", "/home"))
					.responseMode(AuthorizationRequestOptions.ResponseMode.FORM_POST).build());
			QueryParameters query = QueryParameters.parse(first.getAuthorizationUri().getRawQuery());
			assertEquals(List.of("openid profile"), query.getValues("scope"));
			assertEquals(List.of("0"), query.getValues("max_age"));
			assertEquals(List.of("urn:1 urn:2"), query.getValues("acr_values"));
			assertEquals(List.of("login consent"), query.getValues("prompt"));
			assertEquals(List.of("form_post"), query.getValues("response_mode"));
			assertEquals(43, query.getValues("nonce").get(0).length());
			assertEquals(List.of("S256"), query.getValues("code_challenge_method"));
			assertEquals(Map.of("return", "/home"), first.getPendingAuthorization().getApplicationData());
			QueryParameters second = QueryParameters.parse(client.beginAuthentication().getAuthorizationUri().getRawQuery());
			for (String name : List.of("nonce", "state", "code_challenge")) assertNotEquals(query.getValues(name), second.getValues(name));
			assertEquals(0, server.getRequests().size());
		}
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> validatesBothPendingSourcesAndQueryOrFormPostBeforeTokenRelease() {
		return Stream.of("cookie-query", "store-query", "cookie-post", "store-post").map(mode -> DynamicTest.dynamicTest(mode, () -> {
			try (TestHttpsServer server = TestHttpsServer.start()) {
				OidcClient client = builder(server).build();
				boolean post = mode.endsWith("post");
				AuthorizationRedirect redirect = client.beginAuthentication(OidcAuthenticationOptions.builder()
						.maxAge(Duration.ZERO).requiredAcrValues(Set.of("urn:mfa"))
						.responseMode(post ? AuthorizationRequestOptions.ResponseMode.FORM_POST : AuthorizationRequestOptions.ResponseMode.QUERY)
						.applicationData(Map.of("app", "TEST-ONLY-app-data")).build());
				Map<String, String> claims = claims(server, nonce(redirect));
				claims.put("auth_time", Long.toString(NOW.getEpochSecond())); claims.put("acr", "\"urn:mfa\"");
				claims.put("amr", "[\"pwd\",\"mfa\"]"); claims.put("sid", "\"session-sentinel\"");
				claims.put("at_hash", JsonText.string(IdTokenHash.hash(JwsAlgorithm.RS256, ACCESS)));
				claims.put("c_hash", JsonText.string(IdTokenHash.hash(JwsAlgorithm.RS256, CODE)));
				String token = sign(claims, false); respond(server, "/token", 200, "application/json", response(token, "bEaReR"));
				PendingAuthorizationSource source;
				if (mode.startsWith("store")) {
					InMemoryPendingAuthorizationStore store = InMemoryPendingAuthorizationStore.builder().clock(CLOCK).build();
					redirect.getPendingAuthorization().saveTo(store, "browser-A"); source = PendingAuthorizationSource.fromStore(store, "browser-A");
				} else source = sealed(redirect);
				AuthorizationResponse callback = post ? AuthorizationResponse.fromFormBody(callbackQuery(redirect).getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8, null) : callback(redirect);
				OidcAuthentication authentication = client.completeAuthentication(callback, source, CALLBACK);
				assertEquals(server.getBaseUri().toString(), authentication.getIssuer()); assertEquals("subject", authentication.getSubject());
				assertEquals(token, authentication.getIdToken().toCompactSerialization());
				assertEquals(ACCESS, authentication.getTokens().getAccessToken().getValue());
				assertEquals(REFRESH, authentication.getTokens().getRefreshToken().orElseThrow().getValue());
				assertEquals(Set.of("openid"), authentication.getTokens().getGrantedScopes().orElseThrow());
				assertEquals(Optional.of(NOW), authentication.getAuthenticationTime());
				assertEquals(Optional.of("urn:mfa"), authentication.getAuthenticationContextClassReference());
				assertEquals(List.of("pwd", "mfa"), authentication.getAuthenticationMethodReferences());
				assertEquals(Optional.of("session-sentinel"), authentication.getSessionReference().getSessionId());
				assertTrue(authentication.getSessionReference().matchesNonce(nonce(redirect)));
				assertFalse(authentication.getSessionReference().matchesNonce("other"));
				assertEquals(Map.of("app", "TEST-ONLY-app-data"), authentication.getTokens().getApplicationData());
				for (String name : List.of("access_token", "refresh_token", "id_token")) assertTrue(authentication.getTokens().getParameter(name).isEmpty());
				assertEquals(1, server.getRequests().size());
				String body = new String(server.getRequests().get(0).getBody(), StandardCharsets.UTF_8);
				QueryParameters form = QueryParameters.parse(body);
				assertEquals(List.of(CODE), form.getValues("code"));
				assertEquals(List.of(CALLBACK.toString()), form.getValues("redirect_uri"));
				assertEquals(43, form.getValues("code_verifier").get(0).length());
				for (Object value : List.of(authentication, authentication.getIdToken(), authentication.getTokens(),
						authentication.getSessionReference(), client, redirect.getPendingAuthorization()))
					assertRedacted(value.toString(), List.of(token, ACCESS, REFRESH, CODE, nonce(redirect), "TEST-ONLY-app-data", "subject", "session-sentinel"));
				if (mode.startsWith("store")) {
					assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_NOT_FOUND, assertThrows(OAuthValidationException.class,
							() -> client.completeAuthentication(callback, source, CALLBACK)).getReason()); assertEquals(1, server.getRequests().size());
				}
			}
		}));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> rejectsSuccessfulEndpointTokensBeforeCreatingAuthentication() {
		record Case(@NonNull String name, OidcValidationException.@NonNull Reason reason, @NonNull Consumer<@NonNull Map<@NonNull String, @NonNull String>> change) { }
		return Stream.of(
				new Case("signature", OidcValidationException.Reason.ID_TOKEN_SIGNATURE_INVALID, c -> { }),
				new Case("swapped nonce", OidcValidationException.Reason.NONCE_MISMATCH, c -> c.put("nonce", "\"OTHER-FLOW\"")),
				new Case("issuer", OidcValidationException.Reason.ISSUER_MISMATCH, c -> c.put("iss", "\"https://attacker.example\"")),
				new Case("audience", OidcValidationException.Reason.AUDIENCE_MISMATCH, c -> c.put("aud", "\"attacker-client\"")),
				new Case("max age zero", OidcValidationException.Reason.AUTH_TIME_MISSING, c -> c.remove("auth_time")),
				new Case("acr", OidcValidationException.Reason.INSUFFICIENT_ACR, c -> c.put("acr", "\"urn:weak\"")),
				new Case("access hash", OidcValidationException.Reason.ACCESS_TOKEN_HASH_MISMATCH, c -> c.put("at_hash", "\"wrong\"")),
				new Case("code hash", OidcValidationException.Reason.CODE_HASH_MISMATCH, c -> c.put("c_hash", "\"wrong\"")),
				new Case("expired", OidcValidationException.Reason.EXPIRED, c -> c.put("exp", Long.toString(NOW.minusSeconds(60).getEpochSecond()))))
				.map(test -> DynamicTest.dynamicTest(test.name(), () -> {
					try (TestHttpsServer server = TestHttpsServer.start()) {
						List<String> events = new ArrayList<>(); AtomicReference<OidcValidationException> observed = new AtomicReference<>();
						OidcObserver observer = new OidcObserver() {
							@Override public void didRejectIdToken(@NonNull OidcValidationException failure) { observed.set(failure); events.add(failure.toString()); throw new IllegalStateException("hook failure"); }
							@Override public void didCompleteAuthentication() { events.add("completed"); }
							@Override public void didRequestEndpoint(@NonNull OAuthEndpoint kind, @NonNull URI uri, @NonNull Integer status, @NonNull Duration elapsed) { events.add(uri.toString()); }
						};
						OidcClient client = builder(server).observer(observer).build();
						AuthorizationRedirect redirect = client.beginAuthentication(OidcAuthenticationOptions.builder().maxAge(Duration.ZERO).requiredAcrValues(Set.of("urn:mfa")).build());
						Map<String, String> claims = claims(server, nonce(redirect)); claims.put("auth_time", Long.toString(NOW.getEpochSecond())); claims.put("acr", "\"urn:mfa\"");
						test.change().accept(claims); String token = sign(claims, test.name().equals("signature"));
						respond(server, "/token", 200, "application/json", response(token, "Bearer"));
						OidcValidationException failure = assertThrows(OidcValidationException.class, () -> client.completeAuthentication(callback(redirect), sealed(redirect), CALLBACK));
						assertEquals(test.reason(), failure.getReason()); assertSame(failure, observed.get()); assertFalse(events.contains("completed"));
						assertNull(failure.getCause()); assertEquals(0, failure.getSuppressed().length);
						assertRedacted(failure.toString() + events, List.of(token, ACCESS, REFRESH, CODE, nonce(redirect)));
						assertEquals(1, server.getRequests().size());
					}
				}));
	}

	@Test
	void idTokenIsRequiredAndBearerTypeIsRequired() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcClient client = builder(server).build(); AuthorizationRedirect redirect = client.beginAuthentication();
			respond(server, "/token", 200, "application/json", response(null, "Bearer"));
			assertEquals(OidcValidationException.Reason.ID_TOKEN_MISSING, assertThrows(OidcValidationException.class,
					() -> client.completeAuthentication(callback(redirect), sealed(redirect), CALLBACK)).getReason());
			respond(server, "/token", 200, "application/json", response(sign(claims(server, nonce(redirect)), false), "DPoP"));
			assertEquals(OidcValidationException.Reason.TOKEN_TYPE_UNSUPPORTED, assertThrows(OidcValidationException.class,
					() -> client.completeAuthentication(callback(redirect), sealed(redirect), CALLBACK)).getReason());
			assertEquals(2, server.getRequests().size());
		}
	}

	@Test
	void flowKindsCannotBePromotedOrDowngradedBeforeCodeExchange() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcClient client = builder(server).build(); OAuthClient oauth = OAuthClient.withAuthorizationServerMetadata(metadata(server).oauthMetadata())
					.clientId("client").clientAuthentication(ClientAuthentication.noneInstance()).redirectUri(CALLBACK).clock(CLOCK).httpClient(TestTls.httpClient()).build();
			AuthorizationRedirect plain = oauth.beginAuthorization();
			assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_INVALID, assertThrows(OAuthValidationException.class,
					() -> client.completeAuthentication(callback(plain), sealed(plain), CALLBACK)).getReason());
			AuthorizationRedirect oidc = client.beginAuthentication();
			assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_INVALID, assertThrows(OAuthValidationException.class,
					() -> oauth.completeAuthorization(callback(oidc), sealed(oidc), CALLBACK)).getReason());
			assertEquals(0, server.getRequests().size());
		}
	}

	@Test
	void localCallbackChecksRejectBeforeCodeOrKeyRequests() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcClient client = builder(server).issuerParameterPolicy(IssuerParameterPolicy.REQUIRED).build();
			AuthorizationRedirect redirect = client.beginAuthentication(); PendingAuthorizationSource source = sealed(redirect);
			assertEquals(OAuthException.Reason.STATE_MISMATCH, assertThrows(OAuthValidationException.class, () -> client.completeAuthentication(AuthorizationResponse.fromQueryString("state=wrong&code=" + CODE), source, CALLBACK)).getReason());
			assertEquals(OAuthException.Reason.CALLBACK_URI_MISMATCH, assertThrows(OAuthValidationException.class, () -> client.completeAuthentication(callback(redirect), source, URI.create("https://rp.example/other"))).getReason());
			assertEquals(OAuthException.Reason.ISSUER_MISSING, assertThrows(OAuthValidationException.class, () -> client.completeAuthentication(callback(redirect), source, CALLBACK)).getReason());
			assertEquals(OAuthException.Reason.ISSUER_MISMATCH, assertThrows(OAuthValidationException.class, () -> client.completeAuthentication(AuthorizationResponse.fromQueryString(callbackQuery(redirect) + "&iss=https%3A%2F%2Fattacker.example"), source, CALLBACK)).getReason());
			assertEquals(OAuthException.Reason.RESPONSE_MODE_MISMATCH, assertThrows(OAuthValidationException.class, () -> client.completeAuthentication(AuthorizationResponse.fromFormBody(callbackQuery(redirect).getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8, null), source, CALLBACK)).getReason());
			assertEquals(OAuthException.Reason.CLIENT_MISMATCH, assertThrows(OAuthValidationException.class, () -> builder(server).clientId("different").build().completeAuthentication(callback(redirect), source, CALLBACK)).getReason());
			OidcProviderMetadata drift = OidcProviderMetadata.withIssuer(server.getBaseUri().toString()).authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/changed")).jwksUri(server.uri("/jwks")).build();
			OidcClient changed = OidcClient.withProviderMetadata(drift).clientId("client").redirectUri(CALLBACK).clock(CLOCK).httpClient(TestTls.httpClient()).jsonWebKeySource(keys()).build();
			assertEquals(OAuthException.Reason.METADATA_ENDPOINT_DRIFT, assertThrows(OAuthValidationException.class, () -> changed.completeAuthentication(AuthorizationResponse.fromQueryString(callbackQuery(redirect) + "&iss=" + URLEncoder.encode(server.getBaseUri().toString(), StandardCharsets.UTF_8)), source, CALLBACK)).getReason());
			assertEquals(0, server.getRequests().size());
		}
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> expiredOidcPendingIsRejectedBeforeTokenOrKeyIo() {
		return Stream.of("sealed", "store").map(mode -> DynamicTest.dynamicTest(mode, () -> {
			try (TestHttpsServer server = TestHttpsServer.start()) {
				TestClock clock = TestClock.fromInstant(NOW);
				OidcClient client = builder(server).clock(clock).build();
				AuthorizationRedirect redirect = client.beginAuthentication();
				PendingAuthorizationSource source;
				if (mode.equals("sealed")) {
					StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("oidc-expiry")).clock(clock).build();
					source = PendingAuthorizationSource.fromSealedForm(redirect.getPendingAuthorization().toSealedForm(sealer, "oidc-expiry"), sealer, "oidc-expiry");
				} else {
					// Storage deliberately retains the entry; the OIDC transaction must enforce its own expiry.
					InMemoryPendingAuthorizationStore store = InMemoryPendingAuthorizationStore.builder().clock(CLOCK).build();
					redirect.getPendingAuthorization().saveTo(store, "browser");
					source = PendingAuthorizationSource.fromStore(store, "browser");
				}
				clock.advance(Duration.ofMinutes(16));
				OAuthValidationException failure = assertThrows(OAuthValidationException.class,
						() -> client.completeAuthentication(callback(redirect), source, CALLBACK));
				assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_EXPIRED, failure.getReason());
				assertEquals(0, server.getRequests().size());
			}
		}));
	}

	@Test
	void pendingLifetimeUsesRegistryDefaultAndNullRestoresIt() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			Duration expected = Duration.ofMinutes(15);
			assertEquals(expected, com.revetsec.internal.Limits.PENDING_STATE_LIFETIME.getDefaultDuration());
			OidcClient.Builder configured = builder(server);
			PendingAuthorization fresh = configured.build().beginAuthentication().getPendingAuthorization();
			assertEquals(expected, Duration.between(fresh.getCreatedAt(), fresh.getExpiresAt()));
			PendingAuthorization overridden = configured.pendingAuthorizationLifetime(Duration.ofMinutes(2)).build().beginAuthentication().getPendingAuthorization();
			assertEquals(Duration.ofMinutes(2), Duration.between(overridden.getCreatedAt(), overridden.getExpiresAt()));
			PendingAuthorization reset = configured.pendingAuthorizationLifetime(null).build().beginAuthentication().getPendingAuthorization();
			assertEquals(expected, Duration.between(reset.getCreatedAt(), reset.getExpiresAt()));
			assertEquals(0, server.getRequests().size());
		}
	}

	@Test
	void nullableFlagsRestoreStrictDefaults() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcProviderMetadata unadvertised = OidcProviderMetadata.withIssuer(server.getBaseUri().toString())
					.authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token")).jwksUri(server.uri("/jwks"))
					.codeChallengeMethodsSupported(null).build();
			OidcClient.Builder configured = OidcClient.withProviderMetadata(unadvertised).clientId("client").redirectUri(CALLBACK)
					.clock(CLOCK).httpClient(TestTls.httpClient()).jsonWebKeySource(keys()).requirePkceAdvertised(true);
			assertEquals(OAuthException.Reason.PKCE_UNSUPPORTED, assertThrows(OAuthValidationException.class, () -> configured.build().beginAuthentication()).getReason());
			assertNotNull(configured.requirePkceAdvertised(null).acknowledgeUnpatchedRuntime(true).acknowledgeUnpatchedRuntime(null).build().beginAuthentication());
			assertSame(configured, configured.redirectUri(URI.create("http://127.0.0.1/callback")).allowInsecureLoopback(true));
			assertNotNull(configured.build());
			assertThrows(IllegalArgumentException.class, () -> configured.allowInsecureLoopback(null).build());
			OidcProviderMetadata restored = OidcProviderMetadata.withIssuer(server.getBaseUri().toString())
					.authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token")).jwksUri(server.uri("/jwks"))
					.authorizationResponseIssuerSupported(true).authorizationResponseIssuerSupported(null).build();
			assertFalse(restored.oauthMetadata().isAuthorizationResponseIssuerSupported());
			assertEquals(0, server.getRequests().size());
		}
	}

	@Test
	void separateProviderClientsNeverPoolRemoteSigningKeys() throws Exception {
		try (TestHttpsServer first = TestHttpsServer.start(); TestHttpsServer second = TestHttpsServer.start()) {
			OidcClient firstClient = builder(first).jsonWebKeySource(null).build();
			OidcClient secondClient = builder(second).jsonWebKeySource(null).build();
			AuthorizationRedirect secondRedirect = secondClient.beginAuthentication();
			String secondToken = TestJws.withAlgorithm(Algorithm.RS256).kid("foreign")
					.payload(JsonText.object(new ArrayList<>(claims(second, nonce(secondRedirect)).entrySet())))
					.sign(Fixture.IDP_SIGNING_RSA_3072.getPrivateKey());
			respond(second, "/token", 200, "application/json", response(secondToken, "Bearer"));
			respond(second, "/jwks", 200, "application/json", TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_3072).kid("foreign").alg("RS256").toKeySetJson());
			assertEquals("subject", secondClient.completeAuthentication(callback(secondRedirect), sealed(secondRedirect), CALLBACK).getSubject());
			AuthorizationRedirect firstRedirect = firstClient.beginAuthentication();
			// Even an attacker-controlled claim set naming the first issuer and its pending nonce cannot import the second provider's key.
			String attack = TestJws.withAlgorithm(Algorithm.RS256).kid("foreign")
					.payload(JsonText.object(new ArrayList<>(claims(first, nonce(firstRedirect)).entrySet())))
					.sign(Fixture.IDP_SIGNING_RSA_3072.getPrivateKey());
			respond(first, "/token", 200, "application/json", response(attack, "Bearer"));
			respond(first, "/jwks", 200, "application/json", TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("key").alg("RS256").toKeySetJson());
			OidcValidationException failure = assertThrows(OidcValidationException.class,
					() -> firstClient.completeAuthentication(callback(firstRedirect), sealed(firstRedirect), CALLBACK));
			assertEquals(OidcValidationException.Reason.ID_TOKEN_SIGNATURE_INVALID, failure.getReason());
			assertEquals(Optional.of(JoseException.Reason.UNKNOWN_KEY), failure.getJoseReason());
			assertTrue(first.getHitCount("/jwks") >= 1); assertEquals(1, second.getHitCount("/jwks"));
			assertNull(failure.getCause()); assertFalse(failure.toString().contains(attack));
		}
	}

	@Test
	void defectiveStateOnlyStoreStillCannotTransferOidcToAnotherBrowser() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcClient client = builder(server).build(); AuthorizationRedirect redirect = client.beginAuthentication();
			AtomicReference<String> saved = new AtomicReference<>();
			PendingAuthorizationStore broken = new PendingAuthorizationStore() {
				@Override public void save(@NonNull String binding, @NonNull String state, @NonNull String opaque, @NonNull Instant expires) { saved.set(opaque); }
				@Override public @NonNull Optional<@NonNull String> consume(@NonNull String binding, @NonNull String state) { return Optional.ofNullable(saved.getAndSet(null)); }
			};
			redirect.getPendingAuthorization().saveTo(broken, "browser-A");
			assertEquals(OAuthException.Reason.BROWSER_BINDING_MISMATCH, assertThrows(OAuthValidationException.class,
					() -> client.completeAuthentication(callback(redirect), PendingAuthorizationSource.fromStore(broken, "browser-B"), CALLBACK)).getReason());
			assertEquals(0, server.getRequests().size());
		}
	}

	@Test
	void requestAndBuildPoliciesFailClosedAndNullRestoresDefaults() throws Exception {
		for (String prompt : List.of("none login", "", "unknown", "login login", "login  consent")) assertThrows(IllegalArgumentException.class, () -> OidcAuthenticationOptions.builder().prompt(prompt));
		for (Duration age : List.of(Duration.ofSeconds(-1), Duration.ofMillis(1))) assertThrows(IllegalArgumentException.class, () -> OidcAuthenticationOptions.builder().maxAge(age));
		assertThrows(IllegalArgumentException.class, () -> OidcAuthenticationOptions.builder().requiredAcrValues(Set.of("has space")));
		for (String name : List.of("nonce", "max_age", "acr_values", "state", "code_challenge", "request_uri")) assertThrows(IllegalArgumentException.class, () -> OidcAuthenticationOptions.builder().additionalParameters(Map.of(name, "sentinel")));
		try (TestHttpsServer server = TestHttpsServer.start()) {
			assertThrows(IllegalArgumentException.class, () -> builder(server).idTokenSigningAlgorithms(Set.of(JwsAlgorithm.HS256)).build());
			assertThrows(IllegalArgumentException.class, () -> builder(server).idTokenSigningAlgorithms(Set.of(JwsAlgorithm.ES256)).build());
			assertThrows(IllegalArgumentException.class, () -> builder(server).clockSkew(Duration.ofMinutes(6)));
			assertThrows(IllegalArgumentException.class, () -> builder(server).redirectUri(URI.create("http://rp.example/callback")).build());
			assertThrows(IllegalArgumentException.class, () -> builder(server).trustedAudiences(Set.of("")).build());
			OidcClient client = builder(server).scopes(Set.of("email")).requiredAcrValues(Set.of("urn:mfa")).build();
			AuthorizationRedirect redirect = client.beginAuthentication(OidcAuthenticationOptions.builder().scopes(Set.of()).requiredAcrValues(Set.of()).maxAge(Duration.ZERO).maxAge(null).prompt("login").prompt(null).build());
			QueryParameters query = QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()); assertEquals(List.of("openid"), query.getValues("scope"));
			assertTrue(query.getValues("max_age").isEmpty()); assertTrue(query.getValues("acr_values").isEmpty()); assertTrue(query.getValues("prompt").isEmpty());
			assertEquals(0, server.getRequests().size());
		}
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> acrValuesRejectEmptyNonAsciiAndControlCharactersBeforeLogin() {
		return Stream.of("", "\u007f", "urn:mfaé", "urn:mfa\t", "urn:mfa\n")
				.map(value -> DynamicTest.dynamicTest("invalid ACR " + value.length() + ":" + Integer.toHexString(value.hashCode()),
						() -> assertThrows(IllegalArgumentException.class,
								() -> OidcAuthenticationOptions.builder().requiredAcrValues(Set.of(value)))));
	}

	@Test
	void normalCompletionResolvesRemoteKeysOnlyAfterTokenPost() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			java.util.concurrent.atomic.AtomicInteger verified = new java.util.concurrent.atomic.AtomicInteger();
			java.util.concurrent.atomic.AtomicInteger completed = new java.util.concurrent.atomic.AtomicInteger();
			OidcClient client = builder(server).jsonWebKeySource(null).observer(new OidcObserver() {
				@Override public void didValidateJwt(@NonNull JwsAlgorithm algorithm, @NonNull Duration elapsed) { verified.incrementAndGet(); }
				@Override public void didCompleteAuthentication() { completed.incrementAndGet(); throw new IllegalStateException("ignored observer"); }
			}).build(); AuthorizationRedirect redirect = client.beginAuthentication();
			respond(server, "/token", 200, "application/json", response(sign(claims(server, nonce(redirect)), false), "Bearer"));
			respond(server, "/jwks", 200, "application/json", TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("key").alg("RS256").toKeySetJson());
			assertEquals(0, server.getRequests().size()); client.completeAuthentication(callback(redirect), sealed(redirect), CALLBACK);
			assertEquals(1, verified.get()); assertEquals(1, completed.get());
			assertEquals(List.of("/token", "/jwks"), server.getRequests().stream().map(request -> request.getUri().getPath()).toList());
		}
	}

	@Test
	void exhaustedCodeExchangeBudgetCannotStartAFreshJwksLookup() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcObserver slow = new OidcObserver() {
				@Override public void didRequestEndpoint(@NonNull OAuthEndpoint endpoint, @NonNull URI uri, @NonNull Integer status, @NonNull Duration elapsed) {
					if (endpoint == OAuthEndpoint.TOKEN) {
						try { new java.util.concurrent.CountDownLatch(1).await(2, java.util.concurrent.TimeUnit.SECONDS); }
						catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
					}
				}
			};
			OidcClient client = builder(server).jsonWebKeySource(null).requestTimeout(Duration.ofSeconds(1))
					.totalDeadline(Duration.ofSeconds(1)).observer(slow).build();
			AuthorizationRedirect redirect = client.beginAuthentication();
			respond(server, "/token", 200, "application/json", response(sign(claims(server, nonce(redirect)), false), "Bearer"));
			JsonWebKeySetUnavailableException failure = assertThrows(JsonWebKeySetUnavailableException.class,
					() -> client.completeAuthentication(callback(redirect), sealed(redirect), CALLBACK));
			assertEquals(com.revetsec.ErrorCategory.TRANSPORT, failure.getCategory());
			assertEquals(1, server.getHitCount("/token")); assertEquals(0, server.getHitCount("/jwks"));
			assertRedacted(failure.toString(), List.of(ACCESS, REFRESH, CODE, nonce(redirect)));
		}
	}

	private static void respond(@NonNull TestHttpsServer server, @NonNull String path, int status, @NonNull String mediaType, @NonNull String body) { server.script(path, TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.withStatus(status).header("Content-Type", mediaType).body(body.getBytes(StandardCharsets.UTF_8)).build())); }
	private static OidcClient.@NonNull Builder builder(@NonNull TestHttpsServer server) {
		return OidcClient.withProviderMetadata(metadata(server)).clientId("client").redirectUri(CALLBACK).clock(CLOCK).httpClient(TestTls.httpClient()).jsonWebKeySource(keys());
	}
	private static @NonNull StaticJsonWebKeySource keys() { return StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("key").alg("RS256").toKeySetJson())); }
	private static @NonNull OidcProviderMetadata metadata(@NonNull TestHttpsServer server) { return OidcProviderMetadata.withIssuer(server.getBaseUri().toString()).authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token")).jwksUri(server.uri("/jwks")).build(); }
	private static @NonNull PendingAuthorizationSource sealed(@NonNull AuthorizationRedirect redirect) { StateSealer sealer = TestSealers.fromFixedKey(); return PendingAuthorizationSource.fromSealedForm(redirect.getPendingAuthorization().toSealedForm(sealer, "oidc"), sealer, "oidc"); }
	private static @NonNull String nonce(@NonNull AuthorizationRedirect redirect) throws Exception { return QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()).getValues("nonce").get(0); }
	private static @NonNull String callbackQuery(@NonNull AuthorizationRedirect redirect) throws Exception { return "state=" + QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()).getValues("state").get(0) + "&code=" + CODE; }
	private static @NonNull AuthorizationResponse callback(@NonNull AuthorizationRedirect redirect) throws Exception { return AuthorizationResponse.fromQueryString(callbackQuery(redirect)); }
	private static @NonNull Map<@NonNull String, @NonNull String> claims(@NonNull TestHttpsServer server, @NonNull String nonce) { Map<String, String> claims = new LinkedHashMap<>(); claims.put("iss", JsonText.string(server.getBaseUri().toString())); claims.put("sub", "\"subject\""); claims.put("aud", "\"client\""); claims.put("exp", Long.toString(NOW.plusSeconds(300).getEpochSecond())); claims.put("iat", Long.toString(NOW.getEpochSecond())); claims.put("nonce", JsonText.string(nonce)); return claims; }
	private static @NonNull String sign(@NonNull Map<@NonNull String, @NonNull String> claims, boolean forged) { return TestJws.withAlgorithm(Algorithm.RS256).kid("key").payload(JsonText.object(new ArrayList<>(claims.entrySet()))).sign(forged ? Fixture.NEGATIVE_ATTACKER_RSA_2048.getPrivateKey() : Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()); }
	private static @NonNull String response(@Nullable String token, @NonNull String type) { return "{\"access_token\":" + JsonText.string(ACCESS) + ",\"refresh_token\":" + JsonText.string(REFRESH) + ",\"token_type\":" + JsonText.string(type) + (token == null ? "" : ",\"id_token\":" + JsonText.string(token)) + "}"; }
	private static void assertRedacted(@NonNull String text, @NonNull List<@NonNull String> secrets) { for (String secret : secrets) assertFalse(text.contains(secret), "A string form disclosed a sentinel"); }
}
