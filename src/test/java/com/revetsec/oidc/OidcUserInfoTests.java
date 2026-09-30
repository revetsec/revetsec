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

import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.jose.*;
import com.revetsec.oauth.*;
import com.revetsec.testing.*;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws.Algorithm;
import com.revetsec.json.*;
import org.junit.jupiter.api.*;
import org.jspecify.annotations.Nullable;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.Consumer;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

final class OidcUserInfoTests {
	private static final URI CALLBACK = URI.create("https://rp.example/callback");
	private static final Instant NOW = Instant.parse("2026-09-29T12:00:00Z");
	private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
	private static final String ACCESS = "TEST-ONLY-userinfo-access";
	private static final String REFRESH = "TEST-ONLY-userinfo-refresh";
	private static final String SUBJECT = "TEST-ONLY-userinfo-subject";
	private static final String EMAIL = "TEST-ONLY-email@example.test";
	private static final String DISCOVERY = "/.well-known/openid-configuration";

	@Test
	void jsonUsesHeaderOnlyExactSubjectNoResultCacheAndNoDistributedClaimResolution() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			List<String> events = new ArrayList<>();
			OidcClient client = builder(server).observer(new OidcObserver() {
				@Override public void willRequestEndpoint(OAuthEndpoint endpoint, URI uri) { if (endpoint == OAuthEndpoint.USERINFO) { events.add(uri.toString()); throw new IllegalStateException("ignored hook"); } }
				@Override public void didFetchUserInfo(Boolean signed) { events.add("success:" + signed); throw new IllegalStateException("ignored hook"); }
			}).build();
			OidcAuthentication authentication = authenticate(server, client, ACCESS, 300);
			respond(server, 200, "application/json; charset=UTF-8", "{\"sub\":" + JsonText.string(SUBJECT) + ",\"email\":" + JsonText.string(EMAIL) + ",\"email_verified\":true,\"_claim_names\":{\"phone_number\":\"src\"},\"_claim_sources\":{\"src\":{\"endpoint\":" + JsonText.string(server.uri("/private").toString()) + "}}}");
			OidcUserInfo result = client.fetchUserInfo(authentication); client.fetchUserInfo(authentication);
			assertEquals(server.getBaseUri().toString(), result.getIssuer()); assertEquals(SUBJECT, result.getSubject());
			assertEquals(Optional.of(EMAIL), result.getEmail()); assertEquals(Optional.of(true), result.getEmailVerified()); assertFalse(result.isSigned());
			assertTrue(result.getClaims().toJson().contains(EMAIL)); assertRedacted(result.toString() + events);
			assertEquals(List.of(server.uri("/userinfo").toString(), "success:false", server.uri("/userinfo").toString(), "success:false"), events);
			assertEquals(2, server.getHitCount("/userinfo")); assertEquals(0, server.getHitCount("/private")); assertEquals(0, server.getHitCount("/jwks"));
			for (TestHttpsServer.RecordedRequest request : server.getRequests("/userinfo")) {
				assertEquals("GET", request.getMethod()); assertEquals(Optional.of("Bearer " + ACCESS), request.getHeader("Authorization"));
				assertNull(request.getUri().getRawQuery()); assertEquals(0, request.getBody().length);
			}
		}
	}

	@TestFactory
	Stream<DynamicTest> userInfoSubjectAcceptsTheExactAsciiBounds() {
		return Stream.of("s".repeat(255), "\u007f", "s".repeat(254) + "\u007f")
				.map(subject -> DynamicTest.dynamicTest("ASCII subject length " + subject.length(), () -> {
					byte[] body = ("{\"sub\":" + JsonText.string(subject) + "}").getBytes(StandardCharsets.UTF_8);
					assertEquals(subject, UserInfoValidator.json(body, subject).findString("sub").orElseThrow());
				}));
	}

	@TestFactory
	Stream<DynamicTest> malformedOrMismatchedJsonNeverReleasesClaims() {
		record Case(String body, OidcValidationException.Reason reason) { }
		List<Case> cases = new ArrayList<>();
		for (String body : List.of("{}", "{\"sub\":null}", "{\"sub\":1}", "{\"sub\":[]}", "{\"sub\":\"\"}", "{\"sub\":\"é\"}", "{\"sub\":" + JsonText.string("s".repeat(256)) + "}", "[]", "null", "{", "{\"sub\":" + JsonText.string(SUBJECT) + ",\"sub\":" + JsonText.string(SUBJECT) + "}")) cases.add(new Case(body, OidcValidationException.Reason.USERINFO_MALFORMED));
		cases.add(new Case("{\"sub\":\"other\",\"secret\":" + JsonText.string(ACCESS) + "}", OidcValidationException.Reason.USERINFO_SUBJECT_MISMATCH));
		cases.add(new Case("{\"sub\":" + JsonText.string(SUBJECT.toUpperCase(Locale.ROOT)) + "}", OidcValidationException.Reason.USERINFO_SUBJECT_MISMATCH));
		return java.util.stream.IntStream.range(0, cases.size()).mapToObj(i -> DynamicTest.dynamicTest("JSON " + i, () -> {
			try (TestHttpsServer server = TestHttpsServer.start()) {
				AtomicReference<OidcValidationException> observed = new AtomicReference<>(); AtomicInteger success = new AtomicInteger();
				OidcClient client = builder(server).observer(new OidcObserver() {
					@Override public void didRejectUserInfo(OidcValidationException failure) { observed.set(failure); throw new IllegalStateException(ACCESS); }
					@Override public void didFetchUserInfo(Boolean signed) { success.incrementAndGet(); }
				}).build(); OidcAuthentication authentication = authenticate(server, client, ACCESS, 300);
				Case test = cases.get(i); respond(server, 200, "application/json", test.body());
				OidcValidationException failure = assertThrows(OidcValidationException.class, () -> client.fetchUserInfo(authentication));
				assertEquals(test.reason(), failure.getReason()); assertSame(failure, observed.get()); assertEquals(0, success.get());
				assertSafeFailure(failure);
				respond(server, 200, "application/json", json()); assertEquals(SUBJECT, client.fetchUserInfo(authentication).getSubject());
				assertEquals(2, server.getHitCount("/userinfo"));
			}
		}));
	}

	@Test
	void optionalProfileGettersDoNotCoerceStringsNumbersOrNullAndUtf8IsStrict() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcClient client = builder(server).build(); OidcAuthentication auth = authenticate(server, client, ACCESS, 300);
			for (String value : List.of("\"true\"", "1", "null", "{}", "[]")) {
				respond(server, 200, "application/json", "{\"sub\":" + JsonText.string(SUBJECT) + ",\"email\":1,\"email_verified\":" + value + "}");
				OidcUserInfo result = client.fetchUserInfo(auth); assertTrue(result.getEmail().isEmpty()); assertTrue(result.getEmailVerified().isEmpty());
			}
			server.script("/userinfo", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.withStatus(200).header("Content-Type", "application/json").body(new byte[]{(byte) 0xc0, (byte) 0xaf}).build()));
			assertEquals(OidcValidationException.Reason.USERINFO_MALFORMED, assertThrows(OidcValidationException.class, () -> client.fetchUserInfo(auth)).getReason());
		}
	}

	@Test
	void signedUserInfoRequiresIssuerAndAudienceButDatesAreOptionalOnlyInThisProfile() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcClient client = builder(server).userInfoSignedResponseAlgorithm(JwsAlgorithm.RS256).trustedAudiences(Set.of("trusted")).build();
			OidcAuthentication auth = authenticate(server, client, ACCESS, 300);
			Map<String,String> claims = claims(server); String compact = sign(claims, false);
			respond(server, 200, "application/jwt", compact);
			OidcUserInfo result = client.fetchUserInfo(auth); assertTrue(result.isSigned()); assertEquals(SUBJECT, result.getSubject()); assertRedacted(result.toString());
			JwtValidator ordinary = JwtValidator.withIssuer(server.getBaseUri().toString()).expectedAudiences(Set.of("client")).jsonWebKeySource(keys()).clock(CLOCK).build();
			assertEquals(JoseException.Reason.MISSING_CLAIM, assertThrows(JoseException.class, () -> ordinary.validate(compact)).getReason());
			claims.put("aud", "[\"client\",\"trusted\"]"); claims.put("exp", Long.toString(NOW.plusSeconds(60).getEpochSecond())); claims.put("iat", Long.toString(NOW.getEpochSecond()));
			respond(server, 200, "application/jwt; charset=utf-8", sign(claims, false)); assertEquals(SUBJECT, client.fetchUserInfo(auth).getSubject());
		}
	}

	@TestFactory
	Stream<DynamicTest> rejectsSignedClaimAndSignatureFailuresWithSafeOidcAndJoseReasons() {
		record Case(String name, OidcValidationException.Reason reason, Consumer<Map<String,String>> change) { }
		return Stream.of(
			new Case("signature", OidcValidationException.Reason.USERINFO_SIGNATURE_INVALID, c -> {}),
			new Case("issuer absent", OidcValidationException.Reason.MISSING_CLAIM, c -> c.remove("iss")),
			new Case("aud absent", OidcValidationException.Reason.MISSING_CLAIM, c -> c.remove("aud")),
			new Case("subject absent", OidcValidationException.Reason.MISSING_CLAIM, c -> c.remove("sub")),
			new Case("issuer changed", OidcValidationException.Reason.ISSUER_MISMATCH, c -> c.put("iss", "\"https://attacker.example\"")),
			new Case("issuer slash", OidcValidationException.Reason.ISSUER_MISMATCH, c -> { String issuer = Objects.requireNonNull(c.get("iss")); c.put("iss", JsonText.string(issuer.substring(1, issuer.length()-1) + "/")); }),
			new Case("aud changed", OidcValidationException.Reason.AUDIENCE_MISMATCH, c -> c.put("aud", "\"other\"")),
			new Case("untrusted extra", OidcValidationException.Reason.UNTRUSTED_AUDIENCE, c -> c.put("aud", "[\"client\",\"other\"]")),
			new Case("subject changed", OidcValidationException.Reason.USERINFO_SUBJECT_MISMATCH, c -> c.put("sub", "\"other\"")),
			new Case("expired", OidcValidationException.Reason.EXPIRED, c -> c.put("exp", Long.toString(NOW.getEpochSecond()))),
			new Case("issued future", OidcValidationException.Reason.ISSUED_IN_FUTURE, c -> c.put("iat", Long.toString(NOW.plusSeconds(1).getEpochSecond()))),
			new Case("not yet", OidcValidationException.Reason.NOT_YET_VALID, c -> c.put("nbf", Long.toString(NOW.plusSeconds(1).getEpochSecond()))),
			new Case("bad exp", OidcValidationException.Reason.USERINFO_MALFORMED, c -> c.put("exp", "\"future\"")),
			new Case("bad iat", OidcValidationException.Reason.USERINFO_MALFORMED, c -> c.put("iat", "null")),
			new Case("bad aud", OidcValidationException.Reason.USERINFO_MALFORMED, c -> c.put("aud", "1")))
		.map(test -> DynamicTest.dynamicTest(test.name(), () -> {
			try (TestHttpsServer server = TestHttpsServer.start()) {
				OidcClient client = builder(server).clockSkew(Duration.ZERO).userInfoSignedResponseAlgorithm(JwsAlgorithm.RS256).build(); OidcAuthentication auth = authenticate(server, client, ACCESS, 300);
				Map<String,String> claims = claims(server); test.change().accept(claims); String compact = sign(claims, test.name().equals("signature")); respond(server, 200, "application/jwt", compact);
				OidcValidationException failure = assertThrows(OidcValidationException.class, () -> client.fetchUserInfo(auth)); assertEquals(test.reason(), failure.getReason());
				if (!Set.of("subject changed", "untrusted extra").contains(test.name())) assertTrue(failure.getJoseReason().isPresent());
				assertSafeFailure(failure); assertRedacted(failure.toString() + failure.getJoseReason()); assertFalse(failure.toString().contains(compact)); assertEquals(0, server.getHitCount("/jwks"));
			}
		}));
	}

	@TestFactory
	Stream<DynamicTest> rejectsRemoteHeaderAndWrongAlgorithmBeforeKeyIo() {
		return Stream.of("at+jwt", "jku", "crit", "none", "wrong alg", "JWE").map(name -> DynamicTest.dynamicTest(name, () -> {
			try (TestHttpsServer server = TestHttpsServer.start()) {
				OidcAuthentication auth = authenticate(server, builder(server).build(), ACCESS, 300);
				OidcClient client = builder(server).jsonWebKeySource(null).userInfoSignedResponseAlgorithm(JwsAlgorithm.RS256).build();
				TestJws.Builder token = TestJws.withAlgorithm(Algorithm.RS256).kid("key").payload(JsonText.object(new ArrayList<>(claims(server).entrySet())));
				switch (name) {
					case "at+jwt" -> token.typ("at+jwt"); case "jku" -> token.headerMember("jku", JsonText.string(server.uri("/attack").toString()));
					case "crit" -> token.headerMember("crit", "[\"extension\"]").headerMember("extension", "true");
					case "none" -> token.alg("none"); case "wrong alg" -> token.alg("ES256"); default -> { }
				}
				String compact = token.sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()); if (name.equals("JWE")) compact += ".e30.e30";
				respond(server, 200, "application/jwt", compact); OidcValidationException failure = assertThrows(OidcValidationException.class, () -> client.fetchUserInfo(auth));
				assertTrue(failure.getJoseReason().isPresent()); assertEquals(0, server.getHitCount("/jwks")); assertEquals(0, server.getHitCount("/attack")); assertRedacted(failure.toString());
			}
		}));
	}

	@Test
	void configuredFormatsCannotDowngradeAndUnexpectedMediaRedirectAndLargeBodyAreRejected() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcClient jsonClient = builder(server).build(); OidcClient signedClient = builder(server).userInfoSignedResponseAlgorithm(JwsAlgorithm.RS256).build();
			OidcAuthentication auth = authenticate(server, jsonClient, ACCESS, 300);
			respond(server, 200, "application/jwt", sign(claims(server), false)); assertEquals(OidcValidationException.Reason.USERINFO_FORMAT_MISMATCH, assertThrows(OidcValidationException.class, () -> jsonClient.fetchUserInfo(auth)).getReason());
			respond(server, 200, "application/json", json()); assertEquals(OidcValidationException.Reason.USERINFO_FORMAT_MISMATCH, assertThrows(OidcValidationException.class, () -> signedClient.fetchUserInfo(auth)).getReason());
			for (String media : List.of("text/plain", "application/json; charset=iso-8859-1")) {
				respond(server, 200, media, json()); assertEquals(OAuthException.Reason.UNEXPECTED_CONTENT_TYPE, assertThrows(OAuthException.class, () -> jsonClient.fetchUserInfo(auth)).getReason());
			}
			server.script("/userinfo", TestHttpsServer.Script.fromRedirect(302, server.uri("/attack").toString()));
			assertEquals(OAuthException.Reason.REDIRECT_NOT_FOLLOWED, assertThrows(OAuthException.class, () -> jsonClient.fetchUserInfo(auth)).getReason()); assertEquals(0, server.getHitCount("/attack"));
			respond(server, 200, "application/json", " ".repeat(256 * 1024 + 1)); assertEquals(OAuthException.Reason.TOO_LARGE, assertThrows(OAuthException.class, () -> jsonClient.fetchUserInfo(auth)).getReason());
		}
	}

	@Test
	void differentIssuerOrClientRejectsBeforeLazyDiscoveryEvenWithTrustedAudience() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcAuthentication auth = authenticate(server, builder(server).build(), ACCESS, 300);
			for (OidcClient client : List.of(lazy(server).clientId("other").trustedAudiences(Set.of("client")).build(), OidcClient.withIssuer(server.uri("/other-issuer").toString()).clientId("client").redirectUri(CALLBACK).httpClient(TestTls.httpClient()).clock(CLOCK).build())) {
				assertEquals(OidcValidationException.Reason.USERINFO_AUTHENTICATION_MISMATCH, assertThrows(OidcValidationException.class, () -> client.fetchUserInfo(auth)).getReason());
			}
			assertEquals(1, server.getRequests().size());
		}
	}

	@Test
	void unsafeAndExpiredAccessTokenRejectBeforeDiscoveryAndExpiryIsRecheckedAfterDiscovery() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcAuthentication unsafe = authenticate(server, builder(server).build(), "TEST-ONLY access invalid", 300);
			assertEquals(OidcValidationException.Reason.USERINFO_ACCESS_TOKEN_INVALID, assertThrows(OidcValidationException.class, () -> lazy(server).build().fetchUserInfo(unsafe)).getReason());
			TestClock clock = TestClock.fromInstant(NOW); OidcAuthentication expired = authenticate(server, builder(server).clock(clock).build(), ACCESS, 1); clock.advance(Duration.ofSeconds(1));
			assertEquals(OidcValidationException.Reason.USERINFO_ACCESS_TOKEN_EXPIRED, assertThrows(OidcValidationException.class, () -> lazy(server).clock(clock).build().fetchUserInfo(expired)).getReason()); assertEquals(0, server.getHitCount(DISCOVERY));
			TestClock advancing = TestClock.fromInstant(NOW); OidcAuthentication fresh = authenticate(server, builder(server).clock(advancing).build(), ACCESS, 1); discovery(server, null);
			OidcClient client = lazy(server).clock(advancing).observer(new OidcObserver() {
				@Override public void didRequestEndpoint(OAuthEndpoint endpoint, URI uri, Integer status, Duration elapsed) { if (endpoint == OAuthEndpoint.METADATA) advancing.advance(Duration.ofSeconds(1)); }
			}).build();
			assertEquals(OidcValidationException.Reason.USERINFO_ACCESS_TOKEN_EXPIRED, assertThrows(OidcValidationException.class, () -> client.fetchUserInfo(fresh)).getReason()); assertEquals(1, server.getHitCount(DISCOVERY)); assertEquals(0, server.getHitCount("/userinfo"));
		}
	}

	@Test
	void missingEndpointAndAlgorithmCapabilityAreCheckedBeforeCredentialIo() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcAuthentication auth = authenticate(server, builder(server).build(), ACCESS, 300);
			OidcProviderMetadata without = metadata(server).userInfoEndpoint(null).build();
			OidcClient missing = OidcClient.withProviderMetadata(without).clientId("client").redirectUri(CALLBACK).jsonWebKeySource(keys()).httpClient(TestTls.httpClient()).clock(CLOCK).build();
			assertEquals(OidcValidationException.Reason.USERINFO_ENDPOINT_UNAVAILABLE, assertThrows(OidcValidationException.class, () -> missing.fetchUserInfo(auth)).getReason());
			for (JwsAlgorithm algorithm : List.of(JwsAlgorithm.HS256, JwsAlgorithm.HS384, JwsAlgorithm.HS512)) assertThrows(IllegalArgumentException.class, () -> builder(server).userInfoSignedResponseAlgorithm(algorithm).build());
			OidcProviderMetadata restricted = metadata(server).userInfoSigningAlgValuesSupported(Set.of("ES256")).build();
			assertThrows(IllegalArgumentException.class, () -> OidcClient.withProviderMetadata(restricted).clientId("client").redirectUri(CALLBACK).userInfoSignedResponseAlgorithm(JwsAlgorithm.RS256).jsonWebKeySource(keys()).build());
			discovery(server, "[\"ES256\"]"); assertEquals(OAuthException.Reason.METADATA_INVALID, assertThrows(OAuthException.class, () -> lazy(server).userInfoSignedResponseAlgorithm(JwsAlgorithm.RS256).build().fetchUserInfo(auth)).getReason());
			assertEquals(0, server.getHitCount("/userinfo"));
			OidcClient restored = builder(server).userInfoSignedResponseAlgorithm(JwsAlgorithm.RS256).userInfoSignedResponseAlgorithm(null).build(); respond(server, 200, "application/json", json()); assertFalse(restored.fetchUserInfo(auth).isSigned());
		}
	}

	@TestFactory
	Stream<DynamicTest> malformedAdvertisedUserInfoAlgorithmsHaveNoDefaults() {
		return Stream.of("null", "[]", "[1]", "[\"RS256\",\"RS256\"]", "[\"\"]", "\"RS256\"").map(value -> DynamicTest.dynamicTest(value, () -> {
			try (TestHttpsServer server = TestHttpsServer.start()) {
				OidcAuthentication auth = authenticate(server, builder(server).build(), ACCESS, 300); discovery(server, value);
				assertEquals(OAuthException.Reason.DOCUMENT_MALFORMED, assertThrows(OAuthException.class, () -> lazy(server).build().fetchUserInfo(auth)).getReason()); assertEquals(0, server.getHitCount("/userinfo"));
			}
		}));
	}

	@Test
	void signedUserInfoResolvesRemoteKeysAfterGetAndUsesPostLookupClock() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcAuthentication auth = authenticate(server, builder(server).build(), ACCESS, 300); TestClock clock = TestClock.fromInstant(NOW);
			server.script("/jwks", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJsonWebKeySet(keyJson())));
			OidcClient client = builder(server).jsonWebKeySource(null).clock(clock).clockSkew(Duration.ZERO).userInfoSignedResponseAlgorithm(JwsAlgorithm.RS256).observer(new OidcObserver() {
				@Override public void didFetchJsonWebKeySet(URI uri, Integer usable, Integer skipped, Duration ttl, Duration elapsed) { clock.advance(Duration.ofSeconds(2)); }
			}).build();
			Map<String,String> claims = claims(server); claims.put("exp", Long.toString(NOW.plusSeconds(1).getEpochSecond())); respond(server, 200, "application/jwt", sign(claims, false));
			assertEquals(OidcValidationException.Reason.EXPIRED, assertThrows(OidcValidationException.class, () -> client.fetchUserInfo(auth)).getReason());
			assertEquals(List.of("/token", "/userinfo", "/jwks"), server.getRequests().stream().map(TestHttpsServer.RecordedRequest::getPath).toList());
		}
	}

	@Test
	void deadlineSpentOnUserInfoCannotStartNewSigningKeyBudget() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcAuthentication auth = authenticate(server, builder(server).build(), ACCESS, 300); respond(server, 200, "application/jwt", sign(claims(server), false));
			OidcClient client = builder(server).jsonWebKeySource(null).userInfoSignedResponseAlgorithm(JwsAlgorithm.RS256).requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(1)).observer(new OidcObserver() {
				@Override public void didRequestEndpoint(OAuthEndpoint endpoint, URI uri, Integer status, Duration elapsed) { if (endpoint == OAuthEndpoint.USERINFO) pause(); }
			}).build();
			assertThrows(JsonWebKeySetUnavailableException.class, () -> client.fetchUserInfo(auth)); assertEquals(0, server.getHitCount("/jwks")); assertEquals(1, server.getHitCount("/userinfo"));
		}
	}

	@Test
	void deadlineSpentOnDiscoveryCannotSendBearerHeader() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcAuthentication auth = authenticate(server, builder(server).build(), ACCESS, 300); discovery(server, null);
			OidcClient client = lazy(server).requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(1)).observer(new OidcObserver() {
				@Override public void didRequestEndpoint(OAuthEndpoint endpoint, URI uri, Integer status, Duration elapsed) { if (endpoint == OAuthEndpoint.METADATA) pause(); }
			}).build();
			assertEquals(OAuthException.Reason.NETWORK_FAILURE, assertThrows(OAuthException.class, () -> client.fetchUserInfo(auth)).getReason()); assertEquals(0, server.getHitCount("/userinfo"));
		}
	}

	@TestFactory
	Stream<DynamicTest> endpointStatusProseAndChallengesAreNotRetainedAndTransientFailuresAreBounded() {
		return Stream.of(401, 403, 429, 503).map(status -> DynamicTest.dynamicTest("HTTP " + status, () -> {
			try (TestHttpsServer server = TestHttpsServer.start()) {
				OidcClient client = builder(server).build(); OidcAuthentication auth = authenticate(server, client, ACCESS, 300);
				server.script("/userinfo", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.withStatus(status).header("Content-Type", "application/json").header("Retry-After", "10").header("WWW-Authenticate", "Bearer error_description=\"" + ACCESS + "\"").body("{\"secret\":" + JsonText.string(REFRESH) + "}").build()));
				OAuthErrorResponseException failure = assertThrows(OAuthErrorResponseException.class, () -> client.fetchUserInfo(auth)); assertEquals(status, failure.getStatus()); assertEquals(Optional.of(Duration.ofSeconds(10)), failure.getRetryAfter()); assertNull(failure.getCause()); assertRedacted(failure.toString());
				respond(server, 200, "application/json", json());
				if (status == 429 || status == 503) { assertSame(failure, assertThrows(OAuthErrorResponseException.class, () -> client.fetchUserInfo(auth))); assertEquals(1, server.getHitCount("/userinfo")); }
				else { assertEquals(SUBJECT, client.fetchUserInfo(auth).getSubject()); assertEquals(2, server.getHitCount("/userinfo")); }
			}
		}));
	}

	@Test
	void userInfoAlgorithmCapabilitiesAreImmutableAndSeparateFromIdTokenPolicy() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			Set<String> algorithms = new HashSet<>(Set.of("ES256")); OidcProviderMetadata metadata = metadata(server).userInfoSigningAlgValuesSupported(algorithms).build(); algorithms.clear();
			assertEquals(Set.of("ES256"), metadata.getUserInfoSigningAlgValuesSupported().orElseThrow()); assertThrows(UnsupportedOperationException.class, () -> metadata.getUserInfoSigningAlgValuesSupported().orElseThrow().clear());
			String combinedKeys = TestJsonWebKeys.keySet(List.of(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("key").alg("RS256").toJson(), TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P256).kid("ec").alg("ES256").toJson()));
			OidcClient client = OidcClient.withProviderMetadata(metadata).clientId("client").redirectUri(CALLBACK).jsonWebKeySource(StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(combinedKeys))).clock(CLOCK).httpClient(TestTls.httpClient()).userInfoSignedResponseAlgorithm(JwsAlgorithm.ES256).build();
			assertTrue(server.getRequests().isEmpty()); OidcAuthentication auth = authenticate(server, client, ACCESS, 300);
			String compact = TestJws.withAlgorithm(Algorithm.ES256).kid("ec").payload(JsonText.object(new ArrayList<>(claims(server).entrySet()))).sign(Fixture.IDP_SIGNING_EC_P256.getPrivateKey());
			respond(server, 200, "application/jwt", compact); assertTrue(client.fetchUserInfo(auth).isSigned());
			assertEquals(SUBJECT, auth.getSubject());
		}
	}

	@Test
	void timedOutUserInfoIsNotRetriedAndItsFailureBacksOffFurtherCalls() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcClient client = builder(server).requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(1)).build();
			OidcAuthentication auth = authenticate(server, client, ACCESS, 300); server.script("/userinfo", TestHttpsServer.Script.fromTarpit());
			OAuthException failure = assertThrows(OAuthException.class, () -> client.fetchUserInfo(auth)); assertEquals(OAuthException.Reason.NETWORK_FAILURE, failure.getReason());
			assertEquals(1, server.getHitCount("/userinfo")); respond(server, 200, "application/json", json());
			assertSame(failure, assertThrows(OAuthException.class, () -> client.fetchUserInfo(auth))); assertEquals(1, server.getHitCount("/userinfo")); assertRedacted(failure.toString());
		}
	}
	@Test
	void interruptedCallerDoesNotPoisonLaterUserInfoCalls() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcClient client = builder(server).build(); OidcAuthentication auth = authenticate(server, client, ACCESS, 300); respond(server, 200, "application/json", json());
			try {
				Thread.currentThread().interrupt(); assertEquals(OAuthException.Reason.INTERRUPTED, assertThrows(OAuthException.class, () -> client.fetchUserInfo(auth)).getReason()); assertTrue(Thread.currentThread().isInterrupted());
			} finally { Thread.interrupted(); }
			assertEquals(SUBJECT, client.fetchUserInfo(auth).getSubject());
		}
	}

	private static void assertSafeFailure(OidcValidationException failure) throws IllegalAccessException {
		assertNull(failure.getCause()); failure.addSuppressed(new IllegalStateException(ACCESS)); assertEquals(0, failure.getSuppressed().length); assertRedacted(failure.toString());
		for (Class<?> type = failure.getClass(); type != RuntimeException.class; type = type.getSuperclass()) {
			for (var field : type.getDeclaredFields()) {
				if (java.lang.reflect.Modifier.isStatic(field.getModifiers())) continue;
				field.setAccessible(true); Object value = field.get(failure);
				assertFalse(value instanceof OidcUserInfo || value instanceof OidcAuthentication || value instanceof IdToken || value instanceof Jwt || value instanceof AccessToken || value instanceof RefreshToken);
				if (value instanceof String text) assertRedacted(text);
			}
		}
	}

	private static void pause() { try { new CountDownLatch(1).await(2, TimeUnit.SECONDS); } catch (InterruptedException e) { Thread.currentThread().interrupt(); } }
	private static void assertRedacted(String text) { for (String value : List.of(ACCESS, REFRESH, SUBJECT, EMAIL)) assertFalse(text.contains(value), "Disclosed test-only sentinel"); }
	private static String json() { return "{\"sub\":" + JsonText.string(SUBJECT) + "}"; }
	@Test
	void userInfoAfterRefreshUsesNewCredentialAndOriginalIdentityWithStoredReference() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcClient client = builder(server).build(); OidcAuthentication auth = authenticate(server, client, ACCESS, 0);
			OidcSessionReference stored = OidcSessionReference.fromSerializedForm(auth.getSessionReference().toSerializedForm());
			server.script("/token", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,
					"{\"access_token\":\"TEST-ONLY-refreshed-userinfo\",\"token_type\":\"Bearer\",\"expires_in\":300}")));
			OidcRefreshResult refreshed = client.refresh(auth.getTokens().getRefreshToken().orElseThrow(), stored);
			respond(server, 200, "application/json", json()); assertEquals(SUBJECT, client.fetchUserInfo(auth, refreshed).getSubject());
			assertTrue(refreshed.getIdToken().isEmpty()); assertSame(stored, refreshed.getSessionReference());
			assertEquals(Optional.of("Bearer TEST-ONLY-refreshed-userinfo"), server.getRequests("/userinfo").get(0).getHeader("Authorization"));
			assertEquals(OidcValidationException.Reason.USERINFO_ACCESS_TOKEN_EXPIRED, assertThrows(OidcValidationException.class, () -> client.fetchUserInfo(auth)).getReason());
		}
	}

	@Test
	void refreshFromAnotherLoginCannotBeAttachedToOriginalIdentityBeforeAnyIo() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			AtomicReference<OidcValidationException> rejected = new AtomicReference<>();
			OidcClient client = builder(server).observer(new OidcObserver() {
				@Override public void didRejectUserInfo(OidcValidationException failure) { rejected.set(failure); }
			}).build();
			OidcAuthentication first = authenticate(server, client, ACCESS, 300), second = authenticate(server, client, ACCESS, 300);
			server.script("/token", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,
					"{\"access_token\":\"TEST-ONLY-refreshed-userinfo\",\"token_type\":\"Bearer\"}")));
			OidcRefreshResult refreshed = client.refresh(second.getTokens().getRefreshToken().orElseThrow(), second.getSessionReference());
			int before = server.getRequests().size();
			OidcValidationException failure = assertThrows(OidcValidationException.class, () -> lazy(server).build().fetchUserInfo(first, refreshed));
			assertEquals(OidcValidationException.Reason.USERINFO_AUTHENTICATION_MISMATCH, failure.getReason());
			OidcValidationException observed = assertThrows(OidcValidationException.class, () -> client.fetchUserInfo(first, refreshed)); assertSame(observed, rejected.get());
			assertEquals(before, server.getRequests().size()); assertNull(failure.getCause()); assertSafeFailure(failure);
		}
	}

	@Test
	void refreshedUserInfoRetainsSignedPolicyAndSubjectChecks() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcClient client = builder(server).userInfoSignedResponseAlgorithm(JwsAlgorithm.RS256).build();
			OidcAuthentication auth = authenticate(server, client, ACCESS, 300);
			server.script("/token", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,
					"{\"access_token\":\"TEST-ONLY-refreshed-userinfo\",\"token_type\":\"Bearer\"}")));
			OidcRefreshResult refreshed = client.refresh(auth.getTokens().getRefreshToken().orElseThrow(), auth.getSessionReference());
			respond(server, 200, "application/jwt", sign(claims(server), false)); assertTrue(client.fetchUserInfo(auth, refreshed).isSigned());
			respond(server, 200, "application/json", json());
			assertEquals(OidcValidationException.Reason.USERINFO_FORMAT_MISMATCH, assertThrows(OidcValidationException.class, () -> client.fetchUserInfo(auth, refreshed)).getReason());
			Map<String,String> changed = claims(server); changed.put("sub", "\"other\""); respond(server, 200, "application/jwt", sign(changed, false));
			assertEquals(OidcValidationException.Reason.USERINFO_SUBJECT_MISMATCH, assertThrows(OidcValidationException.class, () -> client.fetchUserInfo(auth, refreshed)).getReason());
		}
	}

	private static String keyJson() { return TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("key").alg("RS256").toKeySetJson(); }
	private static StaticJsonWebKeySource keys() { return StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(keyJson())); }
	private static OidcProviderMetadata.Builder metadata(TestHttpsServer server) { return OidcProviderMetadata.withIssuer(server.getBaseUri().toString()).authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token")).jwksUri(server.uri("/jwks")).userInfoEndpoint(server.uri("/userinfo")); }
	private static OidcClient.Builder builder(TestHttpsServer server) { return OidcClient.withProviderMetadata(metadata(server).build()).clientId("client").redirectUri(CALLBACK).clock(CLOCK).httpClient(TestTls.httpClient()).jsonWebKeySource(keys()); }
	private static OidcClient.Builder lazy(TestHttpsServer server) { return OidcClient.withIssuer(server.getBaseUri().toString()).clientId("client").redirectUri(CALLBACK).clock(CLOCK).httpClient(TestTls.httpClient()).jsonWebKeySource(keys()); }
	private static Map<String,String> claims(TestHttpsServer server) { Map<String,String> claims = new LinkedHashMap<>(); claims.put("iss", JsonText.string(server.getBaseUri().toString())); claims.put("sub", JsonText.string(SUBJECT)); claims.put("aud", "\"client\""); return claims; }
	private static String sign(Map<String,String> claims, boolean forged) { return TestJws.withAlgorithm(Algorithm.RS256).kid("key").payload(JsonText.object(new ArrayList<>(claims.entrySet()))).sign(forged ? Fixture.NEGATIVE_ATTACKER_RSA_2048.getPrivateKey() : Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()); }
	private static OidcAuthentication authenticate(TestHttpsServer server, OidcClient client, String access, long lifetime) throws Exception {
		AuthorizationRedirect redirect = client.beginAuthentication(); QueryParameters query = QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery());
		Map<String,String> claims = claims(server); claims.put("nonce", JsonText.string(query.getValues("nonce").get(0))); claims.put("iat", Long.toString(NOW.getEpochSecond())); claims.put("exp", Long.toString(NOW.plusSeconds(300).getEpochSecond()));
		server.script("/token", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200, "{\"access_token\":" + JsonText.string(access) + ",\"token_type\":\"Bearer\",\"expires_in\":" + lifetime + ",\"refresh_token\":" + JsonText.string(REFRESH) + ",\"id_token\":" + JsonText.string(sign(claims, false)) + "}")));
		StateSealer sealer = TestSealers.fromFixedKey(); PendingAuthorizationSource source = PendingAuthorizationSource.fromSealedForm(redirect.getPendingAuthorization().toSealedForm(sealer, "userinfo"), sealer, "userinfo");
		return client.completeAuthentication(AuthorizationResponse.fromQueryString("state=" + query.getValues("state").get(0) + "&code=TEST-ONLY-code"), source, CALLBACK);
	}
	private static void respond(TestHttpsServer server, int status, String media, String body) { server.script("/userinfo", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.withStatus(status).header("Content-Type", media).body(body).build())); }
	private static void discovery(TestHttpsServer server, @Nullable String algorithms) { server.script(DISCOVERY, TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200, "{\"issuer\":" + JsonText.string(server.getBaseUri().toString()) + ",\"authorization_endpoint\":" + JsonText.string(server.uri("/authorize").toString()) + ",\"token_endpoint\":" + JsonText.string(server.uri("/token").toString()) + ",\"jwks_uri\":" + JsonText.string(server.uri("/jwks").toString()) + ",\"userinfo_endpoint\":" + JsonText.string(server.uri("/userinfo").toString()) + ",\"subject_types_supported\":[\"public\"],\"id_token_signing_alg_values_supported\":[\"RS256\"],\"response_types_supported\":[\"code\"]" + (algorithms == null ? "" : ",\"userinfo_signing_alg_values_supported\":" + algorithms) + "}"))); }
}
