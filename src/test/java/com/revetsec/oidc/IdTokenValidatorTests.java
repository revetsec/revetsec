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

import com.revetsec.ErrorCategory;
import com.revetsec.jose.JsonWebKeySet;
import com.revetsec.jose.JoseException;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.StaticJsonWebKeySource;
import com.revetsec.jose.RemoteJsonWebKeySource;
import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestTls;
import com.revetsec.testing.JsonText;
import com.revetsec.testing.TestJsonWebKeys;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws;
import com.revetsec.testing.TestJws.Algorithm;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

final class IdTokenValidatorTests {
	private static final String ISSUER = "https://issuer.example.com";
	private static final String CLIENT = "client";
	private static final String NONCE = "TEST-ONLY-nonce-sentinel";
	private static final String ACCESS = "TEST-ONLY-access-token-sentinel";
	private static final String CODE = "TEST-ONLY-code-sentinel";
	private static final Instant NOW = Instant.parse("2026-09-29T12:00:00Z");

	@Test
	void validatesCoreAppendixA3AndA4WithTheirPublishedPublicKeyAndHashValues() throws IOException {
		StaticJsonWebKeySource source = StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(resource("jwks.json")));
		IdTokenValidator validator = new IdTokenValidator("https://server.example.com", "s6BhdRkqt3", source,
				Set.of(JwsAlgorithm.RS256), Set.of(), Set.of(), Duration.ofSeconds(60), Duration.ofMinutes(5),
				Clock.fixed(Instant.ofEpochSecond(1311281000L), ZoneOffset.UTC));
		IdToken a3 = validator.validate(resource("a-3.jwt").strip(), "n-0S6_WzA2Mj",
				"jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y", CODE, null, Set.of());
		IdToken a4 = validator.validate(resource("a-4.jwt").strip(), "n-0S6_WzA2Mj", ACCESS,
				"Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk", null, Set.of());
		Assertions.assertEquals("248289761001", a3.getClaims().getSubject().orElseThrow());
		Assertions.assertEquals("248289761001", a4.getClaims().getSubject().orElseThrow());
		Assertions.assertEquals("77QmUPtjPfzWtF2AnpK9RQ", IdTokenHash.hash(JwsAlgorithm.RS256,
				"jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"));
		Assertions.assertEquals("LDktKdoQak3Pk0cnXxCltA", IdTokenHash.hash(JwsAlgorithm.RS256,
				"Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk"));
	}

	@TestFactory
	Stream<DynamicTest> hashesUseHalfOfTheIndependentDigestForEverySupportedAlgorithm() {
		return Arrays.stream(JwsAlgorithm.values()).map(algorithm -> DynamicTest.dynamicTest(algorithm.name(), () -> {
			String digestName = switch (algorithm) {
				case RS256, PS256, ES256, HS256 -> "SHA-256";
				case RS384, PS384, ES384, HS384 -> "SHA-384";
				default -> "SHA-512";
			};
			byte[] digest = MessageDigest.getInstance(digestName).digest(ACCESS.getBytes(StandardCharsets.US_ASCII));
			String expected = Base64.getUrlEncoder().withoutPadding().encodeToString(
					Arrays.copyOfRange(digest, 0, digest.length / 2));
			Assertions.assertEquals(expected, IdTokenHash.hash(algorithm, ACCESS));
		}));
	}

	@TestFactory
	Stream<DynamicTest> validatesAsymmetricIdTokensAndTheirHashes() {
		return Stream.of(
				Map.entry(Algorithm.RS256, Fixture.IDP_SIGNING_RSA_2048),
				Map.entry(Algorithm.PS512, Fixture.IDP_SIGNING_RSA_2048),
				Map.entry(Algorithm.ES256, Fixture.IDP_SIGNING_EC_P256),
				Map.entry(Algorithm.ES384, Fixture.IDP_SIGNING_EC_P384),
				Map.entry(Algorithm.ED25519, Fixture.ED25519),
				Map.entry(Algorithm.EDDSA, Fixture.ED25519))
				.map(entry -> DynamicTest.dynamicTest(entry.getKey().name(), () -> {
					JwsAlgorithm algorithm = JwsAlgorithm.findByWireValue(entry.getKey().getWireValue()).orElseThrow();
					Map<String, String> claims = claims();
					claims.put("at_hash", JsonText.string(IdTokenHash.hash(algorithm, ACCESS)));
					claims.put("c_hash", JsonText.string(IdTokenHash.hash(algorithm, CODE)));
					String token = token(entry.getKey(), claims).sign(entry.getValue().getPrivateKey());
					IdToken result = validator(entry.getValue(), Set.of(algorithm), Set.of(), Set.of(), NOW)
							.validate(token, NONCE, ACCESS, CODE, null, Set.of());
					Assertions.assertEquals(token, result.toCompactSerialization());
				}));
	}

	@TestFactory
	Stream<DynamicTest> everyOidcClaimDefectIsRejected() {
		record Case(String name, @Nullable String value, OidcValidationException.Reason reason) {}
		return Stream.of(
				new Case("iss", JsonText.string(ISSUER + "/"), OidcValidationException.Reason.ISSUER_MISMATCH),
				new Case("iss", JsonText.string("https://ISSUER.example.com"), OidcValidationException.Reason.ISSUER_MISMATCH),
				new Case("aud", "\"other\"", OidcValidationException.Reason.AUDIENCE_MISMATCH),
				new Case("aud", "[\"client\",\"other\"]", OidcValidationException.Reason.UNTRUSTED_AUDIENCE),
				new Case("aud", "[]", OidcValidationException.Reason.ID_TOKEN_MALFORMED),
				new Case("aud", "[123]", OidcValidationException.Reason.ID_TOKEN_MALFORMED),
				new Case("azp", "\"other\"", OidcValidationException.Reason.AUTHORIZED_PARTY_MISMATCH),
				new Case("azp", "123", OidcValidationException.Reason.ID_TOKEN_MALFORMED),
				new Case("exp", null, OidcValidationException.Reason.MISSING_CLAIM),
				new Case("exp", "\"" + NOW.getEpochSecond() + "\"", OidcValidationException.Reason.ID_TOKEN_MALFORMED),
				new Case("iat", null, OidcValidationException.Reason.MISSING_CLAIM),
				new Case("sub", null, OidcValidationException.Reason.INVALID_SUBJECT),
				new Case("sub", "\"\"", OidcValidationException.Reason.INVALID_SUBJECT),
				new Case("sub", JsonText.string("x".repeat(256)), OidcValidationException.Reason.INVALID_SUBJECT),
				new Case("sub", "\"é\"", OidcValidationException.Reason.INVALID_SUBJECT),
				new Case("nonce", null, OidcValidationException.Reason.NONCE_MISSING),
				new Case("nonce", "\"other\"", OidcValidationException.Reason.NONCE_MISMATCH),
				new Case("nonce", "null", OidcValidationException.Reason.ID_TOKEN_MALFORMED),
				new Case("auth_time", "\"yesterday\"", OidcValidationException.Reason.ID_TOKEN_MALFORMED),
				new Case("auth_time", "1e100000", OidcValidationException.Reason.ID_TOKEN_MALFORMED),
				new Case("acr", "null", OidcValidationException.Reason.ID_TOKEN_MALFORMED),
				new Case("amr", "\"pwd\"", OidcValidationException.Reason.ID_TOKEN_MALFORMED),
				new Case("amr", "[123]", OidcValidationException.Reason.ID_TOKEN_MALFORMED),
				new Case("sid", "null", OidcValidationException.Reason.ID_TOKEN_MALFORMED),
				new Case("at_hash", "\"altered\"", OidcValidationException.Reason.ACCESS_TOKEN_HASH_MISMATCH),
				new Case("at_hash", "123", OidcValidationException.Reason.ACCESS_TOKEN_HASH_MISMATCH),
				new Case("c_hash", "\"altered\"", OidcValidationException.Reason.CODE_HASH_MISMATCH))
				.map(testCase -> DynamicTest.dynamicTest(testCase.name() + "=" + testCase.value(), () -> {
					Map<String, String> claims = claims();
					if (testCase.value() == null)
						claims.remove(testCase.name());
					else
						claims.put(testCase.name(), testCase.value());
					assertRejected(testCase.reason(), claims);
				}));
	}

	@Test
	void trustedAudiencesAndAuthorizedPartiesAreOptInAndComparedExactly() {
		Map<String, String> claims = claims();
		claims.put("aud", "[\"client\",\"other\"]");
		claims.put("azp", "\"mobile-client\"");
		String token = signed(claims);
		validator(Fixture.IDP_SIGNING_RSA_2048, Set.of(JwsAlgorithm.RS256), Set.of("other"),
				Set.of("mobile-client"), NOW).validate(token, NONCE, ACCESS, CODE, null, Set.of());
		Assertions.assertThrows(OidcValidationException.class, () ->
				validator(Fixture.IDP_SIGNING_RSA_2048, Set.of(JwsAlgorithm.RS256), Set.of("OTHER"),
						Set.of("mobile-client"), NOW).validate(token, NONCE, ACCESS, CODE, null, Set.of()));
		claims.remove("azp");
		validator(Fixture.IDP_SIGNING_RSA_2048, Set.of(JwsAlgorithm.RS256), Set.of("other"),
				Set.of(), NOW).validate(signed(claims), NONCE, ACCESS, CODE, null, Set.of());
		claims.put("aud", "[\"client\"]");
		accept(claims);
	}

	@Test
	void timeChecksUseTheApprovedSkewAndMaximumAgeBoundaries() {
		Map<String, String> claims = claims();
		claims.put("exp", Long.toString(NOW.minusSeconds(59).getEpochSecond()));
		accept(claims);
		claims.put("exp", Long.toString(NOW.minusSeconds(60).getEpochSecond()));
		assertRejected(OidcValidationException.Reason.EXPIRED, claims);

		claims = claims();
		claims.put("iat", Long.toString(NOW.plusSeconds(60).getEpochSecond()));
		accept(claims);
		claims.put("iat", Long.toString(NOW.plusSeconds(61).getEpochSecond()));
		assertRejected(OidcValidationException.Reason.ISSUED_IN_FUTURE, claims);
		claims.put("iat", Long.toString(NOW.minusSeconds(360).getEpochSecond()));
		accept(claims);
		claims.put("iat", Long.toString(NOW.minusSeconds(361).getEpochSecond()));
		assertRejected(OidcValidationException.Reason.TOO_OLD, claims);

		claims = claims();
		claims.put("nbf", Long.toString(NOW.plusSeconds(60).getEpochSecond()));
		accept(claims);
		claims.put("nbf", Long.toString(NOW.plusSeconds(61).getEpochSecond()));
		assertRejected(OidcValidationException.Reason.NOT_YET_VALID, claims);
		claims.remove("nbf");
		claims.put("exp", NOW.plusSeconds(300).getEpochSecond() + ".5");
		Assertions.assertEquals(NOW.plusSeconds(300).plusMillis(500),
				accept(claims).getClaims().getExpiresAt().orElseThrow());
	}

	@Test
	void expiryIsCheckedAfterARemoteKeyLookupRatherThanBeforeIt() throws IOException {
		TestClock clock = TestClock.fromInstant(NOW);
		String keys = TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("key")
				.alg("RS256").toKeySetJson();
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/jwks", exchange -> {
				clock.advance(Duration.ofSeconds(361));
				exchange.send(TestHttpsServer.Response.fromJsonWebKeySet(keys));
			});
			RemoteJsonWebKeySource source = RemoteJsonWebKeySource.withUri(server.uri("/jwks"))
					.httpClient(TestTls.httpClient()).clock(clock).build();
			IdTokenValidator validator = new IdTokenValidator(ISSUER, CLIENT, source, Set.of(JwsAlgorithm.RS256),
					Set.of(), Set.of(), Duration.ofSeconds(60), Duration.ofMinutes(5), clock);
			Assertions.assertEquals(0, server.getHitCount("/jwks"));
			assertFailure(OidcValidationException.Reason.EXPIRED, () ->
					validator.validate(signed(claims()), NONCE, ACCESS, CODE, null, Set.of()));
			Assertions.assertEquals(1, server.getHitCount("/jwks"));
		}
	}

	@Test
	void zeroMaximumAuthenticationAgeStillRequiresAuthTimeAndSkewBoundsIt() {
		assertFailure(OidcValidationException.Reason.AUTH_TIME_MISSING, () ->
				validator().validate(signed(claims()), NONCE, ACCESS, CODE, Duration.ZERO, Set.of()));
		Map<String, String> claims = claims();
		claims.put("auth_time", Long.toString(NOW.minusSeconds(60).getEpochSecond()));
		validator().validate(signed(claims), NONCE, ACCESS, CODE, Duration.ZERO, Set.of());
		claims.put("auth_time", Long.toString(NOW.minusSeconds(61).getEpochSecond()));
		assertFailure(OidcValidationException.Reason.AUTHENTICATION_TOO_OLD, () ->
				validator().validate(signed(claims), NONCE, ACCESS, CODE, Duration.ZERO, Set.of()));
		claims.put("auth_time", Long.toString(NOW.plusSeconds(61).getEpochSecond()));
		assertRejected(OidcValidationException.Reason.AUTHENTICATION_TOO_OLD, claims);
		claims.put("auth_time", Long.toString(NOW.minusSeconds(61).getEpochSecond()));
		validator().validate(signed(claims), NONCE, ACCESS, CODE, Duration.ofSeconds(Long.MAX_VALUE), Set.of());
	}

	@Test
	void requiredAuthenticationContextMustBePresentAndMatchExactly() {
		Map<String, String> claims = claims();
		assertFailure(OidcValidationException.Reason.INSUFFICIENT_ACR, () ->
				validator().validate(signed(claims), NONCE, ACCESS, CODE, null, Set.of("urn:mfa")));
		claims.put("acr", "\"urn:pwd\"");
		assertFailure(OidcValidationException.Reason.INSUFFICIENT_ACR, () ->
				validator().validate(signed(claims), NONCE, ACCESS, CODE, null, Set.of("urn:mfa")));
		claims.put("acr", "\"urn:mfa\"");
		claims.put("amr", "[\"pwd\",\"otp\"]");
		claims.put("sid", "\"session\"");
		validator().validate(signed(claims), NONCE, ACCESS, CODE, null, Set.of("urn:mfa"));
	}

	@Test
	void swappedOrNonAsciiCredentialsFailThePresentHashChecks() {
		Map<String, String> claims = claims();
		claims.put("at_hash", JsonText.string(IdTokenHash.hash(JwsAlgorithm.RS256, ACCESS)));
		claims.put("c_hash", JsonText.string(IdTokenHash.hash(JwsAlgorithm.RS256, CODE)));
		String token = signed(claims);
		for (String accessToken : List.of("swapped", "non-ascii-é"))
			assertFailure(OidcValidationException.Reason.ACCESS_TOKEN_HASH_MISMATCH, () ->
					validator().validate(token, NONCE, accessToken, CODE, null, Set.of()));
		for (String code : List.of("swapped", "non-ascii-é"))
			assertFailure(OidcValidationException.Reason.CODE_HASH_MISMATCH, () ->
					validator().validate(token, NONCE, ACCESS, code, null, Set.of()));
	}

	@Test
	void onlyJsonBooleansMakeEmailVerificationAvailableAndStringFormsAreRedacted() {
		Map<String, String> claims = claims();
		claims.put("email", "\"TEST-ONLY-email-sentinel@example.com\"");
		claims.put("email_verified", "true");
		IdToken verified = accept(claims);
		Assertions.assertEquals(Optional.of(true), verified.getEmailVerified());
		Assertions.assertEquals(Optional.of("TEST-ONLY-email-sentinel@example.com"), verified.getEmail());
		Assertions.assertFalse(verified.toString().contains("sentinel"));
		for (String value : List.of("\"true\"", "123", "null", "[]")) {
			claims.put("email_verified", value);
			Assertions.assertTrue(accept(claims).getEmailVerified().isEmpty());
		}
		claims.put("email_verified", "false");
		Assertions.assertEquals(Optional.of(false), accept(claims).getEmailVerified());
		claims.put("email", "123");
		Assertions.assertTrue(accept(claims).getEmail().isEmpty());
	}

	@Test
	void genericJoseFailuresAreTranslatedWithNoCredentialReferences() throws IllegalAccessException {
		String forged = token(Algorithm.RS256, claims()).sign(Fixture.NEGATIVE_ATTACKER_RSA_2048.getPrivateKey());
		OidcValidationException signature = assertFailure(OidcValidationException.Reason.ID_TOKEN_SIGNATURE_INVALID,
				() -> validator().validate(forged, NONCE, ACCESS, CODE, null, Set.of()));
		Assertions.assertEquals(Optional.of(JoseException.Reason.SIGNATURE_MISMATCH), signature.getJoseReason());
		assertRedactedGraph(signature, forged, NONCE, ACCESS, CODE);

		Map<String, String> claims = claims();
		claims.put("exp", "1");
		OidcValidationException expiry = assertRejected(OidcValidationException.Reason.EXPIRED, claims);
		Assertions.assertEquals(Optional.of(JoseException.Reason.EXPIRED), expiry.getJoseReason());
		claims = claims();
		claims.put("nonce", "\"wrong\"");
		OidcValidationException nonce = assertRejected(OidcValidationException.Reason.NONCE_MISMATCH, claims);
		Assertions.assertTrue(nonce.getJoseReason().isEmpty());
		assertRedactedGraph(nonce, signed(claims), NONCE, ACCESS, CODE);
	}

	@Test
	void badSignaturesWinOverMalformedClaimsAndClaimsAreStrictJson() {
		String duplicate = claimsText(claims()).replace("}", ",\"sub\":\"other\"}");
		String forged = TestJws.withAlgorithm(Algorithm.RS256).kid("key").payload(duplicate)
				.sign(Fixture.NEGATIVE_ATTACKER_RSA_2048.getPrivateKey());
		assertFailure(OidcValidationException.Reason.ID_TOKEN_SIGNATURE_INVALID,
				() -> validator().validate(forged, NONCE, ACCESS, CODE, null, Set.of()));
		String signed = TestJws.withAlgorithm(Algorithm.RS256).kid("key").payload(duplicate)
				.sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());
		assertFailure(OidcValidationException.Reason.ID_TOKEN_MALFORMED,
				() -> validator().validate(signed, NONCE, ACCESS, CODE, null, Set.of()));
	}

	@Test
	void tokenTypeAlgorithmAndNestedTokenHeadersFailClosed() {
		for (String type : List.of("JWT", "jwt", "application/jwt")) {
			String token = token(Algorithm.RS256, claims()).typ(type).sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());
			validator().validate(token, NONCE, ACCESS, CODE, null, Set.of());
		}
		for (String type : List.of("at+jwt", "logout+jwt", "application/secevent+jwt")) {
			String token = token(Algorithm.RS256, claims()).typ(type).sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());
			assertFailure(OidcValidationException.Reason.INVALID_TYPE,
					() -> validator().validate(token, NONCE, ACCESS, CODE, null, Set.of()));
		}
		String nested = token(Algorithm.RS256, claims()).headerMember("cty", "\"JWT\"")
				.sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());
		assertFailure(OidcValidationException.Reason.ID_TOKEN_UNSUPPORTED,
				() -> validator().validate(nested, NONCE, ACCESS, CODE, null, Set.of()));
		String disallowed = token(Algorithm.ES256, claims()).sign(Fixture.IDP_SIGNING_EC_P256.getPrivateKey());
		assertFailure(OidcValidationException.Reason.ALGORITHM_NOT_ALLOWED,
				() -> validator().validate(disallowed, NONCE, ACCESS, CODE, null, Set.of()));
	}

	@Test
	void signingKeyIssuerBindingCannotBeSkippedByTheProfile() {
		String key = TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("key")
				.alg("RS256").issuer("https://other-issuer.example.com").toKeySetJson();
		IdTokenValidator validator = new IdTokenValidator(ISSUER, CLIENT,
				StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(key)), Set.of(JwsAlgorithm.RS256),
				Set.of(), Set.of(), Duration.ofSeconds(60), Duration.ofMinutes(5), Clock.fixed(NOW, ZoneOffset.UTC));
		OidcValidationException failure = assertFailure(OidcValidationException.Reason.ISSUER_MISMATCH, () ->
				validator.validate(signed(claims()), NONCE, ACCESS, CODE, null, Set.of()));
		Assertions.assertEquals(Optional.of(JoseException.Reason.KEY_ISSUER_MISMATCH), failure.getJoseReason());
	}

	private static void assertRedactedGraph(OidcValidationException exception, String... credentials)
			throws IllegalAccessException {
		Assertions.assertEquals(ErrorCategory.VALIDATION_FAILURE, exception.getCategory());
		Assertions.assertFalse(exception.isTransient());
		Assertions.assertNull(exception.getCause());
		exception.addSuppressed(new IllegalStateException(ACCESS));
		Assertions.assertEquals(0, exception.getSuppressed().length);
		for (String credential : credentials) {
			Assertions.assertFalse(java.util.Objects.requireNonNull(exception.getMessage()).contains(credential));
			Assertions.assertFalse(exception.toString().contains(credential));
		}
		for (Class<?> type = exception.getClass(); type != RuntimeException.class; type = type.getSuperclass())
			for (var field : type.getDeclaredFields()) {
				if (Modifier.isStatic(field.getModifiers()))
					continue;
				field.setAccessible(true);
				Object value = field.get(exception);
				Assertions.assertFalse(value instanceof IdToken || value instanceof com.revetsec.jose.Jwt
						|| value instanceof com.revetsec.oauth.AccessToken || value instanceof com.revetsec.oauth.RefreshToken);
				for (String credential : credentials)
					Assertions.assertNotEquals(credential, value);
			}
	}

	private static IdToken accept(Map<String, String> claims) {
		return validator().validate(signed(claims), NONCE, ACCESS, CODE, null, Set.of());
	}

	private static OidcValidationException assertRejected(OidcValidationException.Reason reason,
			Map<String, String> claims) {
		return assertFailure(reason, () -> accept(claims));
	}

	private static OidcValidationException assertFailure(OidcValidationException.Reason reason, Runnable action) {
		OidcValidationException exception = Assertions.assertThrows(OidcValidationException.class, action::run);
		Assertions.assertEquals(reason, exception.getReason());
		return exception;
	}

	private static IdTokenValidator validator() {
		return validator(Fixture.IDP_SIGNING_RSA_2048, Set.of(JwsAlgorithm.RS256), Set.of(), Set.of(), NOW);
	}

	private static IdTokenValidator validator(Fixture fixture, Set<JwsAlgorithm> algorithms, Set<String> audiences,
			Set<String> authorizedParties, Instant now) {
		String key = TestJsonWebKeys.withFixture(fixture).kid("key")
				.alg(algorithms.iterator().next().getWireValue()).toKeySetJson();
		return new IdTokenValidator(ISSUER, CLIENT, StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(key)),
				algorithms, audiences, authorizedParties, Duration.ofSeconds(60), Duration.ofMinutes(5),
				Clock.fixed(now, ZoneOffset.UTC));
	}

	private static Map<String, String> claims() {
		Map<String, String> claims = new LinkedHashMap<>();
		claims.put("iss", JsonText.string(ISSUER));
		claims.put("aud", JsonText.string(CLIENT));
		claims.put("sub", "\"subject\"");
		claims.put("exp", Long.toString(NOW.plusSeconds(300).getEpochSecond()));
		claims.put("iat", Long.toString(NOW.getEpochSecond()));
		claims.put("nonce", JsonText.string(NONCE));
		return claims;
	}

	private static String signed(Map<String, String> claims) {
		return token(Algorithm.RS256, claims).sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());
	}

	private static TestJws.Builder token(Algorithm algorithm, Map<String, String> claims) {
		return TestJws.withAlgorithm(algorithm).kid("key").payload(claimsText(claims));
	}

	private static String claimsText(Map<String, String> claims) {
		return JsonText.object(new ArrayList<>(claims.entrySet()));
	}

	private static String resource(String name) throws IOException {
		try (InputStream input = IdTokenValidatorTests.class.getResourceAsStream("/vectors/oidc-core/" + name)) {
			if (input == null)
				throw new IllegalStateException("The OIDC test example is missing.");
			return new String(input.readAllBytes(), StandardCharsets.UTF_8);
		}
	}
}
