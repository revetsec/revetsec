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

package com.revetsec.jose;

import org.jspecify.annotations.NonNull;

import com.revetsec.testing.RecordingObserver;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws.Algorithm;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.time.Duration;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

/**
 * {@link JwtValidator.Builder}: the settings, their defaults and ranges (M2-4; R8 rows {@code JOSE_CLOCK_SKEW} and
 * {@code COMPACT_JWT_SIZE}), the required settings (IllegalStateException) and bad values (IllegalArgumentException,
 * R15), HMAC refused (G8-2), any audience observed at build (plan M2 exit criterion 8), and no I/O at build.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JwtValidatorBuilderTests {
	// M2-4: an empty issuer is refused at once, and a null one is an NPE.
	@Test
	@SuppressWarnings("NullAway")
	void theIssuerMustNotBeEmpty() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> JwtValidator.withIssuer(""));
		Assertions.assertThrows(NullPointerException.class, () -> JwtValidator.withIssuer(null));
		Assertions.assertNotNull(JwtValidator.withIssuer(" "));
	}

	// Exit criterion 8 and R15: a key source is required, and so are expected audiences unless any audience is
	// accepted; each missing one is IllegalStateException at build().
	@Test
	void missingRequiredSettingsAreIllegalState() {
		StaticJsonWebKeySource source = JwtFixtures.source(Fixture.IDP_SIGNING_RSA_2048);

		Assertions.assertThrows(IllegalStateException.class, () -> JwtValidator.withIssuer(JwtFixtures.ISSUER)
				.expectedAudiences(Set.of(JwtFixtures.AUDIENCE)).build());
		Assertions.assertThrows(IllegalStateException.class, () -> JwtValidator.withIssuer(JwtFixtures.ISSUER)
				.jsonWebKeySource(source).build());
		Assertions.assertThrows(IllegalStateException.class, () -> JwtValidator.withIssuer(JwtFixtures.ISSUER)
				.jsonWebKeySource(source).acceptAnyAudience(false).build());
		Assertions.assertThrows(IllegalStateException.class, () -> JwtValidator.withIssuer(JwtFixtures.ISSUER)
				.jsonWebKeySource(source).expectedAudiences(Set.of(JwtFixtures.AUDIENCE)).expectedAudiences(null).build());
		Assertions.assertThrows(IllegalStateException.class, () -> JwtFixtures.validator(source).jsonWebKeySource(null)
				.build());

		Assertions.assertNotNull(JwtValidator.withIssuer(JwtFixtures.ISSUER).jsonWebKeySource(source)
				.acceptAnyAudience(true).build());
		Assertions.assertNotNull(JwtFixtures.validator(source).build());
	}

	// Exit criterion 8 and M2-4: any audience together with expected audiences is IllegalArgumentException, and so
	// are an empty audience set and an empty audience.
	@Test
	void audienceSettingsThatConflictOrAreEmptyAreIllegalArguments() {
		StaticJsonWebKeySource source = JwtFixtures.source(Fixture.IDP_SIGNING_RSA_2048);

		Assertions.assertThrows(IllegalArgumentException.class, () -> JwtFixtures.validator(source).acceptAnyAudience(true)
				.build());
		Assertions.assertThrows(IllegalArgumentException.class, () -> JwtFixtures.validator(source)
				.expectedAudiences(Set.of()).build());
		Assertions.assertThrows(IllegalArgumentException.class, () -> JwtFixtures.validator(source)
				.expectedAudiences(Set.of("a", "")).build());
		Set<String> withNull = new HashSet<>(Arrays.asList("a", null));
		Assertions.assertThrows(NullPointerException.class, () -> JwtFixtures.validator(source)
				.expectedAudiences(withNull));
	}

	// G8-2: the default allows RS256 alone; an empty set, or any HMAC algorithm alongside others, is
	// IllegalArgumentException, because this validator verifies only with public keys.
	@Test
	void theAlgorithmsDefaultToRs256AndNeverIncludeHmac() {
		StaticJsonWebKeySource source = JwtFixtures.source(Fixture.IDP_SIGNING_RSA_2048);

		Assertions.assertThrows(IllegalArgumentException.class, () -> JwtFixtures.validator(source)
				.allowedAlgorithms(Set.of()).build());
		for (JwsAlgorithm hmac : List.of(JwsAlgorithm.HS256, JwsAlgorithm.HS384, JwsAlgorithm.HS512)) {
			Assertions.assertThrows(IllegalArgumentException.class, () -> JwtFixtures.validator(source)
					.allowedAlgorithms(Set.of(hmac)).build());
			Assertions.assertThrows(IllegalArgumentException.class, () -> JwtFixtures.validator(source)
					.allowedAlgorithms(Set.of(JwsAlgorithm.RS256, hmac)).build());
		}
		Assertions.assertThrows(IllegalArgumentException.class, () -> JwtFixtures.validator(source)
				.allowedAlgorithms(EnumSet.allOf(JwsAlgorithm.class)).build());

		// The default is {RS256}: an ES256 token signed by the right key is not allowed, an RS256 one is.
		JwtValidator validator = JwtFixtures.validator(JwtFixtures.source(JwtFixtures.jwk(Fixture.IDP_SIGNING_RSA_2048)
				.toJson(), JwtFixtures.jwk(Fixture.IDP_SIGNING_EC_P256).kid("ec").toJson())).build();
		JwtFixtures.assertAccepted(validator, JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256));
		JwtFixtures.assertRejected(JoseException.Reason.ALGORITHM_NOT_ALLOWED, validator, JwtFixtures.signed(
				Fixture.IDP_SIGNING_EC_P256, Algorithm.ES256));
		// null restores the default.
		JwtValidator restored = JwtFixtures.validator(JwtFixtures.source(Fixture.IDP_SIGNING_EC_P256))
				.allowedAlgorithms(Set.of(JwsAlgorithm.ES256)).allowedAlgorithms(null).build();
		JwtFixtures.assertRejected(JoseException.Reason.ALGORITHM_NOT_ALLOWED, restored, JwtFixtures.signed(
				Fixture.IDP_SIGNING_EC_P256, Algorithm.ES256));
	}

	// M2-4: allowed types are media types without parameters; an empty set allows only tokens without typ; a
	// required type needs an allowed one.
	@Test
	void typeSettingsMustBeMediaTypesWithoutParameters() {
		StaticJsonWebKeySource source = JwtFixtures.source(Fixture.IDP_SIGNING_RSA_2048);

		for (String type : List.of("", "application/jwt; charset=utf-8", "a/b/c", "jwt ", "\u00e9"))
			Assertions.assertThrows(IllegalArgumentException.class, () -> JwtFixtures.validator(source)
					.allowedTypes(Set.of(type)).build(), type);
		Assertions.assertThrows(IllegalArgumentException.class, () -> JwtFixtures.validator(source).allowedTypes(Set.of())
				.typeRequired(true).build());
		Assertions.assertNotNull(JwtFixtures.validator(source).allowedTypes(Set.of()).build());
		Assertions.assertNotNull(JwtFixtures.validator(source).allowedTypes(Set.of("at+jwt", "application/jwt"))
				.typeRequired(true).build());
	}

	// Each setter's null restores the default: typ JWT, not required, and no extra required claims.
	@Test
	void nullRestoresEachDefault() {
		JwtValidator validator = JwtFixtures.validator(JwtFixtures.source(Fixture.IDP_SIGNING_RSA_2048))
				.allowedTypes(Set.of("at+jwt")).allowedTypes(null).typeRequired(true).typeRequired(null)
				.requiredClaims(Set.of("scope")).requiredClaims(null).clockSkew(Duration.ZERO).clockSkew(null)
				.maximumTokenLength(8_192).maximumTokenLength(null).observer(JoseObserver.disabledInstance()).observer(null)
				.clock(null).clock(JwtFixtures.clock()).build();

		JwtFixtures.assertAccepted(validator, JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256));
		JwtFixtures.assertAccepted(validator, JwtFixtures.token(Algorithm.RS256).typ("JWT").sign(
				Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
		JwtFixtures.assertAccepted(validator, JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256,
				JwtFixtures.claims().put("exp", JwtFixtures.at(Duration.ofSeconds(-30)))));
		JwtFixtures.assertAccepted(validator, JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256,
				JwtFixtures.claims().put("pad", "p".repeat(10_000))));
		JwtFixtures.assertAccepted(JwtFixtures.validator(JwtFixtures.source(Fixture.IDP_SIGNING_RSA_2048))
				.typeRequired(false).build(), JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256));
	}

	// M2-4: a required claim name must not be empty.
	@Test
	void anEmptyRequiredClaimNameIsIllegal() {
		StaticJsonWebKeySource source = JwtFixtures.source(Fixture.IDP_SIGNING_RSA_2048);
		Assertions.assertThrows(IllegalArgumentException.class, () -> JwtFixtures.validator(source)
				.requiredClaims(Set.of("sub", "")).build());
		Assertions.assertNotNull(JwtFixtures.validator(source).requiredClaims(Set.of("sub", "jti")).build());
	}

	// R8: the clock skew is within [0, 5 min] (JOSE_CLOCK_SKEW, zero allowed), and the maximum token length within
	// [8 KiB, 1 MiB] (COMPACT_JWT_SIZE); the edges are accepted and one step past each is refused.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> rangedSettingsAreCheckedAgainstTheirLimitRows() {
		StaticJsonWebKeySource source = JwtFixtures.source(Fixture.IDP_SIGNING_RSA_2048);

		return Stream.of(
				DynamicTest.dynamicTest("clockSkew accepts 0 and 5 minutes", () -> {
					Assertions.assertNotNull(JwtFixtures.validator(source).clockSkew(Duration.ZERO).build());
					Assertions.assertNotNull(JwtFixtures.validator(source).clockSkew(Duration.ofMinutes(5)).build());
				}),
				DynamicTest.dynamicTest("clockSkew refuses negative and past 5 minutes", () -> {
					Assertions.assertThrows(IllegalArgumentException.class, () -> JwtFixtures.validator(source)
							.clockSkew(Duration.ofNanos(-1)).build());
					Assertions.assertThrows(IllegalArgumentException.class, () -> JwtFixtures.validator(source)
							.clockSkew(Duration.ofMinutes(5).plusNanos(1)).build());
				}),
				DynamicTest.dynamicTest("maximumTokenLength accepts 8 KiB and 1 MiB", () -> {
					Assertions.assertNotNull(JwtFixtures.validator(source).maximumTokenLength(8_192).build());
					Assertions.assertNotNull(JwtFixtures.validator(source).maximumTokenLength(1_048_576).build());
				}),
				DynamicTest.dynamicTest("maximumTokenLength refuses below 8 KiB and above 1 MiB", () -> {
					Assertions.assertThrows(IllegalArgumentException.class, () -> JwtFixtures.validator(source)
							.maximumTokenLength(8_191).build());
					Assertions.assertThrows(IllegalArgumentException.class, () -> JwtFixtures.validator(source)
							.maximumTokenLength(1_048_577).build());
					Assertions.assertThrows(IllegalArgumentException.class, () -> JwtFixtures.validator(source)
							.maximumTokenLength(0).build());
				}));
	}

	// The defaults: 60 s of skew and a 64 KiB token limit (JOSE_CLOCK_SKEW and COMPACT_JWT_SIZE), shown by their
	// boundaries through validate.
	@Test
	void theDefaultsAreSixtySecondsOfSkewAndSixtyFourKibibytes() {
		StaticJsonWebKeySource source = JwtFixtures.source(Fixture.IDP_SIGNING_RSA_2048);
		JwtValidator validator = JwtFixtures.validator(source).build();

		JwtFixtures.assertAccepted(validator, JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256,
				JwtFixtures.claims().put("exp", JwtFixtures.at(Duration.ofSeconds(-59)))));
		JwtFixtures.assertRejected(JoseException.Reason.EXPIRED, validator, JwtFixtures.signed(
				Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256, JwtFixtures.claims().put("exp",
						JwtFixtures.at(Duration.ofMinutes(-1)))));

		String padded = JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256, JwtFixtures.claims()
				.put("pad", "x".repeat(40_000)));
		JwtFixtures.assertAccepted(validator, padded);
		String tooLong = JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256, JwtFixtures.claims()
				.put("pad", "x".repeat(50_000)));
		Assertions.assertTrue(tooLong.length() > 65_536);
		JwtFixtures.assertRejected(JoseException.Reason.TOKEN_TOO_LARGE, validator, tooLong);
		JwtFixtures.assertAccepted(JwtFixtures.validator(source).maximumTokenLength(1_048_576).build(), tooLong);
	}

	// Exit criterion 8 (M2-4): accepting any audience is reported to didAcceptAnyAudience when the validator is
	// built, with the issuer; a validator with expected audiences reports nothing.
	@Test
	void acceptingAnyAudienceIsObservedAtBuild() {
		RecordingObserver<JoseObserver> recorder = RecordingObserver.fromInterface(JoseObserver.class);
		StaticJsonWebKeySource source = JwtFixtures.source(Fixture.IDP_SIGNING_RSA_2048);

		Assertions.assertNotNull(JwtValidator.withIssuer(JwtFixtures.ISSUER).jsonWebKeySource(source)
				.acceptAnyAudience(true).observer(recorder.getObserver()).build());
		Assertions.assertEquals(1, recorder.getCalls().size());
		Assertions.assertEquals("didAcceptAnyAudience", recorder.getCalls().get(0).getMethodName());
		Assertions.assertEquals(List.of(JwtFixtures.ISSUER), recorder.getCalls().get(0).getArguments());

		Assertions.assertNotNull(JwtFixtures.validator(source).observer(recorder.getObserver()).build());
		Assertions.assertEquals(1, recorder.getCalls().size());

		// A throwing observer is contained: build still succeeds.
		RecordingObserver<JoseObserver> throwing = RecordingObserver.fromInterface(JoseObserver.class,
				() -> new IllegalStateException("observer failure"));
		Assertions.assertNotNull(JwtValidator.withIssuer(JwtFixtures.ISSUER).jsonWebKeySource(source)
				.acceptAnyAudience(true).observer(throwing.getObserver()).build());
		Assertions.assertEquals(1, throwing.getCalls().size());
	}

	// R15 as a convention: every value check (IllegalArgumentException) runs before the required-setting checks
	// (IllegalStateException), so a builder with both kinds of fault reports the bad value.
	@Test
	void badValuesAreReportedBeforeMissingSettings() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> JwtValidator.withIssuer(JwtFixtures.ISSUER)
				.allowedAlgorithms(Set.of(JwsAlgorithm.HS256)).build());
		Assertions.assertThrows(IllegalArgumentException.class, () -> JwtValidator.withIssuer(JwtFixtures.ISSUER)
				.clockSkew(Duration.ofHours(1)).build());
		Assertions.assertThrows(IllegalArgumentException.class, () -> JwtValidator.withIssuer(JwtFixtures.ISSUER)
				.allowedTypes(Set.of("a;b")).build());
	}

	// A validator is immutable after build: changing the builder, or a set passed to it, changes nothing already
	// built, and validators compare by reference (M2-5).
	@Test
	void aBuiltValidatorIsIndependentOfItsBuilderAndComparesByReference() {
		StaticJsonWebKeySource source = JwtFixtures.source(Fixture.IDP_SIGNING_RSA_2048);
		Set<String> audiences = new HashSet<>(Set.of(JwtFixtures.AUDIENCE));
		JwtValidator.Builder builder = JwtFixtures.validator(source).expectedAudiences(audiences);
		JwtValidator first = builder.build();

		audiences.clear();
		audiences.add("changed");
		Assertions.assertSame(builder, builder.expectedAudiences(Set.of("other")));
		JwtFixtures.assertAccepted(first, JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256));
		JwtValidator second = builder.build();
		JwtFixtures.assertRejected(JoseException.Reason.AUDIENCE_MISMATCH, second, JwtFixtures.signed(
				Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256));

		Assertions.assertNotEquals(first, JwtFixtures.validator(source).build());
		Assertions.assertEquals(first, first);
		Assertions.assertTrue(first.toString().startsWith("JwtValidator{issuer=" + JwtFixtures.ISSUER));
	}
}
