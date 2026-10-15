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

import com.revetsec.ErrorCategory;
import com.revetsec.internal.jose.TestClaims;
import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestJwk;
import com.revetsec.testing.TestJwk.Fixture;
import com.revetsec.testing.TestJws;
import com.revetsec.testing.TestJws.Algorithm;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Shared fixtures for the {@link JwtValidator} tests: one issuer, one audience, a fixed clock, fixture keys as static
 * key sources, and tokens signed by them. Every token's claims default to a valid set for {@link #NOW}; a test changes
 * only what it is about.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JwtFixtures {
	static final String ISSUER = "https://issuer.example.com";
	static final String AUDIENCE = "https://api.example.com";
	static final Instant NOW = Instant.parse("2026-09-27T12:00:00Z");
	static final String KID = "key-1";

	private JwtFixtures() {
		// Static helpers only.
	}

	/**
	 * A clock stopped at {@link #NOW}.
	 */
	static @NonNull TestClock clock() {
		return TestClock.fromInstant(NOW);
	}

	/**
	 * Valid claims for {@link #NOW}: {@code iss}, {@code aud}, {@code sub}, {@code iat} now, and {@code exp} in five
	 * minutes.
	 */
	static @NonNull TestClaims claims() {
		return TestClaims.empty().put("iss", ISSUER).put("sub", "subject-1").put("aud", AUDIENCE)
				.put("iat", NOW.getEpochSecond()).put("exp", NOW.plus(Duration.ofMinutes(5)).getEpochSecond());
	}

	/**
	 * A JWK for a fixture key with {@code kid} {@code KID}.
	 */
	static TestJwk.@NonNull Builder jwk(@NonNull Fixture fixture) {
		return TestJwk.withFixture(fixture).kid(KID);
	}

	/**
	 * A static source over one or more JWKs.
	 */
	static @NonNull StaticJwksSource source(@NonNull String @NonNull ... jwks) {
		return StaticJwksSource.fromJwks(JwtFixtures.assertParsedJwks(TestJwk.keySet(List.of(jwks))));
	}

	/**
	 * A static source over a fixture key with {@code kid} {@code KID}.
	 */
	static @NonNull StaticJwksSource source(@NonNull Fixture fixture) {
		return source(jwk(fixture).toJson());
	}

	/**
	 * A validator builder for {@link #ISSUER} and {@link #AUDIENCE} at {@link #NOW} over {@code source}.
	 */
	static JwtValidator.@NonNull Builder validator(@NonNull JwksSource source) {
		return JwtValidator.withIssuer(ISSUER).jwksSource(source).expectedAudiences(Set.of(AUDIENCE))
				.clock(clock());
	}

	/**
	 * A validator for the fixture key, allowing only {@code algorithm}.
	 */
	static @NonNull JwtValidator validator(@NonNull Fixture fixture,
																@NonNull JwsAlgorithm algorithm) {
		return validator(source(fixture)).allowedAlgorithms(Set.of(algorithm)).build();
	}

	/**
	 * A token builder with {@code kid} {@code KID} and the default claims.
	 */
	static TestJws.@NonNull Builder token(@NonNull Algorithm algorithm) {
		return TestJws.withAlgorithm(algorithm).kid(KID).payload(claims().toJson());
	}

	/**
	 * A token with {@code kid} {@code KID} and {@code claims}, signed by the fixture key.
	 */
	static @NonNull String signed(@NonNull Fixture fixture,
											 @NonNull Algorithm algorithm,
											 @NonNull TestClaims claims) {
		return TestJws.withAlgorithm(algorithm).kid(KID).payload(claims.toJson()).sign(fixture.getPrivateKey());
	}

	/**
	 * A token with {@code kid} {@code KID} and the default claims, signed by the fixture key.
	 */
	static @NonNull String signed(@NonNull Fixture fixture,
											 @NonNull Algorithm algorithm) {
		return signed(fixture, algorithm, claims());
	}

	/**
	 * Asserts that validation returns the rejected variant with the exact fixed reason and no input data.
	 */
	static JwtValidationResult.@NonNull Rejected assertRejected(JoseException.@NonNull Reason reason,
			@NonNull JwtValidator validator, @NonNull String token) {
		JwtValidationResult.Rejected rejected = Assertions.assertInstanceOf(JwtValidationResult.Rejected.class,
				validator.validateResult(token));
		Assertions.assertEquals(reason, rejected.getReason());
		if (token.length() >= 8)
			Assertions.assertFalse(rejected.toString().contains(token));
		return rejected;
	}

	/**
	 * Asserts that {@code exception} carries {@code reason} with its leaf, message, category, no cause and no
	 * transience.
	 */
	static void assertReason(JoseException.@NonNull Reason reason,
													 @NonNull JoseException exception) {
		Assertions.assertEquals(reason, exception.getReason(), () -> "reason of " + exception);
		Assertions.assertEquals(leafFor(reason), exception.getClass());
		Assertions.assertEquals(reason.category(), exception.getCategory());
		Assertions.assertEquals(reason.message(), exception.getMessage());
		Assertions.assertNull(exception.getCause());
		Assertions.assertFalse(exception.isTransient());
	}

	/**
	 * The leaf class a reason's category belongs to.
	 */
	static @NonNull Class<? extends @NonNull JoseException> leafFor(JoseException.@NonNull Reason reason) {
		ErrorCategory category = reason.category();
		if (category == ErrorCategory.MALFORMED_INPUT)
			return MalformedJoseInputException.class;
		if (category == ErrorCategory.UNSUPPORTED)
			return UnsupportedJoseFeatureException.class;
		return JwtValidationException.class;
	}

	/**
	 * Validates and returns the token, failing the test with the reason if it is refused.
	 */
	static @NonNull Jwt assertAccepted(@NonNull JwtValidator validator, @NonNull String token) {
		return Assertions.assertInstanceOf(JwtValidationResult.Succeeded.class,
				validator.validateResult(token)).getJwt();
	}

	static @NonNull Jwks assertParsedJwks(@NonNull String json) {
		return Assertions.assertInstanceOf(JwksParseResult.Succeeded.class,
				Jwks.fromJsonResult(json)).getJwks();
	}

	/**
	 * A key set JSON text from several JWK builders.
	 */
	static @NonNull String keySet(TestJwk.@NonNull Builder @NonNull ... keys) {
		List<String> jwks = new ArrayList<>();
		for (TestJwk.Builder key : keys)
			jwks.add(key.toJson());
		return TestJwk.keySet(jwks);
	}

	/**
	 * Asserts that a hook's {@code elapsed} argument lies between zero and the time the test measured around the call
	 * that fired it ({@link System#nanoTime()} read just before and just after the call), and returns it (M2-3).
	 */
	static @NonNull Duration assertElapsedWithin(@Nullable Object elapsed,
																			long beforeNanos,
																			long afterNanos) {
		Duration duration = Assertions.assertInstanceOf(Duration.class, elapsed);
		Duration span = Duration.ofNanos(afterNanos - beforeNanos);
		Assertions.assertFalse(duration.isNegative(), duration::toString);
		Assertions.assertTrue(duration.compareTo(span) <= 0, () -> duration + " is longer than the call, " + span);
		return duration;
	}

	/**
	 * The epoch second of {@code NOW + offset}.
	 */
	static long at(@NonNull Duration offset) {
		return NOW.plus(requireNonNull(offset)).getEpochSecond();
	}
}
