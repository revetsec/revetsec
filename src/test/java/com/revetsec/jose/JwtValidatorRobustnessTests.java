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

import com.revetsec.testing.Sentinels;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws;
import com.revetsec.testing.TestJws.Algorithm;
import com.revetsec.testing.TestJws.Variant;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.SplittableRandom;
import java.util.stream.Stream;

/**
 * {@link JwtValidator#validate(String)} on hostile input (INV-G1, R9): whatever the token, it returns a {@link Jwt} or
 * throws one of the three {@link JoseException} leaves, with a fixed message, no cause and no stack of the input;
 * no mutation of a valid token is accepted; and neither the exception nor the validator shows the token, its
 * {@code kid} or its claims. Seeds are fixed, so every run is reproducible.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JwtValidatorRobustnessTests {
	private static final int ROUNDS = 3_000;

	// INV-G1: every single-character mutation of a valid token, for each algorithm family, is refused with a
	// JoseException, unless it left the token unchanged. Nothing else escapes, and no forged variant is accepted.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> mutatedTokensAreRefusedAndNothingElseEscapes() {
		List<Object[]> cases = List.of(new Object[]{Algorithm.RS256, Fixture.IDP_SIGNING_RSA_2048},
				new Object[]{Algorithm.PS384, Fixture.IDP_SIGNING_RSA_3072}, new Object[]{Algorithm.ES256,
						Fixture.IDP_SIGNING_EC_P256}, new Object[]{Algorithm.ES512, Fixture.IDP_SIGNING_EC_P521},
				new Object[]{Algorithm.EDDSA, Fixture.ED25519});
		String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.=+/ {\"";

		return cases.stream().map(entry -> DynamicTest.dynamicTest(entry[0].toString(), () -> {
			Algorithm algorithm = (Algorithm) entry[0];
			Fixture fixture = (Fixture) entry[1];
			JwtValidator validator = JwtFixtures.validator(fixture, JwsAlgorithm.findByWireValue(algorithm.getWireValue())
					.orElseThrow());
			String token = JwtFixtures.signed(fixture, algorithm);
			JwtFixtures.assertAccepted(validator, token);
			SplittableRandom random = new SplittableRandom(algorithm.getWireValue().hashCode());

			for (int round = 0; round < ROUNDS; ++round) {
				StringBuilder mutated = new StringBuilder(token);
				int index = random.nextInt(token.length());
				switch (random.nextInt(3)) {
					case 0 -> mutated.setCharAt(index, alphabet.charAt(random.nextInt(alphabet.length())));
					case 1 -> mutated.deleteCharAt(index);
					default -> mutated.insert(index, alphabet.charAt(random.nextInt(alphabet.length())));
				}
				String candidate = mutated.toString();

				try {
					Jwt jwt = validator.validate(candidate);
					Assertions.assertEquals(token, candidate, "a mutated token was accepted");
					Assertions.assertNotNull(jwt);
				} catch (JoseException expected) {
					JwtFixtures.assertReason(expected.getReason(), expected);
				}
			}
		}));
	}

	// INV-G1: arbitrary text, from empty to 70 KiB, with dots and JSON-looking fragments, never escapes as anything
	// but a JoseException from a static source.
	@Test
	void arbitraryTextNeverEscapesAsAnythingButJoseException() {
		JwtValidator validator = JwtFixtures.validator(Fixture.IDP_SIGNING_RSA_2048, JwsAlgorithm.RS256);
		SplittableRandom random = new SplittableRandom(42L);
		List<String> fragments = List.of("eyJhbGciOiJSUzI1NiJ9", "eyJ9", "e30", ".", "..", "{", "=", "AAAA", "-_",
				"\u00e9", "\ud800", " ", "eyJhbGciOiJub25lIn0", "eyJjcml0IjpbXX0");

		for (int round = 0; round < ROUNDS; ++round) {
			StringBuilder text = new StringBuilder();
			int count = random.nextInt(20);
			for (int index = 0; index < count; ++index)
				text.append(fragments.get(random.nextInt(fragments.size())));
			try {
				Jwt accepted = validator.validate(text.toString());
				Assertions.fail("accepted " + accepted);
			} catch (JoseException expected) {
				JwtFixtures.assertReason(expected.getReason(), expected);
			}
		}

		JwtFixtures.assertRejected(JoseException.Reason.TOKEN_SYNTAX, validator, ".".repeat(65_536));
		JwtFixtures.assertRejected(JoseException.Reason.TOKEN_TOO_LARGE, validator, ".".repeat(65_537));
	}

	// R9: a refused token's exception shows only the reason's fixed message: no part of the token, its kid, its
	// claims or its signature appears in the message, toString or stack trace, and there is no cause or suppressed
	// exception to carry them.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> aRefusalRevealsNothingOfTheToken() {
		JwtValidator validator = JwtFixtures.validator(Fixture.IDP_SIGNING_RSA_2048, JwsAlgorithm.RS256);
		List<String> tokens = new ArrayList<>();
		tokens.add(Sentinels.compactJwt("RS256", 256));
		tokens.add(Sentinels.compactJwt("RS256", 11));
		tokens.add(Sentinels.compactJwt("none", 11));
		tokens.add(Sentinels.compactJwt("ES256", 64));
		tokens.add(JwtFixtures.token(Algorithm.RS256).kid(Sentinels.JWT_KEY_ID).sign(
				Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
		tokens.add(JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256, JwtFixtures.claims().put("aud",
				Sentinels.JWT_CLAIM)));
		tokens.add(JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256, JwtFixtures.claims().put("iss",
				Sentinels.JWT_CLAIM)));
		tokens.add(JwtFixtures.token(Algorithm.RS256).typ(Sentinels.JWT_CLAIM).sign(
				Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
		tokens.add(Sentinels.JWT_CLAIM + "." + Sentinels.JWT_CLAIM + "." + Sentinels.JWT_CLAIM);

		return tokens.stream().map(token -> DynamicTest.dynamicTest(token.substring(0, 12), () -> {
			Assertions.assertTrue(Sentinels.containsSentinel(token), "positive control");
			JoseException exception = Assertions.assertThrows(JoseException.class, () -> validator.validate(token));
			Assertions.assertNull(exception.getCause());
			Assertions.assertEquals(0, exception.getSuppressed().length);
			Sentinels.assertAbsent(exception);
			Assertions.assertFalse(Sentinels.containsSentinel(exception.getMessage()));
			Assertions.assertFalse(Sentinels.containsSentinel(exception.toString()));
		}));
	}

	// R9: an accepted token's Jwt and its claims never show the token or a claim in toString, nor does the validator;
	// the token is available only through the explicit toCompactSerialization.
	@Test
	void anAcceptedTokenIsShownOnlyOnRequest() {
		JwtValidator validator = JwtFixtures.validator(Fixture.IDP_SIGNING_RSA_2048, JwsAlgorithm.RS256);
		String token = JwtFixtures.token(Algorithm.RS256).typ("JWT").payload(JwtFixtures.claims().put("sub",
				Sentinels.JWT_CLAIM).put("jti", Sentinels.JWT_CLAIM).toJson()).sign(Fixture.IDP_SIGNING_RSA_2048
				.getPrivateKey());
		Jwt jwt = JwtFixtures.assertAccepted(validator, token);

		Assertions.assertEquals("Jwt{algorithm=RS256}", jwt.toString());
		Assertions.assertEquals("JwtClaims{<redacted>}", jwt.getClaims().toString());
		Assertions.assertFalse(Sentinels.containsSentinel(validator.toString()));
		Assertions.assertTrue(Sentinels.containsSentinel(jwt.toCompactSerialization()));
		Assertions.assertEquals(Sentinels.JWT_CLAIM, jwt.getClaims().getSubject().orElseThrow());
	}

	// A static source has its keys in memory, so a token it cannot verify is a JwtValidationException (unknown key,
	// mismatched signature), never a JsonWebKeySetUnavailableException.
	@Test
	void aStaticSourceNeverMakesTheKeySetUnavailable() {
		JwtValidator validator = JwtFixtures.validator(JwtFixtures.source(Fixture.IDP_SIGNING_EC_P256)).allowedAlgorithms(
				Set.of(JwsAlgorithm.ES256, JwsAlgorithm.RS256)).build();
		for (String token : List.of(JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256),
				JwtFixtures.token(Algorithm.ES256).kid("unknown").sign(Fixture.IDP_SIGNING_EC_P256.getPrivateKey()),
				JwtFixtures.token(Algorithm.ES256).signed(Fixture.IDP_SIGNING_EC_P256.getPrivateKey()).withVariant(
						Variant.FLIPPED_BIT)))
			Assertions.assertThrows(JwtValidationException.class, () -> validator.validate(token));
	}
}
