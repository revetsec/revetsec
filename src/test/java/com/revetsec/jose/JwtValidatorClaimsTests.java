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

import com.revetsec.internal.jose.TestClaims;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws;
import com.revetsec.testing.TestJws.Algorithm;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Stream;

/**
 * {@link JwtValidator#validate(String)} on the JWT claims (plan "JOSE semantics", steps 8 to 14; plan M2 exit
 * criteria 9 and 10; RFC 7519 sections 2, 4.1 and 7.2): their types, the exact issuer, the key's JWK {@code issuer}
 * member (INV-C6), the audience, the time checks at their boundaries for three skews, the required claims, and
 * {@code cnf} (INV-G6). The claims are read only after the signature verifies.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JwtValidatorClaimsTests {
	// Exit criterion 9 (RFC 7519 sections 4.1.4 to 4.1.6): at skews 0, 60 s and 5 minutes, exp is accepted until
	// exp + skew and EXPIRED from it, and nbf and iat are accepted at now + skew and refused one second later.
	@TestFactory
	Stream<DynamicTest> theTimeChecksHoldAtTheirBoundariesForEachSkew() {
		return Stream.of(Duration.ZERO, Duration.ofSeconds(60), Duration.ofMinutes(5)).map(skew -> DynamicTest.dynamicTest(
				"skew " + skew, () -> {
					JwtValidator validator = JwtFixtures.validator(JwtFixtures.source(Fixture.IDP_SIGNING_RSA_2048))
							.clockSkew(skew).build();
					Duration beforeNow = skew.negated();

					accept(validator, JwtFixtures.claims().put("exp", JwtFixtures.at(beforeNow.plusSeconds(1))));
					reject(JoseException.Reason.EXPIRED, validator, JwtFixtures.claims().put("exp", JwtFixtures.at(beforeNow)));
					accept(validator, JwtFixtures.claims().put("nbf", JwtFixtures.at(skew)));
					reject(JoseException.Reason.NOT_YET_VALID, validator, JwtFixtures.claims().put("nbf",
							JwtFixtures.at(skew.plusSeconds(1))));
					accept(validator, JwtFixtures.claims().put("iat", JwtFixtures.at(skew)));
					reject(JoseException.Reason.ISSUED_IN_FUTURE, validator, JwtFixtures.claims().put("iat",
							JwtFixtures.at(skew.plusSeconds(1))));
				}));
	}

	// Exit criterion 9 at the 60 s default, in the plan's own terms: exp + 59 s accepted and exp + 60 s EXPIRED; nbf
	// and iat at now + 60 s accepted and at now + 61 s refused.
	@Test
	void theDefaultSkewBoundariesAreFiftyNineAndSixtyOneSeconds() {
		JwtValidator validator = JwtFixtures.validator(Fixture.IDP_SIGNING_RSA_2048, JwsAlgorithm.RS256);

		accept(validator, JwtFixtures.claims().put("exp", JwtFixtures.at(Duration.ofSeconds(-59))));
		reject(JoseException.Reason.EXPIRED, validator, JwtFixtures.claims().put("exp", JwtFixtures.at(
				Duration.ofMinutes(-1))));
		accept(validator, JwtFixtures.claims().put("nbf", JwtFixtures.at(Duration.ofMinutes(1))));
		reject(JoseException.Reason.NOT_YET_VALID, validator, JwtFixtures.claims().put("nbf", JwtFixtures.at(
				Duration.ofSeconds(61))));
		accept(validator, JwtFixtures.claims().put("iat", JwtFixtures.at(Duration.ofMinutes(1))));
		reject(JoseException.Reason.ISSUED_IN_FUTURE, validator, JwtFixtures.claims().put("iat", JwtFixtures.at(
				Duration.ofSeconds(61))));
	}

	// Exit criterion 9 (RFC 7519 section 2): a fractional NumericDate is accepted and read to the nanosecond; exp as
	// a string, as 2^63 or as JSON null is CLAIMS; exp absent is MISSING_CLAIM.
	@Test
	void expIsANumericDate() {
		JwtValidator validator = JwtFixtures.validator(Fixture.IDP_SIGNING_RSA_2048, JwsAlgorithm.RS256);
		long exp = JwtFixtures.at(Duration.ofMinutes(5));

		Jwt jwt = accept(validator, JwtFixtures.claims().raw("exp", exp + ".5"));
		Assertions.assertEquals(Instant.ofEpochSecond(exp, 500_000_000L), jwt.getClaims().getExpiresAt().orElseThrow());
		for (String value : List.of("\"" + exp + "\"", "9223372036854775808", "null", "true", "[" + exp + "]"))
			reject(JoseException.Reason.CLAIMS, validator, JwtFixtures.claims().raw("exp", value));
		reject(JoseException.Reason.MISSING_CLAIM, validator, JwtFixtures.claims().remove("exp"));
	}

	// Exit criterion 10 (Discovery section 4.3, no normalization): an issuer with a trailing slash or another case is
	// ISSUER_MISMATCH, and iss absent is MISSING_CLAIM.
	@Test
	void theIssuerIsComparedExactly() {
		JwtValidator validator = JwtFixtures.validator(Fixture.IDP_SIGNING_RSA_2048, JwsAlgorithm.RS256);

		for (String issuer : List.of(JwtFixtures.ISSUER + "/", "https://ISSUER.example.com", "https://Issuer.Example.Com",
				JwtFixtures.ISSUER + "#", ""))
			reject(JoseException.Reason.ISSUER_MISMATCH, validator, JwtFixtures.claims().put("iss", issuer));
		reject(JoseException.Reason.MISSING_CLAIM, validator, JwtFixtures.claims().remove("iss"));
		reject(JoseException.Reason.CLAIMS, validator, JwtFixtures.claims().raw("iss", "null"));
	}

	// Exit criterion 10 (RFC 7519 section 4.1.3): aud as [] or [123] is CLAIMS; absent is MISSING_CLAIM; without an
	// expected audience it is AUDIENCE_MISMATCH; extra audiences are allowed; any audience skips the check.
	@Test
	void theAudienceMustNameAnExpectedAudience() {
		JwtValidator validator = JwtFixtures.validator(Fixture.IDP_SIGNING_RSA_2048, JwsAlgorithm.RS256);

		reject(JoseException.Reason.CLAIMS, validator, JwtFixtures.claims().raw("aud", "[]"));
		reject(JoseException.Reason.CLAIMS, validator, JwtFixtures.claims().raw("aud", "[123]"));
		reject(JoseException.Reason.CLAIMS, validator, JwtFixtures.claims().raw("aud", "123"));
		reject(JoseException.Reason.MISSING_CLAIM, validator, JwtFixtures.claims().remove("aud"));
		reject(JoseException.Reason.AUDIENCE_MISMATCH, validator, JwtFixtures.claims().put("aud", "https://other.example"));
		reject(JoseException.Reason.AUDIENCE_MISMATCH, validator, JwtFixtures.claims().put("aud",
				JwtFixtures.AUDIENCE.toUpperCase(Locale.ROOT)));
		Jwt jwt = accept(validator, JwtFixtures.claims().raw("aud", "[\"x\",\"" + JwtFixtures.AUDIENCE + "\"]"));
		Assertions.assertEquals(List.of("x", JwtFixtures.AUDIENCE), jwt.getClaims().getAudiences());

		JwtValidator any = JwtValidator.withIssuer(JwtFixtures.ISSUER).jsonWebKeySource(JwtFixtures.source(
				Fixture.IDP_SIGNING_RSA_2048)).acceptAnyAudience(true).clock(JwtFixtures.clock()).build();
		accept(any, JwtFixtures.claims().remove("aud"));
		accept(any, JwtFixtures.claims().put("aud", "https://other.example"));
		reject(JoseException.Reason.CLAIMS, any, JwtFixtures.claims().raw("aud", "[]"));
	}

	// Exit criterion 10: a required claim that is absent or JSON null is MISSING_CLAIM; iss, exp and aud are always
	// required, so requiring them again changes nothing.
	@Test
	void requiredClaimsMustBePresentAndNotNull() {
		JwtValidator validator = JwtFixtures.validator(JwtFixtures.source(Fixture.IDP_SIGNING_RSA_2048))
				.requiredClaims(Set.of("scope", "iss", "exp")).build();

		accept(validator, JwtFixtures.claims().put("scope", "read"));
		accept(validator, JwtFixtures.claims().raw("scope", "false"));
		reject(JoseException.Reason.MISSING_CLAIM, validator, JwtFixtures.claims());
		reject(JoseException.Reason.MISSING_CLAIM, validator, JwtFixtures.claims().raw("scope", "null"));
		// A registered claim is typed first, so a null sub is CLAIMS even when sub is required.
		JwtValidator subject = JwtFixtures.validator(JwtFixtures.source(Fixture.IDP_SIGNING_RSA_2048))
				.requiredClaims(Set.of("sub")).build();
		reject(JoseException.Reason.CLAIMS, subject, JwtFixtures.claims().raw("sub", "null"));
		reject(JoseException.Reason.MISSING_CLAIM, subject, JwtFixtures.claims().remove("sub"));
	}

	// Exit criterion 10 (RFC 7800, INV-G6): a token with cnf is bound to a key whose possession this validator does
	// not check, so it is CONFIRMATION_NOT_VERIFIED and never accepted as a bearer token.
	@Test
	void aConfirmationClaimIsNeverAccepted() {
		JwtValidator validator = JwtFixtures.validator(Fixture.IDP_SIGNING_RSA_2048, JwsAlgorithm.RS256);
		for (String cnf : List.of("{\"jkt\":\"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I\"}", "{\"x5t#S256\":\"abc\"}",
				"{}", "null"))
			reject(JoseException.Reason.CONFIRMATION_NOT_VERIFIED, validator, JwtFixtures.claims().raw("cnf", cnf));
	}

	// Exit criterion 10 (INV-C6): a key whose JWK issuer member differs from iss never verifies that issuer's
	// tokens (KEY_ISSUER_MISMATCH, after the signature verified), and one equal to iss does.
	@Test
	void aKeysIssuerMemberBindsItToThatIssuer() {
		JwtValidator bound = JwtFixtures.validator(JwtFixtures.source(JwtFixtures.jwk(Fixture.IDP_SIGNING_RSA_2048)
				.issuer(JwtFixtures.ISSUER).toJson())).build();
		accept(bound, JwtFixtures.claims());

		for (String keyIssuer : List.of("https://other.example.com", JwtFixtures.ISSUER + "/",
				"https://ISSUER.example.com")) {
			JwtValidator other = JwtFixtures.validator(JwtFixtures.source(JwtFixtures.jwk(Fixture.IDP_SIGNING_RSA_2048)
					.issuer(keyIssuer).toJson())).build();
			reject(JoseException.Reason.KEY_ISSUER_MISMATCH, other, JwtFixtures.claims());
		}
	}

	// Exit criterion 10: a key whose issuer member is null, 123, [] or "" is skipped, so it is never usable, for any
	// iss, including the empty one.
	@TestFactory
	Stream<DynamicTest> aKeyWithAMalformedIssuerMemberIsNeverUsable() {
		return Stream.of("null", "123", "[]", "\"\"", "{}", "[\"" + JwtFixtures.ISSUER + "\"]").map(member ->
				DynamicTest.dynamicTest("issuer " + member, () -> {
					StaticJsonWebKeySource source = JwtFixtures.source(JwtFixtures.jwk(Fixture.IDP_SIGNING_RSA_2048)
							.member("issuer", member).toJson(), JwtFixtures.jwk(Fixture.IDP_SIGNING_EC_P384).kid("good")
							.toJson());
					for (String issuer : List.of(JwtFixtures.ISSUER, "", "123")) {
						JwtValidator validator = JwtValidator.withIssuer(issuer.isEmpty() ? "x" : issuer).jsonWebKeySource(
								source).acceptAnyAudience(true).clock(JwtFixtures.clock()).build();
						reject(JoseException.Reason.UNKNOWN_KEY, validator, JwtFixtures.claims().put("iss", issuer));
					}
				}));
	}

	// RFC 7519 section 7.2 steps 9 and 10: a verified payload that is not a JSON object, is empty, or has a
	// duplicate member is CLAIMS; the same payload with a forged signature is SIGNATURE_MISMATCH, because the payload
	// is read only after the signature verifies.
	@Test
	void thePayloadIsAStrictJsonObjectReadOnlyAfterTheSignature() {
		JwtValidator validator = JwtFixtures.validator(Fixture.IDP_SIGNING_RSA_2048, JwsAlgorithm.RS256);
		String duplicateSubject = JwtFixtures.claims().toJson().replace("}", ",\"sub\":\"other\"}");

		for (String payload : List.of("", "[]", "\"claims\"", "not json", duplicateSubject, "{\"iss\":\"\\udc00\"}")) {
			TestJws.Builder builder = JwtFixtures.token(Algorithm.RS256).payload(payload);
			JwtFixtures.assertRejected(JoseException.Reason.CLAIMS, validator, builder.sign(
					Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
			JwtFixtures.assertRejected(JoseException.Reason.SIGNATURE_MISMATCH, validator, builder.sign(
					Fixture.NEGATIVE_ATTACKER_RSA_2048.getPrivateKey()));
		}
		JwtFixtures.assertRejected(JoseException.Reason.CLAIMS, validator, JwtFixtures.token(Algorithm.RS256)
				.payloadBytes(new byte[]{'{', '"', 'a', '"', ':', '"', (byte) 0xFF, '"', '}'}).sign(
						Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
	}

	// The claims checks run in order after the signature: issuer, key issuer, audience, time, required claims, cnf; and
	// within the time step, exp, then iat, then nbf.
	@Test
	void theFirstFailingClaimCheckNamesTheReason() {
		JwtValidator validator = JwtFixtures.validator(JwtFixtures.source(JwtFixtures.jwk(Fixture.IDP_SIGNING_RSA_2048)
				.toJson())).requiredClaims(Set.of("scope")).build();
		TestClaims wrong = JwtFixtures.claims().put("iss", "x").put("aud", "x").put("exp", 1L).raw("cnf", "{}");

		reject(JoseException.Reason.ISSUER_MISMATCH, validator, wrong.copy());
		reject(JoseException.Reason.AUDIENCE_MISMATCH, validator, wrong.copy().put("iss", JwtFixtures.ISSUER));
		reject(JoseException.Reason.EXPIRED, validator, wrong.copy().put("iss", JwtFixtures.ISSUER).put("aud",
				JwtFixtures.AUDIENCE));
		reject(JoseException.Reason.MISSING_CLAIM, validator, wrong.copy().put("iss", JwtFixtures.ISSUER).put("aud",
				JwtFixtures.AUDIENCE).put("exp", JwtFixtures.at(Duration.ofMinutes(1))));
		reject(JoseException.Reason.CONFIRMATION_NOT_VERIFIED, validator, wrong.copy().put("iss", JwtFixtures.ISSUER)
				.put("aud", JwtFixtures.AUDIENCE).put("exp", JwtFixtures.at(Duration.ofMinutes(1))).put("scope", "s"));

		TestClaims valid = JwtFixtures.claims().put("scope", "s");
		long past = JwtFixtures.at(Duration.ofMinutes(-10));
		long future = JwtFixtures.at(Duration.ofMinutes(10));
		long later = JwtFixtures.at(Duration.ofHours(1));
		reject(JoseException.Reason.EXPIRED, validator, valid.copy().put("exp", past).put("iat", future).put("nbf",
				future));
		reject(JoseException.Reason.ISSUED_IN_FUTURE, validator, valid.copy().put("exp", later).put("iat", future)
				.put("nbf", future));
		reject(JoseException.Reason.NOT_YET_VALID, validator, valid.copy().put("exp", later).put("nbf", future));
	}

	private static Jwt accept(JwtValidator validator,
													 TestClaims claims) {
		return JwtFixtures.assertAccepted(validator, JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256,
				claims));
	}

	private static void reject(JoseException.Reason reason,
														 JwtValidator validator,
														 TestClaims claims) {
		JwtFixtures.assertRejected(reason, validator, JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256,
				claims));
	}
}
