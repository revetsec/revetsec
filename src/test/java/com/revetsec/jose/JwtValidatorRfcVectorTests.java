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

import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.jose.RfcJoseExamples;
import com.revetsec.json.JsonBoolean;
import com.revetsec.testing.TestClock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * RFC 7515 appendix A through {@link JwtValidator} (plan M2 exit criterion 2): A.2 (RS256) and A.3 (ES256) validate
 * for issuer {@code joe} with any audience before their {@code exp}, and fail once a signature bit flips or the clock
 * passes {@code exp}; A.1 (HS256) is never allowed here; A.5 (unsecured) is
 * {@link JoseException.Reason#ALGORITHM_NOT_ALLOWED}; and the JSON serialization of A.6 and A.7 is
 * {@link JoseException.Reason#JSON_SERIALIZATION}.
 * <p>
 * RFC 7515 was read from rfc-editor.org on 2026-09-28: sections A.2.1 and A.3.1 sign the payload of section A.1.1,
 * {@code {"iss":"joe", "exp":1300819380, "http://example.com/is_root":true}} with CRLF line breaks, which has no
 * {@code aud}, so these validators accept any audience, and their headers carry no {@code typ}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JwtValidatorRfcVectorTests {
	private static final Instant BEFORE_EXPIRY = Instant.ofEpochSecond(RfcJoseExamples.RFC_7515_JWT_EXPIRES_AT - 1);

	// RFC 7515 A.2: the RS256 example validates under the default {RS256}, with its claims read as sent.
	@Test
	void appendixA2ValidatesAsAJwt() {
		JwtValidator validator = joe(RfcJoseExamples.rfc7515A2Key(), Set.of(JwsAlgorithm.RS256), BEFORE_EXPIRY);
		Jwt jwt = JwtFixtures.assertAccepted(validator, RfcJoseExamples.RFC_7515_A2_JWS);

		Assertions.assertEquals(JwsAlgorithm.RS256, jwt.getAlgorithm());
		Assertions.assertEquals(Optional.empty(), jwt.getKeyId());
		Assertions.assertEquals(Optional.empty(), jwt.getType());
		Assertions.assertEquals(RfcJoseExamples.RFC_7515_A2_JWS, jwt.toCompactSerialization());
		Assertions.assertEquals("joe", jwt.getClaims().getIssuer().orElseThrow());
		Assertions.assertEquals(Instant.ofEpochSecond(RfcJoseExamples.RFC_7515_JWT_EXPIRES_AT),
				jwt.getClaims().getExpiresAt().orElseThrow());
		Assertions.assertEquals(List.of(), jwt.getClaims().getAudiences());
		Assertions.assertEquals(JsonBoolean.trueInstance(), jwt.getClaims().getClaim("http://example.com/is_root")
				.orElseThrow());
		Assertions.assertEquals(List.of("iss", "exp", "http://example.com/is_root"),
				List.copyOf(jwt.getClaims().getClaimNames()));
	}

	// RFC 7515 A.3: the ES256 example validates with allowedAlgorithms {ES256}.
	@Test
	void appendixA3ValidatesAsAJwt() {
		JwtValidator validator = joe(RfcJoseExamples.rfc7515A3Key(), Set.of(JwsAlgorithm.ES256), BEFORE_EXPIRY);
		Jwt jwt = JwtFixtures.assertAccepted(validator, RfcJoseExamples.RFC_7515_A3_JWS);
		Assertions.assertEquals(JwsAlgorithm.ES256, jwt.getAlgorithm());
		Assertions.assertEquals("joe", jwt.getClaims().getIssuer().orElseThrow());
	}

	// One flipped signature bit is SIGNATURE_MISMATCH, and the clock at exp + 60 s is EXPIRED for both examples.
	@Test
	void theExamplesFailOnAFlippedBitAndAfterExpiry() throws Exception {
		Instant expired = Instant.ofEpochSecond(RfcJoseExamples.RFC_7515_JWT_EXPIRES_AT + 60);

		JwtFixtures.assertRejected(JoseException.Reason.SIGNATURE_MISMATCH, joe(RfcJoseExamples.rfc7515A2Key(),
				Set.of(JwsAlgorithm.RS256), BEFORE_EXPIRY), flip(RfcJoseExamples.RFC_7515_A2_JWS));
		JwtFixtures.assertRejected(JoseException.Reason.SIGNATURE_MISMATCH, joe(RfcJoseExamples.rfc7515A3Key(),
				Set.of(JwsAlgorithm.ES256), BEFORE_EXPIRY), flip(RfcJoseExamples.RFC_7515_A3_JWS));
		JwtFixtures.assertRejected(JoseException.Reason.EXPIRED, joe(RfcJoseExamples.rfc7515A2Key(),
				Set.of(JwsAlgorithm.RS256), expired), RfcJoseExamples.RFC_7515_A2_JWS);
		JwtFixtures.assertRejected(JoseException.Reason.EXPIRED, joe(RfcJoseExamples.rfc7515A3Key(),
				Set.of(JwsAlgorithm.ES256), expired), RfcJoseExamples.RFC_7515_A3_JWS);
		JwtFixtures.assertAccepted(joe(RfcJoseExamples.rfc7515A2Key(), Set.of(JwsAlgorithm.RS256),
				expired.minusSeconds(1)), RfcJoseExamples.RFC_7515_A2_JWS);
	}

	// RFC 7515 A.1 (HS256) is ALGORITHM_NOT_ALLOWED here, whatever the key set holds; it verifies only through the
	// internal HMAC engine.
	@Test
	void appendixA1IsNeverAllowed() {
		JwtFixtures.assertRejected(JoseException.Reason.ALGORITHM_NOT_ALLOWED, joe(RfcJoseExamples.rfc7515A2Key(),
				Set.of(JwsAlgorithm.RS256), BEFORE_EXPIRY), RfcJoseExamples.RFC_7515_A1_JWS);
	}

	// RFC 7515 A.5 (RFC 8725 section 3.2): the unsecured example is ALGORITHM_NOT_ALLOWED.
	@Test
	void appendixA5IsNotAllowed() {
		JwtFixtures.assertRejected(JoseException.Reason.ALGORITHM_NOT_ALLOWED, joe(RfcJoseExamples.rfc7515A2Key(),
				Set.of(JwsAlgorithm.RS256), BEFORE_EXPIRY), RfcJoseExamples.RFC_7515_A5_JWS);
	}

	// RFC 7515 A.6 and A.7: the general and flattened JSON serializations, here built from the A.2 and A.3 parts in
	// the appendices' shapes, are JSON_SERIALIZATION.
	@Test
	void theJsonSerializationsAreUnsupported() {
		List<String> a2 = segments(RfcJoseExamples.RFC_7515_A2_JWS);
		List<String> a3 = segments(RfcJoseExamples.RFC_7515_A3_JWS);
		String general = "{\"payload\":\"" + a2.get(1) + "\",\"signatures\":[{\"protected\":\"" + a2.get(0)
				+ "\",\"header\":{\"kid\":\"2010-12-29\"},\"signature\":\"" + a2.get(2) + "\"},{\"protected\":\"" + a3.get(0)
				+ "\",\"header\":{\"kid\":\"e9bc097a-ce51-4036-9562-d2ade882db0d\"},\"signature\":\"" + a3.get(2) + "\"}]}";
		String flattened = "{\"payload\":\"" + a3.get(1) + "\",\"protected\":\"" + a3.get(0) + "\",\"header\":{\"kid\":"
				+ "\"e9bc097a-ce51-4036-9562-d2ade882db0d\"},\"signature\":\"" + a3.get(2) + "\"}";
		JwtValidator validator = joe(RfcJoseExamples.rfc7515A3Key(), Set.of(JwsAlgorithm.ES256), BEFORE_EXPIRY);

		JwtFixtures.assertRejected(JoseException.Reason.JSON_SERIALIZATION, validator, general);
		JwtFixtures.assertRejected(JoseException.Reason.JSON_SERIALIZATION, validator, flattened);
	}

	private static JwtValidator joe(String jwk,
																	Set<JwsAlgorithm> algorithms,
																	Instant now) {
		return JwtValidator.withIssuer("joe").jsonWebKeySource(StaticJsonWebKeySource.fromJsonWebKeySet(
				JsonWebKeySet.fromJson("{\"keys\":[" + jwk + "]}"))).acceptAnyAudience(true).allowedAlgorithms(algorithms)
				.clock(TestClock.fromInstant(now)).build();
	}

	private static List<String> segments(String jws) {
		int first = jws.indexOf('.');
		int second = jws.lastIndexOf('.');
		return List.of(jws.substring(0, first), jws.substring(first + 1, second), jws.substring(second + 1));
	}

	private static String flip(String jws) throws Exception {
		int dot = jws.lastIndexOf('.');
		byte[] signature = Base64Url.decode(jws.substring(dot + 1));
		signature[signature.length - 1] ^= 1;
		return jws.substring(0, dot + 1) + Base64Url.encode(signature);
	}
}
