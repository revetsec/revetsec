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

package com.revetsec.internal.jose;

import org.jspecify.annotations.NonNull;

import com.revetsec.internal.crypto.HashAlgorithm;
import com.revetsec.internal.crypto.Hmac;
import com.revetsec.internal.crypto.VerifyResult;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.jose.JoseException;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.json.JsonObject;
import com.revetsec.testing.TestJsonWebKeys;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws;
import com.revetsec.testing.TestJws.Algorithm;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * {@link JwtProcessor} and {@link JwsVerifier}: the pipeline's halves and their order (plan "JOSE semantics", steps 1
 * to 14): the key-independent checks before any key, a selection without a key turned into its reason, a selected key
 * that does not fit refused, the signature over the received text before the payload is read, the claims last, and
 * the internal HMAC path over a configured secret (RFC 7518 section 3.2).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JwtProcessorTests {
	private static final Instant NOW = Instant.parse("2026-09-27T12:00:00Z");
	private static final String ISSUER = "https://issuer.example.com";
	private static final JwtClaimsPolicy CLAIMS = JwtClaimsPolicy.fromSettings(ISSUER, Set.of("api"), Set.of(),
			Duration.ofSeconds(60));
	private static final Set<JwsAlgorithm> PUBLIC_KEY_ALGORITHMS = EnumSet.complementOf(EnumSet.of(JwsAlgorithm.HS256,
			JwsAlgorithm.HS384, JwsAlgorithm.HS512));

	// Every public-key algorithm runs the whole pipeline under the full public-key set: prepared, verified with its
	// selected key (which names its alg, since several RSA algorithms are allowed), then its claims checked, giving a
	// VerifiedJwt with the token as received.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> everyPublicKeyAlgorithmCompletesThePipeline() {
		Map<Algorithm, Fixture> fixtures = Map.ofEntries(Map.entry(Algorithm.RS256, Fixture.IDP_SIGNING_RSA_2048),
				Map.entry(Algorithm.RS384, Fixture.IDP_SIGNING_RSA_3072), Map.entry(Algorithm.RS512,
						Fixture.IDP_SIGNING_RSA_2048), Map.entry(Algorithm.PS256, Fixture.IDP_SIGNING_RSA_2048),
				Map.entry(Algorithm.PS384, Fixture.IDP_SIGNING_RSA_3072), Map.entry(Algorithm.PS512,
						Fixture.IDP_SIGNING_RSA_2048), Map.entry(Algorithm.ES256, Fixture.IDP_SIGNING_EC_P256),
				Map.entry(Algorithm.ES384, Fixture.IDP_SIGNING_EC_P384),
				Map.entry(Algorithm.ES512, Fixture.IDP_SIGNING_EC_P521),
				Map.entry(Algorithm.ED25519, Fixture.ED25519), Map.entry(Algorithm.EDDSA, Fixture.ED25519));

		return fixtures.entrySet().stream().sorted(Map.Entry.comparingByKey()).map(entry -> DynamicTest.dynamicTest(
				entry.getKey().getWireValue(), () -> {
					JwsAlgorithm algorithm = JwsAlgorithm.findByWireValue(entry.getKey().getWireValue()).orElseThrow();
					String token = TestJws.withAlgorithm(entry.getKey()).kid("k").typ("JWT").payload(claims().toJson())
							.sign(entry.getValue().getPrivateKey());
					VerificationKey key = key(TestJsonWebKeys.withFixture(entry.getValue()).kid("k").alg(
							entry.getKey().getWireValue()));

					PreparedJws prepared = JwtProcessor.prepare(token, policy(PUBLIC_KEY_ALGORITHMS));
					Assertions.assertEquals(algorithm, prepared.getAlgorithm());
					Assertions.assertEquals("k", prepared.findKeyId().orElseThrow());
					Assertions.assertEquals("JWT", prepared.findType().orElseThrow());
					Assertions.assertEquals(new KeyQuery(algorithm, "k", PUBLIC_KEY_ALGORITHMS), prepared.getKeyQuery());

					VerifiedJwt jwt = JwtProcessor.complete(prepared, KeySelector.select(List.of(key),
							prepared.getKeyQuery()), CLAIMS, NOW);
					Assertions.assertEquals(algorithm, jwt.algorithm());
					Assertions.assertEquals(token, jwt.compactSerialization());
					Assertions.assertSame(key, jwt.key());
					Assertions.assertEquals(ISSUER, jwt.claims().issuer());
					Assertions.assertEquals("VerifiedJwt{algorithm=" + algorithm.getWireValue() + "}", jwt.toString());
				}));
	}

	// Step 6: a selection without a key gives its reason, and only UNKNOWN is UNKNOWN_KEY.
	@Test
	void aSelectionWithoutAKeyGivesItsReason() throws Exception {
		PreparedJws prepared = prepared(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256, "k");

		assertVerifyFails(JoseException.Reason.UNKNOWN_KEY, prepared, KeySelection.fromKind(KeySelection.Kind.UNKNOWN));
		assertVerifyFails(JoseException.Reason.AMBIGUOUS_KEY, prepared, KeySelection.fromKind(KeySelection.Kind.AMBIGUOUS));
		assertVerifyFails(JoseException.Reason.KEY_ALGORITHM_MISMATCH, prepared, KeySelection.fromKind(
				KeySelection.Kind.ALGORITHM_MISMATCH));
	}

	// Step 6: a selected key is refused if it does not fit the token's query, or has another kid, so a faulty key
	// source cannot make a key verify an algorithm or kid it was not selected for (INV-J3).
	@Test
	void aSelectedKeyThatDoesNotFitTheQueryIsRefused() throws Exception {
		PreparedJws prepared = prepared(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256, "k");

		assertVerifyFails(JoseException.Reason.KEY_ALGORITHM_MISMATCH, prepared, KeySelection.fromKey(key(
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P256).kid("k"))));
		assertVerifyFails(JoseException.Reason.KEY_ALGORITHM_MISMATCH, prepared, KeySelection.fromKey(key(
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("k").alg("PS256"))));
		assertVerifyFails(JoseException.Reason.UNKNOWN_KEY, prepared, KeySelection.fromKey(key(
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("other"))));
		assertVerifyFails(JoseException.Reason.UNKNOWN_KEY, prepared, KeySelection.fromKey(key(
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048))));

		PreparedJws kidless = prepared(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256, null);
		Assertions.assertNotNull(JwtProcessor.verify(kidless, KeySelection.fromKey(key(TestJsonWebKeys.withFixture(
				Fixture.IDP_SIGNING_RSA_2048).kid("any")))));
	}

	// Step 7: a fitting key that did not sign the token is SIGNATURE_MISMATCH; an RSA signature in the 256 to 2,048
	// octet bound but not the key's modulus length is SIGNATURE_MALFORMED.
	@Test
	void theSignatureIsCheckedAgainstTheSelectedKey() throws Exception {
		PreparedJws prepared = prepared(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256, "k");
		assertVerifyFails(JoseException.Reason.SIGNATURE_MISMATCH, prepared, KeySelection.fromKey(key(
				TestJsonWebKeys.withFixture(Fixture.NEGATIVE_ATTACKER_RSA_2048).kid("k"))));
		assertVerifyFails(JoseException.Reason.SIGNATURE_MALFORMED, prepared, KeySelection.fromKey(key(
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_3072).kid("k"))));
	}

	// Defense in depth: a token that skipped step 5 (a PreparedJws built directly) still cannot verify with r = 0 or
	// a short signature; the engine's OUT_OF_RANGE and WRONG_LENGTH at step 7 are SIGNATURE_MALFORMED.
	@Test
	void stepSevenStillRefusesMalformedSignaturesThatSkippedTheShapeCheck() throws Exception {
		VerificationKey key = key(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P256).kid("k"));
		byte[] signingInput = "e30.e30".getBytes(StandardCharsets.US_ASCII);
		byte[] rZero = new byte[64];
		Arrays.fill(rZero, 32, 64, (byte) 1);

		for (byte[] signature : List.of(rZero, new byte[63])) {
			PreparedJws unchecked = new PreparedJws("e30.e30.x", JwsAlgorithm.ES256, "k", null, signingInput,
					"{}".getBytes(StandardCharsets.US_ASCII), signature, new KeyQuery(JwsAlgorithm.ES256, "k",
					Set.of(JwsAlgorithm.ES256)), JsonLimits.jose(65_536));
			JoseFailure failure = Assertions.assertThrows(JoseFailure.class, () -> JwtProcessor.verify(unchecked,
					KeySelection.fromKey(key)));
			Assertions.assertEquals(JoseException.Reason.SIGNATURE_MALFORMED, failure.getReason());
		}
	}

	// Steps 7 then 8: the payload is read only after the signature verifies, so a forged token with a malformed
	// payload is SIGNATURE_MISMATCH, never CLAIMS; with a good signature the same payload is CLAIMS.
	@Test
	void thePayloadIsReadOnlyAfterTheSignatureVerifies() throws Exception {
		TestJws.Builder builder = TestJws.withAlgorithm(Algorithm.RS256).kid("k").payload("not json");
		VerificationKey key = key(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("k"));

		PreparedJws forged = JwtProcessor.prepare(builder.sign(Fixture.NEGATIVE_ATTACKER_RSA_2048.getPrivateKey()),
				policy(Set.of(JwsAlgorithm.RS256)));
		JoseFailure forgedFailure = Assertions.assertThrows(JoseFailure.class, () -> JwtProcessor.complete(forged,
				KeySelection.fromKey(key), CLAIMS, NOW));
		Assertions.assertEquals(JoseException.Reason.SIGNATURE_MISMATCH, forgedFailure.getReason());

		PreparedJws genuine = JwtProcessor.prepare(builder.sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()),
				policy(Set.of(JwsAlgorithm.RS256)));
		Assertions.assertArrayEquals("not json".getBytes(StandardCharsets.UTF_8), JwtProcessor.verify(genuine,
				KeySelection.fromKey(key)).getPayload());
		JoseFailure genuineFailure = Assertions.assertThrows(JoseFailure.class, () -> JwtProcessor.complete(genuine,
				KeySelection.fromKey(key), CLAIMS, NOW));
		Assertions.assertEquals(JoseException.Reason.CLAIMS, genuineFailure.getReason());
	}

	// Steps 1 to 5 run before any key: each fails with its own reason on a token that is also wrong in every later
	// step, and the signature shape is checked last among them.
	@Test
	void theKeyIndependentChecksRunInOrder() {
		String badSignature = TestJws.withAlgorithm(Algorithm.ES256).kid("k").payload("x").withSignature(new byte[63]);

		assertPrepareFails(JoseException.Reason.TOKEN_TOO_LARGE, "a".repeat(65_537) + "." + badSignature);
		assertPrepareFails(JoseException.Reason.TOKEN_SYNTAX, badSignature + "=");
		assertPrepareFails(JoseException.Reason.ALGORITHM_NOT_ALLOWED, TestJws.withAlgorithm(Algorithm.ES256).alg("none")
				.payload("x").withSignature(new byte[63]));
		assertPrepareFails(JoseException.Reason.SIGNATURE_MALFORMED, badSignature);
	}

	// Step 5: each algorithm family's key-independent shape, reported by the internal engine, with the shape check's
	// result for the boundary lengths.
	@Test
	void theShapeCheckKnowsEachAlgorithmsLengths() {
		for (JwsAlgorithm algorithm : List.of(JwsAlgorithm.RS256, JwsAlgorithm.PS512)) {
			for (int length : List.of(0, 1, 255, 2_049, 4_096))
				Assertions.assertEquals(VerifyResult.WRONG_LENGTH, JwsVerifier.findShapeFailure(algorithm, new byte[length])
						.orElseThrow(), algorithm + " " + length);
			for (int length : List.of(256, 384, 512, 2_048))
				Assertions.assertTrue(JwsVerifier.findShapeFailure(algorithm, new byte[length]).isEmpty());
		}
		for (JwsAlgorithm algorithm : List.of(JwsAlgorithm.ED25519, JwsAlgorithm.EDDSA)) {
			Assertions.assertTrue(JwsVerifier.findShapeFailure(algorithm, new byte[64]).isEmpty());
			for (int length : List.of(0, 63, 65, 128))
				Assertions.assertEquals(VerifyResult.WRONG_LENGTH, JwsVerifier.findShapeFailure(algorithm,
						new byte[length]).orElseThrow());
		}
		Map<JwsAlgorithm, Integer> hmac = Map.of(JwsAlgorithm.HS256, 32, JwsAlgorithm.HS384, 48, JwsAlgorithm.HS512, 64);
		hmac.forEach((algorithm, length) -> {
			Assertions.assertTrue(JwsVerifier.findShapeFailure(algorithm, new byte[length]).isEmpty());
			Assertions.assertEquals(VerifyResult.WRONG_LENGTH, JwsVerifier.findShapeFailure(algorithm,
					new byte[length - 1]).orElseThrow());
			Assertions.assertEquals(VerifyResult.WRONG_LENGTH, JwsVerifier.findShapeFailure(algorithm,
					new byte[length + 1]).orElseThrow());
		});
		byte[] nonZero = new byte[64];
		Arrays.fill(nonZero, (byte) 1);
		Assertions.assertTrue(JwsVerifier.findShapeFailure(JwsAlgorithm.ES256, nonZero).isEmpty());
		Assertions.assertEquals(VerifyResult.OUT_OF_RANGE, JwsVerifier.findShapeFailure(JwsAlgorithm.ES256,
				new byte[64]).orElseThrow());
		Assertions.assertEquals(VerifyResult.WRONG_LENGTH, JwsVerifier.findShapeFailure(JwsAlgorithm.ES384,
				nonZero).orElseThrow());
	}

	// A public key never verifies an HMAC tag, whatever its bytes: the HS* family has no public-key engine.
	@Test
	void aPublicKeyNeverVerifiesAnHmacTag() {
		PublicKey rsa = Fixture.IDP_SIGNING_RSA_2048.getPublicKey();
		for (JwsAlgorithm algorithm : List.of(JwsAlgorithm.HS256, JwsAlgorithm.HS384, JwsAlgorithm.HS512))
			Assertions.assertEquals(VerifyResult.MISMATCH, JwsVerifier.verify(algorithm, rsa, new byte[1], new byte[32]));
	}

	// RFC 8725 section 3.1 (read 2026-09-28) and CVE-2015-9235: JwsVerifier's secret engine refuses every algorithm but
	// HS256, HS384 and HS512 itself, whatever its caller checks. The tag is a genuine HMAC of the input under the secret,
	// with the algorithm's hash (SHA-256 for Ed25519 and EdDSA), so an engine without the guard would call it valid; each
	// HMAC algorithm accepts the same inputs.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> theSecretEngineRefusesEveryNonHmacAlgorithm() {
		byte[] secret = new byte[64];
		Arrays.fill(secret, (byte) 0x5a);
		byte[] signingInput = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0".getBytes(StandardCharsets.US_ASCII);

		return Arrays.stream(JwsAlgorithm.values()).map(algorithm -> DynamicTest.dynamicTest(algorithm.name(), () -> {
			byte[] tag = Hmac.compute(Algorithms.findHash(algorithm).orElse(HashAlgorithm.SHA_256), secret, signingInput);
			if (Algorithms.familyOf(algorithm) == Algorithms.Family.HMAC)
				Assertions.assertEquals(VerifyResult.VALID, JwsVerifier.verifyWithSecret(algorithm, secret, signingInput,
						tag));
			else
				Assertions.assertThrows(IllegalArgumentException.class, () -> JwsVerifier.verifyWithSecret(algorithm,
						secret, signingInput, tag));
		}));
	}

	// The HMAC path (internal only; RFC 7518 section 3.2): an HS* token verifies over a secret at least as long as
	// its hash; a wrong secret is SIGNATURE_MISMATCH; a short secret or a non-HMAC algorithm is a configuration error.
	@Test
	void theSecretPathVerifiesOnlyHmacTokensWithLongEnoughSecrets() throws Exception {
		byte[] secret = new byte[32];
		Arrays.fill(secret, (byte) 7);
		String token = TestJws.withAlgorithm(Algorithm.HS256).payload(claims().toJson()).sign(secret);
		PreparedJws prepared = JwtProcessor.prepare(token, policy(Set.of(JwsAlgorithm.HS256)));

		VerifiedJwt jwt = JwtProcessor.completeWithSecret(prepared, secret, CLAIMS, NOW);
		Assertions.assertNull(jwt.key());
		Assertions.assertEquals(JwsAlgorithm.HS256, jwt.algorithm());

		byte[] other = secret.clone();
		other[0] = 8;
		JoseFailure failure = Assertions.assertThrows(JoseFailure.class, () -> JwtProcessor.verifyWithSecret(prepared,
				other));
		Assertions.assertEquals(JoseException.Reason.SIGNATURE_MISMATCH, failure.getReason());

		Assertions.assertThrows(IllegalArgumentException.class, () -> JwtProcessor.verifyWithSecret(prepared,
				Arrays.copyOf(secret, 31)));
		Assertions.assertThrows(IllegalArgumentException.class, () -> JwtProcessor.verifyWithSecret(prepared,
				new byte[0]));
		PreparedJws rsa = prepared(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256, "k");
		Assertions.assertThrows(IllegalArgumentException.class, () -> JwtProcessor.verifyWithSecret(rsa, secret));
		Assertions.assertThrows(IllegalArgumentException.class, () -> JwtProcessor.completeWithSecret(rsa, secret, CLAIMS,
				NOW));
	}

	// The prepared token keeps its parts private: accessors hand out copies, and toString shows the algorithm only.
	@Test
	void aPreparedTokenHandsOutCopiesAndDescribesOnlyItsAlgorithm() throws Exception {
		PreparedJws prepared = prepared(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256, "secret-kid");

		prepared.signature()[0] ^= 1;
		prepared.payload()[0] ^= 1;
		prepared.signingInput()[0] ^= 1;
		Assertions.assertNotNull(JwtProcessor.verify(prepared, KeySelection.fromKey(key(TestJsonWebKeys.withFixture(
				Fixture.IDP_SIGNING_RSA_2048).kid("secret-kid")))));
		Assertions.assertEquals("PreparedJws{algorithm=RS256}", prepared.toString());
		VerifiedJws verified = JwtProcessor.verify(prepared, KeySelection.fromKey(key(TestJsonWebKeys.withFixture(
				Fixture.IDP_SIGNING_RSA_2048).kid("secret-kid"))));
		verified.getPayload()[0] ^= 1;
		Assertions.assertEquals('{', verified.getPayload()[0]);
		Assertions.assertEquals("VerifiedJws{algorithm=RS256, payloadLength=" + verified.getPayload().length + "}",
				verified.toString());
	}

	private static @NonNull TestClaims claims() {
		return TestClaims.empty().put("iss", ISSUER).put("aud", "api").put("exp", NOW.getEpochSecond() + 300);
	}

	private static @NonNull JoseHeaderPolicy policy(@NonNull Set<@NonNull JwsAlgorithm> algorithms) {
		return JoseHeaderPolicy.fromSettings(65_536, algorithms, Set.of("JWT"), false);
	}

	private static @NonNull PreparedJws prepared(@NonNull Fixture fixture,
																			@NonNull Algorithm algorithm,
																			@Nullable String kid) throws JoseFailure {
		String token = TestJws.withAlgorithm(algorithm).kid(kid).payload(claims().toJson()).sign(fixture.getPrivateKey());
		return JwtProcessor.prepare(token, policy(Set.of(JwsAlgorithm.findByWireValue(algorithm.getWireValue())
				.orElseThrow())));
	}

	static @NonNull VerificationKey key(TestJsonWebKeys.@NonNull Builder jwk) throws Exception {
		return JwkParser.parse((JsonObject) JsonCodec.parse(jwk.toJson().getBytes(StandardCharsets.UTF_8),
				JsonLimits.jose(65_536)));
	}

	private static void assertVerifyFails(JoseException.@NonNull Reason reason,
																				@NonNull PreparedJws prepared,
																				@NonNull KeySelection selection) {
		JoseFailure failure = Assertions.assertThrows(JoseFailure.class, () -> JwtProcessor.verify(prepared, selection));
		Assertions.assertEquals(reason, failure.getReason());
		JoseFailure completeFailure = Assertions.assertThrows(JoseFailure.class, () -> JwtProcessor.complete(prepared,
				selection, CLAIMS, NOW));
		Assertions.assertEquals(reason, completeFailure.getReason());
	}

	private static void assertPrepareFails(JoseException.@NonNull Reason reason,
																				 @NonNull String token) {
		JoseFailure failure = Assertions.assertThrows(JoseFailure.class, () -> JwtProcessor.prepare(token,
				policy(Set.of(JwsAlgorithm.ES256))));
		Assertions.assertEquals(reason, failure.getReason());
	}
}
