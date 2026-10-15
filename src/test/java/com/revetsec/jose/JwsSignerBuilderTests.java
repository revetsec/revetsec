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

import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import com.revetsec.testing.Sentinels;
import com.revetsec.testing.TestJwk;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** Exercises typed issuance through independent JCA verification and the public validator. */
final class JwsSignerBuilderTests {
	private static final TestJwk.@NonNull Fixture KEY = TestJwk.Fixture.IDP_SIGNING_RSA_2048;

	@Test
	void everyAlgorithmAndTypeProducesAnIndependentlyVerifiedJwt() throws Exception {
		byte[] digest = new byte[32];
		Arrays.fill(digest, (byte) 7);
		JwtClaimsSet claims = claims().build();
		for (JwsAlgorithm algorithm : List.of(JwsAlgorithm.PS256, JwsAlgorithm.RS256, JwsAlgorithm.RS384)) {
			JwsSigner signer = signer(algorithm);
			for (JwtType type : JwtType.values()) {
				JwtSigningHeader header = JwtSigningHeader.withType(type).keyId(JwtFixtures.KID)
						.certificateSha256Thumbprint(digest).build();
				String compact = signer.fromHeaderAndClaims(header, claims);
				assertSignature(algorithm, compact);
				String[] parts = compact.split("\\.", -1);
				JsonObject actualHeader = (JsonObject) JsonCodec.parse(decode(parts[0]), JsonLimits.jose(4096));
				assertEquals(Set.of("alg", "typ", "kid", "x5t#S256"), actualHeader.getMembers().keySet());
				assertEquals(JsonString.fromValue(algorithm.getWireValue()), actualHeader.getMembers().get("alg"));
				assertEquals(JsonString.fromValue(type.getWireValue()), actualHeader.getMembers().get("typ"));
				assertEquals(JsonString.fromValue(JwtFixtures.KID), actualHeader.getMembers().get("kid"));
				assertEquals(JsonString.fromValue(Base64.getUrlEncoder().withoutPadding().encodeToString(digest)),
						actualHeader.getMembers().get("x5t#S256"));
				assertEquals(claims.toJsonObject(), JsonCodec.parse(decode(parts[1]), JsonLimits.jose(32768)));
				JwtValidator validator = JwtFixtures.validator(JwtFixtures.source(KEY))
						.allowedAlgorithms(Set.of(algorithm)).allowedTypes(Set.of(type.getWireValue()))
						.typeRequired(true).requiredClaims(Set.of("sub")).build();
				var success = assertInstanceOf(JwtValidationResult.Succeeded.class, validator.validateResult(compact));
				assertEquals("subject-1", success.getJwt().getClaims().getSubject().orElseThrow());
				assertEquals(JwtFixtures.NOW.plusSeconds(300), success.getJwt().getClaims().getExpiresAt().orElseThrow());
			}
		}
	}

	@Test
	void defaultFactoryBuilderAndExplicitBytesShareTheSameSigningPath() {
		JwsSigner signer = signer(JwsAlgorithm.RS256);
		JwtSigningHeader header = JwtSigningHeader.fromType(JwtType.JWT);
		JwtClaimsSet claims = claims().build();
		String immediate = signer.fromHeaderAndClaims(header, claims);
		JwsSigner.Builder builder = signer.withHeaderAndClaims(header, claims);
		assertEquals(immediate, builder.build());
		assertEquals(immediate, builder.remainingBudget(Duration.ofSeconds(5)).build());
		assertEquals(immediate, builder.remainingBudget(null).build());
		assertEquals(immediate, signer.toCompactSerialization("JWT", null, null,
				claims.toJsonObject().toJson().getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(2)));
	}

	@Test
	void constructionDoesNotProbeOrSignAndBuildStillRejectsMismatchedPairs() {
		JwsSigner signer = JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(),
				TestJwk.Fixture.NEGATIVE_ATTACKER_RSA_2048.getPublicKey(), JwsAlgorithm.RS256);
		JwtSigningHeader header = JwtSigningHeader.fromType(JwtType.JWT);
		JwtClaimsSet claims = claims().build();
		JwsSigner.Builder builder = assertDoesNotThrow(() -> signer.withHeaderAndClaims(header, claims));
		assertEquals(JwsSigningException.Reason.KEY_PAIR_MISMATCH,
				assertThrows(JwsSigningException.class, builder::build).getReason());
		assertEquals(JwsSigningException.Reason.KEY_PAIR_MISMATCH,
				assertThrows(JwsSigningException.class, () -> signer.fromHeaderAndClaims(header, claims)).getReason());
	}

	@Test
	void eachBuildUsesItsOwnBudgetAndAnExhaustedBuilderCanBeReset() throws Exception {
		JwsSigner.Builder builder = signer(JwsAlgorithm.RS256).withHeaderAndClaims(
				JwtSigningHeader.fromType(JwtType.JWT), claims().build());
		for (Duration budget : List.of(Duration.ZERO, Duration.ofSeconds(-1))) {
			assertSame(builder, builder.remainingBudget(budget));
			assertEquals(JwsSigningException.Reason.BUDGET_EXHAUSTED,
					assertThrows(JwsSigningException.class, builder::build).getReason());
		}
		assertSignature(JwsAlgorithm.RS256, builder.remainingBudget(null).build());
		assertSignature(JwsAlgorithm.RS256, builder.remainingBudget(Duration.ofSeconds(Long.MAX_VALUE)).build());
		assertSignature(JwsAlgorithm.RS256, builder.build());
	}

	@Test
	void signingUsesTheImmutableInputsDespiteLaterSourceBuilderChanges() throws Exception {
		JwtSigningHeader.Builder headers = JwtSigningHeader.withType(JwtType.JWT).keyId("original");
		JwtClaimsSet.Builder claims = claims();
		JwsSigner.Builder operation = signer(JwsAlgorithm.RS256).withHeaderAndClaims(headers.build(), claims.build());
		assertSame(headers, headers.keyId("replacement"));
		claims.subject("replacement");
		String compact = operation.build();
		String[] parts = compact.split("\\.", -1);
		assertEquals(JsonString.fromValue("original"), ((JsonObject) JsonCodec.parse(decode(parts[0]),
				JsonLimits.jose(4096))).getMembers().get("kid"));
		assertEquals(JsonString.fromValue("subject-1"), ((JsonObject) JsonCodec.parse(decode(parts[1]),
				JsonLimits.jose(32768))).getMembers().get("sub"));
		assertSignature(JwsAlgorithm.RS256, compact);
	}

	@Test
	void expandedClaimsAreBoundedBeforeSerializationIncludingSharedTrees() {
		JwsSigner signer = signer(JwsAlgorithm.RS256);
		JwtSigningHeader header = JwtSigningHeader.fromType(JwtType.JWT);
		JwtClaimsSet maximum = JwtClaimsSet.builder().claim("data", "a".repeat(32768 - 11)).build();
		String compact = signer.fromHeaderAndClaims(header, maximum);
		assertEquals(32768, decode(compact.split("\\.", -1)[1]).length);
		for (String oversized : List.of("a".repeat(32768 - 10), "€".repeat(12000), "\u0000".repeat(6000))) {
			JwtClaimsSet claims = JwtClaimsSet.builder().claim("data", oversized).build();
			assertThrows(IllegalArgumentException.class, () -> signer.fromHeaderAndClaims(header, claims));
		}
		JsonValue tree = JsonString.fromValue("leaf");
		for (int depth = 0; depth < 40; ++depth) tree = JsonArray.fromElements(List.of(tree, tree));
		JwtClaimsSet expanded = JwtClaimsSet.builder().claim("data", tree).build();
		assertThrows(IllegalArgumentException.class, () -> signer.fromHeaderAndClaims(header, expanded));
	}

	@Test
	void typedClaimsRetainTheExistingStrictJoseJsonProfile() {
		JsonValue tree = JsonString.fromValue("leaf");
		for (int depth = 0; depth < 33; ++depth) tree = JsonArray.fromElements(List.of(tree));
		JwtClaimsSet claims = JwtClaimsSet.builder().claim("data", tree).build();
		assertThrows(IllegalArgumentException.class, () -> signer(JwsAlgorithm.RS256)
				.fromHeaderAndClaims(JwtSigningHeader.fromType(JwtType.JWT), claims));
	}

	@SuppressWarnings("NullAway")
	@Test
	void requiredInputsAreCheckedBeforeReturningABuilderOrCredential() {
		JwsSigner signer = signer(JwsAlgorithm.RS256);
		JwtSigningHeader header = JwtSigningHeader.fromType(JwtType.JWT);
		JwtClaimsSet claims = claims().build();
		assertThrows(NullPointerException.class, () -> signer.withHeaderAndClaims(null, claims));
		assertThrows(NullPointerException.class, () -> signer.withHeaderAndClaims(header, null));
		assertThrows(NullPointerException.class, () -> signer.fromHeaderAndClaims(null, claims));
		assertThrows(NullPointerException.class, () -> signer.fromHeaderAndClaims(header, null));
	}

	@Test
	void signingBuilderRenderingNeverExposesItsInputs() {
		String secret = Sentinels.secret("jwt-builder");
		JwtSigningHeader header = JwtSigningHeader.withType(JwtType.JWT).keyId(secret).build();
		JwtClaimsSet claims = JwtClaimsSet.builder().subject(secret).claim("private", secret).build();
		JwsSigner.Builder builder = signer(JwsAlgorithm.RS256).withHeaderAndClaims(header, claims);
		Sentinels.assertAbsent(builder);
		Sentinels.assertPresent(builder.build());
	}

	private static JwtClaimsSet.@NonNull Builder claims() {
		return JwtClaimsSet.builder().issuer(JwtFixtures.ISSUER).subject("subject-1")
				.audiences(List.of(JwtFixtures.AUDIENCE)).issuedAt(JwtFixtures.NOW)
				.expiresAt(JwtFixtures.NOW.plusSeconds(300)).claim("role", "reader");
	}

	private static @NonNull JwsSigner signer(@NonNull JwsAlgorithm algorithm) {
		return JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(), KEY.getPublicKey(), algorithm);
	}

	private static byte @NonNull [] decode(@NonNull String value) { return Base64.getUrlDecoder().decode(value); }

	private static void assertSignature(@NonNull JwsAlgorithm algorithm, @NonNull String compact) throws Exception {
		String[] parts = compact.split("\\.", -1);
		assertEquals(3, parts.length);
		String name = switch (algorithm) {
			case PS256 -> "RSASSA-PSS";
			case RS256 -> "SHA256withRSA";
			case RS384 -> "SHA384withRSA";
			default -> throw new AssertionError("Unexpected test algorithm.");
		};
		Signature verifier = Signature.getInstance(name);
		verifier.initVerify(KEY.getPublicKey());
		if (algorithm == JwsAlgorithm.PS256)
			verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
		verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
		assertTrue(verifier.verify(decode(parts[2])));
	}
}
