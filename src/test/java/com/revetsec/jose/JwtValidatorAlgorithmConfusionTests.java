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

import com.revetsec.internal.jose.JoseFailure;
import com.revetsec.internal.jose.JoseHeaderPolicy;
import com.revetsec.internal.jose.JwtProcessor;
import com.revetsec.internal.jose.KeySelector;
import com.revetsec.internal.jose.PreparedJws;
import com.revetsec.testing.TestJsonWebKeys;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws;
import com.revetsec.testing.TestJws.Algorithm;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * {@link JwtValidator} against algorithm confusion (plan M2 exit criterion 4; RFC 8725 sections 2.1, 3.1 and 3.2;
 * CVE-2015-9235): {@code none} in every spelling, an HMAC keyed with the public key's bytes, the allowlist compared
 * exactly, and each key used only with the algorithm its type, curve and {@code alg} allow (INV-J3, G8-2).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JwtValidatorAlgorithmConfusionTests {
	private static final JwtValidator VALIDATOR = JwtFixtures.validator(Fixture.IDP_SIGNING_RSA_2048, JwsAlgorithm.RS256);

	// RFC 8725 section 3.2 (exit criterion 4): alg none in any case, with an empty signature or with a real one, is
	// ALGORITHM_NOT_ALLOWED, whatever else the token holds.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> everySpellingOfNoneIsNotAllowed() {
		byte[] realSignature = JwtFixtures.token(Algorithm.RS256).signed(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey())
				.getSignature();

		return Stream.of("none", "None", "NONE", "nOnE", "none ", "").flatMap(alg -> Stream.of(
				DynamicTest.dynamicTest("[" + alg + "] with an empty signature", () -> JwtFixtures.assertRejected(
						JoseException.Reason.ALGORITHM_NOT_ALLOWED, VALIDATOR, JwtFixtures.token(Algorithm.RS256).alg(alg)
								.unsigned())),
				DynamicTest.dynamicTest("[" + alg + "] with a signature", () -> JwtFixtures.assertRejected(
						JoseException.Reason.ALGORITHM_NOT_ALLOWED, VALIDATOR, JwtFixtures.token(Algorithm.RS256).alg(alg)
								.withSignature(realSignature)))));
	}

	// CVE-2015-9235 (exit criterion 4): an HS256 token MACed with the RSA public key's DER, PEM or JWK bytes, naming
	// the key's kid, is ALGORITHM_NOT_ALLOWED under {RS256}.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> anHmacKeyedWithThePublicKeyIsNotAllowed() {
		return publicKeyEncodings().entrySet().stream().flatMap(encoding -> Stream.of(Algorithm.HS256, Algorithm.HS384,
				Algorithm.HS512).map(hmac -> DynamicTest.dynamicTest(hmac + " keyed with the " + encoding.getKey(), () ->
				JwtFixtures.assertRejected(JoseException.Reason.ALGORITHM_NOT_ALLOWED, VALIDATOR, TestJws.withAlgorithm(hmac)
						.kid(JwtFixtures.KID).payload(JwtFixtures.claims().toJson()).sign(encoding.getValue())))));
	}

	// Exit criterion 4 and G8-2: no JwtValidator can allow HS*, so the confusion cannot be configured in either.
	@Test
	void noValidatorCanAllowAnHmacAlgorithm() {
		for (JwsAlgorithm hmac : List.of(JwsAlgorithm.HS256, JwsAlgorithm.HS384, JwsAlgorithm.HS512))
			Assertions.assertThrows(IllegalArgumentException.class, () -> JwtFixtures.validator(JwtFixtures.source(
					Fixture.IDP_SIGNING_RSA_2048)).allowedAlgorithms(Set.of(JwsAlgorithm.RS256, hmac)).build());
	}

	// CVE-2015-9235, with HS256 allowlisted on the internal HMAC engine: the MAC key is the configured secret, never a
	// key from the key set, so a token MACed with the public key's bytes does not verify; and on the public-key path
	// no key from a key set fits HS256 at all.
	@Test
	void theInternalHmacEngineUsesOnlyItsConfiguredSecret() throws Exception {
		byte[] clientSecret = "a client secret of at least thirty-two octets".getBytes(StandardCharsets.US_ASCII);
		JoseHeaderPolicy hmacPolicy = JoseHeaderPolicy.fromSettings(65_536, Set.of(JwsAlgorithm.HS256), Set.of("JWT"),
				false);
		StaticJsonWebKeySource source = JwtFixtures.source(Fixture.IDP_SIGNING_RSA_2048);

		for (Map.Entry<String, byte[]> encoding : publicKeyEncodings().entrySet()) {
			PreparedJws prepared = JwtProcessor.prepare(TestJws.withAlgorithm(Algorithm.HS256).kid(JwtFixtures.KID)
					.payload(JwtFixtures.claims().toJson()).sign(encoding.getValue()), hmacPolicy);

			JoseFailure failure = Assertions.assertThrows(JoseFailure.class, () -> JwtProcessor.verifyWithSecret(prepared,
					clientSecret), encoding.getKey());
			Assertions.assertEquals(JoseException.Reason.SIGNATURE_MISMATCH, failure.getReason());

			JoseFailure publicKeyPath = Assertions.assertThrows(JoseFailure.class, () -> JwtProcessor.verify(prepared,
					KeySelector.select(source.verificationKeys(), prepared.getKeyQuery())));
			Assertions.assertEquals(JoseException.Reason.KEY_ALGORITHM_MISMATCH, publicKeyPath.getReason());
		}

		PreparedJws genuine = JwtProcessor.prepare(TestJws.withAlgorithm(Algorithm.HS256).payload(JwtFixtures.claims()
				.toJson()).sign(clientSecret), hmacPolicy);
		Assertions.assertNotNull(JwtProcessor.verifyWithSecret(genuine, clientSecret));
	}

	// RFC 8725 section 3.1 (read 2026-09-28; exit criterion 4, G8-2): the caller's set of algorithms is the only one
	// used, matched exactly and case-sensitively; neither a case variant nor the EdDSA/Ed25519 alias widens it.
	@Test
	void theAllowlistIsExact() {
		JwtFixtures.assertRejected(JoseException.Reason.ALGORITHM_NOT_ALLOWED, VALIDATOR, JwtFixtures.token(
				Algorithm.RS256).alg("rs256").sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));

		JwtValidator ed25519Only = JwtFixtures.validator(Fixture.ED25519, JwsAlgorithm.ED25519);
		JwtFixtures.assertAccepted(ed25519Only, JwtFixtures.signed(Fixture.ED25519, Algorithm.ED25519));
		JwtFixtures.assertRejected(JoseException.Reason.ALGORITHM_NOT_ALLOWED, ed25519Only, JwtFixtures.signed(
				Fixture.ED25519, Algorithm.EDDSA));
		JwtValidator eddsaOnly = JwtFixtures.validator(Fixture.ED25519, JwsAlgorithm.EDDSA);
		JwtFixtures.assertAccepted(eddsaOnly, JwtFixtures.signed(Fixture.ED25519, Algorithm.EDDSA));
		JwtFixtures.assertRejected(JoseException.Reason.ALGORITHM_NOT_ALLOWED, eddsaOnly, JwtFixtures.signed(
				Fixture.ED25519, Algorithm.ED25519));
	}

	// RFC 8725 section 3.1 (read 2026-09-28; INV-J3): each key serves exactly one algorithm, so a token whose kid names a
	// key of another type, curve or alg is KEY_ALGORITHM_MISMATCH, even when that key signed it: RS256 naming an EC key,
	// ES256 naming a P-384 key, and PS256 naming a key whose alg is RS256.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> aKidNamingAKeyOfAnotherAlgorithmIsAMismatch() {
		Map<String, Case> cases = new LinkedHashMap<>();
		cases.put("RS256 naming an EC key", new Case(JwtFixtures.jwk(Fixture.IDP_SIGNING_EC_P256), Algorithm.RS256,
				Fixture.IDP_SIGNING_RSA_2048, Set.of(JwsAlgorithm.RS256, JwsAlgorithm.ES256)));
		cases.put("ES256 naming a P-384 key", new Case(JwtFixtures.jwk(Fixture.IDP_SIGNING_EC_P384), Algorithm.ES256,
				Fixture.IDP_SIGNING_EC_P256, Set.of(JwsAlgorithm.ES256, JwsAlgorithm.ES384)));
		cases.put("ES384 naming a P-256 key", new Case(JwtFixtures.jwk(Fixture.IDP_SIGNING_EC_P256), Algorithm.ES384,
				Fixture.IDP_SIGNING_EC_P384, Set.of(JwsAlgorithm.ES256, JwsAlgorithm.ES384)));
		cases.put("PS256 naming a key with alg RS256", new Case(JwtFixtures.jwk(Fixture.IDP_SIGNING_RSA_2048).alg("RS256"),
				Algorithm.PS256, Fixture.IDP_SIGNING_RSA_2048, Set.of(JwsAlgorithm.RS256, JwsAlgorithm.PS256)));
		cases.put("RS256 naming a key with alg RS384", new Case(JwtFixtures.jwk(Fixture.IDP_SIGNING_RSA_2048).alg("RS384"),
				Algorithm.RS256, Fixture.IDP_SIGNING_RSA_2048, Set.of(JwsAlgorithm.RS256)));
		cases.put("EdDSA naming an RSA key", new Case(JwtFixtures.jwk(Fixture.IDP_SIGNING_RSA_2048), Algorithm.EDDSA,
				Fixture.ED25519, Set.of(JwsAlgorithm.EDDSA)));
		cases.put("ES256 naming an Ed25519 key", new Case(JwtFixtures.jwk(Fixture.ED25519), Algorithm.ES256,
				Fixture.IDP_SIGNING_EC_P256, Set.of(JwsAlgorithm.ES256)));

		return cases.entrySet().stream().map(entry -> DynamicTest.dynamicTest(
				entry.getKey(), () -> {
					Case example = entry.getValue();
					JwtValidator validator = JwtFixtures.validator(JwtFixtures.source(example.key().toJson()))
							.allowedAlgorithms(example.allowed()).build();
					JwtFixtures.assertRejected(JoseException.Reason.KEY_ALGORITHM_MISMATCH, validator, JwtFixtures.signed(
							example.signer(), example.algorithm()));
				}));
	}

	// G8-2: a key with alg verifies only that algorithm, except that EdDSA and Ed25519 verify each other on an
	// Ed25519 key, the one operation both name there (RFC 9864 sections 2.2 and 5, read 2026-09-28; the RFC itself
	// defines no alias); the alias applies to the key's alg, never to the allowlist.
	@Test
	void theEdDsaAliasAppliesOnlyBetweenAKeysAlgAndTheToken() {
		JwtValidator ed25519 = JwtFixtures.validator(JwtFixtures.source(JwtFixtures.jwk(Fixture.ED25519).alg("EdDSA")
				.toJson())).allowedAlgorithms(Set.of(JwsAlgorithm.ED25519)).build();
		JwtFixtures.assertAccepted(ed25519, JwtFixtures.signed(Fixture.ED25519, Algorithm.ED25519));

		JwtValidator eddsa = JwtFixtures.validator(JwtFixtures.source(JwtFixtures.jwk(Fixture.ED25519).alg("Ed25519")
				.toJson())).allowedAlgorithms(Set.of(JwsAlgorithm.EDDSA)).build();
		JwtFixtures.assertAccepted(eddsa, JwtFixtures.signed(Fixture.ED25519, Algorithm.EDDSA));
	}

	// G8-2: under {RS256, PS256}, a token signed as RS256 relabelled PS256 (or the reverse) with a key that names its
	// alg is a mismatch; it never verifies under the other algorithm.
	@Test
	void anRsaTokenCannotSwitchBetweenPkcs1AndPss() {
		JwtValidator validator = JwtFixtures.validator(JwtFixtures.source(JwtFixtures.jwk(Fixture.IDP_SIGNING_RSA_2048)
				.alg("RS256").toJson())).allowedAlgorithms(Set.of(JwsAlgorithm.RS256, JwsAlgorithm.PS256)).build();
		byte[] pkcs1 = JwtFixtures.token(Algorithm.RS256).signed(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey())
				.getSignature();

		JwtFixtures.assertAccepted(validator, JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256));
		JwtFixtures.assertRejected(JoseException.Reason.KEY_ALGORITHM_MISMATCH, validator, JwtFixtures.token(
				Algorithm.PS256).withSignature(pkcs1));
		JwtFixtures.assertRejected(JoseException.Reason.KEY_ALGORITHM_MISMATCH, validator, JwtFixtures.signed(
				Fixture.IDP_SIGNING_RSA_2048, Algorithm.PS256));
	}

	/**
	 * The RSA fixture key's public bytes as an attacker would MAC with them: its SubjectPublicKeyInfo DER, its PEM and
	 * its JWK JSON.
	 */
	private static @NonNull Map<@NonNull String, byte @NonNull []> publicKeyEncodings() {
		PublicKey key = Fixture.IDP_SIGNING_RSA_2048.getPublicKey();
		Map<String, byte[]> encodings = new LinkedHashMap<>();
		encodings.put("DER", key.getEncoded());
		encodings.put("PEM", TestJsonWebKeys.publicKeyPem(key).getBytes(StandardCharsets.US_ASCII));
		encodings.put("JWK", JwtFixtures.jwk(Fixture.IDP_SIGNING_RSA_2048).toJson().getBytes(StandardCharsets.UTF_8));
		return encodings;
	}

	private record Case(TestJsonWebKeys.@NonNull Builder key, @NonNull Algorithm algorithm, @NonNull Fixture signer, @NonNull Set<@NonNull JwsAlgorithm> allowed) {
	}
}
