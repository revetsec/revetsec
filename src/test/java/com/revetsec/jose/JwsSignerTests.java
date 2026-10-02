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

import com.revetsec.ErrorCategory;
import com.revetsec.RevetsecException;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.JsonObject;
import com.revetsec.testing.ChildJvm;
import com.revetsec.testing.Sentinels;
import com.revetsec.testing.TestJsonWebKeys;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;
import static java.util.Objects.requireNonNull;

/** M6-A local signer contracts, with raw JCA verification independent of the production verification helper. */
final class JwsSignerTests {
	private static final @NonNull Duration BUDGET = Duration.ofSeconds(5);
	private static final @NonNull String SECRET = Sentinels.secret("signer");
	private static final TestJsonWebKeys.@NonNull Fixture KEY = TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048;
	private static final @NonNull String EXACT_CLAIMS = " \n{\"z\":1e+0,\"label\":\"é😀\",\"a\": [true,null]}\t ";

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> threeAlgorithmsEmitIndependentlyVerifiedExactByteCredentials() {
		return Stream.of(JwsAlgorithm.PS256, JwsAlgorithm.RS256, JwsAlgorithm.RS384).map(algorithm ->
				DynamicTest.dynamicTest(algorithm.name(), () -> {
					JwsSigner signer = signer(algorithm);
					byte[] claims = utf8(EXACT_CLAIMS);
					byte[] original = claims.clone();
					String compact = signer.toCompactSerialization("client-authentication+jwt", "key", null, claims, BUDGET);
					assertArrayEquals(original, claims, "Caller array is unchanged.");
					assertArrayEquals(original, payload(compact));
					assertTrue(verify(algorithm, compact, KEY.getPublicKey(), null));
					assertEquals(algorithm, signer.getAlgorithm());
					assertEquals(((RSAPublicKey) KEY.getPublicKey()).getModulus(), ((RSAPublicKey) signer.getPublicKey()).getModulus());
					assertFalse(compact.contains("="));
					assertEquals(Set.of("alg", "typ", "kid"), header(compact).getMembers().keySet());
					assertEquals(algorithm.getWireValue(), header(compact).findString("alg").orElseThrow());
				}));
	}

	@Test
	void ps256UsesExactSaltMgfAndTrailerParameters() throws Exception {
		String compact = emit(signer(JwsAlgorithm.PS256), "JWT", "{}", BUDGET);
		assertTrue(verify(JwsAlgorithm.PS256, compact, KEY.getPublicKey(), pss("SHA-256", 32)));
		assertFalse(verify(JwsAlgorithm.PS256, compact, KEY.getPublicKey(), pss("SHA-256", 20)));
		assertFalse(verify(JwsAlgorithm.PS256, compact, KEY.getPublicKey(), pss("SHA-384", 32)));
	}

	@Test
	void factoryAcceptsOnlyTheThreeSelectedAlgorithms() {
		for (JwsAlgorithm algorithm : JwsAlgorithm.values()) {
			if (Set.of(JwsAlgorithm.PS256, JwsAlgorithm.RS256, JwsAlgorithm.RS384).contains(algorithm)) continue;
			assertInvalidKey(() -> JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(), KEY.getPublicKey(), algorithm));
		}
	}

	@Test
	void structuralFactoryRejectsNonRsaPrivateAndPublicKeys() {
		assertInvalidKey(() -> JwsSigner.fromRsaKeyPair(TestJsonWebKeys.Fixture.IDP_SIGNING_EC_P256.getPrivateKey(),
				KEY.getPublicKey(), JwsAlgorithm.RS256));
		assertInvalidKey(() -> JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(),
				TestJsonWebKeys.Fixture.IDP_SIGNING_EC_P256.getPublicKey(), JwsAlgorithm.RS256));
		assertInvalidKey(() -> JwsSigner.fromRsaKeyPair(new RefusingPrivateKey("unknown"), KEY.getPublicKey(), JwsAlgorithm.PS256));
	}

	@Test
	void rsaBoundsExponentAndRocaAreCheckedStructurally() {
		RSAPublicKey valid = (RSAPublicKey) KEY.getPublicKey();
		BigInteger n = valid.getModulus();
		BigInteger e = valid.getPublicExponent();
		for (BigInteger badN : List.of(BigInteger.ZERO, n.negate(), n.clearBit(0), BigInteger.ONE.shiftLeft(2046).setBit(0),
				BigInteger.ONE.shiftLeft(16384).setBit(0)))
			assertInvalidKey(() -> JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(), new SuppliedPublicKey(badN, e, null), JwsAlgorithm.RS256));
		for (BigInteger badE : List.of(BigInteger.ZERO, BigInteger.valueOf(3), BigInteger.valueOf(65536),
				BigInteger.ONE.shiftLeft(32).add(BigInteger.ONE), e.negate()))
			assertInvalidKey(() -> JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(), new SuppliedPublicKey(n, badE, null), JwsAlgorithm.RS256));
		assertInvalidKey(() -> JwsSigner.fromRsaKeyPair(TestJsonWebKeys.rocaFingerprintedRsaKeyPair().getPrivate(),
				TestJsonWebKeys.rocaFingerprintedRsaKeyPair().getPublic(), JwsAlgorithm.RS256));
		assertInvalidKey(() -> JwsSigner.fromRsaKeyPair(TestJsonWebKeys.Fixture.NEGATIVE_RSA_1024.getPrivateKey(),
				TestJsonWebKeys.Fixture.NEGATIVE_RSA_1024.getPublicKey(), JwsAlgorithm.RS256));
		BigInteger large = BigInteger.ONE.shiftLeft(16383).add(BigInteger.valueOf(173));
		while (com.revetsec.internal.crypto.RsaPublicKeys.isRocaFingerprinted(large)) large = large.add(BigInteger.TWO);
		JwsSigner maximum = JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(), new SuppliedPublicKey(large,
				BigInteger.valueOf(4294967295L), null), JwsAlgorithm.PS256);
		assertEquals(16384, ((RSAPublicKey) maximum.getPublicKey()).getModulus().bitLength());
		assertEquals(BigInteger.valueOf(4294967295L), ((RSAPublicKey) maximum.getPublicKey()).getPublicExponent());
	}

	@Test
	void publicProjectionSnapshotsBigIntegerSubclassesAndNeverEncodesKeys() throws Exception {
		RSAPublicKey real = (RSAPublicKey) KEY.getPublicKey();
		MutableInteger n = new MutableInteger(real.getModulus());
		MutableInteger e = new MutableInteger(real.getPublicExponent());
		SuppliedPublicKey supplied = new SuppliedPublicKey(n, e, null);
		JwsSigner signer = JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(), supplied, JwsAlgorithm.RS256);
		n.bytes = BigInteger.valueOf(3).toByteArray(); e.bytes = BigInteger.valueOf(3).toByteArray();
		assertEquals(BigInteger.class, ((RSAPublicKey) signer.getPublicKey()).getModulus().getClass());
		assertEquals(BigInteger.class, ((RSAPublicKey) signer.getPublicKey()).getPublicExponent().getClass());
		assertTrue(verify(JwsAlgorithm.RS256, emit(signer, "JWT", "{}", BUDGET), real, null));
		assertNull(signer.getPublicKey().getEncoded());
		assertNull(signer.getPublicKey().getFormat());
		Sentinels.assertAbsent(List.of(signer, signer.getPublicKey()));
	}

	@Test
	void dishonestOversizedIntegerByteArraysAreRefusedBeforeCopying() {
		RSAPublicKey real = (RSAPublicKey) KEY.getPublicKey();
		MutableInteger n = new MutableInteger(real.getModulus());
		n.bytes = new byte[2050];
		assertInvalidKey(() -> JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(),
				new SuppliedPublicKey(n, real.getPublicExponent(), null), JwsAlgorithm.RS256));
		MutableInteger e = new MutableInteger(real.getPublicExponent());
		e.bytes = new byte[6];
		assertInvalidKey(() -> JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(),
				new SuppliedPublicKey(real.getModulus(), e, null), JwsAlgorithm.RS256));
	}

	@Test
	void emptyIntegerEncodingIsARejectedStructuralAccessorResult() {
		RSAPublicKey real = (RSAPublicKey) KEY.getPublicKey();
		MutableInteger modulus = new MutableInteger(real.getModulus());
		modulus.bytes = new byte[0];
		assertInvalidKey(() -> JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(),
				new SuppliedPublicKey(modulus, real.getPublicExponent(), null), JwsAlgorithm.RS256));
	}

	@Test
	void accessorFailuresHaveFixedFactoryMessagesWithoutCauses() {
		RSAPublicKey real = (RSAPublicKey) KEY.getPublicKey();
		for (int failure : List.of(1, 2, 3, 4)) {
			SuppliedPublicKey key = new SuppliedPublicKey(real.getModulus(), real.getPublicExponent(), null);
			key.failure = failure;
			assertInvalidKey(() -> JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(), key, JwsAlgorithm.RS256));
		}
	}

	@Test
	void pairMismatchIsAConfigurationFailureOnEveryOperation() {
		JwsSigner signer = JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(),
				TestJsonWebKeys.Fixture.NEGATIVE_ATTACKER_RSA_2048.getPublicKey(), JwsAlgorithm.RS256);
		for (int index = 0; index < 2; ++index) {
			assertReason(JwsSigningException.Reason.KEY_PAIR_MISMATCH,
					() -> emit(signer, "JWT", "{}", BUDGET));
			assertReason(JwsSigningException.Reason.KEY_PAIR_MISMATCH, () -> signer.warmUp(BUDGET));
		}
	}

	@Test
	void differentModulusLengthsFailAsSigningUnavailableWithoutOutput() {
		PrivateKey largerPrivate = TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_3072.getPrivateKey();
		for (JwsAlgorithm algorithm : List.of(JwsAlgorithm.PS256, JwsAlgorithm.RS256, JwsAlgorithm.RS384)) {
			JwsSigner signer = JwsSigner.fromRsaKeyPair(largerPrivate, KEY.getPublicKey(), algorithm);
			assertReason(JwsSigningException.Reason.SIGNING_UNAVAILABLE, () -> emit(signer, "JWT", "{}", BUDGET));
			assertReason(JwsSigningException.Reason.SIGNING_UNAVAILABLE, () -> signer.warmUp(BUDGET));
		}
	}

	@Test
	void structurallyRsaButUnavailablePrivateKeyFailsWithoutProviderDetails() {
		JwsSigner signer = JwsSigner.fromRsaKeyPair(new RefusingPrivateKey("RSA"), KEY.getPublicKey(), JwsAlgorithm.RS256);
		JwsSigningException failure = assertReason(JwsSigningException.Reason.SIGNING_UNAVAILABLE, () -> signer.warmUp(BUDGET));
		Sentinels.assertAbsent(List.of(signer, failure));
	}

	@Test
	void realRsaPssKeysKeepRestrictionsAndNeverBecomePkcs1Keys() throws Exception {
		RSAPrivateCrtKey real = (RSAPrivateCrtKey) KEY.getPrivateKey();
		PSSParameterSpec parameters = pss("SHA-256", 32);
		KeyFactory factory = KeyFactory.getInstance("RSASSA-PSS");
		PrivateKey privateKey = factory.generatePrivate(new RSAPrivateCrtKeySpec(real.getModulus(), real.getPublicExponent(),
				real.getPrivateExponent(), real.getPrimeP(), real.getPrimeQ(), real.getPrimeExponentP(), real.getPrimeExponentQ(),
				real.getCrtCoefficient(), parameters));
		PublicKey publicKey = factory.generatePublic(new RSAPublicKeySpec(real.getModulus(), real.getPublicExponent(), parameters));
		JwsSigner signer = JwsSigner.fromRsaKeyPair(privateKey, publicKey, JwsAlgorithm.PS256);
		assertNotNull(((RSAPublicKey) signer.getPublicKey()).getParams());
		assertTrue(verify(JwsAlgorithm.PS256, emit(signer, "at+jwt", "{}", BUDGET), publicKey, parameters));
		assertInvalidKey(() -> JwsSigner.fromRsaKeyPair(privateKey, publicKey, JwsAlgorithm.RS256));
		assertInvalidKey(() -> JwsSigner.fromRsaKeyPair(privateKey, publicKey, JwsAlgorithm.RS384));
		PSSParameterSpec incompatible = new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1);
		PrivateKey restrictedPrivate = factory.generatePrivate(new RSAPrivateCrtKeySpec(real.getModulus(), real.getPublicExponent(),
				real.getPrivateExponent(), real.getPrimeP(), real.getPrimeQ(), real.getPrimeExponentP(), real.getPrimeExponentQ(),
				real.getCrtCoefficient(), incompatible));
		JwsSigner refused = JwsSigner.fromRsaKeyPair(restrictedPrivate, KEY.getPublicKey(), JwsAlgorithm.PS256);
		assertReason(JwsSigningException.Reason.SIGNING_UNAVAILABLE, () -> refused.warmUp(BUDGET));
		for (AlgorithmParameterSpec bad : List.of(incompatible, new MGF1ParameterSpec("SHA-256"),
				new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 33, 1)))
			assertInvalidKey(() -> JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(),
					new SuppliedPublicKey(real.getModulus(), real.getPublicExponent(), bad), JwsAlgorithm.PS256));
	}

	@Test
	void publicAlgorithmAndPssRestrictionsCannotBecomePkcs1Keys() throws Exception {
		RSAPublicKey real = (RSAPublicKey) KEY.getPublicKey();
		SuppliedPublicKey unknown = new SuppliedPublicKey(real.getModulus(), real.getPublicExponent(), null);
		unknown.failure = 5;
		assertInvalidKey(() -> JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(), unknown, JwsAlgorithm.PS256));
		PublicKey pssPublic = KeyFactory.getInstance("RSASSA-PSS").generatePublic(
				new RSAPublicKeySpec(real.getModulus(), real.getPublicExponent(), pss("SHA-256", 32)));
		SuppliedPublicKey restrictedRsaPublic = new SuppliedPublicKey(real.getModulus(), real.getPublicExponent(), pss("SHA-256", 32));
		for (JwsAlgorithm algorithm : List.of(JwsAlgorithm.RS256, JwsAlgorithm.RS384)) {
			assertInvalidKey(() -> JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(), pssPublic, algorithm));
			assertInvalidKey(() -> JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(), restrictedRsaPublic, algorithm));
		}
	}

	@Test
	void everyPssRestrictionFactIsValidatedBeforeProjection() {
		RSAPublicKey real = (RSAPublicKey) KEY.getPublicKey();
		MutablePssParameters negativeSalt = new MutablePssParameters(32);
		negativeSalt.minimumSaltLength = -1;
		for (AlgorithmParameterSpec parameters : List.of(
				new PSSParameterSpec("SHA-256", "MGF1", null, 32, 1),
				new PSSParameterSpec("SHA-256", "MGF2", MGF1ParameterSpec.SHA256, 32, 1),
				new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA384, 32, 1),
				new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 2), negativeSalt))
			assertInvalidKey(() -> JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(),
					new SuppliedPublicKey(real.getModulus(), real.getPublicExponent(), parameters), JwsAlgorithm.PS256));
	}

	@Test
	void pssMinimumSaltRestrictionsHaveIndependentStableParameterSnapshots() throws Exception {
		RSAPublicKey real = (RSAPublicKey) KEY.getPublicKey();
		for (int minimumSalt : List.of(0, 20, 32)) {
			MutablePssParameters supplied = new MutablePssParameters(minimumSalt);
			JwsSigner signer = JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(),
					new SuppliedPublicKey(real.getModulus(), real.getPublicExponent(), supplied), JwsAlgorithm.PS256);
			supplied.minimumSaltLength = 33;
			PSSParameterSpec projected = (PSSParameterSpec) requireNonNull(((RSAPublicKey) signer.getPublicKey()).getParams());
			assertEquals(PSSParameterSpec.class, projected.getClass());
			assertEquals(minimumSalt, projected.getSaltLength());
			assertEquals("SHA-256", projected.getDigestAlgorithm());
			assertEquals("MGF1", projected.getMGFAlgorithm());
			assertEquals("SHA-256", ((MGF1ParameterSpec) projected.getMGFParameters()).getDigestAlgorithm());
			assertEquals(1, projected.getTrailerField());
			assertNotSame(projected, ((RSAPublicKey) signer.getPublicKey()).getParams());
			assertTrue(verify(JwsAlgorithm.PS256, emit(signer, "JWT", "{}", BUDGET), real, pss("SHA-256", 32)));
		}
	}

	@Test
	void fixedHeaderHasOnlySelectedFieldsAndExactEscaping() throws Exception {
		byte[] digest = new byte[32]; Arrays.fill(digest, (byte) 12);
		String kid = "quote\"slash\\control\u0000 é😀";
		JwsSigner signer = signer(JwsAlgorithm.RS384);
		for (String type : List.of("client-authentication+jwt", "JWT", "at+jwt")) {
			String compact = signer.toCompactSerialization(type, kid, digest, utf8("{}"), BUDGET);
			JsonObject header = header(compact);
			assertEquals(Set.of("alg", "typ", "kid", "x5t#S256"), header.getMembers().keySet());
			assertEquals(kid, header.findString("kid").orElseThrow());
			assertEquals(type, header.findString("typ").orElseThrow());
			assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(digest), header.findString("x5t#S256").orElseThrow());
			assertTrue(verify(JwsAlgorithm.RS384, compact, KEY.getPublicKey(), null));
		}
		String none = signer.toCompactSerialization("JWT", null, null, utf8("{}"), BUDGET);
		assertEquals(Set.of("alg", "typ"), header(none).getMembers().keySet());
	}

	@Test
	void everyJsonEscapeAndThreeByteUnicodePreservesTheExactKeyId() throws Exception {
		String kid = "\b\f\n\r\t\u007F\u0080\u07FF\u0800\uD7FF\uE000\uFFFF";
		String compact = signer(JwsAlgorithm.RS256).toCompactSerialization("JWT", kid, null, utf8("{}"), BUDGET);
		assertEquals(kid, header(compact).findString("kid").orElseThrow());
		assertEquals(Set.of("alg", "typ", "kid"), header(compact).getMembers().keySet());
		assertTrue(verify(JwsAlgorithm.RS256, compact, KEY.getPublicKey(), null));
	}

	@Test
	void invalidTypesKidDigestAndSurrogatesHaveFixedInputMessages() {
		JwsSigner signer = signer(JwsAlgorithm.RS256);
		for (String type : List.of("", "jwt", "application/JWT", "AT+JWT", SECRET))
			assertInvalidInput(() -> emit(signer, type, "{}", BUDGET));
		for (String kid : List.of("", "x".repeat(257), "\uD800", "\uDC00", "\uD800x"))
			assertInvalidInput(() -> signer.toCompactSerialization("JWT", kid, null, utf8("{}"), BUDGET));
		for (int length : List.of(0, 31, 33))
			assertInvalidInput(() -> signer.toCompactSerialization("JWT", null, new byte[length], utf8("{}"), BUDGET));
		String controls = "\u0000".repeat(256);
		String compact = signer.toCompactSerialization("JWT", controls, new byte[32], utf8("{}"), BUDGET);
		assertTrue(compact.length() < 65536);
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> malformedJsonAndStructuralLimitsFailBeforeSigning() {
		List<@NonNull String> refused = List.of("", "[]", "null", "true", "42", "\"object\"", "{} {}", "{\"a\":1,\"a\":2}",
				"{\"a\":1,\"\\u0061\":2}", "{\"v\":01}", "{\"v\":\"\n\"}", "{\"v\":\"\\uD800\"}",
				"{\"v\":1e10001}", "{\"v\":1e-10001}", "{\"v\":" + "1".repeat(1025) + "}",
				"{\"v\":" + "[".repeat(31) + "0" + "]".repeat(31) + "}");
		return refused.stream().map(claims -> DynamicTest.dynamicTest("rejection-" + refused.indexOf(claims), () ->
				assertInvalidInput(() -> emit(signer(JwsAlgorithm.RS256), "JWT", claims, BUDGET))));
	}

	@Test
	void bomInvalidUtf8AndOversizedClaimsAreRefusedBeforeCopies() {
		JwsSigner signer = signer(JwsAlgorithm.RS256);
		for (byte[] claims : List.of(new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF, '{', '}'},
				new byte[]{'{', '"', 'x', '"', ':', '"', (byte) 0xC0, (byte) 0xAF, '"', '}'},
				new byte[32769]))
			assertInvalidInput(() -> signer.toCompactSerialization("JWT", null, null, claims, BUDGET));
	}

	@Test
	void maximumClaimsBytesAndProtocolDefaultsAreAcceptedWithoutReserialization() throws Exception {
		String maximum = "{\"x\":\"" + "a".repeat(32760) + "\"}";
		assertEquals(32768, utf8(maximum).length);
		JwsSigner signer = signer(JwsAlgorithm.RS256);
		String compact = emit(signer, "at+jwt", maximum, BUDGET);
		assertArrayEquals(utf8(maximum), payload(compact));
		assertTrue(compact.length() < 65536);
		assertTrue(verify(JwsAlgorithm.RS256, compact, KEY.getPublicKey(), null));
		String depth32 = "{\"v\":" + "[".repeat(30) + "0" + "]".repeat(30) + "}";
		assertArrayEquals(utf8(depth32), payload(emit(signer, "JWT", depth32, BUDGET)));
		assertArrayEquals(utf8("{\"v\":1e10000}"), payload(emit(signer, "JWT", "{\"v\":1e10000}", BUDGET)));
		String number = "{\"v\":" + "1".repeat(1024) + "}";
		assertArrayEquals(utf8(number), payload(emit(signer, "JWT", number, BUDGET)));
		JsonLimits limits = JsonLimits.jose(32768);
		assertEquals(32, limits.getMaxDepth()); assertEquals(100000, limits.getMaxNodes());
		assertEquals(1048576, limits.getMaxStringLength()); assertEquals(1024, limits.getMaxNumberLength());
		assertEquals(10000, limits.getMaxExponentMagnitude());
	}

	@Test
	void claimSemanticsBelongToCallerAndNoExtraFieldsAreInvented() throws Exception {
		String claims = "{\"iss\":false,\"exp\":null,\"custom\":0}";
		assertArrayEquals(utf8(claims), payload(emit(signer(JwsAlgorithm.RS256), "JWT", claims, BUDGET)));
	}

	@Test
	void nonpositiveAndElapsedBudgetsReleaseNoCredential() {
		JwsSigner signer = signer(JwsAlgorithm.RS256);
		for (Duration budget : List.of(Duration.ZERO, Duration.ofNanos(-1), Duration.ofSeconds(-10), Duration.ofNanos(1))) {
			assertReason(JwsSigningException.Reason.BUDGET_EXHAUSTED, () -> emit(signer, "JWT", "{}", budget));
			assertReason(JwsSigningException.Reason.BUDGET_EXHAUSTED, () -> signer.warmUp(budget));
		}
	}

	@Test
	void hugeBudgetSaturatesWithoutOverflow() throws Exception {
		Duration huge = Duration.ofSeconds(Long.MAX_VALUE);
		assertTrue(verify(JwsAlgorithm.RS256, emit(signer(JwsAlgorithm.RS256), "JWT", "{}", huge), KEY.getPublicKey(), null));
	}

	@Test
	void explicitWarmUpChecksThePairWithoutChangingPublicState() {
		JwsSigner signer = signer(JwsAlgorithm.PS256);
		signer.warmUp(BUDGET); signer.warmUp(BUDGET);
		assertEquals(JwsAlgorithm.PS256, signer.getAlgorithm());
		assertEquals("JwsSigner{key=<redacted>}", signer.toString());
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> opaqueProviderMalformedRestrictionBudgetAndVmPathsRunInChildJvms() {
		return Stream.of("opaque", "malformed", "oversized-output", "wrong-modulus-length", "null-output", "throwing", "mismatch", "restricted", "late-init", "late-update",
				"late-sign", "late-verify", "throwing-verifier", "vm-error", "interrupt").map(mode ->
				DynamicTest.dynamicTest(mode, () -> {
					ChildJvm.Result result = ChildJvm.withMainClass(JwsSignerTestProvider.class).arguments(List.of(mode)).build().run();
					assertEquals(0, result.getExitCode(), () -> result.getStandardOutput() + result.getStandardError());
					assertEquals("scenario=" + mode + " passed\n", result.getStandardOutput());
					assertFalse(result.isTimedOut());
				}));
	}

	@Test
	void concurrentOperationsUseIndependentEnginesAndSnapshots() throws Exception {
		JwsSigner signer = signer(JwsAlgorithm.PS256);
		var executor = Executors.newFixedThreadPool(4);
		try {
			List<@NonNull Callable<@NonNull String>> calls = java.util.stream.IntStream.range(0, 16)
					.mapToObj(index -> (Callable<@NonNull String>) () -> emit(signer, "JWT", "{\"i\":" + index + "}", BUDGET)).toList();
			Set<String> outputs = new java.util.HashSet<>();
			for (var future : executor.invokeAll(calls)) {
				String compact = future.get();
				assertTrue(verify(JwsAlgorithm.PS256, compact, KEY.getPublicKey(), null)); outputs.add(compact);
			}
			assertEquals(16, outputs.size());
		} finally { executor.shutdownNow(); }
	}

	@Test
	void signerExceptionAndPublicProjectionRedactSentinelsWhileEmissionContainsThem() {
		JwsSigner signer = signer(JwsAlgorithm.RS256);
		String compact = signer.toCompactSerialization("JWT", SECRET, utf8(SECRET).length == 32 ? utf8(SECRET) : new byte[32],
				utf8("{\"secret\":\"" + SECRET + "\"}"), BUDGET);
		Sentinels.assertPresent(compact);
		Sentinels.assertAbsent(List.of(signer, signer.getPublicKey()));
		for (JwsSigningException.Reason reason : JwsSigningException.Reason.values()) {
			JwsSigningException failure = JwsSigningException.fromReason(reason);
			failure.addSuppressed(new IllegalStateException(SECRET));
			assertThrows(IllegalStateException.class, () -> failure.initCause(new IllegalStateException(SECRET)));
			Sentinels.assertAbsent(failure);
		}
	}

	@Test
	void eachSigningReasonHasExactRootCategoryTransienceMessageAndRestrictedConstruction() {
		assertEquals(List.of("SIGNING_UNAVAILABLE", "KEY_PAIR_MISMATCH", "BUDGET_EXHAUSTED"),
				Arrays.stream(JwsSigningException.Reason.values()).map(Enum::name).toList());
		Set<String> messages = new java.util.HashSet<>();
		for (JwsSigningException.Reason reason : JwsSigningException.Reason.values()) {
			JwsSigningException exception = JwsSigningException.fromReason(reason);
			assertSame(reason, exception.getReason());
			assertEquals(reason == JwsSigningException.Reason.BUDGET_EXHAUSTED ? ErrorCategory.TRANSPORT : ErrorCategory.CONFIGURATION,
					exception.getCategory());
			assertEquals(reason == JwsSigningException.Reason.BUDGET_EXHAUSTED, exception.isTransient());
			assertNull(exception.getCause()); assertEquals(0, exception.getSuppressed().length);
			assertTrue(requireNonNull(exception.getMessage()).endsWith(".")); assertTrue(messages.add(requireNonNull(exception.getMessage())));
			assertEquals(exception.getMessage(), JwsSigningException.fromReason(reason).getMessage());
		}
		assertEquals(RevetsecException.class, JwsSigningException.class.getSuperclass());
		for (var constructor : JwsSigningException.class.getDeclaredConstructors()) assertTrue(Modifier.isPrivate(constructor.getModifiers()));
		for (var constructor : JwsSigner.class.getDeclaredConstructors()) assertTrue(Modifier.isPrivate(constructor.getModifiers()));
	}

	@SuppressWarnings("NullAway")
	@Test
	void nullRequiredFactoryOperationAndProbeInputsAreProgrammerErrors() {
		assertThrows(NullPointerException.class, () -> JwsSigner.fromRsaKeyPair(nullValue(), KEY.getPublicKey(), JwsAlgorithm.RS256));
		assertThrows(NullPointerException.class, () -> JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(), nullValue(), JwsAlgorithm.RS256));
		assertThrows(NullPointerException.class, () -> JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(), KEY.getPublicKey(), nullValue()));
		JwsSigner signer = signer(JwsAlgorithm.RS256);
		assertThrows(NullPointerException.class, () -> signer.toCompactSerialization(nullValue(), null, null, utf8("{}"), BUDGET));
		assertThrows(NullPointerException.class, () -> signer.toCompactSerialization("JWT", null, null, nullValue(), BUDGET));
		assertThrows(NullPointerException.class, () -> signer.toCompactSerialization("JWT", null, null, utf8("{}"), nullValue()));
		assertThrows(NullPointerException.class, () -> signer.warmUp(nullValue()));
	}

	private static @NonNull JwsSigner signer(@NonNull JwsAlgorithm algorithm) {
		return JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(), KEY.getPublicKey(), algorithm);
	}
	private static @NonNull String emit(@NonNull JwsSigner signer, @NonNull String type, @NonNull String claims,
			@NonNull Duration budget) { return signer.toCompactSerialization(type, null, null, utf8(claims), budget); }
	private static byte @NonNull [] utf8(@NonNull String value) { return value.getBytes(StandardCharsets.UTF_8); }
	private static byte @NonNull [] payload(@NonNull String compact) { return Base64.getUrlDecoder().decode(compact.split("\\.", -1)[1]); }
	private static @NonNull JsonObject header(@NonNull String compact) throws Exception {
		return (JsonObject) JsonCodec.parse(Base64.getUrlDecoder().decode(compact.split("\\.", -1)[0]), JsonLimits.jose(4096));
	}
	private static @NonNull PSSParameterSpec pss(@NonNull String mgfDigest, int saltLength) {
		return new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec(mgfDigest), saltLength, 1);
	}
	private static boolean verify(@NonNull JwsAlgorithm algorithm, @NonNull String compact, @NonNull PublicKey key,
			@Nullable PSSParameterSpec parameters) throws Exception {
		String[] segments = compact.split("\\.", -1);
		Signature verifier = Signature.getInstance(algorithm == JwsAlgorithm.PS256 ? "RSASSA-PSS"
				: algorithm == JwsAlgorithm.RS256 ? "SHA256withRSA" : "SHA384withRSA");
		verifier.initVerify(key);
		if (algorithm == JwsAlgorithm.PS256) verifier.setParameter(parameters == null ? pss("SHA-256", 32) : parameters);
		verifier.update((segments[0] + "." + segments[1]).getBytes(StandardCharsets.US_ASCII));
		return verifier.verify(Base64.getUrlDecoder().decode(segments[2]));
	}
	private static void assertInvalidKey(@NonNull Executable action) {
		IllegalArgumentException failure = assertThrows(IllegalArgumentException.class, action);
		assertEquals("The RSA signing key or algorithm is invalid.", failure.getMessage()); assertNull(failure.getCause());
	}
	private static void assertInvalidInput(@NonNull Executable action) {
		IllegalArgumentException failure = assertThrows(IllegalArgumentException.class, action);
		assertEquals("The JWS signing input is invalid.", failure.getMessage()); assertNull(failure.getCause());
	}
	private static @NonNull JwsSigningException assertReason(JwsSigningException.@NonNull Reason reason,
			@NonNull Executable action) {
		JwsSigningException failure = assertThrows(JwsSigningException.class, action); assertEquals(reason, failure.getReason()); return failure;
	}
	// Deliberately violates a required-argument contract at typed test call sites to exercise NPE behavior.
	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"}) private static <T> @NonNull T nullValue() { return null; }

	private static final class RefusingPrivateKey implements PrivateKey {
		private static final long serialVersionUID = 1L;
		private final @NonNull String algorithm;
		private RefusingPrivateKey(@NonNull String algorithm) { this.algorithm = algorithm; }
		@Override public @NonNull String getAlgorithm() { return this.algorithm; }
		@Override public @Nullable String getFormat() { return null; }
		@Override public byte @Nullable [] getEncoded() { return null; }
		@Override public @NonNull String toString() { return SECRET; }
	}
	private static final class SuppliedPublicKey implements RSAPublicKey {
		private static final long serialVersionUID = 1L;
		private final @NonNull BigInteger modulus;
		private final @NonNull BigInteger exponent;
		// A test-only in-memory RSA projection; restrictions must stay present even though keys inherit Serializable.
		@SuppressWarnings("serial")
		private final @Nullable AlgorithmParameterSpec parameters;
		private int failure;
		private SuppliedPublicKey(@NonNull BigInteger modulus, @NonNull BigInteger exponent, @Nullable AlgorithmParameterSpec parameters) {
			this.modulus = modulus; this.exponent = exponent; this.parameters = parameters;
		}
		@Override public @NonNull BigInteger getModulus() {
			if (this.failure == 1) throw new IllegalStateException(SECRET);
			if (this.failure == 2) return nullValue();
			return this.modulus;
		}
		@Override public @NonNull BigInteger getPublicExponent() {
			if (this.failure == 3) throw new IllegalStateException(SECRET); return this.exponent;
		}
		@Override public @NonNull String getAlgorithm() {
			if (this.failure == 4) throw new IllegalStateException(SECRET); return this.failure == 5 ? "unknown" : "RSA";
		}
		@Override public @Nullable AlgorithmParameterSpec getParams() { return this.parameters; }
		@Override public @Nullable String getFormat() { throw new AssertionError("Factory encoded public key."); }
		@Override public byte @Nullable [] getEncoded() { throw new AssertionError("Factory encoded public key."); }
		@Override public @NonNull String toString() { return SECRET; }
	}
	private static final class MutablePssParameters extends PSSParameterSpec {
		private int minimumSaltLength;
		private MutablePssParameters(int minimumSaltLength) {
			super("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, minimumSaltLength, 1);
			this.minimumSaltLength = minimumSaltLength;
		}
		@Override public int getSaltLength() { return this.minimumSaltLength; }
	}
	private static final class MutableInteger extends BigInteger {
		private static final long serialVersionUID = 1L;
		private byte @NonNull [] bytes;
		private final int reportedBits;
		private MutableInteger(@NonNull BigInteger value) { super(value.toByteArray()); this.bytes = value.toByteArray(); this.reportedBits = value.bitLength(); }
		@Override public int bitLength() { return this.reportedBits; }
		@Override public byte @NonNull [] toByteArray() { return this.bytes.clone(); }
	}
}
