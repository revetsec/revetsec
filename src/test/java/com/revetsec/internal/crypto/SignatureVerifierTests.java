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

package com.revetsec.internal.crypto;

import org.jspecify.annotations.NonNull;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;

import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.stream.Stream;

/**
 * {@link SignatureVerifier}: RSASSA-PKCS1-v1_5 and RSASSA-PSS (RFC 8017; PSS with the fixed parameters of RFC 7518
 * section 3.5), ECDSA in curve and hash terms (gate 8's G8-3), and Ed25519 (RFC 8032). Shape checks run before the
 * key and the JCA; a JCA {@code false} is a mismatch, and every exception is a provider failure, never valid and
 * never thrown (INV-G1: verification is tri-state safe). The INV-G1 inventory of the unchecked exceptions observed in
 * the JDK's providers is here too, each with a control that shows the JDK still throws it.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class SignatureVerifierTests {
	private static final byte[] MESSAGE = "Revetsec signature verifier".getBytes(StandardCharsets.US_ASCII);

	// RFC 8017 section 8.2.2: the signature is exactly k octets; anything else, any change, and another hash fail.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> rsaPkcs1VerifiesOnlyTheExactSignature() {
		KeyPair keyPair = RsaPublicKeysTests.Keys.rsa2048();
		PublicKey key = keyPair.getPublic();
		BigInteger modulus = ((RSAPublicKey) key).getModulus();

		return Stream.of(HashAlgorithm.values()).map(hash -> DynamicTest.dynamicTest(hash.name(), () -> {
			byte[] signature = sign(hash.getRsaSignatureName(), null, keyPair.getPrivate());

			Assertions.assertEquals(256, signature.length);
			Assertions.assertEquals(VerifyResult.VALID, SignatureVerifier.verifyRsaPkcs1(hash, key, MESSAGE, signature));
			Assertions.assertEquals(VerifyResult.MISMATCH, SignatureVerifier.verifyRsaPkcs1(hash, key, changed(MESSAGE),
					signature));
			Assertions.assertEquals(VerifyResult.MISMATCH, SignatureVerifier.verifyRsaPkcs1(hash, key, MESSAGE,
					changed(signature)));
			Assertions.assertEquals(VerifyResult.MISMATCH, SignatureVerifier.verifyRsaPss(hash, key, MESSAGE, signature));

			for (HashAlgorithm other : HashAlgorithm.values())
				if (other != hash)
					Assertions.assertEquals(VerifyResult.MISMATCH, SignatureVerifier.verifyRsaPkcs1(other, key, MESSAGE,
							signature), other::name);

			// Exit 6's lengths (0, 1 and 2,049 octets), and one octet either side of k.
			for (int length : new int[]{0, 1, 255, 257, 2049})
				Assertions.assertEquals(VerifyResult.WRONG_LENGTH, SignatureVerifier.verifyRsaPkcs1(hash, key, MESSAGE,
						Arrays.copyOf(signature, length)), () -> "" + length);

			// Values at k octets that are no signature: zero, one, n - 1, n and all ones.
			for (BigInteger value : List.of(BigInteger.ZERO, BigInteger.ONE, modulus.subtract(BigInteger.ONE), modulus,
					BigInteger.ONE.shiftLeft(2048).subtract(BigInteger.ONE)))
				Assertions.assertNotEquals(VerifyResult.VALID, SignatureVerifier.verifyRsaPkcs1(hash, key, MESSAGE,
						EcdsaSignaturesTests.fixed(value, 256)));
		}));
	}

	// RFC 7518 section 3.5: PS* uses MGF1 with the same hash and a salt as long as the hash output. The parameters
	// come from the algorithm, never from the signature, so a signature made with any other parameters fails.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> rsaPssVerifiesOnlyWithTheFixedParameters() {
		KeyPair keyPair = RsaPublicKeysTests.Keys.rsa2048();
		PublicKey key = keyPair.getPublic();

		return Stream.of(HashAlgorithm.values()).map(hash -> DynamicTest.dynamicTest(hash.name(), () -> {
			String digest = hash.getDigestName();
			byte[] signature = sign("RSASSA-PSS", hash.getPssParameterSpec(), keyPair.getPrivate());

			Assertions.assertEquals(VerifyResult.VALID, SignatureVerifier.verifyRsaPss(hash, key, MESSAGE, signature));
			Assertions.assertEquals(VerifyResult.MISMATCH, SignatureVerifier.verifyRsaPss(hash, key, changed(MESSAGE),
					signature));
			Assertions.assertEquals(VerifyResult.MISMATCH, SignatureVerifier.verifyRsaPkcs1(hash, key, MESSAGE, signature));
			Assertions.assertEquals(VerifyResult.WRONG_LENGTH, SignatureVerifier.verifyRsaPss(hash, key, MESSAGE,
					Arrays.copyOf(signature, 255)));

			for (PSSParameterSpec other : List.of(
					new PSSParameterSpec(digest, "MGF1", new MGF1ParameterSpec(digest), 20, 1),
					new PSSParameterSpec(digest, "MGF1", new MGF1ParameterSpec(digest), 0, 1),
					new PSSParameterSpec(digest, "MGF1", MGF1ParameterSpec.SHA1, hash.getLength(), 1)))
				Assertions.assertEquals(VerifyResult.MISMATCH, SignatureVerifier.verifyRsaPss(hash, key, MESSAGE,
						sign("RSASSA-PSS", other, keyPair.getPrivate())), () -> "salt " + other.getSaltLength());

			for (HashAlgorithm other : HashAlgorithm.values())
				if (other != hash)
					Assertions.assertEquals(VerifyResult.MISMATCH, SignatureVerifier.verifyRsaPss(other, key, MESSAGE,
							signature), other::name);
		}));
	}

	// RFC 8017 section 8.2.2 step 1 and section 8.1.2 step 1: k is the modulus length in whole bytes, so a 2,049-bit
	// modulus takes 257-byte signatures (and PSS's encoded message is one byte shorter than k).
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> rsaSignaturesAreAsLongAsTheModulusRoundedUpToWholeBytes() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2049);
		KeyPair keyPair = generator.generateKeyPair();
		RSAPublicKey jdkKey = (RSAPublicKey) keyPair.getPublic();
		RSAPublicKey key = RsaPublicKeys.fromComponents(RsaPublicKeysTests.unsigned(jdkKey.getModulus()),
				RsaPublicKeysTests.unsigned(jdkKey.getPublicExponent()));

		Assertions.assertEquals(2049, key.getModulus().bitLength());

		return Stream.of(HashAlgorithm.values()).map(hash -> DynamicTest.dynamicTest(hash.name(), () -> {
			byte[] pkcs1 = sign(hash.getRsaSignatureName(), null, keyPair.getPrivate());
			byte[] pss = sign("RSASSA-PSS", hash.getPssParameterSpec(), keyPair.getPrivate());

			Assertions.assertEquals(257, pkcs1.length);
			Assertions.assertEquals(257, pss.length);
			Assertions.assertEquals(VerifyResult.VALID, SignatureVerifier.verifyRsaPkcs1(hash, key, MESSAGE, pkcs1));
			Assertions.assertEquals(VerifyResult.VALID, SignatureVerifier.verifyRsaPss(hash, key, MESSAGE, pss));

			for (int length : new int[]{256, 258}) {
				Assertions.assertEquals(VerifyResult.WRONG_LENGTH, SignatureVerifier.verifyRsaPkcs1(hash, key, MESSAGE,
						Arrays.copyOf(pkcs1, length)), () -> "" + length);
				Assertions.assertEquals(VerifyResult.WRONG_LENGTH, SignatureVerifier.verifyRsaPss(hash, key, MESSAGE,
						Arrays.copyOf(pss, length)), () -> "" + length);
			}
		}));
	}

	// Family binding (RFC 8725 section 3.1, read 2026-09-28: one algorithm per key): an EC, Ed25519 or Ed448 key never
	// verifies an RSA signature, and a length no allowed modulus has is WRONG_LENGTH whatever the key (plan M2-6).
	@Test
	void rsaVerificationRefusesKeysOfOtherFamilies() throws GeneralSecurityException {
		List<PublicKey> otherKeys = List.of(EcdsaSignaturesTests.Fixture.forCurve(EcCurve.P_256).publicKey,
				generate("Ed25519").getPublic(), generate("Ed448").getPublic());
		byte[] rsaSignature = sign("SHA256withRSA", null, RsaPublicKeysTests.Keys.rsa2048().getPrivate());

		for (PublicKey key : otherKeys) {
			for (HashAlgorithm hash : HashAlgorithm.values()) {
				Assertions.assertEquals(VerifyResult.MISMATCH, SignatureVerifier.verifyRsaPkcs1(hash, key, MESSAGE,
						rsaSignature), key::getAlgorithm);
				Assertions.assertEquals(VerifyResult.MISMATCH, SignatureVerifier.verifyRsaPss(hash, key, MESSAGE,
						rsaSignature), key::getAlgorithm);

				for (int length : new int[]{0, 1, 64, 2049}) {
					Assertions.assertEquals(VerifyResult.WRONG_LENGTH, SignatureVerifier.verifyRsaPkcs1(hash, key, MESSAGE,
							new byte[length]), key::getAlgorithm);
					Assertions.assertEquals(VerifyResult.WRONG_LENGTH, SignatureVerifier.verifyRsaPss(hash, key, MESSAGE,
							new byte[length]), key::getAlgorithm);
				}
			}
		}
	}

	// Plan section 9.3's 2,048-bit floor also bounds signatures: a 1,024-bit key that bypassed RsaPublicKeys, and that
	// the JDK alone verifies with, never verifies here, because its 128-byte signatures are below every allowed k.
	@Test
	void signaturesFromRsaKeysBelowTheSizeFloorNeverVerify() throws GeneralSecurityException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024);
		KeyPair keyPair = generator.generateKeyPair();

		for (HashAlgorithm hash : HashAlgorithm.values()) {
			byte[] pkcs1 = sign(hash.getRsaSignatureName(), null, keyPair.getPrivate());
			Signature control = Signature.getInstance(hash.getRsaSignatureName());
			control.initVerify(keyPair.getPublic());
			control.update(MESSAGE);

			Assertions.assertTrue(control.verify(pkcs1), "control: the JDK alone verifies the 1,024-bit key's signature");
			Assertions.assertEquals(VerifyResult.WRONG_LENGTH, SignatureVerifier.verifyRsaPkcs1(hash, keyPair.getPublic(),
					MESSAGE, pkcs1), hash::name);

			// RFC 8017 section 9.1.1: PSS needs 2 * hLen + 2 <= 128 encoded bytes, so SHA-512 cannot sign here.
			if (2 * hash.getLength() + 2 <= 128)
				Assertions.assertEquals(VerifyResult.WRONG_LENGTH, SignatureVerifier.verifyRsaPss(hash, keyPair.getPublic(),
						MESSAGE, sign("RSASSA-PSS", hash.getPssParameterSpec(), keyPair.getPrivate())), hash::name);
		}
	}

	// The helpers take the curve and the hash separately; binding them is the protocol's job (RFC 7518 section 3.4
	// binds P-256 to SHA-256 and so on). A key on another curve never verifies, whatever its signature.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> ecdsaVerifiesInCurveAndHashTerms() {
		return Stream.of(EcCurve.values()).map(curve -> DynamicTest.dynamicTest(curve.name(), () -> {
			EcdsaSignaturesTests.Fixture fixture = EcdsaSignaturesTests.Fixture.forCurve(curve);

			for (HashAlgorithm hash : HashAlgorithm.values()) {
				byte[] signature = signFixedLength(hash, fixture.keyPair.getPrivate());

				Assertions.assertEquals(VerifyResult.VALID, SignatureVerifier.verifyEcdsa(curve, hash, fixture.publicKey,
						MESSAGE, signature), hash::name);
				Assertions.assertEquals(VerifyResult.MISMATCH, SignatureVerifier.verifyEcdsa(curve, hash,
						fixture.publicKey, changed(MESSAGE), signature), hash::name);

				for (HashAlgorithm other : HashAlgorithm.values())
					if (other != hash)
						Assertions.assertEquals(VerifyResult.MISMATCH, SignatureVerifier.verifyEcdsa(curve, other,
								fixture.publicKey, MESSAGE, signature), other::name);
			}

			// The fixture's own signature and message, so that only the key's curve or family can make it fail.
			byte[] signature = fixture.signature;
			byte[] message = EcdsaSignaturesTests.MESSAGE;
			Assertions.assertEquals(VerifyResult.VALID, SignatureVerifier.verifyEcdsa(curve, fixture.hash,
					fixture.publicKey, message, signature), "control");
			for (EcCurve other : EcCurve.values())
				if (other != curve)
					Assertions.assertEquals(VerifyResult.MISMATCH, SignatureVerifier.verifyEcdsa(curve, fixture.hash,
							EcdsaSignaturesTests.Fixture.forCurve(other).publicKey, message, signature), other::name);

			Assertions.assertEquals(VerifyResult.MISMATCH, SignatureVerifier.verifyEcdsa(curve, fixture.hash,
					RsaPublicKeysTests.Keys.rsa2048().getPublic(), message, signature));
		}));
	}

	// The key's curve is checked, not just its family: a valid signature by a smaller curve's key, with r and s
	// zero-padded to a larger curve's length, passes that curve's shape check (r, s < n) and would verify through the
	// DER form, so only the curve check refuses it. It also keeps the range check tied to the key's own order
	// (CVE-2022-21449 on runtimes without their own check).
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> ecdsaRefusesASignatureZeroPaddedToAnotherCurvesLength() {
		return Stream.of(new EcCurve[]{EcCurve.P_256, EcCurve.P_384}, new EcCurve[]{EcCurve.P_256, EcCurve.P_521},
				new EcCurve[]{EcCurve.P_384, EcCurve.P_521}).map(pair -> DynamicTest.dynamicTest(pair[0] + " as " + pair[1],
				() -> {
					EcCurve keyCurve = pair[0];
					EcCurve claimed = pair[1];
					EcdsaSignaturesTests.Fixture fixture = EcdsaSignaturesTests.Fixture.forCurve(keyCurve);
					HashAlgorithm hash = EcdsaSignaturesTests.hashFor(claimed);
					byte[] signature = signFixedLength(hash, fixture.keyPair.getPrivate());
					int length = keyCurve.getCoordinateLength();
					byte[] padded = EcdsaSignaturesTests.raw(claimed,
							new BigInteger(1, Arrays.copyOfRange(signature, 0, length)),
							new BigInteger(1, Arrays.copyOfRange(signature, length, 2 * length)));

					Assertions.assertEquals(VerifyResult.VALID, SignatureVerifier.verifyEcdsa(keyCurve, hash,
							fixture.publicKey, MESSAGE, signature), "control: the signature is valid on its own curve");
					Assertions.assertEquals(Optional.empty(), EcdsaSignatures.findShapeFailure(claimed, padded));
					Assertions.assertArrayEquals(EcdsaSignatures.toDer(keyCurve, signature),
							EcdsaSignatures.toDer(claimed, padded), "the same DER signature");
					Assertions.assertEquals(VerifyResult.MISMATCH, SignatureVerifier.verifyEcdsa(claimed, hash,
							fixture.publicKey, MESSAGE, padded));
				}));
	}

	// Differential against the JDK's fixed-length ECDSA verifier (a test oracle): on random changes to a valid
	// signature, the result is VALID exactly when the oracle accepts. Out-of-range values are OUT_OF_RANGE, which the
	// oracle on current runtimes rejects too. The unchanged and high-S rows (120 of 300) are valid.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> ecdsaAgreesWithTheJdksFixedLengthVerifier() {
		return Stream.of(EcCurve.values()).map(curve -> DynamicTest.dynamicTest(curve.name(), () -> {
			EcdsaSignaturesTests.Fixture fixture = EcdsaSignaturesTests.Fixture.forCurve(curve);
			Random random = new Random(0x45434453L + curve.getCoordinateLength());
			int length = curve.getCoordinateLength();
			int agreedValid = 0;

			for (int index = 0; index < 300; ++index) {
				byte[] candidate = fixture.signature.clone();

				switch (index % 5) {
					case 0 -> candidate[random.nextInt(candidate.length)] ^= (byte) (1 << random.nextInt(8));
					case 1 -> {
						byte[] half = new byte[length];
						random.nextBytes(half);
						System.arraycopy(half, 0, candidate, random.nextBoolean() ? 0 : length, length);
					}
					case 2 -> candidate = EcdsaSignaturesTests.raw(curve, fixture.r, curve.getOrder().subtract(fixture.s));
					case 3 -> candidate = EcdsaSignaturesTests.raw(curve, fixture.s, fixture.r);
					default -> {
						// Unchanged: the valid signature itself.
					}
				}

				boolean oracle = verifyFixedLength(fixture.hash, fixture.publicKey, EcdsaSignaturesTests.MESSAGE, candidate);
				VerifyResult result = SignatureVerifier.verifyEcdsa(curve, fixture.hash, fixture.publicKey,
						EcdsaSignaturesTests.MESSAGE, candidate);

				Assertions.assertEquals(oracle, result == VerifyResult.VALID, result::name);
				if (oracle)
					++agreedValid;
			}

			int valid = agreedValid;
			Assertions.assertTrue(valid >= 120, () -> valid + " valid; the unchanged and high-S rows alone are 120");
		}));
	}

	// RFC 8032 section 5.1.7 and RFC 8037 section 3.1: exactly 64 octets. JDK 17 alone accepts a valid signature with
	// a trailing zero byte (Wycheproof ed25519 tcId 37); the length check rejects it on every JDK.
	@Test
	void ed25519RequiresExactlySixtyFourBytesAndAnEd25519Key() throws GeneralSecurityException {
		KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
		PublicKey key = keyPair.getPublic();
		byte[] signature = sign("Ed25519", null, keyPair.getPrivate());

		Assertions.assertEquals(VerifyResult.VALID, SignatureVerifier.verifyEd25519(key, MESSAGE, signature));
		Assertions.assertEquals(VerifyResult.MISMATCH, SignatureVerifier.verifyEd25519(key, changed(MESSAGE), signature));
		Assertions.assertEquals(VerifyResult.MISMATCH, SignatureVerifier.verifyEd25519(key, MESSAGE, changed(signature)));

		for (int length : new int[]{0, 32, 63, 65, 128})
			Assertions.assertEquals(VerifyResult.WRONG_LENGTH, SignatureVerifier.verifyEd25519(key, MESSAGE,
					Arrays.copyOf(signature, length)), () -> "" + length);

		// S >= L: the JDK refuses it one way or another, never as valid.
		byte[] largeS = signature.clone();
		largeS[63] = (byte) 0xff;
		Assertions.assertNotEquals(VerifyResult.VALID, SignatureVerifier.verifyEd25519(key, MESSAGE, largeS));

		Assertions.assertEquals(VerifyResult.MISMATCH, SignatureVerifier.verifyEd25519(
				KeyPairGenerator.getInstance("Ed448").generateKeyPair().getPublic(), MESSAGE, signature));
		Assertions.assertEquals(VerifyResult.MISMATCH, SignatureVerifier.verifyEd25519(
				RsaPublicKeysTests.Keys.rsa2048().getPublic(), MESSAGE, signature));
		Assertions.assertEquals(VerifyResult.MISMATCH, SignatureVerifier.verifyEd25519(new Ed25519PublicKeysTests
				.UnusualEdKey(NamedParameterSpec.X25519, ((EdECPublicKey) key).getPoint(), false),
				MESSAGE, signature));
	}

	// The shape checks need neither the key nor the JCA: with a key that makes the JCA throw, a malformed signature is
	// still reported as malformed, and only a well-formed one reaches the provider (exits 5 and 6's ordering). The EC
	// key has the curve's parameters, so it passes the curve check, and its point accessor throws once the JCA
	// translates it.
	@Test
	void shapeFailuresAreDecidedBeforeTheKeyAndTheJca() throws GeneralSecurityException {
		EcCurve curve = EcCurve.P_256;
		EcdsaSignaturesTests.Fixture fixture = EcdsaSignaturesTests.Fixture.forCurve(curve);
		ECPublicKey brokenEcKey = new EcPublicKeysTests.UnusualEcKey(curve.getParameterSpec(),
				curve.getParameterSpec().getGenerator(), true);
		byte[] outOfRange = EcdsaSignaturesTests.raw(curve, curve.getOrder(), fixture.s);
		byte[] message = EcdsaSignaturesTests.MESSAGE;

		Assertions.assertEquals(VerifyResult.PROVIDER_FAILURE, SignatureVerifier.verifyEcdsa(curve, fixture.hash,
				brokenEcKey, message, fixture.signature), "control: a well-formed signature reaches the provider");
		Assertions.assertEquals(VerifyResult.OUT_OF_RANGE, SignatureVerifier.verifyEcdsa(curve, fixture.hash,
				brokenEcKey, message, outOfRange));
		Assertions.assertEquals(VerifyResult.OUT_OF_RANGE, SignatureVerifier.verifyEcdsa(curve, fixture.hash,
				brokenEcKey, message, new byte[64]), "64 zero octets");
		Assertions.assertEquals(VerifyResult.WRONG_LENGTH, SignatureVerifier.verifyEcdsa(curve, fixture.hash,
				brokenEcKey, message, new byte[65]));
		Assertions.assertEquals(VerifyResult.OUT_OF_RANGE, SignatureVerifier.verifyEcdsa(curve, fixture.hash,
				RsaPublicKeysTests.Keys.rsa2048().getPublic(), message, outOfRange), "before the key's family");

		// RSA, in two steps. The 256-2,048-byte bound comes before the key: its modulus accessor throws, and only a
		// signature within the bound reaches it. The exact length k comes before the JCA: a key without an exponent
		// passes the length check (k = 256) and fails only once the JCA translates it.
		BigInteger modulus = ((RSAPublicKey) RsaPublicKeysTests.Keys.rsa2048().getPublic()).getModulus();
		RSAPublicKey throwingRsaKey = new RsaPublicKeysTests.UnusualRsaKey(modulus, BigInteger.valueOf(65_537), true);
		RSAPublicKey exponentlessRsaKey = new RsaPublicKeysTests.UnusualRsaKey(modulus, null, false);

		for (HashAlgorithm hash : HashAlgorithm.values()) {
			Assertions.assertEquals(VerifyResult.PROVIDER_FAILURE, SignatureVerifier.verifyRsaPkcs1(hash, throwingRsaKey,
					MESSAGE, new byte[256]), "control: a signature within the bound reaches the key");
			Assertions.assertEquals(VerifyResult.PROVIDER_FAILURE, SignatureVerifier.verifyRsaPkcs1(hash,
					exponentlessRsaKey, MESSAGE, new byte[256]), "control: a signature of length k reaches the JCA");
			Assertions.assertEquals(VerifyResult.PROVIDER_FAILURE, SignatureVerifier.verifyRsaPss(hash,
					exponentlessRsaKey, MESSAGE, new byte[256]), "control: a signature of length k reaches the JCA");

			for (int length : new int[]{0, 1, 255, 2049}) {
				Assertions.assertEquals(VerifyResult.WRONG_LENGTH, SignatureVerifier.verifyRsaPkcs1(hash, throwingRsaKey,
						MESSAGE, new byte[length]), () -> "" + length);
				Assertions.assertEquals(VerifyResult.WRONG_LENGTH, SignatureVerifier.verifyRsaPss(hash, throwingRsaKey,
						MESSAGE, new byte[length]), () -> "" + length);
			}

			for (int length : new int[]{257, 512, 2048}) {
				Assertions.assertEquals(VerifyResult.WRONG_LENGTH, SignatureVerifier.verifyRsaPkcs1(hash,
						exponentlessRsaKey, MESSAGE, new byte[length]), () -> "" + length);
				Assertions.assertEquals(VerifyResult.WRONG_LENGTH, SignatureVerifier.verifyRsaPss(hash,
						exponentlessRsaKey, MESSAGE, new byte[length]), () -> "" + length);
			}
		}

		PublicKey undecodable = Ed25519PublicKeysTests.rawJdkKey(Ed25519PublicKeysTests.encode(BigInteger.TWO, false));
		Assertions.assertEquals(VerifyResult.PROVIDER_FAILURE, SignatureVerifier.verifyEd25519(undecodable, MESSAGE,
				new byte[64]), "control: the JDK decodes the point only when it verifies");
		Assertions.assertEquals(VerifyResult.WRONG_LENGTH, SignatureVerifier.verifyEd25519(undecodable, MESSAGE,
				new byte[65]));
	}

	// INV-G1: a key implementation or provider that throws gives PROVIDER_FAILURE, never VALID, and no
	// exception leaves the verifier.
	@Test
	void throwingKeysAndProvidersAreProviderFailures() {
		EcCurve curve = EcCurve.P_256;
		EcdsaSignaturesTests.Fixture fixture = EcdsaSignaturesTests.Fixture.forCurve(curve);
		BigInteger modulus = ((RSAPublicKey) RsaPublicKeysTests.Keys.rsa2048().getPublic()).getModulus();
		EdECPublicKey edKey = (EdECPublicKey) generate("Ed25519")
				.getPublic();

		Assertions.assertEquals(VerifyResult.PROVIDER_FAILURE, SignatureVerifier.verifyRsaPkcs1(HashAlgorithm.SHA_256,
				new RsaPublicKeysTests.UnusualRsaKey(modulus, BigInteger.valueOf(65_537), true), MESSAGE, new byte[256]));
		Assertions.assertEquals(VerifyResult.PROVIDER_FAILURE, SignatureVerifier.verifyEcdsa(curve, fixture.hash,
				new ThrowingParametersEcKey(), MESSAGE, fixture.signature));
		Assertions.assertEquals(VerifyResult.PROVIDER_FAILURE, SignatureVerifier.verifyEd25519(
				new Ed25519PublicKeysTests.UnusualEdKey(null, edKey.getPoint(), false), MESSAGE, new byte[64]));
		Assertions.assertEquals(VerifyResult.PROVIDER_FAILURE, SignatureVerifier.verifyEd25519(
				new Ed25519PublicKeysTests.UnusualEdKey(NamedParameterSpec.ED25519, edKey.getPoint(), true), MESSAGE,
				new byte[64]));
	}

	// INV-G1 inventory: the unchecked exceptions observed in the JDK's providers on JDK 17 to 27, and the
	// checked ones that surface only at verification; for each, a control showing the JDK still throws it, and the
	// Revetsec path that never lets it out.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> theInvG1InventoryOfJcaExceptionsNeverEscapes() {
		EcCurve p256 = EcCurve.P_256;
		ECPoint g = p256.getParameterSpec().getGenerator();
		BigInteger wideX = g.getAffineX().add(p256.getFieldPrime());

		return Stream.of(
				new InventoryRow("KeyFactory(EC): a coordinate wider than the field throws RuntimeException",
						RuntimeException.class, () -> KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(
						new ECPoint(wideX, g.getAffineY()), p256.getParameterSpec())),
						() -> Assertions.assertThrows(KeyRejectedException.class, () -> EcPublicKeys.fromCoordinates(p256,
								wideX.toByteArray(), EcdsaSignaturesTests.fixed(g.getAffineY(), 32)))),
				new InventoryRow("ECPublicKeySpec: the point at infinity throws IllegalArgumentException",
						IllegalArgumentException.class, () -> new ECPublicKeySpec(ECPoint.POINT_INFINITY,
						p256.getParameterSpec()), () -> {
					ECPublicKey infinity = new EcPublicKeysTests.UnusualEcKey(p256.getParameterSpec(), ECPoint.POINT_INFINITY,
							false);
					Assertions.assertThrows(KeyRejectedException.class, () -> EcPublicKeys.checkPublicKey(p256, infinity));
					// A key that bypassed the check still never verifies and never throws; whether the JCA answers
					// false or throws for it is the provider's business.
					Assertions.assertNotEquals(VerifyResult.VALID, SignatureVerifier.verifyEcdsa(p256,
							HashAlgorithm.SHA_256, infinity, MESSAGE, EcdsaSignaturesTests.raw(p256, BigInteger.ONE,
									BigInteger.ONE)));
				}),
				new InventoryRow("SecretKeySpec: an empty key throws IllegalArgumentException", IllegalArgumentException.class,
						() -> new SecretKeySpec(new byte[0], "HmacSHA256"),
						() -> Assertions.assertThrows(KeyRejectedException.class, () -> Hmac.verifyTag(HashAlgorithm.SHA_256,
								new byte[0], MESSAGE, new byte[32]))),
				new InventoryRow("Ed25519: an undecodable point throws InvalidKeyException at verification, not at load",
						InvalidKeyException.class, () -> Signature.getInstance("Ed25519").initVerify(
						Ed25519PublicKeysTests.rawJdkKey(Ed25519PublicKeysTests.encode(BigInteger.TWO, false))),
						() -> Assertions.assertThrows(KeyRejectedException.class, () -> Ed25519PublicKeys.fromEncoded(
								Ed25519PublicKeysTests.encode(BigInteger.TWO, false)))),
				new InventoryRow("Signature(RSA): a signature of the wrong length throws SignatureException",
						SignatureException.class, () -> {
					Signature verifier = Signature.getInstance("SHA256withRSA");
					verifier.initVerify(RsaPublicKeysTests.Keys.rsa2048().getPublic());
					verifier.update(MESSAGE);
					verifier.verify(new byte[255]);
				}, () -> Assertions.assertEquals(VerifyResult.WRONG_LENGTH, SignatureVerifier.verifyRsaPkcs1(
						HashAlgorithm.SHA_256, RsaPublicKeysTests.Keys.rsa2048().getPublic(), MESSAGE, new byte[255]))))
				.map(row -> DynamicTest.dynamicTest(row.name, () -> {
					Assertions.assertThrows(row.controlException, row.control, "control: the JDK still throws");
					row.guard.execute();
				}));
	}

	// Deliberate null inputs verify runtime rejection.
	@SuppressWarnings("NullAway")
	@Test
	void rejectsNullArguments() {
		PublicKey rsa = RsaPublicKeysTests.Keys.rsa2048().getPublic();
		byte[] bytes = new byte[64];

		for (HashAlgorithm hash : HashAlgorithm.values()) {
			Assertions.assertThrows(NullPointerException.class, () -> SignatureVerifier.verifyRsaPkcs1(hash, nullValue(),
					bytes, bytes));
			Assertions.assertThrows(NullPointerException.class, () -> SignatureVerifier.verifyRsaPkcs1(hash, rsa,
					nullValue(), bytes));
			Assertions.assertThrows(NullPointerException.class, () -> SignatureVerifier.verifyRsaPss(hash, rsa, bytes,
					nullValue()));
			Assertions.assertThrows(NullPointerException.class, () -> SignatureVerifier.verifyEcdsa(EcCurve.P_256, hash,
					nullValue(), bytes, bytes));
			Assertions.assertThrows(NullPointerException.class, () -> SignatureVerifier.verifyEcdsa(EcCurve.P_256, hash,
					rsa, nullValue(), bytes));
			Assertions.assertThrows(NullPointerException.class, () -> SignatureVerifier.verifyEcdsa(EcCurve.P_256, hash,
					rsa, bytes, nullValue()));
		}

		Assertions.assertThrows(NullPointerException.class, () -> SignatureVerifier.verifyRsaPkcs1(nullValue(), rsa, bytes,
				bytes));
		Assertions.assertThrows(NullPointerException.class, () -> SignatureVerifier.verifyRsaPss(nullValue(), rsa, bytes,
				bytes));
		Assertions.assertThrows(NullPointerException.class, () -> SignatureVerifier.verifyEcdsa(nullValue(),
				HashAlgorithm.SHA_256, rsa, bytes, bytes));
		Assertions.assertThrows(NullPointerException.class, () -> SignatureVerifier.verifyEcdsa(EcCurve.P_256,
				nullValue(), rsa, bytes, bytes));
		Assertions.assertThrows(NullPointerException.class, () -> SignatureVerifier.verifyEd25519(nullValue(), bytes,
				bytes));
		Assertions.assertThrows(NullPointerException.class, () -> SignatureVerifier.verifyEd25519(rsa, nullValue(),
				bytes));
		Assertions.assertThrows(NullPointerException.class, () -> SignatureVerifier.verifyEd25519(rsa, bytes,
				nullValue()));
	}

	private static byte @NonNull [] sign(@NonNull String algorithm, @Nullable AlgorithmParameterSpec parameters, @NonNull PrivateKey privateKey)
			throws GeneralSecurityException {
		Signature signer = Signature.getInstance(algorithm);
		signer.initSign(privateKey);
		if (parameters != null)
			signer.setParameter(parameters);
		signer.update(MESSAGE);
		return signer.sign();
	}

	/**
	 * Signs {@link #MESSAGE} with the JDK's fixed-length ECDSA signer, a test oracle that main code never uses.
	 */
	private static byte @NonNull [] signFixedLength(@NonNull HashAlgorithm hash, @NonNull PrivateKey privateKey) throws GeneralSecurityException {
		return sign(hash.getEcdsaSignatureName() + "inP1363Format", null, privateKey);
	}

	private static boolean verifyFixedLength(@NonNull HashAlgorithm hash, @NonNull PublicKey key, byte @NonNull [] message, byte @NonNull [] signature) {
		try {
			Signature verifier = Signature.getInstance(hash.getEcdsaSignatureName() + "inP1363Format");
			verifier.initVerify(key);
			verifier.update(message);
			return verifier.verify(signature);
		} catch (GeneralSecurityException exception) {
			return false;
		}
	}

	private static @NonNull KeyPair generate(@NonNull String algorithm) {
		try {
			return KeyPairGenerator.getInstance(algorithm).generateKeyPair();
		} catch (GeneralSecurityException exception) {
			throw new IllegalStateException(exception);
		}
	}

	private static byte @NonNull [] changed(byte @NonNull [] value) {
		byte[] copy = value.clone();
		copy[copy.length / 2] ^= 0x01;
		return copy;
	}

	/**
	 * Hides a {@code null} from NullAway, for the tests that check null handling.
	 */
	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> @Nullable T nullValue() {
		return null;
	}

	/**
	 * One INV-G1 inventory row: the JDK behavior with its exception type, and the Revetsec path that contains it.
	 */
	private static final class InventoryRow {
		private final String name;
		private final Class<? extends Throwable> controlException;
		private final Executable control;
		private final Executable guard;

		private InventoryRow(@NonNull String name, @NonNull Class<? extends @NonNull Throwable> controlException, @NonNull Executable control,
												 @NonNull Executable guard) {
			this.name = name;
			this.controlException = controlException;
			this.control = control;
			this.guard = guard;
		}
	}

	/**
	 * An EC key whose parameters accessor throws.
	 */
	private static final class ThrowingParametersEcKey implements ECPublicKey {
		private static final long serialVersionUID = 1L;

		@Override
		public @NonNull ECPoint getW() {
			return EcCurve.P_256.getParameterSpec().getGenerator();
		}

		@Override
		public @NonNull ECParameterSpec getParams() {
			throw new IllegalStateException("A key implementation that throws.");
		}

		@Override
		public @NonNull String getAlgorithm() {
			return "EC";
		}

		@Override
		public @NonNull String getFormat() {
			return "X.509";
		}

		@Override
		public byte @NonNull [] getEncoded() {
			return new byte[0];
		}
	}
}
