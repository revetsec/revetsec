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

import javax.annotation.concurrent.ThreadSafe;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Verifies RSASSA-PKCS1-v1_5, RSASSA-PSS, ECDSA and Ed25519 signatures through the JDK's JCA, in hash and curve
 * terms, with every shape check the JCA does not make done first.
 * <p>
 * Each method first checks what the signature's shape decides without the key: the exact length for ECDSA and
 * Ed25519 (and, for ECDSA, the range of {@code r} and {@code s}), and for RSA the bounds that every allowed modulus
 * length lies within ({@link RsaPublicKeys#isWithinSignatureLengthBounds(int)}). Then it checks that the key fits the
 * algorithm, and for RSA that the signature is exactly as long as the key's modulus. Only then does it call the JCA.
 * So a malformed signature is {@link VerifyResult#WRONG_LENGTH} or {@link VerifyResult#OUT_OF_RANGE} whatever the
 * key, and an RSA key of 2,040 bits or fewer never verifies, even one that bypassed the key policy.
 * <p>
 * The verification is tri-state safe: the JCA's {@code false} is {@link VerifyResult#MISMATCH}, and any
 * {@code GeneralSecurityException} or {@code RuntimeException} from the key, the provider or the signature bytes is
 * {@link VerifyResult#PROVIDER_FAILURE}. Neither is ever {@link VerifyResult#VALID}, and no unchecked exception
 * leaves these methods (INV-G1). Every call creates its own {@link Signature}, because JCA objects are never shared
 * between operations or threads. Algorithm names are pinned and providers are not, so hardware-backed and
 * approved-mode providers work.
 * <p>
 * The keys are expected to come from {@link RsaPublicKeys}, {@link EcPublicKeys} or {@link Ed25519PublicKeys}, or to
 * have passed their {@code checkPublicKey}; this class does not repeat the key policy.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class SignatureVerifier {
	private static final String RSASSA_PSS = "RSASSA-PSS";

	private SignatureVerifier() {
		// Static helpers only.
	}

	/**
	 * Verifies an RSASSA-PKCS1-v1_5 signature (RFC 8017 section 8.2.2). The signature must be exactly as long as the
	 * key's modulus, and so {@value RsaPublicKeys#MINIMUM_SIGNATURE_LENGTH} to
	 * {@value RsaPublicKeys#MAXIMUM_SIGNATURE_LENGTH} bytes.
	 *
	 * @param hash      the hash function
	 * @param key       an RSA public key
	 * @param message   the signed bytes; not modified
	 * @param signature the signature; not modified
	 * @return {@link VerifyResult#VALID}; {@link VerifyResult#WRONG_LENGTH}, before any JCA call, for a signature outside
	 * those bounds (whatever the key) or not exactly as long as the key's modulus; {@link VerifyResult#MISMATCH} for a
	 * key that is not an RSA key or a signature that does not verify; or {@link VerifyResult#PROVIDER_FAILURE}
	 */
	@NonNull
	public static VerifyResult verifyRsaPkcs1(@NonNull HashAlgorithm hash,
																						@NonNull PublicKey key,
																						byte @NonNull [] message,
																						byte @NonNull [] signature) {
		requireNonNull(hash);

		return verifyRsa(hash.getRsaSignatureName(), null, key, message, signature);
	}

	/**
	 * Verifies an RSASSA-PSS signature (RFC 8017 section 8.1.2) with the fixed parameters of
	 * {@link HashAlgorithm#getPssParameterSpec()}: MGF1 with the same hash, a salt as long as the hash output, and
	 * trailer field 1. The signature must be exactly as long as the key's modulus, and so
	 * {@value RsaPublicKeys#MINIMUM_SIGNATURE_LENGTH} to {@value RsaPublicKeys#MAXIMUM_SIGNATURE_LENGTH} bytes.
	 *
	 * @param hash      the hash function, which also fixes MGF1's hash and the salt length
	 * @param key       an RSA public key
	 * @param message   the signed bytes; not modified
	 * @param signature the signature; not modified
	 * @return {@link VerifyResult#VALID}; {@link VerifyResult#WRONG_LENGTH}, before any JCA call, for a signature outside
	 * those bounds (whatever the key) or not exactly as long as the key's modulus; {@link VerifyResult#MISMATCH} for a
	 * key that is not an RSA key or a signature that does not verify, including one made with other PSS parameters; or
	 * {@link VerifyResult#PROVIDER_FAILURE}
	 */
	@NonNull
	public static VerifyResult verifyRsaPss(@NonNull HashAlgorithm hash,
																					@NonNull PublicKey key,
																					byte @NonNull [] message,
																					byte @NonNull [] signature) {
		requireNonNull(hash);

		return verifyRsa(RSASSA_PSS, hash.getPssParameterSpec(), key, message, signature);
	}

	/**
	 * Verifies a fixed-length ECDSA signature {@code r || s} in the order {@link EcdsaSignatures} describes: exact
	 * length, then the range of {@code r} and {@code s}, both without the key or the JCA; then the key's curve; then
	 * the DER form through the JCA's {@code SHAxxxwithECDSA}. The curve and the hash are separate arguments; binding
	 * them (P-256 with SHA-256 in JOSE, for example) is the protocol's job.
	 *
	 * @param curve     the curve, which fixes the signature length and the range of {@code r} and {@code s}
	 * @param hash      the hash function
	 * @param key       an EC public key on {@code curve}
	 * @param message   the signed bytes; not modified
	 * @param signature the signature {@code r || s}; not modified
	 * @return {@link VerifyResult#VALID}; {@link VerifyResult#WRONG_LENGTH} or {@link VerifyResult#OUT_OF_RANGE}
	 * before any JCA call; {@link VerifyResult#MISMATCH} for a key that is not on {@code curve} or a signature that does
	 * not verify; or {@link VerifyResult#PROVIDER_FAILURE}
	 */
	@NonNull
	public static VerifyResult verifyEcdsa(@NonNull EcCurve curve,
																				 @NonNull HashAlgorithm hash,
																				 @NonNull PublicKey key,
																				 byte @NonNull [] message,
																				 byte @NonNull [] signature) {
		requireNonNull(curve);
		requireNonNull(hash);
		requireNonNull(key);
		requireNonNull(message);
		requireNonNull(signature);

		Optional<VerifyResult> shapeFailure = EcdsaSignatures.findShapeFailure(curve, signature);

		if (shapeFailure.isPresent())
			return shapeFailure.get();

		try {
			if (!(key instanceof ECPublicKey ecKey) || !curve.isDescribedBy(ecKey.getParams()))
				return VerifyResult.MISMATCH;
		} catch (RuntimeException exception) {
			return VerifyResult.PROVIDER_FAILURE;
		}

		return verify(hash.getEcdsaSignatureName(), null, key, message, EcdsaSignatures.toDer(curve, signature));
	}

	/**
	 * Verifies an Ed25519 signature (RFC 8032 section 5.1.7) with the JCA name {@code Ed25519}. The signature must be
	 * exactly {@value Ed25519PublicKeys#SIGNATURE_LENGTH} bytes; JDK 17 alone accepts a valid signature with a trailing
	 * zero byte appended.
	 *
	 * @param key       an Ed25519 public key
	 * @param message   the signed bytes; not modified
	 * @param signature the signature; not modified
	 * @return {@link VerifyResult#VALID}; {@link VerifyResult#WRONG_LENGTH} before any JCA call;
	 * {@link VerifyResult#MISMATCH} for a key that is not an Ed25519 key or a signature that does not verify; or
	 * {@link VerifyResult#PROVIDER_FAILURE}
	 */
	@NonNull
	public static VerifyResult verifyEd25519(@NonNull PublicKey key,
																					 byte @NonNull [] message,
																					 byte @NonNull [] signature) {
		requireNonNull(key);
		requireNonNull(message);
		requireNonNull(signature);

		if (signature.length != Ed25519PublicKeys.SIGNATURE_LENGTH)
			return VerifyResult.WRONG_LENGTH;

		try {
			if (!(key instanceof EdECPublicKey edKey) || !Ed25519PublicKeys.isEd25519(edKey.getParams()))
				return VerifyResult.MISMATCH;
		} catch (RuntimeException exception) {
			return VerifyResult.PROVIDER_FAILURE;
		}

		return verify(Ed25519PublicKeys.ALGORITHM, null, key, message, signature);
	}

	@NonNull
	private static VerifyResult verifyRsa(@NonNull String algorithm,
																				@Nullable AlgorithmParameterSpec parameters,
																				@NonNull PublicKey key,
																				byte @NonNull [] message,
																				byte @NonNull [] signature) {
		requireNonNull(key);
		requireNonNull(message);
		requireNonNull(signature);

		// Key-independent first, as for the other algorithms: no allowed modulus has another length (plan M2-6).
		if (!RsaPublicKeys.isWithinSignatureLengthBounds(signature.length))
			return VerifyResult.WRONG_LENGTH;

		try {
			if (!(key instanceof RSAPublicKey rsaKey))
				return VerifyResult.MISMATCH;

			// k, the length of the modulus in bytes (RFC 8017 section 8.2.2 step 1).
			int modulusLength = (rsaKey.getModulus().bitLength() + Byte.SIZE - 1) / Byte.SIZE;

			if (signature.length != modulusLength)
				return VerifyResult.WRONG_LENGTH;
		} catch (RuntimeException exception) {
			return VerifyResult.PROVIDER_FAILURE;
		}

		return verify(algorithm, parameters, key, message, signature);
	}

	@NonNull
	private static VerifyResult verify(@NonNull String algorithm,
																		 @Nullable AlgorithmParameterSpec parameters,
																		 @NonNull PublicKey key,
																		 byte @NonNull [] message,
																		 byte @NonNull [] signature) {
		try {
			Signature verifier = Signature.getInstance(algorithm);
			// Initialize first, so that a provider is chosen for this key before the parameters are set.
			verifier.initVerify(key);

			if (parameters != null)
				verifier.setParameter(parameters);

			verifier.update(message);

			return verifier.verify(signature) ? VerifyResult.VALID : VerifyResult.MISMATCH;
		} catch (GeneralSecurityException | RuntimeException exception) {
			return VerifyResult.PROVIDER_FAILURE;
		}
	}
}
