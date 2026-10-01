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

import com.revetsec.internal.crypto.EcCurve;
import com.revetsec.internal.crypto.EcdsaSignatures;
import com.revetsec.internal.crypto.Ed25519PublicKeys;
import com.revetsec.internal.crypto.HashAlgorithm;
import com.revetsec.internal.crypto.Hmac;
import com.revetsec.internal.crypto.KeyRejectedException;
import com.revetsec.internal.crypto.RsaPublicKeys;
import com.revetsec.internal.crypto.SignatureVerifier;
import com.revetsec.internal.crypto.VerifyResult;
import com.revetsec.jose.JwsAlgorithm;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.security.PublicKey;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Maps a {@link JwsAlgorithm} onto the signature engines in {@code internal.crypto} (RFC 7518 section 3, RFC 8037
 * section 3.1; plan "JOSE semantics", steps 5 and 7).
 * <p>
 * {@link #findShapeFailure(JwsAlgorithm, byte[])} is step 5: what the signature's shape decides with no key.
 * {@code ES256}, {@code ES384} and {@code ES512} need exactly 64, 96 or 132 octets and {@code r} and {@code s} in
 * {@code [1, n - 1]} (RFC 7518 section 3.4; CVE-2022-21449); {@code Ed25519} and {@code EdDSA} need 64 octets;
 * {@code RS*} and {@code PS*} need 256 to 2,048 octets, the modulus lengths the 2,048 to 16,384-bit key policy allows;
 * {@code HS*} needs the hash length. It runs before any key is looked up, so no malformed signature can make a remote
 * key source fetch.
 * <p>
 * {@link #verify(JwsAlgorithm, PublicKey, byte[], byte[])} is step 7. The RSA engines also check that the signature is
 * exactly as long as the key's modulus. ECDSA signatures are re-encoded as DER and verified with the standard JCA
 * names, so this works with any JCA provider, including hardware-backed and approved-mode ones (G8-3). RSASSA-PSS runs
 * with the parameters RFC 7518 section 3.5 fixes for the algorithm, never ones taken from the input. The engines never
 * return {@link VerifyResult#VALID} for a {@code false} from the JCA or an exception.
 * <p>
 * {@link #verifyWithSecret(JwsAlgorithm, byte[], byte[], byte[])} verifies an {@code HS*} tag over a configured secret,
 * in constant time. No public key reaches it and no key from a key set fits an {@code HS*} algorithm, so an HMAC tag
 * made with a public key's bytes never verifies (the algorithm confusion of CVE-2015-9235).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class JwsVerifier {
	private JwsVerifier() {
		// Static helpers only.
	}

	/**
	 * Checks what {@code signature}'s shape decides for {@code algorithm} without a key (step 5).
	 *
	 * @param algorithm the token's algorithm
	 * @param signature the decoded signature; not modified
	 * @return {@link VerifyResult#WRONG_LENGTH} or {@link VerifyResult#OUT_OF_RANGE} for a signature no key can verify,
	 * or empty if the shape allows verification
	 * @throws NullPointerException if an argument is {@code null}
	 */
	@NonNull
	public static Optional<@NonNull VerifyResult> findShapeFailure(@NonNull JwsAlgorithm algorithm,
																												byte @NonNull [] signature) {
		requireNonNull(algorithm);
		requireNonNull(signature);

		return switch (Algorithms.familyOf(algorithm)) {
			case RSA_PKCS1, RSA_PSS -> RsaPublicKeys.isWithinSignatureLengthBounds(signature.length) ? Optional.empty()
					: Optional.of(VerifyResult.WRONG_LENGTH);
			case ECDSA -> EcdsaSignatures.findShapeFailure(ecCurve(algorithm), signature);
			case EDDSA -> signature.length == Ed25519PublicKeys.SIGNATURE_LENGTH ? Optional.empty()
					: Optional.of(VerifyResult.WRONG_LENGTH);
			case HMAC -> signature.length == hash(algorithm).getLength() ? Optional.empty()
					: Optional.of(VerifyResult.WRONG_LENGTH);
		};
	}

	/**
	 * Verifies a signature with a public key (step 7).
	 *
	 * @param algorithm    the token's algorithm, which the key was selected to fit
	 * @param key          the public key
	 * @param signingInput the ASCII {@code header.payload} as received; not modified
	 * @param signature    the decoded signature; not modified
	 * @return {@link VerifyResult#VALID}; {@link VerifyResult#WRONG_LENGTH} or {@link VerifyResult#OUT_OF_RANGE} for a
	 * malformed signature, including an RSA signature not exactly as long as the modulus; or
	 * {@link VerifyResult#MISMATCH} or {@link VerifyResult#PROVIDER_FAILURE} if it does not verify. An {@code HS*}
	 * algorithm is always {@link VerifyResult#MISMATCH}: a public key never verifies a MAC
	 * @throws NullPointerException if an argument is {@code null}
	 */
	@NonNull
	public static VerifyResult verify(@NonNull JwsAlgorithm algorithm,
																		@NonNull PublicKey key,
																		byte @NonNull [] signingInput,
																		byte @NonNull [] signature) {
		requireNonNull(algorithm);
		requireNonNull(key);
		requireNonNull(signingInput);
		requireNonNull(signature);

		return switch (Algorithms.familyOf(algorithm)) {
			case RSA_PKCS1 -> SignatureVerifier.verifyRsaPkcs1(hash(algorithm), key, signingInput, signature);
			case RSA_PSS -> SignatureVerifier.verifyRsaPss(hash(algorithm), key, signingInput, signature);
			case ECDSA -> SignatureVerifier.verifyEcdsa(ecCurve(algorithm), hash(algorithm), key, signingInput, signature);
			case EDDSA -> SignatureVerifier.verifyEd25519(key, signingInput, signature);
			case HMAC -> VerifyResult.MISMATCH;
		};
	}

	/**
	 * Verifies an {@code HS*} tag over a configured secret. Internal only: the public validator refuses {@code HS*}.
	 * <p>
	 * This method refuses every other algorithm itself, before it reads the secret, whatever its callers check: a
	 * secret that verified a tag under a public-key algorithm's name would be the HMAC and public-key confusion of
	 * CVE-2015-9235.
	 *
	 * @param algorithm    an HMAC algorithm
	 * @param secret       the secret, at least as long as the algorithm's hash (RFC 7518 section 3.2); not modified
	 * @param signingInput the ASCII {@code header.payload} as received; not modified
	 * @param tag          the decoded signature; not modified
	 * @return {@link VerifyResult#VALID}; {@link VerifyResult#WRONG_LENGTH} for a tag that is not exactly the hash
	 * length; {@link VerifyResult#MISMATCH}; or {@link VerifyResult#PROVIDER_FAILURE}
	 * @throws NullPointerException     if an argument is {@code null}
	 * @throws IllegalArgumentException if {@code algorithm} is not an HMAC algorithm, or the secret is shorter than its
	 *                                  hash
	 */
	@NonNull
	public static VerifyResult verifyWithSecret(@NonNull JwsAlgorithm algorithm,
																							byte @NonNull [] secret,
																							byte @NonNull [] signingInput,
																							byte @NonNull [] tag) {
		requireHmac(algorithm);
		requireNonNull(secret);
		requireNonNull(signingInput);
		requireNonNull(tag);

		try {
			return Hmac.verifyTag(hash(algorithm), secret, signingInput, tag);
		} catch (KeyRejectedException e) {
			throw new IllegalArgumentException("An HMAC secret must be at least as long as its hash output.");
		}
	}

	/**
	 * Checks that {@code algorithm} is an HMAC algorithm.
	 *
	 * @param algorithm the algorithm
	 * @throws NullPointerException     if {@code algorithm} is {@code null}
	 * @throws IllegalArgumentException if it is not an HMAC algorithm
	 */
	private static void requireHmac(@NonNull JwsAlgorithm algorithm) {
		if (Algorithms.familyOf(requireNonNull(algorithm)) != Algorithms.Family.HMAC)
			throw new IllegalArgumentException("A secret verifies only an HMAC algorithm.");
	}

	/**
	 * The hash of an algorithm that has one: every algorithm but {@code Ed25519} and {@code EdDSA}.
	 */
	@NonNull
	private static HashAlgorithm hash(@NonNull JwsAlgorithm algorithm) {
		return Algorithms.findHash(algorithm).orElseThrow();
	}

	/**
	 * The curve of an {@code ES*} algorithm.
	 */
	@NonNull
	private static EcCurve ecCurve(@NonNull JwsAlgorithm algorithm) {
		return Algorithms.findEcCurve(algorithm).orElseThrow();
	}
}
