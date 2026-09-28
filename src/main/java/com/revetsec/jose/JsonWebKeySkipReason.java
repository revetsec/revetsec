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

import javax.annotation.concurrent.Immutable;

/**
 * Why a key in a JSON Web Key Set is not used.
 * <p>
 * A key that fails any rule is skipped, never used for part of what it holds, and it never makes the whole set fail
 * (RFC 7517 section 5). Only the document's structure or size does that. The checks run in a fixed order, and the
 * first one that fails names the reason:
 * <ol>
 *   <li>{@code kty} is missing or not a string: {@link #MALFORMED_KEY};</li>
 *   <li>{@code kty} is not {@code RSA}, {@code EC} or {@code OKP}: {@link #SYMMETRIC_KEY} for {@code oct}, otherwise
 *   {@link #UNSUPPORTED_KEY_TYPE};</li>
 *   <li>a private or symmetric member ({@code d}, {@code p}, {@code q}, {@code dp}, {@code dq}, {@code qi},
 *   {@code oth} or {@code k}) is present: {@link #PRIVATE_KEY_MEMBERS};</li>
 *   <li>{@code use} or {@code key_ops} does not allow verification: {@link #NOT_A_VERIFICATION_KEY};</li>
 *   <li>{@code alg} is not a {@link JwsAlgorithm}, or names another key type or curve:
 *   {@link #UNSUPPORTED_ALGORITHM} or {@link #ALGORITHM_MISMATCH};</li>
 *   <li>{@code crv} names an unsupported curve: {@link #UNSUPPORTED_CURVE};</li>
 *   <li>a member is missing, of the wrong type or not canonically encoded: {@link #MALFORMED_KEY};</li>
 *   <li>the RSA modulus size is out of range: {@link #RSA_KEY_SIZE};</li>
 *   <li>the RSA public exponent is out of range: {@link #RSA_EXPONENT};</li>
 *   <li>the EC point is not on its curve: {@link #EC_POINT_NOT_ON_CURVE};</li>
 *   <li>the key is known to be weak: {@link #WEAK_KEY};</li>
 *   <li>{@code x5c} does not hold the same key: {@link #CERTIFICATE_MISMATCH}.</li>
 * </ol>
 * This enum is not switch-stable: a later release may add constants, so a {@code switch} over it needs a default
 * branch.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public enum JsonWebKeySkipReason {
	/**
	 * A member is missing, has the wrong JSON type or is not canonically encoded: {@code kty} missing or not a string;
	 * a required key member ({@code n} and {@code e}, {@code crv} with {@code x} and {@code y}, or {@code crv} with
	 * {@code x}) missing, not a string or not canonical base64url; an RSA integer with a leading zero octet or an even
	 * modulus; an EC coordinate of the wrong length; an Ed25519 {@code x} that is not 32 octets or does not decode to a
	 * curve point (RFC 8032 section 5.1.3); a {@code kid} that is not a string of 1 to 256 characters; or an
	 * {@code issuer} member that is present but not a non-empty string.
	 */
	MALFORMED_KEY,
	/**
	 * The key type ({@code kty}) is not {@code RSA}, {@code EC}, {@code OKP} or {@code oct}.
	 */
	UNSUPPORTED_KEY_TYPE,
	/**
	 * The key is symmetric ({@code kty} {@code oct}). Revetsec verifies only with public keys from a key set.
	 */
	SYMMETRIC_KEY,
	/**
	 * The key holds a private or symmetric member ({@code d}, {@code p}, {@code q}, {@code dp}, {@code dq},
	 * {@code qi}, {@code oth} or {@code k}), so the set publishes key material it should not. Its public half is not
	 * used either.
	 */
	PRIVATE_KEY_MEMBERS,
	/**
	 * The key is not for verifying signatures: its {@code use} is not {@code sig}, its {@code key_ops} is not an array
	 * of strings that contains {@code verify}, or the two members disagree (RFC 7517 sections 4.2 and 4.3).
	 */
	NOT_A_VERIFICATION_KEY,
	/**
	 * The key's {@code alg} is present but is not a {@link JwsAlgorithm} wire value, such as {@code RSA-OAEP} or
	 * {@code ES521}.
	 */
	UNSUPPORTED_ALGORITHM,
	/**
	 * The key's {@code alg} names an algorithm for another key type or curve, such as {@code ES384} on a P-256 key or
	 * any HMAC algorithm.
	 */
	ALGORITHM_MISMATCH,
	/**
	 * The key's curve ({@code crv}) is not P-256, P-384 or P-521 for an {@code EC} key, or not Ed25519 for an
	 * {@code OKP} key. A key on secp256k1, Ed448, X25519 or X448 is skipped here unless an earlier check refuses it
	 * first: {@link #UNSUPPORTED_ALGORITHM} for {@code alg} {@code ES256K} or {@code ECDH-ES}, or
	 * {@link #NOT_A_VERIFICATION_KEY} for {@code use} {@code enc}.
	 */
	UNSUPPORTED_CURVE,
	/**
	 * The RSA modulus is shorter than 2048 or longer than 16384 bits.
	 */
	RSA_KEY_SIZE,
	/**
	 * The RSA public exponent is even, below 65537 or at least 2<sup>32</sup>.
	 */
	RSA_EXPONENT,
	/**
	 * An EC coordinate is not below the field prime, or the point is not on the curve.
	 */
	EC_POINT_NOT_ON_CURVE,
	/**
	 * The key is well formed but known to be weak: an RSA modulus with the ROCA fingerprint (CVE-2017-15361), or an
	 * Ed25519 point of small order.
	 */
	WEAK_KEY,
	/**
	 * The key's {@code x5c} is not an array whose first element is a certificate in standard base64 that parses
	 * strictly, or that certificate holds a different key.
	 */
	CERTIFICATE_MISMATCH
}
