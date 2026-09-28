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

import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;

/**
 * HMAC (RFC 2104) with SHA-256, SHA-384 and SHA-512 from the JDK's JCA providers.
 * <p>
 * Every call creates its own {@link Mac}, because JCA objects are never shared between operations or threads. The
 * JCA's {@link SecretKeySpec} rejects an empty key, so {@link #compute}, {@link #mac} and the SHA-256 helpers do too;
 * a key of any other length is used as RFC 2104 describes (a key longer than the hash's block is hashed first).
 * <p>
 * {@link #verifyTag(HashAlgorithm, byte[], byte[], byte[])} adds the policy for signature MACs (RFC 7518 section
 * 3.2): the secret is at least as long as the hash output, checked before {@code SecretKeySpec} sees it, and the tag
 * is the full hash output, checked before the constant-time comparison (which would call two empty arrays equal).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class Hmac {
	/**
	 * The JCA name of HMAC-SHA256.
	 */
	@NonNull
	public static final String HMAC_SHA256 = "HmacSHA256";

	/**
	 * The length of an HMAC-SHA256 value, in bytes.
	 */
	public static final int SHA256_LENGTH = 32;

	private Hmac() {
		// Static helpers only.
	}

	/**
	 * Computes HMAC-SHA256 over one message.
	 *
	 * @param key     the HMAC key; not empty, and not modified
	 * @param message the message, possibly empty; not modified
	 * @return a new 32-byte array holding the MAC
	 * @throws IllegalArgumentException if {@code key} is empty
	 * @throws GeneralSecurityException if the JCA provider refuses the algorithm or the key
	 */
	public static byte @NonNull [] sha256(byte @NonNull [] key,
																				byte @NonNull [] message) throws GeneralSecurityException {
		return compute(HashAlgorithm.SHA_256, key, message);
	}

	/**
	 * Returns a new HMAC-SHA256 {@link Mac} initialized with {@code key}, for a caller that feeds it several parts.
	 *
	 * @param key the HMAC key; not empty, and not modified
	 * @return a new, initialized {@code Mac} that only the caller uses
	 * @throws IllegalArgumentException if {@code key} is empty
	 * @throws GeneralSecurityException if the JCA provider refuses the algorithm or the key
	 */
	@NonNull
	public static Mac sha256Mac(byte @NonNull [] key) throws GeneralSecurityException {
		return mac(HashAlgorithm.SHA_256, key);
	}

	/**
	 * Computes HMAC with {@code hash} over one message.
	 *
	 * @param hash    the hash function
	 * @param key     the HMAC key; not empty, and not modified
	 * @param message the message, possibly empty; not modified
	 * @return a new array holding the MAC, {@link HashAlgorithm#getLength()} bytes long
	 * @throws IllegalArgumentException if {@code key} is empty
	 * @throws GeneralSecurityException if the JCA provider refuses the algorithm or the key
	 */
	public static byte @NonNull [] compute(@NonNull HashAlgorithm hash,
																				 byte @NonNull [] key,
																				 byte @NonNull [] message) throws GeneralSecurityException {
		requireNonNull(message);

		return mac(hash, key).doFinal(message);
	}

	/**
	 * Returns a new HMAC {@link Mac} with {@code hash}, initialized with {@code key}, for a caller that feeds it several
	 * parts.
	 *
	 * @param hash the hash function
	 * @param key  the HMAC key; not empty, and not modified
	 * @return a new, initialized {@code Mac} that only the caller uses
	 * @throws IllegalArgumentException if {@code key} is empty
	 * @throws GeneralSecurityException if the JCA provider refuses the algorithm or the key
	 */
	@NonNull
	public static Mac mac(@NonNull HashAlgorithm hash,
												byte @NonNull [] key) throws GeneralSecurityException {
		requireNonNull(hash);
		requireNonNull(key);

		if (key.length == 0)
			throw new IllegalArgumentException("An HMAC key must not be empty.");

		Mac mac = Mac.getInstance(hash.getHmacName());
		mac.init(new SecretKeySpec(key, hash.getHmacName()));
		return mac;
	}

	/**
	 * Checks that an HMAC secret used for signatures is at least as long as the output of {@code hash}: 32, 48 or 64
	 * bytes (RFC 7518 section 3.2). The length counts bytes, so a text secret counts its encoded octets, not its
	 * characters.
	 *
	 * @param hash   the hash function
	 * @param secret the secret; not modified
	 * @throws KeyRejectedException {@link KeyRejectedException.Kind#SECRET_TOO_SHORT} if the secret is shorter
	 */
	public static void checkSecretLength(@NonNull HashAlgorithm hash,
																			 byte @NonNull [] secret) throws KeyRejectedException {
		requireNonNull(hash);
		requireNonNull(secret);

		if (secret.length < hash.getLength())
			throw new KeyRejectedException(KeyRejectedException.Kind.SECRET_TOO_SHORT);
	}

	/**
	 * Verifies a signature MAC: checks the secret's length ({@link #checkSecretLength}) before the JCA sees it, then the
	 * tag's length, then computes the MAC and compares it in constant time ({@link ConstantTime}). A truncated tag is
	 * never accepted.
	 *
	 * @param hash    the hash function
	 * @param secret  the secret, at least {@link HashAlgorithm#getLength()} bytes; not modified
	 * @param message the MACed bytes; not modified
	 * @param tag     the received tag; not modified
	 * @return {@link VerifyResult#VALID}; {@link VerifyResult#WRONG_LENGTH} if the tag is not exactly
	 * {@link HashAlgorithm#getLength()} bytes; {@link VerifyResult#MISMATCH} if it differs; or
	 * {@link VerifyResult#PROVIDER_FAILURE} if the JCA throws
	 * @throws KeyRejectedException {@link KeyRejectedException.Kind#SECRET_TOO_SHORT} if the secret is shorter than the
	 *                              hash output, including an empty secret
	 */
	@NonNull
	public static VerifyResult verifyTag(@NonNull HashAlgorithm hash,
																			 byte @NonNull [] secret,
																			 byte @NonNull [] message,
																			 byte @NonNull [] tag) throws KeyRejectedException {
		requireNonNull(message);
		requireNonNull(tag);
		checkSecretLength(hash, secret);

		if (tag.length != hash.getLength())
			return VerifyResult.WRONG_LENGTH;

		byte[] expected;

		try {
			expected = compute(hash, secret, message);
		} catch (GeneralSecurityException | RuntimeException exception) {
			return VerifyResult.PROVIDER_FAILURE;
		}

		try {
			return ConstantTime.isEqual(expected, tag) ? VerifyResult.VALID : VerifyResult.MISMATCH;
		} finally {
			Arrays.fill(expected, (byte) 0);
		}
	}
}
