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
import javax.crypto.Mac;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;

/**
 * HKDF with HMAC-SHA256 (RFC 5869), written here because the JDK's own {@code javax.crypto.KDF} arrived only in
 * JDK 25 (M1 plan A-3).
 * <p>
 * This is the general construction, not only the one output length the StateSealer uses:
 * <ul>
 *   <li>{@link #extract(byte[], byte[])}: {@code PRK = HMAC-SHA256(salt, IKM)}. An absent or empty salt means
 *   {@value #HASH_LENGTH} zero bytes (RFC 5869 section 2.2). HMAC pads every key to its block size with zero bytes,
 *   so an empty salt and the zero salt give the same PRK anyway.</li>
 *   <li>{@link #expand(byte[], byte[], int)}: {@code T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)} for
 *   {@code i = 1..N}, and the output is the first {@code L} bytes of {@code T(1) || T(2) || ...}, with
 *   {@code 1 <= L <= 255 * 32 = 8,160} (RFC 5869 section 2.3). A larger or non-positive {@code L}, or a PRK shorter
 *   than {@value #HASH_LENGTH} bytes, is a programming error and throws {@link IllegalArgumentException}.</li>
 * </ul>
 * Intermediate blocks are zeroed before a method returns. Tests check RFC 5869 appendix A.1 to A.3 and, on JDK 25
 * and later, a differential against {@code javax.crypto.KDF}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class Hkdf {
	/**
	 * The length of an HMAC-SHA256 value, in bytes: {@code HashLen} in RFC 5869.
	 */
	public static final int HASH_LENGTH = Hmac.SHA256_LENGTH;

	/**
	 * The largest output {@link #expand(byte[], byte[], int)} can produce: 255 blocks of {@value #HASH_LENGTH}
	 * bytes.
	 */
	public static final int MAXIMUM_OUTPUT_LENGTH = 255 * HASH_LENGTH;

	private Hkdf() {
		// Static helpers only.
	}

	/**
	 * HKDF-Extract (RFC 5869 section 2.2).
	 *
	 * @param salt                the salt, or {@code null} for none (an empty salt is the same as none); not
	 *                            modified
	 * @param inputKeyingMaterial the input keying material, possibly empty; not modified
	 * @return a new 32-byte array holding the pseudorandom key
	 * @throws GeneralSecurityException if the JCA provider refuses HMAC-SHA256
	 */
	public static byte @NonNull [] extract(byte @Nullable [] salt,
																				 byte @NonNull [] inputKeyingMaterial) throws GeneralSecurityException {
		requireNonNull(inputKeyingMaterial);

		byte[] effectiveSalt = salt == null || salt.length == 0 ? new byte[HASH_LENGTH] : salt;
		return Hmac.sha256(effectiveSalt, inputKeyingMaterial);
	}

	/**
	 * HKDF-Expand (RFC 5869 section 2.3).
	 *
	 * @param pseudorandomKey the pseudorandom key, at least {@value #HASH_LENGTH} bytes; not modified
	 * @param info            the context and application-specific information, possibly empty; not modified
	 * @param length          the output length {@code L}, from 1 to {@value #MAXIMUM_OUTPUT_LENGTH}
	 * @return a new array of {@code length} bytes of output keying material
	 * @throws IllegalArgumentException if {@code length} is out of range or {@code pseudorandomKey} is too short
	 * @throws GeneralSecurityException if the JCA provider refuses HMAC-SHA256
	 */
	public static byte @NonNull [] expand(byte @NonNull [] pseudorandomKey,
																				byte @NonNull [] info,
																				int length) throws GeneralSecurityException {
		requireNonNull(pseudorandomKey);
		requireNonNull(info);
		requireOutputLength(length);

		if (pseudorandomKey.length < HASH_LENGTH)
			throw new IllegalArgumentException("An HKDF pseudorandom key must be at least " + HASH_LENGTH + " bytes.");

		Mac mac = Hmac.sha256Mac(pseudorandomKey);
		byte[] output = new byte[length];
		byte[] previous = new byte[0];

		try {
			int offset = 0;

			for (int counter = 1; offset < length; ++counter) {
				mac.update(previous);
				mac.update(info);
				// The counter runs from 1 to at most 255, one unsigned octet.
				mac.update((byte) counter);

				byte[] block = mac.doFinal();
				Arrays.fill(previous, (byte) 0);
				previous = block;

				int count = Math.min(HASH_LENGTH, length - offset);
				System.arraycopy(block, 0, output, offset, count);
				offset += count;
			}

			return output;
		} catch (RuntimeException e) {
			// A provider failure on a later block would leave earlier blocks of key material in the output.
			Arrays.fill(output, (byte) 0);
			throw e;
		} finally {
			Arrays.fill(previous, (byte) 0);
		}
	}

	/**
	 * HKDF-Extract followed by HKDF-Expand, with the pseudorandom key zeroed afterwards.
	 *
	 * @param salt                the salt, or {@code null} for none (an empty salt is the same as none); not
	 *                            modified
	 * @param inputKeyingMaterial the input keying material, possibly empty; not modified
	 * @param info                the context and application-specific information, possibly empty; not modified
	 * @param length              the output length {@code L}, from 1 to {@value #MAXIMUM_OUTPUT_LENGTH}
	 * @return a new array of {@code length} bytes of output keying material
	 * @throws IllegalArgumentException if {@code length} is out of range
	 * @throws GeneralSecurityException if the JCA provider refuses HMAC-SHA256
	 */
	public static byte @NonNull [] derive(byte @Nullable [] salt,
																				byte @NonNull [] inputKeyingMaterial,
																				byte @NonNull [] info,
																				int length) throws GeneralSecurityException {
		requireNonNull(inputKeyingMaterial);
		requireNonNull(info);
		// Check the length before any work, so a bad length never computes a key only to discard it.
		requireOutputLength(length);

		byte[] pseudorandomKey = extract(salt, inputKeyingMaterial);

		try {
			return expand(pseudorandomKey, info, length);
		} finally {
			Arrays.fill(pseudorandomKey, (byte) 0);
		}
	}

	private static void requireOutputLength(int length) {
		if (length < 1 || length > MAXIMUM_OUTPUT_LENGTH)
			throw new IllegalArgumentException("An HKDF output length must be from 1 to " + MAXIMUM_OUTPUT_LENGTH
					+ " bytes.");
	}
}
