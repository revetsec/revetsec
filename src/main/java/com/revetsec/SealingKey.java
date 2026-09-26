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

package com.revetsec;

import com.revetsec.internal.crypto.ConstantTime;
import com.revetsec.internal.crypto.SealerV1;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.StandardBase64;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;

/**
 * A secret key for {@link StateSealer}, with its key ID.
 * <p>
 * A key is exactly 32 random bytes, given as their canonical, padded standard Base64 encoding: 44 characters with
 * one {@code =} at the end and no whitespace, such as the output of {@code openssl rand -base64 32}. A key whose 32
 * bytes are all the same, such as all zeros, is rejected as a placeholder. Generate each key from a cryptographically
 * secure random source, keep it out of source control, and use one key per application.
 * <p>
 * The key ID names the key inside every value it seals, so a sealer finds the right key without trying each one. It
 * is 1 to 64 characters of {@code A-Z}, {@code a-z}, {@code 0-9}, {@code .}, {@code _}, {@code ~} and {@code -}, such
 * as {@code 2026-09}. It is not secret: every sealed value carries it in the clear.
 * <p>
 * The key's bytes are never exposed. {@link #toString()} renders {@code SealingKey{keyId=..., key=<redacted>}}, and
 * {@code equals} is reference identity, so no key material takes part in a comparison: two keys are equal only if they
 * are the same instance.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class SealingKey {
	private static final int ENCODED_LENGTH = 44;

	@NonNull
	private final String keyId;
	/**
	 * Never modified after construction and never exposed; {@link #copyKeyBytes()} hands out copies.
	 */
	private final byte @NonNull [] key;

	private SealingKey(@NonNull String keyId,
										 byte @NonNull [] key) {
		this.keyId = keyId;
		this.key = key;
	}

	/**
	 * Returns a sealing key from its key ID and its Base64 encoding.
	 * <p>
	 * Neither argument appears in an exception message, in case the two were swapped and the "key ID" is the key.
	 *
	 * @param keyId     the key ID: 1 to 64 characters of {@code A-Z}, {@code a-z}, {@code 0-9}, {@code .},
	 *                  {@code _}, {@code ~} and {@code -}
	 * @param base64Key the key: 32 bytes as canonical, padded standard Base64 (44 characters, no whitespace)
	 * @return a new sealing key
	 * @throws NullPointerException     if either argument is {@code null}
	 * @throws IllegalArgumentException if the key ID is not valid, the key is not the canonical Base64 encoding of
	 *                                  exactly 32 bytes, or its 32 bytes are all the same
	 * @since 1.0.0
	 */
	@NonNull
	public static SealingKey fromBase64(@NonNull String keyId,
																			@NonNull String base64Key) {
		requireNonNull(keyId);
		requireNonNull(base64Key);

		if (!SealerV1.isKeyId(keyId))
			throw new IllegalArgumentException("A sealing key ID must be 1 to " + SealerV1.MAXIMUM_KEY_ID_LENGTH
					+ " characters of A-Z, a-z, 0-9, '.', '_', '~' and '-'.");

		// The length check comes first, so an oversized argument is never decoded.
		if (base64Key.length() != ENCODED_LENGTH)
			throw invalidKey();

		byte[] key;

		try {
			key = StandardBase64.decode(base64Key);
		} catch (EncodingException e) {
			throw invalidKey();
		}

		if (key.length != SealerV1.MASTER_KEY_LENGTH) {
			Arrays.fill(key, (byte) 0);
			throw invalidKey();
		}

		if (isUniform(key)) {
			Arrays.fill(key, (byte) 0);
			throw new IllegalArgumentException("A sealing key must not be 32 copies of the same byte.");
		}

		return new SealingKey(keyId, key);
	}

	/**
	 * Returns the key ID.
	 *
	 * @return the key ID
	 * @since 1.0.0
	 */
	@NonNull
	public String getKeyId() {
		return this.keyId;
	}

	/**
	 * Returns {@code SealingKey{keyId=..., key=<redacted>}}; the key's bytes are never rendered.
	 *
	 * @return a description of this key without its secret
	 * @since 1.0.0
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{keyId=" + this.keyId + ", key=<redacted>}";
	}

	/**
	 * Returns a copy of the key's bytes, for {@link StateSealer} to derive its keys from. The caller zeroes the copy.
	 */
	byte @NonNull [] copyKeyBytes() {
		return this.key.clone();
	}

	/**
	 * Returns whether {@code other} holds the same key bytes, compared in constant time.
	 */
	boolean hasSameKeyBytes(@NonNull SealingKey other) {
		return ConstantTime.isEqual(this.key, requireNonNull(other).key);
	}

	/**
	 * Whether all 32 bytes are the same, examined in full whatever they hold.
	 */
	private static boolean isUniform(byte @NonNull [] key) {
		int difference = 0;

		for (byte value : key)
			difference |= value ^ key[0];

		return difference == 0;
	}

	@NonNull
	private static IllegalArgumentException invalidKey() {
		return new IllegalArgumentException("A sealing key must be the canonical, padded standard Base64 encoding of "
				+ "exactly 32 bytes (44 characters).");
	}
}
