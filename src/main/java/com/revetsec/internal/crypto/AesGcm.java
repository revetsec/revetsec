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
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

import static java.util.Objects.requireNonNull;

/**
 * AES-256-GCM (NIST SP 800-38D) from the JDK's JCA providers, with fixed parameters: a {@value #KEY_LENGTH}-byte
 * key, a {@value #IV_LENGTH}-byte IV and a 128-bit tag appended to the ciphertext.
 * <p>
 * Every call creates its own {@link Cipher}, because JCA objects are never shared between operations or threads.
 * The caller supplies the IV and must never reuse one under the same key; the StateSealer derives a fresh key for
 * every message, so its random IVs never meet under one key.
 * <p>
 * {@link #decrypt(byte[], byte[], byte[], byte[])} rejects input shorter than the tag itself with
 * {@link AEADBadTagException} before the provider sees it. For such input, JDK 17's provider throws
 * {@link java.security.ProviderException}, an unchecked exception, while JDK 21 and later throw
 * {@code AEADBadTagException} (M1 plan, "JDK 17 note"), so the check makes the outcome the same on every JDK.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class AesGcm {
	/**
	 * The AES-256 key length, in bytes.
	 */
	public static final int KEY_LENGTH = 32;

	/**
	 * The IV length, in bytes: 96 bits, the length GCM is designed for.
	 */
	public static final int IV_LENGTH = 12;

	/**
	 * The authentication tag length, in bytes: 128 bits.
	 */
	public static final int TAG_LENGTH = 16;

	private static final String TRANSFORMATION = "AES/GCM/NoPadding";
	private static final String KEY_ALGORITHM = "AES";

	private AesGcm() {
		// Static helpers only.
	}

	/**
	 * Encrypts and authenticates {@code plaintext}, and authenticates {@code additionalData}.
	 *
	 * @param key            the {@value #KEY_LENGTH}-byte AES key; not modified
	 * @param iv             the {@value #IV_LENGTH}-byte IV, never reused under {@code key}; not modified
	 * @param additionalData the additional authenticated data, possibly empty; not modified
	 * @param plaintext      the plaintext, possibly empty; not modified
	 * @return a new array holding the ciphertext followed by the {@value #TAG_LENGTH}-byte tag
	 * @throws IllegalArgumentException if the key or IV has the wrong length
	 * @throws GeneralSecurityException if the JCA provider refuses the operation
	 */
	public static byte @NonNull [] encrypt(byte @NonNull [] key,
																				 byte @NonNull [] iv,
																				 byte @NonNull [] additionalData,
																				 byte @NonNull [] plaintext) throws GeneralSecurityException {
		requireNonNull(plaintext);

		return cipher(Cipher.ENCRYPT_MODE, key, iv, additionalData).doFinal(plaintext);
	}

	/**
	 * Verifies the tag over {@code ciphertextAndTag} and {@code additionalData}, and decrypts.
	 *
	 * @param key              the {@value #KEY_LENGTH}-byte AES key; not modified
	 * @param iv               the {@value #IV_LENGTH}-byte IV; not modified
	 * @param additionalData   the additional authenticated data, possibly empty; not modified
	 * @param ciphertextAndTag the ciphertext followed by the {@value #TAG_LENGTH}-byte tag; not modified
	 * @return a new array holding the plaintext
	 * @throws IllegalArgumentException if the key or IV has the wrong length
	 * @throws AEADBadTagException      if the input is shorter than the tag or the tag does not verify
	 * @throws GeneralSecurityException if the JCA provider refuses the operation
	 */
	public static byte @NonNull [] decrypt(byte @NonNull [] key,
																				 byte @NonNull [] iv,
																				 byte @NonNull [] additionalData,
																				 byte @NonNull [] ciphertextAndTag) throws GeneralSecurityException {
		requireNonNull(ciphertextAndTag);

		Cipher cipher = cipher(Cipher.DECRYPT_MODE, key, iv, additionalData);

		// JDK 17 throws ProviderException, not AEADBadTagException, for input shorter than the tag.
		if (ciphertextAndTag.length < TAG_LENGTH)
			throw new AEADBadTagException("The input is shorter than the authentication tag.");

		return cipher.doFinal(ciphertextAndTag);
	}

	@NonNull
	private static Cipher cipher(int mode,
															 byte @NonNull [] key,
															 byte @NonNull [] iv,
															 byte @NonNull [] additionalData) throws GeneralSecurityException {
		requireNonNull(key);
		requireNonNull(iv);
		requireNonNull(additionalData);

		if (key.length != KEY_LENGTH)
			throw new IllegalArgumentException("An AES-256 key must be " + KEY_LENGTH + " bytes.");
		if (iv.length != IV_LENGTH)
			throw new IllegalArgumentException("An AES-GCM IV must be " + IV_LENGTH + " bytes.");

		Cipher cipher = Cipher.getInstance(TRANSFORMATION);
		cipher.init(mode, new SecretKeySpec(key, KEY_ALGORITHM), new GCMParameterSpec(TAG_LENGTH * Byte.SIZE, iv));
		cipher.updateAAD(additionalData);
		return cipher;
	}
}
