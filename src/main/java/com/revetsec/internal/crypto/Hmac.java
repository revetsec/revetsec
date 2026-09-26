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

import static java.util.Objects.requireNonNull;

/**
 * HMAC-SHA256 (RFC 2104) from the JDK's JCA providers.
 * <p>
 * Every call creates its own {@link Mac}, because JCA objects are never shared between operations or threads. The
 * JCA's {@link SecretKeySpec} rejects an empty key, so this class does too; a key of any other length is used as
 * RFC 2104 describes (a key longer than the 64-byte block is hashed first).
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
		requireNonNull(message);

		return sha256Mac(key).doFinal(message);
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
		requireNonNull(key);

		if (key.length == 0)
			throw new IllegalArgumentException("An HMAC key must not be empty.");

		Mac mac = Mac.getInstance(HMAC_SHA256);
		mac.init(new SecretKeySpec(key, HMAC_SHA256));
		return mac;
	}
}
