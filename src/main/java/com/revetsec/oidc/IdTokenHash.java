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

package com.revetsec.oidc;

import org.jspecify.annotations.NonNull;
import com.revetsec.jose.JwsAlgorithm;

import javax.annotation.concurrent.ThreadSafe;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Core sections 3.1.3.6 and 3.3.2.11: the left half of the algorithm's hash of an ASCII credential.
 */
@ThreadSafe
final class IdTokenHash {
	private IdTokenHash() {
	}

	static @NonNull String hash(@NonNull JwsAlgorithm algorithm, @NonNull String credential) {
		for (int index = 0; index < credential.length(); ++index)
			if (credential.charAt(index) > 0x7F)
				throw new IllegalArgumentException("A hashed credential must be ASCII.");

		String digestAlgorithm = switch (algorithm) {
			case RS256, PS256, ES256, HS256 -> "SHA-256";
			case RS384, PS384, ES384, HS384 -> "SHA-384";
			case RS512, PS512, ES512, HS512, EDDSA, ED25519 -> "SHA-512";
		};
		byte[] input = credential.getBytes(StandardCharsets.US_ASCII);
		byte[] digest = null;
		byte[] half = null;
		try {
			digest = MessageDigest.getInstance(digestAlgorithm).digest(input);
			half = Arrays.copyOf(digest, digest.length / 2);
			return Base64.getUrlEncoder().withoutPadding().encodeToString(half);
		} catch (NoSuchAlgorithmException exception) {
			throw new IllegalStateException("The required ID token hash is unavailable.");
		} finally {
			Arrays.fill(input, (byte) 0);
			if (digest != null)
				Arrays.fill(digest, (byte) 0);
			if (half != null)
				Arrays.fill(half, (byte) 0);
		}
	}
}
