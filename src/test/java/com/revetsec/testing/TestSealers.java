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

package com.revetsec.testing;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;

import javax.annotation.concurrent.ThreadSafe;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * {@link StateSealer}s with fixed, well-known keys, for deterministic tests (plan v3 section 4, scenario S5).
 * <p>
 * Each key is derived from its key ID alone, as the SHA-256 of {@value #KEY_DERIVATION_PREFIX} followed by the key
 * ID, so two sealers built here with the same key ID hold the same key, and a test can seal with one and open with
 * the other. That makes rotation easy to script: a sealer from {@code fromFixedKeys("new", List.of("old"))} opens
 * what one from {@code fromFixedKeys("old", List.of())} sealed. The keys are public knowledge, so these sealers
 * belong in tests only.
 * <p>
 * The sealers use the system clock and the default maximum sealed length. A test that needs another clock or
 * length builds its own sealer from {@link #fixedKey(String)}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class TestSealers {
	/**
	 * The key ID of {@link #fromFixedKey()}'s key.
	 */
	public static final String FIXED_KEY_ID = "test";

	/**
	 * What {@link #fixedKey(String)} hashes before the key ID.
	 */
	static final String KEY_DERIVATION_PREFIX = "revetsec-test-sealing-key/";

	private TestSealers() {
		// Static helpers only.
	}

	/**
	 * Returns a sealer whose only key is {@code fixedKey(FIXED_KEY_ID)}.
	 *
	 * @return a new sealer
	 */
	public static StateSealer fromFixedKey() {
		return fromFixedKeys(FIXED_KEY_ID, List.of());
	}

	/**
	 * Returns a sealer that seals with the fixed key for {@code activeKeyId} and also opens values sealed under the
	 * fixed keys for {@code verificationKeyIds}.
	 *
	 * @param activeKeyId        the active key's ID
	 * @param verificationKeyIds the verification keys' IDs, at most 16, all different from each other and from
	 *                           {@code activeKeyId}
	 * @return a new sealer
	 */
	public static StateSealer fromFixedKeys(String activeKeyId,
																					List<String> verificationKeyIds) {
		requireNonNull(activeKeyId);
		requireNonNull(verificationKeyIds);

		List<SealingKey> verificationKeys = new ArrayList<>(verificationKeyIds.size());

		for (String verificationKeyId : verificationKeyIds)
			verificationKeys.add(fixedKey(verificationKeyId));

		return StateSealer.withActiveKey(fixedKey(activeKeyId))
				.verificationKeys(verificationKeys)
				.build();
	}

	/**
	 * Returns the fixed key for {@code keyId}: a new {@link SealingKey} instance on every call, always with the same
	 * bytes for the same key ID.
	 *
	 * @param keyId a valid key ID
	 * @return a new sealing key
	 */
	public static SealingKey fixedKey(String keyId) {
		requireNonNull(keyId);
		return SealingKey.fromBase64(keyId, Base64.getEncoder().encodeToString(fixedKeyBytes(keyId)));
	}

	/**
	 * Returns the 32 bytes of the fixed key for {@code keyId}.
	 *
	 * @param keyId a key ID
	 * @return a new array holding the key's bytes
	 */
	public static byte[] fixedKeyBytes(String keyId) {
		requireNonNull(keyId);

		try {
			return MessageDigest.getInstance("SHA-256")
					.digest((KEY_DERIVATION_PREFIX + keyId).getBytes(StandardCharsets.UTF_8));
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Every JDK provides SHA-256.", e);
		}
	}
}
