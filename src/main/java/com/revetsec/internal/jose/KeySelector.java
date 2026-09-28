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

import com.revetsec.jose.JwsAlgorithm;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.util.List;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Picks the one key that verifies a token, or says why there is none (INV-J3, INV-J9; plan "Key selection").
 * <p>
 * <strong>Candidates</strong> are the keys that fit the token's algorithm:
 * <ul>
 *   <li>the key type and curve fit: an RSA key for {@code RS*} and {@code PS*}; an EC key on the algorithm's curve for
 *   {@code ES*}; an Ed25519 key for {@code Ed25519} and {@code EdDSA}. No key from a key set fits {@code HS*};</li>
 *   <li>a key with {@code alg} verifies only that algorithm, except that {@code EdDSA} and {@code Ed25519} verify each
 *   other on an Ed25519 key, where both name EdDSA with the Ed25519 parameter set (RFC 9864 sections 2.2 and 5, read
 *   2026-09-28; the RFC defines no alias itself, and deprecates {@code EdDSA}). The allowlist never applies that
 *   alias;</li>
 *   <li>an RSA key without {@code alg} fits only when the effective algorithm set holds exactly one RSA algorithm
 *   (RFC 8725 section 3.1, read 2026-09-28: one algorithm per key; G8-2). EC and Ed25519 keys have one algorithm by
 *   their curve.</li>
 * </ul>
 * <strong>With a {@code kid}</strong>, the keys with exactly that {@code kid} are examined: none gives
 * {@link KeySelection.Kind#UNKNOWN}; some, but no candidate among them, gives
 * {@link KeySelection.Kind#ALGORITHM_MISMATCH}; one candidate is {@link KeySelection.Kind#FOUND}; more than one is
 * {@link KeySelection.Kind#AMBIGUOUS}. <strong>Without a {@code kid}</strong>, one candidate among all keys is found,
 * none is unknown, and more than one is ambiguous (OpenID Connect Core section 10.1). So at most one key is ever
 * tried, and two keys that share a {@code kid} are never both tried.
 * <p>
 * {@code kid} values are compared exactly (RFC 7517 section 4.5). The JWK {@code issuer} member plays no part here;
 * the claims check compares it with {@code iss} after the signature verifies.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class KeySelector {
	private KeySelector() {
		// Static helpers only.
	}

	/**
	 * Selects the key for {@code query} among {@code keys}.
	 *
	 * @param keys  the usable keys, in document order
	 * @param query the token's algorithm, {@code kid} and effective algorithm set
	 * @return the selection
	 * @throws NullPointerException if an argument is {@code null}
	 */
	@NonNull
	public static KeySelection select(@NonNull List<@NonNull VerificationKey> keys,
																		@NonNull KeyQuery query) {
		requireNonNull(keys);
		requireNonNull(query);

		String keyId = query.keyId();
		boolean keyIdMatched = false;
		VerificationKey candidate = null;

		for (VerificationKey key : keys) {
			if (keyId != null) {
				if (!keyId.equals(key.keyId()))
					continue;
				keyIdMatched = true;
			}

			if (!fits(key, query))
				continue;
			if (candidate != null)
				return KeySelection.fromKind(KeySelection.Kind.AMBIGUOUS);
			candidate = key;
		}

		if (candidate != null)
			return KeySelection.fromKey(candidate);

		return KeySelection.fromKind(keyIdMatched ? KeySelection.Kind.ALGORITHM_MISMATCH : KeySelection.Kind.UNKNOWN);
	}

	/**
	 * Returns whether {@code key} may verify a token that {@code query} describes, whatever its {@code kid}.
	 *
	 * @param key   the key
	 * @param query the token's algorithm and effective algorithm set
	 * @return {@code true} if the key's type, curve and algorithm fit
	 * @throws NullPointerException if an argument is {@code null}
	 */
	public static boolean fits(@NonNull VerificationKey key,
														 @NonNull KeyQuery query) {
		requireNonNull(key);
		requireNonNull(query);
		JwsAlgorithm tokenAlgorithm = query.algorithm();

		if (Algorithms.familyOf(tokenAlgorithm) == Algorithms.Family.HMAC
				|| !Algorithms.keyTypeOf(tokenAlgorithm).equals(key.keyType()))
			return false;

		Optional<String> curve = Algorithms.findCurveName(tokenAlgorithm);
		if (curve.isPresent() && !curve.get().equals(key.curve()))
			return false;

		JwsAlgorithm keyAlgorithm = key.algorithm();
		if (keyAlgorithm != null)
			return keyAlgorithm == tokenAlgorithm || Algorithms.isAlias(keyAlgorithm, tokenAlgorithm);

		return !Algorithms.isRsa(tokenAlgorithm) || query.allowsRsaKeyWithoutAlgorithm();
	}
}
