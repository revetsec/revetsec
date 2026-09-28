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
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;

import static java.util.Objects.requireNonNull;

/**
 * A JWT that passed every step of {@link JwtProcessor}: its signature verified and its claims passed the
 * {@link JwtClaimsPolicy}. The public {@code jose.Jwt} is built from it; this internal record never is one, so no
 * public method of an internal class hands out a verified type (R17).
 *
 * @param algorithm            the header's {@code alg}
 * @param keyId                the header's {@code kid}, or {@code null} if absent
 * @param type                 the header's {@code typ} as received, or {@code null} if absent
 * @param claims               the claims, with their registered claims read
 * @param compactSerialization the token as received
 * @param key                  the key that verified it, or {@code null} for a configured HMAC secret
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public record VerifiedJwt(@NonNull JwsAlgorithm algorithm,
													@Nullable String keyId,
													@Nullable String type,
													@NonNull RegisteredClaims claims,
													@NonNull String compactSerialization,
													@Nullable VerificationKey key) {
	/**
	 * Checks the required components.
	 *
	 * @throws NullPointerException if {@code algorithm}, {@code claims} or {@code compactSerialization} is
	 *                              {@code null}
	 */
	public VerifiedJwt {
		requireNonNull(algorithm);
		requireNonNull(claims);
		requireNonNull(compactSerialization);
	}

	/**
	 * Describes the JWT by its algorithm only; the token and its claims are secrets.
	 *
	 * @return the description
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{algorithm=" + this.algorithm.getWireValue() + "}";
	}
}
