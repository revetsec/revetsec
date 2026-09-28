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

import com.revetsec.internal.jose.VerifiedJwt;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * A JWT that {@link JwtValidator#validate(String)} accepted: its signature verified with a trusted key, and its type,
 * issuer, audience, lifetime and required claims passed. Only a validator creates one, so holding a {@code Jwt} means
 * the token was validated.
 * <p>
 * The token is a bearer credential. {@link #toCompactSerialization()} returns it as received, for code that must
 * forward it; {@link #toString()} shows only the algorithm. Instances compare by reference, never by content.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class Jwt {
	@NonNull
	private final JwsAlgorithm algorithm;
	@Nullable
	private final String keyId;
	@Nullable
	private final String type;
	@NonNull
	private final JwtClaims claims;
	@NonNull
	private final String compactSerialization;

	private Jwt(@NonNull JwsAlgorithm algorithm,
							@Nullable String keyId,
							@Nullable String type,
							@NonNull JwtClaims claims,
							@NonNull String compactSerialization) {
		this.algorithm = algorithm;
		this.keyId = keyId;
		this.type = type;
		this.claims = claims;
		this.compactSerialization = compactSerialization;
	}

	/**
	 * Returns the public view of a JWT that passed every check. Only the validators call this.
	 *
	 * @param verifiedJwt the verified JWT
	 * @return the public view
	 */
	@NonNull
	static Jwt fromVerifiedJwt(@NonNull VerifiedJwt verifiedJwt) {
		requireNonNull(verifiedJwt);
		return new Jwt(verifiedJwt.algorithm(), verifiedJwt.keyId(), verifiedJwt.type(),
				JwtClaims.fromRegisteredClaims(verifiedJwt.claims()), verifiedJwt.compactSerialization());
	}

	/**
	 * Returns the algorithm the token was signed with ({@code alg}).
	 *
	 * @return the algorithm
	 * @since 1.0.0
	 */
	@NonNull
	public JwsAlgorithm getAlgorithm() {
		return this.algorithm;
	}

	/**
	 * Returns the header's key ID ({@code kid}), which named the key that verified the token.
	 *
	 * @return the key ID, or empty if the header has none
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull String> getKeyId() {
		return Optional.ofNullable(this.keyId);
	}

	/**
	 * Returns the header's type ({@code typ}) exactly as received, before the comparison that folds case and implies
	 * {@code application/}.
	 *
	 * @return the type, or empty if the header has none
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull String> getType() {
		return Optional.ofNullable(this.type);
	}

	/**
	 * Returns the token's claims.
	 *
	 * @return the claims
	 * @since 1.0.0
	 */
	@NonNull
	public JwtClaims getClaims() {
		return this.claims;
	}

	/**
	 * Returns the token exactly as it was received: a bearer credential, so treat it as a secret.
	 *
	 * @return the compact serialization
	 * @since 1.0.0
	 */
	@NonNull
	public String toCompactSerialization() {
		return this.compactSerialization;
	}

	/**
	 * Describes the token by its algorithm only.
	 *
	 * @return the description, without the token or its claims
	 * @since 1.0.0
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{algorithm=" + this.algorithm.getWireValue() + "}";
	}
}
