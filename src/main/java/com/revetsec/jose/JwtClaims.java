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

import com.revetsec.internal.jose.RegisteredClaims;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * The claims of a validated JWT (RFC 7519 section 4). Only a validator creates them, after the token's signature
 * and claims passed.
 * <p>
 * The registered claims were checked for their types before this object existed: {@code iss}, {@code sub} and
 * {@code jti} are strings, {@code aud} is a string or a non-empty array of strings, and {@code exp}, {@code nbf} and
 * {@code iat} are NumericDates. So every getter is total: it returns the claim or reports it absent, and never
 * throws. {@link #getClaim(String)} and {@link #toJsonObject()} give every other claim as JSON.
 * <p>
 * Claims can carry personal data, so {@link #toString()} shows none of them. Instances compare by reference, never
 * by content.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class JwtClaims {
	@NonNull
	private final RegisteredClaims claims;

	private JwtClaims(@NonNull RegisteredClaims claims) {
		this.claims = claims;
	}

	/**
	 * Returns the public view of claims that passed every check. Only the validators call this.
	 *
	 * @param registeredClaims the checked claims
	 * @return the public view
	 */
	@NonNull
	static JwtClaims fromRegisteredClaims(@NonNull RegisteredClaims registeredClaims) {
		return new JwtClaims(requireNonNull(registeredClaims));
	}

	/**
	 * Returns the issuer ({@code iss}).
	 *
	 * @return the issuer, or empty if absent
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull String> getIssuer() {
		return Optional.ofNullable(this.claims.issuer());
	}

	/**
	 * Returns the subject ({@code sub}).
	 *
	 * @return the subject, or empty if absent
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull String> getSubject() {
		return Optional.ofNullable(this.claims.subject());
	}

	/**
	 * Returns the audiences ({@code aud}).
	 *
	 * @return an unmodifiable list: one element for a string {@code aud}, the array's elements in order, or empty if
	 * absent
	 * @since 1.0.0
	 */
	@NonNull
	public List<@NonNull String> getAudiences() {
		return this.claims.audiences();
	}

	/**
	 * Returns the expiration time ({@code exp}).
	 *
	 * @return the instant, or empty if absent
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull Instant> getExpiresAt() {
		return Optional.ofNullable(this.claims.expiresAt());
	}

	/**
	 * Returns the issue time ({@code iat}).
	 *
	 * @return the instant, or empty if absent
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull Instant> getIssuedAt() {
		return Optional.ofNullable(this.claims.issuedAt());
	}

	/**
	 * Returns the time before which the token is not valid ({@code nbf}).
	 *
	 * @return the instant, or empty if absent
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull Instant> getNotBefore() {
		return Optional.ofNullable(this.claims.notBefore());
	}

	/**
	 * Returns the JWT ID ({@code jti}).
	 *
	 * @return the JWT ID, or empty if absent
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull String> getJwtId() {
		return Optional.ofNullable(this.claims.jwtId());
	}

	/**
	 * Returns a claim's JSON value, registered or not.
	 *
	 * @param name the claim name, compared exactly
	 * @return the value, which may be JSON {@code null}, or empty if there is no such claim
	 * @throws NullPointerException if {@code name} is {@code null}
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull JsonValue> getClaim(@NonNull String name) {
		return this.claims.claims().find(requireNonNull(name));
	}

	/**
	 * Returns the names of every claim.
	 *
	 * @return an unmodifiable set, in the order the claims appear in the token
	 * @since 1.0.0
	 */
	@NonNull
	public Set<@NonNull String> getClaimNames() {
		return this.claims.claims().getMembers().keySet();
	}

	/**
	 * Returns every claim as a JSON object: the claims set as received, which can carry personal data.
	 *
	 * @return the claims set
	 * @since 1.0.0
	 */
	@NonNull
	public JsonObject toJsonObject() {
		return this.claims.claims();
	}

	/**
	 * Describes this object without any claim.
	 *
	 * @return a fully redacted description
	 * @since 1.0.0
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{<redacted>}";
	}
}
