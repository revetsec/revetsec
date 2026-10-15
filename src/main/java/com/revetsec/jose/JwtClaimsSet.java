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

import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonBoolean;
import com.revetsec.json.JsonNull;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * An immutable JWT claims set for signing (RFC 7519 section 4), with typed registered claims and JSON custom claims.
 * This is application-supplied content; {@link JwtClaims} instead represents claims that passed validation.
 * <p>
 * Every registered claim is optional. No clock, expiration, audience or token-profile policy is supplied implicitly,
 * and no ordering is required between the time claims. Applications choose those values for their token's purpose.
 * NumericDates preserve the supplied {@link Instant}'s nanoseconds and use the same years -9999 through 9999 range
 * that Revetsec accepts when reading JWTs. Audiences are serialized as a non-empty JSON array, even for one audience.
 * <p>
 * Registered setters replace earlier values, and {@code null} clears them. Custom claims add one name per call and
 * reject duplicates and registered names. Every {@link Builder#build()} returns an independent snapshot, so the
 * builder can be reused. No serialization is performed while building; the signer's output limits apply when signing.
 * <p>
 * Claims can carry personal data, so {@link #toString()} shows none of them. Instances compare by reference.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class JwtClaimsSet {
	@NonNull
	private static final Instant EARLIEST_NUMERIC_DATE = Instant.ofEpochSecond(-377_705_116_800L);
	@NonNull
	private static final Instant END_NUMERIC_DATE = Instant.ofEpochSecond(253_402_300_800L);
	@NonNull
	private static final Set<@NonNull String> REGISTERED_NAMES = Set.of("iss", "sub", "aud", "exp", "nbf", "iat", "jti");

	@Nullable
	private final String issuer;
	@Nullable
	private final String subject;
	@NonNull
	private final List<@NonNull String> audiences;
	@Nullable
	private final Instant expiresAt;
	@Nullable
	private final Instant issuedAt;
	@Nullable
	private final Instant notBefore;
	@Nullable
	private final String jwtId;
	@NonNull
	private final JsonObject claims;

	/**
	 * Returns a builder with no claims.
	 *
	 * @return a new builder
	 * @since 1.0.0
	 */
	@NonNull
	public static Builder builder() {
		return new Builder();
	}

	private JwtClaimsSet(@NonNull Builder builder) {
		this.issuer = builder.issuer;
		this.subject = builder.subject;
		this.audiences = builder.audiences;
		this.expiresAt = builder.expiresAt;
		this.issuedAt = builder.issuedAt;
		this.notBefore = builder.notBefore;
		this.jwtId = builder.jwtId;

		JsonObject.Builder claims = JsonObject.builder();
		if (this.issuer != null)
			claims.put("iss", this.issuer);
		if (this.subject != null)
			claims.put("sub", this.subject);
		if (!this.audiences.isEmpty())
			claims.put("aud", JsonArray.fromElements(this.audiences.stream().map(JsonString::fromValue).toList()));
		if (this.expiresAt != null)
			claims.put("exp", numericDate(this.expiresAt));
		if (this.issuedAt != null)
			claims.put("iat", numericDate(this.issuedAt));
		if (this.notBefore != null)
			claims.put("nbf", numericDate(this.notBefore));
		if (this.jwtId != null)
			claims.put("jti", this.jwtId);
		builder.customClaims.build().getMembers().forEach(claims::put);
		this.claims = claims.build();
	}

	/**
	 * Returns the issuer ({@code iss}).
	 *
	 * @return the issuer, or empty if absent
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull String> getIssuer() {
		return Optional.ofNullable(this.issuer);
	}

	/**
	 * Returns the subject ({@code sub}).
	 *
	 * @return the subject, or empty if absent
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull String> getSubject() {
		return Optional.ofNullable(this.subject);
	}

	/**
	 * Returns the audiences ({@code aud}).
	 *
	 * @return the unmodifiable audiences in order, or an empty list if absent
	 * @since 1.0.0
	 */
	@NonNull
	public List<@NonNull String> getAudiences() {
		return this.audiences;
	}

	/**
	 * Returns the expiration time ({@code exp}).
	 *
	 * @return the instant, or empty if absent
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull Instant> getExpiresAt() {
		return Optional.ofNullable(this.expiresAt);
	}

	/**
	 * Returns the issue time ({@code iat}).
	 *
	 * @return the instant, or empty if absent
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull Instant> getIssuedAt() {
		return Optional.ofNullable(this.issuedAt);
	}

	/**
	 * Returns the time before which the token is not valid ({@code nbf}).
	 *
	 * @return the instant, or empty if absent
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull Instant> getNotBefore() {
		return Optional.ofNullable(this.notBefore);
	}

	/**
	 * Returns the JWT ID ({@code jti}).
	 *
	 * @return the JWT ID, or empty if absent
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull String> getJwtId() {
		return Optional.ofNullable(this.jwtId);
	}

	/**
	 * Returns a claim's JSON value, registered or not.
	 *
	 * @param name the claim name, compared exactly
	 * @return the value, which may be JSON {@code null}, or empty if absent
	 * @throws NullPointerException if {@code name} is {@code null}
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull JsonValue> getClaim(@NonNull String name) {
		return this.claims.find(requireNonNull(name));
	}

	/**
	 * Returns every claim's name, registered claims first and then custom claims in insertion order.
	 *
	 * @return the unmodifiable claim names
	 * @since 1.0.0
	 */
	@NonNull
	public Set<@NonNull String> getClaimNames() {
		return this.claims.getMembers().keySet();
	}

	/**
	 * Returns every claim as a JSON object, which can carry personal data.
	 *
	 * @return the immutable claims set
	 * @since 1.0.0
	 */
	@NonNull
	public JsonObject toJsonObject() {
		return this.claims;
	}

	/**
	 * Describes this claims set without any claim.
	 *
	 * @return a fully redacted description
	 * @since 1.0.0
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{<redacted>}";
	}

	@NonNull
	private static JsonNumber numericDate(@NonNull Instant instant) {
		if (instant.getNano() == 0)
			return JsonNumber.fromValue(instant.getEpochSecond());
		return JsonNumber.fromValue(BigDecimal.valueOf(instant.getEpochSecond())
				.add(BigDecimal.valueOf(instant.getNano(), 9)).stripTrailingZeros());
	}

	@Nullable
	private static Instant requireNumericDate(@Nullable Instant instant) {
		if (instant != null && (instant.isBefore(EARLIEST_NUMERIC_DATE) || !instant.isBefore(END_NUMERIC_DATE)))
			throw new IllegalArgumentException("A NumericDate must lie within years -9999 through 9999.");
		return instant;
	}

	@Nullable
	private static String requireJsonString(@Nullable String value) {
		return value == null ? null : JsonString.fromValue(value).getValue();
	}

	/**
	 * Builds an outbound claims set. Registered setters replace values, and {@code null} clears them. Custom claim
	 * methods add one name per call and reject repeated or registered names, even when their value is JSON {@code null}.
	 * All content checks run in the setters. No token-profile or time-ordering policy is applied by {@link #build()}.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	@CheckReturnValue
	public static final class Builder {
		@Nullable
		private String issuer;
		@Nullable
		private String subject;
		@NonNull
		private List<@NonNull String> audiences;
		@Nullable
		private Instant expiresAt;
		@Nullable
		private Instant issuedAt;
		@Nullable
		private Instant notBefore;
		@Nullable
		private String jwtId;
		private final JsonObject.@NonNull Builder customClaims;

		private Builder() {
			this.audiences = List.of();
			this.customClaims = JsonObject.builder();
		}

		/**
		 * Sets the issuer ({@code iss}).
		 *
		 * @param issuer the issuer, or {@code null} to clear it
		 * @return this builder
		 * @throws IllegalArgumentException if the string contains an unpaired surrogate
		 * @since 1.0.0
		 */
		@NonNull
		@CanIgnoreReturnValue
		public Builder issuer(@Nullable String issuer) {
			this.issuer = requireJsonString(issuer);
			return this;
		}

		/**
		 * Sets the subject ({@code sub}).
		 *
		 * @param subject the subject, or {@code null} to clear it
		 * @return this builder
		 * @throws IllegalArgumentException if the string contains an unpaired surrogate
		 * @since 1.0.0
		 */
		@NonNull
		@CanIgnoreReturnValue
		public Builder subject(@Nullable String subject) {
			this.subject = requireJsonString(subject);
			return this;
		}

		/**
		 * Replaces the audiences ({@code aud}), serialized as an array even when there is one audience.
		 *
		 * @param audiences a non-empty list, copied before assignment; {@code null} clears it
		 * @return this builder
		 * @throws NullPointerException if an element is {@code null}
		 * @throws IllegalArgumentException if the list is empty or an audience contains an unpaired surrogate
		 * @since 1.0.0
		 */
		@NonNull
		@CanIgnoreReturnValue
		public Builder audiences(@Nullable List<@NonNull String> audiences) {
			if (audiences == null) {
				this.audiences = List.of();
				return this;
			}
			List<@NonNull String> snapshot = List.copyOf(audiences);
			if (snapshot.isEmpty())
				throw new IllegalArgumentException("The audiences must not be empty.");
			for (String audience : snapshot)
				JsonString.fromValue(audience);
			this.audiences = snapshot;
			return this;
		}

		/**
		 * Sets the expiration time ({@code exp}) as a NumericDate, preserving nanoseconds.
		 *
		 * @param expiresAt the instant, or {@code null} to clear it
		 * @return this builder
		 * @throws IllegalArgumentException if the instant is outside years -9999 through 9999
		 * @since 1.0.0
		 */
		@NonNull
		@CanIgnoreReturnValue
		public Builder expiresAt(@Nullable Instant expiresAt) {
			this.expiresAt = requireNumericDate(expiresAt);
			return this;
		}

		/**
		 * Sets the issue time ({@code iat}) as a NumericDate, preserving nanoseconds.
		 *
		 * @param issuedAt the instant, or {@code null} to clear it
		 * @return this builder
		 * @throws IllegalArgumentException if the instant is outside years -9999 through 9999
		 * @since 1.0.0
		 */
		@NonNull
		@CanIgnoreReturnValue
		public Builder issuedAt(@Nullable Instant issuedAt) {
			this.issuedAt = requireNumericDate(issuedAt);
			return this;
		}

		/**
		 * Sets the time before which the token is not valid ({@code nbf}) as a NumericDate, preserving nanoseconds.
		 *
		 * @param notBefore the instant, or {@code null} to clear it
		 * @return this builder
		 * @throws IllegalArgumentException if the instant is outside years -9999 through 9999
		 * @since 1.0.0
		 */
		@NonNull
		@CanIgnoreReturnValue
		public Builder notBefore(@Nullable Instant notBefore) {
			this.notBefore = requireNumericDate(notBefore);
			return this;
		}

		/**
		 * Sets the JWT ID ({@code jti}).
		 *
		 * @param jwtId the JWT ID, or {@code null} to clear it
		 * @return this builder
		 * @throws IllegalArgumentException if the string contains an unpaired surrogate
		 * @since 1.0.0
		 */
		@NonNull
		@CanIgnoreReturnValue
		public Builder jwtId(@Nullable String jwtId) {
			this.jwtId = requireJsonString(jwtId);
			return this;
		}

		/**
		 * Adds a custom claim. Use the typed setters for registered claim names.
		 *
		 * @param name the claim name, compared exactly
		 * @param value the JSON value, including {@link JsonNull} for JSON {@code null}
		 * @return this builder
		 * @throws NullPointerException if an argument is {@code null}
		 * @throws IllegalArgumentException if the name is registered, already present or contains an unpaired
		 * surrogate, or the claims object would nest more than 64 deep
		 * @since 1.0.0
		 */
		@NonNull
		@CanIgnoreReturnValue
		public Builder claim(@NonNull String name, @NonNull JsonValue value) {
			requireNonNull(name);
			requireNonNull(value);
			if (REGISTERED_NAMES.contains(name))
				throw new IllegalArgumentException("Use the typed setter for a registered claim.");
			this.customClaims.put(name, value);
			return this;
		}

		/**
		 * Adds a custom string claim.
		 *
		 * @param name the claim name, compared exactly
		 * @param value the string
		 * @return this builder
		 * @throws NullPointerException if an argument is {@code null}
		 * @throws IllegalArgumentException if the name is registered or already present, or the name or value
		 * contains an unpaired surrogate
		 * @since 1.0.0
		 */
		@NonNull
		@CanIgnoreReturnValue
		public Builder claim(@NonNull String name, @NonNull String value) {
			return claim(name, JsonString.fromValue(value));
		}

		/**
		 * Adds a custom integral number claim.
		 *
		 * @param name the claim name, compared exactly
		 * @param value the number
		 * @return this builder
		 * @throws NullPointerException if an argument is {@code null}
		 * @throws IllegalArgumentException if the name is registered, already present or contains an unpaired surrogate
		 * @since 1.0.0
		 */
		@NonNull
		@CanIgnoreReturnValue
		public Builder claim(@NonNull String name, @NonNull Long value) {
			return claim(name, JsonNumber.fromValue(value));
		}

		/**
		 * Adds a custom number claim held exactly as a JSON number.
		 *
		 * @param name the claim name, compared exactly
		 * @param value the number
		 * @return this builder
		 * @throws NullPointerException if an argument is {@code null}
		 * @throws IllegalArgumentException if the name is registered, already present or contains an unpaired
		 * surrogate, or the value exceeds the limits of {@link JsonNumber#fromValue(BigDecimal)}
		 * @since 1.0.0
		 */
		@NonNull
		@CanIgnoreReturnValue
		public Builder claim(@NonNull String name, @NonNull BigDecimal value) {
			return claim(name, JsonNumber.fromValue(value));
		}

		/**
		 * Adds a custom boolean claim.
		 *
		 * @param name the claim name, compared exactly
		 * @param value the boolean
		 * @return this builder
		 * @throws NullPointerException if an argument is {@code null}
		 * @throws IllegalArgumentException if the name is registered, already present or contains an unpaired surrogate
		 * @since 1.0.0
		 */
		@NonNull
		@CanIgnoreReturnValue
		public Builder claim(@NonNull String name, @NonNull Boolean value) {
			return claim(name, JsonBoolean.fromValue(value));
		}

		/**
		 * Adds a custom claim whose value is JSON {@code null}.
		 *
		 * @param name the claim name, compared exactly
		 * @return this builder
		 * @throws NullPointerException if the name is {@code null}
		 * @throws IllegalArgumentException if the name is registered, already present or contains an unpaired surrogate
		 * @since 1.0.0
		 */
		@NonNull
		@CanIgnoreReturnValue
		public Builder claimNull(@NonNull String name) {
			return claim(name, JsonNull.defaultInstance());
		}

		/**
		 * Returns an immutable snapshot of this builder's claims, without signing or applying a token profile.
		 *
		 * @return the outbound claims set
		 * @since 1.0.0
		 */
		@NonNull
		public JwtClaimsSet build() {
			return new JwtClaimsSet(this);
		}

		/**
		 * Describes this builder without any claim.
		 *
		 * @return a fully redacted description
		 * @since 1.0.0
		 */
		@Override
		@NonNull
		public String toString() {
			return "JwtClaimsSet.Builder{<redacted>}";
		}
	}
}
