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

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.internal.Limits;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.jose.JwtValidationAccess;
import com.revetsec.internal.ObserverDispatch;
import com.revetsec.internal.jose.Algorithms;
import com.revetsec.internal.jose.JoseFailure;
import com.revetsec.internal.jose.JoseHeaderPolicy;
import com.revetsec.internal.jose.JwtClaimsPolicy;
import com.revetsec.internal.jose.JwtProcessor;
import com.revetsec.internal.jose.KeyQuery;
import com.revetsec.internal.jose.KeySelection;
import com.revetsec.internal.jose.KeySelector;
import com.revetsec.internal.jose.PreparedJws;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.time.Clock;
import java.time.Duration;
import java.util.Set;
import java.util.function.LongSupplier;

import static java.util.Objects.requireNonNull;

/**
 * Validates JWTs in the JWS compact serialization (RFC 7519, RFC 7515) signed with a public key, for one expected
 * issuer.
 * <p>
 * {@link #validate(String)} runs the checks in a fixed order and stops at the first failure:
 * <ol>
 *   <li>the token's length, before it is examined any further;</li>
 *   <li>the compact serialization and the canonical base64url of every segment;</li>
 *   <li>the JOSE header: a strict JSON object whose {@code alg} is an allowed algorithm (compared exactly, so
 *   {@code none} in any case fails here); then no {@code crit}, {@code b64} or {@code zip}; then no key or key
 *   location in the header ({@code jwk}, {@code jku} and {@code x5u} are rejected and never fetched); then an allowed
 *   {@code typ}; then no {@code cty}; then a {@code kid}, when present, that is a string of 1 to 256 characters;</li>
 *   <li>the signature's length and form for the algorithm, before any key is looked up, so a malformed signature never
 *   causes a key set fetch;</li>
 *   <li>the key, selected from the {@link JsonWebKeySource} by the header's {@code kid} and the algorithm; a remote
 *   source may fetch or refresh its key set here, on the calling thread;</li>
 *   <li>the signature, over the header and payload exactly as received;</li>
 *   <li>the claims: a strict JSON object whose registered claims have the right types; {@code iss} equal to the
 *   expected issuer; the key's JWK {@code issuer} member, when it has one, bound to {@code iss}; an expected audience
 *   in {@code aud}; {@code exp}, then {@code iat}, then {@code nbf} against the clock, with the clock skew; the
 *   required claims; and no {@code cnf}, because this validator does not check proof of possession.</li>
 * </ol>
 * A rejected token throws a {@link JoseException} whose {@link JoseException.Reason} names the failed check. A remote
 * source that cannot supply its key set throws a {@link JsonWebKeySetUnavailableException}, unchanged. Neither
 * message contains the token, a claim or a key ID.
 * <p>
 * Instances are immutable and safe for concurrent use. {@link Builder#build()} does no I/O, even over a remote key
 * source. Validators compare by reference.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
@CheckReturnValue
public final class JwtValidator {
	static { JwtValidationAccess.set(new DeadlineOperations()); }
	@ThreadSafe
	private static final class DeadlineOperations implements JwtValidationAccess.Operations {
		@Override public Jwt validateUserInfo(JwtValidator validator, String compact, LongSupplier remainingNanos) {
			return validator.validate(compact, requireNonNull(remainingNanos), validator.claimsPolicy.withOptionalExpiration());
		}
		@Override public void warmUp(RemoteJsonWebKeySource source, LongSupplier remainingNanos) { source.warmUp(remainingNanos); }
		@Override public Jwt validate(JwtValidator validator, String compact, LongSupplier remainingNanos) {
			return validator.validate(compact, requireNonNull(remainingNanos));
		}
	}

	@NonNull
	private static final Set<@NonNull JwsAlgorithm> DEFAULT_ALLOWED_ALGORITHMS = Set.of(JwsAlgorithm.RS256);
	@NonNull
	private static final Set<@NonNull String> DEFAULT_ALLOWED_TYPES = Set.of("JWT");

	@NonNull
	private final String issuer;
	@NonNull
	private final JsonWebKeySource jsonWebKeySource;
	@NonNull
	private final JoseHeaderPolicy headerPolicy;
	@NonNull
	private final JwtClaimsPolicy claimsPolicy;
	private final boolean acceptAnyAudience;
	@NonNull
	private final Clock clock;
	@NonNull
	private final JoseObserver observer;

	private JwtValidator(@NonNull String issuer,
											 @NonNull JsonWebKeySource jsonWebKeySource,
											 @NonNull JoseHeaderPolicy headerPolicy,
											 @NonNull JwtClaimsPolicy claimsPolicy,
											 boolean acceptAnyAudience,
											 @NonNull Clock clock,
											 @NonNull JoseObserver observer) {
		this.issuer = issuer;
		this.jsonWebKeySource = jsonWebKeySource;
		this.headerPolicy = headerPolicy;
		this.claimsPolicy = claimsPolicy;
		this.acceptAnyAudience = acceptAnyAudience;
		this.clock = clock;
		this.observer = observer;
	}

	/**
	 * Starts building a validator for tokens from {@code issuer}.
	 *
	 * @param issuer the expected {@code iss}, compared exactly, code point by code point, with no normalization: a
	 *               trailing slash or a difference in case is another issuer
	 * @return a new builder
	 * @throws NullPointerException     if {@code issuer} is {@code null}
	 * @throws IllegalArgumentException if {@code issuer} is empty
	 * @since 1.0.0
	 */
	@NonNull
	public static Builder withIssuer(@NonNull String issuer) {
		return new Builder(issuer);
	}

	/**
	 * Validates a token (see the class description for the checks and their order).
	 * <p>
	 * Over a {@link RemoteJsonWebKeySource}, this may fetch the key set on the calling thread, or wait for another
	 * caller's fetch, for up to the source's request timeout.
	 *
	 * @param compactSerialization the token, untrusted
	 * @return the validated token
	 * @throws NullPointerException               if {@code compactSerialization} is {@code null}
	 * @throws MalformedJoseInputException        if the token cannot be parsed or exceeds a limit
	 * @throws UnsupportedJoseFeatureException    if the token uses a JOSE feature Revetsec does not support
	 * @throws JwtValidationException             if the token fails a check
	 * @throws JsonWebKeySetUnavailableException if a remote key source has no usable key set for this call
	 * @since 1.0.0
	 */
	@NonNull
	public Jwt validate(@NonNull String compactSerialization) {
		return validate(compactSerialization, null);
	}

	private Jwt validate(String compactSerialization, @Nullable LongSupplier remainingNanos) {
		return validate(compactSerialization, remainingNanos, this.claimsPolicy);
	}

	private Jwt validate(String compactSerialization, @Nullable LongSupplier remainingNanos, JwtClaimsPolicy policy) {
		requireNonNull(compactSerialization);
		long startNanos = System.nanoTime();

		if (this.acceptAnyAudience)
			ObserverDispatch.dispatch(this.observer, observer -> observer.didAcceptAnyAudience(this.issuer));

		Jwt jwt;

		try {
			jwt = validateOrThrow(compactSerialization, remainingNanos, policy);
		} catch (JoseException | JsonWebKeySetUnavailableException exception) {
			Duration elapsed = Duration.ofNanos(System.nanoTime() - startNanos);
			ObserverDispatch.dispatch(this.observer, observer -> observer.didFailToValidateJwt(exception, elapsed));
			throw exception;
		}

		Duration elapsed = Duration.ofNanos(System.nanoTime() - startNanos);
		ObserverDispatch.dispatch(this.observer, observer -> observer.didValidateJwt(jwt.getAlgorithm(), elapsed));
		return jwt;
	}

	@NonNull
	private Jwt validateOrThrow(@NonNull String compactSerialization, @Nullable LongSupplier remainingNanos, JwtClaimsPolicy policy) {
		try {
			PreparedJws prepared = JwtProcessor.prepare(compactSerialization, this.headerPolicy);
			// Key resolution throws only JsonWebKeySetUnavailableException, which is never translated.
			KeySelection selection = selectKey(prepared.getKeyQuery(), remainingNanos);
			return Jwt.fromVerifiedJwt(JwtProcessor.complete(prepared, selection, policy,
					this.clock.instant()));
		} catch (JoseFailure failure) {
			throw JoseException.fromReason(failure.getReason());
		}
	}

	@NonNull
	private KeySelection selectKey(@NonNull KeyQuery query, @Nullable LongSupplier remainingNanos) {
		if (this.jsonWebKeySource instanceof StaticJsonWebKeySource staticSource) {
			try {
				return KeySelector.select(staticSource.verificationKeys(), query);
			} catch (RuntimeException e) {
				// INV-G1: an unexpected failure selects no key.
				return KeySelection.fromKind(KeySelection.Kind.UNKNOWN);
			}
		}

		// A remote source throws only JsonWebKeySetUnavailableException, which propagates unchanged.
		RemoteJsonWebKeySource remote = (RemoteJsonWebKeySource) this.jsonWebKeySource;
		return remainingNanos == null ? remote.select(query) : remote.select(query,
				Deadline.fromNow(Duration.ofNanos(Math.max(0, remainingNanos.getAsLong()))));
	}

	/**
	 * Describes this validator's configuration.
	 *
	 * @return the issuer, the key source and the checks' settings
	 * @since 1.0.0
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{issuer=" + this.issuer + ", jsonWebKeySource=" + this.jsonWebKeySource
				+ ", headerPolicy=" + this.headerPolicy + ", claimsPolicy=" + this.claimsPolicy + "}";
	}

	/**
	 * Builds a {@link JwtValidator}.
	 * <p>
	 * Each setter stores its value, and {@link #build()} checks them all. {@code null} restores a setting's default.
	 * A key source is required, and so are expected audiences unless any audience is accepted: without them
	 * {@link #build()} throws {@link IllegalStateException}. A value out of range or a conflicting pair throws
	 * {@link IllegalArgumentException}.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	@CheckReturnValue
	public static final class Builder {
		@NonNull
		private final String issuer;
		@Nullable
		private JsonWebKeySource jsonWebKeySource;
		@Nullable
		private Set<@NonNull String> expectedAudiences;
		@Nullable
		private Boolean acceptAnyAudience;
		@Nullable
		private Set<@NonNull JwsAlgorithm> allowedAlgorithms;
		@Nullable
		private Set<@NonNull String> allowedTypes;
		@Nullable
		private Boolean typeRequired;
		@Nullable
		private Set<@NonNull String> requiredClaims;
		@Nullable
		private Duration clockSkew;
		@Nullable
		private Clock clock;
		@Nullable
		private Integer maximumTokenLength;
		@Nullable
		private JoseObserver observer;

		private Builder(@NonNull String issuer) {
			requireNonNull(issuer);

			if (issuer.isEmpty())
				throw new IllegalArgumentException("The issuer must not be empty.");

			this.issuer = issuer;
		}

		/**
		 * Sets where the verification keys come from. Required.
		 *
		 * @param jsonWebKeySource the key source; share one only among validators with the same issuer. {@code null}
		 *                         clears it
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder jsonWebKeySource(@Nullable JsonWebKeySource jsonWebKeySource) {
			this.jsonWebKeySource = jsonWebKeySource;
			return this;
		}

		/**
		 * Sets the audiences a token may name: a token is accepted when at least one of its {@code aud} values is one
		 * of these, compared exactly, and other audiences in it are allowed. Required unless any audience is accepted.
		 *
		 * @param expectedAudiences at least one audience, none empty; {@code null} clears them. The set is copied
		 * @return this builder
		 * @throws NullPointerException if the set contains {@code null}
		 * @since 1.0.0
		 */
		@NonNull
		public Builder expectedAudiences(@Nullable Set<@NonNull String> expectedAudiences) {
			this.expectedAudiences = expectedAudiences == null ? null : Set.copyOf(expectedAudiences);
			return this;
		}

		/**
		 * Sets whether to accept a token for any audience, without checking {@code aud}. That lets a token issued for
		 * another application of the same issuer through, so use it only when the issuer serves this application
		 * alone. The choice is reported to {@link JoseObserver#didAcceptAnyAudience(String)} when the validator is
		 * built and on every validation. It cannot be combined with {@link #expectedAudiences(Set)}.
		 *
		 * @param acceptAnyAudience whether to accept any audience; {@code null} restores the default, {@code false}
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder acceptAnyAudience(@Nullable Boolean acceptAnyAudience) {
			this.acceptAnyAudience = acceptAnyAudience;
			return this;
		}

		/**
		 * Sets the algorithms a token may use, compared exactly with its {@code alg}.
		 * <p>
		 * The default allows {@code RS256} alone. Widen it only to algorithms your identity provider signs with. An RSA
		 * key without an {@code alg} member verifies a token only while exactly one RSA algorithm is allowed, because a
		 * key must serve one algorithm (RFC 8725 section 3.1); allowing two RSA algorithms, such as {@code RS256} and
		 * {@code PS256}, needs keys that name their {@code alg}. Microsoft Entra ID publishes RSA keys without
		 * {@code alg}, so they stop verifying if a second RSA algorithm is allowed (see the supported-algorithms
		 * document).
		 *
		 * @param allowedAlgorithms at least one algorithm, and no HMAC algorithm: this validator verifies only with
		 *                          public keys. {@code null} restores the default, {@code RS256}. The set is copied
		 * @return this builder
		 * @throws NullPointerException if the set contains {@code null}
		 * @since 1.0.0
		 */
		@NonNull
		public Builder allowedAlgorithms(@Nullable Set<@NonNull JwsAlgorithm> allowedAlgorithms) {
			this.allowedAlgorithms = allowedAlgorithms == null ? null : Set.copyOf(allowedAlgorithms);
			return this;
		}

		/**
		 * Sets the allowed values of the header's {@code typ}. Each is a media type without parameters; a value without
		 * {@code /} has {@code application/} implied (RFC 7515 section 4.1.9), and values are compared ignoring the case
		 * of ASCII letters. So the default, {@code JWT}, accepts {@code JWT}, {@code jwt} and {@code application/jwt},
		 * and rejects types that mark other profiles, such as {@code at+jwt} and {@code logout+jwt}.
		 *
		 * @param allowedTypes the allowed media types; may be empty, which allows only tokens without {@code typ}.
		 *                     {@code null} restores the default, {@code JWT}. The set is copied
		 * @return this builder
		 * @throws NullPointerException if the set contains {@code null}
		 * @since 1.0.0
		 */
		@NonNull
		public Builder allowedTypes(@Nullable Set<@NonNull String> allowedTypes) {
			this.allowedTypes = allowedTypes == null ? null : Set.copyOf(allowedTypes);
			return this;
		}

		/**
		 * Sets whether a token without {@code typ} is rejected.
		 *
		 * @param typeRequired whether the header must have {@code typ}; {@code null} restores the default,
		 *                     {@code false}, which accepts a token without one
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder typeRequired(@Nullable Boolean typeRequired) {
			this.typeRequired = typeRequired;
			return this;
		}

		/**
		 * Sets claims that must be present and not JSON {@code null}, besides the ones always required: {@code iss},
		 * {@code exp}, and {@code aud} unless any audience is accepted.
		 *
		 * @param requiredClaims claim names, none empty; {@code null} restores the default, none. The set is copied
		 * @return this builder
		 * @throws NullPointerException if the set contains {@code null}
		 * @since 1.0.0
		 */
		@NonNull
		public Builder requiredClaims(@Nullable Set<@NonNull String> requiredClaims) {
			this.requiredClaims = requiredClaims == null ? null : Set.copyOf(requiredClaims);
			return this;
		}

		/**
		 * Sets the allowance for clock differences between the issuer and this application: a token is expired from
		 * {@code exp} plus the skew, and is not yet valid, or issued in the future, only before {@code nbf} or after
		 * {@code iat} by more than the skew.
		 *
		 * @param clockSkew from zero to 5 minutes; {@code null} restores the default, 60 seconds. {@link #build()} checks
		 *                  the range
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder clockSkew(@Nullable Duration clockSkew) {
			this.clockSkew = clockSkew;
			return this;
		}

		/**
		 * Sets the clock that supplies the current time for the time checks.
		 *
		 * @param clock the clock; {@code null} restores the default, {@link Clock#systemUTC()}
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder clock(@Nullable Clock clock) {
			this.clock = clock;
			return this;
		}

		/**
		 * Sets the longest token accepted, in characters; a longer one is rejected before it is examined.
		 *
		 * @param maximumTokenLength from 8,192 to 1,048,576; {@code null} restores the default, 65,536.
		 *                           {@link #build()} checks the range
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder maximumTokenLength(@Nullable Integer maximumTokenLength) {
			this.maximumTokenLength = maximumTokenLength;
			return this;
		}

		/**
		 * Sets the observer that receives this validator's events.
		 *
		 * @param observer the observer; {@code null} restores the default, {@link JoseObserver#disabledInstance()}
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder observer(@Nullable JoseObserver observer) {
			this.observer = observer;
			return this;
		}

		/**
		 * Builds the validator. It does no I/O, even over a remote key source.
		 *
		 * @return a new validator
		 * @throws IllegalArgumentException if a value is out of range: an empty set of algorithms or audiences, an
		 *                                  HMAC algorithm, an empty audience or claim name, an allowed type that is not a
		 *                                  media type without parameters, a required type with no allowed type, a clock
		 *                                  skew or token length out of range; or if any audience is accepted and expected
		 *                                  audiences are set too
		 * @throws IllegalStateException    if no key source is set, or no expected audiences are set and any audience is
		 *                                  not accepted
		 * @since 1.0.0
		 */
		@NonNull
		public JwtValidator build() {
			Set<JwsAlgorithm> algorithms = this.allowedAlgorithms == null ? DEFAULT_ALLOWED_ALGORITHMS
					: this.allowedAlgorithms;
			if (algorithms.isEmpty())
				throw new IllegalArgumentException("At least one algorithm must be allowed.");
			for (JwsAlgorithm algorithm : algorithms)
				if (Algorithms.familyOf(algorithm) == Algorithms.Family.HMAC)
					throw new IllegalArgumentException("A JwtValidator verifies only with public keys, so it cannot allow "
							+ algorithm.getWireValue() + ".");

			boolean anyAudience = this.acceptAnyAudience != null && this.acceptAnyAudience;
			if (anyAudience && this.expectedAudiences != null)
				throw new IllegalArgumentException("Accept any audience, or set expected audiences, but not both.");
			if (this.expectedAudiences != null && (this.expectedAudiences.isEmpty() || this.expectedAudiences.contains("")))
				throw new IllegalArgumentException("Expected audiences must not be empty, and no audience may be empty.");

			Set<String> claims = this.requiredClaims == null ? Set.of() : this.requiredClaims;
			if (claims.contains(""))
				throw new IllegalArgumentException("A required claim name must not be empty.");

			Duration skew = Limits.JOSE_CLOCK_SKEW.require(this.clockSkew == null
					? Limits.JOSE_CLOCK_SKEW.getDefaultDuration() : this.clockSkew);
			int maximumLength = this.maximumTokenLength == null ? Limits.COMPACT_JWT_SIZE.getDefaultIntValue()
					: Limits.COMPACT_JWT_SIZE.require(this.maximumTokenLength.intValue());
			JoseHeaderPolicy headerPolicy = JoseHeaderPolicy.fromSettings(maximumLength, algorithms,
					this.allowedTypes == null ? DEFAULT_ALLOWED_TYPES : this.allowedTypes,
					this.typeRequired != null && this.typeRequired);

			JsonWebKeySource source = this.jsonWebKeySource;
			if (source == null)
				throw new IllegalStateException("A JwtValidator needs a JSON Web Key source.");
			if (!anyAudience && this.expectedAudiences == null)
				throw new IllegalStateException("A JwtValidator needs expected audiences, unless it accepts any audience.");

			JwtClaimsPolicy claimsPolicy = JwtClaimsPolicy.fromSettings(this.issuer,
					anyAudience ? null : this.expectedAudiences, claims, skew);
			JoseObserver validatorObserver = this.observer == null ? JoseObserver.disabledInstance() : this.observer;

			if (anyAudience)
				ObserverDispatch.dispatch(validatorObserver, observer -> observer.didAcceptAnyAudience(this.issuer));

			return new JwtValidator(this.issuer, source, headerPolicy, claimsPolicy, anyAudience,
					this.clock == null ? Clock.systemUTC() : this.clock, validatorObserver);
		}
	}
}
