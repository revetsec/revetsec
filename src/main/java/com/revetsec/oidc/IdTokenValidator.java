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

import com.revetsec.internal.Limits;
import com.revetsec.internal.ObserverDispatch;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.jose.JwtValidationAccess;
import com.revetsec.internal.json.JsonFieldException;
import com.revetsec.internal.json.JsonFields;
import com.revetsec.jose.JsonWebKeySource;
import com.revetsec.jose.JoseException;
import com.revetsec.jose.JoseObserver;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.Jwt;
import com.revetsec.jose.JwtClaims;
import com.revetsec.jose.JwtValidator;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import javax.annotation.concurrent.NotThreadSafe;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Internal ID-token validation. JOSE authenticates the received bytes and runs the registered-claim
 * checks before this class reads profile claims. Only the final successful check constructs an IdToken.
 * The token endpoint must keep every token internal until this method succeeds.
 */
@ThreadSafe
final class IdTokenValidator {
	private final String issuer;
	private final String clientId;
	private final JsonWebKeySource jsonWebKeySource;
	private final Set<JwsAlgorithm> algorithms;
	private final Set<String> trustedAudiences;
	private final Set<String> trustedAuthorizedParties;
	private final Duration clockSkew;
	private final Duration maximumIdTokenAge;
	private final Clock clock;
	private final JoseObserver observer;
	private final boolean hmacEnabled;

	IdTokenValidator(@NonNull String issuer, @NonNull String clientId, @NonNull JsonWebKeySource jsonWebKeySource,
			@NonNull Set<@NonNull JwsAlgorithm> algorithms, @NonNull Set<@NonNull String> trustedAudiences, @NonNull Set<@NonNull String> trustedAuthorizedParties,
			@NonNull Duration clockSkew, @NonNull Duration maximumIdTokenAge, @NonNull Clock clock) {
		this(issuer, clientId, jsonWebKeySource, algorithms, trustedAudiences, trustedAuthorizedParties, clockSkew,
				maximumIdTokenAge, clock, JoseObserver.disabledInstance());
	}

	IdTokenValidator(@NonNull String issuer, @NonNull String clientId, @NonNull JsonWebKeySource jsonWebKeySource,
			@NonNull Set<@NonNull JwsAlgorithm> algorithms, @NonNull Set<@NonNull String> trustedAudiences, @NonNull Set<@NonNull String> trustedAuthorizedParties,
			@NonNull Duration clockSkew, @NonNull Duration maximumIdTokenAge, @NonNull Clock clock, @NonNull JoseObserver observer) {
		this(issuer, clientId, jsonWebKeySource, algorithms, trustedAudiences, trustedAuthorizedParties, clockSkew,
				maximumIdTokenAge, clock, observer, false);
	}
	IdTokenValidator(@NonNull String issuer, @NonNull String clientId, @NonNull JsonWebKeySource jsonWebKeySource,
			@NonNull Set<@NonNull JwsAlgorithm> algorithms, @NonNull Set<@NonNull String> trustedAudiences, @NonNull Set<@NonNull String> trustedAuthorizedParties,
			@NonNull Duration clockSkew, @NonNull Duration maximumIdTokenAge, @NonNull Clock clock, @NonNull JoseObserver observer, boolean hmacEnabled) {
		this.hmacEnabled = hmacEnabled;
		this.issuer = requireNonNull(issuer);
		this.clientId = requireNonNull(clientId);
		this.jsonWebKeySource = requireNonNull(jsonWebKeySource);
		this.algorithms = Set.copyOf(algorithms);
		this.trustedAudiences = Set.copyOf(trustedAudiences);
		this.trustedAuthorizedParties = Set.copyOf(trustedAuthorizedParties);
		this.clockSkew = Limits.JOSE_CLOCK_SKEW.require(clockSkew);
		this.maximumIdTokenAge = Limits.ID_TOKEN_MAXIMUM_AGE.require(maximumIdTokenAge);
		this.clock = requireNonNull(clock);
		this.observer = requireNonNull(observer);
		if (issuer.isEmpty() || clientId.isEmpty() || this.algorithms.isEmpty()
				|| this.trustedAudiences.contains("") || this.trustedAuthorizedParties.contains(""))
			throw new IllegalArgumentException("The ID token validator configuration is invalid.");
		for (JwsAlgorithm algorithm : this.algorithms)
			if (!hmacEnabled && isHmac(algorithm))
				throw new IllegalArgumentException("This ID token validator requires asymmetric algorithms.");
	}

	boolean needsPublicKeys() { return this.algorithms.stream().anyMatch(algorithm -> !isHmac(algorithm)); }
	private static boolean isHmac(@NonNull JwsAlgorithm algorithm) { return Set.of(JwsAlgorithm.HS256, JwsAlgorithm.HS384, JwsAlgorithm.HS512).contains(algorithm); }
	private void reportHmacUse() {
		if (this.observer instanceof OidcObserver oidc)
			ObserverDispatch.dispatch(oidc, observer -> observer.didUseCompatibilityMode(OidcCompatibilityMode.HMAC_ID_TOKENS));
	}

	@NonNull IdToken validate(@NonNull String compactSerialization, @NonNull String expectedNonce, @NonNull String accessToken, @NonNull String code,
			@Nullable Duration maximumAuthenticationAge, @NonNull Set<@NonNull String> requiredAcrValues) {
		return validate(compactSerialization, expectedNonce, accessToken, code, maximumAuthenticationAge,
				requiredAcrValues, null);
	}

	@NonNull IdToken validate(@NonNull String compactSerialization, @NonNull String expectedNonce, @NonNull String accessToken, @NonNull String code,
			@Nullable Duration maximumAuthenticationAge, @NonNull Set<@NonNull String> requiredAcrValues, @Nullable Deadline deadline) {
		return validate(compactSerialization, expectedNonce, accessToken, code, maximumAuthenticationAge, requiredAcrValues, deadline, null);
	}
	@NonNull IdToken validate(@NonNull String compactSerialization, @NonNull String expectedNonce, @NonNull String accessToken, @NonNull String code,
			@Nullable Duration maximumAuthenticationAge, @NonNull Set<@NonNull String> requiredAcrValues, @Nullable Deadline deadline,
			@Nullable String clientSecret) {
		return validateProfile(compactSerialization, requireNonNull(expectedNonce), accessToken, requireNonNull(code),
				maximumAuthenticationAge, requiredAcrValues, deadline, null, clientSecret);
	}

	@NonNull IdToken validateRefresh(@NonNull String compact, @NonNull OidcSessionReference original, @NonNull String accessToken, @NonNull Set<@NonNull String> acrValues, @NonNull Deadline deadline) {
		return validateRefresh(compact, original, accessToken, acrValues, deadline, null);
	}
	@NonNull IdToken validateRefresh(@NonNull String compact, @NonNull OidcSessionReference original, @NonNull String accessToken, @NonNull Set<@NonNull String> acrValues,
			@NonNull Deadline deadline, @Nullable String clientSecret) {
		return validateProfile(compact, null, accessToken, null, null, acrValues, deadline, requireNonNull(original), clientSecret);
	}

	private @NonNull IdToken validateProfile(@NonNull String compactSerialization, @Nullable String expectedNonce, @NonNull String accessToken,
			@Nullable String code, @Nullable Duration maximumAuthenticationAge, @NonNull Set<@NonNull String> requiredAcrValues,
			@Nullable Deadline deadline, @Nullable OidcSessionReference original, @Nullable String clientSecret) {
		requireNonNull(compactSerialization);
		requireNonNull(accessToken);
		Set<String> acrValues = Set.copyOf(requiredAcrValues);
		if ((expectedNonce != null && expectedNonce.isEmpty()) || acrValues.contains("")
				|| (maximumAuthenticationAge != null && maximumAuthenticationAge.isNegative()))
			throw new IllegalArgumentException("The authenticated OIDC request options are invalid.");

		// Capture time when JOSE asks for it, after any remote key lookup. Freezing it before that lookup would let
		// a slow JWKS response extend a token's effective lifetime. Every remaining check shares that snapshot.
		ValidationClock validationClock = new ValidationClock(this.clock);
		Jwt jwt;
		byte @Nullable [] secret = null;
		try {
			Set<JwsAlgorithm> asymmetric = new java.util.HashSet<>(this.algorithms);
			asymmetric.removeIf(IdTokenValidator::isHmac);
			if (asymmetric.isEmpty()) asymmetric.add(JwsAlgorithm.RS256); // Template only; private profile replaces it.
			JwtValidator validator = JwtValidator.withIssuer(this.issuer).jsonWebKeySource(this.jsonWebKeySource)
					.expectedAudiences(Set.of(this.clientId)).allowedAlgorithms(asymmetric)
					.requiredClaims(Set.of("iat")).clockSkew(this.clockSkew)
					.clock(validationClock).observer(this.observer).build();
			if (this.hmacEnabled) {
				if (clientSecret == null) throw failure(OidcValidationException.Reason.HMAC_SECRET_INVALID);
				secret = StrictUtf8.encode(clientSecret);
				jwt = JwtValidationAccess.get().validateOidc(validator, compactSerialization, this.algorithms, secret,
						deadline == null ? () -> Long.MAX_VALUE : deadline::remainingNanos, this::reportHmacUse);
			} else jwt = deadline == null ? validator.validate(compactSerialization)
					: JwtValidationAccess.get().validate(validator, compactSerialization, deadline::remainingNanos);
		} catch (JoseException exception) {
			throw OidcValidationException.fromJoseReason(exception.getReason());
		} catch (EncodingException | IllegalArgumentException invalidSecret) {
			throw failure(OidcValidationException.Reason.HMAC_SECRET_INVALID);
		} finally { if (secret != null) Arrays.fill(secret, (byte) 0); }
		Instant now = validationClock.instant();

		JwtClaims claims = jwt.getClaims();
		if (isHmac(jwt.getAlgorithm()) && claims.getAudiences().size() != 1)
			throw failure(OidcValidationException.Reason.HMAC_MULTIPLE_AUDIENCES);
		for (String audience : claims.getAudiences())
			if (!audience.equals(this.clientId) && !this.trustedAudiences.contains(audience))
				throw failure(OidcValidationException.Reason.UNTRUSTED_AUDIENCE);

		String authorizedParty = stringClaim(claims, "azp");
		if (authorizedParty != null && !authorizedParty.equals(this.clientId)
				&& !this.trustedAuthorizedParties.contains(authorizedParty))
			throw failure(OidcValidationException.Reason.AUTHORIZED_PARTY_MISMATCH);

		Instant issuedAt = claims.getIssuedAt().orElseThrow(() -> failure(OidcValidationException.Reason.MISSING_CLAIM));
		if (original == null && Duration.between(issuedAt, now).compareTo(this.maximumIdTokenAge.plus(this.clockSkew)) > 0)
			throw failure(OidcValidationException.Reason.TOO_OLD);

		String subject = claims.getSubject().orElse("");
		if (subject.isEmpty() || subject.length() > 255 || subject.chars().anyMatch(character -> character > 0x7F))
			throw failure(OidcValidationException.Reason.INVALID_SUBJECT);

		String nonce = stringClaim(claims, "nonce");
		if (original == null) {
			if (nonce == null) throw failure(OidcValidationException.Reason.NONCE_MISSING);
			if (!sameSecret(requireNonNull(expectedNonce), nonce)) throw failure(OidcValidationException.Reason.NONCE_MISMATCH);
		}

		String acr = stringClaim(claims, "acr");
		if (!acrValues.isEmpty() && (acr == null || !acrValues.contains(acr)))
			throw failure(OidcValidationException.Reason.INSUFFICIENT_ACR);
		validateAuthenticationMethods(claims);

		Instant authenticationTime;
		try {
			authenticationTime = JsonFields.numericDate(claims.toJsonObject(), "auth_time").orElse(null);
		} catch (JsonFieldException exception) {
			throw failure(OidcValidationException.Reason.ID_TOKEN_MALFORMED);
		}
		if (maximumAuthenticationAge != null && authenticationTime == null)
			throw failure(OidcValidationException.Reason.AUTH_TIME_MISSING);
		if (authenticationTime != null && (authenticationTime.isAfter(now.plus(this.clockSkew))
				|| (maximumAuthenticationAge != null && exceedsAuthenticationAge(authenticationTime, now,
				maximumAuthenticationAge))))
			throw failure(OidcValidationException.Reason.AUTHENTICATION_TOO_OLD);

		checkHash(claims, "at_hash", jwt.getAlgorithm(), accessToken,
				OidcValidationException.Reason.ACCESS_TOKEN_HASH_MISMATCH);
		if (code != null) checkHash(claims, "c_hash", jwt.getAlgorithm(), code, OidcValidationException.Reason.CODE_HASH_MISMATCH);
		else if (claims.getClaim("c_hash").isPresent()) throw failure(OidcValidationException.Reason.CODE_HASH_MISMATCH);
		if (original != null) original.checkContinuity(claims);
		return new IdToken(jwt);
	}

	private boolean exceedsAuthenticationAge(@NonNull Instant authenticationTime, @NonNull Instant now, @NonNull Duration maximumAge) {
		// Compare by subtraction to avoid overflow from a caller's very large maximum age.
		Duration ageAfterSkew = Duration.between(authenticationTime, now).minus(this.clockSkew);
		return ageAfterSkew.compareTo(maximumAge) > 0;
	}

	private static void validateAuthenticationMethods(@NonNull JwtClaims claims) {
		JsonValue value = claims.getClaim("amr").orElse(null);
		if (value != null && (!(value instanceof JsonArray array)
				|| array.getElements().stream().anyMatch(element -> !(element instanceof JsonString))))
			throw failure(OidcValidationException.Reason.ID_TOKEN_MALFORMED);
		stringClaim(claims, "sid");
	}

	private static @Nullable String stringClaim(@NonNull JwtClaims claims, @NonNull String name) {
		JsonValue value = claims.getClaim(name).orElse(null);
		if (value == null)
			return null;
		if (!(value instanceof JsonString string))
			throw failure(OidcValidationException.Reason.ID_TOKEN_MALFORMED);
		return string.getValue();
	}

	private static void checkHash(@NonNull JwtClaims claims, @NonNull String name, @NonNull JwsAlgorithm algorithm, @NonNull String credential,
			OidcValidationException.@NonNull Reason reason) {
		if (claims.getClaim(name).isEmpty())
			return;
		JsonValue value = claims.getClaim(name).orElseThrow();
		if (!(value instanceof JsonString string))
			throw failure(reason);
		try {
			if (!sameSecret(IdTokenHash.hash(algorithm, credential), string.getValue()))
				throw failure(reason);
		} catch (IllegalArgumentException exception) {
			throw failure(reason);
		}
	}

	private static boolean sameSecret(@NonNull String expected, @NonNull String actual) {
		byte[] expectedBytes = expected.getBytes(StandardCharsets.UTF_8);
		byte[] actualBytes = actual.getBytes(StandardCharsets.UTF_8);
		try {
			return MessageDigest.isEqual(expectedBytes, actualBytes);
		} finally {
			Arrays.fill(expectedBytes, (byte) 0);
			Arrays.fill(actualBytes, (byte) 0);
		}
	}

	private static @NonNull OidcValidationException failure(OidcValidationException.@NonNull Reason reason) {
		return OidcValidationException.fromReason(reason);
	}

	/** One validation's clock snapshot; never shared between calls or threads. */
	@NotThreadSafe
	private static final class ValidationClock extends Clock {
		private final Clock delegate;
		private @Nullable Instant snapshot;

		private ValidationClock(@NonNull Clock delegate) {
			this.delegate = delegate;
		}

		@Override
		public @NonNull ZoneId getZone() {
			return this.delegate.getZone();
		}

		@Override
		public @NonNull Clock withZone(@NonNull ZoneId zone) {
			return new ValidationClock(this.delegate.withZone(zone));
		}

		@Override
		public @NonNull Instant instant() {
			Instant instant = this.snapshot;
			if (instant == null) {
				instant = this.delegate.instant();
				this.snapshot = instant;
			}
			return instant;
		}
	}
}
