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
package com.revetsec.oauth;

import static java.util.Objects.requireNonNull;
import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.Limits;
import com.revetsec.internal.ObserverDispatch;
import com.revetsec.internal.http.*;
import com.revetsec.internal.jose.*;
import com.revetsec.jose.*;
import com.revetsec.json.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.*;
import java.util.*;
import java.util.concurrent.locks.ReentrantLock;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * RFC9068 JWT bearer-access-token validator for exact issuer and explicitly configured audiences.
 * Build performs no I/O. Header/signature-shape checks precede lazy discovery and JWKS; no incoming credential is retained in proof.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public final class JwtAccessTokenValidator implements AccessTokenValidator {

	private final Builder settings;

	private final JoseHeaderPolicy header;

	private final ReentrantLock stateLock = new ReentrantLock();

	@Nullable
	private State state;

	@Nullable
	private final ResourceServerMetadataCache<State> cache;

	private JwtAccessTokenValidator(@NonNull Builder settings) {
		this.settings = settings;
		this.header = JoseHeaderPolicy.fromSettings(settings.maximumTokenLength, settings.allowedAlgorithms, settings.compatibility == null ? Set.of("at+jwt") : Set.of("at+jwt", "JWT"), settings.compatibility == null);
		if (settings.jsonWebKeySource != null) {
			this.state = stateFor(null);
			this.cache = null;
		} else {
			this.cache = new ResourceServerMetadataCache<>(URI.create(settings.issuer), ResourceServerMetadata.Role.JWT, HttpExchange.fromHttpClient(settings.httpClient, settings.outboundUriPolicy, settings.allowInsecureLoopback), settings.outboundUriPolicy, settings.allowInsecureLoopback, settings.requestTimeout, settings.clock, settings.observer, settings.minimumTimeToLive, settings.defaultTimeToLive, settings.maximumTimeToLive, settings.discoveryCooldown, this::stateFor, System::nanoTime, this::publish);
		}
	}

	private @NonNull State stateFor(@Nullable ResourceServerMetadata metadata) {
		if (this.settings.jsonWebKeySource == null && !UriChecks.isPermitted(requireNonNull(metadata).endpoint(), this.settings.outboundUriPolicy, this.settings.allowInsecureLoopback))
			throw OAuthValidationException.fromReason(OAuthException.Reason.METADATA_INVALID);
		this.stateLock.lock();
		try {
			State previous = this.state;
			JsonWebKeySource source = this.settings.jsonWebKeySource;
			if (source == null && previous != null && previous.endpoint != null && previous.endpoint.toString().equals(requireNonNull(metadata).endpoint().toString()))
				source = previous.source;
			if (source == null)
				source = RemoteJsonWebKeySource.withUri(requireNonNull(metadata).endpoint()).httpClient(this.settings.httpClient).outboundUriPolicy(this.settings.outboundUriPolicy).clock(this.settings.clock).observer(this.settings.observer).allowInsecureLoopback(this.settings.allowInsecureLoopback).acknowledgeUnpatchedRuntime(this.settings.acknowledgeUnpatchedRuntime).requestTimeout(this.settings.requestTimeout).build();
			Set<String> required = new HashSet<>(this.settings.requiredClaims);
			required.addAll(Set.of("exp", "iat", "sub"));
			if (this.settings.compatibility == null)
				required.addAll(Set.of("client_id", "jti"));
			JwtValidator validator = JwtValidator.withIssuer(this.settings.issuer).jsonWebKeySource(source).expectedAudiences(this.settings.expectedAudiences).allowedAlgorithms(this.settings.allowedAlgorithms).allowedTypes(this.header.getAllowedTypes()).typeRequired(this.header.isTypeRequired()).requiredClaims(required).clockSkew(this.settings.clockSkew).clock(this.settings.clock).maximumTokenLength(this.settings.maximumTokenLength).observer(this.settings.observer).build();
			return new State(metadata == null ? null : metadata.endpoint(), source, validator);
		} finally {
			this.stateLock.unlock();
		}
	}

	private void publish(@NonNull State ready) {
		this.stateLock.lock();
		try {
			this.state = ready;
		} finally {
			this.stateLock.unlock();
		}
	}

	private @NonNull State state(@NonNull Deadline deadline) {
		if (this.cache != null)
			return this.cache.get(deadline);
		this.stateLock.lock();
		try {
			return requireNonNull(this.state);
		} finally {
			this.stateLock.unlock();
		}
	}

	private record State(@Nullable URI endpoint, @NonNull JsonWebKeySource source, @NonNull JwtValidator validator) {

		@Override
		public @NonNull String toString() {
			return "State{data=<redacted>}";
		}
	}

	/**
	 * Starts a validator for one exact issuer.
	 * @param issuer expected issuer, never normalized
	 * @return builder
	 * @since 1.0.0
	 */
	@NonNull
	public static Builder withIssuer(@NonNull String issuer) {
		return new Builder(issuer);
	}

	/**
	 * Warms discovery and remote signing keys using one total deadline.
	 * @since 1.0.0
	 */
	public void warmUp() {
		Deadline deadline = Deadline.fromNow(this.settings.totalDeadline);
		State ready = state(deadline);
		if (ready.source instanceof RemoteJsonWebKeySource remote)
			JwtValidationAccess.get().warmUp(remote, deadline::remainingNanos);
	}

	/**
	 * Validates the token exactly once; infrastructure failures remain distinct exceptions.
	 * @param token unverified bearer credential
	 * @return verified access token with no credential retained
	 * @since 1.0.0
	 */
	@Override
	@CheckReturnValue
	@NonNull
	public VerifiedAccessToken validate(@NonNull BearerToken token) {
		requireNonNull(token);
		Deadline deadline = Deadline.fromNow(this.settings.totalDeadline);
		try {
			if (token.value().length() > this.settings.maximumTokenLength)
				throw AccessTokenValidationException.fromReason(AccessTokenValidationException.Reason.MALFORMED_REQUEST);
			PreparedJws prepared;
			try {
				prepared = JwtProcessor.prepare(token.value(), this.header);
			} catch (JoseFailure failure) {
				throw AccessTokenValidationException.fromJoseReason(failure.getReason());
			}
			boolean untyped = prepared.findType().map(t -> JoseHeaderPolicy.normalizeType(t).orElse("").equals("application/jwt")).orElse(true);
			if (untyped)
				ObserverDispatch.dispatch(this.settings.observer, o -> o.didUseCompatibilityMode(AccessTokenCompatibilityMode.UNTYPED_ACCESS_TOKENS));
			Jwt jwt;
			try {
				jwt = JwtValidationAccess.get().validatePrepared(state(deadline).validator, prepared, deadline::remainingNanos);
			} catch (JoseException failure) {
				throw AccessTokenValidationException.fromJoseReason(failure.getReason());
			}
			JsonObject claims = jwt.getClaims().toJsonObject();
			if (untyped)
				for (String name : Set.of("nonce", "at_hash", "c_hash", "auth_time")) if (claims.getMembers().containsKey(name))
					throw AccessTokenValidationException.fromReason(AccessTokenValidationException.Reason.UNTYPED_IDENTITY_CLAIM_PRESENT);
			String subject = AccessTokenClaims.requiredString(claims, "sub");
			String client = claims.getMembers().containsKey("client_id") ? AccessTokenClaims.requiredString(claims, "client_id") : null;
			if (this.settings.compatibility == null) {
				AccessTokenClaims.requiredString(claims, "client_id");
				AccessTokenClaims.requiredString(claims, "jti");
			}
			Set<String> scopes = AccessTokenClaims.scopes(claims.getMembers().get(this.settings.scopeClaimName), this.settings.scopeClaimName.equals("scp"));
			VerifiedAccessToken result = new VerifiedAccessToken(this.settings.issuer, subject, client, scopes, jwt.getClaims().getAudiences(), jwt.getClaims().getExpiresAt().orElse(null), claims);
			ObserverDispatch.dispatch(this.settings.observer, AccessTokenObserver::didValidateAccessToken);
			return result;
		} catch (AccessTokenValidationException rejection) {
			ObserverDispatch.dispatch(this.settings.observer, o -> o.didRejectAccessToken(rejection));
			throw rejection;
		}
	}

	/**
	 * Returns a local credential verdict; provider failures remain exceptions.
	 * @param token unverified bearer credential
	 * @return outcome
	 * @since 1.0.0
	 */
	@Override
	@CheckReturnValue
	@NonNull
	public AccessTokenValidationResult validateResult(@NonNull BearerToken token) {
		try {
			return AccessTokenValidationResult.fromToken(validate(token));
		} catch (AccessTokenValidationException rejection) {
			return AccessTokenValidationResult.fromRejection(rejection);
		}
	}

	/**
	 * Returns a redacted configuration description.
	 * @return description
	 * @since 1.0.0
	 */
	@Override
	@NonNull
	public String toString() {
		return "JwtAccessTokenValidator{data=<redacted>}";
	}

	/**
	 * Configures an immutable resource validator. Nullable setters restore defaults; missing audiences fail at build.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	@CheckReturnValue
	public static final class Builder {

		private final String issuer;

		@Nullable
		private Set<@NonNull String> expectedAudiences;

		private Set<@NonNull JwsAlgorithm> allowedAlgorithms = Set.of(JwsAlgorithm.RS256);

		private Set<@NonNull String> requiredClaims = Set.of();

		private String scopeClaimName = "scope";

		@Nullable
		private AccessTokenCompatibilityMode compatibility;

		private int maximumTokenLength = Limits.BEARER_CREDENTIAL_SIZE.getDefaultIntValue();

		private Duration clockSkew = Limits.JOSE_CLOCK_SKEW.getDefaultDuration();

		private Clock clock = Clock.systemUTC();

		@Nullable
		private JsonWebKeySource jsonWebKeySource;

		@Nullable
		private HttpClient httpClient;

		private OutboundUriPolicy outboundUriPolicy = OutboundUriPolicy.defaultInstance();

		private Duration requestTimeout = Limits.REQUEST_TIMEOUT.getDefaultDuration();

		private Duration totalDeadline = Limits.TOTAL_DEADLINE.getDefaultDuration();

		private Duration minimumTimeToLive = Limits.DISCOVERY_MINIMUM_TIME_TO_LIVE.getDefaultDuration();

		private Duration defaultTimeToLive = Limits.DISCOVERY_DEFAULT_TIME_TO_LIVE.getDefaultDuration();

		private Duration maximumTimeToLive = Limits.DISCOVERY_MAXIMUM_TIME_TO_LIVE.getDefaultDuration();

		private Duration discoveryCooldown = Limits.DISCOVERY_COOLDOWN.getDefaultDuration();

		private boolean allowInsecureLoopback;

		private boolean acknowledgeUnpatchedRuntime;

		private AccessTokenObserver observer = AccessTokenObserver.disabledInstance();

		private Builder(@NonNull String issuer) {
			this.issuer = requireNonNull(issuer);
			if (issuer.isEmpty())
				throw new IllegalArgumentException("An issuer is required.");
		}

		private Builder(@NonNull Builder original) {
			this.issuer = original.issuer;
			this.expectedAudiences = original.expectedAudiences;
			this.allowedAlgorithms = original.allowedAlgorithms;
			this.requiredClaims = original.requiredClaims;
			this.scopeClaimName = original.scopeClaimName;
			this.compatibility = original.compatibility;
			this.maximumTokenLength = original.maximumTokenLength;
			this.clockSkew = original.clockSkew;
			this.clock = original.clock;
			this.jsonWebKeySource = original.jsonWebKeySource;
			this.httpClient = original.httpClient;
			this.outboundUriPolicy = original.outboundUriPolicy;
			this.requestTimeout = original.requestTimeout;
			this.totalDeadline = original.totalDeadline;
			this.minimumTimeToLive = original.minimumTimeToLive;
			this.defaultTimeToLive = original.defaultTimeToLive;
			this.maximumTimeToLive = original.maximumTimeToLive;
			this.discoveryCooldown = original.discoveryCooldown;
			this.allowInsecureLoopback = original.allowInsecureLoopback;
			this.acknowledgeUnpatchedRuntime = original.acknowledgeUnpatchedRuntime;
			this.observer = original.observer;
		}

		/**
		 * Sets required exact audiences.
		 * @param value setting, or null to restore its default or absence
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder expectedAudiences(@Nullable Set<@NonNull String> value) {
			this.expectedAudiences = value == null ? null : AccessTokenClaims.names(value, true);
			return this;
		}

		/**
		 * Sets public-key algorithm set.
		 * @param value setting, or null to restore its default or absence
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder allowedAlgorithms(@Nullable Set<@NonNull JwsAlgorithm> value) {
			this.allowedAlgorithms = value == null ? Set.of(JwsAlgorithm.RS256) : Set.copyOf(value);
			return this;
		}

		/**
		 * Sets additional required claims.
		 * @param value setting, or null to restore its default or absence
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder requiredClaims(@Nullable Set<@NonNull String> value) {
			this.requiredClaims = value == null ? Set.of() : AccessTokenClaims.names(value, false);
			return this;
		}

		/**
		 * Sets scope claim name.
		 * @param value setting, or null to restore its default or absence
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder scopeClaimName(@Nullable String value) {
			if (value != null && !Set.of("scope", "scp").contains(value))
				throw new IllegalArgumentException("The scope claim must be scope or scp.");
			this.scopeClaimName = value == null ? "scope" : value;
			return this;
		}

		/**
		 * Sets explicit compatibility mode.
		 * @param value setting, or null to restore its default or absence
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder compatibility(@Nullable AccessTokenCompatibilityMode value) {
			this.compatibility = value;
			return this;
		}

		/**
		 * Sets credential cap.
		 * @param value setting, or null to restore its default or absence
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder maximumTokenLength(@Nullable Integer value) {
			this.maximumTokenLength = value == null ? Limits.BEARER_CREDENTIAL_SIZE.getDefaultIntValue() : Limits.BEARER_CREDENTIAL_SIZE.require(value);
			return this;
		}

		/**
		 * Sets clock skew.
		 * @param value setting, or null to restore its default or absence
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder clockSkew(@Nullable Duration value) {
			this.clockSkew = value == null ? Limits.JOSE_CLOCK_SKEW.getDefaultDuration() : Limits.JOSE_CLOCK_SKEW.require(value);
			return this;
		}

		/**
		 * Sets clock.
		 * @param value setting, or null to restore its default or absence
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder clock(@Nullable Clock value) {
			this.clock = value == null ? Clock.systemUTC() : value;
			return this;
		}

		/**
		 * Sets key source that bypasses discovery.
		 * @param value setting, or null to restore its default or absence
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder jsonWebKeySource(@Nullable JsonWebKeySource value) {
			this.jsonWebKeySource = value;
			return this;
		}

		/**
		 * Sets transport.
		 * @param value setting, or null to restore its default or absence
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder httpClient(@Nullable HttpClient value) {
			this.httpClient = value;
			return this;
		}

		/**
		 * Sets outbound URI policy.
		 * @param value setting, or null to restore its default or absence
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder outboundUriPolicy(@Nullable OutboundUriPolicy value) {
			this.outboundUriPolicy = value == null ? OutboundUriPolicy.defaultInstance() : value;
			return this;
		}

		/**
		 * Sets request timeout.
		 * @param value setting, or null to restore its default or absence
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder requestTimeout(@Nullable Duration value) {
			this.requestTimeout = value == null ? Limits.REQUEST_TIMEOUT.getDefaultDuration() : Limits.REQUEST_TIMEOUT.require(value);
			return this;
		}

		/**
		 * Sets shared deadline.
		 * @param value setting, or null to restore its default or absence
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder totalDeadline(@Nullable Duration value) {
			this.totalDeadline = value == null ? Limits.TOTAL_DEADLINE.getDefaultDuration() : Limits.TOTAL_DEADLINE.require(value);
			return this;
		}

		/**
		 * Sets minimum metadata TTL.
		 * @param value setting, or null to restore its default or absence
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder minimumTimeToLive(@Nullable Duration value) {
			this.minimumTimeToLive = value == null ? Limits.DISCOVERY_MINIMUM_TIME_TO_LIVE.getDefaultDuration() : Limits.DISCOVERY_MINIMUM_TIME_TO_LIVE.require(value);
			return this;
		}

		/**
		 * Sets fallback metadata TTL.
		 * @param value setting, or null to restore its default or absence
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder defaultTimeToLive(@Nullable Duration value) {
			this.defaultTimeToLive = value == null ? Limits.DISCOVERY_DEFAULT_TIME_TO_LIVE.getDefaultDuration() : Limits.DISCOVERY_DEFAULT_TIME_TO_LIVE.require(value);
			return this;
		}

		/**
		 * Sets maximum metadata TTL.
		 * @param value setting, or null to restore its default or absence
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder maximumTimeToLive(@Nullable Duration value) {
			this.maximumTimeToLive = value == null ? Limits.DISCOVERY_MAXIMUM_TIME_TO_LIVE.getDefaultDuration() : Limits.DISCOVERY_MAXIMUM_TIME_TO_LIVE.require(value);
			return this;
		}

		/**
		 * Sets discovery attempt window.
		 * @param value setting, or null to restore its default or absence
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder discoveryCooldown(@Nullable Duration value) {
			this.discoveryCooldown = value == null ? Limits.DISCOVERY_COOLDOWN.getDefaultDuration() : Limits.DISCOVERY_COOLDOWN.require(value);
			return this;
		}

		/**
		 * Sets explicit local HTTP opt-in.
		 * @param value setting, or null to restore its default or absence
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder allowInsecureLoopback(@Nullable Boolean value) {
			this.allowInsecureLoopback = Boolean.TRUE.equals(value);
			return this;
		}

		/**
		 * Sets explicit unpatched network-runtime acknowledgement.
		 * @param value setting, or null to restore its default or absence
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder acknowledgeUnpatchedRuntime(@Nullable Boolean value) {
			this.acknowledgeUnpatchedRuntime = Boolean.TRUE.equals(value);
			return this;
		}

		/**
		 * Sets observer.
		 * @param value setting, or null to restore its default or absence
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder observer(@Nullable AccessTokenObserver value) {
			this.observer = value == null ? AccessTokenObserver.disabledInstance() : value;
			return this;
		}

		/**
		 * Builds without I/O or new threads.
		 * @return validator
		 * @since 1.0.0
		 */
		@NonNull
		public JwtAccessTokenValidator build() {
			return build(Runtime.version());
		}

		@NonNull JwtAccessTokenValidator build(Runtime.@NonNull Version runtime) {
			if (this.expectedAudiences == null)
				throw new IllegalStateException("Expected audiences are required.");
			if (this.allowedAlgorithms.isEmpty() || this.allowedAlgorithms.stream().anyMatch(a -> Algorithms.familyOf(a) == Algorithms.Family.HMAC))
				throw new IllegalArgumentException("At least one public-key algorithm is required.");
			if (this.compatibility != null && this.requiredClaims.stream().noneMatch(n -> !Set.of("iss", "aud", "sub", "client_id", "jti", "exp", "iat", "nbf").contains(n)))
				throw new IllegalArgumentException("Untyped access tokens require an additional required claim.");
			Limits.requireRequestTimeoutWithinTotalDeadline(this.requestTimeout, this.totalDeadline);
			Limits.requireDiscoveryTimeToLiveOrder(this.minimumTimeToLive, this.defaultTimeToLive, this.maximumTimeToLive, this.discoveryCooldown);
			if (!(this.jsonWebKeySource instanceof StaticJsonWebKeySource)) {
				RuntimeFloor.require(runtime, this.acknowledgeUnpatchedRuntime);
				if (this.jsonWebKeySource == null) {
					URI issuerUri = URI.create(this.issuer);
					if (issuerUri.getRawQuery() != null || issuerUri.getRawFragment() != null)
						throw new IllegalArgumentException("Issuer query/fragment is invalid.");
					UriChecks.requirePermitted(issuerUri, this.outboundUriPolicy, this.allowInsecureLoopback);
				}
			}
			JwtAccessTokenValidator validator = new JwtAccessTokenValidator(new Builder(this));
			AccessTokenCompatibilityMode mode = this.compatibility;
			if (mode != null)
				ObserverDispatch.dispatch(this.observer, o -> o.didEnableCompatibilityMode(mode));
			if (!(this.jsonWebKeySource instanceof StaticJsonWebKeySource) && RuntimeFloor.isBelowFloor(runtime) && this.acknowledgeUnpatchedRuntime)
				ObserverDispatch.dispatch(this.observer, o -> o.didUseUnpatchedRuntime(runtime.toString()));
			return validator;
		}
	}
}
