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
import com.revetsec.internal.Limits;
import com.revetsec.internal.ObserverDispatch;
import com.revetsec.internal.http.*;
import com.revetsec.internal.jose.*;
import com.revetsec.jose.*;
import com.revetsec.json.*;
import java.net.URI;
import java.time.*;
import java.util.*;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Audience-checked RFC7662 JSON introspection using the supplied OAuth client settings.
 * No credential result is cached; each validation performs its own single authenticated POST. Infrastructure errors remain exceptions.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public final class TokenIntrospectionClient implements AccessTokenValidator {

	private final OAuthClient client;

	private final OAuthClient.ResourceSettings settings;

	private final Set<String> audiences;

	private final Set<String> required;

	private final int maximumTokenLength;

	private final Duration skew;

	private final AccessTokenObserver observer;

	@Nullable
	private final ResourceServerMetadata target;

	@Nullable
	private final ResourceServerMetadataCache<ResourceServerMetadata> cache;

	private final IntrospectionFailureGuard guard;

	private TokenIntrospectionClient(@NonNull Builder builder) {
		this.client = builder.client;
		this.settings = this.client.resourceSettings();
		this.audiences = requireNonNull(builder.expectedAudiences);
		this.required = builder.requiredClaims;
		this.maximumTokenLength = builder.maximumTokenLength;
		this.skew = builder.clockSkew;
		this.observer = builder.observer;
		this.guard = new IntrospectionFailureGuard(this.settings.cooldown(), System::nanoTime);
		AuthorizationServerMetadata configured = this.settings.metadata();
		URI endpoint = builder.introspectionEndpoint != null ? builder.introspectionEndpoint : configured == null ? null : configured.getIntrospectionEndpoint().orElse(null);
		if (endpoint != null) {
			UriChecks.requirePermitted(endpoint, this.settings.policy(), this.settings.allowLoopback());
			// Only metadata for the same endpoint governs an explicit override's role policy.
			boolean applicable = configured != null && configured.getIntrospectionEndpoint().map(uri -> ClientAssertionPreparation.sameEndpoint(uri, endpoint)).orElse(false);
			Set<String> methods = applicable ? requireNonNull(configured).getIntrospectionEndpointAuthMethodsSupported().orElse(null) : null;
			Set<String> algorithms = applicable ? requireNonNull(configured).getIntrospectionEndpointAuthSigningAlgValuesSupported().orElse(null) : null;
			this.client.requireIntrospectionAuthentication(methods);
			this.target = new ResourceServerMetadata(this.settings.issuer(), endpoint, methods, algorithms,
					configured == null ? null : configured.getTokenEndpoint());
			this.cache = null;
		} else {
			this.target = null;
			this.cache = new ResourceServerMetadataCache<>(URI.create(this.settings.issuer()), ResourceServerMetadata.Role.INTROSPECTION, this.settings.exchange(), this.settings.policy(), this.settings.allowLoopback(), this.settings.requestTimeout(), this.settings.clock(), this.client.resourceObserver(this.observer), this.settings.minimumTtl(), this.settings.defaultTtl(), this.settings.maximumTtl(), this.settings.cooldown(), metadata -> {
				if (!UriChecks.isPermitted(metadata.endpoint(), this.settings.policy(), this.settings.allowLoopback()))
					throw OAuthValidationException.fromReason(OAuthException.Reason.METADATA_INVALID);
				this.client.requireIntrospectionAuthentication(metadata.authenticationMethods());
				return metadata;
			}, System::nanoTime);
		}
	}

	private @NonNull ResourceServerMetadata endpoint(@NonNull Deadline deadline) {
		return this.target != null ? this.target : requireNonNull(this.cache).get(deadline);
	}
	private @NonNull ResourceServerMetadata assertionTarget(@NonNull Deadline deadline) {
		try { return endpoint(deadline); }
		catch (OAuthException failure) {
			this.client.assertionMetadataFailure(OAuthEndpoint.INTROSPECTION, failure, this.client.resourceObserver(this.observer));
			throw failure;
		}
	}

	/**
	 * Starts introspection with one configured confidential authentication strategy.
	 * @param client OAuth client supplying issuer, credentials, transport, clock and deadlines
	 * @return builder
	 * @since 1.0.0
	 */
	@NonNull
	public static Builder withOAuthClient(@NonNull OAuthClient client) {
		return new Builder(client);
	}

	/**
	 * Warms role-specific discovery without sending a credential.
	 * @since 1.0.0
	 */
	public void warmUp() {
		endpoint(Deadline.fromNow(this.settings.totalDeadline()));
	}

	/**
	 * Performs one uncached authenticated introspection and all audience/profile checks.
	 * @param token unverified bearer credential
	 * @return fully checked proof with no received credential
	 * @since 1.0.0
	 */
	@Override
	@CheckReturnValue
	@NonNull
	public VerifiedAccessToken validate(@NonNull BearerToken token) {
		requireNonNull(token);
		Deadline deadline = Deadline.fromNow(this.settings.totalDeadline());
		try {
			if (token.value().length() > this.maximumTokenLength)
				throw AccessTokenValidationException.fromReason(AccessTokenValidationException.Reason.MALFORMED_REQUEST);
			ResourceServerMetadata target = assertionTarget(deadline);
			IntrospectionFailureGuard.Attempt attempt = this.guard.acquire(deadline, this.settings.requestTimeout());
			IntrospectionResponse parsed;
			long started = System.nanoTime();
			Instant requestStart = this.settings.clock().instant();
			boolean receivedResponse = false;
			try {
				RawResponse response = this.client.introspectionRequest(token, target, deadline, this.observer);
				receivedResponse = true;
				parsed = IntrospectionResponse.parse(response, requestStart);
				this.guard.healthy(attempt);
			} catch (OAuthException failure) {
				this.guard.failed(attempt, failure);
				if (receivedResponse)
					this.client.introspectionResponseFailure(target.endpoint(), failure, Duration.ofNanos(System.nanoTime() - started), this.observer);
				throw failure;
			} catch (RuntimeException misuse) {
				this.guard.abandon(attempt);
				throw misuse;
			}
			VerifiedAccessToken result = parsed.validate(this.settings.issuer(), this.audiences, this.required, this.settings.clock().instant(), this.skew);
			ObserverDispatch.dispatch(this.observer, AccessTokenObserver::didValidateAccessToken);
			return result;
		} catch (AccessTokenValidationException rejection) {
			ObserverDispatch.dispatch(this.observer, o -> o.didRejectAccessToken(rejection));
			throw rejection;
		}
	}

	/**
	 * Returns only local credential verdicts; provider errors remain exceptions.
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
	 * Returns a redacted description.
	 * @return description
	 * @since 1.0.0
	 */
	@Override
	@NonNull
	public String toString() {
		return "TokenIntrospectionClient{data=<redacted>}";
	}

	/**
	 * Configures required audiences and optional introspection policy; OAuth settings are inherited.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	@CheckReturnValue
	public static final class Builder {

		private final OAuthClient client;

		@Nullable
		private Set<@NonNull String> expectedAudiences;

		private Set<@NonNull String> requiredClaims = Set.of();

		private int maximumTokenLength = Limits.BEARER_CREDENTIAL_SIZE.getDefaultIntValue();

		@Nullable
		private URI introspectionEndpoint;

		private Duration clockSkew = Limits.JOSE_CLOCK_SKEW.getDefaultDuration();

		private AccessTokenObserver observer = AccessTokenObserver.disabledInstance();

		private Builder(@NonNull OAuthClient client) {
			this.client = requireNonNull(client);
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
		 * Sets required claims.
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
		 * Sets credential bound.
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
		 * Sets manual introspection endpoint.
		 * @param value setting, or null to restore its default or absence
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder introspectionEndpoint(@Nullable URI value) {
			this.introspectionEndpoint = value;
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
		 * Sets resource observer.
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
		 * @return introspection client
		 * @since 1.0.0
		 */
		@NonNull
		public TokenIntrospectionClient build() {
			if (this.expectedAudiences == null)
				throw new IllegalStateException("Expected audiences are required.");
			this.client.requireIntrospectionAuthentication(null);
			return new TokenIntrospectionClient(this);
		}
	}
}
