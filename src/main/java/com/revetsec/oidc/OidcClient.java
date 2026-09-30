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

import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.Limits;
import com.revetsec.internal.ObserverDispatch;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.http.UriChecks;
import com.revetsec.internal.http.HttpExchange;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import com.revetsec.internal.oauth.OidcTransactionAccess;
import com.revetsec.jose.*;
import com.revetsec.oauth.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import javax.annotation.concurrent.NotThreadSafe;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.util.*;
import static java.util.Objects.requireNonNull;

/**
 * OpenID Connect authorization-code relying party. Provider discovery is lazy; explicit configuration and issuer settings are validated
 * without I/O or new threads in build. Authentication uses fresh nonce and PKCE S256 and validates the ID token before releasing
 * tokens or identity. The application supplies a fixed callback URI from trusted routing and clears pending cookies.
 * A sealed cookie inherits OAuth's concurrent replay boundary; use a durable atomic store for client-side single use.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public final class OidcClient {
	private final @Nullable OidcProviderCache<ProviderState> cache;
	private final OAuthClient oauth;
	private final String issuer;
	private final @Nullable JwsAlgorithm userInfoAlgorithm;
	private final UserInfoEndpoint userInfo;
	private final Set<String> scopes;
	private final List<URI> resources;
	private final Set<String> acrValues;
	private final Duration totalDeadline;
	private final OidcObserver observer;
	private final @Nullable JsonWebKeySource configuredKeySource;
	private final String clientId;
	private final Set<JwsAlgorithm> algorithms;
	private final Set<String> trustedAudiences;
	private final Set<String> trustedAuthorizedParties;
	private final Duration clockSkew;
	private final Duration maximumIdTokenAge;
	private final Clock clock;
	private final @Nullable HttpClient httpClient;
	private final OutboundUriPolicy policy;
	private final boolean allowInsecureLoopback;
	private final boolean acknowledgeUnpatchedRuntime;
	private final Duration requestTimeout;
	private final ReentrantLock stateLock = new ReentrantLock();
	private @Nullable ProviderState state;

	private OidcClient(Builder builder, OAuthClient oauth) {
		this.oauth = oauth; this.issuer = builder.issuer; this.userInfoAlgorithm = builder.userInfoAlgorithm; this.scopes = builder.scopes; this.resources = builder.resources;
		this.acrValues = builder.acrValues; this.totalDeadline = builder.totalDeadline; this.observer = builder.observer;
		this.configuredKeySource = builder.keySource; this.clientId = requireNonNull(builder.clientId);
		this.algorithms = builder.algorithms; this.trustedAudiences = builder.trustedAudiences;
		this.trustedAuthorizedParties = builder.trustedAuthorizedParties; this.clockSkew = builder.clockSkew;
		this.maximumIdTokenAge = builder.maximumIdTokenAge; this.clock = builder.clock; this.httpClient = builder.httpClient;
		this.policy = builder.policy; this.allowInsecureLoopback = builder.allowInsecureLoopback;
		this.acknowledgeUnpatchedRuntime = builder.acknowledgeUnpatchedRuntime; this.requestTimeout = builder.requestTimeout;
		this.userInfo = new UserInfoEndpoint(HttpExchange.fromHttpClient(this.httpClient, this.policy, this.allowInsecureLoopback),
				this.requestTimeout, this.clock, this.observer, new UserInfoAttemptGate(Limits.DISCOVERY_COOLDOWN.getDefaultDuration(), System::nanoTime));
		if (builder.metadata == null) {
			this.cache = new OidcProviderCache<>(URI.create(builder.issuer), HttpExchange.fromHttpClient(this.httpClient, this.policy,
					this.allowInsecureLoopback), this.policy, this.allowInsecureLoopback, this.requestTimeout, this.clock,
					this.observer, builder.minimumTimeToLive, builder.defaultTimeToLive, builder.maximumTimeToLive,
					builder.discoveryCooldown, metadata -> {
						try { checkMetadata(metadata, this.algorithms, this.policy, this.allowInsecureLoopback, this.userInfoAlgorithm); return stateFor(metadata); }
						catch (IllegalArgumentException invalid) {
							throw OidcTransactionAccess.get().endpointFailure(OAuthException.Reason.METADATA_INVALID);
						}
					}, System::nanoTime);
		} else { this.cache = null; stateFor(builder.metadata); }
	}
	private ProviderState provider(Deadline deadline) {
		if (this.cache != null) return this.cache.get(deadline);
		this.stateLock.lock();
		try { return requireNonNull(this.state); } finally { this.stateLock.unlock(); }
	}
	private ProviderState stateFor(OidcProviderMetadata metadata) {
		this.stateLock.lock();
		try {
			ProviderState current = this.state;
			if (current != null && current.metadata == metadata) return current;
			// Keep one current source, sharing its cache only while the exact JWKS URI is unchanged.
			JsonWebKeySource source = this.configuredKeySource;
			if (source == null && current != null && current.metadata.getJwksUri().toString().equals(metadata.getJwksUri().toString())) source = current.source;
			if (source == null) source = RemoteJsonWebKeySource.withUri(metadata.getJwksUri())
					.httpClient(this.httpClient).outboundUriPolicy(this.policy).clock(this.clock).observer(this.observer)
					.allowInsecureLoopback(this.allowInsecureLoopback).acknowledgeUnpatchedRuntime(this.acknowledgeUnpatchedRuntime)
					.requestTimeout(this.requestTimeout).build();
			ProviderState found = new ProviderState(metadata, source, new IdTokenValidator(metadata.getIssuer(), this.clientId, source,
					effectiveAlgorithms(metadata, this.algorithms), this.trustedAudiences, this.trustedAuthorizedParties,
					this.clockSkew, this.maximumIdTokenAge, this.clock, this.observer));
			this.state = found; return found;
		} finally { this.stateLock.unlock(); }
	}
	private static Set<JwsAlgorithm> effectiveAlgorithms(OidcProviderMetadata metadata, Set<JwsAlgorithm> configured) {
		Set<JwsAlgorithm> effective = new HashSet<>();
		for (JwsAlgorithm algorithm : configured)
			if (metadata.getIdTokenSigningAlgValuesSupported().contains(algorithm.getWireValue())) effective.add(algorithm);
		if (effective.isEmpty() || !metadata.getResponseTypesSupported().contains("code"))
			throw new IllegalArgumentException("The OIDC provider does not support this client's code-flow policy.");
		return Set.copyOf(effective);
	}
	private static void checkMetadata(OidcProviderMetadata metadata, Set<JwsAlgorithm> configured,
			OutboundUriPolicy policy, boolean loopback, @Nullable JwsAlgorithm userInfoAlgorithm) {
		effectiveAlgorithms(metadata, configured);
		if (userInfoAlgorithm != null) metadata.getUserInfoSigningAlgValuesSupported().ifPresent(supported -> {
			if (!supported.contains(userInfoAlgorithm.getWireValue())) throw new IllegalArgumentException("The configured UserInfo signing algorithm is not advertised.");
		});
		for (URI endpoint : List.of(metadata.getAuthorizationEndpoint(), metadata.getTokenEndpoint(), metadata.getJwksUri()))
			UriChecks.requirePermitted(endpoint, policy, loopback);
		metadata.getUserInfoEndpoint().ifPresent(uri -> UriChecks.requirePermitted(uri, policy, loopback));
		metadata.oauthMetadata().getRevocationEndpoint().ifPresent(uri -> UriChecks.requirePermitted(uri, policy, loopback));
	}
	@ThreadSafe
	private record ProviderState(OidcProviderMetadata metadata, JsonWebKeySource source, IdTokenValidator validator) { }
	/**
	 * Starts an OIDC client with lazy issuer-path discovery. Build performs no discovery or key lookup.
	 * @param issuer exact issuer identifier, without query or fragment
	 * @return the builder
	 * @since 1.0.0
	 */
	public static @NonNull Builder withIssuer(@NonNull String issuer) { return new Builder(issuer, null); }
	/**
	 * Starts an OIDC client with explicit provider metadata.
	 * @param metadata trusted application configuration
	 * @return the builder
	 * @since 1.0.0
	 */
	public static @NonNull Builder withProviderMetadata(@NonNull OidcProviderMetadata metadata) { return new Builder(requireNonNull(metadata).getIssuer(), metadata); }
	/**
	 * Fetches lazy provider metadata and remote signing keys now. Explicit metadata and static keys perform no I/O.
	 * Metadata and key lookup share the total deadline.
	 *
	 * @since 1.0.0
	 */
	public void warmUp() {
		Deadline deadline = Deadline.fromNow(this.totalDeadline);
		ProviderState provider = provider(deadline);
		if (provider.source instanceof RemoteJsonWebKeySource remote) com.revetsec.internal.jose.JwtValidationAccess.get().warmUp(remote, deadline::remainingNanos);
	}
	/**
	 * Starts authentication with the client defaults. This prepares the authorization URL.
	 *
	 * @return redirect and pending record
	 * @since 1.0.0
	 */
	public @NonNull AuthorizationRedirect beginAuthentication() { return beginAuthentication(OidcAuthenticationOptions.builder().build()); }
	/**
	 * Starts authentication with replacement options. Openid is emitted exactly once and nonce is generated internally.
	 * @param options per-login options
	 * @return redirect and pending record
	 * @since 1.0.0
	 */
	public @NonNull AuthorizationRedirect beginAuthentication(@NonNull OidcAuthenticationOptions options) {
		requireNonNull(options);
		return OidcTransactionAccess.get().begin(this.oauth, options.transactionOptions(this.scopes, this.resources),
				provider(Deadline.fromNow(this.totalDeadline)).metadata.oauthMetadata(), options.getMaxAge().orElse(null), options.getRequiredAcrValues().orElse(this.acrValues));
	}
	/**
	 * Completes authentication after the shared browser binding, state, flow kind, client, issuer, callback route and
	 * endpoint checks. A successful token POST does not release tokens until all ID-token checks pass. Never derive
	 * actualCallbackUri from request headers. Clear the pending browser cookie on every callback, including failure.
	 * @param response raw-parsed callback
	 * @param source browser-bound pending source
	 * @param actualCallbackUri exact receiving route URI from trusted application routing
	 * @return validated authentication and released tokens
	 * @since 1.0.0
	 */
	public @NonNull OidcAuthentication completeAuthentication(@NonNull AuthorizationResponse response,
			@NonNull PendingAuthorizationSource source, @NonNull URI actualCallbackUri) {
		Deadline deadline = Deadline.fromNow(this.totalDeadline);
		AtomicReference<ProviderState> selected = new AtomicReference<>();
		OidcTransactionAccess.Completion completion = OidcTransactionAccess.get().complete(this.oauth,
				response, source, actualCallbackUri, budget -> {
					ProviderState provider = provider(budget); selected.set(provider); return provider.metadata.oauthMetadata();
				}, deadline);
		ProviderState provider = requireNonNull(selected.get());
		IdToken token;
		try {
			String compact = completion.idToken();
			if (compact == null) throw OidcValidationException.fromReason(OidcValidationException.Reason.ID_TOKEN_MISSING);
			if (!completion.tokenType().equalsIgnoreCase("Bearer"))
				throw OidcValidationException.fromReason(OidcValidationException.Reason.TOKEN_TYPE_UNSUPPORTED);
			token = provider.validator.validate(compact, completion.nonce(), completion.accessToken(), completion.code(),
					completion.maxAge(), completion.acrValues(), deadline);
		} catch (OidcValidationException failure) {
			ObserverDispatch.dispatch(this.observer, observer -> observer.didRejectIdToken(failure));
			throw failure;
		}
		OidcAuthentication authentication = new OidcAuthentication(token, completion.releaseTokens(), this.clientId);
		ObserverDispatch.dispatch(this.observer, OidcObserver::didCompleteAuthentication);
		return authentication;
	}
	/**
	 * Fetches UserInfo for this client's validated authentication. The access token is sent only in a Bearer header
	 * to a permitted endpoint; issuer/client binding and safe token form are checked before discovery or UserInfo I/O.
	 * The returned subject must exactly match the ID token. JSON is the default; a configured signed response cannot
	 * be replaced by JSON. The call shares one deadline across discovery, UserInfo and signing-key lookup. Transient
	 * endpoint failures have bounded backoff; no request is automatically retried and no UserInfo result is cached.
	 * @param authentication previously validated authentication for this issuer and client
	 * @return checked UserInfo
	 * @since 1.0.0
	 */
	public @NonNull OidcUserInfo fetchUserInfo(@NonNull OidcAuthentication authentication) {
		requireNonNull(authentication); Deadline deadline = Deadline.fromNow(this.totalDeadline);
		OidcUserInfo result;
		try {
			if (!this.issuer.equals(authentication.getIssuer()) || !this.clientId.equals(authentication.clientId()))
				throw OidcValidationException.fromReason(OidcValidationException.Reason.USERINFO_AUTHENTICATION_MISMATCH);
			UserInfoEndpoint.authorization(authentication.getTokens().getAccessToken(), this.clock);
			ProviderState provider = provider(deadline);
			result = this.userInfo.fetch(provider.metadata, provider.source, authentication, this.clientId, this.userInfoAlgorithm,
					this.clockSkew, this.trustedAudiences, deadline);
		} catch (OidcValidationException failure) {
			ObserverDispatch.dispatch(this.observer, observer -> observer.didRejectUserInfo(failure)); throw failure;
		}
		ObserverDispatch.dispatch(this.observer, observer -> observer.didFetchUserInfo(result.isSigned()));
		return result;
	}
	/**
	 * Redacts client configuration.
	 *
	 * @return a redacted description
	 * @since 1.0.0
	 */
	@Override public @NonNull String toString() { return "OidcClient{configuration=<redacted>}"; }
	/**
	 * Mutable OIDC client configuration. Null restores an optional property's default.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	public static final class Builder {
		private final String issuer;
		private final @Nullable OidcProviderMetadata metadata;
		private @Nullable String clientId;
		private ClientAuthentication authentication = ClientAuthentication.noneInstance();
		private @Nullable URI redirectUri;
		private Set<String> scopes = Set.of();
		private List<URI> resources = List.of();
		private Set<String> acrValues = Set.of();
		private Set<String> trustedAudiences = Set.of();
		private Set<String> trustedAuthorizedParties = Set.of();
		private Set<JwsAlgorithm> algorithms = Set.of(JwsAlgorithm.RS256);
		private @Nullable JsonWebKeySource keySource;
		private @Nullable JwsAlgorithm userInfoAlgorithm;
		private Duration clockSkew = Duration.ofSeconds(60);
		private Duration maximumIdTokenAge = Duration.ofMinutes(5);
		private Duration pendingLifetime = Duration.ofMinutes(10);
		private Duration requestTimeout = Duration.ofSeconds(10);
		private Duration totalDeadline = Duration.ofSeconds(15);
		private Clock clock = Clock.systemUTC();
		private @Nullable HttpClient httpClient;
		private OutboundUriPolicy policy = OutboundUriPolicy.defaultInstance();
		private OidcObserver observer = OidcObserver.disabledInstance();
		private IssuerParameterPolicy issuerParameterPolicy = IssuerParameterPolicy.METADATA_DRIVEN;
		private boolean requirePkceAdvertised;
		private boolean allowInsecureLoopback;
		private boolean acknowledgeUnpatchedRuntime;
		private Duration minimumTimeToLive = Limits.DISCOVERY_MINIMUM_TIME_TO_LIVE.getDefaultDuration();
		private Duration defaultTimeToLive = Limits.DISCOVERY_DEFAULT_TIME_TO_LIVE.getDefaultDuration();
		private Duration maximumTimeToLive = Limits.DISCOVERY_MAXIMUM_TIME_TO_LIVE.getDefaultDuration();
		private Duration discoveryCooldown = Limits.DISCOVERY_COOLDOWN.getDefaultDuration();
		private Builder(String issuer, @Nullable OidcProviderMetadata metadata) { this.issuer = requireNonNull(issuer); this.metadata = metadata; }
		/**
		 * Sets the registered nonempty client identifier.
		 *
		 * @param value value, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder clientId(@Nullable String value) { this.clientId = value; return this; }
		/**
		 * Sets the token endpoint authentication; default public client.
		 *
		 * @param value value, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder clientAuthentication(@Nullable ClientAuthentication value) { this.authentication = value == null ? ClientAuthentication.noneInstance() : value; return this; }
		/**
		 * Sets the exact registered callback URI.
		 *
		 * @param value value, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder redirectUri(@Nullable URI value) { this.redirectUri = value; return this; }
		/**
		 * Sets the complete default scopes, in addition to openid.
		 *
		 * @param value value, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder scopes(@Nullable Set<@NonNull String> value) { this.scopes = value == null ? Set.of() : AuthorizationRequestOptions.builder().scopes(value).build().getScopes(); return this; }
		/**
		 * Sets the complete default resource indicators.
		 *
		 * @param value value, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder resources(@Nullable List<@NonNull URI> value) { this.resources = value == null ? List.of() : AuthorizationRequestOptions.builder().resources(value).build().getResources(); return this; }
		/**
		 * Sets the complete acceptable ACR defaults.
		 *
		 * @param value value, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder requiredAcrValues(@Nullable Set<@NonNull String> value) { this.acrValues = value == null ? Set.of() : OidcAuthenticationOptions.requireAcrValues(value); return this; }
		/**
		 * Sets the complete additional trusted audience set.
		 *
		 * @param value value, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder trustedAudiences(@Nullable Set<@NonNull String> value) { this.trustedAudiences = value == null ? Set.of() : Set.copyOf(value); return this; }
		/**
		 * Sets the complete additional trusted authorized-party set.
		 *
		 * @param value value, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder trustedAuthorizedParties(@Nullable Set<@NonNull String> value) { this.trustedAuthorizedParties = value == null ? Set.of() : Set.copyOf(value); return this; }
		/**
		 * Sets the complete ID-token algorithm allowlist; default RS256.
		 *
		 * @param value value, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder idTokenSigningAlgorithms(@Nullable Set<@NonNull JwsAlgorithm> value) { this.algorithms = value == null ? Set.of(JwsAlgorithm.RS256) : Set.copyOf(value); return this; }
		/**
		 * Sets the exact registered signed-UserInfo algorithm. Null restores JSON responses. This allowlist is separate
		 * from the ID-token allowlist; an advertised UserInfo capability set must include it. HMAC compatibility is not
		 * enabled. JSON cannot replace a configured signed response.
		 * @param value registered signing algorithm, or null for JSON
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder userInfoSignedResponseAlgorithm(@Nullable JwsAlgorithm value) { this.userInfoAlgorithm = value; return this; }
		/**
		 * Sets the advanced signing-key source; share only within the same issuer trust boundary.
		 *
		 * @param value value, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder jsonWebKeySource(@Nullable JsonWebKeySource value) { this.keySource = value; return this; }
		/**
		 * Sets the time skew, zero to five minutes.
		 *
		 * @param value value, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder clockSkew(@Nullable Duration value) { this.clockSkew = value == null ? Duration.ofSeconds(60) : Limits.JOSE_CLOCK_SKEW.require(value); return this; }
		/**
		 * Sets the maximum ID-token age plus skew.
		 *
		 * @param value value, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder maximumIdTokenAge(@Nullable Duration value) { this.maximumIdTokenAge = value == null ? Duration.ofMinutes(5) : Limits.ID_TOKEN_MAXIMUM_AGE.require(value); return this; }
		/**
		 * Sets the pending lifetime, one to sixty minutes.
		 *
		 * @param value value, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder pendingAuthorizationLifetime(@Nullable Duration value) { this.pendingLifetime = value == null ? Duration.ofMinutes(10) : Limits.PENDING_STATE_LIFETIME.require(value); return this; }
		/**
		 * Sets the per-exchange timeout.
		 *
		 * @param value value, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder requestTimeout(@Nullable Duration value) { this.requestTimeout = value == null ? Duration.ofSeconds(10) : Limits.REQUEST_TIMEOUT.require(value); return this; }
		/**
		 * Sets the deadline shared by discovery, code exchange and key lookup.
		 *
		 * @param value value, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder totalDeadline(@Nullable Duration value) { this.totalDeadline = value == null ? Duration.ofSeconds(15) : Limits.TOTAL_DEADLINE.require(value); return this; }
		/**
		 * Sets the clock for pending state, keys and claims.
		 *
		 * @param value value, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder clock(@Nullable Clock value) { this.clock = value == null ? Clock.systemUTC() : value; return this; }
		/**
		 * Sets the application-managed redirect-disabled HTTP client.
		 *
		 * @param value value, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder httpClient(@Nullable HttpClient value) { this.httpClient = value; return this; }
		/**
		 * Sets the outbound URI policy.
		 *
		 * @param value value, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder outboundUriPolicy(@Nullable OutboundUriPolicy value) { this.policy = value == null ? OutboundUriPolicy.defaultInstance() : value; return this; }
		/**
		 * Sets the caller-thread observer.
		 *
		 * @param value value, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder observer(@Nullable OidcObserver value) { this.observer = value == null ? OidcObserver.disabledInstance() : value; return this; }
		/**
		 * Sets the callback issuer policy.
		 *
		 * @param value value, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder issuerParameterPolicy(@Nullable IssuerParameterPolicy value) { this.issuerParameterPolicy = value == null ? IssuerParameterPolicy.METADATA_DRIVEN : value; return this; }
		/**
		 * Sets whether S256 advertisement is required.
		 *
		 * @param value the flag
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder requirePkceAdvertised(boolean value) { this.requirePkceAdvertised = value; return this; }
		/**
		 * Sets whether plain HTTP is allowed for literal loopback tests.
		 *
		 * @param value the flag
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder allowInsecureLoopback(boolean value) { this.allowInsecureLoopback = value; return this; }
		/**
		 * Sets explicit acknowledgment of runtime risk.
		 *
		 * @param value the flag
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder acknowledgeUnpatchedRuntime(boolean value) { this.acknowledgeUnpatchedRuntime = value; return this; }
		/**
		 * Sets the lowest discovery cache lifetime.
		 * @param value duration, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder minimumTimeToLive(@Nullable Duration value) { this.minimumTimeToLive = value == null ? Limits.DISCOVERY_MINIMUM_TIME_TO_LIVE.getDefaultDuration() : Limits.DISCOVERY_MINIMUM_TIME_TO_LIVE.require(value); return this; }
		/**
		 * Sets the fallback discovery cache lifetime.
		 * @param value duration, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder defaultTimeToLive(@Nullable Duration value) { this.defaultTimeToLive = value == null ? Limits.DISCOVERY_DEFAULT_TIME_TO_LIVE.getDefaultDuration() : Limits.DISCOVERY_DEFAULT_TIME_TO_LIVE.require(value); return this; }
		/**
		 * Sets the highest discovery cache lifetime.
		 * @param value duration, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder maximumTimeToLive(@Nullable Duration value) { this.maximumTimeToLive = value == null ? Limits.DISCOVERY_MAXIMUM_TIME_TO_LIVE.getDefaultDuration() : Limits.DISCOVERY_MAXIMUM_TIME_TO_LIVE.require(value); return this; }
		/**
		 * Sets the discovery attempt window and initial failure backoff.
		 * @param value duration, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder discoveryCooldown(@Nullable Duration value) { this.discoveryCooldown = value == null ? Limits.DISCOVERY_COOLDOWN.getDefaultDuration() : Limits.DISCOVERY_COOLDOWN.require(value); return this; }
		/**
		 * Validates issuer, explicit metadata and configuration without I/O or new threads.
		 * @return the client
		 * @since 1.0.0
		 */
		public @NonNull OidcClient build() {
			if (this.clientId == null || this.clientId.isEmpty() || this.redirectUri == null || this.algorithms.isEmpty()
					|| this.trustedAudiences.contains("") || this.trustedAuthorizedParties.contains(""))
				throw new IllegalArgumentException("An OIDC client requires a client ID, callback URI and algorithm allowlist.");
			for (JwsAlgorithm algorithm : this.algorithms)
				if (Set.of(JwsAlgorithm.HS256, JwsAlgorithm.HS384, JwsAlgorithm.HS512).contains(algorithm))
					throw new IllegalArgumentException("HMAC ID-token compatibility is not enabled.");
			if (this.userInfoAlgorithm != null && Set.of(JwsAlgorithm.HS256, JwsAlgorithm.HS384, JwsAlgorithm.HS512).contains(this.userInfoAlgorithm))
				throw new IllegalArgumentException("HMAC UserInfo compatibility is not enabled.");
			Limits.requireDiscoveryTimeToLiveOrder(this.minimumTimeToLive, this.defaultTimeToLive, this.maximumTimeToLive, this.discoveryCooldown);
			if (this.metadata != null) checkMetadata(this.metadata, this.algorithms, this.policy, this.allowInsecureLoopback, this.userInfoAlgorithm);
			OAuthClient.Builder engine = this.metadata == null ? OAuthClient.withIssuer(this.issuer)
					: OAuthClient.withAuthorizationServerMetadata(this.metadata.oauthMetadata());
			OAuthClient oauth = engine.clientId(this.clientId).clientAuthentication(this.authentication).redirectUri(this.redirectUri)
					.scopes(this.scopes).resources(this.resources).issuerParameterPolicy(this.issuerParameterPolicy)
					.requirePkceAdvertised(this.requirePkceAdvertised).pendingAuthorizationLifetime(this.pendingLifetime)
					.httpClient(this.httpClient).outboundUriPolicy(this.policy).requestTimeout(this.requestTimeout)
					.totalDeadline(this.totalDeadline).clock(this.clock).observer(this.observer)
					.allowInsecureLoopback(this.allowInsecureLoopback).acknowledgeUnpatchedRuntime(this.acknowledgeUnpatchedRuntime).build();
			return new OidcClient(this, oauth);
		}
	}
}
