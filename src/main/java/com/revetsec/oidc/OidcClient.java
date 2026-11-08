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

import com.google.errorprone.annotations.CheckReturnValue;

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
import java.time.Instant;
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
	private final OidcIssuerPolicy issuerPolicy;
	private final Object proofOwner = new Object();
	private final @Nullable JwsAlgorithm userInfoAlgorithm;
	private final UserInfoEndpoint userInfo;
	private final Set<String> scopes;
	private final List<URI> resources;
	private final Set<String> acrValues;
	private final @Nullable List<String> acrPreferences;
	private final Duration totalDeadline;
	private final @Nullable URI postLogoutRedirectUri;
	private final Duration logoutPendingLifetime;
	private final OidcObserver observer;
	private final @Nullable JwksSource configuredKeySource;
	private final String clientId;
	private final Set<JwsAlgorithm> algorithms;
	private final Set<JwsAlgorithm> hmacAlgorithms;
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

	private OidcClient(@NonNull Builder builder, @NonNull OAuthClient oauth) {
		this.issuerPolicy = builder.issuerPolicy; this.oauth = oauth; this.issuer = builder.issuer; this.userInfoAlgorithm = builder.userInfoAlgorithm; this.scopes = builder.scopes; this.resources = builder.resources;
		this.acrValues = builder.acrValues; this.acrPreferences = builder.acrPreferences; this.totalDeadline = builder.totalDeadline;
		this.postLogoutRedirectUri = builder.postLogoutRedirectUri; this.logoutPendingLifetime = builder.pendingLifetime; this.observer = builder.observer;
		this.configuredKeySource = builder.keySource; this.clientId = requireNonNull(builder.clientId);
		this.algorithms = builder.algorithms; this.hmacAlgorithms = hmacAlgorithms(this.algorithms); this.trustedAudiences = builder.trustedAudiences;
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
						try { this.issuerPolicy.checkMetadata(metadata); checkMetadata(metadata, this.algorithms, this.policy, this.allowInsecureLoopback, this.userInfoAlgorithm); return stateFor(metadata); }
						catch (IllegalArgumentException invalid) {
							throw OidcTransactionAccess.get().endpointFailure(OAuthException.Reason.METADATA_INVALID);
						}
					}, System::nanoTime, this.issuerPolicy);
		} else { this.cache = null; stateFor(builder.metadata); }
	}
	private @NonNull ProviderState provider(@NonNull Deadline deadline) {
		if (this.cache != null) return this.cache.get(deadline);
		this.stateLock.lock();
		try { return requireNonNull(this.state); } finally { this.stateLock.unlock(); }
	}
	private @NonNull ProviderState stateFor(@NonNull OidcProviderMetadata metadata) {
		this.stateLock.lock();
		try {
			ProviderState current = this.state;
			if (current != null && current.metadata == metadata) return current;
			// Keep one current source, sharing its cache only while the exact JWKS URI is unchanged.
			JwksSource source = this.configuredKeySource;
			if (source == null && current != null && current.metadata.getJwksUri().toString().equals(metadata.getJwksUri().toString())) source = current.source;
			if (source == null) source = RemoteJwksSource.withUri(metadata.getJwksUri())
					.httpClient(this.httpClient).outboundUriPolicy(this.policy).clock(this.clock).observer(this.observer)
					.allowInsecureLoopback(this.allowInsecureLoopback).acknowledgeUnpatchedRuntime(this.acknowledgeUnpatchedRuntime)
					.requestTimeout(this.requestTimeout).build();
			ProviderState found = new ProviderState(metadata, source, new IdTokenValidator(metadata.getIssuer(), this.clientId, source,
					effectiveAlgorithms(metadata, this.algorithms), this.trustedAudiences, this.trustedAuthorizedParties,
					this.clockSkew, this.maximumIdTokenAge, this.clock, this.observer, !this.hmacAlgorithms.isEmpty(), this.issuerPolicy));
			this.state = found; return found;
		} finally { this.stateLock.unlock(); }
	}
	private static @NonNull Set<@NonNull JwsAlgorithm> hmacAlgorithms(@NonNull Set<@NonNull JwsAlgorithm> algorithms) {
		Set<JwsAlgorithm> found = new HashSet<>();
		for (JwsAlgorithm algorithm : algorithms)
			if (Set.of(JwsAlgorithm.HS256, JwsAlgorithm.HS384, JwsAlgorithm.HS512).contains(algorithm)) found.add(algorithm);
		return Set.copyOf(found);
	}
	private static @NonNull Set<@NonNull JwsAlgorithm> effectiveAlgorithms(@NonNull OidcProviderMetadata metadata, @NonNull Set<@NonNull JwsAlgorithm> configured) {
		Set<JwsAlgorithm> effective = new HashSet<>();
		for (JwsAlgorithm algorithm : configured)
			if (metadata.getIdTokenSigningAlgValuesSupported().contains(algorithm.getWireValue())) effective.add(algorithm);
		if (effective.isEmpty() || !metadata.getResponseTypesSupported().contains("code"))
			throw new IllegalArgumentException("The OIDC provider does not support this client's code-flow policy.");
		return Set.copyOf(effective);
	}
	private static void checkMetadata(@NonNull OidcProviderMetadata metadata, @NonNull Set<@NonNull JwsAlgorithm> configured,
			@NonNull OutboundUriPolicy policy, boolean loopback, @Nullable JwsAlgorithm userInfoAlgorithm) {
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
	private record ProviderState(@NonNull OidcProviderMetadata metadata, @NonNull JwksSource source, @NonNull IdTokenValidator validator) { }
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
		if ((provider.validator.needsPublicKeys() || this.userInfoAlgorithm != null) && provider.source instanceof RemoteJwksSource remote) com.revetsec.internal.jose.JwtValidationAccess.get().warmUp(remote, deadline::remainingNanos);
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
		Set<String> required = options.getRequiredAcrValues().orElse(this.acrValues);
		List<String> preferred = options.getAcrPreferences().orElse(this.acrPreferences == null ? required.stream().sorted().toList() : this.acrPreferences);
		return OidcTransactionAccess.get().begin(this.oauth, options.transactionOptions(this.scopes, this.resources),
				provider(Deadline.fromNow(this.totalDeadline)).metadata.oauthMetadata(), options.getMaxAge().orElse(null), required, preferred);
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
	private @NonNull OidcAuthentication completeAuthenticationChecked(@NonNull AuthorizationResponse response,
			@NonNull PendingAuthorizationSource source, @NonNull URI actualCallbackUri) {
		Deadline deadline = Deadline.fromNow(this.totalDeadline);
		AtomicReference<ProviderState> selected = new AtomicReference<>();
		OidcTransactionAccess.Completion completion = OidcTransactionAccess.get().complete(this.oauth,
				response, source, actualCallbackUri, budget -> {
					ProviderState provider = provider(budget); selected.set(provider); return provider.metadata.oauthMetadata();
				}, deadline, this.hmacAlgorithms);
		ProviderState provider = requireNonNull(selected.get());
		IdToken token;
		try {
			String compact = completion.idToken();
			if (compact == null) throw OidcValidationException.fromReason(OidcValidationException.Reason.ID_TOKEN_MISSING);
			if (!completion.tokenType().equalsIgnoreCase("Bearer"))
				throw OidcValidationException.fromReason(OidcValidationException.Reason.TOKEN_TYPE_UNSUPPORTED);
			token = provider.validator.validate(compact, completion.nonce(), completion.accessToken(), completion.code(),
					completion.maxAge(), completion.acrValues(), deadline, completion.clientSecret());
		} catch (OidcValidationException failure) {
			ObserverDispatch.dispatch(this.observer, observer -> observer.didRejectIdToken(failure));
			throw failure;
		}
		OidcAuthentication authentication = new OidcAuthentication(token, completion.releaseTokens(), this.clientId, this.proofOwner, completion.acrValues());
		ObserverDispatch.dispatch(this.observer, OidcObserver::didCompleteAuthentication);
		return authentication;
	}

	/**
	 * Completes authentication once, returning authenticated identity, checked authorization errors, rejected callback
	 * binding, rejected endpoint credentials, or a rejected ID token. Rejected outcomes release no identity, claims or endpoint credentials.
	 * Pending-store failures return a fixed failure result. Metadata, transport, malformed responses, transient
	 * endpoint failures and invalid HMAC-secret failures remain exceptions. Clear the pending
	 * cookie on every outcome; the original completion's atomic-consumption and observer behavior is preserved.
	 * @param response parsed callback
	 * @param source browser-bound pending source
	 * @param actualCallbackUri receiving route URI from trusted routing configuration
	 * @return the authentication outcome
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public @NonNull OidcAuthenticationResult completeAuthenticationResult(@NonNull AuthorizationResponse response,
			@NonNull PendingAuthorizationSource source, @NonNull URI actualCallbackUri) {
		try {
			return OidcAuthenticationResult.fromAuthentication(completeAuthenticationChecked(response, source, actualCallbackUri));
		} catch (AuthorizationErrorException failure) {
			OAuthEndpointError error = OAuthEndpointError.fromWireValue(failure.getErrorCode().orElse(""));
			return error == OAuthEndpointError.ACCESS_DENIED ? OidcAuthenticationResult.fromDenial()
					: OidcAuthenticationResult.fromAuthorizationError(error);
		} catch (OAuthErrorResponseException failure) {
			if (!isEndpointRejection(failure)) throw failure;
			return OidcAuthenticationResult.fromEndpoint(failure);
		} catch (OAuthValidationException rejection) {
			if (!isLocalCallbackRejection(rejection.getReason())) throw rejection;
			return OidcAuthenticationResult.fromAuthorizationReason(rejection.getReason());
		} catch (com.revetsec.oauth.PendingAuthorizationStoreException failure) {
			return OidcAuthenticationResult.fromStoreFailure(failure.getReason());
		} catch (OidcValidationException rejection) {
			if (rejection.getReason() == OidcValidationException.Reason.HMAC_SECRET_INVALID) throw rejection;
			return OidcAuthenticationResult.fromIdTokenReason(rejection.getReason(), rejection.getJoseReason().orElse(null));
		}
	}

	private static boolean isLocalCallbackRejection(OAuthException.@NonNull Reason reason) {
		return switch (reason) {
			case STATE_MISMATCH, BROWSER_BINDING_MISMATCH, PENDING_AUTHORIZATION_INVALID,
				PENDING_AUTHORIZATION_EXPIRED, PENDING_AUTHORIZATION_NOT_FOUND, CLIENT_MISMATCH,
				ISSUER_MISMATCH, ISSUER_MISSING, CALLBACK_URI_MISMATCH, RESPONSE_MODE_MISMATCH -> true;
			default -> false;
		};
	}

	/**
	 * Fetches UserInfo and returns checked data or a fixed local or endpoint rejection. Issuer/client binding,
	 * subject, format and token lifetime checks precede release of any UserInfo. Transport, metadata, transient
	 * endpoint failures and invalid HMAC configuration remain exceptions. No request is automatically retried.
	 * @param authentication previously validated authentication for this issuer and client
	 * @return the UserInfo outcome
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public @NonNull OidcUserInfoResult fetchUserInfoResult(@NonNull OidcAuthentication authentication) {
		try {
			return OidcUserInfoResult.fromUserInfo(fetchUserInfoChecked(authentication));
		} catch (OidcValidationException failure) {
			if (failure.getReason() == OidcValidationException.Reason.HMAC_SECRET_INVALID) throw failure;
			return OidcUserInfoResult.fromRejection(failure);
		} catch (OAuthErrorResponseException failure) {
			if (!isEndpointRejection(failure)) throw failure;
			return OidcUserInfoResult.fromEndpoint(failure);
		}
	}

	/**
	 * Fetches UserInfo using a checked refresh result and the original authenticated identity. The original
	 * session must match before I/O. Rejection releases no UserInfo; infrastructure failures remain exceptions.
	 * @param authentication original validated authentication
	 * @param refreshed checked refresh result for that original session
	 * @return the UserInfo outcome
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public @NonNull OidcUserInfoResult fetchUserInfoResult(@NonNull OidcAuthentication authentication,
			@NonNull OidcRefreshResult refreshed) {
		try {
			return OidcUserInfoResult.fromUserInfo(fetchUserInfoChecked(authentication, refreshed));
		} catch (OidcValidationException failure) {
			if (failure.getReason() == OidcValidationException.Reason.HMAC_SECRET_INVALID) throw failure;
			return OidcUserInfoResult.fromRejection(failure);
		} catch (OAuthErrorResponseException failure) {
			if (!isEndpointRejection(failure)) throw failure;
			return OidcUserInfoResult.fromEndpoint(failure);
		}
	}

	/**
	 * Sends one refresh POST with default options and returns checked tokens or a fixed rejection. Persist the
	 * original session reference in trusted storage and serialize refreshes to avoid token-rotation races.
	 * Infrastructure failures and invalid HMAC configuration remain exceptions; no request is retried.
	 * @param refreshToken current refresh credential
	 * @param original original session comparison reference, not proof of identity
	 * @return the refresh outcome
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public @NonNull OidcRefreshOutcome refreshResult(@NonNull RefreshToken refreshToken,
			@NonNull OidcSessionReference original) {
		return refreshResult(refreshToken, original, TokenRequestOptions.builder().build());
	}

	/**
	 * Sends one refresh POST with scope/resource options and returns checked tokens or a fixed rejection.
	 * The caller restricts scopes to the original grant. Any returned ID token must pass original-session
	 * continuity checks before tokens are released. Infrastructure failures and invalid HMAC configuration
	 * remain exceptions; no request is automatically retried.
	 * @param refreshToken current refresh credential
	 * @param original original session comparison reference
	 * @param options per-request scope and resources
	 * @return the refresh outcome
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public @NonNull OidcRefreshOutcome refreshResult(@NonNull RefreshToken refreshToken,
			@NonNull OidcSessionReference original, @NonNull TokenRequestOptions options) {
		try {
			return OidcRefreshOutcome.fromRefreshResult(refreshChecked(refreshToken, original, options));
		} catch (OidcValidationException failure) {
			if (failure.getReason() == OidcValidationException.Reason.HMAC_SECRET_INVALID) throw failure;
			return OidcRefreshOutcome.fromRejection(failure);
		} catch (OAuthErrorResponseException failure) {
			if (!isEndpointRejection(failure)) throw failure;
			return OidcRefreshOutcome.fromEndpoint(failure);
		}
	}

	private static boolean isEndpointRejection(@NonNull OAuthErrorResponseException failure) {
		return OidcTransactionAccess.get().isEndpointRejection(failure);
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
	private @NonNull OidcUserInfo fetchUserInfoChecked(@NonNull OidcAuthentication authentication) {
		requireNonNull(authentication); Deadline deadline = Deadline.fromNow(this.totalDeadline);
		OidcUserInfo result;
		try {
			if (!this.clientId.equals(authentication.clientId()) || (this.issuerPolicy.isMicrosoftEntra()
					? !authentication.belongsTo(this.proofOwner) || OidcIssuerPolicy.tenantFromIssuer(authentication.getIssuer()) == null
					: !this.issuer.equals(authentication.getIssuer())))
				throw OidcValidationException.fromReason(OidcValidationException.Reason.USERINFO_AUTHENTICATION_MISMATCH);
			if (this.issuerPolicy.isMicrosoftEntra()) {
				ObserverDispatch.dispatch(this.observer, OidcObserver::didUseMicrosoftEntraMultiTenant);
				Instant before = OidcIssuerPolicy.readClock(this.clock);
				this.issuerPolicy.checkTenant(requireNonNull(OidcIssuerPolicy.tenantFromIssuer(authentication.getIssuer())), deadline);
				if (OidcIssuerPolicy.readClock(this.clock).isBefore(before)) throw OidcTransactionAccess.get().endpointFailure(OAuthException.Reason.ISSUER_POLICY_UNAVAILABLE);
			}
			UserInfoEndpoint.authorization(authentication.getTokens().getAccessToken(), this.clock);
			ProviderState provider = provider(deadline);
			result = this.userInfo.fetch(provider.metadata, provider.source, authentication, this.clientId, this.userInfoAlgorithm,
					this.clockSkew, this.trustedAudiences, deadline, this.issuerPolicy);
		} catch (OidcValidationException failure) {
			ObserverDispatch.dispatch(this.observer, observer -> observer.didRejectUserInfo(failure)); throw failure;
		}
		ObserverDispatch.dispatch(this.observer, observer -> observer.didFetchUserInfo(result.isSigned()));
		return result;
	}
	/**
	 * Fetches UserInfo using a checked refresh result's access token and the original authenticated identity.
	 * The result must retain the same original session reference. A parsed session reference alone cannot supply
	 * identity. All ordinary UserInfo issuer/client, subject, format, lifetime and network checks still apply.
	 * @param authentication original validated authentication
	 * @param refreshed checked refresh result for that original session
	 * @return checked UserInfo
	 * @since 1.0.0
	 */
	private @NonNull OidcUserInfo fetchUserInfoChecked(@NonNull OidcAuthentication authentication, @NonNull OidcRefreshResult refreshed) {
		requireNonNull(authentication); requireNonNull(refreshed);
		if (!authentication.getSessionReference().matchesOriginalReference(refreshed.getSessionReference())) {
			OidcValidationException failure = OidcValidationException.fromReason(OidcValidationException.Reason.USERINFO_AUTHENTICATION_MISMATCH);
			ObserverDispatch.dispatch(this.observer, observer -> observer.didRejectUserInfo(failure)); throw failure;
		}
		return fetchUserInfoChecked(authentication.withTokens(refreshed.getTokens()));
	}
	/**
	 * Sends one refresh POST with scope/resource options. No scope option means no scope field is sent; the caller
	 * restricts scope requests to the original grant. A returned ID token must preserve original issuer, subject,
	 * audience and authorized party. Present auth_time and nonce must match the original. Issued-at cannot precede
	 * the original token; refresh does not apply the login token-age or authentication-age window. A present code
	 * hash cannot be verified during refresh and is rejected. The original flow's saved ACR acceptance set applies to every returned ID token, separately from this client's login defaults. Tokens remain private until validation completes.
	 * @param refreshToken current refresh credential
	 * @param original original session comparison reference
	 * @param options per-request options
	 * @return tokens, retained/replacement refresh credential and optional verified ID token
	 * @since 1.0.0
	 */
	private @NonNull OidcRefreshResult refreshChecked(@NonNull RefreshToken refreshToken, @NonNull OidcSessionReference original,
			@NonNull TokenRequestOptions options) {
		requireNonNull(refreshToken); requireNonNull(original); requireNonNull(options);
		Deadline deadline = Deadline.fromNow(this.totalDeadline);
		@Nullable IdToken verified;
		OidcTransactionAccess.RefreshCompletion completion;
		try {
			if (this.issuerPolicy.isMicrosoftEntra()) original.checkMicrosoftEntraClient(this.clientId);
			else original.checkClient(this.issuer, this.clientId);
			ProviderState provider = provider(deadline);
			completion = OidcTransactionAccess.get().refresh(this.oauth, refreshToken, options, provider.metadata.oauthMetadata(), deadline, this.hmacAlgorithms);
			if (!completion.tokenType().equalsIgnoreCase("Bearer")) throw OidcValidationException.fromReason(OidcValidationException.Reason.TOKEN_TYPE_UNSUPPORTED);
			String compact = completion.idToken();
			if (completion.idTokenPresent() && compact == null) throw OidcValidationException.fromReason(OidcValidationException.Reason.ID_TOKEN_MALFORMED);
			verified = compact == null ? null : provider.validator.validateRefresh(compact, original, completion.accessToken(), original.getRequiredAcrValues(), deadline, completion.clientSecret());
		} catch (OidcValidationException failure) {
			ObserverDispatch.dispatch(this.observer, observer -> observer.didRejectRefresh(failure)); throw failure;
		}
		TokenResponse tokens = completion.releaseTokens();
		OidcRefreshResult result = new OidcRefreshResult(tokens, verified, refreshToken, original, this.proofOwner);
		ObserverDispatch.dispatch(this.observer, observer -> observer.didRefreshTokens(result.getIdToken().isPresent(), tokens.getRefreshToken().isPresent()));
		return result;
	}


	/**
	 * Explicitly retains this exact client's validated ID token as a logout hint. This does not extend identity
	 * lifetime or change the comparison-only original reference. A token may later be used after authentication expiry.
	 * @param authentication genuine completed authentication produced by this exact client instance
	 * @return credential-bearing logout companion for trusted storage
	 * @throws NullPointerException if authentication is null
	 * @throws OidcLogoutException if ownership, profile, current issuer policy, interruption or the budget fails
	 * @since 1.0.0
	 */
	public @NonNull OidcLogoutHint logoutHintFrom(@NonNull OidcAuthentication authentication) {
		requireNonNull(authentication); Deadline deadline = Deadline.fromNow(this.totalDeadline); OidcLogoutSupport.active(deadline);
		if (!authentication.belongsTo(this.proofOwner)) throw OidcLogoutSupport.failure(OidcLogoutException.Reason.HINT_MISMATCH);
		checkLogoutReference(authentication.getSessionReference(), deadline);
		OidcLogoutHint hint = checkedLogoutHint(authentication.getSessionReference(), authentication.getIdToken().toCompactSerialization(), deadline);
		OidcLogoutSupport.active(deadline); return hint;
	}

	/**
	 * Explicitly retains a newly validated ID token from this exact client's refresh. Omitted ID tokens yield empty;
	 * the original session reference is always retained and no new authenticated identity is created.
	 * @param refreshed genuine refresh result produced by this exact client instance
	 * @return optional replacement credential, never a replacement original reference
	 * @throws NullPointerException if refreshed is null
	 * @throws OidcLogoutException if ownership, profile, current issuer policy, interruption or the budget fails
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull OidcLogoutHint> logoutHintFrom(@NonNull OidcRefreshResult refreshed) {
		requireNonNull(refreshed); Deadline deadline = Deadline.fromNow(this.totalDeadline); OidcLogoutSupport.active(deadline);
		if (!refreshed.belongsTo(this.proofOwner)) throw OidcLogoutSupport.failure(OidcLogoutException.Reason.HINT_MISMATCH);
		checkLogoutReference(refreshed.getSessionReference(), deadline);
		Optional<OidcLogoutHint> hint = refreshed.getIdToken().map(token -> checkedLogoutHint(refreshed.getSessionReference(), token.toCompactSerialization(), deadline));
		OidcLogoutSupport.active(deadline); return hint;
	}


	/**
	 * Prepares a browser GET/form POST request after the application has authorized its local POST/CSRF request and
	 * terminated its own session. Failures never undo local termination. No end-session server request or automatic
	 * retry is sent. The original reference and retained hint must match before discovery, entropy or output.
	 * @param original original continuity reference for this session, not identity proof
	 * @param hint explicitly retained logout credential bound to that reference
	 * @return credential-bearing browser request and independent pending correlation state
	 * @throws NullPointerException if a required argument is null
	 * @throws OidcLogoutException if configuration, binding, discovery, URI policy, time, entropy or the budget fails
	 * @since 1.0.0
	 */
	public @NonNull OidcLogoutRequest beginLogout(@NonNull OidcSessionReference original, @NonNull OidcLogoutHint hint) {
		requireNonNull(original); requireNonNull(hint); Deadline deadline = Deadline.fromNow(this.totalDeadline); OidcLogoutSupport.active(deadline);
		URI callback = requireLogoutConfiguration();
		if (!original.matchesOriginalReference(hint.reference())) throw OidcLogoutSupport.failure(OidcLogoutException.Reason.HINT_MISMATCH);
		java.time.Instant before = logoutClock(deadline); checkLogoutReference(original, deadline);
		ProviderState provider;
		try { provider = logoutProvider(deadline); OidcLogoutSupport.active(deadline); }
		catch (OidcLogoutException failure) { throw failure; }
		catch (com.revetsec.oauth.OAuthException failure) {
			OidcLogoutSupport.active(deadline); throw OidcLogoutSupport.failure(failure.isTemporaryCondition() ? OidcLogoutException.Reason.DISCOVERY_UNAVAILABLE : OidcLogoutException.Reason.PROVIDER_UNAVAILABLE);
		} catch (VirtualMachineError fatal) { throw fatal; }
		catch (Throwable failure) { if (failure instanceof InterruptedException) Thread.currentThread().interrupt(); OidcLogoutSupport.active(deadline); throw OidcLogoutSupport.failure(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE); }
		URI endpoint = provider.metadata.getEndSessionEndpoint().orElseThrow(() -> OidcLogoutSupport.failure(OidcLogoutException.Reason.END_SESSION_UNSUPPORTED));
		try {
			OidcLogoutSupport.active(deadline); OidcLogoutSupport.endpoint(endpoint); UriChecks.requirePermitted(endpoint, this.policy, this.allowInsecureLoopback); OidcLogoutSupport.active(deadline);
		} catch (OidcLogoutException failure) { throw failure; }
		catch (VirtualMachineError fatal) { throw fatal; }
		catch (Throwable invalid) { if (invalid instanceof InterruptedException) Thread.currentThread().interrupt(); OidcLogoutSupport.active(deadline); throw OidcLogoutSupport.failure(OidcLogoutException.Reason.ENDPOINT_NOT_PERMITTED); }
		java.time.Instant created = logoutClock(deadline);
		if (created.isBefore(before)) throw OidcLogoutSupport.failure(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE);
		byte @Nullable [] random = null;
		try {
			java.time.Instant expires = created.plus(this.logoutPendingLifetime);
			OidcLogoutSupport.active(deadline); com.revetsec.internal.crypto.EntropySource entropy = com.revetsec.internal.crypto.EntropySource.fromDefaults(); OidcLogoutSupport.active(deadline);
			random = entropy.nextBytes(32); OidcLogoutSupport.active(deadline); String state = com.revetsec.internal.encoding.Base64Url.encode(random);
			PendingOidcLogout pending = new PendingOidcLogout(this.issuer, this.clientId, callback, state, created, expires); OidcLogoutPendingCodec.encode(pending, null);
			OidcLogoutRequest request = new OidcLogoutRequest(endpoint, this.clientId, callback, hint.compact(), state, pending);
			java.time.Instant completed = logoutClock(deadline);
			if (completed.isBefore(created) || !completed.isBefore(expires)) throw OidcLogoutSupport.failure(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE);
			OidcLogoutSupport.active(deadline); return request;
		} catch (OidcLogoutException failure) { OidcLogoutSupport.active(deadline); throw failure; }
		catch (VirtualMachineError fatal) { throw fatal; }
		catch (Throwable unavailable) { if (unavailable instanceof InterruptedException) Thread.currentThread().interrupt(); OidcLogoutSupport.active(deadline); throw OidcLogoutSupport.failure(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE); }
		finally { OidcLogoutSupport.clear(random); }
	}

	/**
	 * Correlates a state-only browser return without discovery, JWKS, token POST, ID-token signature verification,
	 * retry or session creation. The actual callback comes from trusted routing configuration, never headers. Clear
	 * a pending cookie on every callback, including rejection/exception paths. Returned proves correlation only.
	 * @param rawQuery raw query without the leading question mark, at most4096characters
	 * @param source this browser's typed pending source
	 * @param actualCallbackUri trusted actual callback route
	 * @return correlation-only Returned or a fixed value-free rejection
	 * @throws NullPointerException if a required argument is null
	 * @throws OidcLogoutException if configuration, budget, interruption, provider or store uncertainty prevents completion
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public @NonNull OidcLogoutResult completeLogoutResult(@NonNull String rawQuery, @NonNull PendingOidcLogoutSource source, @NonNull URI actualCallbackUri) {
		requireNonNull(rawQuery); requireNonNull(source); requireNonNull(actualCallbackUri); Deadline deadline = Deadline.fromNow(this.totalDeadline); OidcLogoutSupport.active(deadline);
		URI callback = requireLogoutConfiguration();
		if (!callback.toString().equals(actualCallbackUri.toString())) return OidcLogoutResult.rejected(OidcLogoutResult.Reason.CALLBACK_MISMATCH);
		String state;
		try { state = OidcLogoutSupport.returnedState(rawQuery); }
		catch (IllegalArgumentException malformed) { return OidcLogoutResult.rejected(OidcLogoutResult.Reason.MALFORMED_RETURN); }
		return source.complete(state, this.issuer, this.clientId, callback, this.clock, deadline);
	}

	private @NonNull URI requireLogoutConfiguration() {
		if (this.postLogoutRedirectUri == null) throw OidcLogoutSupport.failure(OidcLogoutException.Reason.LOGOUT_NOT_CONFIGURED);
		return this.postLogoutRedirectUri;
	}
	private @NonNull ProviderState logoutProvider(@NonNull Deadline deadline) {
		OidcLogoutSupport.active(deadline);
		if (this.cache != null) return this.cache.get(deadline);
		boolean locked = false;
		try {
			locked = this.stateLock.tryLock(OidcLogoutSupport.remaining(deadline).toNanos(), java.util.concurrent.TimeUnit.NANOSECONDS);
			if (!locked) throw OidcLogoutSupport.failure(OidcLogoutException.Reason.BUDGET_EXHAUSTED);
			OidcLogoutSupport.active(deadline); return requireNonNull(this.state);
		} catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw OidcLogoutSupport.failure(OidcLogoutException.Reason.INTERRUPTED); }
		finally { if (locked) this.stateLock.unlock(); }
	}
	private @NonNull Instant logoutClock(@NonNull Deadline deadline) {
		OidcLogoutSupport.active(deadline);
		try { java.time.Instant now = requireNonNull(this.clock.instant()); OidcLogoutSupport.active(deadline); return now; }
		catch (OidcLogoutException failure) { throw failure; }
		catch (VirtualMachineError fatal) { throw fatal; }
		catch (RuntimeException | Error unavailable) { OidcLogoutSupport.active(deadline); throw OidcLogoutSupport.failure(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE); }
	}

	private @NonNull OidcLogoutHint checkedLogoutHint(@NonNull OidcSessionReference reference, @NonNull String compact, @NonNull Deadline deadline) {
		try { OidcLogoutHint hint = new OidcLogoutHint(reference, compact); OidcLogoutSupport.active(deadline); return hint; }
		catch (OidcLogoutException failure) { OidcLogoutSupport.active(deadline); throw failure; }
		catch (VirtualMachineError fatal) { throw fatal; }
		catch (RuntimeException | Error unavailable) { OidcLogoutSupport.active(deadline); throw OidcLogoutSupport.failure(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE); }
	}

	private void checkLogoutReference(@NonNull OidcSessionReference original, @NonNull Deadline deadline) {
		OidcLogoutSupport.active(deadline);
		try {
			OidcLogoutSupport.client(this.clientId); OidcLogoutSupport.text(this.issuer, OidcLogoutSupport.FIELD_LIMIT);
			if (this.issuerPolicy.isMicrosoftEntra()) {
				original.checkMicrosoftEntraClient(this.clientId);
				String actualIssuer = ((com.revetsec.json.JsonString) requireNonNull(original.continuityClaims().getMembers().get("iss"))).getValue();
				OidcLogoutSupport.text(actualIssuer, OidcLogoutSupport.FIELD_LIMIT);
				this.issuerPolicy.checkTenant(requireNonNull(OidcIssuerPolicy.tenantFromIssuer(actualIssuer)), deadline);
			} else original.checkClient(this.issuer, this.clientId);
		} catch (OidcValidationException | IllegalArgumentException invalid) {
			OidcLogoutSupport.active(deadline); throw OidcLogoutSupport.failure(OidcLogoutException.Reason.HINT_MISMATCH);
		} catch (RuntimeException unavailable) {
			OidcLogoutSupport.active(deadline); throw OidcLogoutSupport.failure(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE);
		}
		OidcLogoutSupport.active(deadline);
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
	@CheckReturnValue
	public static final class Builder {
		private final String issuer;
		private final @Nullable OidcProviderMetadata metadata;
		private @Nullable String clientId;
		private ClientAuthentication authentication = ClientAuthentication.noneInstance();
		private @Nullable URI redirectUri;
		private @Nullable URI postLogoutRedirectUri;
		private Set<String> scopes = Set.of();
		private List<URI> resources = List.of();
		private Set<String> acrValues = Set.of();
		private @Nullable List<String> acrPreferences;
		private Set<String> trustedAudiences = Set.of();
		private Set<String> trustedAuthorizedParties = Set.of();
		private Set<JwsAlgorithm> algorithms = Set.of(JwsAlgorithm.RS256);
		private Set<OidcCompatibilityMode> compatibility = Set.of();
		private @Nullable JwksSource keySource;
		private @Nullable JwsAlgorithm userInfoAlgorithm;
		private Duration clockSkew = Duration.ofSeconds(60);
		private Duration maximumIdTokenAge = Duration.ofMinutes(5);
		private Duration pendingLifetime = Limits.PENDING_STATE_LIFETIME.getDefaultDuration();
		private Duration requestTimeout = Duration.ofSeconds(10);
		private Duration totalDeadline = Duration.ofSeconds(15);
		private Clock clock = Clock.systemUTC();
		private @Nullable HttpClient httpClient;
		private OutboundUriPolicy policy = OutboundUriPolicy.defaultInstance();
		private OidcObserver observer = OidcObserver.disabledInstance();
		private OidcIssuerPolicy issuerPolicy = OidcIssuerPolicy.exactInstance();
		private IssuerParameterPolicy issuerParameterPolicy = IssuerParameterPolicy.METADATA_DRIVEN;
		private boolean requirePkceAdvertised;
		private boolean allowInsecureLoopback;
		private boolean acknowledgeUnpatchedRuntime;
		private Duration minimumTimeToLive = Limits.DISCOVERY_MINIMUM_TIME_TO_LIVE.getDefaultDuration();
		private Duration defaultTimeToLive = Limits.DISCOVERY_DEFAULT_TIME_TO_LIVE.getDefaultDuration();
		private Duration maximumTimeToLive = Limits.DISCOVERY_MAXIMUM_TIME_TO_LIVE.getDefaultDuration();
		private Duration discoveryCooldown = Limits.DISCOVERY_COOLDOWN.getDefaultDuration();
		private Builder(@NonNull String issuer, @Nullable OidcProviderMetadata metadata) { this.issuer = requireNonNull(issuer); this.metadata = metadata; }
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
		 * Sets one fixed registered logout callback, independent of the login callback. It must be HTTPS (or explicit
		 * test loopback), at most 2048 UTF8 bytes, without query, fragment or userinfo. Null disables logout.
		 * @param value fixed callback, or null for absent
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder postLogoutRedirectUri(@Nullable URI value) { this.postLogoutRedirectUri = value; return this; }

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
		 * Sets ordered acr_values request preferences, independent of local acceptance. Null derives a deterministic
		 * lexical request list from the effective acceptance set; an empty list omits the request parameter.
		 * @param value distinct nonempty visible-ASCII preferences, or null
		 * @return this builder
		 * @throws IllegalArgumentException if a value is malformed or duplicated
		 * @since 1.0.0
		 */
		public @NonNull Builder acrPreferences(@Nullable List<@NonNull String> value) { this.acrPreferences = value == null ? null : OidcAuthenticationOptions.requireAcrPreferences(value); return this; }

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
		 * Sets the complete per-client compatibility-mode set. Null restores no modes. Enabling HMAC does not change
		 * the default RS256 allowlist; explicitly name HS algorithms and configure confidential client authentication.
		 * Secret suppliers are checked once at build and once per credentialed token POST, before I/O. The exact
		 * secret used for that POST verifies its ID token; a later rotation cannot change the call's key.
		 * @param value modes, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder compatibility(@Nullable Set<@NonNull OidcCompatibilityMode> value) {
			this.compatibility = value == null ? Set.of() : Set.copyOf(value); return this;
		}
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
		 * Sets the advanced signing-key source; share only within the same exact issuer trust boundary,
		 * or with the same Entra issuer-policy instance. Distinct tenant callbacks are not equivalent.
		 *
		 * @param value value, or null to restore the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder jwksSource(@Nullable JwksSource value) { this.keySource = value; return this; }
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
		public @NonNull Builder pendingAuthorizationLifetime(@Nullable Duration value) { this.pendingLifetime = value == null ? Limits.PENDING_STATE_LIFETIME.getDefaultDuration() : Limits.PENDING_STATE_LIFETIME.require(value); return this; }
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
		 * Sets the application-managed HTTP client. It must use {@code HttpClient.Redirect.NEVER} and have no
		 * {@code Authenticator} or {@code CookieHandler}; build rejects noncompliance without a network request.
		 * Null restores the lazy default. The application owns TLS, proxy and egress controls beyond URI text policy.
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
		 * Selects exact validation or the fixed Entra common/organizations policy. Null restores exact validation.
		 * Build performs no tenant callback, key lookup or network request. HMAC ID tokens are incompatible.
		 * @param value selected issuer policy, or null to restore exact
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder issuerPolicy(@Nullable OidcIssuerPolicy value) { this.issuerPolicy = value == null ? OidcIssuerPolicy.exactInstance() : value; return this; }
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
		 * @param value the flag, or null to restore false
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder requirePkceAdvertised(@Nullable Boolean value) { this.requirePkceAdvertised = Boolean.TRUE.equals(value); return this; }
		/**
		 * Sets whether plain HTTP is allowed for literal loopback tests.
		 *
		 * @param value the flag, or null to restore false
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder allowInsecureLoopback(@Nullable Boolean value) { this.allowInsecureLoopback = Boolean.TRUE.equals(value); return this; }
		/**
		 * Sets explicit acknowledgment of runtime risk.
		 *
		 * @param value the flag, or null to restore false
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder acknowledgeUnpatchedRuntime(@Nullable Boolean value) { this.acknowledgeUnpatchedRuntime = Boolean.TRUE.equals(value); return this; }
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
			if (this.clientId == null || this.redirectUri == null)
				throw new IllegalStateException("An OIDC client requires a client ID and callback URI.");
			if (this.clientId.isEmpty() || this.algorithms.isEmpty()
					|| this.trustedAudiences.contains("") || this.trustedAuthorizedParties.contains(""))
				throw new IllegalArgumentException("An OIDC client requires a client ID, callback URI and algorithm allowlist.");
			if (this.postLogoutRedirectUri != null) {
				OidcLogoutSupport.callback(this.postLogoutRedirectUri, this.allowInsecureLoopback);
				OidcLogoutSupport.client(this.clientId); OidcLogoutSupport.text(this.issuer, OidcLogoutSupport.FIELD_LIMIT);
			}
			this.issuerPolicy.checkConfiguredIssuer(this.issuer);
			if (this.metadata != null) this.issuerPolicy.checkMetadata(this.metadata);
			Set<JwsAlgorithm> hmac = hmacAlgorithms(this.algorithms);
			if (this.issuerPolicy.isMicrosoftEntra() && !hmac.isEmpty()) throw new IllegalArgumentException("Entra issuer policy requires asymmetric ID tokens.");
			if (!hmac.isEmpty() && !this.compatibility.contains(OidcCompatibilityMode.HMAC_ID_TOKENS))
				throw new IllegalArgumentException("HMAC ID-token compatibility is not enabled.");
			OidcTransactionAccess.get().checkHmacAuthentication(this.authentication, hmac);
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
			OidcClient client = new OidcClient(this, oauth);
			if (this.issuerPolicy.isMicrosoftEntra()) ObserverDispatch.dispatch(this.observer, OidcObserver::didEnableMicrosoftEntraMultiTenant);
			for (OidcCompatibilityMode mode : this.compatibility)
				ObserverDispatch.dispatch(this.observer, observer -> observer.didEnableCompatibilityMode(mode));
			return client;
		}
	}
}
