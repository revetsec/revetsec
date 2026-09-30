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

import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.HostClassifier;
import com.revetsec.internal.Limits;
import com.revetsec.internal.ObserverDispatch;
import com.revetsec.internal.oauth.OidcTransactionAccess;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.http.HttpExchange;
import com.revetsec.internal.http.HttpExchangeException;
import com.revetsec.internal.http.HttpExchangeRequest;
import com.revetsec.internal.http.RawResponse;
import com.revetsec.internal.http.ResponseProfile;
import com.revetsec.internal.http.RuntimeFloor;
import com.revetsec.internal.http.UriChecks;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.net.http.HttpClient;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;

/**
 * OAuth 2.0 authorization-code, client-credentials, refresh and revocation client. Code authorization always uses
 * fresh PKCE S256. Discovery is lazy; constructing a client does no network I/O and starts no thread. Browser
 * callbacks must be supplied with a pending source and the exact callback URI selected by trusted application
 * routing, never reconstructed from request headers. Tokens are raw credentials, not verified identity results.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public final class OAuthClient {
	static { OidcTransactionAccess.set(new OidcOperations()); }

	@ThreadSafe
	private static final class OidcOperations implements OidcTransactionAccess.Operations {
		@Override public void checkHmacAuthentication(ClientAuthentication authentication, Set<com.revetsec.jose.JwsAlgorithm> algorithms) { authentication.checkHmac(algorithms); }
		@Override public OAuthException endpointFailure(OAuthException.Reason reason) {
			return switch (reason) {
				case METADATA_INVALID -> OAuthValidationException.fromReason(reason);
				case DOCUMENT_MALFORMED -> OAuthResponseException.fromReason(reason);
				case NETWORK_FAILURE, INTERRUPTED, ATTEMPT_LIMIT -> OAuthTransportException.fromReason(reason, null);
				default -> throw new IllegalArgumentException("Unsupported endpoint failure reason.");
			};
		}
		@Override public OAuthException endpointExchangeFailure(com.revetsec.internal.http.HttpExchangeException failure) {
			return OAuthHttpErrors.fromExchange(failure);
		}
		@Override public OAuthException endpointStatusFailure(int status, @Nullable Duration retryAfter) {
			return OAuthErrorResponseException.fromResponse(status, "", Optional.ofNullable(retryAfter));
		}
		@Override public OidcTransactionAccess.RefreshCompletion refresh(OAuthClient client, RefreshToken token,
				TokenRequestOptions options, AuthorizationServerMetadata metadata, Deadline deadline, Set<com.revetsec.jose.JwsAlgorithm> hmacAlgorithms) {
			TokenEndpointPayload payload = client.refreshPayload(token, options, metadata, deadline, hmacAlgorithms);
			return new OidcTransactionAccess.RefreshCompletion(payload.idToken(), payload.idTokenPresent(), payload.accessToken(), payload.tokenType(), payload::toTokenResponse, payload.clientSecret());
		}

		@Override public AuthorizationRedirect begin(OAuthClient client, AuthorizationRequestOptions options,
				AuthorizationServerMetadata metadata, @Nullable Duration maxAge, Set<String> acrValues) {
			return client.begin(options, "oidc", metadata, maxAge, acrValues);
		}
		@Override public OidcTransactionAccess.Completion complete(OAuthClient client, AuthorizationResponse response,
				PendingAuthorizationSource source, URI callback, Function<Deadline, AuthorizationServerMetadata> metadata, Deadline deadline, Set<com.revetsec.jose.JwsAlgorithm> hmacAlgorithms) {
			CodeCompletion completion = client.complete(response, source, callback, "oidc", metadata, deadline, hmacAlgorithms);
			PendingAuthorization pending = completion.pending();
			TokenEndpointPayload payload = completion.payload();
			return new OidcTransactionAccess.Completion(payload.idToken(), payload.accessToken(), payload.tokenType(),
					completion.code(), requireNonNull(pending.nonce()), pending.maxAge(), pending.acrValues(),
					() -> payload.toTokenResponse().withApplicationData(pending.getApplicationData()), payload.clientSecret());
		}
	}

	private record CodeCompletion(PendingAuthorization pending, TokenEndpointPayload payload, String code) {
		@Override public String toString() { return "CodeCompletion{credentials=<redacted>}"; }
	}

	private final @NonNull String issuer;
	private final @Nullable AuthorizationServerMetadata staticMetadata;
	private final @Nullable AuthorizationServerCache cache;
	private final @NonNull String clientId;
	private final @NonNull ClientAuthentication clientAuthentication;
	private final @Nullable URI redirectUri;
	private final @NonNull Set<@NonNull String> scopes;
	private final @NonNull List<@NonNull URI> resources;
	private final @NonNull IssuerParameterPolicy issuerParameterPolicy;
	private final boolean requirePkceAdvertised;
	private final @NonNull Duration pendingAuthorizationLifetime;
	private final @NonNull HttpExchange exchange;
	private final @NonNull Duration requestTimeout;
	private final @NonNull Duration totalDeadline;
	private final @NonNull Clock clock;
	private final @NonNull OAuthObserver observer;
	private final @NonNull SecureRandom random;

	private OAuthClient(@NonNull Builder builder, @NonNull HttpExchange exchange) {
		this.issuer = builder.issuer;
		this.staticMetadata = builder.staticMetadata;
		this.clientId = requireNonNull(builder.clientId);
		this.clientAuthentication = requireNonNull(builder.clientAuthentication);
		this.redirectUri = builder.redirectUri;
		this.scopes = builder.scopes;
		this.resources = builder.resources;
		this.issuerParameterPolicy = builder.issuerParameterPolicy;
		this.requirePkceAdvertised = builder.requirePkceAdvertised;
		this.pendingAuthorizationLifetime = builder.pendingAuthorizationLifetime;
		this.exchange = exchange;
		this.requestTimeout = builder.requestTimeout;
		this.totalDeadline = builder.totalDeadline;
		this.clock = builder.clock;
		this.observer = builder.observer;
		this.random = new SecureRandom();
		this.cache = builder.staticMetadata == null ? new AuthorizationServerCache(URI.create(builder.issuer),
				exchange, builder.outboundUriPolicy, builder.allowInsecureLoopback, builder.requestTimeout,
				builder.clock, builder.observer, builder.minimumTimeToLive, builder.defaultTimeToLive,
				builder.maximumTimeToLive, builder.discoveryCooldown) : null;
	}

	/**
	 * Starts a client with lazy RFC 8414 then OIDC discovery.
	 *
	 * @param issuer exact configured issuer URI
	 * @return the builder
	 * @since 1.0.0
	 */
	public static @NonNull Builder withIssuer(@NonNull String issuer) {
		return new Builder(requireNonNull(issuer), null);
	}

	/**
	 * Starts a client with manually supplied metadata; build validates every known endpoint.
	 *
	 * @param metadata metadata
	 * @return the builder
	 * @since 1.0.0
	 */
	public static @NonNull Builder withAuthorizationServerMetadata(@NonNull AuthorizationServerMetadata metadata) {
		requireNonNull(metadata);
		return new Builder(metadata.getIssuer(), metadata);
	}

	/**
	 * Loads metadata now, under the same cache and deadline policy as normal use. A static client does no I/O.
	 *
	 * @since 1.0.0
	 */
	public void warmUp() { metadata(Deadline.fromNow(this.totalDeadline)); }

	/**
	 * Starts a browser code flow with client-default scopes and resources.
	 *
	 * @return the redirect and pending authorization
	 * @since 1.0.0
	 */
	public @NonNull AuthorizationRedirect beginAuthorization() {
		return beginAuthorization(AuthorizationRequestOptions.builder().build());
	}

	/**
	 * Starts a browser code flow with per-request options. It may perform lazy discovery.
	 *
	 * @param options the options
	 * @return the redirect and pending authorization
	 * @since 1.0.0
	 */
	public @NonNull AuthorizationRedirect beginAuthorization(@NonNull AuthorizationRequestOptions options) {
		requireNonNull(options);
		if (this.redirectUri == null) throw new IllegalStateException("A redirect URI is required for authorization code flow.");
		return begin(options, "oauth", metadata(Deadline.fromNow(this.totalDeadline)), null, Set.of());
	}

	private AuthorizationRedirect begin(AuthorizationRequestOptions options, String kind,
			AuthorizationServerMetadata metadata, @Nullable Duration maxAge, Set<String> acrValues) {
		if (this.redirectUri == null)
			throw new IllegalStateException("A redirect URI is required for authorization code flow.");
		if (metadata.getCodeChallengeMethodsSupported().isPresent()) {
			if (!metadata.getCodeChallengeMethodsSupported().orElseThrow().contains("S256"))
				throw OAuthValidationException.fromReason(OAuthException.Reason.PKCE_UNSUPPORTED);
		} else if (this.requirePkceAdvertised) {
			throw OAuthValidationException.fromReason(OAuthException.Reason.PKCE_UNSUPPORTED);
		}
		String state = randomBase64Url();
		String verifier = randomBase64Url();
		String nonce = randomBase64Url();
		String challenge = challenge(verifier);
		Set<String> requestedScopes = options.scopesOverridden() ? options.getScopes() : this.scopes;
		List<URI> requestedResources = options.resourcesOverridden() ? options.getResources() : this.resources;
		OAuthRequestWriter query = new OAuthRequestWriter().add("response_type", "code")
				.add("client_id", this.clientId).add("redirect_uri", this.redirectUri.toString())
				.add("state", state).add("code_challenge", challenge).add("code_challenge_method", "S256");
		if (!requestedScopes.isEmpty()) query.add("scope", String.join(" ", new TreeSet<>(requestedScopes)));
		query.resources(requestedResources);
		if (kind.equals("oidc")) {
			query.add("nonce", nonce);
			if (maxAge != null) query.add("max_age", Long.toString(maxAge.getSeconds()));
			if (!acrValues.isEmpty()) query.add("acr_values", String.join(" ", new TreeSet<>(acrValues)));
		}
		if (options.getResponseMode() == AuthorizationRequestOptions.ResponseMode.FORM_POST)
			query.add("response_mode", "form_post");
		options.getPrompt().ifPresent(prompt -> query.add("prompt", prompt));
		options.getLoginHint().ifPresent(hint -> query.add("login_hint", hint));
		query.addAll(options.getAdditionalParameters());
		URI uri = query.appendTo(metadata.getAuthorizationEndpoint());
		Instant createdAt = this.clock.instant();
		PendingAuthorization pending = new PendingAuthorization(kind, this.issuer, this.clientId, this.redirectUri,
				state, verifier, nonce, requestedScopes, requestedResources, options.getResponseMode(), createdAt,
				createdAt.plus(this.pendingAuthorizationLifetime), options.getApplicationData(),
				this.issuerParameterPolicy == IssuerParameterPolicy.REQUIRED
						|| metadata.isAuthorizationResponseIssuerSupported(), metadata.getAuthorizationEndpoint(),
				metadata.getTokenEndpoint(), maxAge, acrValues, options.getPrompt().orElse(null));
		URI safe = AuthorizationServerCache.reduced(metadata.getAuthorizationEndpoint());
		ObserverDispatch.dispatch(this.observer, observer -> observer.didBeginAuthorization(safe));
		return new AuthorizationRedirect(uri, pending);
	}

	/**
	 * Completes a browser code flow. The caller supplies the URI of the fixed route that received the callback from
	 * trusted routing configuration. The application clears its pending cookie on every callback. Sealed-cookie
	 * completion may send two code POSTs for concurrent replays; an atomic store is required for client-side single
	 * use. All local checks precede discovery and token I/O.
	 *
	 * @param response parsed callback
	 * @param source sealed cookie or browser-bound store
	 * @param actualCallbackUri fixed registered URI of the receiving route
	 * @return raw token response
	 * @since 1.0.0
	 */
	public @NonNull TokenResponse completeAuthorization(@NonNull AuthorizationResponse response,
			@NonNull PendingAuthorizationSource source, @NonNull URI actualCallbackUri) {
		CodeCompletion completion = complete(response, source, actualCallbackUri, "oauth",
				this::metadata, Deadline.fromNow(this.totalDeadline));
		return completion.payload().toTokenResponse().withApplicationData(completion.pending().getApplicationData());
	}

	private CodeCompletion complete(AuthorizationResponse response, PendingAuthorizationSource source,
			URI actualCallbackUri, String kind, Function<Deadline, AuthorizationServerMetadata> metadataSupplier, Deadline deadline) {
		return complete(response, source, actualCallbackUri, kind, metadataSupplier, deadline, Set.of());
	}
	private CodeCompletion complete(AuthorizationResponse response, PendingAuthorizationSource source,
			URI actualCallbackUri, String kind, Function<Deadline, AuthorizationServerMetadata> metadataSupplier,
			Deadline deadline, Set<com.revetsec.jose.JwsAlgorithm> hmacAlgorithms) {
		requireNonNull(response);
		requireNonNull(source);
		requireNonNull(actualCallbackUri);
		PendingAuthorization pending;
		try {
			pending = PendingAuthorizationResolver.resolve(source, response.getState().orElse(""), this.clock);
			if (!pending.kind().equals(kind))
				throw OAuthValidationException.fromReason(OAuthException.Reason.PENDING_AUTHORIZATION_INVALID);
			if (!pending.getClientId().equals(this.clientId))
				throw OAuthValidationException.fromReason(OAuthException.Reason.CLIENT_MISMATCH);
			if (!pending.getIssuer().equals(this.issuer))
				throw OAuthValidationException.fromReason(OAuthException.Reason.ISSUER_MISMATCH);
			if (pending.responseMode() != response.getResponseMode())
				throw OAuthValidationException.fromReason(OAuthException.Reason.RESPONSE_MODE_MISMATCH);
			if (!pending.getRedirectUri().toString().equals(actualCallbackUri.toString()))
				throw OAuthValidationException.fromReason(OAuthException.Reason.CALLBACK_URI_MISMATCH);
			Optional<String> responseIssuer = response.getIssuer();
			if (responseIssuer.isEmpty() && pending.issuerRequired())
				throw OAuthValidationException.fromReason(OAuthException.Reason.ISSUER_MISSING);
			if (responseIssuer.isPresent() && !responseIssuer.orElseThrow().equals(pending.getIssuer()))
				throw OAuthValidationException.fromReason(OAuthException.Reason.ISSUER_MISMATCH);
		} catch (OAuthValidationException rejection) {
			ObserverDispatch.dispatch(this.observer, observer -> observer.didRejectCallback(rejection));
			throw rejection;
		}
		if (response.getError().isPresent())
			throw AuthorizationErrorException.fromErrorCode(response.getError().orElseThrow());
		String code = response.getCode().orElseThrow(() ->
				OAuthResponseException.fromReason(OAuthException.Reason.CALLBACK_MALFORMED));
		AuthorizationServerMetadata metadata = metadataSupplier.apply(deadline);
		if (!metadata.getAuthorizationEndpoint().toString().equals(pending.authorizationEndpoint().toString())
				|| !metadata.getTokenEndpoint().toString().equals(pending.tokenEndpoint().toString()))
			throw OAuthValidationException.fromReason(OAuthException.Reason.METADATA_ENDPOINT_DRIFT);
		OAuthRequestWriter form = new OAuthRequestWriter().add("grant_type", "authorization_code")
				.add("code", code).add("redirect_uri", pending.getRedirectUri().toString())
				.add("code_verifier", pending.verifier()).resources(pending.resources());
		return new CodeCompletion(pending,
				tokenPayloadRequest(metadata.getTokenEndpoint(), form, pending.getRequestedScopes(), deadline, hmacAlgorithms), code);
	}

	/**
	 * Requests one client-credentials token. A public client cannot use this grant.
	 *
	 * @param options scope, resource and safe additional form options
	 * @return raw token response
	 * @since 1.0.0
	 */
	public @NonNull TokenResponse requestClientCredentialsToken(@NonNull TokenRequestOptions options) {
		requireNonNull(options);
		if (this.clientAuthentication.isPublicClient())
			throw new IllegalStateException("A public client cannot request client credentials.");
		Deadline deadline = Deadline.fromNow(this.totalDeadline);
		AuthorizationServerMetadata metadata = metadata(deadline);
		Set<String> requestedScopes = options.getScopes().orElse(this.scopes);
		OAuthRequestWriter form = new OAuthRequestWriter().add("grant_type", "client_credentials");
		if (!requestedScopes.isEmpty()) form.add("scope", String.join(" ", new TreeSet<>(requestedScopes)));
		form.resources(options.resourcesOverridden() ? options.getResources() : this.resources)
				.addAll(options.getAdditionalParameters());
		return tokenRequest(metadata.getTokenEndpoint(), form, requestedScopes, deadline);
	}

	/**
	 * Sends one refresh POST, with no automatic retry. The caller sends only scopes within the original grant; an
	 * absent scope option remains absent. If the response omits a replacement refresh token, retain the old one.
	 *
	 * @param refreshToken the current refresh token
	 * @param options per-request scope and resources
	 * @return raw token response
	 * @since 1.0.0
	 */
	public @NonNull TokenResponse refresh(@NonNull RefreshToken refreshToken, @NonNull TokenRequestOptions options) {
		requireNonNull(refreshToken);
		requireNonNull(options);
		Deadline deadline = Deadline.fromNow(this.totalDeadline);
		AuthorizationServerMetadata metadata = metadata(deadline);
		return refreshPayload(refreshToken, options, metadata, deadline).toTokenResponse();
	}

	private TokenEndpointPayload refreshPayload(RefreshToken refreshToken, TokenRequestOptions options,
			AuthorizationServerMetadata metadata, Deadline deadline) {
		return refreshPayload(refreshToken, options, metadata, deadline, Set.of());
	}
	private TokenEndpointPayload refreshPayload(RefreshToken refreshToken, TokenRequestOptions options,
			AuthorizationServerMetadata metadata, Deadline deadline, Set<com.revetsec.jose.JwsAlgorithm> hmacAlgorithms) {
		OAuthRequestWriter form = new OAuthRequestWriter().add("grant_type", "refresh_token")
				.add("refresh_token", refreshToken.getValue());
		options.getScopes().ifPresent(scopes -> {
			if (!scopes.isEmpty()) form.add("scope", String.join(" ", new TreeSet<>(scopes)));
		});
		form.resources(options.getResources()).addAll(options.getAdditionalParameters());
		return tokenPayloadRequest(metadata.getTokenEndpoint(), form, options.getScopes().orElse(null), deadline, hmacAlgorithms);
	}

	/**
	 * Sends one RFC 7009 revocation POST, with no automatic retry. A 200 body is ignored.
	 *
	 * @param token the token to revoke
	 * @param hint its type hint
	 * @since 1.0.0
	 */
	public void revoke(@NonNull String token, @NonNull TokenTypeHint hint) {
		if (requireNonNull(token).isEmpty()) throw new IllegalArgumentException("A token must not be empty.");
		requireNonNull(hint);
		Deadline deadline = Deadline.fromNow(this.totalDeadline);
		AuthorizationServerMetadata metadata = metadata(deadline);
		URI endpoint = metadata.getRevocationEndpoint().orElseThrow(() ->
				new IllegalStateException("The authorization server has no revocation endpoint."));
		Map<String, String> headers = new HashMap<>();
		Map<String, String> authentication = new HashMap<>();
		this.clientAuthentication.apply(this.clientId, headers, authentication);
		if (this.clientAuthentication.isUnencodedBasic())
			ObserverDispatch.dispatch(this.observer, OAuthObserver::didUseUnencodedBasic);
		OAuthRequestWriter form = new OAuthRequestWriter().add("token", token)
				.add("token_type_hint", hint.wireValue()).addAll(authentication);
		Instant requestStart = this.clock.instant();
		RawResponse response = send(endpoint, OAuthEndpoint.REVOCATION, ResponseProfile.REVOCATION,
				form.body(), headers, deadline);
		if (response.status() != 200)
			throw TokenResponseParser.error(response, requestStart);
	}

	private TokenResponse tokenRequest(URI endpoint, OAuthRequestWriter form,
			@Nullable Set<String> requestedScopes, Deadline deadline) {
		return tokenPayloadRequest(endpoint, form, requestedScopes, deadline).toTokenResponse();
	}

	private TokenEndpointPayload tokenPayloadRequest(URI endpoint, OAuthRequestWriter form,
			@Nullable Set<String> requestedScopes, Deadline deadline) {
		return tokenPayloadRequest(endpoint, form, requestedScopes, deadline, Set.of());
	}
	private TokenEndpointPayload tokenPayloadRequest(URI endpoint, OAuthRequestWriter form,
			@Nullable Set<String> requestedScopes, Deadline deadline, Set<com.revetsec.jose.JwsAlgorithm> hmacAlgorithms) {
		Map<String, String> headers = new HashMap<>();
		Map<String, String> authentication = new HashMap<>();
		String secret = this.clientAuthentication.applyForOidc(this.clientId, headers, authentication, hmacAlgorithms);
		if (this.clientAuthentication.isUnencodedBasic())
			ObserverDispatch.dispatch(this.observer, OAuthObserver::didUseUnencodedBasic);
		form.addAll(authentication);
		Instant requestStart = this.clock.instant();
		RawResponse response = send(endpoint, OAuthEndpoint.TOKEN, ResponseProfile.TOKEN,
				form.body(), headers, deadline);
		try {
			return TokenResponseParser.parsePayload(response, requestStart, requestedScopes).withClientSecret(hmacAlgorithms.isEmpty() ? null : secret);
		} catch (OAuthException failure) {
			URI safe = AuthorizationServerCache.reduced(endpoint);
			ObserverDispatch.dispatch(this.observer, observer -> observer.didFailEndpoint(
					OAuthEndpoint.TOKEN, safe, failure, response.elapsed()));
			throw failure;
		}
	}

	private RawResponse send(URI endpoint, OAuthEndpoint kind, ResponseProfile profile,
			String formBody, Map<String, String> headers, Deadline deadline) {
		URI safe = AuthorizationServerCache.reduced(endpoint);
		ObserverDispatch.dispatch(this.observer, observer -> observer.willRequestEndpoint(kind, safe));
		long started = System.nanoTime();
		try {
			RawResponse response = this.exchange.execute(new HttpExchangeRequest(endpoint, profile, formBody, headers,
					Limits.HTTP_RESPONSE_BODY_SIZE.getDefaultIntValue(),
					Limits.HTTP_ERROR_BODY_SIZE.getDefaultIntValue(), this.requestTimeout), deadline);
			ObserverDispatch.dispatch(this.observer, observer -> observer.didRequestEndpoint(
					kind, safe, response.status(), response.elapsed()));
			return response;
		} catch (HttpExchangeException failure) {
			OAuthException mapped = OAuthHttpErrors.fromExchange(failure);
			Duration elapsed = Duration.ofNanos(System.nanoTime() - started);
			ObserverDispatch.dispatch(this.observer, observer -> observer.didFailEndpoint(kind, safe, mapped, elapsed));
			throw mapped;
		}
	}

	private AuthorizationServerMetadata metadata(Deadline deadline) {
		return this.staticMetadata != null ? this.staticMetadata : requireNonNull(this.cache).get(deadline);
	}

	Clock clock() { return this.clock; }
	Duration totalDeadline() { return this.totalDeadline; }

	private String randomBase64Url() {
		byte[] bytes = new byte[32];
		this.random.nextBytes(bytes);
		try {
			return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
		} finally {
			Arrays.fill(bytes, (byte) 0);
		}
	}

	static String challenge(String verifier) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(
					verifier.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
			try {
				return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
			} finally {
				Arrays.fill(digest, (byte) 0);
			}
		} catch (NoSuchAlgorithmException impossible) {
			throw new IllegalStateException("SHA-256 is unavailable.");
		}
	}

	/**
	 * Redacts client configuration and credentials.
	 *
	 * @return a redacted description
	 * @since 1.0.0
	 */
	@Override
	public @NonNull String toString() { return "OAuthClient{configuration=<redacted>}"; }

	/**
	 * Configures an OAuth client. Building performs validation only: no discovery, HTTP request or new thread.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	public static final class Builder {
		private final @NonNull String issuer;
		private final @Nullable AuthorizationServerMetadata staticMetadata;
		private @Nullable String clientId;
		private @Nullable ClientAuthentication clientAuthentication;
		private @Nullable URI redirectUri;
		private @NonNull Set<@NonNull String> scopes = Set.of();
		private @NonNull List<@NonNull URI> resources = List.of();
		private @NonNull IssuerParameterPolicy issuerParameterPolicy = IssuerParameterPolicy.METADATA_DRIVEN;
		private boolean requirePkceAdvertised;
		private @NonNull Duration pendingAuthorizationLifetime = Limits.PENDING_STATE_LIFETIME.getDefaultDuration();
		private @Nullable HttpClient httpClient;
		private @NonNull OutboundUriPolicy outboundUriPolicy = OutboundUriPolicy.defaultInstance();
		private @NonNull Duration requestTimeout = Limits.REQUEST_TIMEOUT.getDefaultDuration();
		private @NonNull Duration totalDeadline = Limits.TOTAL_DEADLINE.getDefaultDuration();
		private @NonNull Clock clock = Clock.systemUTC();
		private @NonNull OAuthObserver observer = OAuthObserver.disabledInstance();
		private boolean allowInsecureLoopback;
		private boolean acknowledgeUnpatchedRuntime;
		private @NonNull Duration minimumTimeToLive = Limits.DISCOVERY_MINIMUM_TIME_TO_LIVE.getDefaultDuration();
		private @NonNull Duration defaultTimeToLive = Limits.DISCOVERY_DEFAULT_TIME_TO_LIVE.getDefaultDuration();
		private @NonNull Duration maximumTimeToLive = Limits.DISCOVERY_MAXIMUM_TIME_TO_LIVE.getDefaultDuration();
		private @NonNull Duration discoveryCooldown = Limits.DISCOVERY_COOLDOWN.getDefaultDuration();

		private Builder(@NonNull String issuer, @Nullable AuthorizationServerMetadata staticMetadata) {
			this.issuer = issuer;
			this.staticMetadata = staticMetadata;
		}

		/**
		 * Sets the client identifier registered with the authorization server.
		 *
		 * @param value nonempty client ID
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder clientId(@NonNull String value) {
			if (requireNonNull(value).isEmpty()) throw new IllegalArgumentException("A client ID must not be empty.");
			this.clientId = value; return this;
		}

		/**
		 * Sets the client's token-endpoint authentication method.
		 *
		 * @param value one client authentication strategy
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder clientAuthentication(@NonNull ClientAuthentication value) {
			this.clientAuthentication = requireNonNull(value); return this;
		}

		/**
		 * Sets the registered redirect URI for authorization-code flows.
		 *
		 * @param value exact registered code-flow callback URI, or null for token-only clients
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder redirectUri(@Nullable URI value) { this.redirectUri = value; return this; }

		/**
		 * Sets the scopes used when a request has no scope override.
		 *
		 * @param value complete client-default scopes
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder scopes(@NonNull Set<@NonNull String> value) {
			this.scopes = AuthorizationRequestOptions.builder().scopes(value).build().getScopes(); return this;
		}

		/**
		 * Sets the default resource indicators for token requests.
		 *
		 * @param value complete client-default resources
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder resources(@NonNull List<@NonNull URI> value) {
			this.resources = AuthorizationRequestOptions.builder().resources(value).build().getResources(); return this;
		}

		/**
		 * Sets how the callback issuer parameter is required.
		 *
		 * @param value callback issuer policy
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder issuerParameterPolicy(@NonNull IssuerParameterPolicy value) {
			this.issuerParameterPolicy = requireNonNull(value); return this;
		}

		/**
		 * Requires metadata to advertise S256 before an authorization flow begins.
		 *
		 * @param value whether metadata must advertise S256
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder requirePkceAdvertised(boolean value) { this.requirePkceAdvertised = value; return this; }

		/**
		 * Sets the lifetime of browser-bound pending authorization.
		 *
		 * @param value pending lifetime from 1 to 60 minutes
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder pendingAuthorizationLifetime(@NonNull Duration value) {
			this.pendingAuthorizationLifetime = Limits.PENDING_STATE_LIFETIME.require(value); return this;
		}

		/**
		 * Injects an application-managed HTTP client.
		 *
		 * @param value injected redirect-disabled client, or null for the lazy default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder httpClient(@Nullable HttpClient value) { this.httpClient = value; return this; }

		/**
		 * Sets the policy used to approve outbound endpoint URIs.
		 *
		 * @param value outbound URI policy
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder outboundUriPolicy(@NonNull OutboundUriPolicy value) {
			this.outboundUriPolicy = requireNonNull(value); return this;
		}

		/**
		 * Sets the timeout for one HTTP exchange.
		 *
		 * @param value per-request timeout
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder requestTimeout(@NonNull Duration value) {
			this.requestTimeout = Limits.REQUEST_TIMEOUT.require(value); return this;
		}

		/**
		 * Sets the deadline shared by all exchanges in one public call.
		 *
		 * @param value total deadline per public call
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder totalDeadline(@NonNull Duration value) {
			this.totalDeadline = Limits.TOTAL_DEADLINE.require(value); return this;
		}

		/**
		 * Sets the clock used for pending state, token expiry and cache freshness.
		 *
		 * @param value clock for token expiry and cache freshness
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder clock(@NonNull Clock value) { this.clock = requireNonNull(value); return this; }

		/**
		 * Sets the observer for bounded OAuth events.
		 *
		 * @param value observer
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder observer(@NonNull OAuthObserver value) {
			this.observer = requireNonNull(value); return this;
		}

		/**
		 * Allows plain HTTP to exact loopback hosts for local tests.
		 *
		 * @param value allow plain HTTP to exact loopback hosts for tests
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder allowInsecureLoopback(boolean value) {
			this.allowInsecureLoopback = value; return this;
		}

		/**
		 * Acknowledges the risk of building on an unpatched runtime.
		 *
		 * @param value explicit acknowledgment of an unpatched runtime
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder acknowledgeUnpatchedRuntime(boolean value) {
			this.acknowledgeUnpatchedRuntime = value; return this;
		}

		/**
		 * Sets the lowest permitted discovery cache lifetime.
		 *
		 * @param value minimum discovery cache lifetime
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder minimumTimeToLive(@NonNull Duration value) {
			this.minimumTimeToLive = Limits.DISCOVERY_MINIMUM_TIME_TO_LIVE.require(value); return this;
		}

		/**
		 * Sets the fallback lifetime when discovery supplies no usable cache lifetime.
		 *
		 * @param value fallback discovery cache lifetime
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder defaultTimeToLive(@NonNull Duration value) {
			this.defaultTimeToLive = Limits.DISCOVERY_DEFAULT_TIME_TO_LIVE.require(value); return this;
		}

		/**
		 * Sets the highest permitted discovery cache lifetime.
		 *
		 * @param value maximum discovery cache lifetime
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder maximumTimeToLive(@NonNull Duration value) {
			this.maximumTimeToLive = Limits.DISCOVERY_MAXIMUM_TIME_TO_LIVE.require(value); return this;
		}

		/**
		 * Sets the cooldown after a failed discovery attempt.
		 *
		 * @param value discovery attempt ceiling window
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder discoveryCooldown(@NonNull Duration value) {
			this.discoveryCooldown = Limits.DISCOVERY_COOLDOWN.require(value); return this;
		}

		/**
		 * Validates configuration and builds without I/O or thread creation.
		 *
		 * @return the client
		 * @since 1.0.0
		 */
		public @NonNull OAuthClient build() {
			return build(Runtime.version());
		}

		OAuthClient build(Runtime.Version runtimeVersion) {
			RuntimeFloor.require(requireNonNull(runtimeVersion), this.acknowledgeUnpatchedRuntime);
			if (this.clientId == null || this.clientAuthentication == null)
				throw new IllegalArgumentException("A client ID and client authentication strategy are required.");
			Limits.requireRequestTimeoutWithinTotalDeadline(this.requestTimeout, this.totalDeadline);
			Limits.requireDiscoveryTimeToLiveOrder(this.minimumTimeToLive, this.defaultTimeToLive,
					this.maximumTimeToLive, this.discoveryCooldown);
			URI issuerUri;
			try { issuerUri = URI.create(this.issuer); }
			catch (IllegalArgumentException malformed) { throw new IllegalArgumentException("The issuer URI is invalid."); }
			if (issuerUri.getRawQuery() != null || issuerUri.getRawFragment() != null)
				throw new IllegalArgumentException("An issuer URI must not have a query or fragment.");
			UriChecks.requirePermitted(issuerUri, this.outboundUriPolicy, this.allowInsecureLoopback);
			if (this.redirectUri != null) requireCallbackUri(this.redirectUri, this.allowInsecureLoopback);
			if (this.staticMetadata != null)
				for (URI endpoint : AuthorizationServerCache.allEndpoints(this.staticMetadata))
					UriChecks.requirePermitted(endpoint, this.outboundUriPolicy, this.allowInsecureLoopback);
			HttpExchange exchange = HttpExchange.fromHttpClient(this.httpClient, this.outboundUriPolicy,
					this.allowInsecureLoopback);
			OAuthClient client = new OAuthClient(this, exchange);
			if (this.clientAuthentication.isUnencodedBasic())
				ObserverDispatch.dispatch(this.observer, OAuthObserver::didUseUnencodedBasic);
			if (RuntimeFloor.isBelowFloor(runtimeVersion) && this.acknowledgeUnpatchedRuntime)
				ObserverDispatch.dispatch(this.observer,
						observer -> observer.didUseUnpatchedRuntime(runtimeVersion.toString()));
			return client;
		}

		private static void requireCallbackUri(URI uri, boolean allowLoopback) {
			String scheme = uri.getScheme();
			String host = uri.getHost();
			int port = uri.getPort();
			if (scheme == null || uri.isOpaque() || host == null || uri.getRawUserInfo() != null
					|| uri.getRawFragment() != null || port == 0 || port > 65_535
					|| !(scheme.equalsIgnoreCase("https") || (scheme.equalsIgnoreCase("http") && allowLoopback
					&& HostClassifier.isPlainHttpLoopbackHost(host))))
				throw new IllegalArgumentException("A redirect URI must be an absolute HTTPS URI with a host, no userinfo "
						+ "or fragment, or an allowed test loopback HTTP URI.");
		}
	}
}
