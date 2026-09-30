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

import com.revetsec.json.JsonObject;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.time.Instant;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Parsed token-endpoint fields held inside the OAuth package. OIDC validates the ID token before this object
 * constructs any public token carrier. The raw ID token never enters TokenResponse's safe parameter view.
 */
@Immutable
final class TokenEndpointPayload {
	private final @NonNull String accessToken;
	private final @NonNull String tokenType;
	private final @Nullable Instant expiresAt;
	private final @Nullable String refreshToken;
	private final @Nullable String idToken;
	private final boolean idTokenPresent;
	private final @Nullable String clientSecret;
	private final @Nullable String scope;
	private final @Nullable Set<@NonNull String> grantedScopes;
	private final @NonNull Instant requestStart;
	private final @NonNull JsonObject safeParameters;

	TokenEndpointPayload(@NonNull String accessToken, @NonNull String tokenType,
			@Nullable Instant expiresAt, @Nullable String refreshToken, @Nullable String idToken, boolean idTokenPresent,
			@Nullable String scope, @Nullable Set<@NonNull String> grantedScopes,
			@NonNull Instant requestStart, @NonNull JsonObject safeParameters) {
		this(accessToken, tokenType, expiresAt, refreshToken, idToken, idTokenPresent, scope, grantedScopes,
				requestStart, safeParameters, null);
	}
	private TokenEndpointPayload(String accessToken, String tokenType, @Nullable Instant expiresAt,
			@Nullable String refreshToken, @Nullable String idToken, boolean idTokenPresent, @Nullable String scope,
			@Nullable Set<String> grantedScopes, Instant requestStart, JsonObject safeParameters, @Nullable String clientSecret) {
		this.clientSecret = clientSecret;
		this.accessToken = requireNonNull(accessToken);
		this.tokenType = requireNonNull(tokenType);
		this.expiresAt = expiresAt;
		this.refreshToken = refreshToken;
		this.idToken = idToken; this.idTokenPresent = idTokenPresent;
		this.scope = scope;
		this.grantedScopes = grantedScopes == null ? null : Set.copyOf(grantedScopes);
		this.requestStart = requireNonNull(requestStart);
		this.safeParameters = requireNonNull(safeParameters);
	}

	TokenEndpointPayload withClientSecret(@Nullable String secret) {
		return secret == null ? this : new TokenEndpointPayload(this.accessToken, this.tokenType, this.expiresAt,
				this.refreshToken, this.idToken, this.idTokenPresent, this.scope, this.grantedScopes, this.requestStart,
				this.safeParameters, secret);
	}
	@Nullable String clientSecret() { return this.clientSecret; }
	@Nullable String idToken() { return this.idToken; }
	boolean idTokenPresent() { return this.idTokenPresent; }
	String accessToken() { return this.accessToken; }
	String tokenType() { return this.tokenType; }

	TokenResponse toTokenResponse() {
		return new TokenResponse(new AccessToken(this.accessToken, this.tokenType, this.expiresAt),
				this.refreshToken == null ? null : RefreshToken.fromValue(this.refreshToken),
				this.scope, this.grantedScopes, this.requestStart, this.safeParameters);
	}

	@Override
	public String toString() { return "TokenEndpointPayload{credentials=<redacted>}"; }
}
