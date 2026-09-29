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
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * One token-endpoint success. It carries raw tokens, not a verified identity. Unknown JSON members can be inspected
 * through safe accessors; all token and error members, including {@code id_token}, are excluded from them.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class TokenResponse {
	private final @NonNull AccessToken accessToken;
	private final @Nullable RefreshToken refreshToken;
	private final @Nullable Set<@NonNull String> grantedScopes;
	private final @Nullable String scope;
	private final @NonNull Instant receivedAt;
	private final @NonNull JsonObject safeParameters;
	private final @NonNull Map<@NonNull String, @NonNull String> applicationData;

	TokenResponse(@NonNull AccessToken accessToken, @Nullable RefreshToken refreshToken,
			@Nullable String scope, @Nullable Set<@NonNull String> grantedScopes,
			@NonNull Instant receivedAt, @NonNull JsonObject safeParameters) {
		this.accessToken = requireNonNull(accessToken);
		this.refreshToken = refreshToken;
		this.scope = scope;
		this.grantedScopes = grantedScopes == null ? null : Set.copyOf(grantedScopes);
		this.receivedAt = requireNonNull(receivedAt);
		this.safeParameters = requireNonNull(safeParameters);
		this.applicationData = Map.of();
	}

	private TokenResponse(@NonNull TokenResponse original,
			@NonNull Map<@NonNull String, @NonNull String> applicationData) {
		this.accessToken = original.accessToken;
		this.refreshToken = original.refreshToken;
		this.grantedScopes = original.grantedScopes;
		this.scope = original.scope;
		this.receivedAt = original.receivedAt;
		this.safeParameters = original.safeParameters;
		this.applicationData = Map.copyOf(applicationData);
	}

	TokenResponse withApplicationData(Map<String, String> value) {
		return new TokenResponse(this, value);
	}

	/**
	 * Returns the raw access token.
	 *
	 * @return the token
	 * @since 1.0.0
	 */
	public @NonNull AccessToken getAccessToken() { return this.accessToken; }

	/**
	 * Returns a replacement refresh token when supplied. If absent, callers retain their previous token.
	 *
	 * @return the replacement
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull RefreshToken> getRefreshToken() {
		return Optional.ofNullable(this.refreshToken);
	}

	/**
	 * Returns the authorization server's scope member exactly when it supplied one. Use
	 * {@link #getGrantedScopes()} for the request-specific fallback when it was absent.
	 *
	 * @return the response's scope member
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull String> getScope() { return Optional.ofNullable(this.scope); }

	/**
	 * Returns granted scopes. When the response omitted scope, this request's scopes are used; no client-wide defaults
	 * are inferred for a refresh request that omitted scope.
	 *
	 * @return the scopes when known
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull Set<@NonNull String>> getGrantedScopes() {
		return Optional.ofNullable(this.grantedScopes);
	}

	/**
	 * Returns the access-token expiry, when supplied.
	 *
	 * @return expiry
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull Instant> getExpiresAt() { return this.accessToken.getExpiresAt(); }

	/**
	 * Returns the instant at which this token request began. Expiry is anchored to this instant.
	 *
	 * @return request start
	 * @since 1.0.0
	 */
	public @NonNull Instant getReceivedAt() { return this.receivedAt; }

	/**
	 * Returns the application data authenticated in the pending browser authorization, after code completion. It is
	 * empty for other grants. The application must still allowlist any value used as a redirect destination.
	 *
	 * @return immutable application data
	 * @since 1.0.0
	 */
	public @NonNull Map<@NonNull String, @NonNull String> getApplicationData() {
		return this.applicationData;
	}

	/**
	 * Returns one unknown non-token JSON member.
	 *
	 * @param name exact member name
	 * @return its value
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull JsonValue> getParameter(@NonNull String name) {
		return this.safeParameters.find(name);
	}

	/**
	 * Returns unknown non-token JSON members only.
	 *
	 * @return a safe JSON object
	 * @since 1.0.0
	 */
	public @NonNull JsonObject toJsonObject() { return this.safeParameters; }

	/**
	 * Redacts all tokens and parameters.
	 *
	 * @return a redacted description
	 * @since 1.0.0
	 */
	@Override
	public @NonNull String toString() { return "TokenResponse{tokens=<redacted>}"; }
}
