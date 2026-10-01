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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.time.Instant;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * A raw access token returned by an AS. It is not a verified identity or a validated resource-server token. The
 * value is secret and appears only through explicit accessors.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class AccessToken {
	private final @NonNull String value;
	private final @NonNull String tokenType;
	private final @Nullable Instant expiresAt;

	AccessToken(@NonNull String value, @NonNull String tokenType, @Nullable Instant expiresAt) {
		if (requireNonNull(value).isEmpty() || requireNonNull(tokenType).isEmpty())
			throw new IllegalArgumentException("An access token and type must not be empty.");
		this.value = value;
		this.tokenType = tokenType;
		this.expiresAt = expiresAt;
	}

	/**
	 * Explicitly releases the secret token value.
	 *
	 * @return the token value
	 * @since 1.0.0
	 */
	public @NonNull String getValue() { return this.value; }

	/**
	 * Returns the AS's token type, with its original case.
	 *
	 * @return token type
	 * @since 1.0.0
	 */
	public @NonNull String getTokenType() { return this.tokenType; }

	/**
	 * Reports whether the authorization server named the Bearer token type, ignoring ASCII case.
	 * This does not mean the token value is safe to place in a header.
	 *
	 * @return whether the token type is Bearer
	 * @since 1.0.0
	 */
	public @NonNull Boolean isBearer() { return this.tokenType.equalsIgnoreCase("Bearer"); }

	/**
	 * Returns the request-start-anchored expiry when the AS supplied one.
	 *
	 * @return expiry
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull Instant> getExpiresAt() { return Optional.ofNullable(this.expiresAt); }

	/**
	 * Returns a Bearer Authorization header. Non-Bearer types and values outside RFC 6750's b64token grammar are
	 * refused, including whitespace and line breaks.
	 *
	 * @return the header value
	 * @since 1.0.0
	 */
	public @NonNull String getAuthorizationHeaderValue() {
		if (!isBearer() || !isSafeBearerToken(this.value))
			throw new IllegalStateException("This token cannot be sent as a Bearer Authorization header.");
		return "Bearer " + this.value;
	}

	private static boolean isSafeBearerToken(String value) {
		int index = 0;
		while (index < value.length()) {
			char c = value.charAt(index);
			if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
					|| c == '-' || c == '.' || c == '_' || c == '~' || c == '+' || c == '/')
				index++;
			else
				break;
		}
		if (index == 0) return false;
		while (index < value.length() && value.charAt(index) == '=') index++;
		return index == value.length();
	}

	/**
	 * Redacts the token.
	 *
	 * @return a redacted description
	 * @since 1.0.0
	 */
	@Override
	public @NonNull String toString() { return "AccessToken{value=<redacted>}"; }
}
