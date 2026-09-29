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

import javax.annotation.concurrent.Immutable;

import static java.util.Objects.requireNonNull;

/**
 * A secret refresh token. The caller retains it when a refresh response has no replacement, and atomically replaces
 * it when one is returned. The token does not know its original grant scope; callers must request only a subset.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class RefreshToken {
	private final @NonNull String value;

	private RefreshToken(@NonNull String value) { this.value = value; }

	/**
	 * Wraps a nonempty token value.
	 *
	 * @param value the secret
	 * @return the token
	 * @since 1.0.0
	 */
	public static @NonNull RefreshToken fromValue(@NonNull String value) {
		if (requireNonNull(value).isEmpty())
			throw new IllegalArgumentException("A refresh token must not be empty.");
		return new RefreshToken(value);
	}

	/**
	 * Explicitly releases the secret value to the caller.
	 *
	 * @return the secret
	 * @since 1.0.0
	 */
	public @NonNull String getValue() { return this.value; }

	/**
	 * Redacts the token.
	 *
	 * @return a redacted description
	 * @since 1.0.0
	 */
	@Override
	public @NonNull String toString() { return "RefreshToken{value=<redacted>}"; }
}
