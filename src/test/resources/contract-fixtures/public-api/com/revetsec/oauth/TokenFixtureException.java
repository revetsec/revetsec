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
import javax.annotation.concurrent.NotThreadSafe;

/**
 * A final leaf exception. Controls: its serialVersionUID, a package-private factory, an instance accessor, and one
 * public static factory that ContractMetaTests lists in APP_CONSTRUCTIBLE_EXCEPTION_FACTORIES. Seeded violation: a
 * second public static factory that is not listed.
 *
 * @since 1.0.0
 */
@NotThreadSafe
public final class TokenFixtureException extends OAuthFixtureException {
	private static final long serialVersionUID = 1L;

	/**
	 * Why the token request failed.
	 *
	 * @serial
	 */
	private final @NonNull Reason reason;

	/**
	 * Why a token request failed.
	 *
	 * @since 1.0.0
	 */
	@Immutable
	public enum Reason {
		/**
		 * The server refused the grant.
		 */
		INVALID_GRANT
	}

	private TokenFixtureException(@NonNull Reason reason) {
		super("The token request failed.");
		this.reason = reason;
	}

	static @NonNull TokenFixtureException fromReason(@NonNull Reason reason) {
		return new TokenFixtureException(reason);
	}

	/**
	 * Control: a reviewed factory that applications call, listed in APP_CONSTRUCTIBLE_EXCEPTION_FACTORIES.
	 *
	 * @param status an HTTP status
	 * @return the exception
	 * @since 1.0.0
	 */
	public static @NonNull TokenFixtureException fromStatus(@NonNull Integer status) {
		return new TokenFixtureException(Reason.INVALID_GRANT);
	}

	/**
	 * Seeded violation: a public static factory that is not listed.
	 *
	 * @param description a description
	 * @return the exception
	 * @since 1.0.0
	 */
	public static @NonNull TokenFixtureException fromDescription(@NonNull String description) {
		return new TokenFixtureException(Reason.INVALID_GRANT);
	}

	/**
	 * Why the token request failed.
	 *
	 * @return the reason
	 * @since 1.0.0
	 */
	public @NonNull Reason getReason() {
		return this.reason;
	}
}
