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
 * The outcome of parsing a raw, unverified OAuth browser callback. A successful parse grants no identity;
 * the configured OAuth or OpenID Connect client must complete the browser-bound transaction.
 * <p>
 * Only the producing operation constructs these outcomes. Value accessors exist only on the variant that
 * owns a value, and diagnostic text contains no callback data. Later releases may add variants;
 * consuming switches should include a rejecting default branch.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public abstract sealed class AuthorizationResponseParseResult
		permits AuthorizationResponseParseResult.Succeeded, AuthorizationResponseParseResult.Rejected {
	AuthorizationResponseParseResult() { }

	static @NonNull AuthorizationResponseParseResult fromResponse(@NonNull AuthorizationResponse response) {
		return new Succeeded(requireNonNull(response));
	}

	static @NonNull AuthorizationResponseParseResult fromRejected() {
		return new Rejected();
	}

	/**
	 * Returns the outcome kind without callback data.
	 * @return redacted description
	 * @since 1.0.0
	 */
	@Override
	public final @NonNull String toString() {
		return "AuthorizationResponseParseResult{outcome=" + getClass().getSimpleName() + ", data=<redacted>}";
	}

	/**
	 * A syntactically parsed callback that remains unverified until transaction completion.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Succeeded extends AuthorizationResponseParseResult {
		private final @NonNull AuthorizationResponse response;
		private Succeeded(@NonNull AuthorizationResponse response) { this.response = response; }

		/**
		 * Returns the raw, unverified callback. It grants no identity or permission.
		 * @return the parsed callback
		 * @since 1.0.0
		 */
		public @NonNull AuthorizationResponse getResponse() { return this.response; }
	}

	/**
	 * A malformed, duplicate, oversized or split-channel callback.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Rejected extends AuthorizationResponseParseResult {
		private Rejected() { }

		/**
		 * Returns a fixed reason without attacker-controlled callback data.
		 * @return malformed callback reason
		 * @since 1.0.0
		 */
		public OAuthException.@NonNull Reason getReason() { return OAuthException.Reason.CALLBACK_MALFORMED; }
	}
}
