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
 * The outcome of OAuth callback completion. Transport, store, metadata and endpoint failures remain exceptions.
 * <p>
 * Applications receive these outcomes from the corresponding operation; they cannot construct them.
 * Value accessors exist only on the variant that owns a value. Diagnostic text contains no input or result data.
 * A later release may add variants; consuming switches should include a rejecting default branch.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public abstract sealed class AuthorizationCompletionResult permits AuthorizationCompletionResult.Succeeded, AuthorizationCompletionResult.Denied, AuthorizationCompletionResult.Rejected {
	AuthorizationCompletionResult() { }

	static @NonNull AuthorizationCompletionResult fromTokens(@NonNull TokenResponse tokens) {
		return new Succeeded(requireNonNull(tokens));
	}

	static @NonNull AuthorizationCompletionResult fromDenial() {
		return new Denied();
	}

	static @NonNull AuthorizationCompletionResult fromReason(OAuthException.@NonNull Reason reason) {
		return new Rejected(requireNonNull(reason));
	}

	/**
	 * Returns the outcome kind with all values redacted.
	 * @return redacted description
	 * @since 1.0.0
	 */
	@Override
	public final @NonNull String toString() {
		return "AuthorizationCompletionResult{outcome=" + getClass().getSimpleName() + ", data=<redacted>}";
	}

	/**
	 * The authorization flow completed once and returned endpoint tokens.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Succeeded extends AuthorizationCompletionResult {
		private final @NonNull TokenResponse tokens;
		private Succeeded(@NonNull TokenResponse tokens) { this.tokens = tokens; }

		/**
		 * Returns the endpoint tokens; this OAuth operation establishes no OIDC identity.
		 * @return tokens
		 * @since 1.0.0
		 */
		public @NonNull TokenResponse getTokens() { return this.tokens; }
	}

	/**
	 * A bound callback reported access_denied after all pending-state and issuer checks.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Denied extends AuthorizationCompletionResult {
		private Denied() {  }
	}

	/**
	 * A local callback or pending-state security check rejected completion.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Rejected extends AuthorizationCompletionResult {
		private final OAuthException.@NonNull Reason reason;
		private Rejected(OAuthException.@NonNull Reason reason) { this.reason = reason; }

		/**
		 * Returns the fixed local authorization rejection reason.
		 * @return reason
		 * @since 1.0.0
		 */
		public OAuthException.@NonNull Reason getReason() { return this.reason; }
	}
}
