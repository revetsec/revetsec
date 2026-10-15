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

import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;
import static java.util.Objects.requireNonNull;
import com.revetsec.oauth.OAuthException;
import com.revetsec.oauth.OAuthEndpointError;
import com.revetsec.oauth.OAuthErrorResponseException;
import com.revetsec.jose.JoseException;
import org.jspecify.annotations.Nullable;
import java.util.Optional;
/**
 * The outcome of OIDC callback completion. Only a fully validated authentication releases identity and tokens.
 * <p>
 * Applications receive these outcomes from the corresponding operation; they cannot construct them.
 * Value accessors exist only on the variant that owns a value. Diagnostic text contains no input or result data.
 * A later release may add variants; consuming switches should include a rejecting default branch.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public abstract sealed class OidcAuthenticationResult permits OidcAuthenticationResult.Succeeded, OidcAuthenticationResult.Denied, OidcAuthenticationResult.RejectedAuthorization, OidcAuthenticationResult.RejectedIdToken, OidcAuthenticationResult.Failed, OidcAuthenticationResult.RejectedAuthorizationError, OidcAuthenticationResult.RejectedEndpoint {
	OidcAuthenticationResult() { }

	static @NonNull OidcAuthenticationResult fromAuthentication(@NonNull OidcAuthentication authentication) {
		return new Succeeded(requireNonNull(authentication));
	}

	static @NonNull OidcAuthenticationResult fromDenial() {
		return new Denied();
	}

	static @NonNull OidcAuthenticationResult fromAuthorizationReason(OAuthException.@NonNull Reason reason) {
		return new RejectedAuthorization(requireNonNull(reason));
	}

	static @NonNull OidcAuthenticationResult fromIdTokenReason(OidcValidationException.@NonNull Reason reason, JoseException.@Nullable Reason joseReason) {
		return new RejectedIdToken(requireNonNull(reason), joseReason);
	}

	static @NonNull OidcAuthenticationResult fromStoreFailure(OAuthException.@NonNull Reason reason) {
		return new Failed(requireNonNull(reason));
	}

	static @NonNull OidcAuthenticationResult fromAuthorizationError(@NonNull OAuthEndpointError error) {
		return new RejectedAuthorizationError(requireNonNull(error));
	}
	static @NonNull OidcAuthenticationResult fromEndpoint(@NonNull OAuthErrorResponseException failure) {
		return new RejectedEndpoint(OAuthEndpointError.fromWireValue(failure.getErrorCode().orElse("")), failure.getStatus());
	}

	/**
	 * Returns the outcome kind with all values redacted.
	 * @return redacted description
	 * @since 1.0.0
	 */
	@Override
	public final @NonNull String toString() {
		return "OidcAuthenticationResult{outcome=" + getClass().getSimpleName() + ", data=<redacted>}";
	}

	/**
	 * The shared authorization checks and all ID-token profile checks passed.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Succeeded extends OidcAuthenticationResult {
		private final @NonNull OidcAuthentication authentication;
		private Succeeded(@NonNull OidcAuthentication authentication) { this.authentication = authentication; }

		/**
		 * Returns the validated authentication and its released tokens.
		 * @return authentication
		 * @since 1.0.0
		 */
		public @NonNull OidcAuthentication getAuthentication() { return this.authentication; }
	}

	/**
	 * A bound callback reported access_denied after all pending-state and issuer checks.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Denied extends OidcAuthenticationResult {
		private Denied() {  }
	}

	/**
	 * A local callback or pending-state security check failed.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class RejectedAuthorization extends OidcAuthenticationResult {
		private final OAuthException.@NonNull Reason reason;
		private RejectedAuthorization(OAuthException.@NonNull Reason reason) { this.reason = reason; }

		/**
		 * Returns the fixed local authorization rejection reason.
		 * @return reason
		 * @since 1.0.0
		 */
		public OAuthException.@NonNull Reason getReason() { return this.reason; }
	}

	/**
	 * The ID token failed validation. No identity, claims or endpoint tokens are released.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class RejectedIdToken extends OidcAuthenticationResult {
		private final OidcValidationException.@NonNull Reason reason;
		private final JoseException.@Nullable Reason joseReason;
		private RejectedIdToken(OidcValidationException.@NonNull Reason reason, JoseException.@Nullable Reason joseReason) { this.reason = reason; this.joseReason = joseReason; }

		/**
		 * Returns the fixed ID-token rejection reason.
		 * @return reason
		 * @since 1.0.0
		 */
		public OidcValidationException.@NonNull Reason getReason() { return this.reason; }

		/**
		 * Returns the fixed lower-layer reason when JOSE rejected the input.
		 * @return joseReason
		 * @since 1.0.0
		 */
		public @NonNull Optional<JoseException.@NonNull Reason> getJoseReason() { return Optional.ofNullable(this.joseReason); }
	}

	/**
	 * The pending store did not complete its operation. No identity or token value is released.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Failed extends OidcAuthenticationResult {
		private final OAuthException.@NonNull Reason reason;
		private Failed(OAuthException.@NonNull Reason reason) { this.reason = reason; }

		/**
		 * Returns the fixed store-failure reason.
		 * @return reason
		 * @since 1.0.0
		 */
		public OAuthException.@NonNull Reason getReason() { return this.reason; }
	}

	/**
	 * A bound callback reported an authorization error after all pending-state and issuer checks passed.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class RejectedAuthorizationError extends OidcAuthenticationResult {
		private final @NonNull OAuthEndpointError error;
		private RejectedAuthorizationError(@NonNull OAuthEndpointError error) { this.error = requireNonNull(error); }
		/**
		 * Returns the fixed authorization error; unknown extension codes share one fallback.
		 * @return authorization error
		 * @since 1.0.0
		 */
		public @NonNull OAuthEndpointError getError() { return this.error; }
	}
	/**
	 * The endpoint returned a non-transient client error. No response body or credential is retained.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class RejectedEndpoint extends OidcAuthenticationResult {
		private final @NonNull OAuthEndpointError error;
		private final int status;
		private RejectedEndpoint(@NonNull OAuthEndpointError error, int status) {
			this.error = requireNonNull(error); this.status = status;
		}
		/**
		 * Returns the fixed endpoint error; unrecognized or absent codes use the same fallback.
		 * @return fixed endpoint error
		 * @since 1.0.0
		 */
		public @NonNull OAuthEndpointError getError() { return this.error; }
		/**
		 * Returns the endpoint's HTTP status.
		 * @return endpoint status
		 * @since 1.0.0
		 */
		public @NonNull Integer getStatus() { return this.status; }
	}
}
