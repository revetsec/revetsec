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
import com.revetsec.oauth.OAuthEndpointError;
import com.revetsec.oauth.OAuthErrorResponseException;
import com.revetsec.jose.JoseException;
import org.jspecify.annotations.Nullable;
import java.util.Optional;

/**
 * The outcome of an OIDC token refresh.
 * Local validation and non-transient endpoint client errors return fixed rejections. Transport, metadata,
 * malformed endpoint responses, transient endpoint failures and invalid HMAC configuration remain exceptions.
 * Applications receive outcomes from the operation and cannot construct them. A later release may add variants;
 * consuming switches should include a rejecting default branch.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public abstract sealed class OidcRefreshOutcome permits OidcRefreshOutcome.Succeeded, OidcRefreshOutcome.Rejected, OidcRefreshOutcome.RejectedEndpoint {
	OidcRefreshOutcome() { }
	static @NonNull OidcRefreshOutcome fromRefreshResult(@NonNull OidcRefreshResult value) { return new Succeeded(requireNonNull(value)); }
	static @NonNull OidcRefreshOutcome fromRejection(@NonNull OidcValidationException failure) {
		return new Rejected(failure.getReason(), failure.getJoseReason().orElse(null));
	}
	static @NonNull OidcRefreshOutcome fromEndpoint(@NonNull OAuthErrorResponseException failure) {
		return new RejectedEndpoint(OAuthEndpointError.fromWireValue(failure.getErrorCode().orElse("")), failure.getStatus());
	}
	/**
	 * Returns the outcome kind with all values redacted.
	 * @return redacted description
	 * @since 1.0.0
	 */
	@Override
	public final @NonNull String toString() {
		return "OidcRefreshOutcome{outcome=" + getClass().getSimpleName() + ", data=<redacted>}";
	}
	/**
	 * The refresh completed and any returned ID token passed continuity checks.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Succeeded extends OidcRefreshOutcome {
		private final @NonNull OidcRefreshResult value;
		private Succeeded(@NonNull OidcRefreshResult value) { this.value = requireNonNull(value); }
		/**
		 * Returns the value released after all operation checks passed.
		 * @return checked value
		 * @since 1.0.0
		 */
		public @NonNull OidcRefreshResult getRefreshResult() { return this.value; }
	}
	/**
	 * A local OIDC check rejected the operation. No identity, claim or token value is released.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Rejected extends OidcRefreshOutcome {
		private final OidcValidationException.@NonNull Reason reason;
		private final JoseException.@Nullable Reason joseReason;
		private Rejected(OidcValidationException.@NonNull Reason reason, JoseException.@Nullable Reason joseReason) {
			this.reason = requireNonNull(reason); this.joseReason = joseReason;
		}
		/**
		 * Returns the fixed OIDC rejection reason.
		 * @return rejection reason
		 * @since 1.0.0
		 */
		public OidcValidationException.@NonNull Reason getReason() { return this.reason; }
		/**
		 * Returns the fixed lower-layer reason when JOSE rejected the input.
		 * @return optional JOSE reason
		 * @since 1.0.0
		 */
		public @NonNull Optional<JoseException.@NonNull Reason> getJoseReason() {
			return Optional.ofNullable(this.joseReason);
		}
	}
	/**
	 * The endpoint returned a non-transient client error. No response body or credential is retained.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class RejectedEndpoint extends OidcRefreshOutcome {
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
