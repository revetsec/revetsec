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

import static java.util.Objects.requireNonNull;
import com.revetsec.jose.*;
import com.revetsec.json.*;
import java.time.*;
import java.util.*;
import javax.annotation.concurrent.Immutable;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * The access-token verdict. Only success releases proof. Credential rejection contains fixed reasons only;
 * a checked introspection endpoint rejection is distinct from an invalid credential.
 * Applications cannot construct outcomes. Future variants require a rejecting switch default.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public abstract sealed class AccessTokenValidationResult permits AccessTokenValidationResult.Succeeded, AccessTokenValidationResult.Rejected, AccessTokenValidationResult.RejectedEndpoint {

	AccessTokenValidationResult() {
	}

	static @NonNull AccessTokenValidationResult fromToken(@NonNull VerifiedAccessToken token) {
		return new Succeeded(requireNonNull(token));
	}

	static @NonNull AccessTokenValidationResult fromRejection(@NonNull AccessTokenValidationException rejection) {
		return new Rejected(rejection.getReason(), rejection.getJoseReason().orElse(null));
	}

	static @NonNull AccessTokenValidationResult fromEndpoint(@NonNull OAuthErrorResponseException failure) {
		return new RejectedEndpoint(OAuthEndpointError.fromWireValue(failure.getErrorCode().orElse("")), failure.getStatus());
	}

	/**
	 * Returns the outcome kind without data.
	 * @return redacted description
	 * @since 1.0.0
	 */
	@Override
	@NonNull
	public final String toString() {
		return "AccessTokenValidationResult{outcome=" + getClass().getSimpleName() + ", data=<redacted>}";
	}

	/**
	 * All configured access-token checks passed.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Succeeded extends AccessTokenValidationResult {

		@NonNull
		private final VerifiedAccessToken token;

		private Succeeded(@NonNull VerifiedAccessToken token) {
			this.token = token;
		}

		/**
		 * Returns fully checked proof, without the received credential.
		 * @return access token
		 * @since 1.0.0
		 */
		@NonNull
		public VerifiedAccessToken getAccessToken() {
			return this.token;
		}
	}

	/**
	 * The credential was rejected; no identity, claims, credential or exception is retained.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Rejected extends AccessTokenValidationResult {

		private final AccessTokenValidationException.@NonNull Reason reason;

		private final JoseException.@Nullable Reason joseReason;

		private Rejected(AccessTokenValidationException.@NonNull Reason reason, JoseException.@Nullable Reason joseReason) {
			this.reason = reason;
			this.joseReason = joseReason;
		}

		/**
		 * Returns the fixed resource-profile rejection.
		 * @return reason
		 * @since 1.0.0
		 */
		public AccessTokenValidationException.@NonNull Reason getReason() {
			return this.reason;
		}

		/**
		 * Returns the fixed lower-layer JOSE reason, when applicable.
		 * @return reason
		 * @since 1.0.0
		 */
		@NonNull
		public Optional<JoseException.@NonNull Reason> getJoseReason() {
			return Optional.ofNullable(this.joseReason);
		}

		/**
		 * Returns a safe bearer challenge error; provider outages never enter this branch.
		 * @return bearer error
		 * @since 1.0.0
		 */
		@NonNull
		public BearerError getBearerError() {
			return this.reason == AccessTokenValidationException.Reason.MALFORMED_REQUEST ? BearerError.INVALID_REQUEST : BearerError.INVALID_TOKEN;
		}
	}
	/**
	 * The introspection endpoint rejected the request with a checked, nontransient client error. This establishes
	 * no credential verdict and supplies no bearer challenge error. No identity, credential or endpoint prose is retained.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class RejectedEndpoint extends AccessTokenValidationResult {
		private final @NonNull OAuthEndpointError error;
		private final int status;
		private RejectedEndpoint(@NonNull OAuthEndpointError error, int status) {
			this.error = error; this.status = status;
		}
		/**
		 * Returns the fixed endpoint error. Extension codes have the unrecognized value.
		 * @return fixed error
		 * @since 1.0.0
		 */
		public @NonNull OAuthEndpointError getError() { return this.error; }
		/**
		 * Returns the endpoint's HTTP status.
		 * @return HTTP status
		 * @since 1.0.0
		 */
		public @NonNull Integer getStatus() { return this.status; }
	}

}
