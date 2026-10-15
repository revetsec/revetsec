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
 * The outcome of one token revocation request.
 * Non-transient endpoint client errors return a fixed rejection; transport, metadata, malformed responses and
 * transient endpoint failures remain exceptions. Applications receive outcomes from the operation and cannot
 * construct them. A later release may add variants; consuming switches should include a rejecting default.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public abstract sealed class OAuthRevocationResult permits OAuthRevocationResult.Succeeded, OAuthRevocationResult.Rejected {
	OAuthRevocationResult() { }
	static @NonNull OAuthRevocationResult fromSuccess() {
		return new Succeeded();
	}
	static @NonNull OAuthRevocationResult fromEndpoint(@NonNull OAuthErrorResponseException failure) {
		return new Rejected(OAuthEndpointError.fromWireValue(failure.getErrorCode().orElse("")), failure.getStatus());
	}
	/**
	 * Returns the outcome kind with all values redacted.
	 * @return redacted description
	 * @since 1.0.0
	 */
	@Override
	public final @NonNull String toString() {
		return "OAuthRevocationResult{outcome=" + getClass().getSimpleName() + ", data=<redacted>}";
	}
	/**
	 * The endpoint accepted the revocation request; RFC 7009 also accepts unknown tokens.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Succeeded extends OAuthRevocationResult {
		private Succeeded() { }
	}
	/**
	 * The endpoint returned a non-transient client error. No response body or credential is retained.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Rejected extends OAuthRevocationResult {
		private final @NonNull OAuthEndpointError error;
		private final int status;
		private Rejected(@NonNull OAuthEndpointError error, int status) {
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
