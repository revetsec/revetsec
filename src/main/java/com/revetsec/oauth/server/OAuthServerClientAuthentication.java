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

package com.revetsec.oauth.server;

import com.google.errorprone.annotations.CheckReturnValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import static java.util.Objects.requireNonNull;

/**
 * Trusted registered-client authentication policy: public authentication or confidential client_secret_basic.
 * Construction performs no callback or I/O. The verifier must be thread safe. No secret-post authentication,
 * private-key authentication or client-credentials issuance is implied by this policy.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class OAuthServerClientAuthentication {
	private static final @NonNull OAuthServerClientAuthentication PUBLIC = new OAuthServerClientAuthentication(null);
	private final @Nullable OAuthClientSecretVerifier verifier;
	private OAuthServerClientAuthentication(@Nullable OAuthClientSecretVerifier verifier) { this.verifier = verifier; }
	/**
	 * Selects public-client authentication (none).
	 * @return the public-client policy
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull OAuthServerClientAuthentication publicClientInstance() { return PUBLIC; }
	/**
	 * Selects confidential client_secret_basic verification by the application.
	 * @param verifier the application callback; never called during construction
	 * @return the confidential policy
	 * @throws NullPointerException if verifier is null
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull OAuthServerClientAuthentication fromClientSecretVerifier(@NonNull OAuthClientSecretVerifier verifier) {
		return new OAuthServerClientAuthentication(requireNonNull(verifier));
	}
	boolean isConfidential() { return this.verifier != null; }
	@Nullable OAuthClientSecretVerifier verifier() { return this.verifier; }
	/**
	 * Redacts the strategy and callback from diagnostics.
	 * @return a fixed description
	 * @since 1.0.0
	 */
	@Override public @NonNull String toString() { return "OAuthServerClientAuthentication{configuration=<redacted>}"; }
}
