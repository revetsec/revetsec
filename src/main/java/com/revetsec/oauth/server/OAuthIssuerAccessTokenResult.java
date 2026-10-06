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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import com.google.errorprone.annotations.CheckReturnValue;
import javax.annotation.concurrent.Immutable;
import java.util.Optional;
import static java.util.Objects.requireNonNull;
import com.revetsec.oauth.VerifiedAccessToken;
import com.revetsec.oauth.AccessTokenValidationException;
import com.revetsec.oauth.BearerError;
import com.revetsec.jose.JoseException;
/**
 * A library-created outcome. Applications cannot mint outcomes or proofs. Future variants require a rejecting
 * switch default. Diagnostics disclose no interaction, credential, identity or claims. Infrastructure failures
 * remain exceptions and cannot be reported as credential rejection.
 * @since 1.0.0
 */
@Immutable
public abstract sealed class OAuthIssuerAccessTokenResult permits OAuthIssuerAccessTokenResult.Succeeded, OAuthIssuerAccessTokenResult.Rejected {
	OAuthIssuerAccessTokenResult() {}
	static @NonNull OAuthIssuerAccessTokenResult fromSucceeded(@NonNull VerifiedAccessToken token) { return new Succeeded(requireNonNull(token)); }
	static @NonNull OAuthIssuerAccessTokenResult fromRejection(OAuthServerException.@NonNull Reason reason,
		AccessTokenValidationException.@Nullable Reason accessTokenReason, JoseException.@Nullable Reason joseReason) {
		requireNonNull(reason).requireKind(OAuthServerException.Kind.VALIDATION);
		return new Rejected(reason,accessTokenReason,joseReason);
	}
	/** Returns a fixed redacted description.
	 * @return fixed redacted description
	 * @since 1.0.0
	 */
	@Override public final @NonNull String toString() { return "OAuthIssuerAccessTokenResult{<redacted>}"; }
	/** The library-created Succeeded outcome.
	 * @since 1.0.0
	 */
	@Immutable public static final class Succeeded extends OAuthIssuerAccessTokenResult {
		private final @NonNull VerifiedAccessToken token;
		private Succeeded(@NonNull VerifiedAccessToken token) { this.token=token; }
		/** Returns the checked access-token proof after authoritative issuer status validation.
		 * @return token
		 * @since 1.0.0
		 */
		@CheckReturnValue public @NonNull VerifiedAccessToken getAccessToken() { return this.token; }
	}
	/** A fixed rejection with no proof, request, credential, identity, claims or exception object.
	 * @since 1.0.0
	 */
	@Immutable public static final class Rejected extends OAuthIssuerAccessTokenResult {
		private final OAuthServerException.@NonNull Reason reason;
		private final AccessTokenValidationException.@Nullable Reason accessTokenReason;
		private final JoseException.@Nullable Reason joseReason;
		private Rejected(OAuthServerException.@NonNull Reason reason, AccessTokenValidationException.@Nullable Reason accessTokenReason,
			JoseException.@Nullable Reason joseReason) { this.reason=reason; this.accessTokenReason=accessTokenReason; this.joseReason=joseReason; }
		/** Returns the fixed issuer rejection reason, not an external error string.
		 * @return fixed reason
		 * @since 1.0.0
		 */
		@CheckReturnValue public OAuthServerException.@NonNull Reason getReason() { return this.reason; }
		/** Returns a fixed M5 profile reason, when applicable.
		 * @return optional fixed resource-profile reason
		 * @since 1.0.0
		 */
		@CheckReturnValue public @NonNull Optional<AccessTokenValidationException.@NonNull Reason> getAccessTokenReason() { return Optional.ofNullable(this.accessTokenReason); }
		/** Returns a fixed JOSE reason, when applicable.
		 * @return optional fixed JOSE reason
		 * @since 1.0.0
		 */
		@CheckReturnValue public @NonNull Optional<JoseException.@NonNull Reason> getJoseReason() { return Optional.ofNullable(this.joseReason); }
		/** Returns a safe bearer error; provider or store outages never enter this result.
		 * @return safe bearer error
		 * @since 1.0.0
		 */
		@CheckReturnValue public @NonNull BearerError getBearerError() { return this.reason==OAuthServerException.Reason.MALFORMED_REQUEST ? BearerError.INVALID_REQUEST : BearerError.INVALID_TOKEN; }
	}
}
