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

import com.revetsec.ErrorCategory;
import com.revetsec.RevetsecException;
import com.revetsec.jose.JoseException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.util.Optional;
import static java.util.Objects.requireNonNull;

/**
 * A local bearer credential verdict, with fixed reasons and no token, claims or lower-layer exception retained.
 * Infrastructure failures retain their own exception types; they must not be turned into invalid_token.
 * Applications catch this exception; only Revetsec constructs it. No scope permission is granted by parsing.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@NotThreadSafe
public final class AccessTokenValidationException extends RevetsecException {
	private static final long serialVersionUID = 1L;
	/** The fixed local credential verdict.
	 * @serial
	 */
	private final @NonNull Reason reason;
	/** Optional lower-layer reason; never a lower-layer exception or credential.
	 * @serial
	 */
	private final JoseException.@Nullable Reason joseReason;
	private AccessTokenValidationException(@NonNull Reason reason, JoseException.@Nullable Reason joseReason) {
		super(requireNonNull(reason) == Reason.MALFORMED_REQUEST ? ErrorCategory.MALFORMED_INPUT
				: ErrorCategory.VALIDATION_FAILURE, false, reason.message, null);
		this.reason = reason; this.joseReason = joseReason;
	}
	static @NonNull AccessTokenValidationException fromReason(@NonNull Reason reason) {
		return new AccessTokenValidationException(reason, null);
	}
	static @NonNull AccessTokenValidationException fromJoseReason(JoseException.@NonNull Reason reason) {
		return new AccessTokenValidationException(Reason.JWT_REJECTED, requireNonNull(reason));
	}
	/**
	 * Returns the fixed local failure reason.
	 * @return the reason
	 * @since 1.0.0
	 */
	public @NonNull Reason getReason() { return this.reason; }
	/**
	 * Returns invalid_request for malformed presentation, otherwise invalid_token.
	 * @return the bearer error
	 * @since 1.0.0
	 */
	public @NonNull BearerError getBearerError() {
		return this.reason == Reason.MALFORMED_REQUEST ? BearerError.INVALID_REQUEST : BearerError.INVALID_TOKEN;
	}
	/**
	 * Returns a lower-layer JWT reason, without retaining its exception or input.
	 * @return the JOSE reason, if applicable
	 * @since 1.0.0
	 */
	public @NonNull Optional<JoseException.@NonNull Reason> getJoseReason() {
		return Optional.ofNullable(this.joseReason);
	}
	/**
	 * The failed credential check. Later releases may add values; switches need a default branch.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public enum Reason {
		/** The bearer credential presentation is malformed. */
		MALFORMED_REQUEST("The bearer credential presentation is malformed."),
		/** The access token failed JWT validation. */
		JWT_REJECTED("The access token failed JWT validation."),
		/** An access token claim is invalid. */
		INVALID_CLAIM("An access token claim is invalid."),
		/** A required access token claim is missing. */
		REQUIRED_CLAIM_MISSING("A required access token claim is missing."),
		/** An untyped access token contains an identity-token claim. */
		UNTYPED_IDENTITY_CLAIM_PRESENT("An untyped access token contains an identity-token claim."),
		/** The access token is inactive. */
		INACTIVE("The access token is inactive."),
		/** The access token issuer does not match. */
		ISSUER_MISMATCH("The access token issuer does not match."),
		/** The access token has no required audience. */
		AUDIENCE_MISSING("The access token has no required audience."),
		/** The access token audience does not match. */
		AUDIENCE_MISMATCH("The access token audience does not match."),
		/** The access token has expired. */
		EXPIRED("The access token has expired."),
		/** The access token was issued in the future. */
		ISSUED_IN_FUTURE("The access token was issued in the future."),
		/** The access token is not yet valid. */
		NOT_YET_VALID("The access token is not yet valid."),
		/** The access token requires proof of key possession. */
		CONFIRMATION_NOT_VERIFIED("The access token requires proof of key possession."),
		/** The access token type is invalid. */
		TOKEN_TYPE_INVALID("The access token type is invalid."),
		/** The access token scope is invalid. */
		SCOPE_INVALID("The access token scope is invalid.");
		private final @NonNull String message;
		Reason(@NonNull String message) { this.message = message; }
	}
}
