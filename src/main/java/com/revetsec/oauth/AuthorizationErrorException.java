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
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import java.util.Optional;

/**
 * A browser authorization error, reported only after pending-state and issuer checks pass.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@NotThreadSafe
public final class AuthorizationErrorException extends OAuthException {
	private static final long serialVersionUID = 1L;
	/** Safe bounded authorization error code; null when the AS supplied no safe code. */
	private final @Nullable String errorCode;

	private AuthorizationErrorException(@Nullable String errorCode) {
		super(Reason.AUTHORIZATION_ERROR, "temporarily_unavailable".equals(errorCode), null);
		this.errorCode = errorCode;
	}

	@NonNull
	static AuthorizationErrorException fromErrorCode(@NonNull String code) {
		return new AuthorizationErrorException(OAuthSafeErrorCode.fromValue(code));
	}

	/**
	 * Returns a bounded, safe OAuth error code when one was supplied.
	 *
	 * @return the safe error code
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull String> getErrorCode() {
		return Optional.ofNullable(this.errorCode);
	}
}
