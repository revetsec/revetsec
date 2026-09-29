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
import java.time.Duration;
import java.util.Optional;

/**
 * A token or revocation endpoint error. The response body and its prose are never retained.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@NotThreadSafe
public final class OAuthErrorResponseException extends OAuthException {
	private static final long serialVersionUID = 1L;
	/** Endpoint HTTP status retained without the response body. */
	private final int status;
	/** Safe bounded OAuth error code; null when absent or unsafe. */
	private final @Nullable String errorCode;
	/** Parsed retry delay; null when the header is absent or invalid. */
	private final @Nullable Duration retryAfter;

	private OAuthErrorResponseException(int status, @Nullable String errorCode,
			@Nullable Duration retryAfter) {
		super(Reason.ENDPOINT_ERROR, status == 429 || status >= 500
				|| "temporarily_unavailable".equals(errorCode), null);
		this.status = status;
		this.errorCode = errorCode;
		this.retryAfter = retryAfter;
	}

	@NonNull
	static OAuthErrorResponseException fromResponse(int status, @NonNull String code,
			@NonNull Optional<@NonNull Duration> retryAfter) {
		return new OAuthErrorResponseException(status, OAuthSafeErrorCode.fromValue(code), retryAfter.orElse(null));
	}

	/**
	 * Returns the endpoint's HTTP status, including 200 when the body reported an OAuth error.
	 *
	 * @return the HTTP status
	 * @since 1.0.0
	 */
	public int getStatus() {
		return this.status;
	}

	/**
	 * Returns the bounded, safe OAuth error code, if present.
	 *
	 * @return the safe code
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull String> getErrorCode() {
		return Optional.ofNullable(this.errorCode);
	}

	/**
	 * Returns a parsed Retry-After delay, if present and valid.
	 *
	 * @return the delay
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull Duration> getRetryAfter() {
		return Optional.ofNullable(this.retryAfter);
	}
}
