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

/**
 * RFC 6750 section 3.1 bearer errors and their recommended HTTP status codes.
 * Missing credentials use a 401 challenge without an error; application permission decisions select
 * insufficient_scope. Later releases may add values, so switches need a default branch.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public enum BearerError {
	/** The credential presentation is malformed. */
	INVALID_REQUEST(400, "invalid_request"),
	/** The presented credential was rejected. */
	INVALID_TOKEN(401, "invalid_token"),
	/** The app requires permissions not granted by the token. */
	INSUFFICIENT_SCOPE(403, "insufficient_scope");

	private final @NonNull Integer statusCode;
	private final @NonNull String wireValue;
	BearerError(@NonNull Integer statusCode, @NonNull String wireValue) {
		this.statusCode = statusCode; this.wireValue = wireValue;
	}
	/**
	 * Returns the recommended HTTP status code.
	 * @return the status code
	 * @since 1.0.0
	 */
	public @NonNull Integer getStatusCode() { return this.statusCode; }
	/**
	 * Returns the protocol error value.
	 * @return the wire value
	 * @since 1.0.0
	 */
	public @NonNull String getWireValue() { return this.wireValue; }
}
