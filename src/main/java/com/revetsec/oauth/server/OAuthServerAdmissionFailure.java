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

/** Internal fixed classification; the future endpoint boundary translates it without retaining remote data. */
final class OAuthServerAdmissionFailure extends RuntimeException {
	private static final long serialVersionUID = 1L;
	enum Reason { INVALID_TOKEN, INVALID_GRANT, INVALID_REQUEST, INVALID_CLIENT, UNAUTHORIZED_CLIENT, INVALID_SCOPE, INVALID_TARGET,
		UNSUPPORTED_RESPONSE_TYPE, UNSUPPORTED_GRANT_TYPE, INFRASTRUCTURE }
	private final @NonNull Reason reason;
	OAuthServerAdmissionFailure(@NonNull Reason reason) {
		super("OAuth server admission failed.", null, false, false);
		this.reason = java.util.Objects.requireNonNull(reason);
	}
	@NonNull Reason reason() { return this.reason; }
}
