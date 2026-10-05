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
import static java.util.Objects.requireNonNull;

/** Fixed internal classification; the future public exception boundary translates these reasons. */
final class OAuthStoreFailure extends RuntimeException {
	private static final long serialVersionUID = 1L;
	enum Reason { UNAVAILABLE, CORRUPT_STATE, COMMIT_OUTCOME_UNKNOWN }
	private final @NonNull Reason reason;
	OAuthStoreFailure(@NonNull Reason reason) {
		super("OAuth server store operation failed.", null, false, false);
		this.reason = requireNonNull(reason);
	}
	@NonNull Reason reason() { return this.reason; }
}
