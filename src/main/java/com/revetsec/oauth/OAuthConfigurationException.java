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

import javax.annotation.concurrent.NotThreadSafe;
import org.jspecify.annotations.NonNull;
import static java.util.Objects.requireNonNull;

/**
 * A fixed, cause-free failure of configured assertion keys, signing, endpoint trust or issuer policy.
 * This infrastructure failure is never an invalid-user result.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@NotThreadSafe
public final class OAuthConfigurationException extends OAuthException {
	private static final long serialVersionUID = 1L;
	private OAuthConfigurationException(@NonNull Reason reason) { super(reason, false, null); }
	static @NonNull OAuthConfigurationException fromReason(@NonNull Reason reason) {
		requireNonNull(reason);
		switch (reason) {
			case CLIENT_ASSERTION_KEY_UNAVAILABLE, CLIENT_ASSERTION_SIGNING_FAILED,
				CLIENT_ASSERTION_KEY_PAIR_MISMATCH, CLIENT_ASSERTION_ENDPOINT_MISMATCH, ISSUER_POLICY_UNAVAILABLE -> { }
			default -> throw new IllegalArgumentException("The OAuth reason is not an assertion or issuer-policy configuration reason.");
		}
		return new OAuthConfigurationException(reason);
	}
}
