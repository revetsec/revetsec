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
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import java.io.IOException;

import static java.util.Objects.requireNonNull;

/**
 * A network failure, interruption, attempt-limit hold or unavailable HTTP client.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@NotThreadSafe
public final class OAuthTransportException extends OAuthException {
	private static final long serialVersionUID = 1L;

	private OAuthTransportException(@NonNull Reason reason, @Nullable IOException cause) {
		super(reason, reason == Reason.NETWORK_FAILURE || reason == Reason.ATTEMPT_LIMIT, cause);
	}

	@NonNull
	static OAuthTransportException fromReason(@NonNull Reason reason, @Nullable IOException cause) {
		requireNonNull(reason);
		if (reason.category() != ErrorCategory.TRANSPORT && reason != Reason.HTTP_CLIENT_UNAVAILABLE)
			throw new IllegalArgumentException("The OAuth reason is not a transport or client-configuration reason.");
		if (reason == Reason.HTTP_CLIENT_UNAVAILABLE && cause != null)
			throw new IllegalArgumentException("A configuration failure cannot retain a cause.");
		return new OAuthTransportException(reason, cause);
	}
}
