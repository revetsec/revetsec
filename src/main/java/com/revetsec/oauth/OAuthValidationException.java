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

import javax.annotation.concurrent.NotThreadSafe;

import static java.util.Objects.requireNonNull;

/**
 * A pending authorization or OAuth security check failed. The fixed reason and message never include input or credentials.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@NotThreadSafe
public final class OAuthValidationException extends OAuthException {
	private static final long serialVersionUID = 1L;

	private OAuthValidationException(@NonNull Reason reason) {
		super(reason, false, null);
	}

	@NonNull
	static OAuthValidationException fromReason(@NonNull Reason reason) {
		if (requireNonNull(reason).category() != ErrorCategory.VALIDATION_FAILURE)
			throw new IllegalArgumentException("The OAuth reason has the wrong category.");
		return new OAuthValidationException(reason);
	}
}
