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

package com.revetsec;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.NotThreadSafe;

/**
 * Thrown when a sealed value cannot be opened.
 * <p>
 * Every failure to open a sealed value throws this one exception, with the same fixed message, no cause and nothing
 * suppressed: a value that was tampered with, truncated, malformed, sealed for a different context, sealed under a
 * key that is not configured, or expired. The exception deliberately does not say which, so it cannot help anyone
 * probe the sealer.
 * <p>
 * Its category is {@link ErrorCategory#VALIDATION_FAILURE}, and it is never transient: retrying with the same
 * sealed value always fails the same way.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@NotThreadSafe
public final class InvalidSealedStateException extends RevetsecException {
	/**
	 * The serialized form's version.
	 */
	private static final long serialVersionUID = 1L;

	private static final String MESSAGE = "Sealed state is invalid.";

	/**
	 * Returns a new instance for any failure to open a sealed value. Only Revetsec's sealer calls this.
	 *
	 * @return a new instance, with the fixed message and no cause
	 */
	@NonNull
	static InvalidSealedStateException fromAnyFailure() {
		return new InvalidSealedStateException();
	}

	private InvalidSealedStateException() {
		super(ErrorCategory.VALIDATION_FAILURE, false, MESSAGE, null);
	}
}
