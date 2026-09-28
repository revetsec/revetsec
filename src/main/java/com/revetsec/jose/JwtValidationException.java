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

package com.revetsec.jose;

import com.revetsec.ErrorCategory;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.NotThreadSafe;

import static java.util.Objects.requireNonNull;

/**
 * Thrown when a well-formed token fails a check: its algorithm, key, signature, type, issuer, audience, lifetime,
 * required claims or confirmation claim.
 * <p>
 * Its category is {@link ErrorCategory#VALIDATION_FAILURE}, and its {@link JoseException.Reason} says which check
 * failed. It has no cause and is never transient.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@NotThreadSafe
public final class JwtValidationException extends JoseException {
	/**
	 * The serialized form's version.
	 */
	private static final long serialVersionUID = 1L;

	private JwtValidationException(@NonNull Reason reason) {
		super(reason);
	}

	/**
	 * Returns a new instance for {@code reason}. Only Revetsec calls this.
	 *
	 * @param reason a reason in category {@link ErrorCategory#VALIDATION_FAILURE}
	 * @return a new instance
	 * @throws IllegalArgumentException if {@code reason} belongs to another category
	 */
	@NonNull
	static JwtValidationException fromReason(@NonNull Reason reason) {
		if (requireNonNull(reason).category() != ErrorCategory.VALIDATION_FAILURE)
			throw new IllegalArgumentException("A validation reason must be in category VALIDATION_FAILURE.");

		return new JwtValidationException(reason);
	}
}
