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
 * Thrown when a token or a JSON Web Key Set document cannot be parsed, or exceeds a limit.
 * <p>
 * Its category is {@link ErrorCategory#MALFORMED_INPUT}, and its {@link JoseException.Reason} is one of
 * {@link JoseException.Reason#TOKEN_TOO_LARGE TOKEN_TOO_LARGE}, {@link JoseException.Reason#TOKEN_SYNTAX TOKEN_SYNTAX},
 * {@link JoseException.Reason#HEADER HEADER}, {@link JoseException.Reason#CLAIMS CLAIMS} and
 * {@link JoseException.Reason#KEY_SET KEY_SET}. It has no cause and is never transient.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@NotThreadSafe
public final class MalformedJoseInputException extends JoseException {
	/**
	 * The serialized form's version.
	 */
	private static final long serialVersionUID = 1L;

	private MalformedJoseInputException(@NonNull Reason reason) {
		super(reason);
	}

	/**
	 * Returns a new instance for {@code reason}. Only Revetsec calls this.
	 *
	 * @param reason a reason in category {@link ErrorCategory#MALFORMED_INPUT}
	 * @return a new instance
	 * @throws IllegalArgumentException if {@code reason} belongs to another category
	 */
	@NonNull
	static MalformedJoseInputException fromReason(@NonNull Reason reason) {
		if (requireNonNull(reason).category() != ErrorCategory.MALFORMED_INPUT)
			throw new IllegalArgumentException("A malformed-input reason must be in category MALFORMED_INPUT.");

		return new MalformedJoseInputException(reason);
	}
}
