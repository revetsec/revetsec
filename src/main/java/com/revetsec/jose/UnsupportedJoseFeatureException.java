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
 * Thrown when a token uses a JOSE feature that Revetsec does not support: encryption, the JSON serialization, a
 * critical header parameter, an unencoded or compressed payload, or a nested token.
 * <p>
 * Its category is {@link ErrorCategory#UNSUPPORTED}, and its {@link JoseException.Reason} is one of
 * {@link JoseException.Reason#ENCRYPTED_TOKEN ENCRYPTED_TOKEN},
 * {@link JoseException.Reason#JSON_SERIALIZATION JSON_SERIALIZATION},
 * {@link JoseException.Reason#CRITICAL_HEADER CRITICAL_HEADER},
 * {@link JoseException.Reason#UNENCODED_PAYLOAD UNENCODED_PAYLOAD},
 * {@link JoseException.Reason#COMPRESSED_PAYLOAD COMPRESSED_PAYLOAD} and
 * {@link JoseException.Reason#NESTED_TOKEN NESTED_TOKEN}. It has no cause and is never transient.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@NotThreadSafe
public final class UnsupportedJoseFeatureException extends JoseException {
	/**
	 * The serialized form's version.
	 */
	private static final long serialVersionUID = 1L;

	private UnsupportedJoseFeatureException(@NonNull Reason reason) {
		super(reason);
	}

	/**
	 * Returns a new instance for {@code reason}. Only Revetsec calls this.
	 *
	 * @param reason a reason in category {@link ErrorCategory#UNSUPPORTED}
	 * @return a new instance
	 * @throws IllegalArgumentException if {@code reason} belongs to another category
	 */
	@NonNull
	static UnsupportedJoseFeatureException fromReason(@NonNull Reason reason) {
		if (requireNonNull(reason).category() != ErrorCategory.UNSUPPORTED)
			throw new IllegalArgumentException("An unsupported-feature reason must be in category UNSUPPORTED.");

		return new UnsupportedJoseFeatureException(reason);
	}
}
