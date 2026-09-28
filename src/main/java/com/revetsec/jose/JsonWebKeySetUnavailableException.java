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
import com.revetsec.RevetsecException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import java.io.IOException;

import static java.util.Objects.requireNonNull;

/**
 * Thrown when a {@link RemoteJsonWebKeySource} has no usable JSON Web Key Set for a call: the fetch failed, a
 * recent failure is still suppressing fetches, the limit of two requests per cooldown held the call back, or the
 * call's deadline ended while it waited for another caller's fetch.
 * <p>
 * Its category says what went wrong, and there is no separate reason:
 * <ul>
 *   <li>{@link ErrorCategory#TRANSPORT}: the exchange timed out or failed with an I/O error, the call's deadline
 *   ended while it waited, or the limit of two requests per cooldown held the call back and no request was sent (all
 *   transient; {@link JoseObserver#didSuppressJsonWebKeySetFetch(java.net.URI, java.time.Duration)} reports the
 *   last), or this thread was interrupted (not transient, with the interrupt flag set again);</li>
 *   <li>{@link ErrorCategory#REMOTE_ERROR}: the server answered with an error status (transient for 429 and 5xx) or a
 *   redirect, which is never followed;</li>
 *   <li>{@link ErrorCategory#MALFORMED_INPUT}: the response or the key set document was malformed or too large;</li>
 *   <li>{@link ErrorCategory#CONFIGURATION}: the fetch cannot run in this configuration or runtime, such as a default
 *   HTTP client that could not be created.</li>
 * </ul>
 * The message is fixed for each category and never contains the URI, a header or the response body. Only the caller
 * whose request ended in an I/O error keeps the JDK's {@link IOException} as the cause; every other instance has
 * none. Revetsec never wraps this exception: a validator that needed the key set throws it unchanged.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@NotThreadSafe
public final class JsonWebKeySetUnavailableException extends RevetsecException {
	/**
	 * The serialized form's version.
	 */
	private static final long serialVersionUID = 1L;

	private JsonWebKeySetUnavailableException(@NonNull ErrorCategory category,
																						@NonNull Boolean transientFailure,
																						@Nullable IOException cause) {
		// messageFor checks the category inside the super(...) arguments, so a failed construction leaves no partial
		// instance; RevetsecException checks the transience and the cause.
		super(category, transientFailure, messageFor(category), cause);
	}

	/**
	 * Returns a new instance with no cause. Only Revetsec calls this.
	 *
	 * @param category         {@link ErrorCategory#TRANSPORT}, {@link ErrorCategory#REMOTE_ERROR},
	 *                         {@link ErrorCategory#MALFORMED_INPUT} or {@link ErrorCategory#CONFIGURATION}
	 * @param transientFailure whether retrying later may succeed; only a {@code TRANSPORT} or {@code REMOTE_ERROR}
	 *                         failure may be transient
	 * @return a new instance
	 * @throws IllegalArgumentException if the category is not one of the four, or a category that is never transient
	 *                                  is marked transient
	 */
	@NonNull
	static JsonWebKeySetUnavailableException fromCategory(@NonNull ErrorCategory category,
																												@NonNull Boolean transientFailure) {
		return new JsonWebKeySetUnavailableException(requireNonNull(category), requireNonNull(transientFailure), null);
	}

	/**
	 * Returns a new instance that keeps the JDK's {@link IOException} as its cause. Only Revetsec calls this, for the
	 * caller whose own request failed with that I/O error.
	 *
	 * @param category         {@link ErrorCategory#TRANSPORT}, the only category that keeps a cause
	 * @param transientFailure whether retrying later may succeed
	 * @param cause            the JDK's I/O error, or {@code null} for none
	 * @return a new instance
	 * @throws IllegalArgumentException if the category is not one of the four, a category that is never transient is
	 *                                  marked transient, or a cause is given for a category other than
	 *                                  {@code TRANSPORT}
	 */
	@NonNull
	static JsonWebKeySetUnavailableException fromCategory(@NonNull ErrorCategory category,
																												@NonNull Boolean transientFailure,
																												@Nullable IOException cause) {
		return new JsonWebKeySetUnavailableException(requireNonNull(category), requireNonNull(transientFailure), cause);
	}

	/**
	 * The fixed message of each category a key set failure can have.
	 *
	 * @throws IllegalArgumentException for any other category
	 */
	@NonNull
	private static String messageFor(@NonNull ErrorCategory category) {
		return switch (requireNonNull(category)) {
			case TRANSPORT -> "The JSON Web Key Set could not be fetched.";
			case REMOTE_ERROR -> "The JSON Web Key Set endpoint answered with an error.";
			case MALFORMED_INPUT -> "The JSON Web Key Set response is malformed.";
			case CONFIGURATION -> "The JSON Web Key Set cannot be fetched in this configuration.";
			default -> throw new IllegalArgumentException("A JSON Web Key Set failure is TRANSPORT, REMOTE_ERROR, "
					+ "MALFORMED_INPUT or CONFIGURATION.");
		};
	}
}
