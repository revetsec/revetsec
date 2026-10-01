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
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import java.io.IOException;

import static java.util.Objects.requireNonNull;

/**
 * The root of every exception Revetsec throws for a condition that a remote party, the input or the runtime
 * environment can cause.
 * <p>
 * Programmer misuse, such as a {@code null} argument or an out-of-range setting, throws
 * {@link NullPointerException}, {@link IllegalArgumentException} or {@link IllegalStateException} instead.
 * <p>
 * Every instance has:
 * <ul>
 *   <li>an {@link ErrorCategory} ({@link #getCategory()});</li>
 *   <li>a transience flag ({@link #isTransient()}), which follows from the category and the cause alone, never
 *   from the exception's class: a {@link ErrorCategory#TRANSPORT} failure from a timeout or an I/O error, or from a
 *   request Revetsec held back so that it can be sent later, is transient, and so is a
 *   {@link ErrorCategory#REMOTE_ERROR} for HTTP 429 or 5xx or OAuth {@code error=temporarily_unavailable}. Nothing
 *   else is;</li>
 *   <li>a fixed, one-sentence message that never contains input, tokens, keys or other secrets;</li>
 *   <li>no cause, except the JDK {@link IOException} behind a {@link ErrorCategory#TRANSPORT} failure;</li>
 *   <li>suppression disabled, so {@link #addSuppressed(Throwable)} does nothing and {@link #getSuppressed()} is
 *   always empty.</li>
 * </ul>
 * The constructor is protected only so that Revetsec's own packages can extend this class. Applications catch
 * Revetsec exceptions; they do not subclass or construct them, except through the factories a type documents for
 * that purpose.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@NotThreadSafe
public abstract class RevetsecException extends RuntimeException {
	/**
	 * The serialized form's version.
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * The category of this failure; never {@code null}.
	 *
	 * @serial
	 */
	private final ErrorCategory category;

	/**
	 * Whether retrying the same operation later may succeed; never {@code null}.
	 *
	 * @serial
	 */
	private final Boolean transientFailure;

	/**
	 * Creates an exception with a fixed message and suppression disabled.
	 * <p>
	 * The arguments must follow the rules in the class description: only {@link ErrorCategory#TRANSPORT} and
	 * {@link ErrorCategory#REMOTE_ERROR} failures may be transient, and only a {@link ErrorCategory#TRANSPORT}
	 * failure may carry a cause, which must be the JDK's {@link IOException}.
	 *
	 * @param category         the category of this failure
	 * @param transientFailure whether retrying the same operation later may succeed
	 * @param fixedMessage     a fixed, non-blank, one-sentence message that contains no input and no secret
	 * @param cause            the JDK {@link IOException} behind a {@link ErrorCategory#TRANSPORT} failure, or
	 *                         {@code null}
	 * @throws NullPointerException     if {@code category}, {@code transientFailure} or {@code fixedMessage} is
	 *                                  {@code null}
	 * @throws IllegalArgumentException if the message is blank, a category other than {@code TRANSPORT} or
	 *                                  {@code REMOTE_ERROR} is marked transient, or a cause is given for a category
	 *                                  other than {@code TRANSPORT} or is not an {@link IOException}
	 * @since 1.0.0
	 */
	protected RevetsecException(@NonNull ErrorCategory category,
															@NonNull Boolean transientFailure,
															@NonNull String fixedMessage,
															@Nullable Throwable cause) {
		// Every check runs inside the super(...) arguments, before the object exists, so a failed construction
		// never leaves a partially initialized instance behind (SpotBugs CT_CONSTRUCTOR_THROW).
		super(checkedMessage(category, transientFailure, fixedMessage, cause), cause, false, true);
		this.category = category;
		this.transientFailure = transientFailure;
	}

	/**
	 * Returns the category of this failure.
	 *
	 * @return the category of this failure
	 * @since 1.0.0
	 */
	@NonNull
	public final ErrorCategory getCategory() {
		return this.category;
	}

	/**
	 * Returns whether retrying the same operation later may succeed.
	 * <p>
	 * It is {@code true} only for a {@link ErrorCategory#TRANSPORT} failure caused by a timeout or an I/O error, or
	 * by a request Revetsec held back so that it can be sent later, and for a {@link ErrorCategory#REMOTE_ERROR} with
	 * HTTP status 429 or 5xx or the OAuth error {@code temporarily_unavailable}. It is always {@code false} for an
	 * interrupted thread and for every other category.
	 *
	 * @return whether retrying the same operation later may succeed
	 * @since 1.0.0
	 */
	@NonNull
	public final Boolean isTransient() {
		return this.transientFailure;
	}

	private static @NonNull String checkedMessage(@NonNull ErrorCategory category,
																			 @NonNull Boolean transientFailure,
																			 @NonNull String fixedMessage,
																			 @Nullable Throwable cause) {
		requireNonNull(category);
		requireNonNull(transientFailure);
		requireNonNull(fixedMessage);

		if (fixedMessage.isBlank())
			throw new IllegalArgumentException("A Revetsec exception message must not be blank.");

		if (transientFailure && category != ErrorCategory.TRANSPORT && category != ErrorCategory.REMOTE_ERROR)
			throw new IllegalArgumentException("Only TRANSPORT and REMOTE_ERROR failures may be transient.");

		if (cause != null && (category != ErrorCategory.TRANSPORT || !(cause instanceof IOException)))
			throw new IllegalArgumentException("Only a TRANSPORT failure may keep a cause, and it must be an "
					+ "IOException.");

		return fixedMessage;
	}
}
