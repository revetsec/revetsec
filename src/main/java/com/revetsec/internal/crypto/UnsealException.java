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

package com.revetsec.internal.crypto;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;

import static java.util.Objects.requireNonNull;

/**
 * A checked failure to open a sealed value (M1 plan, G6-2 and "StateSealer v1").
 * <p>
 * It has two kinds. {@link Kind#EXPIRED} means the value is authentic but its notAfter has passed; it is reported
 * only after authentication, so it never tells anyone anything about a forged value. {@link Kind#INVALID} covers
 * every other failure, whichever unseal step found it. The protocol packages translate the kinds into their own
 * exceptions, so that pending state can report expiry separately, and the public {@code StateSealer} translates both
 * into its one {@code InvalidSealedStateException}.
 * <p>
 * The message is the fixed sentence of its kind. The exception has no cause, suppression is disabled, and it records
 * no stack trace, so nothing about it depends on the input or on which step failed. It never leaves Revetsec.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@NotThreadSafe
public final class UnsealException extends Exception {
	private static final long serialVersionUID = 1L;

	/**
	 * Why the value did not open.
	 */
	@NonNull
	private final Kind kind;

	/**
	 * Why a sealed value did not open.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 */
	@Immutable
	public enum Kind {
		/**
		 * The value is too long, malformed, sealed under a key that is not configured, sealed for another type or
		 * context, or tampered with.
		 */
		INVALID("The sealed state is invalid."),
		/**
		 * The value is authentic, but the current time is at or after its notAfter.
		 */
		EXPIRED("The sealed state has expired.");

		@NonNull
		private final String message;

		Kind(@NonNull String message) {
			this.message = message;
		}

		/**
		 * Returns the fixed message for this kind.
		 *
		 * @return the message, which never contains input
		 */
		@NonNull
		public String getMessage() {
			return this.message;
		}
	}

	UnsealException(@NonNull Kind kind) {
		super(requireNonNull(kind).getMessage(), null, false, false);
		this.kind = kind;
	}

	/**
	 * Returns why the value did not open.
	 *
	 * @return the kind of failure
	 */
	@NonNull
	public Kind getKind() {
		return this.kind;
	}
}
