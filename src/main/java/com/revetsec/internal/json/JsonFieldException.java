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

package com.revetsec.internal.json;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;

import static java.util.Objects.requireNonNull;

/**
 * Checked failure of {@link JsonFields} or {@link Rfc7638} on a member of an untrusted JSON object (M1 plan, G6-2).
 * <p>
 * Like {@link JsonParseException}, the message is the fixed sentence of its {@link Kind} and never contains the
 * member's name or value, so the exception is safe to log (R9). It has no cause, and suppression is disabled. Entry
 * points translate it into the protocol's own exception, which names the member through its reason.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@NotThreadSafe
public final class JsonFieldException extends Exception {
	private static final long serialVersionUID = 1L;

	/**
	 * Why the member was rejected.
	 */
	private final @NonNull Kind kind;

	/**
	 * What was wrong with the member. Each kind has one fixed message.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 */
	@Immutable
	public enum Kind {
		/**
		 * A required member is absent.
		 */
		MISSING("A required JSON member is missing."),
		/**
		 * The member holds a value of another JSON type ({@code null} included).
		 */
		WRONG_TYPE("A JSON member has the wrong type."),
		/**
		 * The member's value has the right type but is outside the range the field allows.
		 */
		OUT_OF_RANGE("A JSON member's value is out of range."),
		/**
		 * The member's value has the right type but is not one this operation supports.
		 */
		UNSUPPORTED("A JSON member's value is not supported.");

		private final @NonNull String message;

		Kind(@NonNull String message) {
			this.message = message;
		}

		/**
		 * The fixed message for this kind.
		 *
		 * @return the message, which never contains input
		 */
		public @NonNull String getMessage() {
			return this.message;
		}
	}

	JsonFieldException(@NonNull Kind kind) {
		super(requireNonNull(kind).getMessage(), null, false, true);
		this.kind = kind;
	}

	/**
	 * Why the member was rejected.
	 *
	 * @return the kind of failure
	 */
	public @NonNull Kind getKind() {
		return this.kind;
	}
}
