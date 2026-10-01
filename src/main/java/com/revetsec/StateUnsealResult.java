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
import javax.annotation.concurrent.Immutable;
import static java.util.Objects.requireNonNull;

/**
 * The outcome of opening sealed application state. Every opening failure has the same rejected outcome.
 * <p>
 * Applications receive these outcomes from the corresponding operation; they cannot construct them.
 * Value accessors exist only on the variant that owns a value. Diagnostic text contains no input or result data.
 * A later release may add variants; consuming switches should include a rejecting default branch.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public abstract sealed class StateUnsealResult permits StateUnsealResult.Succeeded, StateUnsealResult.Rejected {
	StateUnsealResult() { }

	static @NonNull StateUnsealResult fromValue(@NonNull String value) {
		return new Succeeded(requireNonNull(value));
	}

	static @NonNull StateUnsealResult fromRejection() {
		return new Rejected();
	}

	/**
	 * Returns the outcome kind with all values redacted.
	 * @return redacted description
	 * @since 1.0.0
	 */
	@Override
	public final @NonNull String toString() {
		return "StateUnsealResult{outcome=" + getClass().getSimpleName() + ", data=<redacted>}";
	}

	/**
	 * The state authenticated for the context and its lifetime has not ended.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Succeeded extends StateUnsealResult {
		private final @NonNull String value;
		private Succeeded(@NonNull String value) { this.value = value; }

		/**
		 * Returns the authenticated plaintext; it may contain application secrets.
		 * @return value
		 * @since 1.0.0
		 */
		public @NonNull String getValue() { return this.value; }
	}

	/**
	 * The state could not be opened. No failure step or plaintext is exposed.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Rejected extends StateUnsealResult {
		private Rejected() {  }
	}
}
