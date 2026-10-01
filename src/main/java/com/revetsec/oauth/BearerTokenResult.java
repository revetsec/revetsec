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

import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;
import static java.util.Objects.requireNonNull;

/**
 * The outcome of parsing materialized Authorization headers. A present token is unverified and grants no permission.
 * <p>
 * Applications receive these outcomes from the corresponding operation; they cannot construct them.
 * Value accessors exist only on the variant that owns a value. Diagnostic text contains no input or result data.
 * A later release may add variants; consuming switches should include a rejecting default branch.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public abstract sealed class BearerTokenResult permits BearerTokenResult.Absent, BearerTokenResult.Present, BearerTokenResult.Malformed {
	BearerTokenResult() { }

	static @NonNull BearerTokenResult fromAbsent() {
		return new Absent();
	}

	static @NonNull BearerTokenResult fromToken(@NonNull BearerToken token) {
		return new Present(requireNonNull(token));
	}

	static @NonNull BearerTokenResult fromMalformed() {
		return new Malformed();
	}

	/**
	 * Returns the outcome kind with all values redacted.
	 * @return redacted description
	 * @since 1.0.0
	 */
	@Override
	public final @NonNull String toString() {
		return "BearerTokenResult{outcome=" + getClass().getSimpleName() + ", data=<redacted>}";
	}

	/**
	 * No Authorization header was supplied.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Absent extends BearerTokenResult {
		private Absent() {  }
	}

	/**
	 * Exactly one header supplied a syntactically valid, unverified bearer credential.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Present extends BearerTokenResult {
		private final @NonNull BearerToken token;
		private Present(@NonNull BearerToken token) { this.token = token; }

		/**
		 * Returns the unverified credential; parsing establishes no identity.
		 * @return token
		 * @since 1.0.0
		 */
		public @NonNull BearerToken getToken() { return this.token; }
	}

	/**
	 * The supplied header values are malformed, duplicated or oversized.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Malformed extends BearerTokenResult {
		private Malformed() {  }
	}
}
