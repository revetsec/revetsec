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

import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;
import static java.util.Objects.requireNonNull;

/**
 * The outcome of parsing a JSON Web Key Set document with the default size and key-count limits.
 * <p>
 * Applications receive these outcomes from the corresponding operation; they cannot construct them.
 * Value accessors exist only on the variant that owns a value. Diagnostic text contains no input or result data.
 * A later release may add variants; consuming switches should include a rejecting default branch.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public abstract sealed class JwksParseResult permits JwksParseResult.Succeeded, JwksParseResult.Rejected {
	JwksParseResult() { }

	static @NonNull JwksParseResult fromJwks(@NonNull Jwks jwks) {
		return new Succeeded(requireNonNull(jwks));
	}

	static @NonNull JwksParseResult fromReason(JoseException.@NonNull Reason reason) {
		return new Rejected(requireNonNull(reason));
	}

	/**
	 * Returns the outcome kind with all values redacted.
	 * @return redacted description
	 * @since 1.0.0
	 */
	@Override
	public final @NonNull String toString() {
		return "JwksParseResult{outcome=" + getClass().getSimpleName() + ", data=<redacted>}";
	}

	/**
	 * A JSON Web Key Set document passed the structural and resource-limit checks. Unusable individual keys were skipped.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Succeeded extends JwksParseResult {
		private final @NonNull Jwks jwks;
		private Succeeded(@NonNull Jwks jwks) { this.jwks = jwks; }

		/**
		 * Returns the parsed set of usable public verification keys.
		 * @return key set
		 * @since 1.0.0
		 */
		public @NonNull Jwks getJwks() { return this.jwks; }
	}

	/**
	 * The input was rejected; this variant contains only a fixed reason.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Rejected extends JwksParseResult {
		private final JoseException.@NonNull Reason reason;
		private Rejected(JoseException.@NonNull Reason reason) { this.reason = reason; }

		/**
		 * Returns the fixed JOSE rejection reason.
		 * @return reason
		 * @since 1.0.0
		 */
		public JoseException.@NonNull Reason getReason() { return this.reason; }
	}
}
