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
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import static java.util.Objects.requireNonNull;

/**
 * A failure to sign with an application-owned RSA key, or to verify the signature before releasing it.
 * Every reason has a fixed message without key, provider or credential contents. No cause or suppressed
 * exception is retained. Applications catch these exceptions; only Revetsec constructs them.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@NotThreadSafe
public final class JwsSigningException extends RevetsecException {
	private static final long serialVersionUID = 1L;
	/** The fixed, non-sensitive reason retained when this exception is serialized. */
	private final @NonNull Reason reason;

	private JwsSigningException(@NonNull Reason reason) {
		super(requireNonNull(reason).category, reason == Reason.BUDGET_EXHAUSTED, reason.message, null);
		this.reason = reason;
	}

	static @NonNull JwsSigningException fromReason(@NonNull Reason reason) {
		return new JwsSigningException(reason);
	}

	/**
	 * Returns why signing failed.
	 * @return the fixed reason
	 * @since 1.0.0
	 */
	public @NonNull Reason getReason() {
		return this.reason;
	}

	/**
	 * Why signing failed. Signing and pair failures are nontransient configuration failures; exhausted budgets
	 * are transient transport timeouts. Revetsec never retries signing automatically. Later releases may add
	 * reasons, so application switches need a default branch.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public enum Reason {
		/** The provider could not produce or verify a well-formed signature. */
		SIGNING_UNAVAILABLE(ErrorCategory.CONFIGURATION, "The JWS signing operation is unavailable."),
		/** The generated signature did not verify against the checked public key. */
		KEY_PAIR_MISMATCH(ErrorCategory.CONFIGURATION, "The JWS signing key pair does not match."),
		/** The supplied remaining budget was exhausted; no credential was released. */
		BUDGET_EXHAUSTED(ErrorCategory.TRANSPORT, "The JWS signing budget is exhausted.");

		private final @NonNull ErrorCategory category;
		private final @NonNull String message;

		Reason(@NonNull ErrorCategory category, @NonNull String message) {
			this.category = category;
			this.message = message;
		}
	}
}
