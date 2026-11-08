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
import javax.annotation.concurrent.NotThreadSafe;
import static java.util.Objects.requireNonNull;

/**
 * A fixed-diagnostic key import or explicit pair-check failure. No input, key or provider message, cause or
 * suppressed exception is retained. Only Revetsec constructs these exceptions.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@NotThreadSafe
public final class KeyImportException extends RevetsecException {
	private static final long serialVersionUID = 1L;
	/** The fixed, non-sensitive reason retained when this exception is serialized. */
	private final @NonNull Reason reason;

	private KeyImportException(@NonNull Reason reason) {
		super(requireNonNull(reason).category, reason == Reason.BUDGET_EXHAUSTED, reason.message, null);
		this.reason = reason;
	}

	static @NonNull KeyImportException fromReason(@NonNull Reason reason) { return new KeyImportException(reason); }

	/**
	 * Returns the fixed failure reason.
	 * @return the reason
	 * @since 1.0.0
	 */
	public @NonNull Reason getReason() { return this.reason; }

	/**
	 * Fixed reasons; later versions may add reasons, so application switches need a default branch.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public enum Reason {
		/** The input exceeds the fixed representation ceiling. */
		INPUT_TOO_LARGE(ErrorCategory.MALFORMED_INPUT, "The key import input exceeds its size limit."),
		/** Armor, Base64 or a selected key structure is malformed or noncanonical. */
		MALFORMED_INPUT(ErrorCategory.MALFORMED_INPUT, "The key import input is malformed."),
		/** The algorithm, parameters, label or container profile is not selected. */
		UNSUPPORTED_KEY(ErrorCategory.UNSUPPORTED, "The key import profile is not supported."),
		/** The decoded key fails the selected strength or point policy. */
		KEY_REJECTED(ErrorCategory.VALIDATION_FAILURE, "The imported key does not satisfy the key policy."),
		/** The probe signature does not agree with the checked public key. */
		KEY_PAIR_MISMATCH(ErrorCategory.CONFIGURATION, "The key pair does not match."),
		/** A trusted synchronous provider cannot complete the operation. */
		OPERATION_UNAVAILABLE(ErrorCategory.CONFIGURATION, "The key import operation is unavailable."),
		/** The original monotonic budget is exhausted. */
		BUDGET_EXHAUSTED(ErrorCategory.TRANSPORT, "The key pair check budget is exhausted."),
		/** The calling thread remains interrupted. */
		CANCELLED(ErrorCategory.TRANSPORT, "The key pair check was interrupted.");

		private final @NonNull ErrorCategory category;
		private final @NonNull String message;
		Reason(@NonNull ErrorCategory category, @NonNull String message) { this.category = category; this.message = message; }
	}
}
