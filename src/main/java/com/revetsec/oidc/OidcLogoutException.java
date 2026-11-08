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

package com.revetsec.oidc;

import com.revetsec.ErrorCategory;
import com.revetsec.RevetsecException;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import static java.util.Objects.requireNonNull;

/**
 * A fixed configuration, preparation, storage or runtime failure in RP-Initiated Logout.
 * No token, input, provider exception, cause or suppressed value is retained. Local session termination remains
 * the application's responsibility and is never undone by this failure. No automatic retry is performed.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@NotThreadSafe
public final class OidcLogoutException extends RevetsecException {
	private static final long serialVersionUID = 1L;
	/** The fixed reason retained when serialized. */
	private final @NonNull Reason reason;
	private OidcLogoutException(@NonNull Reason reason) {
		super(requireNonNull(reason).category, reason == Reason.BUDGET_EXHAUSTED || reason == Reason.DISCOVERY_UNAVAILABLE, reason.message, null);
		this.reason = reason;
	}
	static @NonNull OidcLogoutException fromReason(@NonNull Reason reason) { return new OidcLogoutException(reason); }
	/** Returns the fixed failure reason.
	 * @return reason
	 * @since 1.0.0
	 */
	public @NonNull Reason getReason() { return this.reason; }
	/**
	 * Fixed reasons. Future releases may add reasons; switches should include a rejecting default branch.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public enum Reason {
		/** No fixed post-logout callback was configured. */
		LOGOUT_NOT_CONFIGURED(ErrorCategory.CONFIGURATION, "OIDC logout is not configured."),
		/** The provider does not advertise the selected logout endpoint. */
		END_SESSION_UNSUPPORTED(ErrorCategory.UNSUPPORTED, "The provider does not support the selected logout request."),
		/** The endpoint failed URI or reserved-parameter policy. */
		ENDPOINT_NOT_PERMITTED(ErrorCategory.CONFIGURATION, "The OIDC logout endpoint is not permitted."),
		/** A hint or authenticated source belongs to a different client or original reference. */
		HINT_MISMATCH(ErrorCategory.CONFIGURATION, "The OIDC logout hint does not match the client and original reference."),
		/** A selected logout representation exceeded its fixed profile. */
		INPUT_LIMIT(ErrorCategory.CONFIGURATION, "The OIDC logout value exceeds its selected profile."),
		/** The configured sealer cannot represent this bounded hint or pending record. */
		STORAGE_PROFILE_UNSUPPORTED(ErrorCategory.CONFIGURATION, "The configured storage profile cannot represent OIDC logout state."),
		/** A trusted clock, entropy, policy or sealing provider could not complete the operation. */
		PROVIDER_UNAVAILABLE(ErrorCategory.CONFIGURATION, "The OIDC logout operation is unavailable."),
		/** A transport or held-back discovery attempt did not complete. */
		DISCOVERY_UNAVAILABLE(ErrorCategory.TRANSPORT, "OIDC logout discovery is unavailable."),
		/** A store call may have consumed the pending record; safe retry is not established. */
		STORE_INDETERMINATE(ErrorCategory.CONFIGURATION, "The OIDC logout store outcome is indeterminate."),
		/** The original operation budget is exhausted. */
		BUDGET_EXHAUSTED(ErrorCategory.TRANSPORT, "The OIDC logout budget is exhausted."),
		/** The calling thread remains interrupted. */
		INTERRUPTED(ErrorCategory.TRANSPORT, "The OIDC logout operation was interrupted.");
		private final @NonNull ErrorCategory category;
		private final @NonNull String message;
		Reason(@NonNull ErrorCategory category, @NonNull String message) { this.category = category; this.message = message; }
	}
}
