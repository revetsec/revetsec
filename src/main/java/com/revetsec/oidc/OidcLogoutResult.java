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

import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;
import static java.util.Objects.requireNonNull;

/**
 * A correlated browser return or fixed rejection. Returned proves only correlation; it establishes neither
 * authenticated identity nor termination of every provider session. A sealed cookie has no atomic concurrent
 * single-use guarantee; a shared atomic store's contract and qualification remain application responsibilities.
 * Future releases may add variants; consuming switches should include a rejecting default branch.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public abstract sealed class OidcLogoutResult permits OidcLogoutResult.Returned, OidcLogoutResult.Rejected {
	private OidcLogoutResult() { }
	static @NonNull OidcLogoutResult returned() { return new Returned(); }
	static @NonNull OidcLogoutResult rejected(@NonNull Reason reason) { return new Rejected(requireNonNull(reason)); }
	/** Redacts correlation data.
	 * @return redacted description
	 * @since 1.0.0
	 */
	@Override public final @NonNull String toString() { return "OidcLogoutResult{outcome=" + getClass().getSimpleName() + ", data=<redacted>}"; }
	/**
	 * Correlation succeeded. No identity, credential, redirect target or provider-session termination proof is released.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Returned extends OidcLogoutResult { private Returned() { } }
	/**
	 * The callback did not satisfy the selected correlation profile.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Rejected extends OidcLogoutResult {
		private final @NonNull Reason reason;
		private Rejected(@NonNull Reason reason) { this.reason = reason; }
		/** Returns the fixed rejection reason.
		 * @return reason
		 * @since 1.0.0
		 */
		public @NonNull Reason getReason() { return this.reason; }
	}
	/**
	 * Value-free callback rejection reasons. Later releases may add reasons.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public enum Reason {
		/** The return query is outside the selected state-only grammar. */ MALFORMED_RETURN,
		/** The trusted actual callback differs from the configured callback. */ CALLBACK_MISMATCH,
		/** No matching pending record was available. */ PENDING_NOT_FOUND,
		/** The pending record is malformed, wrongly typed or outside its creation interval. */ PENDING_INVALID,
		/** The exact pending expiry has been reached. */ PENDING_EXPIRED,
		/** The returned state differs from the pending state. */ STATE_MISMATCH,
		/** The browser binding differs from the record's binding. */ BROWSER_BINDING_MISMATCH,
		/** The pending client, issuer or callback differs from this client. */ CLIENT_MISMATCH
	}
}
