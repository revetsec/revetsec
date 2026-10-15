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
 * The outcome of parsing a stored OIDC continuity reference. A parsed reference is not identity proof.
 * Invalid structure and invalid sealed state release no reference or failure details.
 * A later release may add variants; consuming switches should include a rejecting default branch.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public abstract sealed class OidcSessionReferenceParseResult permits OidcSessionReferenceParseResult.Succeeded,
		OidcSessionReferenceParseResult.Rejected {
	OidcSessionReferenceParseResult() { }
	static @NonNull OidcSessionReferenceParseResult fromReference(@NonNull OidcSessionReference reference) {
		return new Succeeded(requireNonNull(reference));
	}
	static @NonNull OidcSessionReferenceParseResult fromRejection() { return new Rejected(); }
	/**
	 * Returns a description with all reference data redacted.
	 * @return redacted description
	 * @since 1.0.0
	 */
	@Override public final @NonNull String toString() {
		return "OidcSessionReferenceParseResult{outcome=" + getClass().getSimpleName() + ", data=<redacted>}";
	}
	/**
	 * A structurally valid continuity reference was parsed. It supplies no authenticated identity.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Succeeded extends OidcSessionReferenceParseResult {
		private final @NonNull OidcSessionReference reference;
		private Succeeded(@NonNull OidcSessionReference reference) { this.reference = reference; }
		/**
		 * Returns the parsed continuity reference.
		 * @return reference, not authenticated identity
		 * @since 1.0.0
		 */
		public @NonNull OidcSessionReference getReference() { return this.reference; }
	}
	/**
	 * The stored reference could not be parsed or opened. No reference is released.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Rejected extends OidcSessionReferenceParseResult {
		private Rejected() { }
		/**
		 * Returns the fixed reference-rejection reason.
		 * @return rejection reason
		 * @since 1.0.0
		 */
		public OidcValidationException.@NonNull Reason getReason() {
			return OidcValidationException.Reason.SESSION_REFERENCE_INVALID;
		}
	}
}
