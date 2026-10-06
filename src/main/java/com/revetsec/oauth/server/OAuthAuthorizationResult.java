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

package com.revetsec.oauth.server;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import com.google.errorprone.annotations.CheckReturnValue;
import javax.annotation.concurrent.Immutable;
import java.util.Optional;
import static java.util.Objects.requireNonNull;
/**
 * A library-created outcome. Applications cannot mint outcomes or proofs. Future variants require a rejecting
 * switch default. Diagnostics disclose no interaction, credential, identity or claims. Infrastructure failures
 * remain exceptions and cannot be reported as credential rejection.
 * @since 1.0.0
 */
@Immutable
public abstract sealed class OAuthAuthorizationResult permits OAuthAuthorizationResult.InteractionRequired, OAuthAuthorizationResult.Completed, OAuthAuthorizationResult.Denied, OAuthAuthorizationResult.Rejected {
	OAuthAuthorizationResult() {}
	static @NonNull OAuthAuthorizationResult fromInteractionRequired(@NonNull OAuthServerInteraction interaction) { return new InteractionRequired(requireNonNull(interaction)); }
	static @NonNull OAuthAuthorizationResult fromCompleted(@NonNull OAuthServerResponse response) { return new Completed(requireNonNull(response)); }
	static @NonNull OAuthAuthorizationResult fromDenied(@NonNull OAuthServerResponse response) { return new Denied(requireNonNull(response)); }
	static @NonNull OAuthAuthorizationResult fromRejection(OAuthServerException.@NonNull Reason reason, @NonNull OAuthServerResponse response) {
		requireNonNull(reason).requireKind(OAuthServerException.Kind.VALIDATION);
		return new Rejected(reason,requireNonNull(response));
	}
	/** Returns a fixed redacted description.
	 * @return fixed redacted description
	 * @since 1.0.0
	 */
	@Override public final @NonNull String toString() { return "OAuthAuthorizationResult{<redacted>}"; }
	/** The library-created InteractionRequired outcome.
	 * @since 1.0.0
	 */
	@Immutable public static final class InteractionRequired extends OAuthAuthorizationResult {
		private final @NonNull OAuthServerInteraction interaction;
		private InteractionRequired(@NonNull OAuthServerInteraction interaction) { this.interaction=interaction; }
		/** Returns the restricted interaction.
		 * @return interaction
		 * @since 1.0.0
		 */
		@CheckReturnValue public @NonNull OAuthServerInteraction getInteraction() { return this.interaction; }
	}
	/** The library-created Completed outcome.
	 * @since 1.0.0
	 */
	@Immutable public static final class Completed extends OAuthAuthorizationResult {
		private final @NonNull OAuthServerResponse response;
		private Completed(@NonNull OAuthServerResponse response) { this.response=response; }
		/** Returns the restricted response.
		 * @return response
		 * @since 1.0.0
		 */
		@CheckReturnValue public @NonNull OAuthServerResponse getResponse() { return this.response; }
	}
	/** The library-created Denied outcome.
	 * @since 1.0.0
	 */
	@Immutable public static final class Denied extends OAuthAuthorizationResult {
		private final @NonNull OAuthServerResponse response;
		private Denied(@NonNull OAuthServerResponse response) { this.response=response; }
		/** Returns the restricted response.
		 * @return response
		 * @since 1.0.0
		 */
		@CheckReturnValue public @NonNull OAuthServerResponse getResponse() { return this.response; }
	}
	/** A fixed rejection with no proof, request, credential, identity, claims or exception object.
	 * @since 1.0.0
	 */
	@Immutable public static final class Rejected extends OAuthAuthorizationResult {
		private final OAuthServerException.@NonNull Reason reason;
		private final @NonNull OAuthServerResponse response;
		private Rejected(OAuthServerException.@NonNull Reason reason, @NonNull OAuthServerResponse response) { this.reason=reason; this.response=response; }
		/** Returns the fixed issuer rejection reason, not an external error string.
		 * @return fixed reason
		 * @since 1.0.0
		 */
		@CheckReturnValue public OAuthServerException.@NonNull Reason getReason() { return this.reason; }
		/** Returns the safe library-prepared local rejection response.
		 * @return restricted response
		 * @since 1.0.0
		 */
		@CheckReturnValue public @NonNull OAuthServerResponse getResponse() { return this.response; }
	}
}
