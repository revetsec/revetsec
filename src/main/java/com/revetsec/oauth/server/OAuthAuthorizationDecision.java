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

import com.google.errorprone.annotations.CheckReturnValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Trusted application authorization decision; it is not a verified authentication or token proof.
 * An allowed decision has one exact resource and an issuer-local subject. An explicit empty scope set is
 * representable for policy denial and never authorizes a zero-scope credential. The issuer must enforce the
 * interaction/client/server subsets and continuing subject identity before issuance. Applications authenticate
 * users and protect their login/consent submissions and sessions themselves.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class OAuthAuthorizationDecision {
	private static final @NonNull OAuthAuthorizationDecision DENIED = new OAuthAuthorizationDecision(null, Map.of(), false);
	private final @Nullable String subject;
	private final @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> authorizedScopesByResource;
	private final boolean refreshTokenPermitted;
	private OAuthAuthorizationDecision(@Nullable String subject,
			@NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> resources, boolean refreshTokenPermitted) {
		this.subject = subject; this.authorizedScopesByResource = Map.copyOf(resources); this.refreshTokenPermitted = refreshTokenPermitted;
	}
	/**
	 * Returns an explicit application denial, without a subject or grant.
	 * @return the denied decision
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull OAuthAuthorizationDecision deniedInstance() { return DENIED; }
	/**
	 * Starts a decision for an application-authenticated issuer-local subject.
	 * @param subject the exact nonempty subject, at most 1024 UTF-16 code units
	 * @return the builder
	 * @throws NullPointerException if subject is null
	 * @throws IllegalArgumentException if subject is invalid
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull Builder withSubject(@NonNull String subject) { return new Builder(subject); }
	/**
	 * Returns whether the application explicitly denied authorization.
	 * @return the configured value
	 * @since 1.0.0
	 */
	public @NonNull Boolean isDenied() { return this.subject == null; }
	/**
	 * Returns the application subject, absent for explicit denial.
	 * @return the configured value
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull String> getSubject() { return Optional.ofNullable(this.subject); }
	/**
	 * Returns the immutable complete resource/scope decision.
	 * @return the configured value
	 * @since 1.0.0
	 */
	public @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> getAuthorizedScopesByResource() { return this.authorizedScopesByResource; }
	/**
	 * Returns application refresh permission, subject to the server and client policies.
	 * @return the configured value
	 * @since 1.0.0
	 */
	public @NonNull Boolean isRefreshTokenPermitted() { return this.refreshTokenPermitted; }
	/**
	 * Redacts all decision values from diagnostics.
	 * @return a fixed description
	 * @since 1.0.0
	 */
	@Override public @NonNull String toString() { return "OAuthAuthorizationDecision{decision=<redacted>}"; }
	/**
	 * Replacing decision builder. Null scope maps clear a required setting; null refresh permission resets false.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	@CheckReturnValue
	public static final class Builder {
		private final @NonNull String subject;
		private @Nullable Map<@NonNull String, @NonNull Set<@NonNull String>> authorizedScopesByResource;
		private boolean refreshTokenPermitted;
		private Builder(@NonNull String subject) {
			this.subject = OAuthServerConfiguration.text(subject, OAuthServerConfiguration.MAXIMUM_SUBJECT_LENGTH);
		}
		/**
		 * Snapshots a complete one-resource decision. An empty scope set is retained; null clears the required map.
		 * @param value the replacement value, or null to reset
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder authorizedScopesByResource(@Nullable Map<@NonNull String, @NonNull Set<@NonNull String>> value) {
			this.authorizedScopesByResource = value == null ? null : OAuthServerConfiguration.resources(value, 1);
			return this;
		}
		/**
		 * Sets application refresh permission; null resets to false.
		 * @param value the replacement value, or null to reset
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder refreshTokenPermitted(@Nullable Boolean value) {
			this.refreshTokenPermitted = Boolean.TRUE.equals(value);
			return this;
		}
		/**
		 * Builds a trusted app decision without authentication or I/O.
		 * @return the immutable decision
		 * @throws IllegalStateException if the resource/scope map is missing
		 * @since 1.0.0
		 */
		public @NonNull OAuthAuthorizationDecision build() {
			Map<String, Set<String>> resources = this.authorizedScopesByResource;
			if (resources == null) throw new IllegalStateException("An authorization resource/scope decision is required.");
			return new OAuthAuthorizationDecision(this.subject, resources, this.refreshTokenPermitted);
		}
		/**
		 * Redacts mutable decision values from diagnostics.
		 * @return a fixed description
		 * @since 1.0.0
		 */
		@Override public @NonNull String toString() { return "OAuthAuthorizationDecision.Builder{decision=<redacted>}"; }
	}
}
