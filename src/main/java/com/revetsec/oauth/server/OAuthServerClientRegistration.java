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
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Immutable application-owned client registration. Identifiers and redirects retain their exact spelling.
 * This configuration grants no user identity or permission. HTTP redirects are admitted only for the exact
 * literal loopbacks 127.0.0.1/[::1] or localhost; their use still requires the server's separate explicit opt-ins.
 * Introspection authority is independent of authorization-code scopes and requires confidential Basic verification.
 * Carrier bounds admit the server's maximum configurable capacities; the server applies its configured limits.
 * Construction performs no callback or I/O.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class OAuthServerClientRegistration {
	private final @NonNull String clientId;
	private final @NonNull List<@NonNull URI> redirectUris;
	private final @NonNull OAuthServerClientAuthentication authentication;
	private final @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> allowedScopesByResource;
	private final boolean refreshTokenPermitted;
	private final boolean authorizationCodePermitted;
	private final @NonNull Set<@NonNull String> introspectionResources;
	private final @Nullable String clientName;
	private final @NonNull String configurationVersion;
	private OAuthServerClientRegistration(@NonNull Builder builder, @NonNull String version,
			@NonNull List<@NonNull URI> redirects,
			@NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> resources) {
		this.clientId = builder.clientId; this.redirectUris = List.copyOf(redirects); this.authentication = builder.authentication;
		this.allowedScopesByResource = Map.copyOf(resources); this.refreshTokenPermitted = builder.refreshTokenPermitted;
		this.authorizationCodePermitted = builder.authorizationCodePermitted;
		this.introspectionResources = builder.introspectionResources; this.clientName = builder.clientName;
		this.configurationVersion = version;
	}
	/**
	 * Starts a public-client registration permitting authorization codes and no refresh tokens.
	 * @param clientId the exact nonempty identifier, at most 4096 UTF-16 code units
	 * @return the builder
	 * @throws NullPointerException if clientId is null
	 * @throws IllegalArgumentException if clientId is invalid
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull Builder withClientId(@NonNull String clientId) { return new Builder(clientId); }
	/**
	 * Returns the exact client identifier.
	 * @return the configured value
	 * @since 1.0.0
	 */
	public @NonNull String getClientId() { return this.clientId; }
	/**
	 * Returns an immutable redirect list in configured order; URI spelling is unchanged.
	 * @return the configured value
	 * @since 1.0.0
	 */
	public @NonNull List<@NonNull URI> getRedirectUris() { return this.redirectUris; }
	/**
	 * Returns the trusted authentication policy.
	 * @return the configured value
	 * @since 1.0.0
	 */
	public @NonNull OAuthServerClientAuthentication getAuthentication() { return this.authentication; }
	/**
	 * Returns the immutable exact resource/scope registry.
	 * @return the configured value
	 * @since 1.0.0
	 */
	public @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> getAllowedScopesByResource() { return this.allowedScopesByResource; }
	/**
	 * Returns whether this client permits refresh, subject to server and application approval.
	 * @return the configured value
	 * @since 1.0.0
	 */
	public @NonNull Boolean isRefreshTokenPermitted() { return this.refreshTokenPermitted; }
	/**
	 * Returns whether this client may request authorization codes.
	 * @return the configured value
	 * @since 1.0.0
	 */
	public @NonNull Boolean isAuthorizationCodePermitted() { return this.authorizationCodePermitted; }
	/**
	 * Returns the explicit resources whose tokens this client may introspect.
	 * @return the configured value
	 * @since 1.0.0
	 */
	public @NonNull Set<@NonNull String> getIntrospectionResources() { return this.introspectionResources; }
	/**
	 * Returns optional display text, which applications must escape before rendering.
	 * @return the configured value
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull String> getClientName() { return Optional.ofNullable(this.clientName); }
	/**
	 * Returns the application version binding for rechecking changed configuration.
	 * @return the configured value
	 * @since 1.0.0
	 */
	public @NonNull String getConfigurationVersion() { return this.configurationVersion; }
	/**
	 * Redacts identifiers, callbacks and registration values from diagnostics.
	 * @return a fixed description
	 * @since 1.0.0
	 */
	@Override public @NonNull String toString() { return "OAuthServerClientRegistration{configuration=<redacted>}"; }
	/**
	 * Replacing, snapshotting registration builder. Null setters reset defaults or clear required values.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	@CheckReturnValue
	public static final class Builder {
		private final @NonNull String clientId;
		private @Nullable List<@NonNull URI> redirectUris;
		private @NonNull OAuthServerClientAuthentication authentication = OAuthServerClientAuthentication.publicClientInstance();
		private @Nullable Map<@NonNull String, @NonNull Set<@NonNull String>> allowedScopesByResource;
		private boolean refreshTokenPermitted;
		private boolean authorizationCodePermitted = true;
		private @NonNull Set<@NonNull String> introspectionResources = Set.of();
		private @Nullable String clientName;
		private @Nullable String configurationVersion;
		private Builder(@NonNull String clientId) {
			this.clientId = OAuthServerConfiguration.text(clientId, OAuthServerConfiguration.MAXIMUM_CLIENT_ID_LENGTH);
		}
		/**
		 * Snapshots at most 64 distinct exact redirects. Null clears the required browser setting.
		 * @param value the replacement value, or null to reset
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder redirectUris(@Nullable List<@NonNull URI> value) {
			this.redirectUris = value == null || value.isEmpty() && !this.authorizationCodePermitted ? null : OAuthServerConfiguration.redirects(value);
			return this;
		}
		/**
		 * Replaces authentication; null resets to public authentication.
		 * @param value the replacement value, or null to reset
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder authentication(@Nullable OAuthServerClientAuthentication value) {
			this.authentication = value == null ? OAuthServerClientAuthentication.publicClientInstance() : value;
			return this;
		}
		/**
		 * Snapshots exact resource/scopes. Null clears the required browser setting; empty scope sets are allowed.
		 * @param value the replacement value, or null to reset
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder allowedScopesByResource(@Nullable Map<@NonNull String, @NonNull Set<@NonNull String>> value) {
			this.allowedScopesByResource = value == null || value.isEmpty() && !this.authorizationCodePermitted ? null
					: OAuthServerConfiguration.resources(value, OAuthServerConfiguration.MAXIMUM_RESOURCES);
			return this;
		}
		/**
		 * Sets refresh permission; null resets to false.
		 * @param value the replacement value, or null to reset
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder refreshTokenPermitted(@Nullable Boolean value) {
			this.refreshTokenPermitted = Boolean.TRUE.equals(value);
			return this;
		}
		/**
		 * Sets code permission; null resets to true. False clears browser redirects/scopes; re-enabling requires replacement.
		 * @param value the replacement value, or null to reset
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder authorizationCodePermitted(@Nullable Boolean value) {
			this.authorizationCodePermitted = value == null || value;
			if (!this.authorizationCodePermitted) { this.redirectUris = null; this.allowedScopesByResource = null; }
			return this;
		}
		/**
		 * Snapshots explicit introspection authority; null resets to empty. Confidential authentication is required at build.
		 * @param value the replacement value, or null to reset
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder introspectionResources(@Nullable Set<@NonNull String> value) {
			this.introspectionResources = value == null ? Set.of() : OAuthServerConfiguration.introspectionResources(value);
			return this;
		}
		/**
		 * Sets optional display text, at most 4096 UTF-16 code units; null clears it.
		 * @param value the replacement value, or null to reset
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder clientName(@Nullable String value) {
			this.clientName = value == null ? null : OAuthServerConfiguration.text(value, OAuthServerConfiguration.MAXIMUM_TEXT_LENGTH);
			return this;
		}
		/**
		 * Sets the required nonempty application configuration version, at most 4096 UTF-16 code units; null clears it.
		 * @param value the replacement value, or null to reset
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder configurationVersion(@Nullable String value) {
			this.configurationVersion = value == null ? null : OAuthServerConfiguration.text(value, OAuthServerConfiguration.MAXIMUM_TEXT_LENGTH);
			return this;
		}
		/**
		 * Builds without invoking application callbacks or performing I/O.
		 * @return the immutable registration
		 * @throws IllegalStateException if version or required browser configuration is missing
		 * @throws IllegalArgumentException if introspection authority has public authentication
		 * @since 1.0.0
		 */
		public @NonNull OAuthServerClientRegistration build() {
			String version = this.configurationVersion;
			if (version == null) throw new IllegalStateException("A client configuration version is required.");
			List<URI> redirects = this.redirectUris;
			Map<String, Set<String>> resources = this.allowedScopesByResource;
			if (this.authorizationCodePermitted && (redirects == null || resources == null))
				throw new IllegalStateException("Authorization-code client configuration is required.");
			if (!this.introspectionResources.isEmpty() && !this.authentication.isConfidential()) throw OAuthServerConfiguration.invalid();
			return new OAuthServerClientRegistration(this, version, !this.authorizationCodePermitted || redirects == null ? List.of() : redirects,
					!this.authorizationCodePermitted || resources == null ? Map.of() : resources);
		}
		/**
		 * Redacts mutable registration configuration from diagnostics.
		 * @return a fixed description
		 * @since 1.0.0
		 */
		@Override public @NonNull String toString() { return "OAuthServerClientRegistration.Builder{configuration=<redacted>}"; }
	}
}
