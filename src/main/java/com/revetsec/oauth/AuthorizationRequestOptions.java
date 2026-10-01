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
import org.jspecify.annotations.Nullable;

import com.google.errorprone.annotations.CheckReturnValue;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;


/**
 * Per-authorization options. Scope and resource setters replace the complete list for this request; they never add
 * silently to a client's defaults. Application data is authenticated as pending state but is never a safe redirect
 * destination without the application's own validation.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class AuthorizationRequestOptions {
	private static final Set<String> RESERVED = Set.of("response_type", "client_id", "redirect_uri", "state",
			"nonce", "code_challenge", "code_challenge_method", "scope", "resource", "response_mode", "prompt",
			"max_age", "login_hint", "acr_values", "request", "request_uri", "dpop_jkt");
	private final @NonNull Set<@NonNull String> scopes;
	private final boolean scopesOverridden;
	private final @NonNull List<@NonNull URI> resources;
	private final boolean resourcesOverridden;
	private final @NonNull ResponseMode responseMode;
	private final @Nullable String prompt;
	private final @Nullable String loginHint;
	private final @NonNull Map<@NonNull String, @NonNull String> applicationData;
	private final @NonNull Map<@NonNull String, @NonNull String> additionalParameters;

	private AuthorizationRequestOptions(@NonNull Builder builder) {
		this.scopes = Set.copyOf(builder.scopes);
		this.scopesOverridden = builder.scopesOverridden;
		this.resources = List.copyOf(builder.resources);
		this.resourcesOverridden = builder.resourcesOverridden;
		this.responseMode = builder.responseMode;
		this.prompt = builder.prompt;
		this.loginHint = builder.loginHint;
		this.applicationData = Map.copyOf(builder.applicationData);
		this.additionalParameters = Map.copyOf(builder.additionalParameters);
	}

	/**
	 * Starts a request with query callback delivery and no overrides.
	 *
	 * @return the builder
	 * @since 1.0.0
	 */
	public static @NonNull Builder builder() {
		return new Builder();
	}

	/**
	 * Returns the complete scope override, empty when no scopes were requested.
	 *
	 * @return the scopes
	 * @since 1.0.0
	 */
	public @NonNull Set<@NonNull String> getScopes() {
		return this.scopes;
	}

	boolean scopesOverridden() { return this.scopesOverridden; }
	boolean resourcesOverridden() { return this.resourcesOverridden; }

	/**
	 * Returns ordered RFC 8707 resource indicators.
	 *
	 * @return the resources
	 * @since 1.0.0
	 */
	public @NonNull List<@NonNull URI> getResources() {
		return this.resources;
	}

	/**
	 * Returns the trusted callback delivery mode requested for this flow.
	 *
	 * @return the mode
	 * @since 1.0.0
	 */
	public @NonNull ResponseMode getResponseMode() {
		return this.responseMode;
	}

	/**
	 * Returns the requested prompt, if any.
	 *
	 * @return the prompt
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull String> getPrompt() {
		return Optional.ofNullable(this.prompt);
	}

	/**
	 * Returns the login hint, if any. Treat it as user data when logging.
	 *
	 * @return the login hint
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull String> getLoginHint() {
		return Optional.ofNullable(this.loginHint);
	}

	/**
	 * Returns application data to authenticate in pending state.
	 *
	 * @return the data
	 * @since 1.0.0
	 */
	public @NonNull Map<@NonNull String, @NonNull String> getApplicationData() {
		return this.applicationData;
	}

	/**
	 * Returns additional nonreserved authorization parameters.
	 *
	 * @return the parameters
	 * @since 1.0.0
	 */
	public @NonNull Map<@NonNull String, @NonNull String> getAdditionalParameters() {
		return this.additionalParameters;
	}

	/**
	 * The trusted callback delivery mode.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public enum ResponseMode {
		/** URL query response, normally delivered by GET. */
		QUERY,
		/** UTF-8 form body response, delivered by POST. */
		FORM_POST
	}

	/**
	 * Mutable request-option builder.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	@CheckReturnValue
	public static final class Builder {
		private @NonNull Set<@NonNull String> scopes = Set.of();
		private boolean scopesOverridden;
		private @NonNull List<@NonNull URI> resources = List.of();
		private boolean resourcesOverridden;
		private @NonNull ResponseMode responseMode = ResponseMode.QUERY;
		private @Nullable String prompt;
		private @Nullable String loginHint;
		private @NonNull Map<@NonNull String, @NonNull String> applicationData = Map.of();
		private @NonNull Map<@NonNull String, @NonNull String> additionalParameters = Map.of();

		private Builder() {
		}

		/**
		 * Replaces the complete requested scope set.
		 *
		 * @param value scopes, or null which restores inheritance
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder scopes(@Nullable Set<@NonNull String> value) {
			this.scopes = value == null ? Set.of() : Set.copyOf(value);
			this.scopesOverridden = value != null;
			for (String scope : this.scopes)
				if (scope.isEmpty() || scope.chars().anyMatch(c -> c <= 0x20 || c == 0x22 || c == 0x5C || c >= 0x7F))
					throw new IllegalArgumentException("A scope contains invalid characters.");
			return this;
		}

		/**
		 * Replaces the complete ordered resource list.
		 *
		 * @param value resources, or null which restores inheritance
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder resources(@Nullable List<@NonNull URI> value) {
			this.resources = value == null ? List.of() : List.copyOf(value);
			this.resourcesOverridden = value != null;
			for (URI resource : this.resources)
				if (!resource.isAbsolute() || resource.getFragment() != null)
					throw new IllegalArgumentException("A resource indicator must be absolute and fragment-free.");
			return this;
		}

		/**
		 * Sets the requested callback delivery mode.
		 *
		 * @param value the mode, or null which restores the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder responseMode(@Nullable ResponseMode value) {
			this.responseMode = value == null ? ResponseMode.QUERY : value;
			return this;
		}

		/**
		 * Sets an optional prompt.
		 *
		 * @param value the prompt, or null to omit
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder prompt(@Nullable String value) {
			this.prompt = value;
			return this;
		}

		/**
		 * Sets an optional login hint.
		 *
		 * @param value the hint, or null to omit
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder loginHint(@Nullable String value) {
			this.loginHint = value;
			return this;
		}

		/**
		 * Replaces the complete application-data map.
		 *
		 * @param value the data, or null which restores the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder applicationData(@Nullable Map<@NonNull String, @NonNull String> value) {
			this.applicationData = value == null ? Map.of() : Map.copyOf(value);
			return this;
		}

		/**
		 * Replaces the complete additional-parameter map. Reserved OAuth names are rejected.
		 *
		 * @param value the parameters, or null which restores the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder additionalParameters(@Nullable Map<@NonNull String, @NonNull String> value) {
			Map<String, String> copy = value == null ? Map.of() : Map.copyOf(value);
			for (String name : copy.keySet())
				if (RESERVED.contains(name) || name.isEmpty())
					throw new IllegalArgumentException("An additional authorization parameter has a reserved name.");
			this.additionalParameters = copy;
			return this;
		}

		/**
		 * Builds the immutable options.
		 *
		 * @return the options
		 * @since 1.0.0
		 */
		public @NonNull AuthorizationRequestOptions build() {
			return new AuthorizationRequestOptions(this);
		}
	}
}
