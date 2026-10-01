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
 * Scope, resource and additional form options for one token request. An absent scope set means the refresh request
 * omits scope; it does not inherit client defaults. A caller refreshing a token must request only a subset of the
 * original grant because this object does not know that grant.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class TokenRequestOptions {
	private static final Set<String> RESERVED = Set.of("grant_type", "code", "redirect_uri", "code_verifier",
			"refresh_token", "client_id", "client_secret", "scope", "resource", "token", "token_type_hint");
	private final @Nullable Set<@NonNull String> scopes;
	private final @NonNull List<@NonNull URI> resources;
	private final boolean resourcesOverridden;
	private final @NonNull Map<@NonNull String, @NonNull String> additionalParameters;

	private TokenRequestOptions(@NonNull Builder builder) {
		this.scopes = builder.scopes;
		this.resources = builder.resources;
		this.resourcesOverridden = builder.resourcesOverridden;
		this.additionalParameters = builder.additionalParameters;
	}

	/**
	 * Starts a builder with no scope override or resources.
	 *
	 * @return builder
	 * @since 1.0.0
	 */
	public static @NonNull Builder builder() { return new Builder(); }

	/**
	 * Returns the complete requested scope set if explicitly supplied.
	 *
	 * @return scopes
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull Set<@NonNull String>> getScopes() {
		return Optional.ofNullable(this.scopes);
	}

	/**
	 * Returns ordered RFC 8707 resource indicators.
	 *
	 * @return resources
	 * @since 1.0.0
	 */
	public @NonNull List<@NonNull URI> getResources() { return this.resources; }

	boolean resourcesOverridden() { return this.resourcesOverridden; }

	/**
	 * Returns additional nonreserved form parameters.
	 *
	 * @return parameters
	 * @since 1.0.0
	 */
	public @NonNull Map<@NonNull String, @NonNull String> getAdditionalParameters() {
		return this.additionalParameters;
	}

	/**
	 * Mutable builder for one token request.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	@CheckReturnValue
	public static final class Builder {
		private @Nullable Set<@NonNull String> scopes;
		private @NonNull List<@NonNull URI> resources = List.of();
		private boolean resourcesOverridden;
		private @NonNull Map<@NonNull String, @NonNull String> additionalParameters = Map.of();

		private Builder() {
		}

		/**
		 * Replaces the complete scope set for this request. Null omits the scope field.
		 *
		 * @param value scopes or null
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder scopes(@Nullable Set<@NonNull String> value) {
			Set<String> copy = value == null ? null : Set.copyOf(value);
			if (copy != null)
				for (String scope : copy)
					if (scope.isEmpty() || scope.chars().anyMatch(c -> c <= 0x20 || c == 0x22 || c == 0x5C || c >= 0x7F))
						throw new IllegalArgumentException("A scope contains invalid characters.");
			this.scopes = copy;
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
			for (URI resource : this.resources)
				if (!resource.isAbsolute() || resource.getFragment() != null)
					throw new IllegalArgumentException("A resource indicator must be absolute and fragment-free.");
			this.resourcesOverridden = value != null;
			return this;
		}

		/**
		 * Replaces the additional nonreserved form parameters.
		 *
		 * @param value parameters, or null which restores the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder additionalParameters(@Nullable Map<@NonNull String, @NonNull String> value) {
			Map<String, String> copy = value == null ? Map.of() : Map.copyOf(value);
			for (String name : copy.keySet())
				if (name.isEmpty() || RESERVED.contains(name))
					throw new IllegalArgumentException("A token request parameter has a reserved name.");
			this.additionalParameters = copy;
			return this;
		}

		/**
		 * Builds immutable options.
		 *
		 * @return options
		 * @since 1.0.0
		 */
		public @NonNull TokenRequestOptions build() { return new TokenRequestOptions(this); }
	}
}
