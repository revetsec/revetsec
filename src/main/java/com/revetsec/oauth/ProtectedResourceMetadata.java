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

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.http.UriChecks;
import com.revetsec.internal.HostClassifier;
import com.revetsec.internal.Limits;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import static java.util.Objects.requireNonNull;

/**
 * Application-configured protected-resource metadata (RFC 9728 sections 2 and 3).
 * The resource identifier is preserved exactly, including its raw path/query; no URI normalization or I/O occurs.
 * The app serves {@link #toJson()} as application/json and chooses cache policy. This metadata grants no permission.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class ProtectedResourceMetadata {
	private static final int MAXIMUM_JSON_LENGTH = Limits.HTTP_RESPONSE_BODY_SIZE.getDefaultIntValue();
	private static final String WELL_KNOWN = "/.well-known/oauth-protected-resource";
	private final @NonNull URI resource;
	private final @NonNull List<@NonNull String> authorizationServers;
	private final @NonNull List<@NonNull String> scopesSupported;
	private final @NonNull String json;
	private ProtectedResourceMetadata(@NonNull Builder builder, @NonNull String json) {
		this.resource = builder.resource; this.authorizationServers = builder.authorizationServers;
		this.scopesSupported = builder.scopesSupported; this.json = json;
	}
	/**
	 * Starts metadata for an exact configured resource identifier.
	 * @param resource the resource URI; HTTPS is required unless loopback HTTP is explicitly allowed
	 * @return the builder
	 * @throws NullPointerException if resource is null
	 * @since 1.0.0
	 */
	public static @NonNull Builder withResource(@NonNull URI resource) { return new Builder(resource); }
	/**
	 * Returns the exact configured resource identifier.
	 * @return the resource
	 * @since 1.0.0
	 */
	public @NonNull URI getResource() { return this.resource; }
	/**
	 * Returns exact authorization-server issuer strings in configured order, without duplicates.
	 * @return immutable issuer strings
	 * @since 1.0.0
	 */
	public @NonNull List<@NonNull String> getAuthorizationServers() { return this.authorizationServers; }
	/**
	 * Returns supported scope tokens in first-occurrence order.
	 * @return immutable scopes
	 * @since 1.0.0
	 */
	public @NonNull List<@NonNull String> getScopesSupported() { return this.scopesSupported; }
	/**
	 * Derives the RFC 9728 well-known location using raw components and stripping a terminating literal path slash.
	 * The configured resource identifier is unchanged, including percent escapes, dot segments and query.
	 * @return the metadata URI
	 * @since 1.0.0
	 */
	public @NonNull URI getWellKnownUri() {
		String path = requireNonNull(this.resource.getRawPath());
		if (path.endsWith("/")) path = path.substring(0, path.length() - 1);
		String query = this.resource.getRawQuery();
		return URI.create(this.resource.getScheme() + "://" + this.resource.getRawAuthority() + WELL_KNOWN
				+ path + (query == null ? "" : "?" + query));
	}
	/**
	 * Returns bounded compact JSON advertising only header bearer presentation. Empty optional arrays are omitted.
	 * @return the JSON text, at most 256 KiB in UTF-8
	 * @since 1.0.0
	 */
	public @NonNull String toJson() { return this.json; }
	/**
	 * Redacts metadata configuration from diagnostic text.
	 * @return the redacted description
	 * @since 1.0.0
	 */
	@Override
	public @NonNull String toString() { return "ProtectedResourceMetadata{configuration=<redacted>}"; }

	static void requireResourceUri(URI uri, boolean allowInsecureLoopback) {
		String scheme = uri.getScheme(); String host = uri.getHost(); int port = uri.getPort();
		if (scheme == null || uri.isOpaque() || host == null || (port != -1 && (port < 1 || port > 65_535))
				|| uri.getRawUserInfo() != null || uri.getRawFragment() != null
				|| !(scheme.equalsIgnoreCase("https") || (scheme.equalsIgnoreCase("http") && allowInsecureLoopback
						&& HostClassifier.isPlainHttpLoopbackHost(host))))
			throw new IllegalArgumentException("A resource URI must be absolute HTTPS without userinfo or fragment, "
					+ "or explicitly allowed loopback HTTP.");
	}

	static List<String> checkedScopes(@Nullable List<String> values, long maximum) {
		if (values == null) return List.of();
		if (values.size() > maximum / 3) throw new IllegalArgumentException("The scope list is too large.");
		LinkedHashSet<String> copy = new LinkedHashSet<>(); long length = 0;
		for (String value : values) {
			requireNonNull(value);
			length += (long) value.length() + 3;
			if (length > maximum) throw new IllegalArgumentException("The scope list is too large.");
			if (value.isEmpty()) throw new IllegalArgumentException("A scope must not be empty.");
			for (int index = 0; index < value.length(); index++) {
				char c = value.charAt(index);
				if (c <= 0x20 || c == 0x22 || c == 0x5C || c >= 0x7F)
					throw new IllegalArgumentException("A scope contains invalid characters.");
			}
			copy.add(value);
		}
		return List.copyOf(copy);
	}

	private static int jsonStringLength(String value) {
		if (value.length() > MAXIMUM_JSON_LENGTH) throw new IllegalArgumentException("Resource metadata is too large.");
		return JsonString.fromValue(value).toJson().getBytes(StandardCharsets.UTF_8).length;
	}

	/**
	 * Mutable metadata configuration. Null optional values restore the empty/false defaults.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	@CheckReturnValue
	public static final class Builder {
		private final @NonNull URI resource;
		private @NonNull List<@NonNull String> authorizationServers = List.of();
		private @NonNull List<@NonNull String> scopesSupported = List.of();
		private boolean allowInsecureLoopback;
		private Builder(@NonNull URI resource) { this.resource = requireNonNull(resource); }
		/**
		 * Replaces exact issuer identifiers. Uses the default outbound URI checks; queries are also invalid.
		 * @param value issuer strings, or null/empty to omit
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder authorizationServers(@Nullable List<@NonNull String> value) {
			if (value == null) { this.authorizationServers = List.of(); return this; }
			if (value.size() > MAXIMUM_JSON_LENGTH / 3) throw new IllegalArgumentException("Resource metadata is too large.");
			LinkedHashSet<String> copy = new LinkedHashSet<>(); long length = 0;
			for (String issuer : value) {
				requireNonNull(issuer);
				length += (long) jsonStringLength(issuer) + 1;
				if (length > MAXIMUM_JSON_LENGTH) throw new IllegalArgumentException("Resource metadata is too large.");
				copy.add(issuer);
			}
			this.authorizationServers = List.copyOf(copy); return this;
		}
		/**
		 * Replaces supported scope tokens, preserving first occurrence order and removing duplicates.
		 * @param value scope tokens, or null/empty to omit
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder scopesSupported(@Nullable List<@NonNull String> value) {
			this.scopesSupported = checkedScopes(value, MAXIMUM_JSON_LENGTH); return this;
		}
		/**
		 * Permits plain HTTP only to a recognized loopback literal or exactly localhost for local tests.
		 * @param value whether to allow loopback HTTP, or null to restore false
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder allowInsecureLoopback(@Nullable Boolean value) {
			this.allowInsecureLoopback = Boolean.TRUE.equals(value); return this;
		}
		/**
		 * Checks URI policy and renders bounded metadata without I/O. Builders can be reused.
		 * @return immutable metadata
		 * @throws IllegalArgumentException if configuration is unsafe or serialized JSON exceeds 256 KiB
		 * @since 1.0.0
		 */
		public @NonNull ProtectedResourceMetadata build() {
			requireResourceUri(this.resource, this.allowInsecureLoopback);
			long length = 51L + jsonStringLength(this.resource.toString());
			JsonObject.Builder json = JsonObject.builder().put("resource", this.resource.toString())
					.put("bearer_methods_supported", JsonArray.fromElements(List.of(JsonString.fromValue("header"))));
			if (!this.authorizationServers.isEmpty()) length += 26;
			if (!this.scopesSupported.isEmpty()) length += 21;
			for (String issuer : this.authorizationServers) {
				URI uri;
				try { uri = URI.create(issuer); }
				catch (IllegalArgumentException exception) { throw new IllegalArgumentException("An issuer URI is malformed."); }
				UriChecks.requirePermitted(uri, OutboundUriPolicy.defaultInstance(), this.allowInsecureLoopback);
				if (uri.getRawQuery() != null) throw new IllegalArgumentException("An issuer must not have a query.");
				length += (long) jsonStringLength(issuer) + 1;
			}
			for (String scope : this.scopesSupported) length += (long) scope.length() + 3;
			// Bound the full JSON expansion before constructing arrays/rendering. Exact size is checked below.
			if (length > MAXIMUM_JSON_LENGTH) throw new IllegalArgumentException("Resource metadata is too large.");
			if (!this.authorizationServers.isEmpty()) json.put("authorization_servers", JsonArray.fromElements(
					this.authorizationServers.stream().map(JsonString::fromValue).toList()));
			if (!this.scopesSupported.isEmpty()) json.put("scopes_supported", JsonArray.fromElements(
					this.scopesSupported.stream().map(JsonString::fromValue).toList()));
			String text = json.build().toJson();
			if (text.getBytes(StandardCharsets.UTF_8).length > MAXIMUM_JSON_LENGTH)
				throw new IllegalArgumentException("Resource metadata is too large.");
			return new ProtectedResourceMetadata(this, text);
		}
	}
}
