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
import com.revetsec.internal.Limits;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.net.URI;
import java.util.List;

/**
 * A bounded WWW-Authenticate Bearer value (RFC 6750 section 3 and RFC 9728 section 5).
 * Supply only trusted application configuration, never reflected token/provider error text. The app chooses the
 * HTTP status. An initial 401 challenge has no error. At least one rendered parameter is required.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class BearerChallenge {
	private final @NonNull String headerValue;
	private BearerChallenge(@NonNull String headerValue) { this.headerValue = headerValue; }
	/**
	 * Starts a challenge with no parameters and an 8 KiB rendered field limit.
	 * @return the builder
	 * @since 1.0.0
	 */
	public static @NonNull Builder builder() { return new Builder(); }
	/**
	 * Returns the complete ASCII field value, suitable for WWW-Authenticate.
	 * @return the header value
	 * @since 1.0.0
	 */
	public @NonNull String getHeaderValue() { return this.headerValue; }
	/**
	 * Redacts challenge configuration from diagnostic text.
	 * @return the redacted description
	 * @since 1.0.0
	 */
	@Override
	public @NonNull String toString() { return "BearerChallenge{parameters=<redacted>}"; }

	private static void requireText(String value, boolean description) {
		if (value.length() > Limits.BEARER_CHALLENGE_SIZE.getCap())
			throw new IllegalArgumentException("A challenge parameter is too large.");
		for (int index = 0; index < value.length(); index++) {
			char c = value.charAt(index);
			if (c < 0x20 || c > 0x7E || (description && (c == '"' || c == '\\')))
				throw new IllegalArgumentException("A challenge parameter contains invalid characters.");
		}
	}

	private static void append(StringBuilder output, String name, String value, int maximum) {
		long length = (long) output.length() + (output.length() == 6 ? 1 : 2) + name.length() + 3 + value.length();
		for (int index = 0; index < value.length(); index++) {
			char c = value.charAt(index);
			if (c == '"' || c == '\\') length++;
		}
		if (length > maximum) throw new IllegalArgumentException("The rendered bearer challenge is too large.");
		output.append(output.length() == 6 ? " " : ", ").append(name).append("=\"");
		for (int index = 0; index < value.length(); index++) {
			char c = value.charAt(index);
			if (c == '"' || c == '\\') output.append('\\');
			output.append(c);
		}
		output.append('"');
	}

	/**
	 * Mutable challenge configuration. Null property values restore omission or the documented default.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	@CheckReturnValue
	public static final class Builder {
		private @Nullable String realm;
		private @Nullable BearerError error;
		private @Nullable String errorDescription;
		private @NonNull List<@NonNull String> scopes = List.of();
		private @Nullable URI resourceMetadata;
		private int maximumHeaderLength = Limits.BEARER_CHALLENGE_SIZE.getDefaultIntValue();
		private boolean allowInsecureLoopback;
		private Builder() { }
		/**
		 * Sets a quoted ASCII realm. Quote/backslash are escaped; controls and non-ASCII are rejected.
		 * @param value the realm, or null to omit
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder realm(@Nullable String value) {
			if (value != null) requireText(value, false);
			this.realm = value; return this;
		}
		/**
		 * Sets the protocol error. Omit for an initial missing-credential challenge.
		 * @param value the error, or null to omit
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder error(@Nullable BearerError value) { this.error = value; return this; }
		/**
		 * Sets trusted ASCII prose satisfying RFC 6750's error_description grammar; quotes/backslashes are invalid.
		 * @param value the description, or null to omit
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder errorDescription(@Nullable String value) {
			if (value != null) requireText(value, true);
			this.errorDescription = value; return this;
		}
		/**
		 * Replaces required scopes, preserving first-occurrence order and removing duplicates.
		 * @param value the scope tokens, or null/empty to omit
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder scopes(@Nullable List<@NonNull String> value) {
			this.scopes = ProtectedResourceMetadata.checkedScopes(value,
					Limits.BEARER_CHALLENGE_SIZE.getCap()); return this;
		}
		/**
		 * Sets the trusted resource metadata location. HTTPS is required except explicit loopback HTTP.
		 * @param value the metadata URI, or null to omit
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder resourceMetadata(@Nullable URI value) { this.resourceMetadata = value; return this; }
		/**
		 * Sets the rendered ASCII field byte limit, including quote/backslash expansion.
		 * @param value the limit from 1 KiB through 64 KiB, or null to restore 8 KiB
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder maximumHeaderLength(@Nullable Integer value) {
			this.maximumHeaderLength = value == null ? Limits.BEARER_CHALLENGE_SIZE.getDefaultIntValue()
					: Limits.BEARER_CHALLENGE_SIZE.require(value); return this;
		}
		/**
		 * Permits plain HTTP only to an existing recognized loopback literal or exactly localhost, for local tests.
		 * @param value whether to allow local HTTP, or null to restore false
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder allowInsecureLoopback(@Nullable Boolean value) {
			this.allowInsecureLoopback = Boolean.TRUE.equals(value); return this;
		}
		/**
		 * Builds the field without I/O.
		 * @return the immutable challenge
		 * @throws IllegalStateException if no parameter would be rendered
		 * @throws IllegalArgumentException if the supplied configuration is incompatible, unsafe or oversized
		 * @since 1.0.0
		 */
		public @NonNull BearerChallenge build() {
			if (this.errorDescription != null && this.error == null)
				throw new IllegalArgumentException("A bearer error description requires an error.");
			StringBuilder output = new StringBuilder("Bearer");
			if (this.realm != null) append(output, "realm", this.realm, this.maximumHeaderLength);
			if (this.error != null) append(output, "error", this.error.getWireValue(), this.maximumHeaderLength);
			if (this.errorDescription != null) append(output, "error_description", this.errorDescription, this.maximumHeaderLength);
			if (!this.scopes.isEmpty()) append(output, "scope", String.join(" ", this.scopes), this.maximumHeaderLength);
			if (this.resourceMetadata != null) {
				ProtectedResourceMetadata.requireResourceUri(this.resourceMetadata, this.allowInsecureLoopback);
				if (this.resourceMetadata.toString().length() > this.maximumHeaderLength)
					throw new IllegalArgumentException("The rendered bearer challenge is too large.");
				append(output, "resource_metadata", this.resourceMetadata.toASCIIString(), this.maximumHeaderLength);
			}
			if (output.length() == 6) throw new IllegalStateException("A bearer challenge requires a parameter.");
			return new BearerChallenge(output.toString());
		}
	}
}
