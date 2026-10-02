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

import com.revetsec.internal.Limits;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonBoolean;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.google.errorprone.annotations.CheckReturnValue;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.net.URI;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Known authorization-server metadata. A remote document's issuer must match the configured issuer exactly. A
 * manual instance is application configuration, not proof from a remote server. The {@link OAuthClient} builder
 * checks every known requestable endpoint against its outbound URI policy before use.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class AuthorizationServerMetadata {
	private final @NonNull String issuer;
	private final @NonNull URI authorizationEndpoint;
	private final @NonNull URI tokenEndpoint;
	private final @Nullable URI jwksUri;
	private final @Nullable URI introspectionEndpoint;
	private final @Nullable URI revocationEndpoint;
	private final @Nullable Set<@NonNull String> codeChallengeMethodsSupported;
	private final @Nullable Set<@NonNull String> tokenEndpointAuthMethodsSupported;
	private final @Nullable Set<@NonNull String> introspectionEndpointAuthMethodsSupported;
	private final @Nullable Set<@NonNull String> tokenEndpointAuthSigningAlgValuesSupported;
	private final @Nullable Set<@NonNull String> revocationEndpointAuthMethodsSupported;
	private final @Nullable Set<@NonNull String> revocationEndpointAuthSigningAlgValuesSupported;
	private final @Nullable Set<@NonNull String> introspectionEndpointAuthSigningAlgValuesSupported;
	private final boolean authorizationResponseIssuerSupported;
	private final boolean remotelyDiscovered;

	private AuthorizationServerMetadata(@NonNull Builder builder, boolean remotelyDiscovered) {
		this.issuer = builder.issuer;
		this.authorizationEndpoint = requireNonNull(builder.authorizationEndpoint);
		this.tokenEndpoint = requireNonNull(builder.tokenEndpoint);
		this.jwksUri = builder.jwksUri;
		this.introspectionEndpoint = builder.introspectionEndpoint;
		this.revocationEndpoint = builder.revocationEndpoint;
		this.codeChallengeMethodsSupported = builder.codeChallengeMethodsSupported;
		this.tokenEndpointAuthMethodsSupported = builder.tokenEndpointAuthMethodsSupported;
		this.introspectionEndpointAuthMethodsSupported = builder.introspectionEndpointAuthMethodsSupported;
		this.tokenEndpointAuthSigningAlgValuesSupported = builder.tokenEndpointAuthSigningAlgValuesSupported;
		this.revocationEndpointAuthMethodsSupported = builder.revocationEndpointAuthMethodsSupported;
		this.revocationEndpointAuthSigningAlgValuesSupported = builder.revocationEndpointAuthSigningAlgValuesSupported;
		this.introspectionEndpointAuthSigningAlgValuesSupported = builder.introspectionEndpointAuthSigningAlgValuesSupported;
		this.authorizationResponseIssuerSupported = builder.authorizationResponseIssuerSupported;
		this.remotelyDiscovered = remotelyDiscovered;
	}

	/**
	 * Starts a manual metadata builder for an AS without discovery.
	 *
	 * @param issuer the deployment's exact issuer identifier
	 * @return the builder
	 * @since 1.0.0
	 */
	public static @NonNull Builder withIssuer(@NonNull String issuer) {
		return new Builder(issuer);
	}

	/**
	 * Parses a strict, bounded metadata JSON document and compares its issuer exactly.
	 *
	 * @param expectedIssuer the configured issuer
	 * @param json the JSON text
	 * @return the metadata
	 * @since 1.0.0
	 */
	public static @NonNull AuthorizationServerMetadata fromJson(@NonNull String expectedIssuer,
			@NonNull String json) {
		requireNonNull(expectedIssuer);
		requireNonNull(json);
		try {
			byte[] bytes = StrictUtf8.encode(json);
			JsonValue parsed = JsonCodec.parse(bytes,
					JsonLimits.protocolDocument(Limits.HTTP_RESPONSE_BODY_SIZE.getDefaultIntValue()));
			if (!(parsed instanceof JsonObject object))
				throw OAuthResponseException.fromReason(OAuthException.Reason.DOCUMENT_MALFORMED);
			Map<String, JsonValue> members = object.getMembers();
			String actualIssuer = requiredString(members, "issuer");
			if (!expectedIssuer.equals(actualIssuer))
				throw OAuthValidationException.fromReason(OAuthException.Reason.ISSUER_MISMATCH);
			Builder builder = withIssuer(expectedIssuer)
					.authorizationEndpoint(URI.create(requiredString(members, "authorization_endpoint")))
					.tokenEndpoint(URI.create(requiredString(members, "token_endpoint")));
			if (members.containsKey("jwks_uri")) builder = builder.jwksUri(URI.create(requiredString(members, "jwks_uri")));
			if (members.containsKey("introspection_endpoint")) builder = builder.introspectionEndpoint(URI.create(requiredString(members, "introspection_endpoint")));
			if (members.containsKey("revocation_endpoint"))
				builder = builder.revocationEndpoint(URI.create(requiredString(members, "revocation_endpoint")));
			if (members.containsKey("code_challenge_methods_supported"))
				builder = builder.codeChallengeMethodsSupported(stringSet(members.get("code_challenge_methods_supported")));
			if (members.containsKey("token_endpoint_auth_methods_supported"))
				builder = builder.tokenEndpointAuthMethodsSupported(stringSet(members.get("token_endpoint_auth_methods_supported")));
			if (members.containsKey("introspection_endpoint_auth_methods_supported")) builder = builder.introspectionEndpointAuthMethodsSupported(stringSet(members.get("introspection_endpoint_auth_methods_supported")));
			if (members.containsKey("token_endpoint_auth_signing_alg_values_supported")) builder = builder.tokenEndpointAuthSigningAlgValuesSupported(stringSet(members.get("token_endpoint_auth_signing_alg_values_supported")));
			if (members.containsKey("revocation_endpoint_auth_methods_supported")) builder = builder.revocationEndpointAuthMethodsSupported(stringSet(members.get("revocation_endpoint_auth_methods_supported")));
			if (members.containsKey("revocation_endpoint_auth_signing_alg_values_supported")) builder = builder.revocationEndpointAuthSigningAlgValuesSupported(stringSet(members.get("revocation_endpoint_auth_signing_alg_values_supported")));
			if (members.containsKey("introspection_endpoint_auth_signing_alg_values_supported")) builder = builder.introspectionEndpointAuthSigningAlgValuesSupported(stringSet(members.get("introspection_endpoint_auth_signing_alg_values_supported")));
			if (members.containsKey("authorization_response_iss_parameter_supported")) {
				JsonValue value = members.get("authorization_response_iss_parameter_supported");
				if (!(value instanceof JsonBoolean booleanValue))
					throw OAuthResponseException.fromReason(OAuthException.Reason.DOCUMENT_MALFORMED);
				builder = builder.authorizationResponseIssuerSupported(booleanValue.getValue());
			}
			return builder.buildDiscovered();
		} catch (EncodingException | JsonParseException | IllegalArgumentException exception) {
			throw OAuthResponseException.fromReason(OAuthException.Reason.DOCUMENT_MALFORMED);
		}
	}

	private static @NonNull String requiredString(@NonNull Map<@NonNull String, @NonNull JsonValue> members, @NonNull String name) {
		JsonValue value = members.get(name);
		if (!(value instanceof JsonString text) || text.getValue().isEmpty())
			throw OAuthResponseException.fromReason(OAuthException.Reason.DOCUMENT_MALFORMED);
		return text.getValue();
	}

	private static @NonNull Set<@NonNull String> stringSet(@NonNull JsonValue value) {
		if (!(value instanceof JsonArray array))
			throw OAuthResponseException.fromReason(OAuthException.Reason.DOCUMENT_MALFORMED);
		Set<String> strings = new LinkedHashSet<>();
		for (JsonValue element : array.getElements()) {
			if (!(element instanceof JsonString text) || text.getValue().isEmpty()
					|| !strings.add(text.getValue()))
				throw OAuthResponseException.fromReason(OAuthException.Reason.DOCUMENT_MALFORMED);
		}
		return Set.copyOf(strings);
	}

	/**
	 * Returns the exact issuer identifier.
	 *
	 * @return issuer
	 * @since 1.0.0
	 */
	public @NonNull String getIssuer() { return this.issuer; }

	/**
	 * Returns the authorization endpoint.
	 *
	 * @return endpoint
	 * @since 1.0.0
	 */
	public @NonNull URI getAuthorizationEndpoint() { return this.authorizationEndpoint; }

	/**
	 * Returns the token endpoint.
	 *
	 * @return endpoint
	 * @since 1.0.0
	 */
	public @NonNull URI getTokenEndpoint() { return this.tokenEndpoint; }

    /** Returns the optional jwks_uri.
     * @return endpoint when configured or advertised
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull URI> getJwksUri() { return Optional.ofNullable(this.jwksUri); }
    /** Returns the optional introspection_endpoint.
     * @return endpoint when configured or advertised
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull URI> getIntrospectionEndpoint() { return Optional.ofNullable(this.introspectionEndpoint); }
	/**
	 * Returns the revocation endpoint, when one was advertised or configured.
	 *
	 * @return endpoint
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull URI> getRevocationEndpoint() {
		return Optional.ofNullable(this.revocationEndpoint);
	}

	/**
	 * Returns advertised PKCE methods, or empty when the metadata field was absent.
	 *
	 * @return methods if advertised
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull Set<@NonNull String>> getCodeChallengeMethodsSupported() {
		return Optional.ofNullable(this.codeChallengeMethodsSupported);
	}

	/**
	 * Returns advertised token endpoint client authentication methods, or empty when absent.
	 *
	 * @return methods if advertised
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull Set<@NonNull String>> getTokenEndpointAuthMethodsSupported() {
		return Optional.ofNullable(this.tokenEndpointAuthMethodsSupported);
	}

    /** Returns introspection endpoint methods separately from token endpoint methods.
     * @return advertised methods, or empty when absent
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull Set<@NonNull String>> getIntrospectionEndpointAuthMethodsSupported() { return Optional.ofNullable(this.introspectionEndpointAuthMethodsSupported); }
	/**
	 * Returns the optional token_endpoint_auth_signing_alg_values_supported role policy, retaining absent versus empty and unknown names.
	 * @return advertised or configured names when present
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull Set<@NonNull String>> getTokenEndpointAuthSigningAlgValuesSupported() { return Optional.ofNullable(this.tokenEndpointAuthSigningAlgValuesSupported); }
	/**
	 * Returns the optional revocation_endpoint_auth_methods_supported role policy, retaining absent versus empty and unknown names.
	 * @return advertised or configured names when present
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull Set<@NonNull String>> getRevocationEndpointAuthMethodsSupported() { return Optional.ofNullable(this.revocationEndpointAuthMethodsSupported); }
	/**
	 * Returns the optional revocation_endpoint_auth_signing_alg_values_supported role policy, retaining absent versus empty and unknown names.
	 * @return advertised or configured names when present
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull Set<@NonNull String>> getRevocationEndpointAuthSigningAlgValuesSupported() { return Optional.ofNullable(this.revocationEndpointAuthSigningAlgValuesSupported); }
	/**
	 * Returns the optional introspection_endpoint_auth_signing_alg_values_supported role policy, retaining absent versus empty and unknown names.
	 * @return advertised or configured names when present
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull Set<@NonNull String>> getIntrospectionEndpointAuthSigningAlgValuesSupported() { return Optional.ofNullable(this.introspectionEndpointAuthSigningAlgValuesSupported); }
	/**
	 * Returns whether metadata advertised RFC 9207 issuer response support.
	 *
	 * @return whether support was advertised
	 * @since 1.0.0
	 */
	public @NonNull Boolean isAuthorizationResponseIssuerSupported() {
		return this.authorizationResponseIssuerSupported;
	}

	/**
	 * Returns whether this instance came from a checked remote metadata document.
	 *
	 * @return whether discovered
	 * @since 1.0.0
	 */
	public @NonNull Boolean isRemotelyDiscovered() { return this.remotelyDiscovered; }

	/**
	 * Builds manually configured metadata.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	@CheckReturnValue
	public static final class Builder {
		private final @NonNull String issuer;
		private @Nullable URI authorizationEndpoint;
		private @Nullable URI tokenEndpoint;
		private @Nullable URI jwksUri;
		private @Nullable URI introspectionEndpoint;
		private @Nullable URI revocationEndpoint;
		private @Nullable Set<@NonNull String> codeChallengeMethodsSupported;
		private @Nullable Set<@NonNull String> tokenEndpointAuthMethodsSupported;
		private @Nullable Set<@NonNull String> introspectionEndpointAuthMethodsSupported;
		private boolean authorizationResponseIssuerSupported;

		private @Nullable Set<@NonNull String> tokenEndpointAuthSigningAlgValuesSupported;

		/**
		 * Replaces the complete token_endpoint_auth_signing_alg_values_supported role policy, preserving an empty set.
		 * @param value names, or null to restore absence
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder tokenEndpointAuthSigningAlgValuesSupported(@Nullable Set<@NonNull String> value) {
			this.tokenEndpointAuthSigningAlgValuesSupported = value == null ? null : AccessTokenClaims.names(value, false); return this;
		}

		private @Nullable Set<@NonNull String> revocationEndpointAuthMethodsSupported;

		/**
		 * Replaces the complete revocation_endpoint_auth_methods_supported role policy, preserving an empty set.
		 * @param value names, or null to restore absence
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder revocationEndpointAuthMethodsSupported(@Nullable Set<@NonNull String> value) {
			this.revocationEndpointAuthMethodsSupported = value == null ? null : AccessTokenClaims.names(value, false); return this;
		}

		private @Nullable Set<@NonNull String> revocationEndpointAuthSigningAlgValuesSupported;

		/**
		 * Replaces the complete revocation_endpoint_auth_signing_alg_values_supported role policy, preserving an empty set.
		 * @param value names, or null to restore absence
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder revocationEndpointAuthSigningAlgValuesSupported(@Nullable Set<@NonNull String> value) {
			this.revocationEndpointAuthSigningAlgValuesSupported = value == null ? null : AccessTokenClaims.names(value, false); return this;
		}

		private @Nullable Set<@NonNull String> introspectionEndpointAuthSigningAlgValuesSupported;

		/**
		 * Replaces the complete introspection_endpoint_auth_signing_alg_values_supported role policy, preserving an empty set.
		 * @param value names, or null to restore absence
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder introspectionEndpointAuthSigningAlgValuesSupported(@Nullable Set<@NonNull String> value) {
			this.introspectionEndpointAuthSigningAlgValuesSupported = value == null ? null : AccessTokenClaims.names(value, false); return this;
		}

		private Builder(@NonNull String issuer) {
			if (requireNonNull(issuer).isEmpty())
				throw new IllegalArgumentException("An issuer must not be empty.");
			this.issuer = issuer;
		}

		/**
		 * Sets the authorization endpoint.
		 *
		 * @param value endpoint, or null to restore the unset default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder authorizationEndpoint(@Nullable URI value) {
			this.authorizationEndpoint = value;
			return this;
		}

		/**
		 * Sets the token endpoint.
		 *
		 * @param value endpoint, or null to restore the unset default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder tokenEndpoint(@Nullable URI value) {
			this.tokenEndpoint = value;
			return this;
		}

        /** Sets optional jwks_uri.
         * @param value endpoint, or null to omit
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder jwksUri(@Nullable URI value) { this.jwksUri = value; return this; }
        /** Sets optional introspection_endpoint.
         * @param value endpoint, or null to omit
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder introspectionEndpoint(@Nullable URI value) { this.introspectionEndpoint = value; return this; }
		/**
		 * Sets an optional revocation endpoint.
		 *
		 * @param value endpoint, or null to restore the unset default, or null to omit
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder revocationEndpoint(@Nullable URI value) {
			this.revocationEndpoint = value;
			return this;
		}

		/**
		 * Sets the complete advertised PKCE method set. Null denotes absent metadata.
		 *
		 * @param value methods, or null
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder codeChallengeMethodsSupported(@Nullable Set<@NonNull String> value) {
			this.codeChallengeMethodsSupported = value == null ? null : Set.copyOf(value);
			return this;
		}

		/**
		 * Sets the complete advertised client authentication method set. Null denotes absent metadata.
		 *
		 * @param value methods, or null
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder tokenEndpointAuthMethodsSupported(@Nullable Set<@NonNull String> value) {
			this.tokenEndpointAuthMethodsSupported = value == null ? null : Set.copyOf(value);
			return this;
		}

        /** Sets introspection endpoint client authentication methods.
         * @param value methods, or null to restore absence
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder introspectionEndpointAuthMethodsSupported(@Nullable Set<@NonNull String> value) { this.introspectionEndpointAuthMethodsSupported = value == null ? null : AccessTokenClaims.names(value, false); return this; }
		/**
		 * Sets whether RFC 9207 issuer response support was advertised.
		 *
		 * @param value whether advertised, or null which restores the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder authorizationResponseIssuerSupported(@Nullable Boolean value) {
			this.authorizationResponseIssuerSupported = Boolean.TRUE.equals(value);
			return this;
		}

		/**
		 * Builds manually configured metadata.
		 *
		 * @return metadata
		 * @since 1.0.0
		 */
		public @NonNull AuthorizationServerMetadata build() {
			if (this.authorizationEndpoint == null || this.tokenEndpoint == null)
				throw new IllegalStateException("Authorization and token endpoints are required.");
			return new AuthorizationServerMetadata(this, false);
		}

		private @NonNull AuthorizationServerMetadata buildDiscovered() {
			if (this.authorizationEndpoint == null || this.tokenEndpoint == null)
				throw OAuthResponseException.fromReason(OAuthException.Reason.DOCUMENT_MALFORMED);
			return new AuthorizationServerMetadata(this, true);
		}
	}
}
