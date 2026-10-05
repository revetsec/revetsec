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

import com.google.errorprone.annotations.CheckReturnValue;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.net.URI;
import java.util.*;
import static java.util.Objects.requireNonNull;
import com.revetsec.oauth.AuthorizationServerMetadata;
import com.revetsec.oauth.OAuthException;
import com.revetsec.internal.oauth.OidcTransactionAccess;
import com.revetsec.internal.Limits;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.json.*;

/**
 * OpenID provider metadata (OpenID Connect Discovery 1.0 section 3), from discovery or explicit configuration. It is
 * not authenticated identity. The client validates every known requestable URI against its outbound policy.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class OidcProviderMetadata {
	private final AuthorizationServerMetadata oauth;
	private final String advertisedIssuer;
	private final URI jwksUri;
	private final @Nullable URI userInfoEndpoint;
	private final Set<String> subjectTypes;
	private final Set<String> algorithms;
	private final Set<String> responseTypes;
	private final @Nullable Set<String> userInfoAlgorithms;
	private OidcProviderMetadata(@NonNull Builder builder) {
		this.oauth = builder.oauth.build(); this.advertisedIssuer = this.oauth.getIssuer(); this.jwksUri = requireNonNull(builder.jwksUri);
		this.userInfoEndpoint = builder.userInfoEndpoint; this.subjectTypes = builder.subjectTypes;
		this.algorithms = builder.algorithms; this.responseTypes = builder.responseTypes;
		this.userInfoAlgorithms = builder.userInfoAlgorithms == null ? null : Set.copyOf(builder.userInfoAlgorithms);
	}
	private OidcProviderMetadata(@NonNull AuthorizationServerMetadata oauth, @NonNull URI jwksUri, @Nullable URI userInfo,
			@NonNull Set<@NonNull String> subjects, @NonNull Set<@NonNull String> algorithms, @NonNull Set<@NonNull String> responses, @Nullable Set<@NonNull String> userInfoAlgorithms, @NonNull String advertisedIssuer) {
		this.advertisedIssuer = advertisedIssuer; this.oauth = oauth; this.jwksUri = jwksUri; this.userInfoEndpoint = userInfo;
		this.userInfoAlgorithms = userInfoAlgorithms == null ? null : Set.copyOf(userInfoAlgorithms);
		this.subjectTypes = Set.copyOf(subjects); this.algorithms = Set.copyOf(algorithms); this.responseTypes = Set.copyOf(responses);
	}
	/**
	 * Parses a strict, bounded discovery document and compares the issuer exactly. Required OIDC fields must be
	 * present; explicit configuration defaults are never applied to a remote document. Unknown members and future
	 * algorithm names do not enlarge a client's allowlist. Discovery must advertise RS256 (Discovery section 3).
	 * The client separately checks every requestable URI.
	 * @param expectedIssuer exact configured issuer
	 * @param json metadata JSON text
	 * @return checked provider metadata, not authenticated identity
	 * @since 1.0.0
	 */
	public static @NonNull OidcProviderMetadata fromJson(@NonNull String expectedIssuer, @NonNull String json) {
		return fromJson(expectedIssuer, json, OidcIssuerPolicy.exactInstance());
	}
	/**
	 * Parses bounded metadata using exact issuer validation or the selected fixed Entra template.
	 * getIssuer retains configured trust; getAdvertisedIssuer retains the received issuer string.
	 * @param expectedIssuer configured trust issuer
	 * @param json metadata JSON
	 * @param issuerPolicy selected fixed issuer policy; no predicate runs during parsing
	 * @return checked metadata, not identity
	 * @throws NullPointerException if an argument is null
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull OidcProviderMetadata fromJson(@NonNull String expectedIssuer, @NonNull String json, @NonNull OidcIssuerPolicy issuerPolicy) {
		requireNonNull(expectedIssuer); requireNonNull(json); requireNonNull(issuerPolicy);
		issuerPolicy.checkConfiguredIssuer(expectedIssuer);
		@Nullable AuthorizationServerMetadata exact = issuerPolicy.isMicrosoftEntra() ? null : AuthorizationServerMetadata.fromJson(expectedIssuer, json);
		byte @Nullable [] bytes = null;
		try {
			bytes = StrictUtf8.encode(json);
			JsonValue parsed = JsonCodec.parse(bytes, JsonLimits.protocolDocument(Limits.HTTP_RESPONSE_BODY_SIZE.getDefaultIntValue()));
			if (!(parsed instanceof JsonObject object)) throw new IllegalArgumentException();
			Map<String, JsonValue> members = object.getMembers();
			String advertisedIssuer = requiredString(members, "issuer");
			AuthorizationServerMetadata oauth;
			if (issuerPolicy.isMicrosoftEntra()) {
				if (!OidcIssuerPolicy.TEMPLATE.equals(advertisedIssuer)) throw new IllegalArgumentException();
				JsonObject.Builder projection = JsonObject.builder();
				for (Map.Entry<String, JsonValue> member : members.entrySet())
					if (!member.getKey().equals("issuer")) projection = projection.put(member.getKey(), member.getValue());
				oauth = AuthorizationServerMetadata.fromJson(expectedIssuer, projection.put("issuer", expectedIssuer).build().toJson());
			} else oauth = requireNonNull(exact);
			URI jwks = URI.create(requiredString(members, "jwks_uri"));
			URI userInfo = members.containsKey("userinfo_endpoint") ? URI.create(requiredString(members, "userinfo_endpoint")) : null;
			Set<String> subjects = requiredSet(members, "subject_types_supported");
			Set<String> algorithms = requiredSet(members, "id_token_signing_alg_values_supported");
			Set<String> responses = requiredSet(members, "response_types_supported");
			if (subjects.stream().anyMatch(type -> !Set.of("public", "pairwise").contains(type)) || !responses.contains("code") || !algorithms.contains("RS256"))
				throw new IllegalArgumentException();
			Set<String> userInfoAlgorithms = members.containsKey("userinfo_signing_alg_values_supported")
					? requiredSet(members, "userinfo_signing_alg_values_supported") : null;
			return new OidcProviderMetadata(oauth, jwks, userInfo, subjects, algorithms, responses, userInfoAlgorithms, advertisedIssuer);
		} catch (EncodingException | JsonParseException | IllegalArgumentException invalid) {
			throw OidcTransactionAccess.get().endpointFailure(OAuthException.Reason.DOCUMENT_MALFORMED);
		} finally { if (bytes != null) Arrays.fill(bytes, (byte) 0); }
	}
	private static @NonNull String requiredString(@NonNull Map<@NonNull String, @NonNull JsonValue> members, @NonNull String name) {
		if (!(members.get(name) instanceof JsonString text) || text.getValue().isEmpty()) throw new IllegalArgumentException();
		return text.getValue();
	}
	private static @NonNull Set<@NonNull String> requiredSet(@NonNull Map<@NonNull String, @NonNull JsonValue> members, @NonNull String name) {
		if (!(members.get(name) instanceof JsonArray array) || array.getElements().isEmpty()) throw new IllegalArgumentException();
		Set<String> values = new LinkedHashSet<>();
		for (JsonValue item : array.getElements()) {
			if (!(item instanceof JsonString text) || text.getValue().isEmpty() || !values.add(text.getValue()))
				throw new IllegalArgumentException();
		}
		return Set.copyOf(values);
	}
	/**
	 * Starts explicit provider configuration for an exact issuer.
	 * @param issuer exact issuer identifier
	 * @return the builder
	 * @since 1.0.0
	 */
	public static @NonNull Builder withIssuer(@NonNull String issuer) { return new Builder(issuer); }
	/**
	 * Returns the optional token_endpoint_auth_signing_alg_values_supported role policy without enabling unknown names.
	 * @return names when present, retaining empty versus absent
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull Set<@NonNull String>> getTokenEndpointAuthSigningAlgValuesSupported() { return this.oauth.getTokenEndpointAuthSigningAlgValuesSupported(); }
	/**
	 * Returns the optional revocation_endpoint_auth_methods_supported role policy without enabling unknown names.
	 * @return names when present, retaining empty versus absent
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull Set<@NonNull String>> getRevocationEndpointAuthMethodsSupported() { return this.oauth.getRevocationEndpointAuthMethodsSupported(); }
	/**
	 * Returns the optional revocation_endpoint_auth_signing_alg_values_supported role policy without enabling unknown names.
	 * @return names when present, retaining empty versus absent
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull Set<@NonNull String>> getRevocationEndpointAuthSigningAlgValuesSupported() { return this.oauth.getRevocationEndpointAuthSigningAlgValuesSupported(); }
	/**
	 * Returns the optional introspection_endpoint_auth_signing_alg_values_supported role policy without enabling unknown names.
	 * @return names when present, retaining empty versus absent
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull Set<@NonNull String>> getIntrospectionEndpointAuthSigningAlgValuesSupported() { return this.oauth.getIntrospectionEndpointAuthSigningAlgValuesSupported(); }
	/**
	 * Returns the optional introspection_endpoint_auth_methods_supported role policy without enabling unknown names.
	 * @return names when present, retaining empty versus absent
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull Set<@NonNull String>> getIntrospectionEndpointAuthMethodsSupported() { return this.oauth.getIntrospectionEndpointAuthMethodsSupported(); }
	@NonNull AuthorizationServerMetadata oauthMetadata() { return this.oauth; }
	/**
	 * Returns the exact issuer.
	 *
	 * @return exact issuer
	 * @since 1.0.0
	 */
	public @NonNull String getIssuer() { return this.oauth.getIssuer(); }
	/**
	 * Returns the exact issuer string advertised by parsed metadata, or the configured issuer for explicit metadata.
	 * @return advertised issuer, possibly the selected Entra template
	 * @since 1.0.0
	 */
	public @NonNull String getAdvertisedIssuer() { return this.advertisedIssuer; }
	/**
	 * Returns the authorization endpoint.
	 *
	 * @return authorization endpoint
	 * @since 1.0.0
	 */
	public @NonNull URI getAuthorizationEndpoint() { return this.oauth.getAuthorizationEndpoint(); }
	/**
	 * Returns the token endpoint.
	 *
	 * @return token endpoint
	 * @since 1.0.0
	 */
	public @NonNull URI getTokenEndpoint() { return this.oauth.getTokenEndpoint(); }
	/**
	 * Returns the signing-key URI.
	 *
	 * @return signing-key URI
	 * @since 1.0.0
	 */
	public @NonNull URI getJwksUri() { return this.jwksUri; }
	/**
	 * Returns the optional UserInfo endpoint.
	 *
	 * @return optional UserInfo endpoint
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull URI> getUserInfoEndpoint() { return Optional.ofNullable(this.userInfoEndpoint); }
	/**
	 * Returns the subject types.
	 *
	 * @return subject types
	 * @since 1.0.0
	 */
	public @NonNull Set<@NonNull String> getSubjectTypesSupported() { return this.subjectTypes; }
	/**
	 * Returns the advertised ID-token algorithm names.
	 *
	 * @return advertised ID-token algorithm names
	 * @since 1.0.0
	 */
	public @NonNull Set<@NonNull String> getIdTokenSigningAlgValuesSupported() { return this.algorithms; }
	/**
	 * Returns the advertised response types.
	 *
	 * @return advertised response types
	 * @since 1.0.0
	 */
	public @NonNull Set<@NonNull String> getResponseTypesSupported() { return this.responseTypes; }
	/**
	 * Returns advertised signed-UserInfo algorithm names, or empty when absent. The client's registered algorithm
	 * must occur in this set when the provider advertises it.
	 * @return supported algorithm names when advertised
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull Set<@NonNull String>> getUserInfoSigningAlgValuesSupported() {
		return Optional.ofNullable(this.userInfoAlgorithms);
	}
	/**
	 * Redacts provider configuration.
	 * @return a redacted description
	 * @since 1.0.0
	 */
	@Override public @NonNull String toString() { return "OidcProviderMetadata{configuration=<redacted>}"; }
	/**
	 * Mutable explicit provider configuration.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	@CheckReturnValue
	public static final class Builder {
		private AuthorizationServerMetadata.Builder oauth;
		private @Nullable URI jwksUri;
		private @Nullable URI userInfoEndpoint;
		private Set<String> subjectTypes = Set.of("public");
		private Set<String> algorithms = Set.of("RS256");
		private Set<String> responseTypes = Set.of("code");
		private @Nullable Set<String> userInfoAlgorithms;
		/**
		 * Replaces the complete token_endpoint_auth_signing_alg_values_supported role policy.
		 * @param value names, or null to restore absence
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder tokenEndpointAuthSigningAlgValuesSupported(@Nullable Set<@NonNull String> value) { this.oauth = this.oauth.tokenEndpointAuthSigningAlgValuesSupported(value); return this; }
		/**
		 * Replaces the complete revocation_endpoint_auth_methods_supported role policy.
		 * @param value names, or null to restore absence
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder revocationEndpointAuthMethodsSupported(@Nullable Set<@NonNull String> value) { this.oauth = this.oauth.revocationEndpointAuthMethodsSupported(value); return this; }
		/**
		 * Replaces the complete revocation_endpoint_auth_signing_alg_values_supported role policy.
		 * @param value names, or null to restore absence
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder revocationEndpointAuthSigningAlgValuesSupported(@Nullable Set<@NonNull String> value) { this.oauth = this.oauth.revocationEndpointAuthSigningAlgValuesSupported(value); return this; }
		/**
		 * Replaces the complete introspection_endpoint_auth_signing_alg_values_supported role policy.
		 * @param value names, or null to restore absence
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder introspectionEndpointAuthSigningAlgValuesSupported(@Nullable Set<@NonNull String> value) { this.oauth = this.oauth.introspectionEndpointAuthSigningAlgValuesSupported(value); return this; }
		/**
		 * Replaces the complete introspection_endpoint_auth_methods_supported role policy.
		 * @param value names, or null to restore absence
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder introspectionEndpointAuthMethodsSupported(@Nullable Set<@NonNull String> value) { this.oauth = this.oauth.introspectionEndpointAuthMethodsSupported(value); return this; }
		private Builder(@NonNull String issuer) { this.oauth = AuthorizationServerMetadata.withIssuer(issuer); }
		/**
		 * Sets the authorizationEndpoint.
		 *
		 * @param value endpoint, or null to restore the unset default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder authorizationEndpoint(@Nullable URI value) { this.oauth = this.oauth.authorizationEndpoint(value); return this; }
		/**
		 * Sets the tokenEndpoint.
		 *
		 * @param value endpoint, or null to restore the unset default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder tokenEndpoint(@Nullable URI value) { this.oauth = this.oauth.tokenEndpoint(value); return this; }
		/**
		 * Sets the revocationEndpoint.
		 *
		 * @param value endpoint, or null to restore the unset default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder revocationEndpoint(@Nullable URI value) { this.oauth = this.oauth.revocationEndpoint(value); return this; }
		/**
		 * Sets the jwksUri.
		 *
		 * @param value endpoint, or null to restore the unset default, or null to clear
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder jwksUri(@Nullable URI value) { this.jwksUri = value; return this; }
		/**
		 * Sets the userInfoEndpoint.
		 *
		 * @param value endpoint, or null to restore the unset default, or null to clear
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder userInfoEndpoint(@Nullable URI value) { this.userInfoEndpoint = value; return this; }
		/**
		 * Replaces the complete subjectTypesSupported set. Null restores the explicit configuration default.
		 *
		 * @param value values, or null
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder subjectTypesSupported(@Nullable Set<@NonNull String> value) { this.subjectTypes = value == null ? Set.of("public") : Set.copyOf(value); return this; }
		/**
		 * Replaces the complete idTokenSigningAlgValuesSupported set. Null restores the explicit configuration default.
		 *
		 * @param value values, or null
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder idTokenSigningAlgValuesSupported(@Nullable Set<@NonNull String> value) { this.algorithms = value == null ? Set.of("RS256") : Set.copyOf(value); return this; }
		/**
		 * Replaces the complete responseTypesSupported set. Null restores the explicit configuration default.
		 *
		 * @param value values, or null
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder responseTypesSupported(@Nullable Set<@NonNull String> value) { this.responseTypes = value == null ? Set.of("code") : Set.copyOf(value); return this; }
		/**
		 * Replaces the complete advertised codeChallengeMethodsSupported set.
		 *
		 * @param value values, or null for absent
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder codeChallengeMethodsSupported(@Nullable Set<@NonNull String> value) { this.oauth = this.oauth.codeChallengeMethodsSupported(value); return this; }
		/**
		 * Replaces the complete advertised tokenEndpointAuthMethodsSupported set.
		 *
		 * @param value values, or null for absent
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder tokenEndpointAuthMethodsSupported(@Nullable Set<@NonNull String> value) { this.oauth = this.oauth.tokenEndpointAuthMethodsSupported(value); return this; }
		/**
		 * Replaces advertised signed-UserInfo algorithms. Null denotes absent advertisement.
		 * @param value complete supported set, or null
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder userInfoSigningAlgValuesSupported(@Nullable Set<@NonNull String> value) {
			if (value != null && (value.isEmpty() || value.contains("")))
				throw new IllegalArgumentException("UserInfo algorithm capabilities must not be empty.");
			this.userInfoAlgorithms = value == null ? null : Set.copyOf(value); return this;
		}
		/**
		 * Sets RFC 9207 callback issuer support.
		 *
		 * @param value whether advertised, or null to restore false
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder authorizationResponseIssuerSupported(@Nullable Boolean value) { this.oauth = this.oauth.authorizationResponseIssuerSupported(Boolean.TRUE.equals(value)); return this; }
		/**
		 * Builds explicit provider metadata without I/O.
		 *
		 * @return the metadata
		 * @since 1.0.0
		 */
		public @NonNull OidcProviderMetadata build() {
			if (this.jwksUri == null)
				throw new IllegalStateException("An OIDC provider requires a JWKS URI.");
			if (this.subjectTypes.isEmpty() || this.algorithms.isEmpty()
					|| this.responseTypes.isEmpty() || this.algorithms.contains("") || this.responseTypes.contains("")
					|| this.subjectTypes.stream().anyMatch(type -> !Set.of("public", "pairwise").contains(type)))
				throw new IllegalArgumentException("The OIDC provider metadata is incomplete or invalid.");
			return new OidcProviderMetadata(this);
		}
	}
}
