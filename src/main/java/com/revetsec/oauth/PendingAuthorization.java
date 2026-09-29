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

import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * One pending browser authorization, including secret state, PKCE verifier and an OIDC nonce slot. The public
 * accessors expose only descriptive fields. The complete record can be placed in a sealed cookie or saved in a
 * browser-bound store; neither path exposes a free-standing serializer. A sealed cookie can be replayed concurrently:
 * use a durable shared atomic store when client-side single use is required across callbacks, nodes or restarts.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class PendingAuthorization {
	private final @NonNull String kind;
	private final @NonNull String issuer;
	private final @NonNull String clientId;
	private final @NonNull URI redirectUri;
	private final @NonNull String state;
	private final @NonNull String verifier;
	private final @Nullable String nonce;
	private final @NonNull Set<@NonNull String> scopes;
	private final @NonNull List<@NonNull URI> resources;
	private final AuthorizationRequestOptions.@NonNull ResponseMode responseMode;
	private final @NonNull Instant createdAt;
	private final @NonNull Instant expiresAt;
	private final @NonNull Map<@NonNull String, @NonNull String> applicationData;
	private final boolean issuerRequired;
	private final @NonNull URI authorizationEndpoint;
	private final @NonNull URI tokenEndpoint;

	PendingAuthorization(@NonNull String kind, @NonNull String issuer, @NonNull String clientId,
			@NonNull URI redirectUri, @NonNull String state, @NonNull String verifier, @Nullable String nonce,
			@NonNull Set<@NonNull String> scopes, @NonNull List<@NonNull URI> resources,
			AuthorizationRequestOptions.@NonNull ResponseMode responseMode, @NonNull Instant createdAt,
			@NonNull Instant expiresAt, @NonNull Map<@NonNull String, @NonNull String> applicationData,
			boolean issuerRequired, @NonNull URI authorizationEndpoint, @NonNull URI tokenEndpoint) {
		this.kind = requireNonNull(kind);
		this.issuer = requireNonNull(issuer);
		this.clientId = requireNonNull(clientId);
		this.redirectUri = requireNonNull(redirectUri);
		this.state = requireNonNull(state);
		this.verifier = requireNonNull(verifier);
		this.nonce = nonce;
		this.scopes = Set.copyOf(scopes);
		this.resources = List.copyOf(resources);
		this.responseMode = requireNonNull(responseMode);
		this.createdAt = requireNonNull(createdAt);
		this.expiresAt = requireNonNull(expiresAt);
		this.applicationData = Map.copyOf(applicationData);
		this.issuerRequired = issuerRequired;
		this.authorizationEndpoint = requireNonNull(authorizationEndpoint);
		this.tokenEndpoint = requireNonNull(tokenEndpoint);
	}

	/**
	 * Returns the initiating authorization-server issuer.
	 *
	 * @return the issuer
	 * @since 1.0.0
	 */
	public @NonNull String getIssuer() { return this.issuer; }

	/**
	 * Returns the initiating client ID.
	 *
	 * @return the client ID
	 * @since 1.0.0
	 */
	public @NonNull String getClientId() { return this.clientId; }

	/**
	 * Returns the exact registered redirect URI sent at begin.
	 *
	 * @return the redirect URI
	 * @since 1.0.0
	 */
	public @NonNull URI getRedirectUri() { return this.redirectUri; }

	/**
	 * Returns the requested scope set.
	 *
	 * @return scopes
	 * @since 1.0.0
	 */
	public @NonNull Set<@NonNull String> getRequestedScopes() { return this.scopes; }

	/**
	 * Returns the creation instant.
	 *
	 * @return creation
	 * @since 1.0.0
	 */
	public @NonNull Instant getCreatedAt() { return this.createdAt; }

	/**
	 * Returns the authenticated expiry instant.
	 *
	 * @return expiry
	 * @since 1.0.0
	 */
	public @NonNull Instant getExpiresAt() { return this.expiresAt; }

	/**
	 * Returns application data, authenticated but still subject to application redirect allowlisting.
	 *
	 * @return data
	 * @since 1.0.0
	 */
	public @NonNull Map<@NonNull String, @NonNull String> getApplicationData() { return this.applicationData; }

	/**
	 * Seals the complete record under the pending-authorization label and exact application context.
	 *
	 * @param sealer the active and verification keys
	 * @param context an application-chosen fixed context
	 * @return the sealed form for a secure browser cookie
	 * @since 1.0.0
	 */
	public @NonNull String toSealedForm(@NonNull StateSealer sealer, @NonNull String context) {
		return SealedStateAccess.get().seal(requireNonNull(sealer), SealedStateType.PENDING_AUTHORIZATION,
				PendingAuthorizationCodec.encode(this, null), requireNonNull(context), this.expiresAt);
	}

	/**
	 * Saves the complete record with a digest of the browser binding. The store receives its exact expiry and must
	 * consume atomically.
	 *
	 * @param store the store
	 * @param browserBinding a browser-specific secret
	 * @since 1.0.0
	 */
	public void saveTo(@NonNull PendingAuthorizationStore store, @NonNull String browserBinding) {
		requireNonNull(store).save(requireNonNull(browserBinding), this.state,
				PendingAuthorizationCodec.encode(this, PendingAuthorizationCodec.bindingDigest(browserBinding)),
				this.expiresAt);
	}

	String kind() { return this.kind; }
	String state() { return this.state; }
	String verifier() { return this.verifier; }
	@Nullable String nonce() { return this.nonce; }
	List<URI> resources() { return this.resources; }
	AuthorizationRequestOptions.ResponseMode responseMode() { return this.responseMode; }
	boolean issuerRequired() { return this.issuerRequired; }
	URI authorizationEndpoint() { return this.authorizationEndpoint; }
	URI tokenEndpoint() { return this.tokenEndpoint; }

	/**
	 * Redacts all pending secrets and application data.
	 *
	 * @return a redacted description
	 * @since 1.0.0
	 */
	@Override
	public @NonNull String toString() { return "PendingAuthorization{secrets=<redacted>}"; }
}
