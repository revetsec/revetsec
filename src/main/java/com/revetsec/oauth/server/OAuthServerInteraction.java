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
import java.net.URI;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

/**
 * A restricted view of a checked, pending browser interaction. The application owns login, session fixation
 * and CSRF protection. The secret interaction handle is not a subject or proof of user authentication.
 * Client display text is untrusted and must be escaped. Identity equality and diagnostics disclose no data.
 * @since 1.0.0
 */
@Immutable
public final class OAuthServerInteraction {
	private final @NonNull String value, clientId;
	private final @Nullable String clientName;
	private final @NonNull URI redirectUri;
	private final @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> scopes;
	private final @NonNull Instant expires;
	private OAuthServerInteraction(@NonNull String value, @NonNull String clientId, @Nullable String clientName,
		@NonNull URI redirectUri, @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> scopes, @NonNull Instant expires) {
		this.value=value; this.clientId=clientId; this.clientName=clientName; this.redirectUri=redirectUri;
		this.scopes=Map.copyOf(scopes); this.expires=expires;
	}
	// The engine supplies only a freshly authenticated pending record, never a previous UI view.
	static @NonNull OAuthServerInteraction fromRecord(@NonNull String value, @NonNull OAuthAuthorizationRecord record,
		@Nullable String clientName, @NonNull OAuthServerIngressLimits limits) {
		OAuthStoreFormat.nonce(value); requireNonNull(record); requireNonNull(limits);
		if (!record.text("status").equals("PENDING") || !OAuthAuthorizationRecord.equalDigest(OAuthAuthorizationRecord.credentialDigest(value),record.text("id"))) throw OAuthStoreFormat.invalid();
		if (clientName!=null) OAuthServerConfiguration.text(clientName,255);
		return new OAuthServerInteraction(value,record.text("clientId"),clientName,URI.create(record.text("redirect")),
			Map.of(record.text("resource"),Set.copyOf(record.scopes(limits))),record.expires());
	}
	/** Returns the secret continuation handle; use only inside the protected application session.
	 * @return secret continuation handle
	 * @since 1.0.0
	 */
	@CheckReturnValue public @NonNull String getInteractionValue() { return this.value; }
	/** Returns the checked client identifier.
	 * @return checked client identifier
	 * @since 1.0.0
	 */
	@CheckReturnValue public @NonNull String getClientId() { return this.clientId; }
	/** Returns optional untrusted display text that the application must escape.
	 * @return optional display text
	 * @since 1.0.0
	 */
	@CheckReturnValue public @NonNull Optional<@NonNull String> getClientName() { return Optional.ofNullable(this.clientName); }
	/** Returns the exact checked return destination for display, without state or issued credentials.
	 * @return selected registered redirect URI
	 * @since 1.0.0
	 */
	@CheckReturnValue public @NonNull URI getRedirectUri() { return this.redirectUri; }
	/** Returns the immutable exact requested resource and scopes for explicit application approval.
	 * @return requested scopes by resource
	 * @since 1.0.0
	 */
	@CheckReturnValue public @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> getRequestedScopesByResource() { return this.scopes; }
	/** Returns the pending interaction expiry; completion rechecks current authoritative state.
	 * @return expiry instant
	 * @since 1.0.0
	 */
	@CheckReturnValue public @NonNull Instant getExpiresAt() { return this.expires; }
	/** Returns a fixed redacted description.
	 * @return fixed redacted description
	 * @since 1.0.0
	 */
	@Override public @NonNull String toString() { return "OAuthServerInteraction{<redacted>}"; }
}
