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

import static java.util.Objects.requireNonNull;
import com.revetsec.jose.*;
import com.revetsec.json.*;
import java.time.*;
import java.util.*;
import javax.annotation.concurrent.Immutable;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Access-token proof released only after all configured profile checks. Claims access is sensitive.
 * No received credential is retained; diagnostic text contains no identity, claim or scope data.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class VerifiedAccessToken {

	@NonNull
	private final String issuer;

	@Nullable
	private final String subject;

	@Nullable
	private final String clientId;

	@NonNull
	private final Set<@NonNull String> scopes;

	@NonNull
	private final List<@NonNull String> audiences;

	@Nullable
	private final Instant expiresAt;

	@NonNull
	private final JsonObject claims;

	VerifiedAccessToken(@NonNull String issuer, @Nullable String subject, @Nullable String clientId, @NonNull Set<@NonNull String> scopes, @NonNull List<@NonNull String> audiences, @Nullable Instant expiresAt, @NonNull JsonObject claims) {
		this.issuer = requireNonNull(issuer);
		this.subject = subject;
		this.clientId = clientId;
		this.scopes = Set.copyOf(scopes);
		this.audiences = List.copyOf(audiences);
		this.expiresAt = expiresAt;
		this.claims = requireNonNull(claims);
	}

	/**
	 * Returns the configured authoritative issuer; introspection may omit the issuer member.
	 * @return issuer
	 * @since 1.0.0
	 */
	@NonNull
	public String getIssuer() {
		return this.issuer;
	}

	/**
	 * Returns the checked subject, when supplied.
	 * @return subject
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull String> getSubject() {
		return Optional.ofNullable(this.subject);
	}

	/**
	 * Returns the checked client ID, when supplied.
	 * @return clientId
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull String> getClientId() {
		return Optional.ofNullable(this.clientId);
	}

	/**
	 * Returns the checked scopes; the application decides permission.
	 * @return scopes
	 * @since 1.0.0
	 */
	@NonNull
	public Set<@NonNull String> getScopes() {
		return this.scopes;
	}

	/**
	 * Returns the checked audiences.
	 * @return audiences
	 * @since 1.0.0
	 */
	@NonNull
	public List<@NonNull String> getAudiences() {
		return this.audiences;
	}

	/**
	 * Returns the checked expiry, when supplied.
	 * @return expiresAt
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull Instant> getExpiresAt() {
		return Optional.ofNullable(this.expiresAt);
	}

	/**
	 * Returns the checked claims; this explicit access may reveal sensitive data.
	 * @return claims
	 * @since 1.0.0
	 */
	@NonNull
	public JsonObject getClaims() {
		return this.claims;
	}

	/**
	 * Returns a redacted description.
	 * @return description
	 * @since 1.0.0
	 */
	@Override
	@NonNull
	public String toString() {
		return "VerifiedAccessToken{data=<redacted>}";
	}
}
