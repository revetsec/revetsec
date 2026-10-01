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

import com.revetsec.internal.json.JsonFields;
import com.revetsec.internal.json.JsonFieldException;
import com.revetsec.oauth.TokenResponse;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonString;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * One fully validated code-flow authentication. The exact issuer and subject pair is the stable account key
 * (OpenID Connect Core section 5.7); email is never an account key. No public constructor or parse-only factory exists.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class OidcAuthentication {
	private final String clientId;
	private final IdToken idToken;
	private final TokenResponse tokens;
	private final OidcSessionReference sessionReference;
	OidcAuthentication(@NonNull IdToken idToken, @NonNull TokenResponse tokens, @NonNull String clientId) {
		this.clientId = java.util.Objects.requireNonNull(clientId);
		this.idToken = idToken; this.tokens = tokens; this.sessionReference = new OidcSessionReference(idToken, clientId);
	}
	@NonNull String clientId() { return this.clientId; }
	/**
	 * Returns the exact validated issuer.
	 *
	 * @return issuer
	 * @since 1.0.0
	 */
	public @NonNull String getIssuer() { return this.idToken.getClaims().getIssuer().orElseThrow(); }
	/**
	 * Returns the validated subject, scoped to this issuer.
	 *
	 * @return subject
	 * @since 1.0.0
	 */
	public @NonNull String getSubject() { return this.idToken.getClaims().getSubject().orElseThrow(); }
	/**
	 * Returns the validated ID token.
	 *
	 * @return ID token
	 * @since 1.0.0
	 */
	public @NonNull IdToken getIdToken() { return this.idToken; }
	/**
	 * Returns endpoint tokens only after ID-token validation.
	 *
	 * @return tokens
	 * @since 1.0.0
	 */
	public @NonNull TokenResponse getTokens() { return this.tokens; }
	/**
	 * Returns the validated authentication time when present.
	 *
	 * @return authentication time
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull Instant> getAuthenticationTime() {
		try { return JsonFields.numericDate(this.idToken.getClaims().toJsonObject(), "auth_time"); }
		catch (JsonFieldException impossible) { throw new IllegalStateException("Validated authentication time is invalid."); }
	}
	/**
	 * Returns the validated ACR when present.
	 *
	 * @return ACR
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull String> getAuthenticationContextClassReference() {
		return this.idToken.getClaims().getClaim("acr").map(value -> ((JsonString) value).getValue());
	}
	/**
	 * Returns validated authentication method references, or an empty list.
	 *
	 * @return authentication methods
	 * @since 1.0.0
	 */
	public @NonNull List<@NonNull String> getAuthenticationMethodReferences() {
		return this.idToken.getClaims().getClaim("amr").map(value -> ((JsonArray) value).getElements().stream()
				.map(element -> ((JsonString) element).getValue()).toList()).orElse(List.of());
	}
	/**
	 * Returns a persistence reference for continuity checks. It is not proof of identity.
	 *
	 * @return session reference
	 * @since 1.0.0
	 */
	public @NonNull OidcSessionReference getSessionReference() { return this.sessionReference; }
	/**
	 * Redacts identity and credentials.
	 *
	 * @return a redacted description
	 * @since 1.0.0
	 */
	@Override public @NonNull String toString() { return "OidcAuthentication{identity=<redacted>, tokens=<redacted>}"; }
}
