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

import com.revetsec.oauth.RefreshToken;
import com.revetsec.oauth.TokenResponse;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import java.util.Optional;
import static java.util.Objects.requireNonNull;

/**
 * Tokens from one refresh, released after any returned ID token passes signature, profile and original-session
 * continuity checks. An omitted ID token yields no new identity. The original reference remains a continuity
 * comparison value and is not proof of identity. Applications serialize concurrent refreshes and store tokens.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class OidcRefreshResult {
	private final TokenResponse tokens;
	private final @Nullable IdToken idToken;
	private final RefreshToken refreshToken;
	private final OidcSessionReference original;
	OidcRefreshResult(@NonNull TokenResponse tokens, @Nullable IdToken idToken, @NonNull RefreshToken previous, @NonNull OidcSessionReference original) {
		this.tokens = requireNonNull(tokens); this.idToken = idToken; this.original = requireNonNull(original);
		this.refreshToken = tokens.getRefreshToken().orElse(requireNonNull(previous));
	}
	/**
	 * Returns the endpoint tokens. The raw id_token is absent from its safe parameter view.
	 * @return token response
	 * @since 1.0.0
	 */
	public @NonNull TokenResponse getTokens() { return this.tokens; }
	/**
	 * Returns the newly verified ID token, if the provider returned one. An absent value establishes no new identity.
	 * @return verified ID token
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull IdToken> getIdToken() { return Optional.ofNullable(this.idToken); }
	/**
	 * Returns the replacement refresh token, or the previous token when no replacement was returned.
	 * @return refresh credential to retain securely
	 * @since 1.0.0
	 */
	public @NonNull RefreshToken getRefreshToken() { return this.refreshToken; }
	/**
	 * Returns the original reference for subsequent refresh comparisons. Parsing it never authenticates identity.
	 * @return original continuity reference
	 * @since 1.0.0
	 */
	public @NonNull OidcSessionReference getSessionReference() { return this.original; }
	/**
	 * Redacts tokens and continuity data.
	 * @return redacted description
	 * @since 1.0.0
	 */
	@Override public @NonNull String toString() { return "OidcRefreshResult{credentials=<redacted>, session=<redacted>}"; }
}
