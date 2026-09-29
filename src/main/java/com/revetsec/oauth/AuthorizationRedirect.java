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

import javax.annotation.concurrent.Immutable;
import java.net.URI;

import static java.util.Objects.requireNonNull;

/**
 * A browser redirect and its pending authorization. The authorization URI contains transient state and must not be
 * logged. Store or seal the pending object before sending the redirect. Applications set and clear cookies.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class AuthorizationRedirect {
	private final @NonNull URI authorizationUri;
	private final @NonNull PendingAuthorization pendingAuthorization;

	AuthorizationRedirect(@NonNull URI authorizationUri, @NonNull PendingAuthorization pendingAuthorization) {
		this.authorizationUri = requireNonNull(authorizationUri);
		this.pendingAuthorization = requireNonNull(pendingAuthorization);
	}

	/**
	 * Returns the browser redirect URI, including state and PKCE challenge.
	 *
	 * @return the URI
	 * @since 1.0.0
	 */
	public @NonNull URI getAuthorizationUri() { return this.authorizationUri; }

	/**
	 * Returns the pending authorization to seal or store.
	 *
	 * @return pending authorization
	 * @since 1.0.0
	 */
	public @NonNull PendingAuthorization getPendingAuthorization() { return this.pendingAuthorization; }

	/**
	 * Returns an optional per-flow cookie name. The suffix selects a cookie, not authenticates it.
	 *
	 * @return cookie name
	 * @since 1.0.0
	 */
	public @NonNull String getPerFlowCookieName() {
		return OAuthCookieNames.fromState(this.pendingAuthorization.state());
	}

	/**
	 * Redacts the authorization URI and pending secrets.
	 *
	 * @return a redacted description
	 * @since 1.0.0
	 */
	@Override
	public @NonNull String toString() { return "AuthorizationRedirect{uri=<redacted>}"; }
}
