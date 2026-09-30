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

import com.revetsec.oauth.OAuthObserver;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.ThreadSafe;

/**
 * Receives caller-thread OIDC events and the inherited OAuth/JOSE endpoint events. Hooks carry no tokens or claims.
 * Hook failures are contained except for VirtualMachineError; implementations must be thread-safe and fast.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public interface OidcObserver extends OAuthObserver {
	/**
	 * Returns a silent observer.
	 * @return the disabled observer
	 * @since 1.0.0
	 */
	static @NonNull OidcObserver disabledInstance() { return DisabledOidcObserver.INSTANCE; }
	/**
	 * Called after a client successfully builds with an explicit compatibility mode.
	 * @param mode enabled mode; no credential is passed
	 * @since 1.0.0
	 */
	default void didEnableCompatibilityMode(@NonNull OidcCompatibilityMode mode) { }
	/**
	 * Called when validation uses the mode, including when its signature or later checks fail.
	 * @param mode used mode; no credential or token is passed
	 * @since 1.0.0
	 */
	default void didUseCompatibilityMode(@NonNull OidcCompatibilityMode mode) { }
	/**
	 * Called when an ID token or OIDC token response fails validation, before token release.
	 * @param exception the same fixed-message exception the caller receives
	 * @since 1.0.0
	 */
	default void didRejectIdToken(@NonNull OidcValidationException exception) { }
	/**
	 * Called after successful OIDC validation. No identity or credential is passed.
	 * @since 1.0.0
	 */
	default void didCompleteAuthentication() { }
	/**
	 * Called when a UserInfo response fails profile validation. No claims or credentials are passed.
	 * @param exception fixed-message rejection
	 * @since 1.0.0
	 */
	default void didRejectUserInfo(@NonNull OidcValidationException exception) { }
	/**
	 * Called after the UserInfo subject matches the verified authentication.
	 * @param signed whether a signed response was validated
	 * @since 1.0.0
	 */
	default void didFetchUserInfo(@NonNull Boolean signed) { }
	/**
	 * Called when refresh profile/continuity checks reject. No endpoint credential or rejected claim is passed.
	 * @param exception fixed-message rejection
	 * @since 1.0.0
	 */
	default void didRejectRefresh(@NonNull OidcValidationException exception) { }
	/**
	 * Called after refresh tokens are released following all required ID-token checks.
	 * @param idTokenReturned whether a new verified ID token was returned
	 * @param refreshTokenReturned whether the endpoint supplied a replacement refresh token
	 * @since 1.0.0
	 */
	default void didRefreshTokens(@NonNull Boolean idTokenReturned, @NonNull Boolean refreshTokenReturned) { }

}
