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
import javax.annotation.concurrent.Immutable;
import java.util.Map;
import java.util.Set;

/**
 * Issuer-created grant facts supplied to the application's continuing authorization policy.
 * This type has no application factory or builder and contains no raw code or refresh credential.
 * The grant management handle is sensitive; release it only to trusted application management code.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class OAuthGrantContext {
	private final @NonNull String subject;
	private final @NonNull String clientId;
	private final @NonNull String grantType;
	private final @NonNull String grantValue;
	private final @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> authorizedScopesByResource;
	private final boolean refreshTokenPermitted;
	private OAuthGrantContext(@NonNull String subject, @NonNull String clientId, @NonNull String grantType,
			@NonNull String grantValue, @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> resources,
			boolean refreshTokenPermitted) {
		this.subject = subject; this.clientId = clientId; this.grantType = grantType; this.grantValue = grantValue;
		this.authorizedScopesByResource = Map.copyOf(resources); this.refreshTokenPermitted = refreshTokenPermitted;
	}
	// Called only after the engine has validated and bound these facts. Value checks do not authenticate a grant.
	static @NonNull OAuthGrantContext fromCheckedGrant(@NonNull String subject, @NonNull String clientId,
			@NonNull String grantType, @NonNull String grantValue,
			@NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> resources, boolean refreshTokenPermitted) {
		OAuthServerConfiguration.text(subject, OAuthServerConfiguration.MAXIMUM_SUBJECT_LENGTH);
		OAuthServerConfiguration.text(clientId, OAuthServerConfiguration.MAXIMUM_CLIENT_ID_LENGTH);
		OAuthServerConfiguration.text(grantType, OAuthServerConfiguration.MAXIMUM_TEXT_LENGTH);
		OAuthServerConfiguration.text(grantValue, OAuthServerConfiguration.MAXIMUM_TEXT_LENGTH);
		if (!grantType.equals("authorization_code") && !grantType.equals("refresh_token")) throw OAuthServerConfiguration.invalid();
		return new OAuthGrantContext(subject, clientId, grantType, grantValue,
				OAuthServerConfiguration.resources(resources, 1), refreshTokenPermitted);
	}
	/**
	 * Returns the checked issuer-local subject.
	 * @return the configured value
	 * @since 1.0.0
	 */
	public @NonNull String getSubject() { return this.subject; }
	/**
	 * Returns the exact checked client identifier.
	 * @return the configured value
	 * @since 1.0.0
	 */
	public @NonNull String getClientId() { return this.clientId; }
	/**
	 * Returns the authorization_code or refresh_token operation being checked.
	 * @return the configured value
	 * @since 1.0.0
	 */
	public @NonNull String getGrantType() { return this.grantType; }
	/**
	 * Explicitly releases the sensitive grant handle for trusted application management; never log it.
	 * @return the configured value
	 * @since 1.0.0
	 */
	public @NonNull String getGrantValue() { return this.grantValue; }
	/**
	 * Returns the immutable complete checked resource/scope grant.
	 * @return the configured value
	 * @since 1.0.0
	 */
	public @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> getAuthorizedScopesByResource() { return this.authorizedScopesByResource; }
	/**
	 * Returns whether the checked grant permits refresh.
	 * @return the configured value
	 * @since 1.0.0
	 */
	public @NonNull Boolean isRefreshTokenPermitted() { return this.refreshTokenPermitted; }
	/**
	 * Redacts all grant facts and the management handle from diagnostics.
	 * @return a fixed description
	 * @since 1.0.0
	 */
	@Override public @NonNull String toString() { return "OAuthGrantContext{grant=<redacted>}"; }
}
