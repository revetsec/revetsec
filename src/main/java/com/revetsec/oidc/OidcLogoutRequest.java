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

import com.revetsec.internal.encoding.FormUrlEncoding;
import com.revetsec.internal.encoding.EncodingException;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;
import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A prepared browser request, not provider-session termination or authenticated identity. GET and form POST
 * getters deliberately emit the retained ID-token credential; never log them. Local session termination and
 * POST/CSRF authorization precede preparation. On the store path deliver only after pending save reports SAVED.
 * No server request to the logout endpoint or automatic retry occurs. The 128 KiB representation ceiling is not a
 * promise that every browser/provider accepts maximal GET URLs.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class OidcLogoutRequest {
	private final @NonNull URI redirectUri, action;
	private final @NonNull Map<@NonNull String, @NonNull String> parameters;
	private final @NonNull String body;
	private final @NonNull PendingOidcLogout pending;
	OidcLogoutRequest(@NonNull URI endpoint, @NonNull String clientId, @NonNull URI callback, @NonNull String compact, @NonNull String state, @NonNull PendingOidcLogout pending) {
		Map<String, String> values = new LinkedHashMap<>(); values.put("id_token_hint", compact); values.put("client_id", clientId); values.put("post_logout_redirect_uri", callback.toASCIIString()); values.put("state", state);
		try {
			StringBuilder form = new StringBuilder();
			for (Map.Entry<String, String> field : values.entrySet()) {
				String name = FormUrlEncoding.encode(field.getKey()), value = FormUrlEncoding.encode(field.getValue());
				if ((long) form.length() + name.length() + value.length() + 2 > OidcLogoutSupport.REQUEST_LIMIT) throw OidcLogoutSupport.failure(OidcLogoutException.Reason.INPUT_LIMIT);
				if (!form.isEmpty()) form.append('&'); form.append(name).append('=').append(value);
			}
			this.body = form.toString(); String base = endpoint.toASCIIString();
			if ((long) base.length() + this.body.length() + 1 > OidcLogoutSupport.REQUEST_LIMIT) throw OidcLogoutSupport.failure(OidcLogoutException.Reason.INPUT_LIMIT);
			this.redirectUri = URI.create(base + (endpoint.getRawQuery() == null ? "?" : endpoint.getRawQuery().isEmpty() ? "" : "&") + this.body);
		} catch (EncodingException invalid) { throw OidcLogoutSupport.failure(OidcLogoutException.Reason.INPUT_LIMIT); }
		this.action = endpoint; this.parameters = Collections.unmodifiableMap(new LinkedHashMap<>(values)); this.pending = pending;
	}
	/** Explicitly emits a credential-bearing GET target.
	 * @return browser redirect URI; never log it
	 * @since 1.0.0
	 */
	public @NonNull URI getRedirectUri() { return this.redirectUri; }
	/** Returns the trusted form action, preserving allowed provider query parameters.
	 * @return form POST action
	 * @since 1.0.0
	 */
	public @NonNull URI getFormAction() { return this.action; }
	/** Explicitly emits immutable credential-bearing form parameters.
	 * @return form parameters; never log them
	 * @since 1.0.0
	 */
	public @NonNull Map<@NonNull String, @NonNull String> getFormParameters() { return this.parameters; }
	/** Explicitly emits the UTF8 application/x-www-form-urlencoded credential-bearing form body.
	 * @return browser POST body; never log it
	 * @since 1.0.0
	 */
	public @NonNull String toFormBody() { return this.body; }
	/** Returns the independent correlation record to save or seal before browser delivery.
	 * @return pending logout state, not authentication proof
	 * @since 1.0.0
	 */
	public @NonNull PendingOidcLogout getPending() { return this.pending; }
	/** Redacts all credential and state fields.
	 * @return redacted description
	 * @since 1.0.0
	 */
	@Override public @NonNull String toString() { return "OidcLogoutRequest{credential=<redacted>, correlation=<redacted>}"; }
}
