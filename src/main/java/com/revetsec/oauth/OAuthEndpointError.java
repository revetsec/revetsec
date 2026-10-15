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
import static java.util.Objects.requireNonNull;

/**
 * Fixed OAuth and OpenID Connect protocol errors for endpoint and checked authorization rejections.
 * Unknown extension codes share one fallback and never become diagnostic text. A later release may add constants;
 * consuming switches should include a default branch.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public enum OAuthEndpointError {
	/** The endpoint reported invalid_request. */
	INVALID_REQUEST,
	/** The endpoint reported unauthorized_client. */
	UNAUTHORIZED_CLIENT,
	/** The endpoint reported access_denied. */
	ACCESS_DENIED,
	/** The endpoint reported unsupported_response_type. */
	UNSUPPORTED_RESPONSE_TYPE,
	/** The endpoint reported invalid_scope. */
	INVALID_SCOPE,
	/** The endpoint reported server_error. */
	SERVER_ERROR,
	/** The endpoint reported temporarily_unavailable. */
	TEMPORARILY_UNAVAILABLE,
	/** The endpoint reported invalid_client. */
	INVALID_CLIENT,
	/** The endpoint reported invalid_grant. */
	INVALID_GRANT,
	/** The endpoint reported unsupported_grant_type. */
	UNSUPPORTED_GRANT_TYPE,
	/** The endpoint reported unsupported_token_type. */
	UNSUPPORTED_TOKEN_TYPE,
	/** The endpoint reported invalid_token. */
	INVALID_TOKEN,
	/** The endpoint reported insufficient_scope. */
	INSUFFICIENT_SCOPE,
	/** The endpoint reported login_required. */
	LOGIN_REQUIRED,
	/** The endpoint reported interaction_required. */
	INTERACTION_REQUIRED,
	/** The endpoint reported account_selection_required. */
	ACCOUNT_SELECTION_REQUIRED,
	/** The endpoint reported consent_required. */
	CONSENT_REQUIRED,
	/** The endpoint reported invalid_request_uri. */
	INVALID_REQUEST_URI,
	/** The endpoint reported invalid_request_object. */
	INVALID_REQUEST_OBJECT,
	/** The endpoint reported request_not_supported. */
	REQUEST_NOT_SUPPORTED,
	/** The endpoint reported request_uri_not_supported. */
	REQUEST_URI_NOT_SUPPORTED,
	/** The endpoint reported registration_not_supported. */
	REGISTRATION_NOT_SUPPORTED,
	/** The endpoint supplied an absent or unrecognized error code; no supplied text is retained. */
	UNRECOGNIZED;

	/**
	 * Interprets an exact wire error code without retaining supplied text.
	 * @param wireValue supplied protocol error code
	 * @return fixed error or the unrecognized fallback
	 * @throws NullPointerException if the code is null
	 * @since 1.0.0
	 */
	public static @NonNull OAuthEndpointError fromWireValue(@NonNull String wireValue) {
		return switch (requireNonNull(wireValue)) {
			case "invalid_request" -> INVALID_REQUEST;
			case "unauthorized_client" -> UNAUTHORIZED_CLIENT;
			case "access_denied" -> ACCESS_DENIED;
			case "unsupported_response_type" -> UNSUPPORTED_RESPONSE_TYPE;
			case "invalid_scope" -> INVALID_SCOPE;
			case "server_error" -> SERVER_ERROR;
			case "temporarily_unavailable" -> TEMPORARILY_UNAVAILABLE;
			case "invalid_client" -> INVALID_CLIENT;
			case "invalid_grant" -> INVALID_GRANT;
			case "unsupported_grant_type" -> UNSUPPORTED_GRANT_TYPE;
			case "unsupported_token_type" -> UNSUPPORTED_TOKEN_TYPE;
			case "invalid_token" -> INVALID_TOKEN;
			case "insufficient_scope" -> INSUFFICIENT_SCOPE;
			case "login_required" -> LOGIN_REQUIRED;
			case "interaction_required" -> INTERACTION_REQUIRED;
			case "account_selection_required" -> ACCOUNT_SELECTION_REQUIRED;
			case "consent_required" -> CONSENT_REQUIRED;
			case "invalid_request_uri" -> INVALID_REQUEST_URI;
			case "invalid_request_object" -> INVALID_REQUEST_OBJECT;
			case "request_not_supported" -> REQUEST_NOT_SUPPORTED;
			case "request_uri_not_supported" -> REQUEST_URI_NOT_SUPPORTED;
			case "registration_not_supported" -> REGISTRATION_NOT_SUPPORTED;
			default -> UNRECOGNIZED;
		};
	}
}
