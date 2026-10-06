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
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.List;
import static com.revetsec.oauth.server.OAuthServerException.Reason.*;

/** Fixed local HTTP translation, independent of untrusted redirect/state/description or exception text. */
final class OAuthServerFailureBoundary {
	private OAuthServerFailureBoundary() {}
	static @NonNull OAuthServerException admission(@NonNull OAuthServerAdmissionFailure failure) {
		return switch(requireNonNull(failure).reason()) {
			case INVALID_TOKEN -> OAuthServerValidationException.fromReason(TOKEN_REVOKED);
			case INVALID_GRANT -> OAuthServerValidationException.fromReason(INVALID_GRANT);
			case INVALID_REQUEST -> OAuthServerValidationException.fromReason(MALFORMED_REQUEST);
			case INVALID_CLIENT -> OAuthServerValidationException.fromReason(INVALID_CLIENT);
			case UNAUTHORIZED_CLIENT -> OAuthServerValidationException.fromReason(UNAUTHORIZED_CLIENT);
			case INVALID_SCOPE -> OAuthServerValidationException.fromReason(INVALID_SCOPE);
			case INVALID_TARGET -> OAuthServerValidationException.fromReason(INVALID_RESOURCE);
			case UNSUPPORTED_RESPONSE_TYPE -> OAuthServerValidationException.fromReason(UNSUPPORTED_RESPONSE_TYPE);
			case UNSUPPORTED_GRANT_TYPE -> OAuthServerValidationException.fromReason(UNSUPPORTED_GRANT_TYPE);
			case INFRASTRUCTURE -> OAuthServerConfigurationException.fromReason(CONFIGURATION_INVALID);
		};
	}
	static @NonNull OAuthServerStoreException store(@NonNull OAuthStoreFailure failure) {
		return OAuthServerStoreException.fromReason(switch(requireNonNull(failure).reason()) {
			case UNAVAILABLE -> STORE_UNAVAILABLE; case CORRUPT_STATE -> STORE_CORRUPT; case COMMIT_OUTCOME_UNKNOWN -> COMMIT_OUTCOME_UNKNOWN;
		},false);
	}
	static @NonNull OAuthServerResponse failure(@NonNull OAuthServerException failure, int bodyCap, int headerCap) {
		requireNonNull(failure); return local(503,"server_error",null,false,bodyCap,headerCap);
	}
	static @NonNull OAuthServerResponse rejection(OAuthServerRequest.@NonNull Endpoint endpoint,
		OAuthServerException.@NonNull Reason reason, boolean basicAuthenticationUsed, int bodyCap, int headerCap) {
		requireNonNull(endpoint); requireNonNull(reason).requireKind(OAuthServerException.Kind.VALIDATION);
		String error=switch(reason) {
			case INVALID_CLIENT,UNKNOWN_CLIENT -> "invalid_client";
			case UNAUTHORIZED_CLIENT -> "unauthorized_client";
			case UNSUPPORTED_GRANT_TYPE -> "unsupported_grant_type";
			case UNSUPPORTED_RESPONSE_TYPE -> "unsupported_response_type";
			case INVALID_SCOPE -> "invalid_scope";
			case INVALID_RESOURCE -> "invalid_target";
			case INVALID_GRANT,REFRESH_REUSE,PKCE_MISMATCH -> "invalid_grant";
			case ACCESS_DENIED -> "access_denied";
			default -> "invalid_request";
		};
		boolean challenge=error.equals("invalid_client") && endpoint!=OAuthServerRequest.Endpoint.AUTHORIZATION
			&& (basicAuthenticationUsed || endpoint==OAuthServerRequest.Endpoint.INTROSPECTION);
		String allow=reason==METHOD_NOT_ALLOWED ? endpoint==OAuthServerRequest.Endpoint.AUTHORIZATION ? "GET" : "POST" : null;
		return local(allow!=null ? 405 : challenge ? 401 : 400,error,allow,challenge,bodyCap,headerCap);
	}
	private static @NonNull OAuthServerResponse local(int status, @NonNull String error, @Nullable String allow,
		boolean challenge, int bodyCap, int headerCap) {
		byte[] body=("{\"error\":\""+error+"\"}").getBytes(StandardCharsets.US_ASCII);
		Map<String,List<String>> headers=OAuthServerResponse.privateHeaders(body.length);
		if(allow!=null) headers.put("Allow",List.of(allow));
		if(challenge) headers.put("WWW-Authenticate",List.of("Basic realm=\"oauth\""));
		return OAuthServerResponse.prepare(status,headers,null,body,bodyCap,headerCap);
	}
}
