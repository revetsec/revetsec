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

import com.revetsec.jose.JoseException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * An ID token, UserInfo response or refresh continuity check failed. The exception retains only fixed reasons;
 * it never retains the rejected token, a claim, a lower-layer exception or any access or refresh token.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@NotThreadSafe
public final class OidcValidationException extends OidcException {
	private static final long serialVersionUID = 1L;
	/** The failed OIDC check. */
	private final @NonNull Reason reason;
	/** The lower-layer reason, without the lower-layer exception. */
	private final JoseException.@Nullable Reason joseReason;

	private OidcValidationException(@NonNull Reason reason, JoseException.@Nullable Reason joseReason) {
		super(requireNonNull(reason).message);
		this.reason = reason;
		this.joseReason = joseReason;
	}

	static @NonNull OidcValidationException fromReason(@NonNull Reason reason) {
		return new OidcValidationException(reason, null);
	}

	static @NonNull OidcValidationException fromJoseReason(JoseException.@NonNull Reason reason) {
		requireNonNull(reason);
		Reason oidcReason = switch (reason) {
			case ISSUER_MISMATCH, KEY_ISSUER_MISMATCH -> Reason.ISSUER_MISMATCH;
			case AUDIENCE_MISMATCH -> Reason.AUDIENCE_MISMATCH;
			case EXPIRED -> Reason.EXPIRED;
			case NOT_YET_VALID -> Reason.NOT_YET_VALID;
			case ISSUED_IN_FUTURE -> Reason.ISSUED_IN_FUTURE;
			case INVALID_TYPE -> Reason.INVALID_TYPE;
			case MISSING_CLAIM -> Reason.MISSING_CLAIM;
			case ALGORITHM_NOT_ALLOWED -> Reason.ALGORITHM_NOT_ALLOWED;
			case TOKEN_TOO_LARGE, TOKEN_SYNTAX, HEADER, CLAIMS, KEY_SET -> Reason.ID_TOKEN_MALFORMED;
			case ENCRYPTED_TOKEN, JSON_SERIALIZATION, CRITICAL_HEADER, UNENCODED_PAYLOAD, COMPRESSED_PAYLOAD,
					NESTED_TOKEN, CONFIRMATION_NOT_VERIFIED -> Reason.ID_TOKEN_UNSUPPORTED;
			default -> Reason.ID_TOKEN_SIGNATURE_INVALID;
		};
		return new OidcValidationException(oidcReason, reason);
	}

	static @NonNull OidcValidationException fromUserInfoJoseReason(JoseException.@NonNull Reason reason) {
		OidcValidationException mapped = fromJoseReason(reason);
		Reason profile = switch (mapped.getReason()) {
			case ID_TOKEN_MALFORMED -> Reason.USERINFO_MALFORMED;
			case ID_TOKEN_UNSUPPORTED -> Reason.USERINFO_UNSUPPORTED;
			case ID_TOKEN_SIGNATURE_INVALID -> Reason.USERINFO_SIGNATURE_INVALID;
			default -> mapped.getReason();
		};
		return new OidcValidationException(profile, reason);
	}

	/**
	 * Returns the fixed OIDC failure reason.
	 *
	 * @return the reason
	 * @since 1.0.0
	 */
	public @NonNull Reason getReason() {
		return this.reason;
	}

	/**
	 * Returns the JOSE reason when the underlying signature, header or JWT checks failed.
	 *
	 * @return the lower-layer reason, if applicable
	 * @since 1.0.0
	 */
	public @NonNull Optional<JoseException.@NonNull Reason> getJoseReason() {
		return Optional.ofNullable(this.joseReason);
	}

	/**
	 * Fixed OIDC validation reasons. A later release may add constants; switches should have a default branch.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public enum Reason {
		/** The ID token is absent from a successful code-flow token response. */
		ID_TOKEN_MISSING("The token response has no ID token."),
		/** The compact token, header or claims are malformed. */
		ID_TOKEN_MALFORMED("The ID token is malformed."),
		/** The signature did not verify with a trusted key. */
		ID_TOKEN_SIGNATURE_INVALID("The ID token signature is invalid."),
		/** The ID token uses an unsupported JOSE feature. */
		ID_TOKEN_UNSUPPORTED("The ID token uses an unsupported feature."),
		/** The ID-token or signed-UserInfo algorithm is outside its effective allowlist. */
		ALGORITHM_NOT_ALLOWED("The OIDC token algorithm is not allowed."),
		/** The issuer or key-issuer binding does not match. */
		ISSUER_MISMATCH("The OIDC issuer does not match."),
		/** The verified Entra tenant is denied by the application. */
		TENANT_NOT_ALLOWED("The OIDC tenant is not allowed."),
		/** The audience does not include the configured client. */
		AUDIENCE_MISMATCH("The OIDC audience does not match."),
		/** Another audience is not explicitly trusted. */
		UNTRUSTED_AUDIENCE("The OIDC response includes an untrusted audience."),
		/** The authorized party is not the client or an explicitly trusted party. */
		AUTHORIZED_PARTY_MISMATCH("The ID token authorized party does not match."),
		/** A required JWT claim is missing. */
		MISSING_CLAIM("A required OIDC claim is missing."),
		/** The expiry time, allowing for skew, has been reached. */
		EXPIRED("The OIDC token has expired."),
		/** The token's not-before time has not been reached. */
		NOT_YET_VALID("The OIDC token is not yet valid."),
		/** The issued-at time is in the future beyond skew. */
		ISSUED_IN_FUTURE("The OIDC token was issued in the future."),
		/** The issued-at age exceeds the configured maximum plus skew. */
		TOO_OLD("The ID token is too old."),
		/** The subject is absent, empty, non-ASCII or longer than 255 characters. */
		INVALID_SUBJECT("The ID token subject is invalid."),
		/** The header marks a different JWT profile. */
		INVALID_TYPE("The OIDC token type is not allowed."),
		/** The required nonce is absent. */
		NONCE_MISSING("The ID token nonce is missing."),
		/** The nonce differs from the authenticated pending request. */
		NONCE_MISMATCH("The ID token nonce does not match."),
		/** Authentication time is absent after requesting maximum authentication age. */
		AUTH_TIME_MISSING("The ID token authentication time is missing."),
		/** The authentication time is too old or in the future beyond skew. */
		AUTHENTICATION_TOO_OLD("The ID token authentication time is not acceptable."),
		/** The authentication context does not meet the configured requirement. */
		INSUFFICIENT_ACR("The ID token authentication context is insufficient."),
		/** The present access-token hash does not match the returned access token. */
		ACCESS_TOKEN_HASH_MISMATCH("The ID token access-token hash does not match."),
		/** The present code hash does not match the exchanged authorization code. */
		CODE_HASH_MISMATCH("The ID token code hash does not match."),
		/** The token response does not use the Bearer token type. */
		TOKEN_TYPE_UNSUPPORTED("The token response type is not supported."),
		/** UserInfo is not a strict JSON object or has malformed claims. */
		USERINFO_MALFORMED("The UserInfo response is malformed."),
		/** Signed UserInfo did not verify with a trusted key. */
		USERINFO_SIGNATURE_INVALID("The UserInfo signature is invalid."),
		/** Signed UserInfo uses an unsupported JOSE feature. */
		USERINFO_UNSUPPORTED("The UserInfo response uses an unsupported feature."),
		/** The response format differs from the client's registered signed/JSON policy. */
		USERINFO_FORMAT_MISMATCH("The UserInfo response format does not match the configured policy."),
		/** No UserInfo endpoint is configured or advertised. */
		USERINFO_ENDPOINT_UNAVAILABLE("The provider has no UserInfo endpoint."),
		/** The supplied authentication was validated for a different issuer or client. */
		USERINFO_AUTHENTICATION_MISMATCH("The authentication does not belong to this OIDC client."),
		/** An endpoint access token cannot safely be sent as a Bearer header. */
		USERINFO_ACCESS_TOKEN_INVALID("The access token cannot be sent to UserInfo."),
		/** The supplied access token's known lifetime has ended. */
		USERINFO_ACCESS_TOKEN_EXPIRED("The UserInfo access token has expired."),
		/** UserInfo names a different subject from the validated ID token. */
		USERINFO_SUBJECT_MISMATCH("The UserInfo subject does not match."),
		/** The per-request HMAC client secret is missing, malformed or too short. */
		HMAC_SECRET_INVALID("The OIDC client secret cannot verify an ID token."),
		/** A MAC ID token has more than one audience entry. */
		HMAC_MULTIPLE_AUDIENCES("An HMAC ID token must have exactly one audience."),
		/** A serialized continuity reference has invalid structure. */
		SESSION_REFERENCE_INVALID("The OIDC session reference is invalid."),
		/** A refreshed ID token differs from the original session's continuity claims. */
		REFRESHED_ID_TOKEN_MISMATCH("The refreshed ID token does not match the original session.");

		private final @NonNull String message;

		Reason(@NonNull String message) {
			this.message = message;
		}
	}
}
