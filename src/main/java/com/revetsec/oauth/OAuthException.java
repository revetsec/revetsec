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

import com.revetsec.ErrorCategory;
import com.revetsec.RevetsecException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.io.IOException;

import static java.util.Objects.requireNonNull;

/**
 * An OAuth request, response, validation or transport failure. The reason and message are fixed; neither contains
 * authorization codes, pending state, client secrets or tokens. Applications catch this type or one of its leaves.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@NotThreadSafe
public abstract sealed class OAuthException extends RevetsecException permits AuthorizationErrorException,
		OAuthErrorResponseException, OAuthValidationException, OAuthResponseException, OAuthTransportException,
		PendingAuthorizationStoreException {
	private static final long serialVersionUID = 1L;
	/** Stable public failure reason. */
	private final @NonNull Reason reason;

	OAuthException(@NonNull Reason reason, boolean transientFailure, @Nullable IOException cause) {
		super(requireNonNull(reason).category, transientFailure, reason.message, cause);
		this.reason = reason;
	}

	/**
	 * Returns the fixed reason for this failure.
	 *
	 * @return the reason
	 * @since 1.0.0
	 */
	public final @NonNull Reason getReason() {
		return this.reason;
	}

	/**
	 * Reasons for OAuth failures. New reasons may be added in a later release.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public enum Reason {
		/** The callback reported an authorization error. */
		AUTHORIZATION_ERROR(ErrorCategory.REMOTE_ERROR, "The authorization server rejected the authorization request."),
		/** The token or revocation endpoint reported an OAuth error. */
		ENDPOINT_ERROR(ErrorCategory.REMOTE_ERROR, "The authorization server rejected the endpoint request."),
		/** The callback state is absent or differs from the pending state. */
		STATE_MISMATCH(ErrorCategory.VALIDATION_FAILURE, "The authorization response state does not match."),
		/** The browser binding does not match the saved pending authorization. */
		BROWSER_BINDING_MISMATCH(ErrorCategory.VALIDATION_FAILURE, "The pending authorization belongs to another browser."),
		/** The sealed pending record is invalid or cannot be opened. */
		PENDING_AUTHORIZATION_INVALID(ErrorCategory.VALIDATION_FAILURE, "The pending authorization is invalid."),
		/** The authenticated pending record has expired. */
		PENDING_AUTHORIZATION_EXPIRED(ErrorCategory.VALIDATION_FAILURE, "The pending authorization has expired."),
		/** No pending record was found in the store. */
		PENDING_AUTHORIZATION_NOT_FOUND(ErrorCategory.VALIDATION_FAILURE, "The pending authorization was not found."),
		/** The pending record belongs to another client. */
		CLIENT_MISMATCH(ErrorCategory.VALIDATION_FAILURE, "The pending authorization belongs to another client."),
		/** The pending record belongs to another issuer. */
		ISSUER_MISMATCH(ErrorCategory.VALIDATION_FAILURE, "The authorization issuer does not match."),
		/** A required callback issuer is missing. */
		ISSUER_MISSING(ErrorCategory.VALIDATION_FAILURE, "The authorization response issuer is missing."),
		/** The trusted callback route differs from the registered redirect URI. */
		CALLBACK_URI_MISMATCH(ErrorCategory.VALIDATION_FAILURE, "The callback URI does not match the authorization request."),
		/** The callback delivery mode differs from the pending request. */
		RESPONSE_MODE_MISMATCH(ErrorCategory.VALIDATION_FAILURE, "The authorization response mode does not match."),
		/** The metadata issuer or an endpoint is unsafe or mismatched. */
		METADATA_INVALID(ErrorCategory.VALIDATION_FAILURE, "The authorization server metadata is invalid."),
		/** The endpoint pair changed while an authorization was pending. */
		METADATA_ENDPOINT_DRIFT(ErrorCategory.VALIDATION_FAILURE, "The authorization server endpoints changed."),
		/** An authorization server does not advertise required PKCE S256 support. */
		PKCE_UNSUPPORTED(ErrorCategory.VALIDATION_FAILURE, "The authorization server does not advertise PKCE S256."),
		/** A token cannot be returned because its lifetime has already ended. */
		TOKEN_EXPIRED(ErrorCategory.VALIDATION_FAILURE, "The token has expired."),
		/** The in-memory store has reached a configured live capacity. */
		CAPACITY_EXCEEDED(ErrorCategory.CONFIGURATION, "The pending-authorization store is full."),
		/** A callback has duplicate, conflicting or malformed parameters. */
		CALLBACK_MALFORMED(ErrorCategory.MALFORMED_INPUT, "The authorization response is malformed."),
		/** A metadata or token JSON document is malformed. */
		DOCUMENT_MALFORMED(ErrorCategory.MALFORMED_INPUT, "The authorization server document is malformed."),
		/** An endpoint returned an unexpected status or media type. */
		ENDPOINT_RESPONSE_MALFORMED(ErrorCategory.MALFORMED_INPUT, "The authorization server response is malformed."),
		/** The endpoint redirected a request carrying credentials; the redirect was not followed. */
		REDIRECT_NOT_FOLLOWED(ErrorCategory.REMOTE_ERROR, "The authorization server redirected a credentialed request."),
		/** The endpoint response exceeded its configured body limit. */
		TOO_LARGE(ErrorCategory.MALFORMED_INPUT, "The authorization server response is too large."),
		/** A successful endpoint response lacked one permitted JSON media type. */
		UNEXPECTED_CONTENT_TYPE(ErrorCategory.MALFORMED_INPUT,
				"The authorization server response has an unexpected content type."),
		/** A network request failed or timed out. */
		NETWORK_FAILURE(ErrorCategory.TRANSPORT, "The authorization server request failed."),
		/** A thread was interrupted during a network request. */
		INTERRUPTED(ErrorCategory.TRANSPORT, "The authorization server request was interrupted."),
		/** A cache attempt ceiling temporarily held back the request. */
		ATTEMPT_LIMIT(ErrorCategory.TRANSPORT, "The authorization server request is temporarily held back."),
		/** The default HTTP client could not be constructed. */
		HTTP_CLIENT_UNAVAILABLE(ErrorCategory.CONFIGURATION, "The HTTP client is unavailable.");

		private final @NonNull ErrorCategory category;
		private final @NonNull String message;

		Reason(@NonNull ErrorCategory category, @NonNull String message) {
			this.category = category;
			this.message = message;
		}

		@NonNull ErrorCategory category() {
			return this.category;
		}
	}
}
