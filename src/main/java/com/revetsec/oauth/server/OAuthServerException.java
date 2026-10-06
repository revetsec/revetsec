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
import com.revetsec.RevetsecException;
import com.revetsec.ErrorCategory;
import javax.annotation.concurrent.NotThreadSafe;

/**
 * The sealed issuer exception family. Fixed reasons and messages contain no request or application data.
 * External causes and suppressed exceptions are never retained. Transience is not permission to retransmit
 * a code, refresh or revocation request. An unknown commit outcome is always nontransient and needs reconciliation.
 * @since 1.0.0
 */
@NotThreadSafe
public abstract sealed class OAuthServerException extends RevetsecException permits OAuthServerValidationException,
	OAuthServerStoreException, OAuthServerTransportException, OAuthServerConfigurationException, OAuthServerSigningException {
	private static final long serialVersionUID=1L;
	/** The fixed classification.
	 * @serial
	 */
	private final @NonNull Reason reason;
	OAuthServerException(@NonNull Reason reason, boolean transientFailure) {
		super(requireNonNull(reason).category,transientFailure,reason.message,null); this.reason=reason;
	}
	/** Returns the fixed issuer reason; it is not an external OAuth error string.
	 * @return fixed issuer reason
	 * @since 1.0.0
	 */
	@CheckReturnValue public final @NonNull Reason getReason() { return this.reason; }
	/** Returns a fixed description without causes, credentials or application data.
	 * @return fixed description
	 * @since 1.0.0
	 */
	@Override public final @NonNull String toString() { return "OAuthServerException{"+this.reason+"}"; }
	enum Kind { VALIDATION, STORE, TRANSPORT, CONFIGURATION, SIGNING }
	/** Fixed internal classifications; different reasons may deliberately share the same safe wire error.
	 * @since 1.0.0
	 */
	@Immutable public enum Reason {
		/** The OAuth server request is malformed. */
		MALFORMED_REQUEST(Kind.VALIDATION,ErrorCategory.MALFORMED_INPUT,"The OAuth server request is malformed."),
		/** The OAuth server request method is not supported. */
		METHOD_NOT_ALLOWED(Kind.VALIDATION,ErrorCategory.UNSUPPORTED,"The OAuth server request method is not supported."),
		/** The OAuth server grant type is not supported. */
		UNSUPPORTED_GRANT_TYPE(Kind.VALIDATION,ErrorCategory.UNSUPPORTED,"The OAuth server grant type is not supported."),
		/** The OAuth server response type is not supported. */
		UNSUPPORTED_RESPONSE_TYPE(Kind.VALIDATION,ErrorCategory.UNSUPPORTED,"The OAuth server response type is not supported."),
		/** The OAuth server client is not recognized. */
		UNKNOWN_CLIENT(Kind.VALIDATION,ErrorCategory.VALIDATION_FAILURE,"The OAuth server client is not recognized."),
		/** The OAuth server client authentication failed. */
		INVALID_CLIENT(Kind.VALIDATION,ErrorCategory.VALIDATION_FAILURE,"The OAuth server client authentication failed."),
		/** The OAuth server client is not authorized. */
		UNAUTHORIZED_CLIENT(Kind.VALIDATION,ErrorCategory.VALIDATION_FAILURE,"The OAuth server client is not authorized."),
		/** The OAuth server redirect is not trusted. */
		REDIRECT_NOT_TRUSTED(Kind.VALIDATION,ErrorCategory.VALIDATION_FAILURE,"The OAuth server redirect is not trusted."),
		/** The OAuth server request requires PKCE. */
		PKCE_REQUIRED(Kind.VALIDATION,ErrorCategory.VALIDATION_FAILURE,"The OAuth server request requires PKCE."),
		/** The OAuth server PKCE check failed. */
		PKCE_MISMATCH(Kind.VALIDATION,ErrorCategory.VALIDATION_FAILURE,"The OAuth server PKCE check failed."),
		/** The OAuth server resource is not permitted. */
		INVALID_RESOURCE(Kind.VALIDATION,ErrorCategory.VALIDATION_FAILURE,"The OAuth server resource is not permitted."),
		/** The OAuth server scope is not permitted. */
		INVALID_SCOPE(Kind.VALIDATION,ErrorCategory.VALIDATION_FAILURE,"The OAuth server scope is not permitted."),
		/** The OAuth server interaction has expired. */
		INTERACTION_EXPIRED(Kind.VALIDATION,ErrorCategory.VALIDATION_FAILURE,"The OAuth server interaction has expired."),
		/** The OAuth server interaction is no longer pending. */
		INTERACTION_REUSED(Kind.VALIDATION,ErrorCategory.VALIDATION_FAILURE,"The OAuth server interaction is no longer pending."),
		/** The OAuth server grant is invalid. */
		INVALID_GRANT(Kind.VALIDATION,ErrorCategory.VALIDATION_FAILURE,"The OAuth server grant is invalid."),
		/** The OAuth server refresh credential was reused. */
		REFRESH_REUSE(Kind.VALIDATION,ErrorCategory.VALIDATION_FAILURE,"The OAuth server refresh credential was reused."),
		/** The OAuth server token is not active. */
		TOKEN_REVOKED(Kind.VALIDATION,ErrorCategory.VALIDATION_FAILURE,"The OAuth server token is not active."),
		/** The OAuth server authorization was denied. */
		ACCESS_DENIED(Kind.VALIDATION,ErrorCategory.VALIDATION_FAILURE,"The OAuth server authorization was denied."),
		/** The OAuth server store is unavailable. */
		STORE_UNAVAILABLE(Kind.STORE,ErrorCategory.TRANSPORT,"The OAuth server store is unavailable."),
		/** The OAuth server store state is invalid. */
		STORE_CORRUPT(Kind.STORE,ErrorCategory.CONFIGURATION,"The OAuth server store state is invalid."),
		/** The OAuth server commit outcome is unknown. */
		COMMIT_OUTCOME_UNKNOWN(Kind.STORE,ErrorCategory.TRANSPORT,"The OAuth server commit outcome is unknown."),
		/** The OAuth server client metadata is unavailable. */
		CLIENT_METADATA_UNAVAILABLE(Kind.TRANSPORT,ErrorCategory.TRANSPORT,"The OAuth server client metadata is unavailable."),
		/** The OAuth server configuration is invalid. */
		CONFIGURATION_INVALID(Kind.CONFIGURATION,ErrorCategory.CONFIGURATION,"The OAuth server configuration is invalid."),
		/** The OAuth server response could not be signed. */
		SIGNING_FAILED(Kind.SIGNING,ErrorCategory.CONFIGURATION,"The OAuth server response could not be signed.");
		private final @NonNull Kind kind;
		private final @NonNull ErrorCategory category;
		private final @NonNull String message;
		Reason(@NonNull Kind kind, @NonNull ErrorCategory category, @NonNull String message) { this.kind=kind; this.category=category; this.message=message; }
		void requireKind(@NonNull Kind expected) { if(this.kind!=requireNonNull(expected)) throw OAuthStoreFormat.invalid(); }
	}
}
