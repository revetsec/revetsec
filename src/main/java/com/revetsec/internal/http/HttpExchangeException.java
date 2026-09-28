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

package com.revetsec.internal.http;

import com.revetsec.ErrorCategory;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.io.IOException;

import static java.util.Objects.requireNonNull;

/**
 * Checked failure of one HTTP exchange (M1 plan, G6-2 and "HTTP helper").
 * <p>
 * Each {@link Kind} fixes the {@link ErrorCategory} and transience that the translating entry point passes on
 * (G6-3); M2 and later choose the public exception class per path. The one exception is {@link Kind#URI_REJECTED},
 * whose category the carrying class decides (M2 plan, G8-9); its transience stays fixed. The message is the kind's
 * fixed sentence and never contains the URI, a header or any part of the body. Only {@link Kind#IO} keeps a cause, and only the JDK's
 * {@link IOException}. Suppression is disabled. A non-2xx response is not an exception: {@link HttpExchange} returns
 * it as a {@link RawResponse}, and the protocol raises {@code REMOTE_ERROR}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@NotThreadSafe
public final class HttpExchangeException extends Exception {
	private static final long serialVersionUID = 1L;

	/**
	 * Why the exchange failed.
	 */
	@NonNull
	private final Kind kind;

	/**
	 * Why an exchange failed, with the category and transience the M1 plan's Kind table assigns.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 */
	@Immutable
	public enum Kind {
		/**
		 * The exchange ran out of time: the call's total deadline, the per-request timeout, or the JDK's own request
		 * timeout, whichever came first. Transient.
		 */
		TIMEOUT(ErrorCategory.TRANSPORT, true, "The HTTP exchange did not finish before its deadline."),
		/**
		 * The connection, TLS handshake, request or response failed. Transient; the JDK's {@link IOException} is kept
		 * as the cause when there is one.
		 */
		IO(ErrorCategory.TRANSPORT, true, "The HTTP exchange failed with an I/O error."),
		/**
		 * The calling thread was interrupted. Not transient; the thread's interrupt flag is set again.
		 */
		INTERRUPTED(ErrorCategory.TRANSPORT, false, "The thread was interrupted during the HTTP exchange."),
		/**
		 * The response was a redirect (any 3xx), which Revetsec never follows.
		 */
		REDIRECT(ErrorCategory.REMOTE_ERROR, false, "The server answered with a redirect, which is not followed."),
		/**
		 * A 2xx body, by {@code Content-Length} or as it streamed, was larger than the limit.
		 */
		TOO_LARGE(ErrorCategory.MALFORMED_INPUT, false, "The response body is larger than the limit."),
		/**
		 * A 2xx carried a {@code Content-Encoding} other than {@code identity}.
		 */
		CONTENT_ENCODING(ErrorCategory.MALFORMED_INPUT, false,
				"The response has a content encoding other than identity."),
		/**
		 * The response's framing was ambiguous: a repeated or malformed {@code Content-Length}, {@code Content-Length}
		 * with {@code Transfer-Encoding}, or a {@code Transfer-Encoding} other than {@code chunked}.
		 */
		FRAMING(ErrorCategory.MALFORMED_INPUT, false, "The response framing is ambiguous or malformed."),
		/**
		 * A 2xx did not carry exactly one {@code Content-Type} that its {@link ResponseProfile} accepts.
		 */
		MEDIA_TYPE(ErrorCategory.MALFORMED_INPUT, false, "The response does not have exactly one permitted media type."),
		/**
		 * The URI failed {@link UriChecks}: it is malformed, carries user information or a fragment, is not
		 * {@code https} (or loopback {@code http} where allowed), or the {@code OutboundUriPolicy} refused it. No request
		 * was sent. The category here is the one a protocol exception carries for a discovered or app-supplied endpoint
		 * ({@code OUTBOUND_URI_REJECTED}); the class that carries the kind decides it (G8-9), and a JSON Web Key Set
		 * source, whose URI was already checked at {@code build()}, reports this unreachable backstop as
		 * {@link ErrorCategory#CONFIGURATION}.
		 */
		URI_REJECTED(ErrorCategory.VALIDATION_FAILURE, false, "The request URI is not permitted."),
		/**
		 * No client was injected, and the process-wide default client could not be created in this runtime.
		 */
		DEFAULT_CLIENT_UNAVAILABLE(ErrorCategory.CONFIGURATION, false,
				"The default HttpClient could not be created in this runtime.");

		@NonNull
		private final ErrorCategory category;
		private final boolean transientFailure;
		@NonNull
		private final String message;

		Kind(@NonNull ErrorCategory category,
				 boolean transientFailure,
				 @NonNull String message) {
			this.category = category;
			this.transientFailure = transientFailure;
			this.message = message;
		}

		/**
		 * The category the public exception carries.
		 *
		 * @return the category
		 */
		@NonNull
		public ErrorCategory getCategory() {
			return this.category;
		}

		/**
		 * Whether the public exception is transient.
		 *
		 * @return {@code true} for {@link #TIMEOUT} and {@link #IO} only
		 */
		public boolean isTransient() {
			return this.transientFailure;
		}

		/**
		 * The fixed message of this kind.
		 *
		 * @return the message, which never contains input
		 */
		@NonNull
		public String getMessage() {
			return this.message;
		}
	}

	HttpExchangeException(@NonNull Kind kind) {
		this(kind, null);
	}

	HttpExchangeException(@NonNull Kind kind,
												@Nullable IOException cause) {
		super(checkedMessage(kind, cause), cause, false, true);
		this.kind = kind;
	}

	/**
	 * Why the exchange failed.
	 *
	 * @return the kind of failure
	 */
	@NonNull
	public Kind getKind() {
		return this.kind;
	}

	private static String checkedMessage(@NonNull Kind kind,
																			 @Nullable IOException cause) {
		requireNonNull(kind);

		if (cause != null && kind != Kind.IO)
			throw new IllegalArgumentException("Only an IO failure keeps a cause.");

		return kind.getMessage();
	}
}
