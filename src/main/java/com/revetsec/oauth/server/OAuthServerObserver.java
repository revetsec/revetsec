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
import javax.annotation.concurrent.ThreadSafe;
import java.time.Duration;

/**
 * Safe synchronous caller-thread issuer events. Hooks run outside held locks and transactions and must be fast
 * and thread-safe. Failures are contained except VirtualMachineError; interruption is restored. No event includes
 * a client, subject, grant, credential, key identifier, URL, request or claims. Exactly one terminal hook follows
 * each will hook during ordinary completion; status is absent only for validation or trusted management work.
 * @since 1.0.0
 */
@ThreadSafe
public interface OAuthServerObserver {
	/** Returns the shared observer whose hooks do nothing.
	 * @return disabled observer
	 * @since 1.0.0
	 */
	@CheckReturnValue static @NonNull OAuthServerObserver disabledInstance() { return DisabledOAuthServerObserver.INSTANCE; }
	/** Called before handling an operation.
	 * @param endpoint fixed operation kind
	 * @since 1.0.0
	 */
	default void willHandleEndpoint(@NonNull Endpoint endpoint) {}
	/** Called after ordinary successful completion.
	 * @param endpoint fixed operation kind
	 * @param statusCode HTTP status or null for non-HTTP work
	 * @param elapsed monotonic elapsed duration
	 * @since 1.0.0
	 */
	default void didHandleEndpoint(@NonNull Endpoint endpoint, @Nullable Integer statusCode, @NonNull Duration elapsed) {}
	/** Called after an expected rejection, including explicit application denial.
	 * @param endpoint fixed operation kind
	 * @param reason fixed rejection reason
	 * @param statusCode HTTP status or null for non-HTTP work
	 * @param elapsed monotonic elapsed duration
	 * @since 1.0.0
	 */
	default void didRejectEndpoint(@NonNull Endpoint endpoint, OAuthServerException.@NonNull Reason reason,
		@Nullable Integer statusCode, @NonNull Duration elapsed) {}
	/** Called after infrastructure failure; the same fixed exception reaches the caller.
	 * @param endpoint fixed operation kind
	 * @param failure fixed exception without external causes
	 * @param elapsed monotonic elapsed duration
	 * @since 1.0.0
	 */
	default void didFailToHandleEndpoint(@NonNull Endpoint endpoint, @NonNull OAuthServerException failure, @NonNull Duration elapsed) {}
	/** Fixed operation kinds, without request or application data.
	 * @since 1.0.0
	 */
	@Immutable enum Endpoint {
		/** Browser interaction work. */ AUTHORIZATION,
		/** Code or refresh exchange. */ TOKEN,
		/** Explicit fresh deployment initialization. */ ISSUER_INITIALIZATION,
		/** Explicit first subject registration. */ SUBJECT_REGISTRATION,
		/** Credential revocation. */ REVOCATION,
		/** Registered-resource introspection. */ INTROSPECTION,
		/** Public issuer metadata. */ METADATA,
		/** Public verification keys. */ JSON_WEB_KEY_SET,
		/** Online issuer access-token validation. */ ACCESS_TOKEN_VALIDATION,
		/** Trusted grant invalidation. */ GRANT_REVOCATION,
		/** Trusted subject invalidation. */ SUBJECT_REVOCATION,
		/** Trusted issuer-wide invalidation. */ ISSUER_REVOCATION,
		/** Trusted store maintenance. */ STORE_RESEAL
	}
}
final class DisabledOAuthServerObserver implements OAuthServerObserver {
	static final @NonNull OAuthServerObserver INSTANCE=new DisabledOAuthServerObserver();
	private DisabledOAuthServerObserver() {}
}
