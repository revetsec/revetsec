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

import com.revetsec.jose.JoseObserver;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.time.Duration;

/**
 * Receives synchronous, caller-thread OAuth events. Endpoint URIs contain only scheme, host, port and path;
 * callbacks and request bodies are never passed. Implementations must be thread-safe and fast. A hook failure is
 * contained by the caller except for {@link VirtualMachineError}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public interface OAuthObserver extends JoseObserver {
	/**
	 * Returns an observer whose hooks do nothing.
	 *
	 * @return the disabled observer
	 * @since 1.0.0
	 */
	@NonNull
	static OAuthObserver disabledInstance() { return DisabledOAuthObserver.INSTANCE; }

	/**
	 * Called after a browser authorization URL is prepared.
	 *
	 * @param endpoint its reduced endpoint URI
	 * @since 1.0.0
	 */
	default void didBeginAuthorization(@NonNull URI endpoint) { }

	/**
	 * Called before an OAuth endpoint request.
	 *
	 * @param endpoint endpoint kind
	 * @param uri its reduced URI
	 * @since 1.0.0
	 */
	default void willRequestEndpoint(@NonNull OAuthEndpoint endpoint, @NonNull URI uri) { }

	/**
	 * Called after a completed endpoint request.
	 *
	 * @param endpoint endpoint kind
	 * @param uri its reduced URI
	 * @param status HTTP status
	 * @param elapsed elapsed duration
	 * @since 1.0.0
	 */
	default void didRequestEndpoint(@NonNull OAuthEndpoint endpoint, @NonNull URI uri,
			@NonNull Integer status, @NonNull Duration elapsed) { }

	/**
	 * Called when an endpoint request fails. The exception is the same instance the caller receives.
	 *
	 * @param endpoint endpoint kind
	 * @param uri its reduced URI
	 * @param exception fixed-message exception
	 * @param elapsed elapsed duration
	 * @since 1.0.0
	 */
	default void didFailEndpoint(@NonNull OAuthEndpoint endpoint, @NonNull URI uri,
			@NonNull OAuthException exception, @NonNull Duration elapsed) { }

	/**
	 * Called when a callback fails a local validation check.
	 *
	 * @param exception fixed-message exception
	 * @since 1.0.0
	 */
	default void didRejectCallback(@NonNull OAuthValidationException exception) { }

	/**
	 * Called when the explicit unencoded Basic interoperability mode is configured and on every request using it.
	 * No credential value is passed.
	 *
	 * @since 1.0.0
	 */
	default void didUseUnencodedBasic() { }
}
