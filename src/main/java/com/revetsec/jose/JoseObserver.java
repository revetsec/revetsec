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

package com.revetsec.jose;

import com.revetsec.RevetsecException;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.time.Duration;

/**
 * Receives events from {@link JwtValidator} and {@link RemoteJsonWebKeySource}, for metrics, logs and alerts.
 * <p>
 * Every hook is a {@code default} method that does nothing, so an implementation overrides only the hooks it needs.
 * Hooks run synchronously on the calling thread, never while Revetsec holds a lock. Anything a hook throws is
 * contained and does not affect the operation, except a {@link VirtualMachineError}. Keep hooks fast: a slow hook
 * slows the call that fired it.
 * <p>
 * Hooks never receive a string taken from a token or a key set: no key ID, claim or header value. A key is named by
 * its position in the set's {@code keys} array. URIs are cut to their scheme, host, port and path. Elapsed durations
 * are measured with {@link System#nanoTime()}; {@code untilNextAttempt} follows the key source's
 * {@link java.time.Clock}, and {@code timeToLive} comes from the response's cache headers within the source's limits.
 * A failure hook receives the same exception instance the caller gets.
 * <p>
 * An observer may be called from many threads at once, so implementations must be thread-safe.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public interface JoseObserver {
	/**
	 * Returns an observer whose hooks do nothing: the default for every component that takes an observer.
	 *
	 * @return the shared observer that does nothing
	 * @since 1.0.0
	 */
	@NonNull
	static JoseObserver disabledInstance() {
		return DisabledJoseObserver.INSTANCE;
	}

	/**
	 * Called just before a {@link RemoteJsonWebKeySource} sends a request for its key set, by the one caller that
	 * fetches it.
	 *
	 * @param jwksUri the key set's URI, cut to its scheme, host, port and path
	 * @since 1.0.0
	 */
	default void willFetchJsonWebKeySet(@NonNull URI jwksUri) {
		// Does nothing unless overridden.
	}

	/**
	 * Called when a key set fetch succeeded, by the one caller that fetched it. A key set in which every key was
	 * skipped still succeeds.
	 *
	 * @param jwksUri         the key set's URI, cut to its scheme, host, port and path
	 * @param usableKeyCount  how many keys are usable
	 * @param skippedKeyCount how many keys were skipped (each also reported to
	 *                        {@link #didSkipJsonWebKey(URI, Integer, JsonWebKeySkipReason)})
	 * @param timeToLive      how long the key set stays fresh, from the response's cache headers within the source's
	 *                        limits
	 * @param elapsed         how long the fetch took
	 * @since 1.0.0
	 */
	default void didFetchJsonWebKeySet(@NonNull URI jwksUri,
																		 @NonNull Integer usableKeyCount,
																		 @NonNull Integer skippedKeyCount,
																		 @NonNull Duration timeToLive,
																		 @NonNull Duration elapsed) {
		// Does nothing unless overridden.
	}

	/**
	 * Called when a key set fetch failed, by the one caller that fetched it.
	 *
	 * @param jwksUri          the key set's URI, cut to its scheme, host, port and path
	 * @param exception        the failure, the same instance that caller receives unless it is served stale keys
	 * @param servingStaleKeys whether the caller is served keys from the expired key set instead
	 * @param elapsed          how long the fetch took
	 * @since 1.0.0
	 */
	default void didFailToFetchJsonWebKeySet(@NonNull URI jwksUri,
																					 @NonNull JsonWebKeySetUnavailableException exception,
																					 @NonNull Boolean servingStaleKeys,
																					 @NonNull Duration elapsed) {
		// Does nothing unless overridden.
	}

	/**
	 * Called on every call that needed a key set fetch but sent no request, because a recent failure, the unknown-key
	 * cooldown or the limit on attempts per cooldown held it back. Many of these in a short time can mean that
	 * someone is sending tokens with made-up key IDs.
	 *
	 * @param jwksUri          the key set's URI, cut to its scheme, host, port and path
	 * @param untilNextAttempt how long until a fetch may be sent again, on the source's clock
	 * @since 1.0.0
	 */
	default void didSuppressJsonWebKeySetFetch(@NonNull URI jwksUri,
																						 @NonNull Duration untilNextAttempt) {
		// Does nothing unless overridden.
	}

	/**
	 * Called for each key a fetched key set holds but Revetsec does not use, on every fetch. Some identity providers
	 * publish an encryption key beside their signing keys, so this hook can fire on every fetch in normal operation.
	 *
	 * @param jwksUri  the key set's URI, cut to its scheme, host, port and path
	 * @param keyIndex the key's zero-based position in the set's {@code keys} array
	 * @param reason   why the key is not used
	 * @since 1.0.0
	 */
	default void didSkipJsonWebKey(@NonNull URI jwksUri,
																 @NonNull Integer keyIndex,
																 @NonNull JsonWebKeySkipReason reason) {
		// Does nothing unless overridden.
	}

	/**
	 * Called when {@link JwtValidator#validate(String)} accepted a token.
	 *
	 * @param algorithm the token's algorithm
	 * @param elapsed   how long validation took, any key set fetch included
	 * @since 1.0.0
	 */
	default void didValidateJwt(@NonNull JwsAlgorithm algorithm,
															@NonNull Duration elapsed) {
		// Does nothing unless overridden.
	}

	/**
	 * Called when {@link JwtValidator#validate(String)} rejected a token or could not get its keys, just before it
	 * throws.
	 *
	 * @param exception the exception about to be thrown: a {@link JoseException} or a
	 *                  {@link JsonWebKeySetUnavailableException}
	 * @param elapsed   how long validation took, any key set fetch included
	 * @since 1.0.0
	 */
	default void didFailToValidateJwt(@NonNull RevetsecException exception,
																		@NonNull Duration elapsed) {
		// Does nothing unless overridden.
	}

	/**
	 * Called when a validator configured to accept any audience is built, and on each of its validations, because
	 * accepting any audience lets a token issued for another application through.
	 *
	 * @param issuer the validator's expected issuer
	 * @since 1.0.0
	 */
	default void didAcceptAnyAudience(@NonNull String issuer) {
		// Does nothing unless overridden.
	}

	/**
	 * Called when a component that acknowledged running below Revetsec's minimum Java runtime version is built, and
	 * on each of its fetches.
	 *
	 * @param runtimeVersion the running Java version, such as {@code 17.0.2}
	 * @since 1.0.0
	 */
	default void didUseUnpatchedRuntime(@NonNull String runtimeVersion) {
		// Does nothing unless overridden.
	}
}
