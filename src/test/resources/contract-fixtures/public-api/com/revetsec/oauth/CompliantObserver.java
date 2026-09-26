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

import com.revetsec.RevetsecException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

/**
 * Control: an observer interface that follows every rule. Its hooks are default void methods whose parameters use
 * every allowlisted type, it has a static disabledInstance(), and a private helper, which is not API, is ignored.
 *
 * @since 1.0.0
 */
@ThreadSafe
public interface CompliantObserver {
	/**
	 * The observer whose hooks do nothing.
	 *
	 * @return the disabled observer
	 * @since 1.0.0
	 */
	static @NonNull CompliantObserver disabledInstance() {
		return DisabledCompliantObserver.INSTANCE;
	}

	/**
	 * Called after a fetch.
	 *
	 * @param uri      the URI, cut to scheme, host, port and path
	 * @param duration how long the fetch took
	 * @param fetchedAt when it finished
	 * @param keyId    a key ID
	 * @param keyCount the number of keys
	 * @param bodySize the body size
	 * @param cached   whether the result was cached
	 * @since 1.0.0
	 */
	default void didFetch(@Nullable URI uri, @Nullable Duration duration, @Nullable Instant fetchedAt,
			@Nullable String keyId, @Nullable Integer keyCount, @Nullable Long bodySize, @Nullable Boolean cached) {
		requireNothing();
	}

	/**
	 * Called with the other boxed numbers.
	 *
	 * @param first  a byte
	 * @param second a short
	 * @param third  a float
	 * @param fourth a double
	 * @since 1.0.0
	 */
	default void didMeasure(@Nullable Byte first, @Nullable Short second, @Nullable Float third,
			@Nullable Double fourth) {
	}

	/**
	 * Called after a failure: enums, from Revetsec or the JDK, and Revetsec exceptions.
	 *
	 * @param reason         a Revetsec enum
	 * @param unit           a JDK enum
	 * @param exception      the exception root
	 * @param oauthException a protocol exception
	 * @since 1.0.0
	 */
	default void didFailToFetch(TokenFixtureException.@Nullable Reason reason, @Nullable TimeUnit unit,
			@Nullable RevetsecException exception, @Nullable OAuthFixtureException oauthException) {
	}

	private static void requireNothing() {
	}
}

/**
 * The package-private disabled observer.
 */
final class DisabledCompliantObserver implements CompliantObserver {
	static final DisabledCompliantObserver INSTANCE = new DisabledCompliantObserver();

	private DisabledCompliantObserver() {
	}
}
