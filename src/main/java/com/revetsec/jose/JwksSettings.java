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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.time.Clock;
import java.time.Duration;

import static java.util.Objects.requireNonNull;

/**
 * The settings of one {@link RemoteJsonWebKeySource} and its {@link JwksCache}, already checked against their
 * {@code Limits} rows and the cross-field rules by {@link RemoteJsonWebKeySource.Builder#build()}, which is the only
 * place that makes them for applications. A later milestone's component that embeds a key source (M4, M5) builds them
 * the same way, from settings it has checked itself, the cross-field rules included. The constructor keeps only the
 * cache's own preconditions: it does not require the unknown-key cooldown to be within the minimum time to live, which
 * the cache does not need to stay correct, but without which its two-attempt ceiling can hold back refreshes after
 * expiry.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
final class JwksSettings {
	@NonNull
	private final Clock clock;
	@NonNull
	private final Duration requestTimeout;
	@NonNull
	private final Duration minimumTimeToLive;
	@NonNull
	private final Duration defaultTimeToLive;
	@NonNull
	private final Duration maximumTimeToLive;
	@NonNull
	private final Duration unknownKeyRefreshCooldown;
	@NonNull
	private final Duration maximumStaleness;
	private final int maximumResponseBytes;
	private final int maximumKeys;
	@NonNull
	private final JoseObserver observer;
	@Nullable
	private final String unpatchedRuntimeVersion;

	/**
	 * Holds settings that were already checked.
	 *
	 * @param clock                     the clock for the time to live, cooldown, backoff and staleness
	 * @param requestTimeout            the longest one fetch may take, and a standalone call's deadline
	 * @param minimumTimeToLive         the shortest time a key set stays fresh
	 * @param defaultTimeToLive         the time a key set stays fresh when its response has neither {@code max-age}
	 *                                  nor {@code Expires}
	 * @param maximumTimeToLive         the longest time a key set stays fresh
	 * @param unknownKeyRefreshCooldown the shortest time between two unknown-key refreshes, the first backoff step and
	 *                                  the window of the two-attempt ceiling
	 * @param maximumStaleness          how long after it expires a key set may still answer for the keys it holds
	 * @param maximumResponseBytes      the largest key set body accepted
	 * @param maximumKeys               the most elements a key set's {@code keys} array may hold
	 * @param observer                  the observer of fetch events
	 * @param unpatchedRuntimeVersion   the running Java version when it is below Revetsec's floor for network I/O and
	 *                                  the application acknowledged that, reported on every fetch; otherwise
	 *                                  {@code null}
	 * @throws NullPointerException     if an argument other than {@code unpatchedRuntimeVersion} is {@code null}
	 * @throws IllegalArgumentException if a duration is negative, the request timeout or cooldown is not positive, a
	 *                                  limit is not positive, or the time-to-live settings are not ordered
	 */
	JwksSettings(@NonNull Clock clock,
							 @NonNull Duration requestTimeout,
							 @NonNull Duration minimumTimeToLive,
							 @NonNull Duration defaultTimeToLive,
							 @NonNull Duration maximumTimeToLive,
							 @NonNull Duration unknownKeyRefreshCooldown,
							 @NonNull Duration maximumStaleness,
							 int maximumResponseBytes,
							 int maximumKeys,
							 @NonNull JoseObserver observer,
							 @Nullable String unpatchedRuntimeVersion) {
		this.clock = requireNonNull(clock);
		this.requestTimeout = requirePositive(requestTimeout);
		this.minimumTimeToLive = requireNonNegative(minimumTimeToLive);
		this.defaultTimeToLive = requireNonNegative(defaultTimeToLive);
		this.maximumTimeToLive = requireNonNegative(maximumTimeToLive);
		this.unknownKeyRefreshCooldown = requirePositive(unknownKeyRefreshCooldown);
		this.maximumStaleness = requireNonNegative(maximumStaleness);
		this.observer = requireNonNull(observer);
		this.unpatchedRuntimeVersion = unpatchedRuntimeVersion;

		if (minimumTimeToLive.compareTo(defaultTimeToLive) > 0 || defaultTimeToLive.compareTo(maximumTimeToLive) > 0)
			throw new IllegalArgumentException("The time-to-live settings must be ordered minimum, default, maximum.");

		if (maximumResponseBytes <= 0 || maximumKeys <= 0)
			throw new IllegalArgumentException("The response and key limits must be positive.");

		this.maximumResponseBytes = maximumResponseBytes;
		this.maximumKeys = maximumKeys;
	}

	@NonNull
	Clock clock() {
		return this.clock;
	}

	@NonNull
	Duration requestTimeout() {
		return this.requestTimeout;
	}

	@NonNull
	Duration minimumTimeToLive() {
		return this.minimumTimeToLive;
	}

	@NonNull
	Duration defaultTimeToLive() {
		return this.defaultTimeToLive;
	}

	@NonNull
	Duration maximumTimeToLive() {
		return this.maximumTimeToLive;
	}

	@NonNull
	Duration unknownKeyRefreshCooldown() {
		return this.unknownKeyRefreshCooldown;
	}

	@NonNull
	Duration maximumStaleness() {
		return this.maximumStaleness;
	}

	int maximumResponseBytes() {
		return this.maximumResponseBytes;
	}

	int maximumKeys() {
		return this.maximumKeys;
	}

	@NonNull
	JoseObserver observer() {
		return this.observer;
	}

	@Nullable
	String unpatchedRuntimeVersion() {
		return this.unpatchedRuntimeVersion;
	}

	/**
	 * Describes the settings, for {@link RemoteJsonWebKeySource#toString()}.
	 *
	 * @return the settings, without the observer
	 */
	@Override
	@NonNull
	public String toString() {
		return "requestTimeout=" + this.requestTimeout + ", minimumTimeToLive=" + this.minimumTimeToLive
				+ ", defaultTimeToLive=" + this.defaultTimeToLive + ", maximumTimeToLive=" + this.maximumTimeToLive
				+ ", unknownKeyRefreshCooldown=" + this.unknownKeyRefreshCooldown + ", maximumStaleness="
				+ this.maximumStaleness + ", maximumResponseBytes=" + this.maximumResponseBytes + ", maximumKeys="
				+ this.maximumKeys + ", clock=" + this.clock;
	}

	@NonNull
	private static Duration requirePositive(@NonNull Duration duration) {
		requireNonNull(duration);

		if (duration.isNegative() || duration.isZero())
			throw new IllegalArgumentException("The duration must be positive.");

		return duration;
	}

	@NonNull
	private static Duration requireNonNegative(@NonNull Duration duration) {
		requireNonNull(duration);

		if (duration.isNegative())
			throw new IllegalArgumentException("The duration must not be negative.");

		return duration;
	}
}
