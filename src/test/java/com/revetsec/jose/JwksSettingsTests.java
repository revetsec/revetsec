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

import com.revetsec.testing.TestClock;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.time.Clock;
import java.time.Duration;
import java.util.function.Function;
import java.util.stream.Stream;

/**
 * The settings behind the package-private constructor that a later milestone's component uses to embed a key source
 * (M2 plan, "Internal types": a constructor from already-validated settings). The builder checks every setting
 * against its {@code Limits} row; these settings keep the cache's own preconditions even when their maker checked
 * less: a positive request timeout and cooldown (a zero cooldown would make the backoff and the two-attempt ceiling
 * windows empty), non-negative lifetimes, ordered times to live and positive limits.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JwksSettingsTests {
	private static final Clock CLOCK = TestClock.fromInstant(JwksCacheTests.START);

	// The cache's preconditions: each refused value is IllegalArgumentException, and the edge values pass (zero
	// lifetimes and staleness, equal times to live, limits of 1).
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> eachSettingKeepsTheCachesPreconditions() {
		return Stream.of(
				refused("a zero request timeout", settings -> settings.requestTimeout(Duration.ZERO)),
				refused("a negative request timeout", settings -> settings.requestTimeout(Duration.ofNanos(-1))),
				refused("a zero cooldown", settings -> settings.cooldown(Duration.ZERO)),
				refused("a negative cooldown", settings -> settings.cooldown(Duration.ofNanos(-1))),
				refused("a negative minimum time to live", settings -> settings.timesToLive(Duration.ofNanos(-1),
						Duration.ZERO, Duration.ZERO)),
				refused("a negative staleness", settings -> settings.staleness(Duration.ofNanos(-1))),
				refused("a minimum above the default", settings -> settings.timesToLive(Duration.ofMinutes(11),
						Duration.ofMinutes(10), Duration.ofHours(6))),
				refused("a default above the maximum", settings -> settings.timesToLive(Duration.ofMinutes(1),
						Duration.ofHours(7), Duration.ofHours(6))),
				refused("a zero body limit", settings -> settings.limits(0, 100)),
				refused("a zero key limit", settings -> settings.limits(256 * 1024, 0)),
				accepted("zero times to live and staleness", settings -> settings.timesToLive(Duration.ZERO, Duration.ZERO,
						Duration.ZERO).staleness(Duration.ZERO)),
				accepted("equal times to live", settings -> settings.timesToLive(Duration.ofMinutes(5),
						Duration.ofMinutes(5), Duration.ofMinutes(5))),
				accepted("the smallest positive values", settings -> settings.requestTimeout(Duration.ofNanos(1))
						.cooldown(Duration.ofNanos(1)).limits(1, 1)));
	}

	// The accessors return what was given, and toString lists the settings without the observer or the runtime.
	@Test
	void theSettingsAreKeptAsGivenAndDescribed() {
		JwksSettings settings = JwksCacheTests.settings(CLOCK, JoseObserver.disabledInstance());

		Assertions.assertSame(CLOCK, settings.clock());
		Assertions.assertEquals(Duration.ofSeconds(10), settings.requestTimeout());
		Assertions.assertEquals(Duration.ofMinutes(1), settings.minimumTimeToLive());
		Assertions.assertEquals(Duration.ofMinutes(10), settings.defaultTimeToLive());
		Assertions.assertEquals(Duration.ofHours(6), settings.maximumTimeToLive());
		Assertions.assertEquals(JwksCacheTests.COOLDOWN, settings.unknownKeyRefreshCooldown());
		Assertions.assertEquals(Duration.ofHours(12), settings.maximumStaleness());
		Assertions.assertEquals(256 * 1024, settings.maximumResponseBytes());
		Assertions.assertEquals(100, settings.maximumKeys());
		Assertions.assertSame(JoseObserver.disabledInstance(), settings.observer());
		Assertions.assertNull(settings.unpatchedRuntimeVersion());
		Assertions.assertEquals("requestTimeout=PT10S, minimumTimeToLive=PT1M, defaultTimeToLive=PT10M, "
				+ "maximumTimeToLive=PT6H, unknownKeyRefreshCooldown=PT30S, maximumStaleness=PT12H, "
				+ "maximumResponseBytes=262144, maximumKeys=100, clock=" + CLOCK, settings.toString());
		Assertions.assertEquals("17.0.2", new Draft().runtime("17.0.2").build().unpatchedRuntimeVersion());
	}

	// R1: every argument but the unpatched runtime version is required.
	@Test
	@SuppressWarnings("NullAway")
	void nullArgumentsAreRefused() {
		Duration second = Duration.ofSeconds(1);
		JoseObserver observer = JoseObserver.disabledInstance();
		Assertions.assertThrows(NullPointerException.class, () -> new JwksSettings(null, second, second, second, second,
				second, second, 1, 1, observer, null));
		Assertions.assertThrows(NullPointerException.class, () -> new JwksSettings(CLOCK, null, second, second, second,
				second, second, 1, 1, observer, null));
		Assertions.assertThrows(NullPointerException.class, () -> new JwksSettings(CLOCK, second, null, second, second,
				second, second, 1, 1, observer, null));
		Assertions.assertThrows(NullPointerException.class, () -> new JwksSettings(CLOCK, second, second, null, second,
				second, second, 1, 1, observer, null));
		Assertions.assertThrows(NullPointerException.class, () -> new JwksSettings(CLOCK, second, second, second, null,
				second, second, 1, 1, observer, null));
		Assertions.assertThrows(NullPointerException.class, () -> new JwksSettings(CLOCK, second, second, second, second,
				null, second, 1, 1, observer, null));
		Assertions.assertThrows(NullPointerException.class, () -> new JwksSettings(CLOCK, second, second, second, second,
				second, null, 1, 1, observer, null));
		Assertions.assertThrows(NullPointerException.class, () -> new JwksSettings(CLOCK, second, second, second, second,
				second, second, 1, 1, null, null));
	}

	private static @NonNull DynamicTest refused(@NonNull String name, @NonNull Function<@NonNull Draft, @NonNull Draft> change) {
		return DynamicTest.dynamicTest(name + " is refused", () -> Assertions.assertThrows(IllegalArgumentException.class,
				() -> change.apply(new Draft()).build()));
	}

	private static @NonNull DynamicTest accepted(@NonNull String name, @NonNull Function<@NonNull Draft, @NonNull Draft> change) {
		return DynamicTest.dynamicTest(name + " is accepted", () -> Assertions.assertDoesNotThrow(
				() -> change.apply(new Draft()).build()));
	}

	/**
	 * The default settings, changed one group at a time.
	 */
	private static final class Draft {
		private Duration requestTimeout = Duration.ofSeconds(10);
		private Duration minimumTimeToLive = Duration.ofMinutes(1);
		private Duration defaultTimeToLive = Duration.ofMinutes(10);
		private Duration maximumTimeToLive = Duration.ofHours(6);
		private Duration cooldown = JwksCacheTests.COOLDOWN;
		private Duration staleness = Duration.ofHours(12);
		private int maximumResponseBytes = 256 * 1024;
		private int maximumKeys = 100;
		private @Nullable String runtime;

		@NonNull Draft requestTimeout(@NonNull Duration value) {
			this.requestTimeout = value;
			return this;
		}

		@NonNull Draft timesToLive(@NonNull Duration minimum, @NonNull Duration standard, @NonNull Duration maximum) {
			this.minimumTimeToLive = minimum;
			this.defaultTimeToLive = standard;
			this.maximumTimeToLive = maximum;
			return this;
		}

		@NonNull Draft cooldown(@NonNull Duration value) {
			this.cooldown = value;
			return this;
		}

		@NonNull Draft staleness(@NonNull Duration value) {
			this.staleness = value;
			return this;
		}

		@NonNull Draft limits(int responseBytes, int keys) {
			this.maximumResponseBytes = responseBytes;
			this.maximumKeys = keys;
			return this;
		}

		@NonNull Draft runtime(@NonNull String version) {
			this.runtime = version;
			return this;
		}

		@NonNull JwksSettings build() {
			return new JwksSettings(CLOCK, this.requestTimeout, this.minimumTimeToLive, this.defaultTimeToLive,
					this.maximumTimeToLive, this.cooldown, this.staleness, this.maximumResponseBytes, this.maximumKeys,
					JoseObserver.disabledInstance(), this.runtime);
		}
	}
}
