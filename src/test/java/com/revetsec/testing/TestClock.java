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

package com.revetsec.testing;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;

import static java.util.Objects.requireNonNull;

/**
 * A settable, thread-safe {@link Clock} for tests (plan R11: Revetsec reads validation time only from an injected
 * {@code Clock}).
 * <p>
 * <strong>Monotonic.</strong> Time never moves backward: {@link #set(Instant)} rejects an instant earlier than the
 * current one and {@link #advance(Duration)} rejects a negative duration, both with
 * {@link IllegalArgumentException} and without changing the clock. So every read on any thread returns an instant no
 * earlier than any read that happened before it. A test that needs an earlier time starts a new clock.
 * <p>
 * The clock keeps nanosecond precision, so sub-second boundaries ({@code .000}, {@code .001}, {@code .999}) can be
 * pinned exactly. {@link #withZone(ZoneId)} returns a view that shares this clock's instant, so setting either one
 * moves both.
 * <p>
 * Deadlines and observer durations use {@link System#nanoTime()}, not a {@code Clock} (M1 plan, R11 errata), so this
 * clock cannot speed up a timeout test.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class TestClock extends Clock {
	private final AtomicReference<Instant> instant;
	private final ZoneId zone;

	private TestClock(@NonNull AtomicReference<@NonNull Instant> instant, @NonNull ZoneId zone) {
		this.instant = instant;
		this.zone = zone;
	}

	/**
	 * A clock in UTC that reads {@code instant} until it is set or advanced.
	 *
	 * @param instant the starting instant
	 * @return a new clock
	 */
	public static @NonNull TestClock fromInstant(@NonNull Instant instant) {
		requireNonNull(instant);
		return new TestClock(new AtomicReference<>(instant), ZoneOffset.UTC);
	}

	/**
	 * Moves the clock to {@code target}, which must not be earlier than the current instant.
	 *
	 * @param target the new instant
	 * @return {@code target}
	 * @throws IllegalArgumentException if {@code target} is earlier than the current instant
	 */
	public @NonNull Instant set(@NonNull Instant target) {
		requireNonNull(target);
		return this.instant.updateAndGet(current -> {
			if (target.isBefore(current))
				throw new IllegalArgumentException("TestClock is monotonic: " + target + " is before " + current);
			return target;
		});
	}

	/**
	 * Moves the clock forward by {@code duration}, atomically, so concurrent advances all count.
	 *
	 * @param duration how far to move, zero or positive
	 * @return the new instant
	 * @throws IllegalArgumentException if {@code duration} is negative
	 * @throws java.time.DateTimeException if the result is out of {@link Instant}'s range
	 */
	public @NonNull Instant advance(@NonNull Duration duration) {
		requireNonNull(duration);
		if (duration.isNegative())
			throw new IllegalArgumentException("TestClock is monotonic: cannot advance by " + duration);
		return this.instant.updateAndGet(current -> current.plus(duration));
	}

	@Override
	public @NonNull Instant instant() {
		return requireNonNull(this.instant.get());
	}

	@Override
	public long millis() {
		return instant().toEpochMilli();
	}

	@Override
	public @NonNull ZoneId getZone() {
		return this.zone;
	}

	/**
	 * A view in {@code zone} that shares this clock's instant: setting or advancing either one moves both.
	 *
	 * @param zone the zone of the view
	 * @return this clock if {@code zone} is its own, otherwise a view sharing its instant
	 */
	@Override
	public @NonNull TestClock withZone(@NonNull ZoneId zone) {
		requireNonNull(zone);
		return zone.equals(this.zone) ? this : new TestClock(this.instant, zone);
	}

	@Override
	public @NonNull String toString() {
		return "TestClock[" + instant() + "," + this.zone + "]";
	}
}
