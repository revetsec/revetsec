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
 * A thread-safe {@link Clock} a test can move in both directions, for the clock-set-back cases (plan M2, A-2): a
 * wall clock that an operator or NTP steps backward while a component holds the {@code Clock} it was built with.
 * <p>
 * {@link TestClock} stays monotonic and is the clock to use everywhere else: its promise that time never moves
 * backward is what makes most tests simple, and "start a new clock" cannot work for a component, such as the key-set
 * cache, that keeps the clock it was given. This clock makes no such promise: {@link #set(Instant)} takes any instant,
 * {@link #advance(Duration)} takes a negative duration, and {@link #rewind(Duration)} moves back. Each change is
 * atomic, so concurrent moves all count.
 * <p>
 * The clock keeps nanosecond precision. {@link #withZone(ZoneId)} returns a view that shares this clock's instant, so
 * moving either one moves both. Deadlines and observer durations use {@link System#nanoTime()}, not a {@code Clock}
 * (R11 as amended by M1), so moving this clock never ends or extends a timeout.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class RewindableClock extends Clock {
	private final AtomicReference<Instant> instant;
	private final ZoneId zone;

	private RewindableClock(@NonNull AtomicReference<@NonNull Instant> instant, @NonNull ZoneId zone) {
		this.instant = instant;
		this.zone = zone;
	}

	/**
	 * A clock in UTC that reads {@code instant} until it is moved.
	 *
	 * @param instant the starting instant
	 * @return a new clock
	 */
	public static @NonNull RewindableClock fromInstant(@NonNull Instant instant) {
		requireNonNull(instant);
		return new RewindableClock(new AtomicReference<>(instant), ZoneOffset.UTC);
	}

	/**
	 * Moves the clock to {@code target}, earlier or later.
	 *
	 * @param target the new instant
	 * @return {@code target}, as {@link TestClock#set(Instant)} returns it
	 */
	public @NonNull Instant set(@NonNull Instant target) {
		requireNonNull(target);
		this.instant.set(target);
		return target;
	}

	/**
	 * Moves the clock by {@code duration}, forward if it is positive and backward if it is negative.
	 *
	 * @param duration how far to move
	 * @return the new instant
	 * @throws java.time.DateTimeException if the result is out of {@link Instant}'s range; the clock is unchanged
	 */
	public @NonNull Instant advance(@NonNull Duration duration) {
		requireNonNull(duration);
		return this.instant.updateAndGet(current -> current.plus(duration));
	}

	/**
	 * Moves the clock back by {@code duration}.
	 *
	 * @param duration how far back to move, zero or positive
	 * @return the new instant
	 * @throws IllegalArgumentException if {@code duration} is negative (use {@link #advance(Duration)})
	 * @throws java.time.DateTimeException if the result is out of {@link Instant}'s range; the clock is unchanged
	 */
	public @NonNull Instant rewind(@NonNull Duration duration) {
		requireNonNull(duration);
		if (duration.isNegative())
			throw new IllegalArgumentException("Rewind by a zero or positive duration, not " + duration);
		return this.instant.updateAndGet(current -> current.minus(duration));
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
	 * A view in {@code zone} that shares this clock's instant: moving either one moves both.
	 *
	 * @param zone the zone of the view
	 * @return this clock if {@code zone} is its own, otherwise a view sharing its instant
	 */
	@Override
	public @NonNull RewindableClock withZone(@NonNull ZoneId zone) {
		requireNonNull(zone);
		return zone.equals(this.zone) ? this : new RewindableClock(this.instant, zone);
	}

	@Override
	public @NonNull String toString() {
		return "RewindableClock[" + instant() + "," + this.zone + "]";
	}
}
