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

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import java.time.Duration;

import static java.util.Objects.requireNonNull;

/**
 * The total deadline of one public call, which covers every HTTP exchange in it (M1 plan, G5-5).
 * <p>
 * Time is measured with {@link System#nanoTime()}, never with the component's {@link java.time.Clock}, so a clock
 * that is set back or frozen (as in tests) cannot extend a deadline (R11 as amended). A deadline starts when it is
 * created; {@link HttpExchange} fails with {@link HttpExchangeException.Kind#TIMEOUT} before it builds a request once
 * no time is left.
 * <p>
 * This internal type accepts any non-negative total, including zero (a deadline that has already passed), so tests
 * can use short deadlines. Public builders check their settings against {@code Limits.TOTAL_DEADLINE} first.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public final class Deadline {
	private final long startNanos;
	private final long totalNanos;

	private Deadline(long startNanos, long totalNanos) {
		this.startNanos = startNanos;
		this.totalNanos = totalNanos;
	}

	/**
	 * Starts a deadline that ends {@code total} from now.
	 *
	 * @param total the time allowed, zero or positive; a total too large for a {@code long} of nanoseconds is capped
	 *              at about 292 years
	 * @return a new deadline
	 * @throws NullPointerException     if {@code total} is {@code null}
	 * @throws IllegalArgumentException if {@code total} is negative
	 */
	@NonNull
	public static Deadline fromNow(@NonNull Duration total) {
		requireNonNull(total);

		if (total.isNegative())
			throw new IllegalArgumentException("A deadline's total must not be negative.");

		long totalNanos;

		try {
			totalNanos = total.toNanos();
		} catch (ArithmeticException e) {
			totalNanos = Long.MAX_VALUE;
		}

		return new Deadline(System.nanoTime(), totalNanos);
	}

	/**
	 * Restricts the remaining time without moving this deadline's original absolute cutoff.
	 * The returned deadline uses the same monotonic start and expires at the earlier cutoff.
	 * @param maximumRemaining zero or positive remaining allowance
	 * @return the restricted deadline
	 */
	public @NonNull Deadline boundedBy(@NonNull Duration maximumRemaining) {
		requireNonNull(maximumRemaining);
		if (maximumRemaining.isNegative()) throw new IllegalArgumentException("A remaining allowance must not be negative.");
		long maximum;
		try { maximum = maximumRemaining.toNanos(); }
		catch (ArithmeticException failure) { maximum = Long.MAX_VALUE; }
		long elapsed = System.nanoTime() - this.startNanos;
		long cutoff = maximum > Long.MAX_VALUE - elapsed ? Long.MAX_VALUE : elapsed + maximum;
		return new Deadline(this.startNanos, Math.min(this.totalNanos, cutoff));
	}

	/**
	 * The time left, in nanoseconds: zero or negative once the deadline has passed.
	 *
	 * @return the nanoseconds left
	 */
	public long remainingNanos() {
		// nanoTime differences are exact even across numeric overflow; the elapsed time is never negative.
		long elapsedNanos = System.nanoTime() - this.startNanos;
		return this.totalNanos - elapsedNanos;
	}

	/**
	 * The time left: zero or negative once the deadline has passed.
	 *
	 * @return the time left
	 */
	@NonNull
	public Duration remaining() {
		return Duration.ofNanos(remainingNanos());
	}

	/**
	 * Whether no time is left.
	 *
	 * @return {@code true} once the deadline has passed
	 */
	public boolean isExpired() {
		return remainingNanos() <= 0;
	}

	/**
	 * The time this deadline allowed when it started.
	 *
	 * @return the total
	 */
	@NonNull
	public Duration getTotal() {
		return Duration.ofNanos(this.totalNanos);
	}

	/**
	 * Describes this deadline.
	 *
	 * @return the total and the time left
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{total=" + getTotal() + ", remaining=" + remaining() + "}";
	}
}
