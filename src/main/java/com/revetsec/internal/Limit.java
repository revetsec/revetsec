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

package com.revetsec.internal;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.time.Duration;

import static java.util.Objects.requireNonNull;

/**
 * One row of the R8 limits registry: a name, a unit, a default, a floor and a hard cap (plan R8; M1 plan gate 5).
 * <p>
 * Every setting outside [floor, cap] is rejected with {@link IllegalArgumentException}. Negative values are always
 * outside, and so is zero, except in the rows whose floor is zero ({@link #isZeroAllowed()}). Nothing can be set to
 * "unlimited".
 * <p>
 * <strong>Units.</strong> A {@link Unit#DURATION} row is read and checked with {@link Duration}s:
 * {@link #getDefaultDuration()}, {@link #getFloorDuration()}, {@link #getCapDuration()} and
 * {@link #require(Duration)}. Every other row is read and checked with whole numbers in its unit:
 * {@link #getDefaultValue()}, {@link #getFloor()}, {@link #getCap()}, {@link #require(int)} and
 * {@link #require(long)}. Calling the accessor for the other kind of row is a bug and throws
 * {@link IllegalStateException}.
 * <p>
 * The rejection message is fixed per row: it names the row and its range and repeats only the rejected number.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public final class Limit {
	/**
	 * What a limit counts.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 */
	@Immutable
	public enum Unit {
		/**
		 * A size in bytes. A KiB is 1,024 bytes and a MiB 1,048,576.
		 */
		BYTES,
		/**
		 * A length in UTF-16 code units, which is what {@link String#length()} returns.
		 */
		CHARACTERS,
		/**
		 * A plain number: a count of items, such as keys, nodes, elements, operations or nesting levels, or another
		 * dimensionless bound, such as the magnitude of a decimal exponent.
		 */
		COUNT,
		/**
		 * A length of time, read and checked as a {@link Duration} with nanosecond precision.
		 */
		DURATION
	}

	@NonNull
	private final String name;
	@NonNull
	private final Unit unit;
	private final boolean hasDefault;
	/**
	 * In the row's unit; nanoseconds for a {@link Unit#DURATION} row. Meaningless when {@link #hasDefault} is false.
	 */
	private final long defaultAmount;
	private final long floor;
	private final long cap;

	/**
	 * A row counted in bytes, characters or items.
	 */
	@NonNull
	static Limit fromAmounts(@NonNull String name,
													 @NonNull Unit unit,
													 long defaultValue,
													 long floor,
													 long cap) {
		requireNonNull(unit);

		if (unit == Unit.DURATION)
			throw new IllegalArgumentException("Use fromDurations for a duration limit.");

		return new Limit(name, unit, true, defaultValue, floor, cap);
	}

	/**
	 * A row counted in time. {@code defaultValue} is {@code null} for a row with no default, such as a per-call
	 * argument.
	 */
	@NonNull
	static Limit fromDurations(@NonNull String name,
														 @Nullable Duration defaultValue,
														 @NonNull Duration floor,
														 @NonNull Duration cap) {
		requireNonNull(floor);
		requireNonNull(cap);

		return new Limit(name, Unit.DURATION, defaultValue != null, defaultValue == null ? 0 : defaultValue.toNanos(),
				floor.toNanos(), cap.toNanos());
	}

	private Limit(@NonNull String name,
								@NonNull Unit unit,
								boolean hasDefault,
								long defaultAmount,
								long floor,
								long cap) {
		requireNonNull(name);
		requireNonNull(unit);

		if (name.isBlank())
			throw new IllegalArgumentException("A limit needs a name.");
		if (floor < 0 || cap <= 0 || floor > cap)
			throw new IllegalArgumentException("A limit needs 0 <= floor <= cap and a positive cap.");
		if (hasDefault && (defaultAmount < floor || defaultAmount > cap))
			throw new IllegalArgumentException("A limit's default must lie in [floor, cap].");

		this.name = name;
		this.unit = unit;
		this.hasDefault = hasDefault;
		this.defaultAmount = defaultAmount;
		this.floor = floor;
		this.cap = cap;
	}

	/**
	 * Returns the row's name, as rejection messages print it.
	 *
	 * @return the row's name
	 */
	@NonNull
	public String getName() {
		return this.name;
	}

	/**
	 * Returns what the row counts.
	 *
	 * @return the row's unit
	 */
	@NonNull
	public Unit getUnit() {
		return this.unit;
	}

	/**
	 * Returns whether the row has a default. Only a per-call argument, such as a seal lifetime, has none.
	 *
	 * @return whether the row has a default
	 */
	public boolean hasDefault() {
		return this.hasDefault;
	}

	/**
	 * Returns whether zero is a permitted value, which is exactly when the floor is zero.
	 *
	 * @return whether zero is permitted
	 */
	public boolean isZeroAllowed() {
		return this.floor == 0;
	}

	/**
	 * Returns the default of a row counted in bytes, characters or items.
	 *
	 * @return the default, in the row's unit
	 * @throws IllegalStateException if this is a duration row or has no default
	 */
	public long getDefaultValue() {
		requireAmountRow();
		requireDefault();
		return this.defaultAmount;
	}

	/**
	 * Returns the default of a row counted in bytes, characters or items, as an {@code int}.
	 *
	 * @return the default, in the row's unit
	 * @throws IllegalStateException if this is a duration row, has no default, or the default does not fit an
	 *                               {@code int}
	 */
	public int getDefaultIntValue() {
		long value = getDefaultValue();

		if (value > Integer.MAX_VALUE)
			throw new IllegalStateException("The default of " + this.name + " does not fit an int.");

		return (int) value;
	}

	/**
	 * Returns the floor of a row counted in bytes, characters or items.
	 *
	 * @return the smallest permitted value, in the row's unit
	 * @throws IllegalStateException if this is a duration row
	 */
	public long getFloor() {
		requireAmountRow();
		return this.floor;
	}

	/**
	 * Returns the hard cap of a row counted in bytes, characters or items.
	 *
	 * @return the largest permitted value, in the row's unit
	 * @throws IllegalStateException if this is a duration row
	 */
	public long getCap() {
		requireAmountRow();
		return this.cap;
	}

	/**
	 * Returns the default of a duration row.
	 *
	 * @return the default
	 * @throws IllegalStateException if this is not a duration row or has no default
	 */
	@NonNull
	public Duration getDefaultDuration() {
		requireDurationRow();
		requireDefault();
		return Duration.ofNanos(this.defaultAmount);
	}

	/**
	 * Returns the floor of a duration row.
	 *
	 * @return the shortest permitted duration
	 * @throws IllegalStateException if this is not a duration row
	 */
	@NonNull
	public Duration getFloorDuration() {
		requireDurationRow();
		return Duration.ofNanos(this.floor);
	}

	/**
	 * Returns the hard cap of a duration row.
	 *
	 * @return the longest permitted duration
	 * @throws IllegalStateException if this is not a duration row
	 */
	@NonNull
	public Duration getCapDuration() {
		requireDurationRow();
		return Duration.ofNanos(this.cap);
	}

	/**
	 * Checks a setting of a row counted in bytes, characters or items.
	 *
	 * @param value the setting
	 * @return {@code value}
	 * @throws IllegalArgumentException if {@code value} is outside [floor, cap]
	 * @throws IllegalStateException    if this is a duration row
	 */
	public int require(int value) {
		require((long) value);
		return value;
	}

	/**
	 * Checks a setting of a row counted in bytes, characters or items.
	 *
	 * @param value the setting
	 * @return {@code value}
	 * @throws IllegalArgumentException if {@code value} is outside [floor, cap]
	 * @throws IllegalStateException    if this is a duration row
	 */
	public long require(long value) {
		requireAmountRow();

		if (value < this.floor || value > this.cap)
			throw new IllegalArgumentException(this.name + " must be from " + this.floor + " to " + this.cap
					+ unitSuffix() + "; got " + value + ".");

		return value;
	}

	/**
	 * Checks a setting of a duration row. The comparison is exact, to the nanosecond, and never overflows.
	 *
	 * @param value the setting
	 * @return {@code value}
	 * @throws NullPointerException     if {@code value} is {@code null}
	 * @throws IllegalArgumentException if {@code value} is outside [floor, cap]
	 * @throws IllegalStateException    if this is not a duration row
	 */
	@NonNull
	public Duration require(@NonNull Duration value) {
		requireNonNull(value);
		requireDurationRow();

		Duration floorDuration = Duration.ofNanos(this.floor);
		Duration capDuration = Duration.ofNanos(this.cap);

		if (value.compareTo(floorDuration) < 0 || value.compareTo(capDuration) > 0)
			throw new IllegalArgumentException(this.name + " must be from " + floorDuration + " to " + capDuration
					+ "; got " + value + ".");

		return value;
	}

	@Override
	@NonNull
	public String toString() {
		if (this.unit == Unit.DURATION)
			return getClass().getSimpleName() + "{name=" + this.name + ", unit=" + this.unit + ", default="
					+ (this.hasDefault ? Duration.ofNanos(this.defaultAmount) : "none") + ", floor="
					+ Duration.ofNanos(this.floor) + ", cap=" + Duration.ofNanos(this.cap) + "}";

		return getClass().getSimpleName() + "{name=" + this.name + ", unit=" + this.unit + ", default="
				+ this.defaultAmount + ", floor=" + this.floor + ", cap=" + this.cap + "}";
	}

	@NonNull
	private String unitSuffix() {
		return switch (this.unit) {
			case BYTES -> " bytes";
			case CHARACTERS -> " characters";
			case COUNT, DURATION -> "";
		};
	}

	private void requireAmountRow() {
		if (this.unit == Unit.DURATION)
			throw new IllegalStateException(this.name + " is a duration limit.");
	}

	private void requireDurationRow() {
		if (this.unit != Unit.DURATION)
			throw new IllegalStateException(this.name + " is not a duration limit.");
	}

	private void requireDefault() {
		if (!this.hasDefault)
			throw new IllegalStateException(this.name + " has no default.");
	}
}
