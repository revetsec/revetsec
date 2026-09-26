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

package com.revetsec.json;

import com.revetsec.internal.json.JsonWriter;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.math.BigDecimal;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * A JSON number, held exactly as a {@link BigDecimal}. There is no floating-point form.
 * <p>
 * <strong>Caps.</strong> A number has at most 4,096 significant digits (its {@link BigDecimal#precision()}) and an
 * adjusted decimal exponent (precision &minus; scale &minus; 1, the exponent of its leading digit) of magnitude at
 * most 100,000, so it always renders in bounded space and compares in bounded time.
 * <p>
 * <strong>Equality</strong> is by numeric value: {@code 1}, {@code 1.0}, {@code 1E0} and {@code 0.1E1} are equal and
 * have the same hash code, which is computed once from the nearest {@code double}. No method expands a number to its
 * plain form, so {@code 1E+100000} costs no more to compare or hash than {@code 1}.
 * <p>
 * <strong>Rendering.</strong> {@link #toJson()} writes the canonical form of {@link BigDecimal#toString()}, not the
 * text a number was parsed from: {@code 1e2} becomes {@code 1E+2}, {@code -0} becomes {@code 0}, and {@code 1.50}
 * stays {@code 1.50}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class JsonNumber implements JsonValue {
	/**
	 * A long has at most 19 digits, so only an adjusted exponent from 0 to 18 can hold a non-zero whole long.
	 */
	private static final long MAXIMUM_LONG_ADJUSTED_EXPONENT = 18;

	@NonNull
	private final BigDecimal value;
	private final int hashCode;

	/**
	 * Returns a JSON number holding {@code value} exactly.
	 * <p>
	 * A subclass of {@link BigDecimal} is first copied into a {@code BigDecimal} with the same unscaled value and
	 * scale, and the copy is what the number checks, holds and renders, so the number can never change later.
	 *
	 * @param value the number's value
	 * @return the JSON number
	 * @throws NullPointerException     if {@code value} is {@code null}
	 * @throws IllegalArgumentException if {@code value} has more than 4,096 digits, or an adjusted exponent of
	 *                                  magnitude above 100,000
	 * @since 1.0.0
	 */
	@NonNull
	public static JsonNumber fromValue(@NonNull BigDecimal value) {
		return new JsonNumber(JsonInvariants.requireNumberWithinCaps(JsonInvariants.exactBigDecimal(value)));
	}

	/**
	 * Returns a JSON number holding {@code value}.
	 *
	 * @param value the number's value
	 * @return the JSON number
	 * @throws NullPointerException if {@code value} is {@code null}
	 * @since 1.0.0
	 */
	@NonNull
	public static JsonNumber fromValue(@NonNull Long value) {
		requireNonNull(value);
		return new JsonNumber(BigDecimal.valueOf(value.longValue()));
	}

	private JsonNumber(@NonNull BigDecimal value) {
		this.value = value;
		// Numerically equal values have the same exact value, so the same correctly rounded double.
		this.hashCode = Double.hashCode(value.doubleValue());
	}

	/**
	 * Returns this number's exact value, with the scale it was given or parsed with. It is always an instance of
	 * {@link BigDecimal} itself, never a subclass.
	 *
	 * @return the value
	 * @since 1.0.0
	 */
	@NonNull
	public BigDecimal getValue() {
		return this.value;
	}

	/**
	 * Returns this number as a {@code long}, if it is a whole number in the range of {@code long}. Trailing zeros after
	 * the decimal point do not matter: {@code 42.0} and {@code 4.2E+1} give 42.
	 *
	 * @return the value, or empty if it has a non-zero fraction or is outside the range of {@code long}
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull Long> getLongValueExact() {
		if (this.value.signum() == 0)
			return Optional.of(0L);

		long adjustedExponent = JsonInvariants.adjustedExponent(this.value);

		// Rejects magnitudes below 1 or above 10^19 before any rescaling, so the cost never depends on the exponent.
		if (adjustedExponent < 0 || adjustedExponent > MAXIMUM_LONG_ADJUSTED_EXPONENT)
			return Optional.empty();

		try {
			return Optional.of(this.value.longValueExact());
		} catch (ArithmeticException exception) {
			return Optional.empty();
		}
	}

	@Override
	@NonNull
	public String toJson() {
		return JsonWriter.toJson(this);
	}

	@Override
	public boolean equals(@Nullable Object other) {
		return this == other || (other instanceof JsonNumber number && this.hashCode == number.hashCode
				&& this.value.compareTo(number.value) == 0);
	}

	@Override
	public int hashCode() {
		return this.hashCode;
	}

	@Override
	@NonNull
	public String toString() {
		return "JsonNumber{value=<redacted>}";
	}
}
