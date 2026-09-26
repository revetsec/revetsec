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

package com.revetsec.internal.json;

import com.revetsec.internal.json.JsonFieldException.Kind;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Typed reads of protocol members (claims, metadata and token-response parameters) for protocol validation.
 * <p>
 * Unlike {@code JsonObject}'s {@code findX} conveniences, which return empty for a member of the wrong type, each
 * method here tells the three cases apart: an absent member gives an empty {@link Optional}; a member of the expected
 * type gives its value; and anything else, a JSON {@code null} included, throws {@link JsonFieldException}, so the
 * caller rejects the malformed document instead of treating the member as absent.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class JsonFields {
	/**
	 * -9999-01-01T00:00:00Z, the earliest NumericDate accepted, in epoch seconds.
	 */
	@NonNull
	private static final BigDecimal EARLIEST_EPOCH_SECOND = BigDecimal.valueOf(-377_705_116_800L);

	/**
	 * 10000-01-01T00:00:00Z, the first instant after the latest NumericDate accepted, in epoch seconds.
	 */
	@NonNull
	private static final BigDecimal END_EPOCH_SECOND = BigDecimal.valueOf(253_402_300_800L);

	private static final int NANOSECOND_DIGITS = 9;

	private JsonFields() {
	}

	/**
	 * Reads a string member.
	 *
	 * @param object the object
	 * @param name   the member name, compared exactly
	 * @return the string, or empty if the member is absent
	 * @throws NullPointerException if an argument is {@code null}
	 * @throws JsonFieldException   ({@link Kind#WRONG_TYPE}) if the member is not a string
	 */
	public static @NonNull Optional<@NonNull String> string(@NonNull JsonObject object, @NonNull String name)
			throws JsonFieldException {
		@Nullable JsonValue value = member(object, name);

		if (value == null)
			return Optional.empty();

		if (!(value instanceof JsonString string))
			throw new JsonFieldException(Kind.WRONG_TYPE);

		return Optional.of(string.getValue());
	}

	/**
	 * Reads a member that is either one string or an array of strings, such as the JWT {@code aud} claim
	 * (RFC 7519 section 4.1.3).
	 *
	 * @param object the object
	 * @param name   the member name, compared exactly
	 * @return the strings in order (one string gives a list of one, an empty array an empty list), or empty if the
	 * member is absent
	 * @throws NullPointerException if an argument is {@code null}
	 * @throws JsonFieldException   ({@link Kind#WRONG_TYPE}) if the member is neither a string nor an array of only
	 *                              strings
	 */
	public static @NonNull Optional<@NonNull List<@NonNull String>> stringOrStringArray(@NonNull JsonObject object,
																																											 @NonNull String name)
			throws JsonFieldException {
		@Nullable JsonValue value = member(object, name);

		if (value == null)
			return Optional.empty();

		if (value instanceof JsonString string)
			return Optional.of(List.of(string.getValue()));

		if (!(value instanceof JsonArray array))
			throw new JsonFieldException(Kind.WRONG_TYPE);

		List<@NonNull String> strings = new ArrayList<>(array.getElements().size());

		for (JsonValue element : array.getElements()) {
			if (!(element instanceof JsonString string))
				throw new JsonFieldException(Kind.WRONG_TYPE);

			strings.add(string.getValue());
		}

		return Optional.of(Collections.unmodifiableList(strings));
	}

	/**
	 * Reads a NumericDate member (RFC 7519 section 2): seconds since 1970-01-01T00:00:00Z, ignoring leap seconds, which
	 * may have a fraction.
	 * <p>
	 * The value is range-checked against years -9999 to 9999 before any conversion, so neither a huge exponent nor
	 * {@link Instant}'s own range can make the conversion fail or expand the number. A fraction finer than a
	 * nanosecond is rounded down, toward the past.
	 *
	 * @param object the object
	 * @param name   the member name, compared exactly
	 * @return the instant, or empty if the member is absent
	 * @throws NullPointerException if an argument is {@code null}
	 * @throws JsonFieldException   {@link Kind#WRONG_TYPE} if the member is not a number, or
	 *                              {@link Kind#OUT_OF_RANGE} if it is before -9999-01-01T00:00:00Z or not before
	 *                              10000-01-01T00:00:00Z
	 */
	public static @NonNull Optional<@NonNull Instant> numericDate(@NonNull JsonObject object, @NonNull String name)
			throws JsonFieldException {
		@Nullable JsonValue value = member(object, name);

		if (value == null)
			return Optional.empty();

		if (!(value instanceof JsonNumber number))
			throw new JsonFieldException(Kind.WRONG_TYPE);

		BigDecimal seconds = number.getValue();

		// compareTo first compares adjusted exponents, so a huge exponent is rejected without expanding it.
		if (seconds.compareTo(EARLIEST_EPOCH_SECOND) < 0 || seconds.compareTo(END_EPOCH_SECOND) >= 0)
			throw new JsonFieldException(Kind.OUT_OF_RANGE);

		return Optional.of(toInstant(seconds));
	}

	/**
	 * Converts a number of seconds already known to lie within the NumericDate range, rounding down to a nanosecond.
	 */
	private static @NonNull Instant toInstant(@NonNull BigDecimal seconds) {
		// A magnitude below 10^-9 (adjusted exponent -10 or less) floors to 0 or, if negative, to -1 ns. Handling it
		// here keeps setScale from dividing by a large power of ten for a value such as 1E-100000.
		if ((long) seconds.precision() - seconds.scale() - 1 < -NANOSECOND_DIGITS)
			return seconds.signum() < 0 ? Instant.ofEpochSecond(0, -1) : Instant.EPOCH;

		BigDecimal nanosecondPrecision = seconds.setScale(NANOSECOND_DIGITS, RoundingMode.FLOOR);
		BigDecimal wholeSeconds = nanosecondPrecision.setScale(0, RoundingMode.FLOOR);
		long nanoseconds = nanosecondPrecision.subtract(wholeSeconds).movePointRight(NANOSECOND_DIGITS)
				.longValueExact();

		return Instant.ofEpochSecond(wholeSeconds.longValueExact(), nanoseconds);
	}

	private static @Nullable JsonValue member(@NonNull JsonObject object, @NonNull String name) {
		requireNonNull(object);
		requireNonNull(name);
		return object.getMembers().get(name);
	}
}
