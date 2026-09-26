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

import javax.annotation.concurrent.ThreadSafe;
import java.net.http.HttpHeaders;
import java.time.DateTimeException;
import java.time.DayOfWeek;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Parses a {@code Retry-After} field (RFC 9110 section 10.2.3) into the delay it asks for, as a hint that M2's
 * protocol exceptions pass on; Revetsec itself never waits or retries.
 * <p>
 * The field is {@code HTTP-date / delay-seconds}:
 * <ul>
 *   <li>{@code delay-seconds} is {@code 1*DIGIT}. Leading zeros are allowed, and a value above
 *   {@value #MAXIMUM_DELAY_SECONDS} seconds (about 68 years) is treated as malformed rather than overflowing.</li>
 *   <li>{@code HTTP-date} is any of the three formats a recipient must accept (RFC 9110 section 5.6.7):
 *   IMF-fixdate ({@code Sun, 06 Nov 1994 08:49:37 GMT}), the obsolete RFC 850 form
 *   ({@code Sunday, 06-Nov-94 08:49:37 GMT}, whose two-digit year is read as the latest year with those last two
 *   digits that puts the timestamp no more than 50 years after {@code now}, compared to the second) and asctime
 *   ({@code Sun Nov  6 08:49:37 1994}). Names are case-sensitive, the day name must match the date, and a second of
 *   60 (a leap second) counts as the next second. The delay is the time from {@code now} to the date, or zero for a
 *   date in the past.</li>
 * </ul>
 * The result is empty when the field is absent, repeated, or not exactly one of those forms (leading and trailing
 * OWS aside), so a hint the server garbled is simply dropped.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class RetryAfter {
	/**
	 * The largest {@code delay-seconds} value accepted: {@link Integer#MAX_VALUE}.
	 */
	public static final long MAXIMUM_DELAY_SECONDS = Integer.MAX_VALUE;

	private static final List<String> DAY_NAMES = List.of("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun");
	private static final List<String> LONG_DAY_NAMES = List.of("Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
			"Saturday", "Sunday");
	private static final List<String> MONTH_NAMES = List.of("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
			"Sep", "Oct", "Nov", "Dec");

	private RetryAfter() {
		// Static helpers only.
	}

	/**
	 * Reads the {@code Retry-After} field of a response.
	 *
	 * @param headers the response headers
	 * @param now     the current time, from the component's clock
	 * @return the requested delay, zero or positive, or empty (see the class description)
	 * @throws NullPointerException if an argument is {@code null}
	 */
	@NonNull
	public static Optional<Duration> parse(@NonNull HttpHeaders headers,
																				 @NonNull Instant now) {
		requireNonNull(headers);
		requireNonNull(now);
		return parse(headers.allValues("Retry-After"), now);
	}

	/**
	 * Reads the values of a {@code Retry-After} field.
	 *
	 * @param fieldValues every value the field had, one per field line
	 * @param now         the current time, from the component's clock
	 * @return the requested delay, zero or positive, or empty (see the class description)
	 * @throws NullPointerException if an argument or a value is {@code null}
	 */
	@NonNull
	public static Optional<Duration> parse(@NonNull List<@NonNull String> fieldValues,
																				 @NonNull Instant now) {
		requireNonNull(fieldValues);
		requireNonNull(now);

		if (fieldValues.size() != 1)
			return Optional.empty();

		String value = trimOws(requireNonNull(fieldValues.get(0)));

		if (value.isEmpty())
			return Optional.empty();

		if (isAllDigits(value, 0, value.length()))
			return delaySeconds(value);

		Optional<Instant> date = httpDate(value, now);

		if (date.isEmpty())
			return Optional.empty();

		Duration delay = Duration.between(now, date.get());
		return Optional.of(delay.isNegative() ? Duration.ZERO : delay);
	}

	@NonNull
	private static Optional<Duration> delaySeconds(@NonNull String digits) {
		int start = 0;

		while (start < digits.length() - 1 && digits.charAt(start) == '0')
			++start;

		// Ten significant digits exceed Integer.MAX_VALUE only by value, so longer strings cannot be in range.
		if (digits.length() - start > 10)
			return Optional.empty();

		long seconds = Long.parseLong(digits, start, digits.length(), 10);
		return seconds > MAXIMUM_DELAY_SECONDS ? Optional.empty() : Optional.of(Duration.ofSeconds(seconds));
	}

	@NonNull
	private static Optional<Instant> httpDate(@NonNull String value,
																						@NonNull Instant now) {
		try {
			if (value.length() == 29 && value.charAt(3) == ',')
				return imfFixdate(value);

			if (value.length() == 24 && value.charAt(3) == ' ')
				return asctimeDate(value);

			int comma = value.indexOf(',');

			if (comma > 3)
				return rfc850Date(value, comma, now);
		} catch (DateTimeException e) {
			// An impossible date, such as 31 Feb, is malformed.
			return Optional.empty();
		}

		return Optional.empty();
	}

	/**
	 * {@code Sun, 06 Nov 1994 08:49:37 GMT}: day-name "," SP 2DIGIT SP month SP 4DIGIT SP time SP "GMT".
	 */
	@NonNull
	private static Optional<Instant> imfFixdate(@NonNull String value) {
		int dayName = DAY_NAMES.indexOf(value.substring(0, 3));
		int month = MONTH_NAMES.indexOf(value.substring(8, 11));

		if (dayName < 0 || month < 0 || value.charAt(4) != ' ' || value.charAt(7) != ' ' || value.charAt(11) != ' '
				|| value.charAt(16) != ' ' || value.charAt(25) != ' ' || !value.startsWith("GMT", 26)
				|| !isAllDigits(value, 5, 7) || !isAllDigits(value, 12, 16))
			return Optional.empty();

		return dateTime(dayName, Integer.parseInt(value, 12, 16, 10), month, Integer.parseInt(value, 5, 7, 10), value,
				17);
	}

	/**
	 * {@code Sun Nov  6 08:49:37 1994}: day-name SP month SP ( 2DIGIT / ( SP DIGIT ) ) SP time SP 4DIGIT.
	 */
	@NonNull
	private static Optional<Instant> asctimeDate(@NonNull String value) {
		int dayName = DAY_NAMES.indexOf(value.substring(0, 3));
		int month = MONTH_NAMES.indexOf(value.substring(4, 7));

		if (dayName < 0 || month < 0 || value.charAt(7) != ' ' || value.charAt(10) != ' ' || value.charAt(19) != ' '
				|| !isAllDigits(value, 20, 24))
			return Optional.empty();

		int day;

		if (value.charAt(8) == ' ' && isAllDigits(value, 9, 10))
			day = value.charAt(9) - '0';
		else if (isAllDigits(value, 8, 10))
			day = Integer.parseInt(value, 8, 10, 10);
		else
			return Optional.empty();

		return dateTime(dayName, Integer.parseInt(value, 20, 24, 10), month, day, value, 11);
	}

	/**
	 * {@code Sunday, 06-Nov-94 08:49:37 GMT}: day-name-l "," SP 2DIGIT "-" month "-" 2DIGIT SP time SP "GMT".
	 */
	@NonNull
	private static Optional<Instant> rfc850Date(@NonNull String value,
																							int comma,
																							@NonNull Instant now) {
		int dayName = LONG_DAY_NAMES.indexOf(value.substring(0, comma));

		if (dayName < 0 || value.length() != comma + 24)
			return Optional.empty();

		int date = comma + 2;
		int month = MONTH_NAMES.indexOf(value.substring(date + 3, date + 6));

		if (month < 0 || value.charAt(comma + 1) != ' ' || value.charAt(date + 2) != '-' || value.charAt(date + 6) != '-'
				|| value.charAt(date + 9) != ' ' || value.charAt(date + 18) != ' ' || !value.startsWith("GMT", date + 19)
				|| !isAllDigits(value, date, date + 2) || !isAllDigits(value, date + 7, date + 9))
			return Optional.empty();

		int time = date + 10;

		if (!isAllDigits(value, time, time + 2) || !isAllDigits(value, time + 3, time + 5)
				|| !isAllDigits(value, time + 6, time + 8))
			return Optional.empty();

		// RFC 9110 section 5.6.7: a timestamp that appears to be more than 50 years in the future means the most recent
		// past year with the same last two digits. So the year is the latest one with those digits whose timestamp is at
		// most 50 years after now, compared to the second, in the century of that limit or the one before. The day name
		// is checked afterwards, against the chosen year.
		int day = Integer.parseInt(value, date, date + 2, 10);
		LocalDateTime latest = LocalDateTime.ofInstant(now, ZoneOffset.UTC).plusYears(50);
		int year = Math.floorDiv(latest.getYear(), 100) * 100 + Integer.parseInt(value, date + 7, date + 9, 10);

		if (isAfter(year, month + 1, day, Integer.parseInt(value, time, time + 2, 10),
				Integer.parseInt(value, time + 3, time + 5, 10), Integer.parseInt(value, time + 6, time + 8, 10), latest))
			year -= 100;

		return dateTime(dayName, year, month, day, value, time);
	}

	/**
	 * Whether the date and time, field by field, come after {@code limit}. The fields need not form a real date (a
	 * 29 February or a leap second is compared as written), so no exception is possible here.
	 */
	private static boolean isAfter(int year,
																 int month,
																 int day,
																 int hour,
																 int minute,
																 int second,
																 @NonNull LocalDateTime limit) {
		int[] fields = {year, month, day, hour, minute, second};
		int[] limits = {limit.getYear(), limit.getMonthValue(), limit.getDayOfMonth(), limit.getHour(), limit.getMinute(),
				limit.getSecond()};

		for (int index = 0; index < fields.length; ++index)
			if (fields[index] != limits[index])
				return fields[index] > limits[index];

		// Equal to the second: not after, although the limit may carry a fraction of a second.
		return false;
	}

	/**
	 * Reads {@code HH:MM:SS} at {@code timeStart} and checks the day name against the date.
	 */
	@NonNull
	private static Optional<Instant> dateTime(int dayNameIndex,
																						int year,
																						int monthIndex,
																						int day,
																						@NonNull String value,
																						int timeStart) {
		if (value.charAt(timeStart + 2) != ':' || value.charAt(timeStart + 5) != ':'
				|| !isAllDigits(value, timeStart, timeStart + 2) || !isAllDigits(value, timeStart + 3, timeStart + 5)
				|| !isAllDigits(value, timeStart + 6, timeStart + 8))
			return Optional.empty();

		int hour = Integer.parseInt(value, timeStart, timeStart + 2, 10);
		int minute = Integer.parseInt(value, timeStart + 3, timeStart + 5, 10);
		int second = Integer.parseInt(value, timeStart + 6, timeStart + 8, 10);

		if (hour > 23 || minute > 59 || second > 60)
			return Optional.empty();

		LocalDate date = LocalDate.of(year, monthIndex + 1, day);

		if (date.getDayOfWeek() != DayOfWeek.of(dayNameIndex + 1))
			return Optional.empty();

		// A leap second (:60) is read as the first second of the next minute.
		int leapSecond = second == 60 ? 1 : 0;
		return Optional.of(date.atTime(hour, minute, second - leapSecond).toInstant(ZoneOffset.UTC)
				.plusSeconds(leapSecond));
	}

	private static boolean isAllDigits(@NonNull String value, int start, int end) {
		if (start >= end)
			return false;

		for (int i = start; i < end; ++i) {
			char c = value.charAt(i);

			if (c < '0' || c > '9')
				return false;
		}

		return true;
	}

	@NonNull
	private static String trimOws(@NonNull String value) {
		int start = 0;
		int end = value.length();

		while (start < end && MediaType.isOws(value.charAt(start)))
			++start;

		while (end > start && MediaType.isOws(value.charAt(end - 1)))
			--end;

		return value.substring(start, end);
	}
}
