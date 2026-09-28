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
import java.time.Duration;
import java.time.Instant;
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
 *   ({@code Sun Nov  6 08:49:37 1994}), as {@link HttpDate} parses them. Names are case-sensitive, the day name must
 *   match the date, and a second of 60 (a leap second) counts as the next second. The delay is the time from
 *   {@code now} to the date, or zero for a date in the past.</li>
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

		String value = HttpDate.trimOws(requireNonNull(fieldValues.get(0)));

		if (value.isEmpty())
			return Optional.empty();

		if (HttpDate.isAllDigits(value, 0, value.length()))
			return delaySeconds(value);

		Optional<Instant> date = HttpDate.parse(value, now);

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
}
