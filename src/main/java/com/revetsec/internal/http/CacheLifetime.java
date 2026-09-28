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
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.net.http.HttpHeaders;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * How long a cache keeps a fetched document, such as a JSON Web Key Set or a metadata document, from the response's
 * headers: a subset of RFC 9111 (sections 1.2.2, 4.2.1, 4.2.3, 5.1, 5.2 and 5.3), clamped to the component's bounds
 * (M2 plan, M2-8).
 * <p>
 * The rules, in order; the first that decides wins:
 * <ol>
 *   <li>{@code Cache-Control} is every field line, each a comma-separated list whose empty elements are ignored
 *   (RFC 9110 section 5.6.1). Each element must be {@code token [ "=" ( token / quoted-string ) ]} (RFC 9111
 *   section 5.2), with OWS allowed only around it, and a directive name is compared as an ASCII case-insensitive
 *   token. An element that does not fit, such as a non-token name ({@code {bad}}), an unterminated quoted string or
 *   text after the argument, makes the field malformed: the minimum.</li>
 *   <li>{@code no-store}, or {@code no-cache} with or without an argument: the minimum. For a document whose content
 *   gates verification, "refresh as soon as the minimum allows" is the safe reading of "do not store" and "do not
 *   reuse without revalidation".</li>
 *   <li>{@code max-age}, in token or quoted-string form: its value must be {@code delta-seconds} ({@code 1*DIGIT}),
 *   and a value above 2<sup>31</sup> counts as 2<sup>31</sup> seconds (section 1.2.2). Every occurrence must have
 *   the same value after that cap. No argument, an empty, signed or fractional value, or two different values: the
 *   minimum (section 4.2.1 allows treating conflicting values as stale). Otherwise that many seconds, an explicit
 *   lifetime. Other directives ({@code s-maxage}, {@code private}, {@code public}, {@code must-revalidate},
 *   {@code immutable}, {@code stale-if-error}, {@code stale-while-revalidate} and unknown ones) are ignored: the
 *   component's own maximum staleness, not the server, bounds stale use.</li>
 *   <li>Otherwise {@code Expires} (section 5.3): exactly one field line holding a valid {@link HttpDate} gives the
 *   explicit lifetime {@code Expires - Date}, or zero if that is negative, where {@code Date} is the one valid
 *   {@code Date} field line, or else {@code receivedAt}. Using the server's own {@code Date} keeps the result
 *   independent of clock skew between the server and this host. A repeated or invalid {@code Expires}, such as
 *   {@code 0}: the minimum.</li>
 *   <li>Otherwise the default.</li>
 *   <li>A valid {@code Age} ({@code delta-seconds}, capped the same way) is subtracted from an explicit lifetime,
 *   never below zero (section 4.2.3). {@code Age} is a singleton field, so, as section 5.1 says, only the first
 *   member of its list counts (its first non-empty element, taking the field lines in order), and an {@code Age}
 *   whose first member is not {@code delta-seconds} is ignored.</li>
 *   <li>The result is clamped to [minimum, maximum], so an explicit lifetime of zero gives the minimum.</li>
 * </ol>
 * {@code Pragma}, {@code ETag} and {@code Last-Modified} are ignored; there are no conditional requests, and a 304
 * never reaches this class, because {@link HttpExchange} refuses every 3xx. The computation is total: no header value
 * makes it throw.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class CacheLifetime {
	/**
	 * The value a larger {@code delta-seconds} counts as: 2<sup>31</sup> (RFC 9111 section 1.2.2).
	 */
	public static final long MAXIMUM_DELTA_SECONDS = 1L << 31;

	private static final String CACHE_CONTROL = "Cache-Control";
	private static final String EXPIRES = "Expires";
	private static final String DATE = "Date";
	private static final String AGE = "Age";
	private static final String NO_STORE = "no-store";
	private static final String NO_CACHE = "no-cache";
	private static final String MAX_AGE = "max-age";

	/**
	 * A {@code Cache-Control} result that decides the minimum, or that there is no {@code max-age}.
	 */
	private static final long MINIMUM = -1;
	private static final long NO_MAX_AGE = -2;

	private CacheLifetime() {
		// Static helpers only.
	}

	/**
	 * Computes how long to keep a response (see the class description).
	 *
	 * @param headers           the response headers
	 * @param receivedAt        when the response was received, from the component's clock
	 * @param minimum           the shortest time to keep it, zero or positive
	 * @param defaultTimeToLive the time to keep it when the headers give no lifetime, at least {@code minimum}
	 * @param maximum           the longest time to keep it, at least {@code defaultTimeToLive}
	 * @return the time to keep the response, from {@code receivedAt}, in [minimum, maximum]
	 * @throws NullPointerException     if an argument is {@code null}
	 * @throws IllegalArgumentException if {@code minimum} is negative, or the bounds are not in order
	 */
	@NonNull
	public static Duration timeToLive(@NonNull HttpHeaders headers,
																		@NonNull Instant receivedAt,
																		@NonNull Duration minimum,
																		@NonNull Duration defaultTimeToLive,
																		@NonNull Duration maximum) {
		requireNonNull(headers);
		requireNonNull(receivedAt);
		requireNonNull(minimum);
		requireNonNull(defaultTimeToLive);
		requireNonNull(maximum);

		if (minimum.isNegative() || minimum.compareTo(defaultTimeToLive) > 0 || defaultTimeToLive.compareTo(maximum) > 0)
			throw new IllegalArgumentException("The bounds must satisfy 0 <= minimum <= default <= maximum.");

		@Nullable Duration explicitLifetime = explicitLifetime(headers, receivedAt);

		if (explicitLifetime == null)
			return defaultTimeToLive;

		if (explicitLifetime.compareTo(minimum) < 0)
			return minimum;

		return explicitLifetime.compareTo(maximum) > 0 ? maximum : explicitLifetime;
	}

	/**
	 * The explicit lifetime after {@code Age} (rules 1 to 4 and 6), {@link Duration#ZERO} for a rule that decides the
	 * minimum, or {@code null} for the default.
	 */
	@Nullable
	private static Duration explicitLifetime(@NonNull HttpHeaders headers,
																					 @NonNull Instant receivedAt) {
		long maxAge = maxAge(headers.allValues(CACHE_CONTROL));

		if (maxAge == MINIMUM)
			return Duration.ZERO;

		Duration lifetime;

		if (maxAge != NO_MAX_AGE) {
			lifetime = Duration.ofSeconds(maxAge);
		} else {
			List<String> expires = headers.allValues(EXPIRES);

			if (expires.isEmpty())
				return null;

			Optional<Instant> expiresAt = HttpDate.parseSingleField(expires, receivedAt);

			if (expiresAt.isEmpty())
				return Duration.ZERO;

			Instant date = HttpDate.parseSingleField(headers.allValues(DATE), receivedAt).orElse(receivedAt);
			lifetime = Duration.between(date, expiresAt.get());
		}

		lifetime = lifetime.minusSeconds(age(headers.allValues(AGE)));
		return lifetime.isNegative() ? Duration.ZERO : lifetime;
	}

	/**
	 * Reads every {@code Cache-Control} field line (rules 1 to 3): the one {@code max-age} value, {@link #MINIMUM}, or
	 * {@link #NO_MAX_AGE}.
	 */
	private static long maxAge(@NonNull List<@NonNull String> fieldValues) {
		long maxAge = NO_MAX_AGE;

		for (String fieldValue : fieldValues) {
			int end = fieldValue.length();
			int index = 0;

			while (true) {
				index = MediaType.owsEnd(fieldValue, index, end);

				if (index >= end)
					break;

				// An empty list element.
				if (fieldValue.charAt(index) == ',') {
					++index;
					continue;
				}

				int nameEnd = MediaType.tokenEnd(fieldValue, index, end);

				if (nameEnd == index)
					return MINIMUM;

				String name = MediaType.asciiLowerCase(fieldValue.substring(index, nameEnd));
				@Nullable String argument = null;
				index = nameEnd;

				if (index < end && fieldValue.charAt(index) == '=') {
					++index;

					if (index < end && fieldValue.charAt(index) == '"') {
						StringBuilder unquoted = new StringBuilder();
						index = MediaType.quotedStringEnd(fieldValue, index, end, unquoted);

						if (index < 0)
							return MINIMUM;

						argument = unquoted.toString();
					} else {
						int argumentEnd = MediaType.tokenEnd(fieldValue, index, end);

						if (argumentEnd == index)
							return MINIMUM;

						argument = fieldValue.substring(index, argumentEnd);
						index = argumentEnd;
					}
				}

				index = MediaType.owsEnd(fieldValue, index, end);

				if (index < end && fieldValue.charAt(index) != ',')
					return MINIMUM;

				if (NO_STORE.equals(name) || NO_CACHE.equals(name))
					return MINIMUM;

				if (MAX_AGE.equals(name)) {
					long value = argument == null ? -1 : deltaSeconds(argument);

					if (value < 0 || (maxAge != NO_MAX_AGE && maxAge != value))
						return MINIMUM;

					maxAge = value;
				}
			}
		}

		return maxAge;
	}

	/**
	 * The {@code Age} in seconds: its first list member if that is {@code delta-seconds}, otherwise zero (rule 6).
	 */
	private static long age(@NonNull List<@NonNull String> fieldValues) {
		for (String fieldValue : fieldValues) {
			int start = 0;

			while (start <= fieldValue.length()) {
				int comma = fieldValue.indexOf(',', start);
				int end = comma < 0 ? fieldValue.length() : comma;
				String member = HttpDate.trimOws(fieldValue.substring(start, end));

				// Empty list elements are not members (RFC 9110 section 5.6.1).
				if (!member.isEmpty())
					return Math.max(0, deltaSeconds(member));

				start = end + 1;
			}
		}

		return 0;
	}

	/**
	 * {@code delta-seconds} ({@code 1*DIGIT}), capped at {@link #MAXIMUM_DELTA_SECONDS}, or -1 if the value is not
	 * one.
	 */
	private static long deltaSeconds(@NonNull String value) {
		if (!HttpDate.isAllDigits(value, 0, value.length()))
			return -1;

		long seconds = 0;

		for (int i = 0; i < value.length() && seconds < MAXIMUM_DELTA_SECONDS; ++i)
			seconds = seconds * 10 + (value.charAt(i) - '0');

		return Math.min(seconds, MAXIMUM_DELTA_SECONDS);
	}
}
