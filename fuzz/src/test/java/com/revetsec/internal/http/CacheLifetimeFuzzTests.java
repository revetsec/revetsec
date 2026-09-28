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

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.revetsec.internal.Limits;
import org.junit.jupiter.api.Assertions;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import java.math.BigInteger;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.DayOfWeek;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Coverage-guided checks for {@link CacheLifetime}, the RFC 9111 subset that sets a JSON Web Key Set's time to live
 * (M2 plan, M2-8 "TTL"; exit criterion 15), and for {@link HttpDate}, which it reads {@code Expires} and {@code Date}
 * with.
 * <p>
 * The input is a block of header field lines, {@code name: value}, one per line, read as ISO-8859-1 (every byte one
 * character, as the JDK client reads a response head) and again as UTF-8, which reaches characters above U+00FF. The
 * lines become a {@link HttpHeaders} through {@link HttpHeaders#of}, which trims names and values the way the JDK
 * client's own headers are trimmed, and which keeps an empty value as an empty value. The oracle then reads the same
 * {@link HttpHeaders}, so both sides see exactly the values a response would deliver.
 * <p>
 * The oracle is written here from RFC 9110 (sections 5.6.1 to 5.6.4 and 5.6.7) and RFC 9111 (sections 1.2.2, 4.2.1,
 * 4.2.3, 5.1, 5.2 and 5.3) as {@link CacheLifetime} documents its subset: a list splitter that honors quoted strings,
 * one regular expression per {@code cache-directive}, a regular expression per {@code HTTP-date} form, and the
 * two-digit-year rule stated as a search over candidate years. It never calls the code under test to decide what that
 * code should do.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public class CacheLifetimeFuzzTests {
	private static final String TCHAR = "[!#$%&'*+.^_`|~0-9A-Za-z-]";
	private static final String QDTEXT = "[\\t \\x21\\x23-\\x5B\\x5D-\\x7E\\x80-\\xFF]";
	private static final String QUOTED_PAIR = "\\\\[\\t \\x21-\\x7E\\x80-\\xFF]";

	/**
	 * RFC 9111 section 5.2: {@code cache-directive = token [ "=" ( token / quoted-string ) ]}, with no whitespace
	 * around the {@code =}.
	 */
	private static final Pattern CACHE_DIRECTIVE = Pattern.compile("(" + TCHAR + "+)(?:=(?:(" + TCHAR + "+)|\"((?:"
			+ QDTEXT + "|" + QUOTED_PAIR + ")*)\"))?");
	private static final Pattern DELTA_SECONDS = Pattern.compile("[0-9]+");
	private static final BigInteger DELTA_SECONDS_CAP = BigInteger.TWO.pow(31);

	private static final String DAY = "(Mon|Tue|Wed|Thu|Fri|Sat|Sun)";
	private static final String LONG_DAY = "(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)";
	private static final String MONTH = "(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)";
	private static final String TIME = "([0-9]{2}):([0-9]{2}):([0-9]{2})";
	private static final Pattern IMF_FIXDATE = Pattern.compile(DAY + ", ([0-9]{2}) " + MONTH + " ([0-9]{4}) " + TIME
			+ " GMT");
	private static final Pattern RFC_850_DATE = Pattern.compile(LONG_DAY + ", ([0-9]{2})-" + MONTH + "-([0-9]{2}) "
			+ TIME + " GMT");
	private static final Pattern ASCTIME_DATE = Pattern.compile(DAY + " " + MONTH + " ([0-9]{2}| [0-9]) " + TIME
			+ " ([0-9]{4})");
	private static final List<String> DAYS = List.of("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun");
	private static final List<String> LONG_DAYS = List.of("Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
			"Saturday", "Sunday");
	private static final List<String> MONTHS = List.of("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
			"Oct", "Nov", "Dec");

	/**
	 * When the response was received. The second one has a fraction, and the third puts RFC 850's 50-year window in the
	 * next century.
	 */
	private static final List<Instant> RECEIVED_AT = List.of(Instant.parse("2026-09-27T12:00:00Z"),
			Instant.parse("1999-12-31T23:59:59.500Z"), Instant.parse("2075-06-15T08:30:00Z"));

	/**
	 * The JWKS rows' defaults; a range whose maximum lies above the 2<sup>31</sup>-second cap, so that an explicit
	 * lifetime is seen unclamped; and a range of one point.
	 */
	private static final List<Bounds> BOUNDS = List.of(
			new Bounds(Limits.JWKS_MINIMUM_TIME_TO_LIVE.getDefaultDuration(),
					Limits.JWKS_DEFAULT_TIME_TO_LIVE.getDefaultDuration(), Limits.JWKS_MAXIMUM_TIME_TO_LIVE.getDefaultDuration()),
			new Bounds(Duration.ZERO, Duration.ofSeconds(5), Duration.ofSeconds((1L << 31) + 3_600)),
			new Bounds(Duration.ofSeconds(7), Duration.ofSeconds(7), Duration.ofSeconds(7)));

	/**
	 * {@link CacheLifetime#timeToLive} is total, stays within its bounds (or is the default), and equals the oracle's
	 * lifetime for every header block, receipt time and bounds (RFC 9111 subset, M2-8). {@link HttpDate#parse} agrees
	 * with the oracle's {@code HTTP-date} reading (RFC 9110 section 5.6.7) for every field value, and
	 * {@link HttpDate#parseSingleField} gives a date only for a field with exactly one line.
	 *
	 * @param input the fuzzed header block: {@code name: value} lines separated by LF
	 */
	@FuzzTest(maxDuration = "5m")
	public void timeToLiveIsTotalClampedAndAgreesWithAnRfc9111Oracle(byte[] input) {
		requireAgreement(headersOf(new String(input, StandardCharsets.ISO_8859_1)));
		requireAgreement(headersOf(new String(input, StandardCharsets.UTF_8)));
	}

	private static void requireAgreement(HttpHeaders headers) {
		for (Instant receivedAt : RECEIVED_AT) {
			for (List<String> values : headers.map().values()) {
				for (String value : values)
					Assertions.assertEquals(expectedDate(value, receivedAt), HttpDate.parse(value, receivedAt),
							"HttpDate.parse disagrees with the oracle");

				Assertions.assertEquals(values.size() == 1 ? expectedDate(values.get(0), receivedAt) : Optional.empty(),
						HttpDate.parseSingleField(values, receivedAt), "HttpDate.parseSingleField disagrees with the oracle");
			}

			Optional<Duration> explicit = explicitLifetime(headers, receivedAt);

			for (Bounds bounds : BOUNDS) {
				Duration actual = CacheLifetime.timeToLive(headers, receivedAt, bounds.minimum, bounds.defaultTimeToLive,
						bounds.maximum);
				Duration expected = explicit.map(bounds::clamp).orElse(bounds.defaultTimeToLive);

				Assertions.assertEquals(expected, actual, "the time to live disagrees with the RFC 9111 oracle");
				Assertions.assertTrue(actual.compareTo(bounds.minimum) >= 0 && actual.compareTo(bounds.maximum) <= 0,
						"the time to live is outside its bounds");
			}
		}
	}

	/**
	 * The header block as the JDK client would deliver it: each line split at its first colon, names and values
	 * trimmed by {@link HttpHeaders#of}, and lines of one name (compared case-insensitively) kept in order.
	 */
	private static HttpHeaders headersOf(String text) {
		Map<String, List<String>> fields = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

		for (String line : text.split("\n", -1)) {
			int colon = line.indexOf(':');

			if (colon < 0)
				continue;

			// HttpHeaders.of trims names too, so two names that differ only by surrounding whitespace are one field.
			String name = line.substring(0, colon).trim();

			if (name.isEmpty())
				continue;

			fields.computeIfAbsent(name, key -> new ArrayList<>()).add(line.substring(colon + 1));
		}

		return HttpHeaders.of(fields, (name, value) -> true);
	}

	/**
	 * The explicit lifetime after {@code Age}, {@link Duration#ZERO} for every case the subset sends to the minimum, or
	 * empty for the default.
	 */
	private static Optional<Duration> explicitLifetime(HttpHeaders headers, Instant receivedAt) {
		CacheControl cacheControl = cacheControl(headers.allValues("Cache-Control"));

		if (cacheControl.minimum)
			return Optional.of(Duration.ZERO);

		Duration lifetime;

		if (cacheControl.maxAge != null) {
			lifetime = Duration.ofSeconds(cacheControl.maxAge);
		} else {
			List<String> expires = headers.allValues("Expires");

			if (expires.isEmpty())
				return Optional.empty();

			Optional<Instant> expiresAt = expires.size() == 1 ? expectedDate(expires.get(0), receivedAt) : Optional.empty();

			if (expiresAt.isEmpty())
				return Optional.of(Duration.ZERO);

			List<String> dates = headers.allValues("Date");
			Instant date = (dates.size() == 1 ? expectedDate(dates.get(0), receivedAt) : Optional.<Instant>empty())
					.orElse(receivedAt);
			lifetime = Duration.between(date, expiresAt.get());

			if (lifetime.isNegative())
				lifetime = Duration.ZERO;
		}

		lifetime = lifetime.minusSeconds(age(headers.allValues("Age")));
		return Optional.of(lifetime.isNegative() ? Duration.ZERO : lifetime);
	}

	/**
	 * RFC 9111 section 5.2 over every {@code Cache-Control} line: any element that is not a {@code cache-directive},
	 * {@code no-store} or {@code no-cache}, a {@code max-age} whose argument is not {@code delta-seconds}, or two
	 * different {@code max-age} values (after the 2<sup>31</sup> cap) decide the minimum.
	 */
	private static CacheControl cacheControl(List<String> lines) {
		Set<Long> maxAges = new HashSet<>();
		boolean minimum = false;

		for (String line : lines) {
			for (String element : listElements(line)) {
				String trimmed = trimOws(element);

				// RFC 9110 section 5.6.1: empty list elements are ignored.
				if (trimmed.isEmpty())
					continue;

				Matcher directive = CACHE_DIRECTIVE.matcher(trimmed);

				if (!directive.matches())
					return new CacheControl(true, null);

				String name = asciiLowerCase(directive.group(1));
				String argument = directive.group(2) != null ? directive.group(2)
						: directive.group(3) != null ? unquote(directive.group(3)) : null;

				if (name.equals("no-store") || name.equals("no-cache"))
					minimum = true;

				if (name.equals("max-age")) {
					Long seconds = argument == null ? null : deltaSeconds(argument);

					if (seconds == null)
						minimum = true;
					else
						maxAges.add(seconds);
				}
			}
		}

		if (minimum || maxAges.size() > 1)
			return new CacheControl(true, null);

		return new CacheControl(false, maxAges.isEmpty() ? null : maxAges.iterator().next());
	}

	/**
	 * Splits a field line at the commas outside quoted strings (RFC 9110 sections 5.6.1 and 5.6.4).
	 */
	private static List<String> listElements(String line) {
		List<String> elements = new ArrayList<>();
		StringBuilder current = new StringBuilder();
		boolean quoted = false;

		for (int index = 0; index < line.length(); ++index) {
			char c = line.charAt(index);

			if (quoted) {
				current.append(c);

				if (c == '\\' && index + 1 < line.length())
					current.append(line.charAt(++index));
				else if (c == '"')
					quoted = false;
			} else if (c == ',') {
				elements.add(current.toString());
				current.setLength(0);
			} else {
				current.append(c);
				quoted = c == '"';
			}
		}

		elements.add(current.toString());
		return elements;
	}

	/**
	 * RFC 9110 section 5.6.4: the text of a quoted string, each quoted-pair replaced by its second character.
	 */
	private static String unquote(String quoted) {
		StringBuilder text = new StringBuilder();

		for (int index = 0; index < quoted.length(); ++index) {
			char c = quoted.charAt(index);
			text.append(c == '\\' ? quoted.charAt(++index) : c);
		}

		return text.toString();
	}

	/**
	 * RFC 9111 sections 5.1 and 4.2.3: the first member of the {@code Age} list, over its lines in order, in seconds;
	 * 0 when it is not {@code delta-seconds} or there is none.
	 */
	private static long age(List<String> lines) {
		for (String line : lines)
			for (String member : line.split(",", -1)) {
				String trimmed = trimOws(member);

				if (!trimmed.isEmpty()) {
					Long seconds = deltaSeconds(trimmed);
					return seconds == null ? 0 : seconds;
				}
			}

		return 0;
	}

	/**
	 * RFC 9111 section 1.2.2: {@code 1*DIGIT}, where a value above 2<sup>31</sup> counts as 2<sup>31</sup>.
	 */
	private static Long deltaSeconds(String value) {
		if (!DELTA_SECONDS.matcher(value).matches())
			return null;

		return new BigInteger(value).min(DELTA_SECONDS_CAP).longValueExact();
	}

	/**
	 * RFC 9110 section 5.6.7 (read 2026-09-28): the three forms a recipient must accept, case-sensitive, with the day
	 * name checked against the date, only {@code GMT}, hours to 23, minutes to 59, and a leap second read as the first
	 * second of the next minute. An RFC 850 date's year is the latest year ending in its two digits whose timestamp is no
	 * more than 50 years after {@code now}, compared to the second.
	 */
	private static Optional<Instant> expectedDate(String value, Instant now) {
		String date = trimOws(value);
		Matcher imf = IMF_FIXDATE.matcher(date);

		if (imf.matches())
			return instant(DAYS.indexOf(imf.group(1)), Integer.parseInt(imf.group(4)), MONTHS.indexOf(imf.group(3)) + 1,
					Integer.parseInt(imf.group(2)), imf.group(5), imf.group(6), imf.group(7));

		Matcher asctime = ASCTIME_DATE.matcher(date);

		if (asctime.matches())
			return instant(DAYS.indexOf(asctime.group(1)), Integer.parseInt(asctime.group(7)),
					MONTHS.indexOf(asctime.group(2)) + 1, Integer.parseInt(asctime.group(3).trim()), asctime.group(4),
					asctime.group(5), asctime.group(6));

		Matcher rfc850 = RFC_850_DATE.matcher(date);

		if (!rfc850.matches())
			return Optional.empty();

		int month = MONTHS.indexOf(rfc850.group(3)) + 1;
		int day = Integer.parseInt(rfc850.group(2));
		int[] fields = {0, month, day, Integer.parseInt(rfc850.group(5)), Integer.parseInt(rfc850.group(6)),
				Integer.parseInt(rfc850.group(7))};
		LocalDateTime limit = LocalDateTime.ofInstant(now, ZoneOffset.UTC).plusYears(50);
		int[] limits = {limit.getYear(), limit.getMonthValue(), limit.getDayOfMonth(), limit.getHour(), limit.getMinute(),
				limit.getSecond()};
		int twoDigits = Integer.parseInt(rfc850.group(4));

		// The candidates end in those two digits; searching down from the limit's year, the first one whose timestamp is
		// not after the limit, field by field, is the latest. Two centuries always hold it.
		for (int year = limit.getYear(); ; --year) {
			if (Math.floorMod(year, 100) != twoDigits)
				continue;

			fields[0] = year;

			if (!isAfter(fields, limits))
				return instant(LONG_DAYS.indexOf(rfc850.group(1)), year, month, day, rfc850.group(5), rfc850.group(6),
						rfc850.group(7));
		}
	}

	private static boolean isAfter(int[] fields, int[] limits) {
		for (int index = 0; index < fields.length; ++index)
			if (fields[index] != limits[index])
				return fields[index] > limits[index];

		return false;
	}

	private static Optional<Instant> instant(int dayName, int year, int month, int day, String hour, String minute,
																					 String second) {
		int hours = Integer.parseInt(hour);
		int minutes = Integer.parseInt(minute);
		int seconds = Integer.parseInt(second);

		if (hours > 23 || minutes > 59 || seconds > 60)
			return Optional.empty();

		LocalDate date;

		try {
			date = LocalDate.of(year, month, day);
		} catch (DateTimeException e) {
			return Optional.empty();
		}

		if (date.getDayOfWeek() != DayOfWeek.of(dayName + 1))
			return Optional.empty();

		return Optional.of(LocalDateTime.of(date, LocalTime.of(hours, minutes)).plusSeconds(seconds)
				.toInstant(ZoneOffset.UTC));
	}

	/**
	 * RFC 9110 section 5.6.3: OWS is spaces and horizontal tabs only.
	 */
	private static String trimOws(String value) {
		int start = 0;
		int end = value.length();

		while (start < end && (value.charAt(start) == ' ' || value.charAt(start) == '\t'))
			++start;

		while (end > start && (value.charAt(end - 1) == ' ' || value.charAt(end - 1) == '\t'))
			--end;

		return value.substring(start, end);
	}

	/**
	 * Folds {@code A-Z} only: a directive name is a token, so nothing else can fold into one (RFC 9111 section 5.2).
	 */
	private static String asciiLowerCase(String value) {
		StringBuilder folded = new StringBuilder(value.length());

		for (int index = 0; index < value.length(); ++index) {
			char c = value.charAt(index);
			folded.append(c >= 'A' && c <= 'Z' ? (char) (c + ('a' - 'A')) : c);
		}

		return folded.toString();
	}

	/**
	 * What the {@code Cache-Control} lines decide: the minimum, or the one {@code max-age} value (or none).
	 */
	@Immutable
	private static final class CacheControl {
		private final boolean minimum;
		private final Long maxAge;

		private CacheControl(boolean minimum, Long maxAge) {
			this.minimum = minimum;
			this.maxAge = maxAge;
		}
	}

	/**
	 * One set of bounds for the time to live.
	 */
	@Immutable
	private static final class Bounds {
		private final Duration minimum;
		private final Duration defaultTimeToLive;
		private final Duration maximum;

		private Bounds(Duration minimum, Duration defaultTimeToLive, Duration maximum) {
			this.minimum = minimum;
			this.defaultTimeToLive = defaultTimeToLive;
			this.maximum = maximum;
		}

		private Duration clamp(Duration lifetime) {
			if (lifetime.compareTo(this.minimum) < 0)
				return this.minimum;

			return lifetime.compareTo(this.maximum) > 0 ? this.maximum : lifetime;
		}
	}
}
