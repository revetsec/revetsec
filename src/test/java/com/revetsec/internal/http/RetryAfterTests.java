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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.net.http.HttpHeaders;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * {@code Retry-After} (RFC 9110 section 10.2.3): {@code delay-seconds} and the three {@code HTTP-date} formats a
 * recipient must accept (section 5.6.7, read 2026-09-28), read as a delay from the component's clock; anything else is
 * dropped.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class RetryAfterTests {
	private static final Instant NOW = Instant.parse("2026-09-24T12:00:00Z");

	// RFC 9110 section 10.2.3: delay-seconds = 1*DIGIT, leading zeros allowed; values past Integer.MAX_VALUE seconds
	// are dropped rather than overflowing.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> readsDelaySeconds() {
		Map<String, Optional<Duration>> cases = new LinkedHashMap<>();
		cases.put("0", Optional.of(Duration.ZERO));
		cases.put("90", Optional.of(Duration.ofSeconds(90)));
		cases.put("007", Optional.of(Duration.ofSeconds(7)));
		cases.put(" 30\t", Optional.of(Duration.ofSeconds(30)));
		cases.put("0000000000000000000000090", Optional.of(Duration.ofSeconds(90)));
		cases.put("2147483647", Optional.of(Duration.ofSeconds(Integer.MAX_VALUE)));
		cases.put("2147483648", Optional.empty());
		cases.put("9999999999", Optional.empty());
		cases.put("99999999999999999999999", Optional.empty());
		return cases.entrySet().stream().map(entry -> DynamicTest.dynamicTest("\"" + entry.getKey() + "\"",
				() -> Assertions.assertEquals(entry.getValue(), RetryAfter.parse(List.of(entry.getKey()), NOW))));
	}

	// RFC 9110 section 5.6.7: IMF-fixdate, the obsolete RFC 850 form and asctime all name the same instant; the delay
	// runs from now, and a date in the past is no delay.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> readsTheThreeHttpDateFormats() {
		Instant example = Instant.parse("1994-11-06T08:49:37Z");
		Instant justBefore = example.minusSeconds(37);
		Map<String, Duration> cases = new LinkedHashMap<>();
		cases.put("Sun, 06 Nov 1994 08:49:37 GMT", Duration.ofSeconds(37));
		cases.put("Sunday, 06-Nov-94 08:49:37 GMT", Duration.ofSeconds(37));
		cases.put("Sun Nov  6 08:49:37 1994", Duration.ofSeconds(37));
		cases.put("Sun Nov 06 08:49:37 1994", Duration.ofSeconds(37));
		cases.put("  Sun, 06 Nov 1994 08:49:37 GMT ", Duration.ofSeconds(37));
		return cases.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () -> {
			// RFC 850's two-digit year reads as 1994 only when "now" is close enough (the 50-year rule).
			Assertions.assertEquals(Optional.of(entry.getValue()), RetryAfter.parse(List.of(entry.getKey()), justBefore));
			Assertions.assertEquals(Optional.of(Duration.ZERO), RetryAfter.parse(List.of(entry.getKey()),
					example.plusSeconds(1)));
		}));
	}

	// RFC 9110 section 5.6.7: a timestamp that appears to be more than 50 years in the future means the most recent past
	// year with those two digits. So the year is the latest one whose timestamp is at most 50 years after now, to the
	// second, and the day name must then match it. From 2026-09-24T12:00Z, "70" is 2070 (a Wednesday on 1 January);
	// 31-Dec-76 would be 50 years and 3 months ahead, so it is 1976, a Friday.
	@Test
	void readsATwoDigitYearWithTheFiftyYearRule() {
		Assertions.assertEquals(Optional.of(Duration.between(NOW, Instant.parse("2070-01-01T00:00:00Z"))),
				RetryAfter.parse(List.of("Wednesday, 01-Jan-70 00:00:00 GMT"), NOW));
		Assertions.assertEquals(Optional.empty(), RetryAfter.parse(List.of("Thursday, 31-Dec-76 00:00:00 GMT"), NOW));
		Assertions.assertEquals(Optional.of(Duration.ZERO),
				RetryAfter.parse(List.of("Friday, 31-Dec-76 00:00:00 GMT"), NOW));
		Assertions.assertEquals(Optional.of(Duration.ZERO),
				RetryAfter.parse(List.of("Saturday, 01-Jan-77 00:00:00 GMT"), NOW));
		Assertions.assertEquals(Optional.empty(), RetryAfter.parse(List.of("Friday, 01-Jan-77 00:00:00 GMT"), NOW));
	}

	// RFC 9110 section 5.6.7: the 50 years are compared to the second. Exactly 50 years ahead is still ahead (2076, a
	// Thursday); one second more is the past (1976, a Friday).
	@Test
	void comparesTheFiftyYearsToTheSecond() {
		Assertions.assertEquals(Optional.of(Duration.between(NOW, Instant.parse("2076-09-24T12:00:00Z"))),
				RetryAfter.parse(List.of("Thursday, 24-Sep-76 12:00:00 GMT"), NOW));
		Assertions.assertEquals(Optional.empty(), RetryAfter.parse(List.of("Thursday, 24-Sep-76 12:00:01 GMT"), NOW));
		Assertions.assertEquals(Optional.of(Duration.ZERO),
				RetryAfter.parse(List.of("Friday, 24-Sep-76 12:00:01 GMT"), NOW));
	}

	// RFC 9110 section 5.6.7: the window moves with now, into the next century too. In mid-2080, "10" is 2110 (a
	// Wednesday), not 2010 (a Friday); half an hour before 2100, "00" is 2100 (a Friday), not 2000 (a Saturday).
	@Test
	void readsATwoDigitYearInTheNextCenturyWhenNowIsLateInItsOwn() {
		Instant mid2080 = Instant.parse("2080-06-01T00:00:00Z");
		Assertions.assertEquals(Optional.of(Duration.between(mid2080, Instant.parse("2110-01-01T00:00:00Z"))),
				RetryAfter.parse(List.of("Wednesday, 01-Jan-10 00:00:00 GMT"), mid2080));
		Assertions.assertEquals(Optional.empty(), RetryAfter.parse(List.of("Friday, 01-Jan-10 00:00:00 GMT"), mid2080));

		Instant endOf2099 = Instant.parse("2099-12-31T23:30:00Z");
		Assertions.assertEquals(Optional.of(Duration.ofHours(1)),
				RetryAfter.parse(List.of("Friday, 01-Jan-00 00:30:00 GMT"), endOf2099));
		Assertions.assertEquals(Optional.empty(), RetryAfter.parse(List.of("Saturday, 01-Jan-00 00:30:00 GMT"),
				endOf2099));
	}

	// RFC 9110 section 5.6.7: a leap second (:60) is the first second of the next minute.
	@Test
	void readsALeapSecondAsTheNextSecond() {
		Instant before = Instant.parse("2025-12-31T23:59:00Z");
		Assertions.assertEquals(Optional.of(Duration.ofSeconds(60)),
				RetryAfter.parse(List.of("Wed, 31 Dec 2025 23:59:60 GMT"), before));
	}

	// RFC 9110 sections 5.6.7 and 10.2.3: anything else is dropped, never guessed: signs, fractions, units, other
	// digits, lower-case or unknown names, a day name that does not match the date, impossible dates and times, other
	// zones, and misplaced spaces.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> dropsEverythingElse() {
		return Stream.of("", " ", "-1", "+1", "1.5", "1e3", "120s", "1 20", "0x10", "\u0661\u0662\u0660", "soon",
						"sun, 06 Nov 1994 08:49:37 GMT", "Sun, 06 nov 1994 08:49:37 GMT", "Sun, 06 Nov 1994 08:49:37 gmt",
						"Sun, 06 Nov 1994 08:49:37 UTC", "Mon, 06 Nov 1994 08:49:37 GMT", "Sun, 6 Nov 1994 08:49:37 GMT",
						"Sun,  06 Nov 1994 08:49:37 GMT", "Sun, 06 Nov 94 08:49:37 GMT", "Sun, 06 Nov 1994 8:49:37 GMT",
						"Sun, 06 Nov 1994 24:00:00 GMT", "Sun, 06 Nov 1994 08:60:00 GMT", "Sun, 06 Nov 1994 08:49:61 GMT",
						"Sat, 31 Feb 2026 00:00:00 GMT", "Sun, 06 Nov 1994 08:49:37 GMT+1", "Sun, 06 Nov 1994 08:49:37",
						"Sunday, 06-Nov-1994 08:49:37 GMT", "Sun, 06-Nov-94 08:49:37 GMT", "Sunday, 06 Nov 94 08:49:37 GMT",
						"Sunday,06-Nov-94 08:49:37 GMT", "Sun Nov 6 08:49:37 1994", "Sun Nov  6 08:49:37 94",
						"Sun  Nov 6 08:49:37 1994", "Mon Nov  6 08:49:37 1994", "Sun Nov  6 08:49:37 1994 GMT",
						"Sun, 06 Nov 1994 08:49:37 GMT, Sun, 06 Nov 1994 08:49:37 GMT", "Sun, 06 Nov 1994\u000008:49:37 GMT")
				.map(value -> DynamicTest.dynamicTest("\"" + value.replace("\u0000", "\\u0000") + "\"",
						() -> Assertions.assertEquals(Optional.empty(), RetryAfter.parse(List.of(value), NOW))));
	}

	// RFC 9110 section 10.2.3 defines one value: a repeated or absent field is no hint.
	@Test
	void dropsARepeatedOrAbsentField() {
		Assertions.assertEquals(Optional.empty(), RetryAfter.parse(List.of("1", "2"), NOW));
		Assertions.assertEquals(Optional.empty(), RetryAfter.parse(List.of("1", "1"), NOW));
		Assertions.assertEquals(Optional.empty(), RetryAfter.parse(List.of(), NOW));
	}

	// The HttpHeaders form reads the field case-insensitively, as the JDK stores it.
	@Test
	void readsTheFieldFromResponseHeaders() {
		HttpHeaders headers = HttpHeaders.of(Map.of("retry-after", List.of("45")), (name, value) -> true);
		HttpHeaders none = HttpHeaders.of(Map.of(), (name, value) -> true);

		Assertions.assertEquals(Optional.of(Duration.ofSeconds(45)), RetryAfter.parse(headers, NOW));
		Assertions.assertEquals(Optional.empty(), RetryAfter.parse(none, NOW));
		Assertions.assertThrows(NullPointerException.class, () -> RetryAfter.parse(headers, nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> RetryAfter.parse(nullHeaders(), NOW));
	}

	@SuppressWarnings("NullAway")
	private static @NonNull HttpHeaders nullHeaders() {
		return nullValue();
	}

	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> @NonNull T nullValue() {
		@Nullable T value = null;
		return value;
	}
}
