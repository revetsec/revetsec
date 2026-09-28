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

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.stream.Stream;

/**
 * {@link HttpDate}: the three {@code HTTP-date} forms a recipient must accept (RFC 9110 section 5.6.7, read from
 * rfc-editor.org on 2026-09-28: IMF-fixdate and the obsolete RFC 850 and asctime forms, case-sensitive, with a leap
 * second allowed and the two-digit year's 50-year rule), which {@link RetryAfter} and {@link CacheLifetime} share (M2
 * plan, G8-11). The forms are checked against an independent formatter over {@code java.time}, and every other text is
 * not a date. RFC 9111 section 4.2 asks a cache recipient to match dates case-insensitively; {@link CacheLifetime} does
 * not, so a date in another case is not a date there either.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class HttpDateTests {
	private static final Instant NOW = Instant.parse("2026-09-27T12:00:00Z");
	private static final List<String> DAY_NAMES = List.of("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun");
	private static final List<String> LONG_DAY_NAMES = List.of("Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
			"Saturday", "Sunday");
	private static final List<String> MONTH_NAMES = List.of("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
			"Sep", "Oct", "Nov", "Dec");

	// RFC 9110 section 5.6.7: its own example in each of the three forms names 1994-11-06T08:49:37Z; asctime pads a
	// one-digit day with a space, and a zero is read too.
	@TestFactory
	Stream<DynamicTest> readsTheThreeFormsOfTheRfcExample() {
		Instant example = Instant.parse("1994-11-06T08:49:37Z");
		return Stream.of("Sun, 06 Nov 1994 08:49:37 GMT", "Sunday, 06-Nov-94 08:49:37 GMT", "Sun Nov  6 08:49:37 1994",
						"Sun Nov 06 08:49:37 1994")
				.map(value -> DynamicTest.dynamicTest(value,
						() -> Assertions.assertEquals(Optional.of(example), HttpDate.parse(value, example))));
	}

	// RFC 9110 section 5.6.3: leading and trailing OWS (spaces and horizontal tabs) are not part of the value; other
	// whitespace is.
	@TestFactory
	Stream<DynamicTest> ignoresLeadingAndTrailingOwsOnly() {
		Instant example = Instant.parse("1994-11-06T08:49:37Z");
		Map<String, Optional<Instant>> cases = new LinkedHashMap<>();
		cases.put("  Sun, 06 Nov 1994 08:49:37 GMT ", Optional.of(example));
		cases.put("\tSun, 06 Nov 1994 08:49:37 GMT\t", Optional.of(example));
		cases.put(" \tSunday, 06-Nov-94 08:49:37 GMT \t", Optional.of(example));
		cases.put("\tSun Nov  6 08:49:37 1994 ", Optional.of(example));
		cases.put("\nSun, 06 Nov 1994 08:49:37 GMT", Optional.empty());
		cases.put("Sun, 06 Nov 1994 08:49:37 GMT\r", Optional.empty());
		cases.put("\u00a0Sun, 06 Nov 1994 08:49:37 GMT", Optional.empty());
		return cases.entrySet().stream().map(entry -> DynamicTest.dynamicTest(escaped(entry.getKey()),
				() -> Assertions.assertEquals(entry.getValue(), HttpDate.parse(entry.getKey(), NOW))));
	}

	// RFC 9110 section 5.6.7: every day in 1901 to 2099 reads back in IMF-fixdate and asctime, whose four-digit years
	// do not depend on now, with the day name java.time gives the date; RFC 850 is checked separately below.
	@Test
	void readsEveryDayOfTwoCenturiesInTheFourDigitYearForms() {
		Random random = new Random(0x5EED_6001L);
		for (LocalDateTime day = LocalDateTime.of(1901, 1, 1, 0, 0); day.getYear() < 2100; day = day.plusDays(1)) {
			LocalDateTime dateTime = day.withHour(random.nextInt(24)).withMinute(random.nextInt(60))
					.withSecond(random.nextInt(60));
			Instant expected = dateTime.toInstant(ZoneOffset.UTC);

			Assertions.assertEquals(Optional.of(expected), HttpDate.parse(imfFixdate(dateTime), NOW), dateTime::toString);
			Assertions.assertEquals(Optional.of(expected), HttpDate.parse(asctime(dateTime), NOW), dateTime::toString);
			Assertions.assertEquals(Optional.of(expected), HttpDate.parse(imfFixdate(dateTime), Instant.EPOCH),
					dateTime::toString);
		}
	}

	// RFC 9110 section 5.6.7: in RFC 850 form, the two-digit year is the latest year with those digits whose timestamp
	// is at most 50 years after now. Every day from 49 years back to 50 years ahead of now reads back exactly.
	@Test
	void readsEveryDayOfTheRfc850WindowAroundNow() {
		LocalDateTime now = LocalDateTime.ofInstant(NOW, ZoneOffset.UTC);
		for (LocalDateTime day = now.minusYears(49); !day.isAfter(now.plusYears(50)); day = day.plusDays(1)) {
			Instant expected = day.toInstant(ZoneOffset.UTC);
			Assertions.assertEquals(Optional.of(expected), HttpDate.parse(rfc850(day), NOW), day::toString);
		}
	}

	// RFC 9110 section 5.6.7: the 50 years are compared to the second. From 2026-09-27T12:00Z, exactly 50 years ahead is
	// still ahead (2076-09-27, a Sunday); one second more is the past (1976-09-27, a Monday), and the day name must then
	// match 1976.
	@Test
	void comparesTheRfc850WindowToTheSecond() {
		Assertions.assertEquals(Optional.of(Instant.parse("2076-09-27T12:00:00Z")),
				HttpDate.parse("Sunday, 27-Sep-76 12:00:00 GMT", NOW));
		Assertions.assertEquals(Optional.empty(), HttpDate.parse("Sunday, 27-Sep-76 12:00:01 GMT", NOW));
		Assertions.assertEquals(Optional.of(Instant.parse("1976-09-27T12:00:01Z")),
				HttpDate.parse("Monday, 27-Sep-76 12:00:01 GMT", NOW));
	}

	// RFC 9110 section 5.6.7: the RFC 850 window moves with now into the next century. Half an hour before 2100, "00" is
	// 2100 (a Friday), not 2000 (a Saturday).
	@Test
	void readsAnRfc850YearInTheNextCenturyWhenNowIsLateInItsOwn() {
		Instant endOf2099 = Instant.parse("2099-12-31T23:30:00Z");
		Assertions.assertEquals(Optional.of(Instant.parse("2100-01-01T00:30:00Z")),
				HttpDate.parse("Friday, 01-Jan-00 00:30:00 GMT", endOf2099));
		Assertions.assertEquals(Optional.empty(), HttpDate.parse("Saturday, 01-Jan-00 00:30:00 GMT", endOf2099));
	}

	// RFC 9110 section 5.6.7 allows a leap second (:60), read as the first second of the next minute, in every form.
	@TestFactory
	Stream<DynamicTest> readsALeapSecondAsTheNextSecond() {
		Instant next = Instant.parse("2026-01-01T00:00:00Z");
		return Stream.of("Wed, 31 Dec 2025 23:59:60 GMT", "Wednesday, 31-Dec-25 23:59:60 GMT",
						"Wed Dec 31 23:59:60 2025")
				.map(value -> DynamicTest.dynamicTest(value,
						() -> Assertions.assertEquals(Optional.of(next), HttpDate.parse(value, NOW))));
	}

	// RFC 9110 section 5.6.7: anything else is not a date, never a guess: lower-case or unknown names, a day name that
	// does not match the date, impossible dates and times, other zones, misplaced or doubled spaces, other digits,
	// delay-seconds, and two dates.
	@TestFactory
	Stream<DynamicTest> readsNothingElseAsADate() {
		return Stream.of("", " ", "0", "3600", "-1", "soon", "\u0661\u0669\u0669\u0664",
						"sun, 06 Nov 1994 08:49:37 GMT", "SUN, 06 Nov 1994 08:49:37 GMT", "Sun, 06 nov 1994 08:49:37 GMT",
						"Sun, 06 Nov 1994 08:49:37 gmt", "Sun, 06 Nov 1994 08:49:37 UTC", "Sun, 06 Nov 1994 08:49:37 +0000",
						"Mon, 06 Nov 1994 08:49:37 GMT", "Sun, 6 Nov 1994 08:49:37 GMT", "Sun,  06 Nov 1994 08:49:37 GMT",
						"Sun, 06 Nov 94 08:49:37 GMT", "Sun, 06 Nov 1994 8:49:37 GMT", "Sun, 06 Nov 1994 24:00:00 GMT",
						"Sun, 06 Nov 1994 08:60:00 GMT", "Sun, 06 Nov 1994 08:49:61 GMT", "Sat, 31 Feb 2026 00:00:00 GMT",
						"Sun, 29 Feb 2026 00:00:00 GMT", "Sun, 00 Nov 1994 08:49:37 GMT", "Sun, 06 Nov 1994 08:49:37 GMT+1",
						"Sun, 06 Nov 1994 08:49:37", "Sun, 06 Nov 1994 08-49-37 GMT", "Sun, 06 Nov \u0661994 08:49:37 GMT",
						"Sunday, 06-Nov-1994 08:49:37 GMT", "Sun, 06-Nov-94 08:49:37 GMT", "Sunday, 06 Nov 94 08:49:37 GMT",
						"Sunday,06-Nov-94 08:49:37 GMT", "Sunday, 06-Nov-94 08:49:37 UTC", "Sunday, 6-Nov-94 08:49:37 GMT",
						"Monday, 06-Nov-94 08:49:37 GMT", "Sunday, 06-nov-94 08:49:37 GMT", "Sun Nov 6 08:49:37 1994",
						"Sun Nov  6 08:49:37 94", "Sun  Nov 6 08:49:37 1994", "Mon Nov  6 08:49:37 1994",
						"Sun Nov  6 08:49:37 1994 GMT", "Sun Nov 6  08:49:37 1994", "Sun Nov  6 08:49:37  1994",
						"Sun, 06 Nov 1994 08:49:37 GMT, Sun, 06 Nov 1994 08:49:37 GMT", "Sun, 06 Nov 1994\u000008:49:37 GMT",
						"2026-09-27T12:00:00Z", "Sun, 06 Nov 1994 08:49:37 GMT\u0000")
				.map(value -> DynamicTest.dynamicTest(escaped(value),
						() -> Assertions.assertEquals(Optional.empty(), HttpDate.parse(value, NOW))));
	}

	// RFC 9110 section 5.6.7: a 29 February exists only in a leap year, and the day name is checked against the real
	// date: 2024-02-29 is a Thursday.
	@Test
	void readsTheTwentyNinthOfFebruaryOnlyInALeapYear() {
		Assertions.assertEquals(Optional.of(Instant.parse("2024-02-29T00:00:00Z")),
				HttpDate.parse("Thu, 29 Feb 2024 00:00:00 GMT", NOW));
		Assertions.assertEquals(Optional.empty(), HttpDate.parse("Sun, 29 Feb 2026 00:00:00 GMT", NOW));
		Assertions.assertEquals(Optional.empty(), HttpDate.parse("Thu, 29 Feb 2100 00:00:00 GMT", NOW));
	}

	// The four-digit forms read any year from 0000 to 9999, so the result never depends on now, even at the extreme
	// instants, where an RFC 850 date has no window and is not a date (and nothing throws).
	@Test
	void readsTheFourDigitFormsAtEveryNowAndNeverThrowsAtTheExtremes() {
		Instant example = Instant.parse("1994-11-06T08:49:37Z");
		for (Instant now : List.of(Instant.MIN, Instant.EPOCH, NOW, Instant.MAX)) {
			Assertions.assertEquals(Optional.of(example), HttpDate.parse("Sun, 06 Nov 1994 08:49:37 GMT", now));
			Assertions.assertEquals(Optional.of(example), HttpDate.parse("Sun Nov  6 08:49:37 1994", now));
		}
		Assertions.assertEquals(Optional.empty(), HttpDate.parse("Sunday, 06-Nov-94 08:49:37 GMT", Instant.MAX));
		Assertions.assertEquals(Optional.empty(), HttpDate.parse("Sunday, 06-Nov-94 08:49:37 GMT", Instant.MIN));
		Assertions.assertEquals(Optional.of(Instant.parse("9999-12-31T23:59:59Z")),
				HttpDate.parse("Fri, 31 Dec 9999 23:59:59 GMT", NOW));
		Assertions.assertEquals(Optional.of(LocalDateTime.of(0, 1, 1, 0, 0).toInstant(ZoneOffset.UTC)),
				HttpDate.parse("Sat, 01 Jan 0000 00:00:00 GMT", NOW));
	}

	// Totality: no text built from date characters, however garbled, makes the parser throw, and whatever it reads is a
	// whole second.
	@Test
	void neverThrowsOnGarbledDates() {
		Random random = new Random(0x5EED_6002L);
		String alphabet = "SunMoTeWdhFrSaJbpAgOcNvDlyG0123456789 ,:-\t\u0661\u00e9";
		List<String> seeds = List.of("Sun, 06 Nov 1994 08:49:37 GMT", "Sunday, 06-Nov-94 08:49:37 GMT",
				"Sun Nov  6 08:49:37 1994");
		for (int i = 0; i < 50_000; ++i) {
			StringBuilder value = new StringBuilder(seeds.get(random.nextInt(seeds.size())));
			int edits = 1 + random.nextInt(4);
			for (int edit = 0; edit < edits; ++edit) {
				int position = random.nextInt(value.length() + 1);
				char c = alphabet.charAt(random.nextInt(alphabet.length()));
				switch (random.nextInt(3)) {
					case 0 -> value.insert(position, c);
					case 1 -> {
						if (position < value.length())
							value.setCharAt(position, c);
					}
					default -> {
						if (position < value.length())
							value.deleteCharAt(position);
					}
				}
			}
			String text = value.toString();
			Optional<Instant> parsed = Assertions.assertDoesNotThrow(() -> HttpDate.parse(text, NOW), text);
			parsed.ifPresent(instant -> Assertions.assertEquals(instant.truncatedTo(ChronoUnit.SECONDS), instant, text));
		}
	}

	// Date and Expires are singleton fields: one field line holding a date gives it; none, two (even equal) or one that
	// is not a date gives nothing.
	@Test
	void readsASingletonFieldOnlyFromExactlyOneValidLine() {
		String date = "Sun, 06 Nov 1994 08:49:37 GMT";
		Assertions.assertEquals(Optional.of(Instant.parse("1994-11-06T08:49:37Z")),
				HttpDate.parseSingleField(List.of(date), NOW));
		Assertions.assertEquals(Optional.empty(), HttpDate.parseSingleField(List.of(), NOW));
		Assertions.assertEquals(Optional.empty(), HttpDate.parseSingleField(List.of(date, date), NOW));
		Assertions.assertEquals(Optional.empty(), HttpDate.parseSingleField(List.of("0"), NOW));
	}

	// RetryAfter reads an HTTP-date exactly as HttpDate does: the delay is the time from now to the date, or zero.
	@TestFactory
	Stream<DynamicTest> retryAfterReadsDatesThroughThisParser() {
		return Stream.of("Sun, 27 Sep 2026 12:00:37 GMT", "Sunday, 27-Sep-26 12:00:37 GMT", "Sun Sep 27 12:00:37 2026",
						"Sun, 06 Nov 1994 08:49:37 GMT", " Sun, 27 Sep 2026 12:01:00 GMT\t", "Mon, 27 Sep 2026 12:00:37 GMT")
				.map(value -> DynamicTest.dynamicTest(value, () -> Assertions.assertEquals(
						HttpDate.parse(value, NOW).map(date -> date.isBefore(NOW) ? Duration.ZERO
								: Duration.between(NOW, date)), RetryAfter.parse(List.of(value), NOW))));
	}

	// The arguments are required.
	@Test
	void refusesNullArguments() {
		Assertions.assertThrows(NullPointerException.class, () -> HttpDate.parse(nullValue(), NOW));
		Assertions.assertThrows(NullPointerException.class, () -> HttpDate.parse("0", nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> HttpDate.parseSingleField(nullValue(), NOW));
		Assertions.assertThrows(NullPointerException.class, () -> HttpDate.parseSingleField(List.of("0"), nullValue()));
	}

	/**
	 * {@code Sun, 06 Nov 1994 08:49:37 GMT}, written independently of the parser.
	 */
	private static String imfFixdate(LocalDateTime dateTime) {
		return String.format(Locale.ROOT, "%s, %02d %s %04d %02d:%02d:%02d GMT",
				DAY_NAMES.get(dateTime.getDayOfWeek().getValue() - 1), dateTime.getDayOfMonth(),
				MONTH_NAMES.get(dateTime.getMonthValue() - 1), dateTime.getYear(), dateTime.getHour(), dateTime.getMinute(),
				dateTime.getSecond());
	}

	/**
	 * {@code Sunday, 06-Nov-94 08:49:37 GMT}.
	 */
	private static String rfc850(LocalDateTime dateTime) {
		return String.format(Locale.ROOT, "%s, %02d-%s-%02d %02d:%02d:%02d GMT",
				LONG_DAY_NAMES.get(dateTime.getDayOfWeek().getValue() - 1), dateTime.getDayOfMonth(),
				MONTH_NAMES.get(dateTime.getMonthValue() - 1), dateTime.getYear() % 100, dateTime.getHour(),
				dateTime.getMinute(), dateTime.getSecond());
	}

	/**
	 * {@code Sun Nov  6 08:49:37 1994}, with a space before a one-digit day.
	 */
	private static String asctime(LocalDateTime dateTime) {
		return String.format(Locale.ROOT, "%s %s %2d %02d:%02d:%02d %04d",
				DAY_NAMES.get(dateTime.getDayOfWeek().getValue() - 1), MONTH_NAMES.get(dateTime.getMonthValue() - 1),
				dateTime.getDayOfMonth(), dateTime.getHour(), dateTime.getMinute(), dateTime.getSecond(),
				dateTime.getYear());
	}

	private static String escaped(String value) {
		StringBuilder escaped = new StringBuilder("\"");
		for (char c : value.toCharArray())
			escaped.append(c < 0x20 || c > 0x7E ? String.format(Locale.ROOT, "\\u%04x", (int) c)
					: String.valueOf(c));
		return escaped.append('"').toString();
	}

	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> T nullValue() {
		@Nullable T value = null;
		return value;
	}
}
