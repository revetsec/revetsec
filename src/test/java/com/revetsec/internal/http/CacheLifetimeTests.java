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

import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.Limits;
import com.revetsec.testing.RawTlsServer;
import com.revetsec.testing.TestTls;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.net.http.HttpHeaders;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

/**
 * {@link CacheLifetime}: the RFC 9111 subset that decides how long a fetched key set (and, from M3, a metadata
 * document) is kept (M2 plan, M2-8, "TTL"; exit criterion 15). RFC 9111 was read from rfc-editor.org on 2026-09-27 for
 * sections 1.2.2, 4.2.1, 4.2.3, 5.1, 5.2 and 5.3.
 * <p>
 * The header tables run through {@link RawTlsServer} and the real JDK client, because the JDK's own header handling
 * (repeated field lines, name case, obs-fold, empty values) is part of the result, and because the JDK
 * {@code HttpServer} always replaces {@code Date} with its own clock, so only exact bytes can script the
 * {@code Date}, {@code Expires} and {@code Age} cases. The rule tables and the model check call the class directly.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class CacheLifetimeTests {
	/**
	 * The JWKS rows' defaults: 1 min, 10 min and 6 h.
	 */
	private static final Duration MINIMUM = Limits.JWKS_MINIMUM_TIME_TO_LIVE.getDefaultDuration();
	private static final Duration DEFAULT = Limits.JWKS_DEFAULT_TIME_TO_LIVE.getDefaultDuration();
	private static final Duration MAXIMUM = Limits.JWKS_MAXIMUM_TIME_TO_LIVE.getDefaultDuration();

	/**
	 * Bounds for the rule tables, wide and distinct enough to show which rule decided: the minimum is 1 s, the default
	 * 777 s, and the maximum far above 2<sup>31</sup> s.
	 */
	private static final Duration RULE_MINIMUM = Duration.ofSeconds(1);
	private static final Duration RULE_DEFAULT = Duration.ofSeconds(777);
	private static final Duration RULE_MAXIMUM = Duration.ofSeconds(1L << 40);

	private static final Instant RECEIVED_AT = Instant.parse("2026-09-26T12:00:00Z");
	private static final String DATE = "Date: Sat, 26 Sep 2026 12:00:00 GMT\r\n";
	private static final String EXPIRES_IN_TWO_HOURS = "Expires: Sat, 26 Sep 2026 14:00:00 GMT\r\n";
	private static final String BODY = "{\"keys\":[]}";
	private static final AtomicInteger NEXT_PATH = new AtomicInteger();

	private static @Nullable RawTlsServer server;
	private static @Nullable HttpExchange exchange;

	@BeforeAll
	static void startServer() throws IOException {
		server = RawTlsServer.start();
		exchange = HttpExchange.fromHttpClient(TestTls.httpClient(), OutboundUriPolicy.defaultInstance(), false);
	}

	@AfterAll
	static void stopServer() {
		if (server != null)
			server.close();
	}

	// M2-8 and exit criterion 15: the M2 plan's 35-row header table, first measured through M1's HttpExchange on JDK 17
	// and 27, every row with the Date field of the receipt time, under the JWKS rows' defaults (1 min, 10 min, 6 h). It
	// includes the four values of exit criterion 15's first half: max-age=5 gives 1 min, no-store 1 min,
	// max-age=999999999 6 h, and no header 10 min. The 35 rows are here, and so is the obs-fold row, which the JDK
	// unfolds, so no-store wins. One expectation was mistyped when the table was first measured and is corrected here:
	// max-age=3600 with Age: 3500 leaves 100 s, above the 1 min minimum.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> thePlansHeaderTableHoldsThroughTheJdkClient() {
		Map<String, Row> rows = new LinkedHashMap<>();
		rows.put("absent", new Row("", 600));
		rows.put("max-age=5 (below the minimum)", new Row("Cache-Control: max-age=5\r\n", 60));
		rows.put("max-age=3600", new Row("Cache-Control: max-age=3600\r\n", 3600));
		rows.put("max-age=999999999 (above the maximum)", new Row("Cache-Control: max-age=999999999\r\n", 21600));
		rows.put("max-age=99999999999999999999 (overflow)",
				new Row("Cache-Control: max-age=99999999999999999999\r\n", 21600));
		rows.put("MAX-AGE=3600 (case)", new Row("Cache-Control: MAX-AGE=3600\r\n", 3600));
		rows.put("max-age=\"3600\" (quoted)", new Row("Cache-Control: max-age=\"3600\"\r\n", 3600));
		rows.put("max-age=-1", new Row("Cache-Control: max-age=-1\r\n", 60));
		rows.put("max-age=1.5", new Row("Cache-Control: max-age=1.5\r\n", 60));
		rows.put("max-age= (empty)", new Row("Cache-Control: max-age=\r\n", 60));
		rows.put("max-age (no argument)", new Row("Cache-Control: max-age\r\n", 60));
		rows.put("max-age=0", new Row("Cache-Control: max-age=0\r\n", 60));
		rows.put("no-store", new Row("Cache-Control: no-store\r\n", 60));
		rows.put("no-cache", new Row("Cache-Control: no-cache\r\n", 60));
		rows.put("no-cache=\"Set-Cookie\", max-age=3600",
				new Row("Cache-Control: no-cache=\"Set-Cookie\", max-age=3600\r\n", 60));
		rows.put("public, max-age=3600, must-revalidate",
				new Row("Cache-Control: public, max-age=3600, must-revalidate\r\n", 3600));
		rows.put("private, max-age=3600", new Row("Cache-Control: private, max-age=3600\r\n", 3600));
		rows.put("s-maxage=60, max-age=3600", new Row("Cache-Control: s-maxage=60, max-age=3600\r\n", 3600));
		rows.put("s-maxage only", new Row("Cache-Control: s-maxage=7200\r\n", 600));
		rows.put("two lines: max-age=3600 then no-store",
				new Row("Cache-Control: max-age=3600\r\nCache-Control: no-store\r\n", 60));
		rows.put("duplicate equal max-age", new Row("Cache-Control: max-age=3600, max-age=3600\r\n", 3600));
		rows.put("conflicting max-age on two lines, the second in lower case",
				new Row("Cache-Control: max-age=3600\r\ncache-control: max-age=7200\r\n", 60));
		rows.put("max-age=3600 and Age: 3500", new Row("Cache-Control: max-age=3600\r\nAge: 3500\r\n", 100));
		rows.put("max-age=3600 and Age: 600", new Row("Cache-Control: max-age=3600\r\nAge: 600\r\n", 3000));
		rows.put("max-age=3600 and Age: x", new Row("Cache-Control: max-age=3600\r\nAge: x\r\n", 3600));
		rows.put("Expires two hours after Date", new Row(EXPIRES_IN_TWO_HOURS, 7200));
		rows.put("Expires two hours after Date, and max-age=120, which wins",
				new Row("Cache-Control: max-age=120\r\n" + EXPIRES_IN_TWO_HOURS, 120));
		rows.put("Expires: 0", new Row("Expires: 0\r\n", 60));
		rows.put("Expires in the past", new Row("Expires: Sat, 26 Sep 2026 11:00:00 GMT\r\n", 60));
		rows.put("Expires with the wrong day name", new Row("Expires: Mon, 26 Sep 2026 14:00:00 GMT\r\n", 60));
		rows.put("Expires in 30 days (above the maximum)", new Row("Expires: Mon, 26 Oct 2026 12:00:00 GMT\r\n", 21600));
		rows.put("Pragma: no-cache only", new Row("Pragma: no-cache\r\n", 600));
		rows.put("stale-if-error=86400, max-age=300",
				new Row("Cache-Control: stale-if-error=86400, max-age=300\r\n", 300));
		rows.put("a token that is not a directive", new Row("Cache-Control: max-age=300, {bad}\r\n", 60));
		rows.put("an empty Cache-Control, which has no directives", new Row("Cache-Control: \r\n", 600));
		rows.put("obs-fold continuation", new Row("Cache-Control: max-age=3600,\r\n no-store\r\n", 60));

		Assertions.assertEquals(36, rows.size());
		return rows.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(),
				() -> Assertions.assertEquals(Duration.ofSeconds(entry.getValue().expectedSeconds()),
						timeToLiveThroughTheJdk(DATE + entry.getValue().headerLines()))));
	}

	// RFC 9111 sections 4.2.1, 4.2.3, 5.1 and 5.3, M2-8 rules 4 and 6: every other Date, Expires and Age case, through
	// the JDK client. Expires counts from the server's one valid Date, or else from the receipt time, in any of the
	// three HTTP-date forms; a repeated or invalid Expires, or one at or before Date, gives the minimum; max-age makes
	// Expires irrelevant, even an invalid one; Age's first list member is subtracted from an explicit lifetime only.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> everyDateExpiresAndAgeCaseHoldsThroughTheJdkClient() {
		Map<String, Row> rows = new LinkedHashMap<>();
		rows.put("Expires in two hours and no Date: counted from the receipt time", new Row(EXPIRES_IN_TWO_HOURS, 7200));
		rows.put("Expires, and Date an hour later than the receipt time",
				new Row("Date: Sat, 26 Sep 2026 13:00:00 GMT\r\n" + EXPIRES_IN_TWO_HOURS, 3600));
		rows.put("Expires, and Date an hour earlier than the receipt time",
				new Row("Date: Sat, 26 Sep 2026 11:00:00 GMT\r\n" + EXPIRES_IN_TWO_HOURS, 10800));
		rows.put("Expires, and a Date that is not a date: the receipt time",
				new Row("Date: yesterday\r\n" + EXPIRES_IN_TWO_HOURS, 7200));
		rows.put("Expires, and two Date lines an hour later: the receipt time",
				new Row("Date: Sat, 26 Sep 2026 13:00:00 GMT\r\nDate: Sat, 26 Sep 2026 13:00:00 GMT\r\n"
						+ EXPIRES_IN_TWO_HOURS, 7200));
		rows.put("Expires in RFC 850 form", new Row(DATE + "Expires: Saturday, 26-Sep-26 14:00:00 GMT\r\n", 7200));
		rows.put("Expires in asctime form", new Row(DATE + "Expires: Sat Sep 26 14:00:00 2026\r\n", 7200));
		rows.put("Date in asctime form, an hour later",
				new Row("Date: Sat Sep 26 13:00:00 2026\r\n" + EXPIRES_IN_TWO_HOURS, 3600));
		rows.put("Expires and Date with lower-case names",
				new Row("date: Sat, 26 Sep 2026 13:00:00 GMT\r\nexpires: Sat, 26 Sep 2026 14:00:00 GMT\r\n", 3600));
		rows.put("two equal Expires lines", new Row(DATE + EXPIRES_IN_TWO_HOURS + EXPIRES_IN_TWO_HOURS, 60));
		rows.put("Expires equal to Date", new Row(DATE + "Expires: Sat, 26 Sep 2026 12:00:00 GMT\r\n", 60));
		rows.put("Expires one minute after Date", new Row(DATE + "Expires: Sat, 26 Sep 2026 12:01:00 GMT\r\n", 60));
		rows.put("Expires seven hours after Date: the maximum",
				new Row(DATE + "Expires: Sat, 26 Sep 2026 19:00:00 GMT\r\n", 21600));
		rows.put("Expires in two hours, and Age: 600", new Row(DATE + EXPIRES_IN_TWO_HOURS + "Age: 600\r\n", 6600));
		rows.put("Expires in seven hours, and Age: 3600",
				new Row(DATE + "Expires: Sat, 26 Sep 2026 19:00:00 GMT\r\nAge: 3600\r\n", 21600));
		rows.put("Expires in two hours, and Cache-Control: public",
				new Row(DATE + "Cache-Control: public\r\n" + EXPIRES_IN_TWO_HOURS, 7200));
		rows.put("Expires in two hours, and Cache-Control: no-cache",
				new Row(DATE + "Cache-Control: no-cache\r\n" + EXPIRES_IN_TWO_HOURS, 60));
		rows.put("Expires: 0, and max-age=120, which wins", new Row(DATE + "Cache-Control: max-age=120\r\nExpires: 0\r\n",
				120));
		rows.put("max-age=3600, and the Age list 600, 100: the first member",
				new Row(DATE + "Cache-Control: max-age=3600\r\nAge: 600, 100\r\n", 3000));
		rows.put("max-age=3600, and two Age lines, 600 then 100: the first",
				new Row(DATE + "Cache-Control: max-age=3600\r\nAge: 600\r\nAge: 100\r\n", 3000));
		rows.put("max-age=3600, and the Age list x, 600: ignored",
				new Row(DATE + "Cache-Control: max-age=3600\r\nAge: x, 600\r\n", 3600));
		rows.put("max-age=3600, and Age: 3600", new Row(DATE + "Cache-Control: max-age=3600\r\nAge: 3600\r\n", 60));
		rows.put("max-age=3600, and an Age too large for a long",
				new Row(DATE + "Cache-Control: max-age=3600\r\nAge: 99999999999999999999\r\n", 60));
		rows.put("Age alone is not subtracted from the default", new Row(DATE + "Age: 300\r\n", 600));
		rows.put("Age with no-store", new Row(DATE + "Cache-Control: no-store\r\nAge: 30\r\n", 60));
		// The JDK keeps an empty field line as an empty value, so these are fields present with an invalid value.
		rows.put("an empty Expires: the minimum", new Row(DATE + "Expires: \r\n", 60));
		rows.put("Expires in two hours, and a second, empty Expires line: the minimum",
				new Row(DATE + EXPIRES_IN_TWO_HOURS + "Expires: \r\n", 60));
		rows.put("Expires, and an empty Date: the receipt time", new Row("Date: \r\n" + EXPIRES_IN_TWO_HOURS, 7200));
		rows.put("max-age=3600, and an empty Age: ignored", new Row(DATE + "Cache-Control: max-age=3600\r\nAge: \r\n",
				3600));
		rows.put("Age lines before and after Cache-Control: the first line",
				new Row(DATE + "Age: 100\r\nCache-Control: max-age=3600\r\nAge: 200\r\n", 3500));

		return rows.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(),
				() -> Assertions.assertEquals(Duration.ofSeconds(entry.getValue().expectedSeconds()),
						timeToLiveThroughTheJdk(entry.getValue().headerLines()))));
	}

	// RFC 9111 section 5.2 and M2-8 rules 1 to 3: each Cache-Control element is token [ "=" ( token / quoted-string ) ]
	// with a case-insensitive name; a malformed element, no-store or no-cache, or conflicting max-age values give the
	// minimum; max-age is delta-seconds (section 1.2.2), capped at 2^31; every other directive is ignored. The bounds
	// here are 1 s, 777 s (the default) and 2^40 s, so the rule that decided shows in the result.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> cacheControlFollowsTheRfc9111Grammar() {
		long minimum = RULE_MINIMUM.toSeconds();
		long defaultSeconds = RULE_DEFAULT.toSeconds();
		long cap = CacheLifetime.MAXIMUM_DELTA_SECONDS;
		Map<List<String>, Long> cases = new LinkedHashMap<>();
		cases.put(List.of("max-age=5"), 5L);
		cases.put(List.of("MAX-AGE=5"), 5L);
		cases.put(List.of("Max-Age=5"), 5L);
		cases.put(List.of("max-age=\"5\""), 5L);
		cases.put(List.of("max-age=00005"), 5L);
		cases.put(List.of("max-age=0"), minimum);
		cases.put(List.of("max-age=2147483647"), 2_147_483_647L);
		cases.put(List.of("max-age=2147483648"), cap);
		cases.put(List.of("max-age=99999999999999999999999"), cap);
		// RFC 9111 section 1.2.2: the value is capped, never wrapped. These three would wrap a long to 0, to a negative
		// number and to 5, where the values above happen to wrap to large positive numbers.
		cases.put(List.of("max-age=18446744073709551616"), cap);
		cases.put(List.of("max-age=9223372036854775808"), cap);
		cases.put(List.of("max-age=18446744073709551621"), cap);
		cases.put(List.of("max-age=" + "0".repeat(1_000) + "7"), 7L);
		cases.put(List.of("max-age=2147483648, max-age=99999999999"), cap);
		cases.put(List.of("max-age=2147483647, max-age=2147483648"), minimum);
		cases.put(List.of("max-age=5", "max-age=5"), 5L);
		cases.put(List.of("max-age=5, max-age=\"5\""), 5L);
		cases.put(List.of("max-age=5, max-age=05"), 5L);
		cases.put(List.of("max-age=5", "max-age=6"), minimum);
		cases.put(List.of("max-age=\"\""), minimum);
		cases.put(List.of("max-age=+5"), minimum);
		cases.put(List.of("max-age=-5"), minimum);
		cases.put(List.of("max-age=5.0"), minimum);
		cases.put(List.of("max-age=1e3"), minimum);
		cases.put(List.of("max-age=0x10"), minimum);
		cases.put(List.of("max-age=\u0665"), minimum);
		cases.put(List.of("max-age"), minimum);
		cases.put(List.of("max-age="), minimum);
		cases.put(List.of("max-age= 5"), minimum);
		cases.put(List.of("max-age =5"), minimum);
		cases.put(List.of("max-age==5"), minimum);
		cases.put(List.of("max-age=5 6"), minimum);
		cases.put(List.of("max-age=5;x"), minimum);
		cases.put(List.of("max-age=5\"x\""), minimum);
		cases.put(List.of("max-age=5\u0000x"), minimum);
		cases.put(List.of("max\u2010age=5"), minimum);
		cases.put(List.of("no-store"), minimum);
		cases.put(List.of("NO-STORE"), minimum);
		cases.put(List.of("no-store=1"), minimum);
		cases.put(List.of("no-cache"), minimum);
		cases.put(List.of("No-Cache=\"Set-Cookie, Authorization\""), minimum);
		cases.put(List.of("max-age=5, no-store"), minimum);
		cases.put(List.of("no-store, max-age=5"), minimum);
		cases.put(List.of("max-age=5", "no-cache"), minimum);
		cases.put(List.of("private=\"a, max-age=1\", max-age=5"), 5L);
		cases.put(List.of("private=\"a\\\"b, no-store\", max-age=5"), 5L);
		cases.put(List.of("private=\"a, max-age=5"), minimum);
		cases.put(List.of("private=\"bad\\"), minimum);
		cases.put(List.of("private=\"\u0001\", max-age=5"), minimum);
		cases.put(List.of(" , ,max-age=5 ,, "), 5L);
		cases.put(List.of("\tmax-age=5\t"), 5L);
		cases.put(List.of("max-age=5,"), 5L);
		cases.put(List.of(""), defaultSeconds);
		cases.put(List.of(","), defaultSeconds);
		cases.put(List.of(" \t "), defaultSeconds);
		cases.put(List.of("public", "must-revalidate"), defaultSeconds);
		cases.put(List.of("s-maxage=5"), defaultSeconds);
		cases.put(List.of("s-maxage=5, max-age=50"), 50L);
		cases.put(List.of("immutable, stale-while-revalidate=30, stale-if-error=86400, max-age=50"), 50L);
		cases.put(List.of("x-extension=\"any, thing\", max-age=50"), 50L);
		cases.put(List.of("{bad}"), minimum);
		cases.put(List.of("max-age=50, {bad}"), minimum);
		cases.put(List.of("max-age=50", "{bad}"), minimum);
		cases.put(List.of("\"max-age=50\""), minimum);
		cases.put(List.of("=5"), minimum);
		cases.put(List.of("public;max-age=50"), minimum);
		// An "=" must be followed by a token or a quoted-string, whichever directive it follows; token is 1*tchar.
		cases.put(List.of("s-maxage=, max-age=50"), minimum);
		cases.put(List.of("max-age=50, private="), minimum);
		cases.put(List.of("max-age=50", "x-extension= "), minimum);
		cases.put(List.of("private=\"\", max-age=50"), 50L);
		return cases.entrySet().stream().map(entry -> DynamicTest.dynamicTest(escaped(entry.getKey().toString()),
				() -> Assertions.assertEquals(Duration.ofSeconds(entry.getValue()), ruleTimeToLive(headers(
						"Cache-Control", entry.getKey())))));
	}

	// RFC 9111 sections 4.2.1, 5.1 and 5.3, M2-8 rules 4 to 6, with the same bounds: Expires only without max-age;
	// exactly one valid Expires; Date only when it is one valid line; Age's first member, only for an explicit
	// lifetime, never below zero.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> expiresDateAndAgeFollowRfc9111() {
		String date = "Sat, 26 Sep 2026 12:00:00 GMT";
		String later = "Sat, 26 Sep 2026 12:10:00 GMT";
		long minimum = RULE_MINIMUM.toSeconds();
		long defaultSeconds = RULE_DEFAULT.toSeconds();
		Map<String, Object[]> cases = new LinkedHashMap<>();
		cases.put("Expires ten minutes after Date", new Object[]{Map.of("Date", List.of(date), "Expires",
				List.of(later)), 600L});
		cases.put("Expires, no Date", new Object[]{Map.of("Expires", List.of(later)), 600L});
		cases.put("Expires, two Date lines", new Object[]{Map.of("Date", List.of(later, later), "Expires",
				List.of(later)), 600L});
		cases.put("Expires, Date not a date", new Object[]{Map.of("Date", List.of("0"), "Expires", List.of(later)),
				600L});
		cases.put("Expires equal to Date", new Object[]{Map.of("Date", List.of(later), "Expires", List.of(later)),
				minimum});
		cases.put("Expires before Date", new Object[]{Map.of("Date", List.of(later), "Expires", List.of(date)),
				minimum});
		cases.put("Expires: 0", new Object[]{Map.of("Expires", List.of("0")), minimum});
		cases.put("Expires empty", new Object[]{Map.of("Expires", List.of("")), minimum});
		cases.put("two equal Expires lines", new Object[]{Map.of("Expires", List.of(later, later)), minimum});
		cases.put("Date alone", new Object[]{Map.of("Date", List.of(date)), defaultSeconds});
		cases.put("max-age wins over a valid Expires", new Object[]{Map.of("Cache-Control", List.of("max-age=5"),
				"Expires", List.of(later)), 5L});
		cases.put("max-age wins over an invalid Expires", new Object[]{Map.of("Cache-Control", List.of("max-age=5"),
				"Expires", List.of("0")), 5L});
		cases.put("no-store wins over Expires", new Object[]{Map.of("Cache-Control", List.of("no-store"), "Expires",
				List.of(later)), minimum});
		cases.put("Expires minus Age", new Object[]{Map.of("Expires", List.of(later), "Age", List.of("100")), 500L});
		cases.put("max-age minus Age", new Object[]{Map.of("Cache-Control", List.of("max-age=500"), "Age",
				List.of("100")), 400L});
		cases.put("Age above max-age", new Object[]{Map.of("Cache-Control", List.of("max-age=500"), "Age",
				List.of("501")), minimum});
		cases.put("Age capped at 2^31", new Object[]{Map.of("Cache-Control", List.of("max-age=99999999999"), "Age",
				List.of("99999999999")), minimum});
		cases.put("Age of 2^64 + 100 capped at 2^31, not wrapped to 100", new Object[]{Map.of("Cache-Control",
				List.of("max-age=500"), "Age", List.of("18446744073709551716")), minimum});
		cases.put("Age list: the first member", new Object[]{Map.of("Cache-Control", List.of("max-age=500"), "Age",
				List.of("100, 200")), 400L});
		cases.put("Age lines: the first member", new Object[]{Map.of("Cache-Control", List.of("max-age=500"), "Age",
				List.of("100", "200")), 400L});
		cases.put("Age list with empty elements first", new Object[]{Map.of("Cache-Control", List.of("max-age=500"),
				"Age", List.of(" , ", " ,\t100 , 7")), 400L});
		cases.put("Age whose first member is not delta-seconds", new Object[]{Map.of("Cache-Control",
				List.of("max-age=500"), "Age", List.of("-1, 100")), 500L});
		cases.put("Age with a fraction", new Object[]{Map.of("Cache-Control", List.of("max-age=500"), "Age",
				List.of("1.5")), 500L});
		cases.put("Age quoted", new Object[]{Map.of("Cache-Control", List.of("max-age=500"), "Age", List.of("\"100\"")),
				500L});
		cases.put("Age without an explicit lifetime", new Object[]{Map.of("Age", List.of("100")), defaultSeconds});
		return cases.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () -> {
			@SuppressWarnings("unchecked")
			Map<String, List<String>> fields = (Map<String, List<String>>) entry.getValue()[0];
			Assertions.assertEquals(Duration.ofSeconds((Long) entry.getValue()[1]), ruleTimeToLive(
					HttpHeaders.of(fields, (name, value) -> true)));
		}));
	}

	// M2-8 rule 7: the result is always clamped to [minimum, maximum]; equal bounds and a zero minimum are allowed, and
	// with a zero minimum an explicit lifetime of zero stays zero.
	@Test
	void clampsEveryLifetimeToTheBounds() {
		HttpHeaders fiveSeconds = headers("Cache-Control", List.of("max-age=5"));
		HttpHeaders zero = headers("Cache-Control", List.of("max-age=0"));
		HttpHeaders noStore = headers("Cache-Control", List.of("no-store"));
		HttpHeaders none = headers("Cache-Control", List.of());
		Duration minute = Duration.ofMinutes(1);

		Assertions.assertEquals(minute, CacheLifetime.timeToLive(fiveSeconds, RECEIVED_AT, minute, minute, minute));
		Assertions.assertEquals(minute, CacheLifetime.timeToLive(none, RECEIVED_AT, minute, minute, minute));
		Assertions.assertEquals(Duration.ofSeconds(5), CacheLifetime.timeToLive(fiveSeconds, RECEIVED_AT, Duration.ZERO,
				minute, minute));
		Assertions.assertEquals(Duration.ZERO, CacheLifetime.timeToLive(zero, RECEIVED_AT, Duration.ZERO, minute,
				minute));
		Assertions.assertEquals(Duration.ZERO, CacheLifetime.timeToLive(noStore, RECEIVED_AT, Duration.ZERO, minute,
				minute));
		Assertions.assertEquals(Duration.ofSeconds(3), CacheLifetime.timeToLive(fiveSeconds, RECEIVED_AT, Duration.ZERO,
				Duration.ofSeconds(3), Duration.ofSeconds(3)));
		Assertions.assertEquals(MINIMUM, CacheLifetime.timeToLive(noStore, RECEIVED_AT, MINIMUM, DEFAULT, MAXIMUM));
		Assertions.assertEquals(DEFAULT, CacheLifetime.timeToLive(none, RECEIVED_AT, MINIMUM, DEFAULT, MAXIMUM));
	}

	// The bounds must satisfy 0 <= minimum <= default <= maximum, and every argument is required.
	@Test
	void refusesBoundsOutOfOrderAndNullArguments() {
		HttpHeaders none = headers("Cache-Control", List.of());
		Duration minute = Duration.ofMinutes(1);
		Duration hour = Duration.ofHours(1);

		Assertions.assertThrows(IllegalArgumentException.class, () -> CacheLifetime.timeToLive(none, RECEIVED_AT,
				Duration.ofSeconds(-1), minute, hour));
		Assertions.assertThrows(IllegalArgumentException.class, () -> CacheLifetime.timeToLive(none, RECEIVED_AT, hour,
				minute, hour));
		Assertions.assertThrows(IllegalArgumentException.class, () -> CacheLifetime.timeToLive(none, RECEIVED_AT, minute,
				hour, minute));
		Assertions.assertThrows(NullPointerException.class, () -> CacheLifetime.timeToLive(nullValue(), RECEIVED_AT,
				minute, minute, hour));
		Assertions.assertThrows(NullPointerException.class, () -> CacheLifetime.timeToLive(none, nullValue(), minute,
				minute, hour));
		Assertions.assertThrows(NullPointerException.class, () -> CacheLifetime.timeToLive(none, RECEIVED_AT,
				nullValue(), minute, hour));
		Assertions.assertThrows(NullPointerException.class, () -> CacheLifetime.timeToLive(none, RECEIVED_AT, minute,
				nullValue(), hour));
		Assertions.assertThrows(NullPointerException.class, () -> CacheLifetime.timeToLive(none, RECEIVED_AT, minute,
				minute, nullValue()));
	}

	// Totality at the clock's extremes: an Expires counted from a receipt time of Instant.MIN or Instant.MAX, and an RFC
	// 850 Expires whose century cannot be decided there, never throw, and the result stays within the bounds.
	@Test
	void neverThrowsAtTheClocksExtremes() {
		for (Instant receivedAt : List.of(Instant.MIN, Instant.MAX))
			for (String expires : List.of("Sat, 26 Sep 2026 14:00:00 GMT", "Saturday, 26-Sep-26 14:00:00 GMT",
					"Fri, 31 Dec 9999 23:59:59 GMT")) {
				Duration timeToLive = CacheLifetime.timeToLive(headers("Expires", List.of(expires)), receivedAt, MINIMUM,
						DEFAULT, MAXIMUM);
				Assertions.assertTrue(timeToLive.compareTo(MINIMUM) >= 0 && timeToLive.compareTo(MAXIMUM) <= 0,
						() -> receivedAt + " " + expires);
			}
		Assertions.assertEquals(MAXIMUM, CacheLifetime.timeToLive(headers("Expires",
				List.of("Fri, 31 Dec 9999 23:59:59 GMT")), Instant.MIN, MINIMUM, DEFAULT, MAXIMUM));
		Assertions.assertEquals(MINIMUM, CacheLifetime.timeToLive(headers("Expires",
				List.of("Sat, 26 Sep 2026 14:00:00 GMT")), Instant.MAX, MINIMUM, DEFAULT, MAXIMUM));
	}

	// RFC 9111 section 5.2 and M2-8 rules 1 to 3 and 6, as a model: random Cache-Control lists built from elements
	// whose meaning is known (ignored directives, max-age in both forms, no-store and no-cache, malformed elements),
	// with random case, OWS, empty elements and field-line splits, and a random Age. The model's answer is computed from
	// the elements alone; CacheLifetime must agree with it on every list, under the rule bounds and the JWKS defaults.
	@Test
	void randomDirectiveListsAgreeWithAModelOfTheRules() {
		Random random = new Random(0x5EED_6003L);
		List<String> ignored = List.of("public", "private", "must-revalidate", "proxy-revalidate", "immutable",
				"no-transform", "must-understand", "s-maxage=60", "stale-if-error=86400", "stale-while-revalidate=30",
				"private=\"Set-Cookie, X-Other\"", "x-extension=\"a\\\"b, max-age=1\"", "x-flag");
		List<String> minimumElements = List.of("no-store", "no-cache", "no-cache=\"Set-Cookie\"", "no-store=x",
				"{bad}", "max-age", "max-age=", "max-age=-1", "max-age=1.5", "max-age=5 5", "\"quoted\"",
				"max-age= 5", "=x", "max-age=5;q", "max-age=\"\"", "max-age=\"5", "private=\"open", "s-maxage=", "private=");
		List<String> values = List.of("0", "5", "60", "3600", "0003600", "86400", "2147483647", "2147483648",
				"99999999999999999999", "9223372036854775808", "18446744073709551621");
		List<String> ages = List.of("100", "0", "x", "100, 5", " , 7", "99999999999", "18446744073709551716", "-1",
				"5\t");
		List<String> separators = List.of(",", ", ", " ,", "\t,\t", ",,", ", ,", " , \t, ");

		for (int iteration = 0; iteration < 20_000; ++iteration) {
			int count = random.nextInt(5);
			List<String> elements = new ArrayList<>();
			boolean minimum = false;
			List<Long> maxAges = new ArrayList<>();

			for (int index = 0; index < count; ++index) {
				int choice = random.nextInt(10);
				if (choice < 4) {
					elements.add(randomCase(random, ignored.get(random.nextInt(ignored.size()))));
				} else if (choice < 8) {
					String value = values.get(random.nextInt(values.size()));
					maxAges.add(capped(value));
					elements.add(randomCase(random, "max-age") + "=" + (random.nextBoolean() ? value : "\"" + value + "\""));
				} else {
					String element = minimumElements.get(random.nextInt(minimumElements.size()));
					elements.add(element.startsWith("{") || element.startsWith("\"") || element.startsWith("=")
							? element : randomCase(random, element));
					minimum = true;
				}
			}

			// Unterminated quoted strings swallow the rest of their field line, so they go last on theirs.
			List<String> fieldLines = new ArrayList<>();
			StringBuilder line = new StringBuilder(random.nextBoolean() ? "" : " ,");
			for (String element : elements) {
				if (line.length() > 0 && random.nextInt(3) == 0) {
					fieldLines.add(line.toString());
					line = new StringBuilder();
				} else if (line.length() > 0) {
					line.append(separators.get(random.nextInt(separators.size())));
				}
				line.append(element);
				if (element.endsWith("\"open") || element.equals("max-age=\"5")) {
					fieldLines.add(line.toString());
					line = new StringBuilder();
				}
			}
			if (line.length() > 0 || fieldLines.isEmpty())
				fieldLines.add(line + (random.nextBoolean() ? "" : ", "));

			List<String> age = random.nextBoolean() ? List.of() : List.of(ages.get(random.nextInt(ages.size())));
			boolean noLifetime = !minimum && maxAges.isEmpty();
			long expectedSeconds;
			if (minimum || maxAges.stream().distinct().count() > 1) {
				expectedSeconds = RULE_MINIMUM.toSeconds();
			} else if (noLifetime) {
				expectedSeconds = RULE_DEFAULT.toSeconds();
			} else {
				long lifetime = Math.max(0, maxAges.get(0) - firstAgeMember(age));
				expectedSeconds = Math.max(RULE_MINIMUM.toSeconds(), lifetime);
			}

			Map<String, List<String>> fields = new LinkedHashMap<>();
			fields.put("Cache-Control", fieldLines);
			if (!age.isEmpty())
				fields.put("Age", age);
			HttpHeaders headers = HttpHeaders.of(fields, (name, value) -> true);
			String description = fields.toString();

			Assertions.assertEquals(Duration.ofSeconds(expectedSeconds), ruleTimeToLive(headers), description);
			Duration jwks = CacheLifetime.timeToLive(headers, RECEIVED_AT, MINIMUM, DEFAULT, MAXIMUM);
			Duration expectedJwks = noLifetime ? DEFAULT : clamp(Duration.ofSeconds(expectedSeconds), MINIMUM, MAXIMUM);
			Assertions.assertEquals(expectedJwks, jwks, description);
		}
	}

	private static long capped(@NonNull String digits) {
		long value = 0;
		for (int i = 0; i < digits.length() && value <= CacheLifetime.MAXIMUM_DELTA_SECONDS; ++i)
			value = value * 10 + (digits.charAt(i) - '0');
		return Math.min(value, CacheLifetime.MAXIMUM_DELTA_SECONDS);
	}

	/**
	 * The model's Age: the first non-empty list member if it is all digits, capped; otherwise zero.
	 */
	private static long firstAgeMember(@NonNull List<@NonNull String> age) {
		for (String line : age)
			for (String member : line.split(",", -1)) {
				String trimmed = member.strip();
				if (trimmed.isEmpty())
					continue;
				return trimmed.chars().allMatch(c -> c >= '0' && c <= '9') ? capped(trimmed) : 0;
			}
		return 0;
	}

	private static @NonNull Duration clamp(@NonNull Duration value, @NonNull Duration minimum, @NonNull Duration maximum) {
		return value.compareTo(minimum) < 0 ? minimum : value.compareTo(maximum) > 0 ? maximum : value;
	}

	private static @NonNull String randomCase(@NonNull Random random, @NonNull String text) {
		StringBuilder result = new StringBuilder(text.length());
		boolean quoted = false;
		for (int index = 0; index < text.length(); ++index) {
			char c = text.charAt(index);
			if (c == '"')
				quoted = true;
			result.append(!quoted && c >= 'a' && c <= 'z' && random.nextBoolean() ? (char) (c - 'a' + 'A') : c);
		}
		return result.toString();
	}

	private static @NonNull Duration ruleTimeToLive(@NonNull HttpHeaders headers) {
		return CacheLifetime.timeToLive(headers, RECEIVED_AT, RULE_MINIMUM, RULE_DEFAULT, RULE_MAXIMUM);
	}

	private static @NonNull HttpHeaders headers(@NonNull String name, @NonNull List<@NonNull String> values) {
		return HttpHeaders.of(values.isEmpty() ? Map.of() : Map.of(name, values), (fieldName, value) -> true);
	}

	/**
	 * Sends a 200 JWKS response with {@code headerLines} as exact bytes and computes its lifetime from the headers the
	 * JDK client hands over, under the JWKS rows' defaults.
	 */
	private static @NonNull Duration timeToLiveThroughTheJdk(@NonNull String headerLines) throws Exception {
		RawTlsServer rawServer = required(server);
		String path = "/ttl/" + NEXT_PATH.incrementAndGet();
		rawServer.script(path, RawTlsServer.Script.builder()
				.write("HTTP/1.1 200 OK\r\nContent-Type: application/jwk-set+json\r\n" + headerLines + "Content-Length: "
						+ BODY.length() + "\r\nConnection: close\r\n\r\n" + BODY)
				.closeConnection()
				.build());

		RawResponse response = required(exchange).execute(HttpExchangeRequest.fromDefaults(rawServer.uri(path),
				ResponseProfile.JWKS), Deadline.fromNow(Duration.ofSeconds(30)));

		Assertions.assertEquals(200, response.status());
		return CacheLifetime.timeToLive(response.headers(), RECEIVED_AT, MINIMUM, DEFAULT, MAXIMUM);
	}

	private static @NonNull String escaped(@NonNull String value) {
		StringBuilder escaped = new StringBuilder();
		for (char c : value.toCharArray())
			escaped.append(c < 0x20 || c > 0x7E ? String.format(Locale.ROOT, "\\u%04x", (int) c) : String.valueOf(c));
		return escaped.length() > 120 ? escaped.substring(0, 120) + "..." : escaped.toString();
	}

	private static <T> @NonNull T required(@Nullable T value) {
		if (value == null)
			throw new IllegalStateException("The fixture did not start");
		return value;
	}

	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> @NonNull T nullValue() {
		@Nullable T value = null;
		return value;
	}

	/**
	 * One header-table row: the header lines to send and the lifetime expected, in seconds.
	 */
	private record Row(@NonNull String headerLines, long expectedSeconds) {
	}
}
