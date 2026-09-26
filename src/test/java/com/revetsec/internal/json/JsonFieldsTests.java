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

import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static com.revetsec.internal.json.JsonFailures.SENTINEL;
import static com.revetsec.internal.json.JsonFailures.assertFieldRejected;
import static com.revetsec.internal.json.JsonFailures.utf8;

/**
 * Typed member reads for protocol validation (M1 plan internal types; RFC 7519 sections 2 and 4.1): absent, the
 * expected type, or a {@link JsonFieldException}, never a silent empty result for a malformed member.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JsonFieldsTests {
	/**
	 * One member of every JSON type, and a sentinel in each string so a failure that echoed input would show.
	 */
	private static final String CLAIMS = "{\"s\":\"" + SENTINEL + "\",\"n\":1311280970,\"f\":1311280970.5,"
			+ "\"t\":true,\"z\":null,\"a\":[\"" + SENTINEL + "\",\"b\"],\"e\":[],\"m\":[\"a\",1],\"o\":{\"k\":\""
			+ SENTINEL + "\"}}";

	// RFC 7519 section 4.1.2 (sub) and similar string claims: absent gives empty, a string gives its value, and
	// every other type, null included, is WRONG_TYPE.
	@Test
	void readsAStringOrRejectsAnotherType() throws Exception {
		JsonObject claims = claims();

		Assertions.assertEquals(Optional.of(SENTINEL), JsonFields.string(claims, "s"));
		Assertions.assertEquals(Optional.empty(), JsonFields.string(claims, "absent"));
		Assertions.assertEquals(Optional.empty(), JsonFields.string(claims, "S"), "names compare exactly");

		for (String name : List.of("n", "f", "t", "z", "a", "e", "o"))
			assertFieldRejected(JsonFieldException.Kind.WRONG_TYPE, () -> JsonFields.string(claims, name));
	}

	// RFC 7519 section 4.1.3 (aud): one string or an array of strings, in order; an empty array is an empty list.
	@Test
	void readsAStringOrAStringArray() throws Exception {
		JsonObject claims = claims();

		Assertions.assertEquals(Optional.of(List.of(SENTINEL)), JsonFields.stringOrStringArray(claims, "s"));
		Assertions.assertEquals(Optional.of(List.of(SENTINEL, "b")), JsonFields.stringOrStringArray(claims, "a"));
		Assertions.assertEquals(Optional.of(List.of()), JsonFields.stringOrStringArray(claims, "e"));
		Assertions.assertEquals(Optional.empty(), JsonFields.stringOrStringArray(claims, "absent"));
		Assertions.assertThrows(UnsupportedOperationException.class,
				() -> JsonFields.stringOrStringArray(claims, "a").orElseThrow().add("c"));

		for (String name : List.of("n", "t", "z", "m", "o"))
			assertFieldRejected(JsonFieldException.Kind.WRONG_TYPE, () -> JsonFields.stringOrStringArray(claims, name));
	}

	// RFC 7519 section 2: a NumericDate is seconds since the epoch and may have a fraction; a string or any other type
	// is WRONG_TYPE.
	@Test
	void readsANumericDate() throws Exception {
		JsonObject claims = claims();

		Assertions.assertEquals(Optional.of(Instant.ofEpochSecond(1_311_280_970L)), JsonFields.numericDate(claims, "n"));
		Assertions.assertEquals(Optional.of(Instant.ofEpochSecond(1_311_280_970L, 500_000_000L)),
				JsonFields.numericDate(claims, "f"));
		Assertions.assertEquals(Optional.empty(), JsonFields.numericDate(claims, "absent"));

		for (String name : List.of("s", "t", "z", "a", "o"))
			assertFieldRejected(JsonFieldException.Kind.WRONG_TYPE, () -> JsonFields.numericDate(claims, name));

		assertFieldRejected(JsonFieldException.Kind.WRONG_TYPE,
				() -> JsonFields.numericDate(object("{\"exp\":\"1311280970\"}"), "exp"));
	}

	// M1 plan: the NumericDate range is checked against years -9999 to 9999 before any conversion, at exact
	// boundaries, with every representation of the same value treated alike.
	@TestFactory
	Stream<DynamicTest> boundsNumericDatesToYearsMinus9999Through9999() {
		Instant earliest = OffsetDateTime.of(-9999, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC).toInstant();
		Instant latest = OffsetDateTime.of(9999, 12, 31, 23, 59, 59, 999_999_999, ZoneOffset.UTC).toInstant();

		return Stream.of(
				new Object[]{"-377705116800", earliest},
				new Object[]{"-3.777051168E+11", earliest},
				new Object[]{"253402300799.999999999", latest},
				new Object[]{"253402300799.9999999999999", latest},
				new Object[]{"2.53402300799999999999E+11", latest},
				new Object[]{"0", Instant.EPOCH},
				new Object[]{"-0.0", Instant.EPOCH},
				new Object[]{"0E+100000", Instant.EPOCH},
				new Object[]{"0E-100000", Instant.EPOCH},
				new Object[]{"1E-100000", Instant.EPOCH},
				new Object[]{"-1E-100000", Instant.EPOCH.minusNanos(1)},
				new Object[]{"-0.5", Instant.EPOCH.minusMillis(500)},
				new Object[]{"1.0000000009", Instant.EPOCH.plusSeconds(1)},
				new Object[]{"-1.0000000001", Instant.EPOCH.minusSeconds(1).minusNanos(1)},
				new Object[]{"1e9", Instant.ofEpochSecond(1_000_000_000L)},
				new Object[]{"1" + "0".repeat(10) + "." + "0".repeat(4_000), Instant.ofEpochSecond(10_000_000_000L)},
				new Object[]{"-377705116800.0000000001", null},
				new Object[]{"-377705116801", null},
				new Object[]{"253402300800", null},
				new Object[]{"2.534023008E+11", null},
				new Object[]{"1E+100000", null},
				new Object[]{"-1E+100000", null},
				new Object[]{"9".repeat(4_096), null})
				.map(row -> DynamicTest.dynamicTest(abbreviate((String) row[0]), () -> {
					JsonObject claims = JsonObject.builder().put("exp", new BigDecimal((String) row[0])).build();

					if (row[1] == null)
						assertFieldRejected(JsonFieldException.Kind.OUT_OF_RANGE, () -> JsonFields.numericDate(claims, "exp"));
					else
						Assertions.assertEquals(Optional.of(row[1]), JsonFields.numericDate(claims, "exp"));
				}));
	}

	// Plan risk "Number cost": a NumericDate with the model's largest exponent is rejected at once, without
	// expanding the number.
	@Test
	void rejectsHugeExponentsWithoutExpandingThem() {
		JsonObject claims = JsonObject.builder()
				.put("big", JsonNumber.fromValue(new BigDecimal("9.99E+100000")))
				.put("tiny", JsonNumber.fromValue(new BigDecimal("-9.99E-99998")))
				.build();

		Assertions.assertTimeoutPreemptively(Duration.ofSeconds(5), () -> {
			for (int count = 0; count < 1_000; ++count) {
				assertFieldRejected(JsonFieldException.Kind.OUT_OF_RANGE, () -> JsonFields.numericDate(claims, "big"));
				Assertions.assertEquals(Optional.of(Instant.EPOCH.minusNanos(1)), JsonFields.numericDate(claims, "tiny"));
			}
		});
	}

	// R15: null arguments are misuse.
	@Test
	void rejectsNullArguments() throws Exception {
		JsonObject claims = claims();
		JsonObject noObject = JsonFailures.nullValue();
		String noName = JsonFailures.nullValue();

		Assertions.assertThrows(NullPointerException.class, () -> JsonFields.string(noObject, "s"));
		Assertions.assertThrows(NullPointerException.class, () -> JsonFields.string(claims, noName));
		Assertions.assertThrows(NullPointerException.class, () -> JsonFields.stringOrStringArray(noObject, "a"));
		Assertions.assertThrows(NullPointerException.class, () -> JsonFields.stringOrStringArray(claims, noName));
		Assertions.assertThrows(NullPointerException.class, () -> JsonFields.numericDate(noObject, "n"));
		Assertions.assertThrows(NullPointerException.class, () -> JsonFields.numericDate(claims, noName));
	}

	private static String abbreviate(String text) {
		return text.length() <= 40 ? text : text.substring(0, 40) + "... (" + text.length() + " characters)";
	}

	private static JsonObject claims() throws JsonParseException {
		return object(CLAIMS);
	}

	private static JsonObject object(String json) throws JsonParseException {
		return (JsonObject) JsonCodec.parse(utf8(json), JsonLimits.jose(64 * 1_024));
	}
}
