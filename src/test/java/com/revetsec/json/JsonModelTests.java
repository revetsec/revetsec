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

import com.revetsec.testing.Sentinels;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;

import java.lang.reflect.Modifier;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * The public JSON value model (M1 plan G7-4 to G7-8 and exit criterion 5).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JsonModelTests {
	private static final String SECRET = Sentinels.secret("json-model");

	// ---------------------------------------------------------------------------------------------------------------
	// Equality and hashing (G7-5)
	// ---------------------------------------------------------------------------------------------------------------

	// Exit criterion 5 and G7-5: numbers compare by value, so 1, 1.0, 1E0 and their relatives are equal and hash alike.
	@Test
	void numbersCompareByValueWithEqualHashes() {
		List<JsonNumber> ones = Stream.of("1", "1.0", "1E0", "1e0", "0.1E1", "10E-1", "1.000000000000000000000000000",
				"100E-2").map(text -> JsonNumber.fromValue(new BigDecimal(text))).toList();

		for (JsonNumber one : ones) {
			Assertions.assertEquals(JsonNumber.fromValue(1L), one, one.getValue()::toString);
			Assertions.assertEquals(JsonNumber.fromValue(1L).hashCode(), one.hashCode(), one.getValue()::toString);
		}

		Assertions.assertEquals(JsonNumber.fromValue(new BigDecimal("-0")), JsonNumber.fromValue(new BigDecimal("0.000")));
		Assertions.assertEquals(JsonNumber.fromValue(new BigDecimal("0E+5")).hashCode(), JsonNumber.fromValue(0L)
				.hashCode());
		Assertions.assertNotEquals(JsonNumber.fromValue(1L), JsonNumber.fromValue(new BigDecimal("1.0000000000000001")));
		Assertions.assertNotEquals(JsonNumber.fromValue(1L), JsonString.fromValue("1"));
	}

	// G7-5 pins the number hash itself: Double.hashCode of the nearest double, for zero, small values, long fractions,
	// a 1,024-digit value and values beyond the range of double (which hash as infinity or zero). A stripTrailingZeros
	// hash would also agree with equality, but costs a scan of every digit on each parse (plan risk "Number cost").
	@TestFactory
	Stream<DynamicTest> numbersHashAsTheirNearestDouble() {
		return Stream.of("0", "-0.000", "1", "1.0", "-1", "2", "0.1", "3.14159265358979323846264338327950288",
						"1" + "0".repeat(1_023), "1E+100000", "-9.99E-99998", "1E-400", "1E+400", "-1E+400", "4.9E-324",
						"1.7976931348623157E+308", "123456789012345678901234567890")
				.map(text -> DynamicTest.dynamicTest(text.length() > 40 ? text.substring(0, 40) + "..." : text, () -> {
					BigDecimal value = new BigDecimal(text);
					Assertions.assertEquals(Double.hashCode(value.doubleValue()), JsonNumber.fromValue(value).hashCode());
				}));
	}

	// Distinct values of each type hash apart, so a constant hash cannot pass for G7-5's.
	@Test
	void distinctValuesOfEachTypeHashApart() {
		Assertions.assertNotEquals(JsonNumber.fromValue(1L).hashCode(), JsonNumber.fromValue(2L).hashCode());
		Assertions.assertNotEquals(JsonString.fromValue("a").hashCode(), JsonString.fromValue("b").hashCode());
		Assertions.assertNotEquals(JsonArray.fromElements(List.of(JsonNumber.fromValue(1L))).hashCode(),
				JsonArray.fromElements(List.of(JsonNumber.fromValue(2L))).hashCode());
		Assertions.assertNotEquals(JsonObject.builder().put("a", 1L).build().hashCode(),
				JsonObject.builder().put("a", 2L).build().hashCode());
		Assertions.assertNotEquals(JsonObject.builder().put("a", 1L).build().hashCode(),
				JsonObject.builder().put("b", 1L).build().hashCode());
	}

	// G7-5: the cached Double.hashCode(doubleValue()) is the hash, and it agrees with numeric equality for random values
	// written at many scales, including values beyond the range of double.
	@Test
	void numberHashesAgreeWithEqualityAtEveryScale() {
		Random random = new Random(0x5EED_0010L);

		for (int count = 0; count < 20_000; ++count) {
			BigInteger unscaled = new BigInteger(1 + random.nextInt(200), random);
			BigDecimal value = new BigDecimal(random.nextBoolean() ? unscaled : unscaled.negate(),
					random.nextInt(800) - 400);
			BigDecimal rescaled = value.setScale(value.scale() + random.nextInt(30));
			BigDecimal stripped = value.signum() == 0 ? value : value.stripTrailingZeros();

			JsonNumber original = JsonNumber.fromValue(value);
			Assertions.assertEquals(Double.hashCode(value.doubleValue()), original.hashCode(), value::toString);

			for (BigDecimal equal : List.of(rescaled, stripped)) {
				JsonNumber other = JsonNumber.fromValue(equal);
				Assertions.assertEquals(original, other, value::toString);
				Assertions.assertEquals(original.hashCode(), other.hashCode(), value::toString);
			}
		}
	}

	// G7-5 and plan risk "Number cost": numbers with the largest exponents are built, hashed and compared without being
	// expanded.
	@Test
	void comparesAndHashesHugeExponentsWithoutExpandingThem() {
		Assertions.assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
			for (int count = 0; count < 10_000; ++count) {
				JsonNumber big = JsonNumber.fromValue(new BigDecimal("1E+100000"));
				JsonNumber sameBig = JsonNumber.fromValue(new BigDecimal("10E+99999"));
				JsonNumber otherBig = JsonNumber.fromValue(new BigDecimal("2E+100000"));
				JsonNumber tiny = JsonNumber.fromValue(new BigDecimal("1E-100000"));

				Assertions.assertEquals(big.hashCode(), sameBig.hashCode());
				Assertions.assertEquals(big, sameBig);
				Assertions.assertNotEquals(big, otherBig);
				Assertions.assertNotEquals(big, tiny);
				Assertions.assertEquals(Optional.empty(), big.getLongValueExact());
				Assertions.assertEquals(Optional.empty(), tiny.getLongValueExact());
				Assertions.assertEquals("1E+100000", big.toJson());
			}
		});
	}

	// Exit criterion 5 and G7-5: object equality ignores member order; arrays are ordered; strings compare exactly.
	@Test
	void objectsIgnoreMemberOrderWhileArraysAndStringsDoNot() {
		JsonObject first = JsonObject.builder().put("a", 1L).put("b", "x").putNull("c").build();
		JsonObject second = JsonObject.builder().putNull("c").put("b", "x").put("a", new BigDecimal("1.00")).build();

		Assertions.assertEquals(first, second);
		Assertions.assertEquals(first.hashCode(), second.hashCode());
		Assertions.assertNotEquals(first.toJson(), second.toJson());
		Assertions.assertNotEquals(first, JsonObject.builder().put("a", 1L).put("b", "x").build());
		Assertions.assertNotEquals(first, JsonObject.builder().put("a", 1L).put("b", "X").putNull("c").build());

		JsonArray ordered = JsonArray.fromElements(List.of(JsonNumber.fromValue(1L), JsonNumber.fromValue(2L)));
		JsonArray reversed = JsonArray.fromElements(List.of(JsonNumber.fromValue(2L), JsonNumber.fromValue(1L)));
		Assertions.assertNotEquals(ordered, reversed);
		Assertions.assertEquals(ordered, JsonArray.fromElements(List.of(JsonNumber.fromValue(new BigDecimal("1.0")),
				JsonNumber.fromValue(new BigDecimal("2E0")))));

		Assertions.assertNotEquals(JsonString.fromValue("a"), JsonString.fromValue("A"));
		Assertions.assertNotEquals(JsonString.fromValue("\u00E9"), JsonString.fromValue("e\u0301"),
				"no Unicode normalization");
		Assertions.assertNotEquals(JsonObject.builder().put("id", 1L).build(), JsonObject.builder().put("ID", 1L).build());
	}

	// The cached hash is only a shortcut: values whose hashes collide ("Aa" and "BB" share a String hash) still
	// compare their content.
	@Test
	void equalHashesStillCompareContent() {
		Assertions.assertEquals("Aa".hashCode(), "BB".hashCode());

		JsonObject first = JsonObject.builder().put("Aa", 1L).build();
		JsonObject second = JsonObject.builder().put("BB", 1L).build();
		JsonArray firstArray = JsonArray.fromElements(List.of(JsonString.fromValue("Aa")));
		JsonArray secondArray = JsonArray.fromElements(List.of(JsonString.fromValue("BB")));

		Assertions.assertEquals(first.hashCode(), second.hashCode());
		Assertions.assertNotEquals(first, second);
		Assertions.assertEquals(firstArray.hashCode(), secondArray.hashCode());
		Assertions.assertNotEquals(firstArray, secondArray);
		Assertions.assertNotEquals(JsonString.fromValue("Aa"), JsonString.fromValue("BB"));
	}

	// JsonValue's "Cost" paragraph: a value may hold one instance in several places, and toJson() writes it once per
	// occurrence, so 20 levels of [v, v] around "x" (21 objects) write 6 * 2^20 - 3 characters, while hashCode stays a
	// cached field and equals a structurally equal copy.
	@Test
	void aSharedChildIsWrittenOncePerOccurrence() {
		JsonValue shared = JsonString.fromValue("x");
		JsonValue copy = JsonString.fromValue("x");

		for (int level = 0; level < 20; ++level) {
			shared = JsonArray.fromElements(List.of(shared, shared));
			copy = JsonArray.fromElements(List.of(copy, copy));
		}

		Assertions.assertEquals(6 * (1 << 20) - 3, shared.toJson().length());
		Assertions.assertEquals(copy.hashCode(), shared.hashCode());
		Assertions.assertEquals(copy, shared);
	}

	// Each type equals only itself and values of its own type.
	@Test
	void valuesOfDifferentTypesAreNeverEqual() {
		List<JsonValue> values = List.of(JsonObject.emptyInstance(), JsonArray.emptyInstance(), JsonString.fromValue(""),
				JsonNumber.fromValue(0L), JsonBoolean.falseInstance(), JsonBoolean.trueInstance(), JsonNull.defaultInstance());

		for (int first = 0; first < values.size(); ++first)
			for (int second = 0; second < values.size(); ++second)
				Assertions.assertEquals(first == second, values.get(first).equals(values.get(second)),
						values.get(first) + " vs " + values.get(second));

		Object nothing = nullValue();

		for (JsonValue value : values) {
			Assertions.assertNotEquals(value, new Object());
			Assertions.assertFalse(value.equals(nothing));
		}
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Invariants (G7-6)
	// ---------------------------------------------------------------------------------------------------------------

	// Exit criterion 5 and G7-6: factories accept depth 64 and reject 65, where a scalar or an empty container is 1 and
	// any other container is 1 more than its deepest child (member names add nothing).
	@TestFactory
	Stream<DynamicTest> factoriesAcceptDepth64AndRejectDepth65() {
		Function<JsonValue, JsonValue> inArray = value -> JsonArray.fromElements(List.of(value));
		Function<JsonValue, JsonValue> inObject = value -> JsonObject.fromMembers(Map.of("name", value));
		Function<JsonValue, JsonValue> inBuiltObject = value -> JsonObject.builder().put("name", value).build();

		return Stream.of(
				new Object[]{"arrays around an empty array", inArray, JsonArray.emptyInstance(), 63},
				new Object[]{"arrays around a scalar", inArray, JsonNumber.fromValue(1L), 63},
				new Object[]{"objects around an empty object", inObject, JsonObject.emptyInstance(), 63},
				new Object[]{"built objects around a string", inBuiltObject, JsonString.fromValue("s"), 63})
				.map(row -> DynamicTest.dynamicTest((String) row[0], () -> {
					@SuppressWarnings("unchecked")
					Function<JsonValue, JsonValue> wrap = (Function<JsonValue, JsonValue>) row[1];
					JsonValue depth64 = (JsonValue) row[2];

					for (int count = 0; count < (Integer) row[3]; ++count)
						depth64 = wrap.apply(depth64);

					JsonValue deepest = depth64;
					Assertions.assertThrows(IllegalArgumentException.class, () -> wrap.apply(deepest));
					Assertions.assertThrows(IllegalArgumentException.class, () -> JsonArray.fromElements(List.of(deepest)));
					Assertions.assertThrows(IllegalArgumentException.class, () -> JsonObject.fromMembers(Map.of("x",
							deepest)));
					Assertions.assertThrows(IllegalArgumentException.class, () -> JsonObject.builder().put("x", deepest));
					// A shallower sibling does not change the depth; the deepest child decides.
					Assertions.assertDoesNotThrow(() -> JsonArray.fromElements(List.of(JsonNull.defaultInstance(),
							wrap.apply(JsonNull.defaultInstance()))));
					Assertions.assertEquals(deepest, deepest);
					Assertions.assertEquals(copy(deepest), deepest);
					Assertions.assertEquals(copy(deepest).hashCode(), deepest.hashCode());
				}));
	}

	// G7-6: an object's depth ignores member names, and an empty container is depth 1.
	@Test
	void countsDepthByValuesOnly() {
		JsonValue building = JsonArray.emptyInstance();

		for (int count = 1; count < 63; ++count)
			building = JsonArray.fromElements(List.of(building));

		JsonValue depth63 = building;
		JsonValue withLongNames = JsonObject.builder().put("x".repeat(1_000), depth63).put("y", JsonArray.emptyInstance())
				.build();
		Assertions.assertThrows(IllegalArgumentException.class, () -> JsonArray.fromElements(List.of(withLongNames)));
		Assertions.assertDoesNotThrow(() -> JsonObject.builder().put("z", depth63).build());
	}

	// Exit criterion 5 and G7-6: strings and member names must be well-formed UTF-16; pairs, NUL and noncharacters are
	// fine.
	@Test
	void rejectsUnpairedSurrogatesInStringsAndNames() {
		for (String bad : List.of("\uD800", "\uDFFF", "a\uD83D", "\uDE00b", "\uDE00\uD83D", "ok\uD83D\uDE00\uD800")) {
			assertInvalid(() -> JsonString.fromValue(bad));
			assertInvalid(() -> JsonObject.builder().putNull(bad));
			assertInvalid(() -> JsonObject.builder().put("name", bad));
			assertInvalid(() -> JsonObject.fromMembers(Map.of(bad, JsonNull.defaultInstance())));
		}

		String good = "\uD83D\uDE00 \u0000 \uFFFF \uDBFF\uDFFF";
		Assertions.assertEquals(good, JsonString.fromValue(good).getValue());
		Assertions.assertTrue(JsonObject.builder().put(good, good).build().getMembers().containsKey(good));
	}

	// Exit criterion 5 and G7-6: a number has at most 4,096 digits and an adjusted exponent of magnitude at most
	// 100,000, zero included.
	@Test
	void enforcesTheNumberDigitAndExponentCaps() {
		Assertions.assertEquals(4_096, JsonNumber.fromValue(new BigDecimal("9".repeat(4_096))).getValue().precision());
		assertInvalid(() -> JsonNumber.fromValue(new BigDecimal("9".repeat(4_097))));
		assertInvalid(() -> JsonNumber.fromValue(new BigDecimal("1" + "0".repeat(4_096))));
		assertInvalid(() -> JsonNumber.fromValue(new BigDecimal(BigInteger.TEN.pow(20_000))));
		Assertions.assertDoesNotThrow(() -> JsonNumber.fromValue(new BigDecimal("1" + "0".repeat(4_095))));
		Assertions.assertDoesNotThrow(() -> JsonNumber.fromValue(new BigDecimal("0." + "0".repeat(4_095) + "1")));

		for (String allowed : List.of("1E+100000", "9.99E+100000", "1E-100000", "-1E-100000", "0E+100000", "0E-100000"))
			Assertions.assertDoesNotThrow(() -> JsonNumber.fromValue(new BigDecimal(allowed)), allowed);

		for (String rejected : List.of("1E+100001", "1E-100001", "10E+100000", "0.1E-100000", "0E+100001", "0E-100001",
				"1E+2147483647"))
			assertInvalid(() -> JsonNumber.fromValue(new BigDecimal(rejected)));

		assertInvalid(() -> JsonObject.builder().put("n", new BigDecimal("1E+100001")));
	}

	// G7-6 and R9 (Effective Java item 50): BigDecimal is not final, so fromValue copies a subclass into a plain
	// BigDecimal before any check. A subclass can then neither render as other JSON text in toJson(), nor change after
	// the number exists, nor understate its precision to pass the digit cap, nor keep a BigInteger subclass inside.
	@Test
	void copiesBigDecimalSubclassesBeforeCheckingThem() {
		JsonNumber rendered = JsonNumber.fromValue(new RendersAsOtherJson());
		Assertions.assertEquals("1", rendered.toJson());
		Assertions.assertSame(BigDecimal.class, rendered.getValue().getClass());
		Assertions.assertEquals("{\"n\":1}", JsonObject.builder().put("n", new RendersAsOtherJson()).build().toJson());

		ChangesLater changing = new ChangesLater();
		JsonNumber snapshot = JsonNumber.fromValue(changing);
		changing.rendering = "\"changed\"";
		Assertions.assertEquals("2", snapshot.toJson());
		Assertions.assertEquals(JsonNumber.fromValue(2L), snapshot);

		assertInvalid(() -> JsonNumber.fromValue(new UnderstatesItsPrecision()));
		assertInvalid(() -> JsonObject.builder().put("n", new UnderstatesItsPrecision()));

		JsonNumber unscaled = JsonNumber.fromValue(new HoldsABigIntegerSubclass());
		Assertions.assertEquals("12345678901234567890123", unscaled.toJson());
		Assertions.assertSame(BigInteger.class, unscaled.getValue().unscaledValue().getClass());
	}

	// R15: every factory, builder method and lookup rejects null with NullPointerException.
	@Test
	void rejectsNullEverywhere() {
		String noString = nullValue();
		JsonValue noValue = nullValue();
		BigDecimal noDecimal = nullValue();
		Long noLong = nullValue();
		Boolean noBoolean = nullValue();
		List<JsonValue> noList = nullValue();
		Map<String, JsonValue> noMap = nullValue();
		JsonObject object = JsonObject.builder().put("a", 1L).build();

		for (Executable call : List.<Executable>of(
				() -> JsonString.fromValue(noString),
				() -> JsonNumber.fromValue(noDecimal),
				() -> JsonNumber.fromValue(noLong),
				() -> JsonBoolean.fromValue(noBoolean),
				() -> JsonArray.fromElements(noList),
				() -> JsonArray.fromElements(Arrays.asList(JsonNull.defaultInstance(), noValue)),
				() -> JsonObject.fromMembers(noMap),
				() -> JsonObject.fromMembers(mapWith(noString, JsonNull.defaultInstance())),
				() -> JsonObject.fromMembers(mapWith("a", noValue)),
				() -> JsonObject.builder().put(noString, JsonNull.defaultInstance()),
				() -> JsonObject.builder().put("a", noValue),
				() -> JsonObject.builder().put("a", noString),
				() -> JsonObject.builder().put("a", noLong),
				() -> JsonObject.builder().put("a", noDecimal),
				() -> JsonObject.builder().put("a", noBoolean),
				() -> JsonObject.builder().putNull(noString),
				() -> object.find(noString),
				() -> object.findString(noString),
				() -> object.findLong(noString),
				() -> object.findBoolean(noString),
				() -> object.findStringList(noString)))
			Assertions.assertThrows(NullPointerException.class, call);
	}

	// R9: invariant failures have fixed messages that never contain the rejected value.
	@Test
	void invariantFailuresNeverEchoTheValue() {
		for (Executable call : List.<Executable>of(
				() -> JsonString.fromValue(SECRET + "\uD800"),
				() -> JsonObject.builder().putNull(SECRET + "\uDC00"),
				() -> JsonObject.builder().put(SECRET, 1L).put(SECRET, 2L),
				() -> JsonNumber.fromValue(new BigDecimal("1" + "0".repeat(5_000))))) {
			IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, call);
			Sentinels.assertAbsent(exception);
		}
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Builder and snapshots (G7-8)
	// ---------------------------------------------------------------------------------------------------------------

	// G7-8 and NAMING_CONVENTIONS.md: put adds one member per call, and a name already present throws instead of
	// replacing the earlier value, whichever overload adds it.
	@Test
	void builderRejectsARepeatedNameWithEveryOverload() {
		List<Function<JsonObject.Builder, JsonObject.Builder>> puts = List.of(
				builder -> builder.put("a", JsonNull.defaultInstance()),
				builder -> builder.put("a", "s"),
				builder -> builder.put("a", 1L),
				builder -> builder.put("a", BigDecimal.ONE),
				builder -> builder.put("a", true),
				builder -> builder.putNull("a"));

		for (Function<JsonObject.Builder, JsonObject.Builder> first : puts)
			for (Function<JsonObject.Builder, JsonObject.Builder> second : puts) {
				JsonObject.Builder builder = first.apply(JsonObject.builder());
				JsonObject before = builder.build();
				IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class,
						() -> second.apply(builder));
				Assertions.assertEquals("A JSON object must not contain two members with the same name.",
						exception.getMessage());
				Assertions.assertEquals(before, builder.build(), "a rejected put changes nothing");
			}

		Assertions.assertEquals(2, JsonObject.builder().put("a", 1L).put("A", 1L).build().getMembers().size());
	}

	// G7-8: the builder keeps insertion order; build() returns a snapshot, and later puts do not change it.
	@Test
	void builderReturnsInsertionOrderedSnapshots() {
		JsonObject.Builder builder = JsonObject.builder().put("z", 1L).put("a", "x").put("m", true).putNull("b")
				.put("n", new BigDecimal("1.50"));
		JsonObject first = builder.build();
		builder.put("later", 2L);

		Assertions.assertEquals(List.of("z", "a", "m", "b", "n"), List.copyOf(first.getMembers().keySet()));
		Assertions.assertEquals("{\"z\":1,\"a\":\"x\",\"m\":true,\"b\":null,\"n\":1.50}", first.toJson());
		Assertions.assertEquals(6, builder.build().getMembers().size());
		Assertions.assertSame(JsonObject.emptyInstance(), JsonObject.builder().build());
	}

	// fromMembers and fromElements snapshot their arguments, keep the source's order, and expose unmodifiable views.
	@Test
	void factoriesSnapshotTheirArgumentsAndExposeUnmodifiableViews() {
		LinkedHashMap<String, JsonValue> members = new LinkedHashMap<>();
		members.put("b", JsonNumber.fromValue(2L));
		members.put("a", JsonNumber.fromValue(1L));
		List<JsonValue> elements = new ArrayList<>(List.of(JsonString.fromValue("x")));

		JsonObject object = JsonObject.fromMembers(members);
		JsonArray array = JsonArray.fromElements(elements);
		members.put("c", JsonNull.defaultInstance());
		elements.add(JsonNull.defaultInstance());

		Assertions.assertEquals("{\"b\":2,\"a\":1}", object.toJson());
		Assertions.assertEquals("[\"x\"]", array.toJson());
		Assertions.assertThrows(UnsupportedOperationException.class, () -> object.getMembers().put("c",
				JsonNull.defaultInstance()));
		Assertions.assertThrows(UnsupportedOperationException.class, () -> object.getMembers().clear());
		Assertions.assertThrows(UnsupportedOperationException.class, () -> array.getElements().add(JsonNull
				.defaultInstance()));
		Assertions.assertSame(JsonObject.emptyInstance(), JsonObject.fromMembers(Map.of()));
		Assertions.assertSame(JsonArray.emptyInstance(), JsonArray.fromElements(List.of()));
	}

	// A map that holds two equal names (an identity map can) is rejected rather than silently merged.
	@Test
	void fromMembersRejectsEqualNamesFromAnIdentityMap() {
		IdentityHashMap<String, JsonValue> members = new IdentityHashMap<>();
		members.put(new String("id"), JsonNumber.fromValue(1L));
		members.put(new String("id"), JsonNumber.fromValue(2L));

		Assertions.assertEquals(2, members.size());
		assertInvalid(() -> JsonObject.fromMembers(members));
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Lookups
	// ---------------------------------------------------------------------------------------------------------------

	// The findX conveniences return empty for an absent member and for a member of another type alike, which is why
	// protocol validation never uses them.
	@Test
	void findHelpersReturnEmptyForAbsentAndMistypedMembers() {
		JsonObject object = JsonObject.builder()
				.put("s", "text")
				.put("n", 42L)
				.put("f", new BigDecimal("42.5"))
				.put("w", new BigDecimal("4.2E+1"))
				.put("big", new BigDecimal("9223372036854775808"))
				.put("t", true)
				.putNull("z")
				.put("list", JsonArray.fromElements(List.of(JsonString.fromValue("a"), JsonString.fromValue("b"))))
				.put("mixed", JsonArray.fromElements(List.of(JsonString.fromValue("a"), JsonNumber.fromValue(1L))))
				.put("empty", JsonArray.emptyInstance())
				.build();

		Assertions.assertEquals(Optional.of(JsonNull.defaultInstance()), object.find("z"));
		Assertions.assertEquals(Optional.empty(), object.find("absent"));
		Assertions.assertEquals(Optional.of("text"), object.findString("s"));
		Assertions.assertEquals(Optional.of(42L), object.findLong("n"));
		Assertions.assertEquals(Optional.of(42L), object.findLong("w"));
		Assertions.assertEquals(Optional.of(true), object.findBoolean("t"));
		Assertions.assertEquals(Optional.of(List.of("a", "b")), object.findStringList("list"));
		Assertions.assertEquals(Optional.of(List.of()), object.findStringList("empty"));

		for (String name : List.of("n", "t", "z", "list", "absent"))
			Assertions.assertEquals(Optional.empty(), object.findString(name), name);
		for (String name : List.of("s", "f", "big", "t", "z", "absent"))
			Assertions.assertEquals(Optional.empty(), object.findLong(name), name);
		for (String name : List.of("s", "n", "z", "absent"))
			Assertions.assertEquals(Optional.empty(), object.findBoolean(name), name);
		for (String name : List.of("s", "mixed", "z", "absent"))
			Assertions.assertEquals(Optional.empty(), object.findStringList(name), name);

		Assertions.assertThrows(UnsupportedOperationException.class, () -> object.findStringList("list").orElseThrow()
				.add("c"));
	}

	// getLongValueExact: whole numbers in the range of long, whatever their scale; nothing else.
	@TestFactory
	Stream<DynamicTest> readsLongsExactly() {
		Map<String, Optional<Long>> cases = new LinkedHashMap<>();
		cases.put("0", Optional.of(0L));
		cases.put("-0.000", Optional.of(0L));
		cases.put("0E+100000", Optional.of(0L));
		cases.put("42.000", Optional.of(42L));
		cases.put("4.2E+1", Optional.of(42L));
		cases.put("9223372036854775807", Optional.of(Long.MAX_VALUE));
		cases.put("-9223372036854775808", Optional.of(Long.MIN_VALUE));
		cases.put("9.223372036854775807E+18", Optional.of(Long.MAX_VALUE));
		cases.put("1" + "." + "0".repeat(4_000), Optional.of(1L));
		cases.put("9223372036854775808", Optional.empty());
		cases.put("-9223372036854775809", Optional.empty());
		cases.put("1E+19", Optional.empty());
		cases.put("0.5", Optional.empty());
		cases.put("42.0000000001", Optional.empty());
		cases.put("1E-100000", Optional.empty());
		cases.put("1E+100000", Optional.empty());

		return cases.entrySet().stream().map(entry -> DynamicTest.dynamicTest(abbreviate(entry.getKey()),
				() -> Assertions.assertEquals(entry.getValue(), JsonNumber.fromValue(new BigDecimal(entry.getKey()))
						.getLongValueExact())));
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Rendering (R9, G7-4)
	// ---------------------------------------------------------------------------------------------------------------

	// Exit criterion 5 and R9: every toString() renders SimpleName{...=<redacted>} and never content, while toJson()
	// is the one method that emits it (the positive control).
	@Test
	void everyToStringIsRedacted() {
		Map<JsonValue, String> renderings = new LinkedHashMap<>();
		renderings.put(JsonObject.builder().put(SECRET, SECRET).build(), "JsonObject{members=<redacted>}");
		renderings.put(JsonArray.fromElements(List.of(JsonString.fromValue(SECRET))), "JsonArray{elements=<redacted>}");
		renderings.put(JsonString.fromValue(SECRET), "JsonString{value=<redacted>}");
		renderings.put(JsonNumber.fromValue(new BigDecimal("1234567890.1234567890")), "JsonNumber{value=<redacted>}");
		renderings.put(JsonBoolean.trueInstance(), "JsonBoolean{value=<redacted>}");
		renderings.put(JsonNull.defaultInstance(), "JsonNull{value=<redacted>}");

		for (Map.Entry<JsonValue, String> rendering : renderings.entrySet()) {
			Assertions.assertEquals(rendering.getValue(), rendering.getKey().toString());
			Assertions.assertTrue(rendering.getKey().toString().startsWith(rendering.getKey().getClass().getSimpleName()
					+ "{"));
		}

		JsonObject.Builder builder = JsonObject.builder().put(SECRET, SECRET);
		Assertions.assertEquals("JsonObject.Builder{members=<redacted>}", builder.toString());

		JsonObject holder = builder.build();
		Assertions.assertFalse(Sentinels.containsSentinel(holder.toString()));
		Assertions.assertTrue(holder.toJson().contains(SECRET), "positive control: toJson emits content");
		Sentinels.assertPresent(holder);
	}

	// Exit criterion 5 and G7-4: toJson() writes BigDecimal.toString(), the canonical form, not the parsed text.
	@TestFactory
	Stream<DynamicTest> writesTheCanonicalNumberForm() {
		return Stream.of(
				new String[]{"1e2", "1E+2"}, new String[]{"-0", "0"}, new String[]{"-0.0", "0.0"},
				new String[]{"1.50", "1.50"}, new String[]{"0.000001", "0.000001"}, new String[]{"1e-6", "0.000001"},
				new String[]{"1e-7", "1E-7"}, new String[]{"123456789012", "123456789012"},
				new String[]{"12.3e5", "1.23E+6"}, new String[]{"1E+100000", "1E+100000"},
				new String[]{"-1.5e-100000", "-1.5E-100000"}, new String[]{"0e5", "0E+5"})
				.map(row -> DynamicTest.dynamicTest(row[0] + " -> " + row[1], () -> Assertions.assertEquals(row[1],
						JsonNumber.fromValue(new BigDecimal(row[0])).toJson())));
	}

	// RFC 8259 section 7: strings escape only the quotation mark, the reverse solidus and U+0000 to U+001F; the
	// solidus, DEL, U+2028, U+2029 and non-ASCII characters are written as themselves.
	@Test
	void escapesOnlyWhatJsonRequires() {
		StringBuilder controls = new StringBuilder();

		for (char character = 0; character < 0x20; ++character)
			controls.append(character);

		Assertions.assertEquals("\"\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007\\b\\t\\n\\u000b\\f\\r\\u000e"
				+ "\\u000f\\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016\\u0017\\u0018\\u0019\\u001a\\u001b\\u001c\\u001d"
				+ "\\u001e\\u001f\"", JsonString.fromValue(controls.toString()).toJson());
		Assertions.assertEquals("\"\\\"\\\\/\u007F\u2028\u2029\u00E9\uD83D\uDE80\"",
				JsonString.fromValue("\"\\/\u007F\u2028\u2029\u00E9\uD83D\uDE80").toJson());
		Assertions.assertEquals("{\"a\\\"b\":[true,false,null,{},[]]}", JsonObject.builder().put("a\"b",
				JsonArray.fromElements(List.of(JsonBoolean.trueInstance(), JsonBoolean.falseInstance(),
						JsonNull.defaultInstance(), JsonObject.emptyInstance(), JsonArray.emptyInstance()))).build().toJson());
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Shape of the API (G7-2, G7-6, R19)
	// ---------------------------------------------------------------------------------------------------------------

	// R19: JsonValue is sealed to exactly the six types, each final; JsonNull is a class, not an enum; the booleans and
	// null are shared instances.
	@Test
	void jsonValueIsSealedToSixFinalTypes() {
		Set<Class<?>> permitted = Arrays.stream(JsonValue.class.getPermittedSubclasses()).collect(Collectors.toSet());

		Assertions.assertTrue(JsonValue.class.isSealed());
		Assertions.assertEquals(Set.of(JsonObject.class, JsonArray.class, JsonString.class, JsonNumber.class,
				JsonBoolean.class, JsonNull.class), permitted);

		for (Class<?> type : permitted)
			Assertions.assertTrue(Modifier.isFinal(type.getModifiers()), type::getName);

		Assertions.assertFalse(JsonNull.class.isEnum());
		Assertions.assertSame(JsonNull.defaultInstance(), JsonNull.defaultInstance());
		Assertions.assertSame(JsonBoolean.trueInstance(), JsonBoolean.fromValue(true));
		Assertions.assertSame(JsonBoolean.falseInstance(), JsonBoolean.fromValue(false));
		Assertions.assertTrue(JsonBoolean.trueInstance().getValue());
		Assertions.assertFalse(JsonBoolean.falseInstance().getValue());
		Assertions.assertNotEquals(JsonBoolean.trueInstance().hashCode(), JsonBoolean.falseInstance().hashCode());
		Assertions.assertSame(JsonObject.emptyInstance(), JsonObject.emptyInstance());
		Assertions.assertSame(JsonArray.emptyInstance(), JsonArray.emptyInstance());
		Assertions.assertEquals("{}", JsonObject.emptyInstance().toJson());
		Assertions.assertEquals("true", JsonBoolean.trueInstance().toJson());
		Assertions.assertEquals("false", JsonBoolean.falseInstance().toJson());
		Assertions.assertEquals("null", JsonNull.defaultInstance().toJson());
		Assertions.assertEquals("[]", JsonArray.emptyInstance().toJson());
	}

	// Values work as keys of hash-based collections.
	@Test
	void valuesWorkAsHashMapKeys() {
		Map<JsonValue, String> map = new HashMap<>();
		map.put(JsonNumber.fromValue(new BigDecimal("1.0")), "one");
		map.put(JsonObject.builder().put("a", 1L).put("b", 2L).build(), "object");

		Assertions.assertEquals("one", map.get(JsonNumber.fromValue(1L)));
		Assertions.assertEquals("object", map.get(JsonObject.builder().put("b", 2L).put("a", new BigDecimal("1E0"))
				.build()));
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Helpers
	// ---------------------------------------------------------------------------------------------------------------

	private static void assertInvalid(Executable call) {
		Assertions.assertThrows(IllegalArgumentException.class, call);
	}

	/**
	 * A structurally equal copy built through the factories, so equality is not identity.
	 */
	private static JsonValue copy(JsonValue value) {
		if (value instanceof JsonObject object) {
			JsonObject.Builder builder = JsonObject.builder();
			object.getMembers().forEach((name, member) -> builder.put(name, copy(member)));
			return builder.build();
		}

		if (value instanceof JsonArray array)
			return JsonArray.fromElements(array.getElements().stream().map(JsonModelTests::copy).toList());

		if (value instanceof JsonString string)
			return JsonString.fromValue(new String(string.getValue()));

		if (value instanceof JsonNumber number)
			return JsonNumber.fromValue(new BigDecimal(number.getValue().unscaledValue(), number.getValue().scale()));

		return value;
	}

	private static Map<String, JsonValue> mapWith(String name, JsonValue value) {
		Map<String, JsonValue> map = new HashMap<>();
		map.put(name, value);
		return map;
	}

	private static String abbreviate(String text) {
		return text.length() <= 40 ? text : text.substring(0, 40) + "... (" + text.length() + " characters)";
	}

	/**
	 * Hides a {@code null} from NullAway, for the tests that check null handling (R15).
	 */
	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> T nullValue() {
		return null;
	}

	/**
	 * A {@link BigDecimal} worth 1 that renders itself as JSON text with an extra member.
	 */
	private static final class RendersAsOtherJson extends BigDecimal {
		private static final long serialVersionUID = 1L;

		private RendersAsOtherJson() {
			super("1");
		}

		@Override
		public String toString() {
			return "1,\"admin\":true";
		}
	}

	/**
	 * A {@link BigDecimal} worth 2 whose rendering can change after it is passed on.
	 */
	private static final class ChangesLater extends BigDecimal {
		private static final long serialVersionUID = 1L;

		private String rendering = "2";

		private ChangesLater() {
			super("2");
		}

		@Override
		public String toString() {
			return this.rendering;
		}
	}

	/**
	 * A {@link BigDecimal} with 4,097 digits (10^4096) that reports a precision of 1.
	 */
	private static final class UnderstatesItsPrecision extends BigDecimal {
		private static final long serialVersionUID = 1L;

		private UnderstatesItsPrecision() {
			super(BigInteger.TEN.pow(4_096));
		}

		@Override
		public int precision() {
			return 1;
		}
	}

	/**
	 * A {@link BigInteger} that renders itself as JSON text with an extra member.
	 */
	private static final class RendersAsOtherJsonInteger extends BigInteger {
		private static final long serialVersionUID = 1L;

		private RendersAsOtherJsonInteger() {
			super("12345678901234567890123");
		}

		@Override
		public String toString() {
			return "1,\"admin\":true";
		}
	}

	/**
	 * A {@link BigDecimal} whose unscaled value is a {@link BigInteger} subclass.
	 */
	private static final class HoldsABigIntegerSubclass extends BigDecimal {
		private static final long serialVersionUID = 1L;

		private HoldsABigIntegerSubclass() {
			super("12345678901234567890123");
		}

		@Override
		public BigInteger unscaledValue() {
			return new RendersAsOtherJsonInteger();
		}
	}
}
