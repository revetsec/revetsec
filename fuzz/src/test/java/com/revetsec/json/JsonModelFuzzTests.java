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

import org.jspecify.annotations.Nullable;

import org.jspecify.annotations.NonNull;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonFuzzSupport;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import org.junit.jupiter.api.Assertions;

import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Coverage-guided checks for the public JSON model's invariants (G7-5, G7-6 and G7-8; exit criteria 5 and 18).
 * <p>
 * {@link #factoriesAcceptExactlyTheValuesInsideTheModelInvariants(FuzzedDataProvider)} drives the factories and the
 * builder directly, with inputs the codec never produces: unpaired surrogates, numbers past the digit and exponent
 * caps, {@code BigDecimal} subclasses that lie about themselves, repeated builder names and nesting past 64 levels.
 * {@link #parsedValuesKeepEqualityUnderReorderingAndRescaling(byte[])} takes JSON text (the core corpus and
 * JSONTestSuite are its seeds, as for the codec target) and checks equality, hashing and the lookup methods on what
 * the maximum-cap profile parses.
 * <p>
 * Every {@link IllegalArgumentException} must carry one of the model's fixed messages, which are collected once from
 * known-bad values; a message that echoed its input would not be in that set (R9).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public class JsonModelFuzzTests {
	private static final int MAXIMUM_DEPTH = JsonLimits.MODEL_MAXIMUM_DEPTH;
	private static final int MAXIMUM_DIGITS = JsonLimits.MODEL_MAXIMUM_NUMBER_DIGITS;
	private static final int MAXIMUM_EXPONENT = JsonLimits.MODEL_MAXIMUM_EXPONENT_MAGNITUDE;
	/**
	 * Bounds the work of one input: values built per input, and bytes of a fuzzed unscaled value (about 16,000 bits,
	 * past the 13,607 bits that 4,096 digits need).
	 */
	private static final int MAXIMUM_VALUES = 256;
	private static final int MAXIMUM_UNSCALED_BYTES = 2_000;
	private static final JsonLimits MAXIMUM_CAPS = JsonFuzzSupport.maximumCaps();

	private static final String SURROGATE_MESSAGE = messageOf(() -> JsonString.fromValue("\uD800"));
	private static final String DIGITS_MESSAGE = messageOf(() -> JsonNumber.fromValue(
			BigDecimal.TEN.pow(MAXIMUM_DIGITS)));
	private static final String EXPONENT_MESSAGE = messageOf(() -> JsonNumber.fromValue(
			BigDecimal.ONE.scaleByPowerOfTen(MAXIMUM_EXPONENT + 1)));
	private static final String DEPTH_MESSAGE = messageOf(() -> nested(JsonNull.defaultInstance(), MAXIMUM_DEPTH,
			false));
	private static final String DUPLICATE_MESSAGE = messageOf(() -> JsonObject.builder().putNull("a").putNull("a"));

	/**
	 * Each public factory and builder method accepts exactly the values that satisfy G7-6, as an independent oracle
	 * computes them, and rejects the rest with {@link IllegalArgumentException} carrying the fixed message of the first
	 * failed check: an unpaired surrogate in a string or name, more than 4,096 digits, an adjusted exponent beyond
	 * &plusmn;100,000, depth above 64, or a repeated builder name (G7-8). Numbers are copied to exact
	 * {@code BigDecimal}s, so a subclass cannot lie its way past the caps or into {@code toJson()}. Every accepted value
	 * keeps its invariants: {@code toJson()}, {@code equals} and {@code hashCode} never throw, {@code toString()} is
	 * redacted, a copy rebuilt here with its members reversed and its numbers rescaled is equal with an equal
	 * hash (G7-5), and {@code toJson()} parses back to an equal value under the maximum-cap profile unless a number's
	 * canonical form is longer than 4,096 characters, which is then {@code NUMBER_LENGTH}.
	 *
	 * @param data the fuzzed construction program
	 */
	@FuzzTest(maxDuration = "5m")
	public void factoriesAcceptExactlyTheValuesInsideTheModelInvariants(@NonNull FuzzedDataProvider data) {
		Program program = new Program(data);
		Built built = program.value(4);

		if (built.value != null)
			requireInvariants(built.value);
	}

	/**
	 * For every value the maximum-cap profile parses: a copy rebuilt through the public factories, with object members
	 * in reverse order and every number rescaled (so {@code 1} becomes {@code 1.0}), is equal with an equal hash
	 * (G7-5); changing any one leaf makes it unequal; reversing an array whose ends differ makes it unequal; and the
	 * {@code find} methods agree with {@link JsonObject#getMembers()} for every member.
	 *
	 * @param input the fuzzed document
	 */
	@FuzzTest(maxDuration = "5m")
	public void parsedValuesKeepEqualityUnderReorderingAndRescaling(byte @NonNull [] input) {
		JsonValue value;

		try {
			value = JsonCodec.parse(input, MAXIMUM_CAPS);
		} catch (JsonParseException e) {
			JsonFuzzSupport.requireFixedShape(e, input.length);
			return;
		}

		requireInvariants(value);
		JsonValue mutated = withFirstLeafChanged(value);
		Assertions.assertNotEquals(value, mutated, "changing one leaf left the value equal");
		Assertions.assertNotEquals(mutated, value, "changing one leaf left the value equal");
		requireOrderedArrays(value);
		requireLookupsAgree(value);
	}

	/**
	 * The invariants every value the model holds keeps (G7-5, G7-6, R9).
	 */
	private static void requireInvariants(@NonNull JsonValue value) {
		JsonFuzzSupport.Shape shape = JsonFuzzSupport.shapeOf(value);
		Assertions.assertTrue(shape.getDepth() <= MAXIMUM_DEPTH, "the model holds a value deeper than 64");
		Assertions.assertEquals(shape.getDepth(), JsonInvariants.depthOf(value), "the model's depth is wrong");
		Assertions.assertTrue(shape.getMostDigits() <= MAXIMUM_DIGITS, "the model holds too many digits");
		Assertions.assertTrue(shape.getLargestAdjustedExponent() <= MAXIMUM_EXPONENT, "the model holds a large exponent");
		Assertions.assertFalse(shape.hasInexactNumberClass(), "the model holds a BigDecimal subclass");
		requireRedacted(value);

		String json = value.toJson();
		byte[] utf8 = JsonCodec.toUtf8Bytes(value);
		Assertions.assertEquals(json, new String(utf8, StandardCharsets.UTF_8), "toJson() and toUtf8Bytes() disagree");

		JsonValue copy = rebuilt(value);
		Assertions.assertEquals(value, value, "a value is not equal to itself");
		Assertions.assertEquals(value, copy, "a reordered, rescaled copy is not equal");
		Assertions.assertEquals(copy, value, "equality is not symmetric");
		Assertions.assertEquals(value.hashCode(), copy.hashCode(), "equal values have different hashes");

		try {
			JsonValue reparsed = JsonCodec.parse(utf8, MAXIMUM_CAPS);
			Assertions.assertTrue(shape.getLongestCanonicalNumber() <= MAXIMUM_DIGITS,
					"parsed a number whose canonical form is longer than the maximum-cap profile allows");
			Assertions.assertEquals(value, reparsed, "toJson() did not parse back to an equal value");
			Assertions.assertEquals(value.hashCode(), reparsed.hashCode(), "the round trip changed the hash");
		} catch (JsonParseException e) {
			JsonFuzzSupport.requireFixedShape(e, utf8.length);
			Assertions.assertTrue(shape.getLongestCanonicalNumber() > MAXIMUM_DIGITS,
					() -> "toJson() of a model value did not parse: " + e.getKind());
			Assertions.assertEquals(JsonParseException.Kind.NUMBER_LENGTH, e.getKind(), "expected NUMBER_LENGTH");
		}
	}

	private static void requireRedacted(@NonNull JsonValue value) {
		JsonFuzzSupport.requireRedactedToString(value);

		if (value instanceof JsonObject object)
			for (JsonValue member : object.getMembers().values())
				requireRedacted(member);
		else if (value instanceof JsonArray array)
			for (JsonValue element : array.getElements())
				requireRedacted(element);
	}

	/**
	 * Rebuilds a value through the public factories: object members reversed, arrays in order, strings copied, and
	 * numbers rescaled by one digit where the digit cap allows, which G7-5 says is the same number.
	 */
	private static @NonNull JsonValue rebuilt(@NonNull JsonValue value) {
		if (value instanceof JsonObject object) {
			List<Map.Entry<String, JsonValue>> members = new ArrayList<>(object.getMembers().entrySet());
			Collections.reverse(members);
			LinkedHashMap<String, JsonValue> reversed = new LinkedHashMap<>();

			for (Map.Entry<String, JsonValue> member : members)
				reversed.put(new String(member.getKey().toCharArray()), rebuilt(member.getValue()));

			return JsonObject.fromMembers(reversed);
		}

		if (value instanceof JsonArray array) {
			List<JsonValue> elements = new ArrayList<>();

			for (JsonValue element : array.getElements())
				elements.add(rebuilt(element));

			return JsonArray.fromElements(elements);
		}

		if (value instanceof JsonString string)
			return JsonString.fromValue(new String(string.getValue().toCharArray()));

		if (value instanceof JsonNumber number) {
			BigDecimal decimal = number.getValue();

			// Zero's adjusted exponent is minus its scale, so zero is rescaled toward scale 0, which keeps it inside the
			// exponent cap; 0E-100000 is accepted and the equal 0E-100001 is not (found by this target).
			if (decimal.signum() == 0)
				return JsonNumber.fromValue(decimal.setScale(decimal.scale() > 0 ? decimal.scale() - 1 : decimal.scale() + 1,
						RoundingMode.UNNECESSARY));

			// Any other number gains one trailing zero, which keeps its adjusted exponent.
			if (decimal.precision() < MAXIMUM_DIGITS)
				return JsonNumber.fromValue(decimal.setScale(decimal.scale() + 1, RoundingMode.UNNECESSARY));

			return JsonNumber.fromValue(new BigDecimal(decimal.unscaledValue(), decimal.scale()));
		}

		if (value instanceof JsonBoolean bool)
			return JsonBoolean.fromValue(Boolean.valueOf(bool.getValue().booleanValue()));

		return JsonNull.defaultInstance();
	}

	/**
	 * The value with the first leaf, in depth-first order, replaced by an unequal one; an empty container is a leaf.
	 */
	private static @NonNull JsonValue withFirstLeafChanged(@NonNull JsonValue value) {
		if (value instanceof JsonObject object && !object.getMembers().isEmpty()) {
			LinkedHashMap<String, JsonValue> members = new LinkedHashMap<>(object.getMembers());
			Map.Entry<String, JsonValue> first = members.entrySet().iterator().next();
			members.put(first.getKey(), withFirstLeafChanged(first.getValue()));
			return JsonObject.fromMembers(members);
		}

		if (value instanceof JsonArray array && !array.getElements().isEmpty()) {
			List<JsonValue> elements = new ArrayList<>(array.getElements());
			elements.set(0, withFirstLeafChanged(elements.get(0)));
			return JsonArray.fromElements(elements);
		}

		// An empty container becomes a scalar, never a deeper container, so the result stays within 64 levels.
		if (value instanceof JsonObject || value instanceof JsonArray)
			return JsonNull.defaultInstance();

		if (value instanceof JsonString string)
			return JsonString.fromValue(string.getValue() + "\u0000");

		if (value instanceof JsonNumber number)
			return JsonNumber.fromValue(number.getValue().signum() == 0 ? BigDecimal.ONE : number.getValue().negate());

		if (value instanceof JsonBoolean bool)
			return JsonBoolean.fromValue(Boolean.valueOf(!bool.getValue().booleanValue()));

		return JsonBoolean.falseInstance();
	}

	/**
	 * Arrays are ordered (G7-5): reversing one whose first and last elements differ gives an unequal array.
	 */
	private static void requireOrderedArrays(@NonNull JsonValue value) {
		if (value instanceof JsonArray array) {
			List<JsonValue> elements = array.getElements();

			if (elements.size() >= 2 && !elements.get(0).equals(elements.get(elements.size() - 1))) {
				List<JsonValue> reversed = new ArrayList<>(elements);
				Collections.reverse(reversed);
				Assertions.assertNotEquals(array, JsonArray.fromElements(reversed), "array equality ignores order");
			}

			for (JsonValue element : elements)
				requireOrderedArrays(element);
		} else if (value instanceof JsonObject object) {
			for (JsonValue member : object.getMembers().values())
				requireOrderedArrays(member);
		}
	}

	/**
	 * The {@code find} methods agree with {@link JsonObject#getMembers()}, at every level.
	 */
	private static void requireLookupsAgree(@NonNull JsonValue value) {
		if (value instanceof JsonArray array) {
			for (JsonValue element : array.getElements())
				requireLookupsAgree(element);
			return;
		}

		if (!(value instanceof JsonObject object))
			return;

		for (Map.Entry<String, JsonValue> member : object.getMembers().entrySet()) {
			String name = member.getKey();
			JsonValue memberValue = member.getValue();

			Assertions.assertEquals(Optional.of(memberValue), object.find(name), "find() disagrees with getMembers()");
			Assertions.assertEquals(memberValue instanceof JsonString string ? Optional.of(string.getValue())
					: Optional.empty(), object.findString(name), "findString() disagrees with getMembers()");
			Assertions.assertEquals(memberValue instanceof JsonBoolean bool ? Optional.of(bool.getValue())
					: Optional.empty(), object.findBoolean(name), "findBoolean() disagrees with getMembers()");
			Assertions.assertEquals(memberValue instanceof JsonNumber number ? exactLong(number.getValue())
					: Optional.empty(), object.findLong(name), "findLong() disagrees with getMembers()");
			Assertions.assertEquals(stringList(memberValue), object.findStringList(name),
					"findStringList() disagrees with getMembers()");
			requireLookupsAgree(memberValue);
		}

		// A name the object does not hold: the empty name with a NUL appended to the longest name.
		String absent = object.getMembers().keySet().stream().reduce("", (a, b) -> a.length() >= b.length() ? a : b)
				+ "\u0000";
		Assertions.assertEquals(Optional.empty(), object.find(absent), "find() found an absent name");
	}

	/**
	 * The oracle for {@link JsonNumber#getLongValueExact()}: the value as a long if it is an integer in range, found
	 * without {@code stripTrailingZeros} (a CPU amplifier on large exponents, M1 plan "Risks").
	 */
	private static @NonNull Optional<@NonNull Long> exactLong(@NonNull BigDecimal value) {
		if (value.signum() == 0)
			return Optional.of(0L);

		long adjustedExponent = (long) value.precision() - value.scale() - 1;

		if (adjustedExponent < 0 || adjustedExponent > 18)
			return Optional.empty();

		BigInteger integer;

		try {
			integer = value.setScale(0, RoundingMode.UNNECESSARY).toBigIntegerExact();
		} catch (ArithmeticException fractional) {
			return Optional.empty();
		}

		return integer.bitLength() <= 63 ? Optional.of(integer.longValue()) : Optional.empty();
	}

	private static @NonNull Optional<@NonNull List<@NonNull String>> stringList(@NonNull JsonValue value) {
		if (!(value instanceof JsonArray array))
			return Optional.empty();

		List<String> strings = new ArrayList<>();

		for (JsonValue element : array.getElements()) {
			if (!(element instanceof JsonString string))
				return Optional.empty();

			strings.add(string.getValue());
		}

		return Optional.of(strings);
	}

	/**
	 * The G7-6 depth by a plain walk, apart from the model's cached depth, which is what the oracle predicts.
	 */
	private static int depth(@NonNull JsonValue value) {
		int deepestChild = 0;

		if (value instanceof JsonObject object)
			for (JsonValue member : object.getMembers().values())
				deepestChild = Math.max(deepestChild, depth(member));
		else if (value instanceof JsonArray array)
			for (JsonValue element : array.getElements())
				deepestChild = Math.max(deepestChild, depth(element));
		else
			return 1;

		return deepestChild + 1;
	}

	private static @NonNull JsonValue nested(@NonNull JsonValue innermost, int levels, boolean objects) {
		JsonValue value = innermost;

		for (int level = 0; level < levels; ++level)
			value = objects ? JsonObject.builder().put("n", value).build() : JsonArray.fromElements(List.of(value));

		return value;
	}

	private static @NonNull String messageOf(@NonNull Runnable misuse) {
		try {
			misuse.run();
		} catch (IllegalArgumentException e) {
			return e.getMessage();
		}

		throw new IllegalStateException("A known-bad JSON value was accepted.");
	}

	/**
	 * Whether a string is well-formed UTF-16, by the Character API alone (an oracle apart from StrictUtf8).
	 */
	private static boolean isWellFormed(@NonNull String value) {
		for (int index = 0; index < value.length(); ++index) {
			char character = value.charAt(index);

			if (Character.isHighSurrogate(character) && index + 1 < value.length()
					&& Character.isLowSurrogate(value.charAt(index + 1)))
				++index;
			else if (Character.isSurrogate(character))
				return false;
		}

		return true;
	}

	/**
	 * The message G7-6 requires for a number, or {@code null} if the number is inside the caps. Computed on an exact
	 * copy, so a subclass's overridden methods play no part.
	 */
	private static @Nullable String numberFailure(@NonNull BigDecimal value) {
		BigDecimal exact = new BigDecimal(value.unscaledValue(), value.scale());

		if (exact.precision() > MAXIMUM_DIGITS)
			return DIGITS_MESSAGE;

		if (Math.abs((long) exact.precision() - exact.scale() - 1) > MAXIMUM_EXPONENT)
			return EXPONENT_MESSAGE;

		return null;
	}

	private static void requireRejection(@NonNull IllegalArgumentException exception, @Nullable String expectedMessage) {
		Assertions.assertNotNull(expectedMessage, () -> "rejected a value the oracle accepts: " + exception.getMessage());
		Assertions.assertEquals(expectedMessage, exception.getMessage(), "not the fixed message of the first failed check");
		Assertions.assertNull(exception.getCause(), "a model IllegalArgumentException has a cause");
	}

	/**
	 * A {@code BigDecimal} subclass that lies about its precision and renders itself as other JSON. The model must
	 * copy it into an exact {@code BigDecimal} before checking or storing it (the WP-1 review finding).
	 */
	@NotThreadSafe
	private static final class LyingDecimal extends BigDecimal {
		private static final long serialVersionUID = 1L;

		private LyingDecimal(@NonNull BigInteger unscaled, int scale) {
			super(unscaled, scale);
		}

		@Override
		public int precision() {
			return 1;
		}

		@Override
		public @NonNull String toString() {
			return "{\"injected\":true}";
		}
	}

	/**
	 * A value, or {@code null} after the expected rejection.
	 */
	@NotThreadSafe
	private static final class Built {
		private final JsonValue value;

		private Built(@Nullable JsonValue value) {
			this.value = value;
		}
	}

	/**
	 * One construction program: reads fuzzed choices, calls a factory, and compares the outcome with the oracle.
	 */
	@NotThreadSafe
	private static final class Program {
		private final FuzzedDataProvider data;
		private int values;

		private Program(@NonNull FuzzedDataProvider data) {
			this.data = data;
		}

		private @NonNull Built value(int depthBudget) {
			if (++this.values > MAXIMUM_VALUES || this.data.remainingBytes() == 0)
				return new Built(JsonNull.defaultInstance());

			int kind = this.data.consumeInt(0, depthBudget > 0 ? 8 : 4);

			return switch (kind) {
				case 0 -> string();
				case 1 -> number();
				case 2 -> {
					long longValue = this.data.consumeLong();
					JsonNumber number = JsonNumber.fromValue(Long.valueOf(longValue));
					Assertions.assertEquals(JsonNumber.fromValue(BigDecimal.valueOf(longValue)), number, "Long factory");
					Assertions.assertEquals(Optional.of(longValue), number.getLongValueExact(), "getLongValueExact()");
					yield new Built(number);
				}
				case 3 -> new Built(JsonBoolean.fromValue(Boolean.valueOf(this.data.consumeBoolean())));
				case 4 -> new Built(JsonNull.defaultInstance());
				case 5 -> array(depthBudget);
				case 6 -> builderObject(depthBudget);
				case 7 -> mapObject(depthBudget);
				default -> nesting(depthBudget);
			};
		}

		private @NonNull String text() {
			if (this.data.consumeBoolean())
				return this.data.consumeString(24);

			// consumeChar() can return any UTF-16 code unit, so unpaired surrogates are reachable.
			int length = this.data.consumeInt(0, 8);
			char[] characters = new char[length];

			for (int index = 0; index < length; ++index)
				characters[index] = this.data.consumeChar();

			return new String(characters);
		}

		private @NonNull Built string() {
			String text = text();

			try {
				JsonString string = JsonString.fromValue(text);
				Assertions.assertTrue(isWellFormed(text), "accepted an unpaired surrogate");
				Assertions.assertEquals(text, string.getValue(), "a string changed");
				return new Built(string);
			} catch (IllegalArgumentException e) {
				requireRejection(e, isWellFormed(text) ? null : SURROGATE_MESSAGE);
				return new Built(null);
			}
		}

		private @NonNull BigDecimal decimal() {
			byte[] unscaledBytes = this.data.consumeBytes(this.data.consumeInt(0, MAXIMUM_UNSCALED_BYTES));
			BigInteger unscaled = unscaledBytes.length == 0 ? BigInteger.ZERO : new BigInteger(unscaledBytes);
			int scale = this.data.consumeInt();

			if (!this.data.consumeBoolean())
				return new BigDecimal(unscaled, scale);

			return new LyingDecimal(unscaled, scale);
		}

		private @NonNull Built number() {
			BigDecimal decimal = decimal();
			String failure = numberFailure(decimal);

			try {
				JsonNumber number = JsonNumber.fromValue(decimal);
				Assertions.assertNull(failure, "accepted a number outside the caps");
				Assertions.assertSame(BigDecimal.class, number.getValue().getClass(), "kept a BigDecimal subclass");
				Assertions.assertEquals(decimal.unscaledValue(), number.getValue().unscaledValue(), "unscaled changed");
				Assertions.assertEquals(decimal.scale(), number.getValue().scale(), "scale changed");
				Assertions.assertEquals(number.getValue().toString(), number.toJson(), "toJson() is not canonical");
				Assertions.assertEquals(exactLong(number.getValue()), number.getLongValueExact(), "getLongValueExact()");
				return new Built(number);
			} catch (IllegalArgumentException e) {
				requireRejection(e, failure);
				return new Built(null);
			}
		}

		private @NonNull Built array(int depthBudget) {
			int size = this.data.consumeInt(0, 4);
			List<JsonValue> elements = new ArrayList<>(size);
			int deepestChild = 0;

			for (int index = 0; index < size; ++index) {
				Built element = value(depthBudget - 1);

				if (element.value != null) {
					elements.add(element.value);
					deepestChild = Math.max(deepestChild, depth(element.value));
				}
			}

			return container(() -> JsonArray.fromElements(elements), deepestChild + 1 > MAXIMUM_DEPTH
					? DEPTH_MESSAGE : null);
		}

		private @NonNull Built builderObject(int depthBudget) {
			JsonObject.Builder builder = JsonObject.builder();
			JsonFuzzSupport.requireRedactedBuilder(builder);
			List<String> names = new ArrayList<>();
			int size = this.data.consumeInt(0, 4);

			for (int index = 0; index < size; ++index) {
				String name = !names.isEmpty() && this.data.consumeBoolean()
						? names.get(this.data.consumeInt(0, names.size() - 1)) : text();
				put(builder, names, name, depthBudget);
			}

			// build() always succeeds: every put checked its own member.
			JsonObject object = builder.build();
			Assertions.assertEquals(names, new ArrayList<>(object.getMembers().keySet()), "builder lost member order");
			return new Built(object);
		}

		private void put(JsonObject.@NonNull Builder builder, @NonNull List<@NonNull String> names, @NonNull String name, int depthBudget) {
			String nameFailure = !isWellFormed(name) ? SURROGATE_MESSAGE
					: names.contains(name) ? DUPLICATE_MESSAGE : null;
			String valueFailure;
			Runnable call;

			switch (this.data.consumeInt(0, 5)) {
				case 0 -> {
					String text = text();
					valueFailure = isWellFormed(text) ? null : SURROGATE_MESSAGE;
					call = () -> builder.put(name, text);
				}
				case 1 -> {
					long longValue = this.data.consumeLong();
					valueFailure = null;
					call = () -> builder.put(name, Long.valueOf(longValue));
				}
				case 2 -> {
					BigDecimal decimal = decimal();
					valueFailure = numberFailure(decimal);
					call = () -> builder.put(name, decimal);
				}
				case 3 -> {
					boolean bool = this.data.consumeBoolean();
					valueFailure = null;
					call = () -> builder.put(name, Boolean.valueOf(bool));
				}
				case 4 -> {
					valueFailure = null;
					call = () -> builder.putNull(name);
				}
				default -> {
					Built child = value(depthBudget - 1);

					if (child.value == null)
						return;

					JsonValue childValue = child.value;
					valueFailure = depth(childValue) + 1 > MAXIMUM_DEPTH ? DEPTH_MESSAGE : null;
					call = () -> builder.put(name, childValue);
					// JsonValue puts check the name before the depth; the typed puts build the value first.
					if (nameFailure != null)
						valueFailure = null;
				}
			}

			String expected = valueFailure != null ? valueFailure : nameFailure;

			try {
				call.run();
				Assertions.assertNull(expected, "the builder accepted a member it must reject");
				names.add(name);
			} catch (IllegalArgumentException e) {
				requireRejection(e, expected);
			}
		}

		private @NonNull Built mapObject(int depthBudget) {
			LinkedHashMap<String, JsonValue> members = new LinkedHashMap<>();
			String failure = null;
			int deepestChild = 0;
			int size = this.data.consumeInt(0, 4);

			for (int index = 0; index < size; ++index) {
				String name = text();
				Built member = value(depthBudget - 1);

				if (member.value == null || members.containsKey(name))
					continue;

				members.put(name, member.value);
				deepestChild = Math.max(deepestChild, depth(member.value));

				if (failure == null && !isWellFormed(name))
					failure = SURROGATE_MESSAGE;
			}

			if (failure == null && deepestChild + 1 > MAXIMUM_DEPTH)
				failure = DEPTH_MESSAGE;

			String expected = failure;
			Built built = container(() -> JsonObject.fromMembers(members), expected);

			if (built.value instanceof JsonObject object)
				Assertions.assertEquals(new ArrayList<>(members.keySet()), new ArrayList<>(object.getMembers().keySet()),
						"fromMembers() lost member order");

			return built;
		}

		/**
		 * Wraps a value in up to 70 singleton arrays or objects, so depth 64 and 65 are both reachable.
		 */
		private @NonNull Built nesting(int depthBudget) {
			Built innermost = value(depthBudget - 1);

			if (innermost.value == null)
				return innermost;

			boolean objects = this.data.consumeBoolean();
			int levels = this.data.consumeInt(0, MAXIMUM_DEPTH + 6);
			JsonValue value = innermost.value;

			for (int level = 0; level < levels; ++level) {
				JsonValue child = value;
				boolean tooDeep = depth(child) + 1 > MAXIMUM_DEPTH;
				Built wrapped = container(() -> objects ? JsonObject.builder().put("", child).build()
						: JsonArray.fromElements(List.of(child)), tooDeep ? DEPTH_MESSAGE : null);

				if (wrapped.value == null)
					return wrapped;

				value = wrapped.value;
			}

			return new Built(value);
		}

		private @NonNull Built container(@NonNull Supplier<@NonNull JsonValue> factory, @Nullable String expectedFailure) {
			try {
				JsonValue value = factory.get();
				Assertions.assertNull(expectedFailure, "a container factory accepted a value it must reject");
				return new Built(value);
			} catch (IllegalArgumentException e) {
				requireRejection(e, expectedFailure);
				return new Built(null);
			}
		}
	}
}
