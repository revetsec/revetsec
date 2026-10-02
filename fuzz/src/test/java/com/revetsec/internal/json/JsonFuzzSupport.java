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

import org.jspecify.annotations.NonNull;

import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.junit.jupiter.api.Assertions;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.math.BigDecimal;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Shared checks for the JSON fuzz targets, kept in {@code com.revetsec.internal.json} so they can reach two
 * package-private hooks: {@link JsonLimits#maximumCaps()} and the {@link JsonLimits} constructor, which builds the
 * exact-name twin and the tight profile. Not a fuzz target itself (no {@code FuzzTests} suffix).
 * <p>
 * {@link #shapeOf(JsonValue)} measures a value with its own walker and its own ASCII fold, so the targets check the
 * codec's and the model's bookkeeping against an independent computation rather than against themselves.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class JsonFuzzSupport {
	/**
	 * Every {@code toString()} of the model renders {@code SimpleName{...=<redacted>}} (R9, INV-G9).
	 */
	private static final Pattern REDACTED = Pattern.compile("Json(Object|Array|String|Number|Boolean|Null)"
			+ "\\{[a-z]+=<redacted>}");

	private JsonFuzzSupport() {
	}

	/**
	 * The package-private maximum-cap profile: every JSON row at its cap, no input-size bound, exact names.
	 *
	 * @return the profile
	 */
	public static @NonNull JsonLimits maximumCaps() {
		return JsonLimits.maximumCaps();
	}

	/**
	 * A synthetic profile far below every registry floor, built through the package-private constructor for fuzzing
	 * only: 64 KiB of input, depth 3, 12 nodes, strings of 6 UTF-16 code units, numbers of 6 characters (text and
	 * canonical form), exponents of magnitude 3, and exact names. The real profiles' string limit (1 Mi code units) is
	 * beyond any fuzz input, and their other structural limits need hundreds of bytes or more; under this profile every
	 * structural {@link JsonParseException.Kind} is a few bytes away, so the targets' bound checks see both sides of
	 * each limit on most inputs.
	 *
	 * @return the profile
	 */
	public static @NonNull JsonLimits tightLimits() {
		return new JsonLimits(65_536, 3, 12, 6, 6, 3, false);
	}

	/**
	 * A profile with exactly the limits of {@code limits} but exact member-name comparison: the protocol profiles'
	 * duplicate rule ("exact" in {@link JsonLimits}' profile table), applied to otherwise identical limits.
	 *
	 * @param limits the profile to copy
	 * @return the copy with {@code isAsciiCaseVariantNamesRejected() == false}
	 */
	public static @NonNull JsonLimits exactNameTwinOf(@NonNull JsonLimits limits) {
		return new JsonLimits(limits.getMaxInputBytes(), limits.getMaxDepth(), limits.getMaxNodes(),
				limits.getMaxStringLength(), limits.getMaxNumberLength(), limits.getMaxExponentMagnitude(), false);
	}

	/**
	 * Requires the fixed shape of every {@link JsonParseException} (G7-3, R9): the message is the {@link
	 * JsonParseException.Kind}'s own fixed message, so it can never echo the input; there is no cause and nothing
	 * suppressed; and the byte offset lies inside the input or at its end.
	 *
	 * @param exception   the exception
	 * @param inputLength the length of the rejected input
	 */
	public static void requireFixedShape(@NonNull JsonParseException exception, int inputLength) {
		Assertions.assertNotNull(exception.getKind(), "a JsonParseException has no Kind");
		Assertions.assertEquals(exception.getKind().getMessage(), exception.getMessage(),
				"a JsonParseException message is not its Kind's fixed message");
		Assertions.assertNull(exception.getCause(), "a JsonParseException has a cause");
		Assertions.assertEquals(0, exception.getSuppressed().length, "a JsonParseException has suppressed exceptions");
		Assertions.assertTrue(exception.getByteOffset() >= 0 && exception.getByteOffset() <= inputLength,
				() -> "byte offset " + exception.getByteOffset() + " is outside an input of " + inputLength + " bytes");
	}

	/**
	 * Requires a {@link JsonFieldException} to carry only its Kind's fixed message, with no cause.
	 *
	 * @param exception the exception
	 */
	public static void requireFixedShape(@NonNull JsonFieldException exception) {
		Assertions.assertNotNull(exception.getKind(), "a JsonFieldException has no Kind");
		Assertions.assertEquals(exception.getKind().getMessage(), exception.getMessage(),
				"a JsonFieldException message is not its Kind's fixed message");
		Assertions.assertNull(exception.getCause(), "a JsonFieldException has a cause");
		Assertions.assertEquals(0, exception.getSuppressed().length, "a JsonFieldException has suppressed exceptions");
	}

	/**
	 * Requires {@code value.toString()} to be the redacted rendering of R9.
	 *
	 * @param value the value
	 */
	public static void requireRedactedToString(@NonNull Object value) {
		String rendered = value.toString();
		Assertions.assertTrue(REDACTED.matcher(rendered).matches(), () -> "toString() is not redacted: " + rendered);
	}

	/**
	 * Requires a {@code JsonObject.Builder}'s {@code toString()} to be the redacted
	 * {@code JsonObject.Builder{members=<redacted>}} (R9).
	 *
	 * @param builder the builder
	 */
	public static void requireRedactedBuilder(JsonObject.@NonNull Builder builder) {
		Assertions.assertEquals("JsonObject.Builder{members=<redacted>}", builder.toString(),
				"JsonObject.Builder.toString() is not redacted");
	}

	/**
	 * Measures a value with an independent walker. Recursion is safe: the model caps depth at 64 (G7-6).
	 *
	 * @param value the value
	 * @return its shape
	 */
	public static @NonNull Shape shapeOf(@NonNull JsonValue value) {
		Shape.Accumulator accumulator = new Shape.Accumulator();
		int depth = walk(value, accumulator);
		return new Shape(depth, accumulator.nodes, accumulator.longestString, accumulator.longestCanonicalNumber,
				accumulator.largestAdjustedExponent, accumulator.mostDigits, accumulator.asciiCaseVariantNames,
				accumulator.inexactNumberClass);
	}

	/**
	 * Folds ASCII letters only, the way G7-7 defines SCIM's name comparison. Written here by arithmetic, apart from
	 * {@link AsciiCase}, so the fuzz check does not share the code it checks.
	 *
	 * @param name the name
	 * @return the name with {@code A-Z} mapped to {@code a-z}
	 */
	public static @NonNull String foldAsciiCase(@NonNull String name) {
		char[] characters = name.toCharArray();

		for (int index = 0; index < characters.length; ++index)
			if (characters[index] >= 'A' && characters[index] <= 'Z')
				characters[index] = (char) (characters[index] + ('a' - 'A'));

		return new String(characters);
	}

	private static int walk(@NonNull JsonValue value, Shape.@NonNull Accumulator accumulator) {
		++accumulator.nodes;

		if (value instanceof JsonObject object) {
			Map<String, JsonValue> members = object.getMembers();
			Set<String> folded = new HashSet<>();
			int deepestChild = 0;

			for (Map.Entry<String, JsonValue> member : members.entrySet()) {
				accumulator.longestString = Math.max(accumulator.longestString, member.getKey().length());

				if (!folded.add(foldAsciiCase(member.getKey())))
					accumulator.asciiCaseVariantNames = true;

				deepestChild = Math.max(deepestChild, walk(member.getValue(), accumulator));
			}

			return deepestChild + 1;
		}

		if (value instanceof JsonArray array) {
			List<JsonValue> elements = array.getElements();
			int deepestChild = 0;

			for (JsonValue element : elements)
				deepestChild = Math.max(deepestChild, walk(element, accumulator));

			return deepestChild + 1;
		}

		if (value instanceof JsonString string)
			accumulator.longestString = Math.max(accumulator.longestString, string.getValue().length());

		if (value instanceof JsonNumber number) {
			BigDecimal decimal = number.getValue();

			if (decimal.getClass() != BigDecimal.class)
				accumulator.inexactNumberClass = true;

			accumulator.mostDigits = Math.max(accumulator.mostDigits, decimal.precision());
			accumulator.largestAdjustedExponent = Math.max(accumulator.largestAdjustedExponent,
					Math.abs((long) decimal.precision() - decimal.scale() - 1));
			accumulator.longestCanonicalNumber = Math.max(accumulator.longestCanonicalNumber,
					decimal.toString().length());
		}

		return 1;
	}

	/**
	 * What {@link #shapeOf(JsonValue)} measured.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 */
	@Immutable
	public static final class Shape {
		private final int depth;
		private final long nodes;
		private final int longestString;
		private final int longestCanonicalNumber;
		private final long largestAdjustedExponent;
		private final int mostDigits;
		private final boolean asciiCaseVariantNames;
		private final boolean inexactNumberClass;

		private Shape(int depth, long nodes, int longestString, int longestCanonicalNumber,
									long largestAdjustedExponent, int mostDigits, boolean asciiCaseVariantNames,
									boolean inexactNumberClass) {
			this.depth = depth;
			this.nodes = nodes;
			this.longestString = longestString;
			this.longestCanonicalNumber = longestCanonicalNumber;
			this.largestAdjustedExponent = largestAdjustedExponent;
			this.mostDigits = mostDigits;
			this.asciiCaseVariantNames = asciiCaseVariantNames;
			this.inexactNumberClass = inexactNumberClass;
		}

		/**
		 * The G7-6 depth: 1 for a scalar or an empty container, else 1 more than the deepest child.
		 *
		 * @return the depth
		 */
		public int getDepth() {
			return this.depth;
		}

		/**
		 * Every value, the root and containers included.
		 *
		 * @return the node count
		 */
		public long getNodes() {
			return this.nodes;
		}

		/**
		 * The longest string value or member name, in UTF-16 code units.
		 *
		 * @return the length
		 */
		public int getLongestString() {
			return this.longestString;
		}

		/**
		 * The longest canonical number form ({@code BigDecimal.toString()}), in characters.
		 *
		 * @return the length, 0 without numbers
		 */
		public int getLongestCanonicalNumber() {
			return this.longestCanonicalNumber;
		}

		/**
		 * The largest magnitude of any number's adjusted decimal exponent.
		 *
		 * @return the magnitude, 0 without numbers
		 */
		public long getLargestAdjustedExponent() {
			return this.largestAdjustedExponent;
		}

		/**
		 * The largest precision of any number.
		 *
		 * @return the digit count, 0 without numbers
		 */
		public int getMostDigits() {
			return this.mostDigits;
		}

		/**
		 * Whether some object holds two member names that differ only in ASCII case (or not at all).
		 *
		 * @return {@code true} if so
		 */
		public boolean hasAsciiCaseVariantNames() {
			return this.asciiCaseVariantNames;
		}

		/**
		 * Whether some number's value is a {@code BigDecimal} subclass rather than {@code BigDecimal} itself.
		 *
		 * @return {@code true} if so
		 */
		public boolean hasInexactNumberClass() {
			return this.inexactNumberClass;
		}

		/**
		 * Mutable counters for one walk.
		 */
		@NotThreadSafe
		private static final class Accumulator {
			private long nodes;
			private int longestString;
			private int longestCanonicalNumber;
			private long largestAdjustedExponent;
			private int mostDigits;
			private boolean asciiCaseVariantNames;
			private boolean inexactNumberClass;
		}
	}
}
