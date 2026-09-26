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

import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.internal.json.JsonLimits;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.math.BigDecimal;

import static java.util.Objects.requireNonNull;

/**
 * The model invariants of G7-6, checked by every public factory. Messages are fixed and never contain the rejected
 * value (R9).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
final class JsonInvariants {
	/**
	 * An unscaled value with more bits than this has more than {@link JsonLimits#MODEL_MAXIMUM_NUMBER_DIGITS} digits:
	 * 4,096 decimal digits need at most ceil(4,096 log2 10) = 13,607 bits. Checking the bit length first keeps
	 * {@code precision()} from computing a large power of ten for an oversized value.
	 */
	private static final int MAXIMUM_UNSCALED_BITS = 13_607;

	private JsonInvariants() {
	}

	/**
	 * Requires a string (a value or a member name) to be non-null, well-formed UTF-16.
	 */
	@NonNull
	static String requireWellFormed(@NonNull String value) {
		requireNonNull(value);

		if (!StrictUtf8.isWellFormed(value))
			throw new IllegalArgumentException("A JSON string or member name must not contain an unpaired surrogate.");

		return value;
	}

	/**
	 * Returns {@code value} if its class is {@link BigDecimal} itself, and otherwise a {@code BigDecimal} with the same
	 * unscaled value and scale. {@code BigDecimal} is not final, so a subclass could report a false precision to pass
	 * the caps, render itself as other JSON text in {@code toJson()}, or change after the checks; the copy can do none
	 * of these. The JDK's constructor also copies an unscaled value that is a {@code BigInteger} subclass.
	 */
	@NonNull
	static BigDecimal exactBigDecimal(@NonNull BigDecimal value) {
		requireNonNull(value);
		return value.getClass() == BigDecimal.class ? value : new BigDecimal(value.unscaledValue(), value.scale());
	}

	/**
	 * Requires a number to be within the model's digit and exponent caps.
	 */
	@NonNull
	static BigDecimal requireNumberWithinCaps(@NonNull BigDecimal value) {
		requireNonNull(value);

		if (value.unscaledValue().bitLength() > MAXIMUM_UNSCALED_BITS
				|| value.precision() > JsonLimits.MODEL_MAXIMUM_NUMBER_DIGITS)
			throw new IllegalArgumentException("A JSON number must have at most "
					+ JsonLimits.MODEL_MAXIMUM_NUMBER_DIGITS + " digits.");

		if (Math.abs(adjustedExponent(value)) > JsonLimits.MODEL_MAXIMUM_EXPONENT_MAGNITUDE)
			throw new IllegalArgumentException("A JSON number's adjusted exponent must be from -"
					+ JsonLimits.MODEL_MAXIMUM_EXPONENT_MAGNITUDE + " to " + JsonLimits.MODEL_MAXIMUM_EXPONENT_MAGNITUDE
					+ ".");

		return value;
	}

	/**
	 * The adjusted decimal exponent, precision - scale - 1: the exponent of the value's leading digit.
	 */
	static long adjustedExponent(@NonNull BigDecimal value) {
		return (long) value.precision() - value.scale() - 1;
	}

	/**
	 * The G7-6 depth of a value: 1 for a scalar or an empty container, otherwise 1 more than its deepest child. Each
	 * container computes its own depth once, at construction.
	 */
	static int depthOf(@NonNull JsonValue value) {
		if (value instanceof JsonObject object)
			return object.getDepth();
		if (value instanceof JsonArray array)
			return array.getDepth();
		return 1;
	}

	/**
	 * The depth of a container whose deepest child has depth {@code deepestChild} (0 for an empty container), checked
	 * against the model cap.
	 */
	static int requireContainerDepth(int deepestChild) {
		int depth = deepestChild + 1;

		if (depth > JsonLimits.MODEL_MAXIMUM_DEPTH)
			throw new IllegalArgumentException("A JSON value must nest at most " + JsonLimits.MODEL_MAXIMUM_DEPTH
					+ " levels deep.");

		return depth;
	}
}
