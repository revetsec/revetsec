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

import javax.annotation.concurrent.Immutable;

/**
 * Bounded lexical evidence for one JSON number token. Flags describe syntax, not numeric value: {@code 1.0} and
 * {@code 1E0} remain distinct from the integer token {@code 1}, even though their public number values are equal.
 */
@Immutable
public final class JsonNumberSyntax {
	private static final @NonNull JsonNumberSyntax INTEGER = new JsonNumberSyntax(false, false);
	private static final @NonNull JsonNumberSyntax FRACTION = new JsonNumberSyntax(true, false);
	private static final @NonNull JsonNumberSyntax EXPONENT = new JsonNumberSyntax(false, true);
	private static final @NonNull JsonNumberSyntax FRACTION_AND_EXPONENT = new JsonNumberSyntax(true, true);
	private final boolean hadFraction;
	private final boolean hadExponent;

	private JsonNumberSyntax(boolean hadFraction, boolean hadExponent) {
		this.hadFraction = hadFraction;
		this.hadExponent = hadExponent;
	}

	static @NonNull JsonNumberSyntax from(boolean hadFraction, boolean hadExponent) {
		return hadFraction ? (hadExponent ? FRACTION_AND_EXPONENT : FRACTION) : (hadExponent ? EXPONENT : INTEGER);
	}

	/** @return whether the token contained a fraction part */
	public boolean hadFraction() {
		return this.hadFraction;
	}

	/** @return whether the token contained an exponent part */
	public boolean hadExponent() {
		return this.hadExponent;
	}

	@Override
	public @NonNull String toString() {
		return "JsonNumberSyntax{hadFraction=" + this.hadFraction + ", hadExponent=" + this.hadExponent + "}";
	}
}
