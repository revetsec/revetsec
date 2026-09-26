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

import javax.annotation.concurrent.ThreadSafe;

import static java.util.Objects.requireNonNull;

/**
 * ASCII-only case folding: the one fold shared by the SCIM profile's duplicate-name check and, from M9, SCIM attribute
 * lookup (M1 plan G7-7), so the two can never disagree about which names are the same.
 * <p>
 * Only the 26 letters {@code A}-{@code Z} fold, to {@code a}-{@code z}, by arithmetic. Every other UTF-16 code unit,
 * non-ASCII letters included, is left as it is. The JDK's case-insensitive comparisons and case mappings fold more,
 * even with {@code Locale.ROOT}: they equate the dotless small i (U+0131) and the dotted capital I (U+0130) with
 * {@code i}, the Kelvin sign (U+212A) with {@code k}, and the long s (U+017F) with {@code s}. So U+0131 followed by
 * {@code d}, and {@code id}, would be one SCIM attribute to them and two to a peer that folds ASCII only. The
 * {@code ascii-case-fold} source rule bans those JDK methods in {@code scim} and {@code internal.json}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class AsciiCase {
	private AsciiCase() {
	}

	/**
	 * Folds one UTF-16 code unit.
	 *
	 * @param character the code unit
	 * @return its lowercase ASCII letter if {@code character} is {@code A}-{@code Z}, otherwise {@code character}
	 */
	public static char fold(char character) {
		return character >= 'A' && character <= 'Z' ? (char) (character + ('a' - 'A')) : character;
	}

	/**
	 * Folds a string, one UTF-16 code unit at a time.
	 *
	 * @param value the string
	 * @return {@code value} with {@code A}-{@code Z} replaced by {@code a}-{@code z}; {@code value} itself if it has
	 * no such letter
	 */
	public static @NonNull String fold(@NonNull String value) {
		requireNonNull(value);
		int length = value.length();
		int first = 0;

		while (first < length && fold(value.charAt(first)) == value.charAt(first))
			++first;

		if (first == length)
			return value;

		char[] folded = value.toCharArray();

		for (int index = first; index < length; ++index)
			folded[index] = fold(folded[index]);

		return new String(folded);
	}

	/**
	 * Whether two strings are equal after {@link #fold(String) folding}.
	 *
	 * @param first  one string
	 * @param second the other string
	 * @return {@code true} if the strings have the same length and each pair of code units folds to the same unit
	 */
	public static boolean equalsIgnoringAsciiCase(@NonNull String first, @NonNull String second) {
		requireNonNull(first);
		requireNonNull(second);
		int length = first.length();

		if (length != second.length())
			return false;

		for (int index = 0; index < length; ++index)
			if (fold(first.charAt(index)) != fold(second.charAt(index)))
				return false;

		return true;
	}
}
