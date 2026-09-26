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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.util.Locale;
import java.util.stream.Stream;

/**
 * ASCII-only case folding (M1 plan G7-7 and exit criterion 3; RFC 7643 section 2.1, where SCIM attribute names are
 * case-insensitive).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class AsciiCaseTests {
	// G7-7: exactly A-Z fold, to a-z, and every other UTF-16 code unit (all 65,536 of them) is unchanged.
	@Test
	void foldsExactlyTheTwentySixAsciiCapitals() {
		int folded = 0;

		for (int code = 0; code <= Character.MAX_VALUE; ++code) {
			char character = (char) code;
			char expected = character >= 'A' && character <= 'Z' ? (char) (character - 'A' + 'a') : character;

			Assertions.assertEquals(expected, AsciiCase.fold(character), () -> Integer.toHexString(character));

			if (expected != character)
				++folded;
		}

		Assertions.assertEquals(26, folded);
	}

	// G7-7: the letters the JDK's case-insensitive comparisons equate with ASCII letters stay apart here: the
	// dotless small i (U+0131), the dotted capital I (U+0130), the Kelvin sign (U+212A) and the long s (U+017F).
	@TestFactory
	Stream<DynamicTest> keepsNonAsciiCaseVariantsApartThatTheJdkMerges() {
		return Stream.of(
				new String[]{"\u0131d", "id"},
				new String[]{"\u0131d", "ID"},
				new String[]{"\u0130D", "id"},
				new String[]{"\u212Aey", "key"},
				new String[]{"\u017Fub", "SUB"})
				.map(pair -> DynamicTest.dynamicTest(Integer.toHexString(pair[0].charAt(0)) + " vs " + pair[1], () -> {
					Assertions.assertTrue(pair[0].equalsIgnoreCase(pair[1]) || pair[0].toLowerCase(Locale.ROOT)
							.equals(pair[1].toLowerCase(Locale.ROOT)), "precondition: the JDK folds these together");
					Assertions.assertFalse(AsciiCase.equalsIgnoringAsciiCase(pair[0], pair[1]));
					Assertions.assertNotEquals(AsciiCase.fold(pair[0]), AsciiCase.fold(pair[1]));
				}));
	}

	// G7-7: names that differ only in ASCII case compare equal, and fold to the same string.
	@Test
	void comparesAsciiCaseVariantsAsEqual() {
		for (String[] pair : new String[][]{{"id", "ID"}, {"userName", "USERNAME"}, {"Operations", "operations"},
				{"", ""}, {"a1-_.$", "A1-_.$"}, {"\u00E9A", "\u00E9a"}}) {
			Assertions.assertTrue(AsciiCase.equalsIgnoringAsciiCase(pair[0], pair[1]), pair[0]);
			Assertions.assertEquals(AsciiCase.fold(pair[0]), AsciiCase.fold(pair[1]), pair[0]);
		}

		Assertions.assertFalse(AsciiCase.equalsIgnoringAsciiCase("id", "i"));
		Assertions.assertFalse(AsciiCase.equalsIgnoringAsciiCase("id", "ie"));
		Assertions.assertFalse(AsciiCase.equalsIgnoringAsciiCase("@", "`"), "@ and ` are 32 apart but not letters");
		Assertions.assertFalse(AsciiCase.equalsIgnoringAsciiCase("[", "{"));
	}

	// A string with nothing to fold is returned as it is; otherwise every capital is lowered and nothing else moves.
	@Test
	void foldsStringsWithoutChangingAnythingElse() {
		String lower = "already lower \u00C9 \u0130";

		Assertions.assertSame(lower, AsciiCase.fold(lower));
		Assertions.assertEquals("mixed \u00C9 case \u212A zz", AsciiCase.fold("MiXeD \u00C9 CASE \u212A ZZ"));
		Assertions.assertEquals("", AsciiCase.fold(""));
		Assertions.assertEquals("\uD83D\uDE80a", AsciiCase.fold("\uD83D\uDE80A"));
	}

	// R15: null arguments are misuse.
	@Test
	void rejectsNullArguments() {
		String nothing = JsonFailures.nullValue();

		Assertions.assertThrows(NullPointerException.class, () -> AsciiCase.fold(nothing));
		Assertions.assertThrows(NullPointerException.class, () -> AsciiCase.equalsIgnoringAsciiCase(nothing, "a"));
		Assertions.assertThrows(NullPointerException.class, () -> AsciiCase.equalsIgnoringAsciiCase("a", nothing));
	}
}
