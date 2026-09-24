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

package com.revetsec;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.util.Locale;

/**
 * Canary for the CI locale legs (plan 10.3). A locale leg runs the build with
 * {@code JAVA_TOOL_OPTIONS=-Duser.language=tr -Duser.country=TR} (or {@code ar}/{@code EG}) and sets
 * {@value #EXPECTED_LOCALE_VARIABLE} to the same locale as a BCP 47 tag ({@code tr-TR}, {@code ar-EG}). This test
 * then fails unless the test JVM really runs in that locale, so a leg cannot pass vacuously. Outside a locale leg
 * the variable is unset and the test is skipped.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class LocaleCanaryTests {
	static final String EXPECTED_LOCALE_VARIABLE = "REVETSEC_EXPECTED_LOCALE";

	@Test
	void testJvmRunsInTheLocaleLegsLocale() {
		@Nullable String expectedTag = System.getenv(EXPECTED_LOCALE_VARIABLE);
		if (expectedTag == null || expectedTag.isBlank()) {
			Assumptions.abort(EXPECTED_LOCALE_VARIABLE + " is not set; this is not a locale leg");
			return;
		}

		Locale expected = Locale.forLanguageTag(expectedTag.strip());
		Assertions.assertFalse(expected.getLanguage().isEmpty(),
				() -> EXPECTED_LOCALE_VARIABLE + " is not a BCP 47 language tag: " + expectedTag);

		for (Locale actual : new Locale[]{Locale.getDefault(), Locale.getDefault(Locale.Category.FORMAT)}) {
			Assertions.assertEquals(expected.getLanguage(), actual.getLanguage(), "default locale language");
			if (!expected.getCountry().isEmpty())
				Assertions.assertEquals(expected.getCountry(), actual.getCountry(), "default locale country");
		}
	}
}
