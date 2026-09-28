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

package com.revetsec.internal.jose;

/**
 * Seeded violations: the JDK's case folding of a typ media type in internal.jose (ascii-case-fold, G7-7, M2-4), which
 * folds non-ASCII letters too. The exact equality in controls() is not reported.
 */
final class TypeHeaderFixture {
	boolean seeded(String type) {
		boolean jwt = type.equalsIgnoreCase("JWT");
		jwt |= "application/jwt".equals(type.toLowerCase(java.util.Locale.ROOT));
		return jwt || type.regionMatches(true, 0, "application/", 0, 12);
	}

	boolean controls(String type) {
		return type.equals("JWT") || type.regionMatches(0, "application/", 0, 12);
	}
}
