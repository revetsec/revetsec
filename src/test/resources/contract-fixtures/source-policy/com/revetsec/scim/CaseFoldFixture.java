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

package com.revetsec.scim;

/**
 * Seeded violations: the JDK's case-insensitive comparisons and case mappings in scim (G7-7), through calls, a method
 * reference and the comparator constant. In controls(), the case-sensitive regionMatches, exact equality, a comment and
 * a string after a U+FFFF literal are not reported.
 */
final class CaseFoldFixture {
	void seeded(String name, String other, java.util.List<String> names) {
		name.equalsIgnoreCase(other);
		name.compareToIgnoreCase(other);
		names.removeIf(name::equalsIgnoreCase);
		name.regionMatches(true, 0, other, 0, 2);
		names.sort(String.CASE_INSENSITIVE_ORDER);
		names.add(name.toLowerCase(java.util.Locale.ROOT));
		names.add(Character.toString(Character.toUpperCase(name.codePointAt(0))));
	}

	boolean controls(String name, String other) {
		boolean equal = name.regionMatches(0, other, 0, 2) || name.equals(other);
		// String.CASE_INSENSITIVE_ORDER in a comment is not code
		return equal || name.equals("\uFFFF") || name.equals("CASE_INSENSITIVE_ORDER after U+FFFF is not code");
	}
}
