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

package com.revetsec.internal.crypto;

/**
 * Seeded violations: early-exit equality in internal.crypto (R10), through calls on a variable and on a literal, the
 * range overload, and a method reference. The constant-time comparison, the Integer equality and the literals in
 * controls() are not reported.
 */
final class ComparisonFixture {
	boolean seeded(byte[] first, byte[] second, String text, String other, StringBuilder builder,
			java.util.List<String> values) {
		boolean equal = java.util.Arrays.equals(first, second);
		equal &= java.util.Arrays.equals(first, 0, 16, second, 0, 16);
		equal &= text.equals(other);
		equal &= "revetsec/app/v1".equals(text);
		equal &= text.contentEquals(builder);
		values.removeIf(text::equals);
		return equal;
	}

	boolean controls(byte[] first, byte[] second, Integer length, String text) {
		boolean equal = java.security.MessageDigest.isEqual(first, second);
		equal &= length.equals(32);
		equal &= text.length() == 32;
		String prose = "text.equals(other) and Arrays.equals in a string are not code";
		return equal && !prose.isEmpty();
	}
}
