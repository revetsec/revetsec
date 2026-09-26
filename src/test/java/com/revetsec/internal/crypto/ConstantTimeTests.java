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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.util.stream.Stream;

/**
 * Constant-time comparison (plan R10): {@link ConstantTime} gives the same answers as ordinary equality, compares
 * every code unit in full, and treats {@code null} as equal to nothing, not even {@code null}. Its timing is
 * {@link java.security.MessageDigest#isEqual(byte[], byte[])}'s and is not measured here, because a timing assertion
 * would be flaky; the {@code constant-time-comparison} source rule keeps early-exit comparisons out of the sealer.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class ConstantTimeTests {
	@Test
	void byteArraysAreEqualExactlyWhenTheyHoldTheSameBytes() {
		Assertions.assertTrue(ConstantTime.isEqual(new byte[0], new byte[0]));
		Assertions.assertTrue(ConstantTime.isEqual(new byte[]{1, 2, 3}, new byte[]{1, 2, 3}));
		Assertions.assertFalse(ConstantTime.isEqual(new byte[]{1, 2, 3}, new byte[]{1, 2, 4}));
		Assertions.assertFalse(ConstantTime.isEqual(new byte[]{0, 2, 3}, new byte[]{1, 2, 3}));
		Assertions.assertFalse(ConstantTime.isEqual(new byte[]{1, 2, 3}, new byte[]{1, 2}));
		Assertions.assertFalse(ConstantTime.isEqual(new byte[]{1, 2}, new byte[]{1, 2, 0}));
		Assertions.assertFalse(ConstantTime.isEqual(new byte[0], new byte[]{0}));
	}

	// R10: null-guarded. A missing value never matches, not even another missing value.
	@Test
	void nullIsEqualToNothingNotEvenNull() {
		Assertions.assertFalse(ConstantTime.isEqual((byte[]) null, (byte[]) null));
		Assertions.assertFalse(ConstantTime.isEqual(null, new byte[0]));
		Assertions.assertFalse(ConstantTime.isEqual(new byte[0], null));
		Assertions.assertFalse(ConstantTime.isEqual((String) null, (String) null));
		Assertions.assertFalse(ConstantTime.isEqual(null, ""));
		Assertions.assertFalse(ConstantTime.isEqual("", null));
	}

	// Strings compare as UTF-16 code units: both bytes of each unit count, and unpaired surrogates stay distinct
	// (String.getBytes(UTF_8) would map every one of them to '?').
	@TestFactory
	Stream<DynamicTest> stringsAreEqualExactlyWhenTheyHoldTheSameCodeUnits() {
		return Stream.of(new String[][]{
				{"", ""}, {"state", "state"}, {"state", "State"}, {"state", "state "}, {"state", "stat"},
				{"a\u0000", "a"}, {"\u0100", "\u0001"}, {"\u0001", "\u0100"}, {"\ud800", "\udc00"}, {"\ud800", "?"},
				{"\ud800", "\ufffd"}, {"\ud800", "\ud800"}, {"\ud834\udd1e", "\ud834\udd1e"}, {"\ud834\udd1e", "\ud834\udd1f"},
				{"\u00e9", "e\u0301"}, {"K", "\u212a"}
		}).map(pair -> DynamicTest.dynamicTest(escape(pair[0]) + " vs " + escape(pair[1]), () -> {
			boolean expected = pair[0].equals(pair[1]);
			Assertions.assertEquals(expected, ConstantTime.isEqual(pair[0], pair[1]));
			Assertions.assertEquals(expected, ConstantTime.isEqual(pair[1], pair[0]));
		}));
	}

	@Test
	void comparingNeverModifiesItsArguments() {
		byte[] first = {5, 6, 7};
		byte[] second = {5, 6, 7};

		Assertions.assertTrue(ConstantTime.isEqual(first, second));
		Assertions.assertArrayEquals(new byte[]{5, 6, 7}, first);
		Assertions.assertArrayEquals(new byte[]{5, 6, 7}, second);
	}

	private static String escape(String value) {
		StringBuilder escaped = new StringBuilder();

		for (char character : value.toCharArray())
			escaped.append(character >= 0x20 && character < 0x7f ? String.valueOf(character)
					: String.format(java.util.Locale.ROOT, "\\u%04x", (int) character));

		return escaped.toString();
	}
}
