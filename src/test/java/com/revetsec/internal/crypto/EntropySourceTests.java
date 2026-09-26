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
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;

/**
 * The entropy seam (plan R6): the length and uniqueness of random values, never the values themselves.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class EntropySourceTests {
	@Test
	void returnsFreshArraysOfTheRequestedLength() {
		EntropySource entropySource = EntropySource.fromDefaults();

		Assertions.assertEquals(0, entropySource.nextBytes(0).length);
		Assertions.assertEquals(12, entropySource.nextBytes(12).length);
		Assertions.assertEquals(16, entropySource.nextBytes(16).length);
		Assertions.assertNotSame(entropySource.nextBytes(4), entropySource.nextBytes(4));
	}

	// 1,000 draws of 128 bits from two sources never repeat (a repeat is a 2^-108 event).
	@Test
	void neverRepeatsASixteenByteValueAcrossDrawsOrSources() {
		EntropySource first = EntropySource.fromDefaults();
		EntropySource second = EntropySource.fromDefaults();
		Set<String> seen = new HashSet<>();

		for (int index = 0; index < 500; ++index) {
			Assertions.assertTrue(seen.add(HexFormat.of().formatHex(first.nextBytes(16))));
			Assertions.assertTrue(seen.add(HexFormat.of().formatHex(second.nextBytes(16))));
		}
	}

	@Test
	void rejectsANegativeLength() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> EntropySource.fromDefaults().nextBytes(-1));
	}
}
