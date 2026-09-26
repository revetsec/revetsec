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

package com.revetsec.internal;

import com.revetsec.internal.Limit.Unit;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.Duration;

/**
 * One limits-registry row's behavior (plan R8; M1 plan gate 5 and "Limits registry"). Every real row is covered by
 * {@code LimitsTests}; these tests pin the mechanics on hand-made rows.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class LimitTests {
	private static final Limit SIZE = Limit.fromAmounts("Test body size", Unit.BYTES, 256, 16, 4_096);
	private static final Limit TIME = Limit.fromDurations("Test lifetime", Duration.ofMinutes(15),
			Duration.ofMinutes(1), Duration.ofMinutes(60));
	private static final Limit ZERO_FLOOR_TIME = Limit.fromDurations("Test staleness", Duration.ofHours(12),
			Duration.ZERO, Duration.ofHours(24));
	private static final Limit NO_DEFAULT_TIME = Limit.fromDurations("Test argument", null, Duration.ofSeconds(1),
			Duration.ofDays(400));

	@Test
	void requireAcceptsTheFloorTheCapAndEverythingBetween() {
		Assertions.assertEquals(16, SIZE.require(16));
		Assertions.assertEquals(4_096, SIZE.require(4_096));
		Assertions.assertEquals(256L, SIZE.require(256L));
		Assertions.assertEquals(Duration.ofMinutes(1), TIME.require(Duration.ofMinutes(1)));
		Assertions.assertEquals(Duration.ofMinutes(60), TIME.require(Duration.ofMinutes(60)));
	}

	@Test
	void requireRejectsZeroNegativesAndEverythingOutsideTheRange() {
		// Plan R8: zero and negative values are never accepted, and nothing can be "unlimited".
		for (long value : new long[]{0, -1, 15, 4_097, Long.MIN_VALUE, Long.MAX_VALUE, Integer.MAX_VALUE + 1L})
			Assertions.assertThrows(IllegalArgumentException.class, () -> SIZE.require(value), () -> "" + value);

		for (int value : new int[]{0, -1, 15, 4_097, Integer.MIN_VALUE, Integer.MAX_VALUE})
			Assertions.assertThrows(IllegalArgumentException.class, () -> SIZE.require(value), () -> "" + value);

		for (Duration value : new Duration[]{Duration.ZERO, Duration.ofNanos(-1), Duration.ofMinutes(1).minusNanos(1),
				Duration.ofMinutes(60).plusNanos(1), Duration.ofSeconds(Long.MAX_VALUE, 999_999_999),
				Duration.ofSeconds(Long.MIN_VALUE)})
			Assertions.assertThrows(IllegalArgumentException.class, () -> TIME.require(value), value::toString);
	}

	@Test
	void aZeroFloorRowAcceptsZeroButNotNegatives() {
		// Plan R8: maximum staleness (and, from gate 5, renewBefore) may be zero.
		Assertions.assertTrue(ZERO_FLOOR_TIME.isZeroAllowed());
		Assertions.assertFalse(TIME.isZeroAllowed());
		Assertions.assertFalse(SIZE.isZeroAllowed());
		Assertions.assertEquals(Duration.ZERO, ZERO_FLOOR_TIME.require(Duration.ZERO));
		Assertions.assertThrows(IllegalArgumentException.class, () -> ZERO_FLOOR_TIME.require(Duration.ofNanos(-1)));
	}

	@Test
	void theRejectionMessageNamesTheRowAndRepeatsOnlyTheNumber() {
		// Plan R9: fixed messages; the rejected value is a number and nothing else.
		IllegalArgumentException size = Assertions.assertThrows(IllegalArgumentException.class,
				() -> SIZE.require(4_097));
		Assertions.assertEquals("Test body size must be from 16 to 4096 bytes; got 4097.", size.getMessage());

		IllegalArgumentException time = Assertions.assertThrows(IllegalArgumentException.class,
				() -> TIME.require(Duration.ofSeconds(30)));
		Assertions.assertEquals("Test lifetime must be from PT1M to PT1H; got PT30S.", time.getMessage());

		Limit count = Limit.fromAmounts("Test count", Unit.COUNT, 10, 1, 100);
		Assertions.assertEquals("Test count must be from 1 to 100; got 0.",
				Assertions.assertThrows(IllegalArgumentException.class, () -> count.require(0)).getMessage());

		Limit characters = Limit.fromAmounts("Test length", Unit.CHARACTERS, 10, 1, 100);
		Assertions.assertEquals("Test length must be from 1 to 100 characters; got -5.",
				Assertions.assertThrows(IllegalArgumentException.class, () -> characters.require(-5)).getMessage());
	}

	@Test
	void accessorsReturnTheRowsValues() {
		Assertions.assertEquals("Test body size", SIZE.getName());
		Assertions.assertEquals(Unit.BYTES, SIZE.getUnit());
		Assertions.assertTrue(SIZE.hasDefault());
		Assertions.assertEquals(256L, SIZE.getDefaultValue());
		Assertions.assertEquals(256, SIZE.getDefaultIntValue());
		Assertions.assertEquals(16L, SIZE.getFloor());
		Assertions.assertEquals(4_096L, SIZE.getCap());

		Assertions.assertEquals(Unit.DURATION, TIME.getUnit());
		Assertions.assertEquals(Duration.ofMinutes(15), TIME.getDefaultDuration());
		Assertions.assertEquals(Duration.ofMinutes(1), TIME.getFloorDuration());
		Assertions.assertEquals(Duration.ofMinutes(60), TIME.getCapDuration());

		Assertions.assertFalse(NO_DEFAULT_TIME.hasDefault());
		Assertions.assertEquals(Duration.ofDays(400), NO_DEFAULT_TIME.getCapDuration());
		Assertions.assertThrows(IllegalStateException.class, NO_DEFAULT_TIME::getDefaultDuration);
	}

	@Test
	void usingTheWrongKindOfAccessorIsABug() {
		// A duration row is never read as a number, and a size never as a Duration.
		Assertions.assertThrows(IllegalStateException.class, TIME::getDefaultValue);
		Assertions.assertThrows(IllegalStateException.class, TIME::getDefaultIntValue);
		Assertions.assertThrows(IllegalStateException.class, TIME::getFloor);
		Assertions.assertThrows(IllegalStateException.class, TIME::getCap);
		Assertions.assertThrows(IllegalStateException.class, () -> TIME.require(1));
		Assertions.assertThrows(IllegalStateException.class, () -> TIME.require(1L));
		Assertions.assertThrows(IllegalStateException.class, SIZE::getDefaultDuration);
		Assertions.assertThrows(IllegalStateException.class, SIZE::getFloorDuration);
		Assertions.assertThrows(IllegalStateException.class, SIZE::getCapDuration);
		Assertions.assertThrows(IllegalStateException.class, () -> SIZE.require(Duration.ofSeconds(1)));
		Assertions.assertThrows(NullPointerException.class, () -> TIME.require(nullDuration()));
	}

	@Test
	void malformedRowsAreRejected() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> Limit.fromAmounts("x", Unit.BYTES, 1, 2, 3));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Limit.fromAmounts("x", Unit.BYTES, 4, 2, 3));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Limit.fromAmounts("x", Unit.BYTES, 1, 3, 2));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Limit.fromAmounts("x", Unit.BYTES, 0, -1, 2));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Limit.fromAmounts("x", Unit.BYTES, 0, 0, 0));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Limit.fromAmounts(" ", Unit.BYTES, 1, 1, 1));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Limit.fromAmounts("x", Unit.DURATION, 1, 1, 1));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Limit.fromDurations("x", Duration.ofSeconds(-1),
				Duration.ZERO, Duration.ofSeconds(1)));
	}

	@Test
	void aDefaultThatDoesNotFitAnIntIsNotTruncated() {
		// getDefaultIntValue must never narrow silently: 2^31 would become Integer.MIN_VALUE.
		Limit large = Limit.fromAmounts("Test large size", Unit.BYTES, Integer.MAX_VALUE + 1L, 1, Long.MAX_VALUE);

		Assertions.assertEquals(Integer.MAX_VALUE + 1L, large.getDefaultValue());
		Assertions.assertThrows(IllegalStateException.class, large::getDefaultIntValue);

		Limit largest = Limit.fromAmounts("Test largest int", Unit.BYTES, Integer.MAX_VALUE, 1, Long.MAX_VALUE);
		Assertions.assertEquals(Integer.MAX_VALUE, largest.getDefaultIntValue());
	}

	@Test
	void toStringDescribesTheRow() {
		Assertions.assertEquals("Limit{name=Test body size, unit=BYTES, default=256, floor=16, cap=4096}",
				SIZE.toString());
		Assertions.assertEquals("Limit{name=Test lifetime, unit=DURATION, default=PT15M, floor=PT1M, cap=PT1H}",
				TIME.toString());
		Assertions.assertEquals("Limit{name=Test argument, unit=DURATION, default=none, floor=PT1S, cap=PT9600H}",
				NO_DEFAULT_TIME.toString());
	}

	@SuppressWarnings("NullAway")
	private static Duration nullDuration() {
		return null;
	}
}
