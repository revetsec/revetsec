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

package com.revetsec.testing;

import org.jspecify.annotations.Nullable;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Tests {@link RewindableClock}: settable in both directions and thread-safe, for the clock-set-back cases of plan
 * M2-8 and exit criterion 13 (INV-J9: a clock set back never extends a lifetime), while {@link TestClock} stays
 * monotonic (A-2).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class RewindableClockTests {
	private static final Instant START = Instant.parse("2026-09-27T12:00:00.999Z");
	private static final Duration WAIT = Duration.ofSeconds(30);

	@Test
	void readsTheStartingInstantInUtcUntilMoved() {
		RewindableClock clock = RewindableClock.fromInstant(START);
		Assertions.assertEquals(START, clock.instant());
		Assertions.assertEquals(START.toEpochMilli(), clock.millis());
		Assertions.assertEquals(ZoneOffset.UTC, clock.getZone());
	}

	@Test
	void setMovesToAnEarlierOrALaterInstant() {
		RewindableClock clock = RewindableClock.fromInstant(START);
		Instant earlier = START.minus(Duration.ofHours(6));
		Assertions.assertEquals(earlier, clock.set(earlier));
		Assertions.assertEquals(earlier, clock.instant());
		Instant later = START.plus(Duration.ofDays(1));
		Assertions.assertEquals(later, clock.set(later));
		Assertions.assertEquals(later, clock.instant());
	}

	@Test
	void advanceTakesPositiveZeroAndNegativeDurationsWithNanosecondPrecision() {
		RewindableClock clock = RewindableClock.fromInstant(START);
		Assertions.assertEquals(START.plusNanos(1), clock.advance(Duration.ofNanos(1)));
		Assertions.assertEquals(START.plusNanos(1), clock.advance(Duration.ZERO));
		Assertions.assertEquals(START.minusSeconds(30), clock.advance(Duration.ofSeconds(-30).minusNanos(1)));
		Assertions.assertEquals(START.minusSeconds(30), clock.instant());
	}

	@Test
	void rewindMovesBackAndRejectsANegativeDurationWithoutMoving() {
		RewindableClock clock = RewindableClock.fromInstant(START);
		Assertions.assertEquals(START.minusMillis(1), clock.rewind(Duration.ofMillis(1)));
		Assertions.assertEquals(START.minusMillis(1), clock.rewind(Duration.ZERO));
		Assertions.assertThrows(IllegalArgumentException.class, () -> clock.rewind(Duration.ofNanos(-1)));
		Assertions.assertEquals(START.minusMillis(1), clock.instant());
	}

	@Test
	void aMoveOutOfInstantRangeFailsAndLeavesTheClockUnchanged() {
		RewindableClock clock = RewindableClock.fromInstant(START);
		Duration span = Duration.between(Instant.MIN, Instant.MAX);
		Assertions.assertThrows(DateTimeException.class, () -> clock.advance(span));
		Assertions.assertThrows(DateTimeException.class, () -> clock.rewind(span));
		Assertions.assertEquals(START, clock.instant());
	}

	// Deliberate null inputs verify runtime rejection.
	@SuppressWarnings("NullAway")
	@Test
	void rejectsNullArguments() {
		RewindableClock clock = RewindableClock.fromInstant(START);
		Assertions.assertThrows(NullPointerException.class, () -> RewindableClock.fromInstant(nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> clock.set(nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> clock.advance(nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> clock.rewind(nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> clock.withZone(nullValue()));
	}

	@Test
	void aZonedViewSharesTheInstantInBothDirections() {
		RewindableClock clock = RewindableClock.fromInstant(START);
		ZoneId zone = ZoneId.of("Asia/Tokyo");
		RewindableClock zoned = clock.withZone(zone);
		Assertions.assertEquals(zone, zoned.getZone());
		Assertions.assertSame(clock, clock.withZone(ZoneOffset.UTC));

		clock.rewind(Duration.ofSeconds(1));
		Assertions.assertEquals(START.minusSeconds(1), zoned.instant());
		zoned.advance(Duration.ofSeconds(3));
		Assertions.assertEquals(START.plusSeconds(2), clock.instant());
		Assertions.assertTrue(zoned.toString().contains("Asia/Tokyo"), zoned::toString);
		Assertions.assertEquals("RewindableClock[" + START.plusSeconds(2) + ",Z]", clock.toString());
	}

	@Test
	void concurrentMovesInBothDirectionsAreNeverLost() throws Exception {
		int threads = 8;
		int movesPerThread = 1_000;
		RewindableClock clock = RewindableClock.fromInstant(START);
		ExecutorService executor = Executors.newFixedThreadPool(threads);
		try {
			CountDownLatch startGate = new CountDownLatch(1);
			List<Future<?>> futures = new ArrayList<>();
			for (int thread = 0; thread < threads; ++thread)
				futures.add(executor.submit(() -> {
					startGate.await();
					for (int move = 0; move < movesPerThread; ++move) {
						clock.advance(Duration.ofNanos(3));
						clock.rewind(Duration.ofNanos(1));
						clock.advance(Duration.ofNanos(-1));
					}
					return null;
				}));
			startGate.countDown();
			for (Future<?> future : futures)
				future.get(WAIT.toSeconds(), TimeUnit.SECONDS);
		} finally {
			executor.shutdownNow();
		}
		Assertions.assertEquals(START.plusNanos((long) threads * movesPerThread), clock.instant());
	}

	/**
	 * A null of any type, so tests can pass one where the signature says non-null.
	 */
	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> @Nullable T nullValue() {
		return null;
	}
}
