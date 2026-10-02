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
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Tests {@link TestClock}: settable, thread-safe and monotonic (R11; M1 plan, "Test helpers", and the StateSealer
 * boundary tests that pin {@code .000}, {@code .001} and {@code .999} offsets with it).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class TestClockTests {
	private static final Instant START = Instant.parse("2026-09-24T12:00:00.999Z");
	private static final Duration WAIT = Duration.ofSeconds(30);

	@Test
	void readsTheStartingInstantInUtcUntilMoved() {
		TestClock clock = TestClock.fromInstant(START);
		Assertions.assertEquals(START, clock.instant());
		Assertions.assertEquals(START.toEpochMilli(), clock.millis());
		Assertions.assertEquals(ZoneOffset.UTC, clock.getZone());
	}

	@Test
	void advanceMovesForwardByExactlyTheDurationWithNanosecondPrecision() {
		TestClock clock = TestClock.fromInstant(START);
		Assertions.assertEquals(START.plusMillis(1), clock.advance(Duration.ofMillis(1)));
		Assertions.assertEquals(START.plusMillis(1).plusNanos(1), clock.advance(Duration.ofNanos(1)));
		Assertions.assertEquals(START.plusMillis(1).plusNanos(1), clock.advance(Duration.ZERO));
		Assertions.assertEquals(START.plusMillis(1).plusNanos(1), clock.instant());
	}

	@Test
	void setAcceptsTheCurrentOrALaterInstant() {
		TestClock clock = TestClock.fromInstant(START);
		Assertions.assertEquals(START, clock.set(START));
		Instant later = Instant.parse("2026-09-24T12:00:01.000Z");
		Assertions.assertEquals(later, clock.set(later));
		Assertions.assertEquals(later, clock.instant());
	}

	@Test
	void neverMovesBackwardAndARejectedMoveChangesNothing() {
		TestClock clock = TestClock.fromInstant(START);
		Assertions.assertThrows(IllegalArgumentException.class, () -> clock.set(START.minusNanos(1)));
		Assertions.assertThrows(IllegalArgumentException.class, () -> clock.advance(Duration.ofNanos(-1)));
		Assertions.assertEquals(START, clock.instant());
	}

	// Deliberate null inputs verify runtime rejection.
	@SuppressWarnings("NullAway")
	@Test
	void rejectsNullArguments() {
		TestClock clock = TestClock.fromInstant(START);
		Assertions.assertThrows(NullPointerException.class, () -> TestClock.fromInstant(nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> clock.set(nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> clock.advance(nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> clock.withZone(nullValue()));
	}

	@Test
	void aZonedViewSharesTheInstantInBothDirections() {
		TestClock clock = TestClock.fromInstant(START);
		ZoneId zone = ZoneId.of("Asia/Tokyo");
		TestClock zoned = clock.withZone(zone);
		Assertions.assertEquals(zone, zoned.getZone());
		Assertions.assertSame(clock, clock.withZone(ZoneOffset.UTC));

		clock.advance(Duration.ofSeconds(1));
		Assertions.assertEquals(START.plusSeconds(1), zoned.instant());
		zoned.advance(Duration.ofSeconds(1));
		Assertions.assertEquals(START.plusSeconds(2), clock.instant());
	}

	@Test
	void concurrentAdvancesAreNeverLost() throws Exception {
		int threads = 8;
		int advancesPerThread = 1_000;
		TestClock clock = TestClock.fromInstant(START);
		ExecutorService executor = Executors.newFixedThreadPool(threads);
		try {
			CountDownLatch startGate = new CountDownLatch(1);
			List<Future<?>> futures = new ArrayList<>();
			for (int thread = 0; thread < threads; ++thread)
				futures.add(executor.submit(() -> {
					startGate.await();
					for (int advance = 0; advance < advancesPerThread; ++advance)
						clock.advance(Duration.ofNanos(1));
					return null;
				}));
			startGate.countDown();
			for (Future<?> future : futures)
				future.get(WAIT.toSeconds(), TimeUnit.SECONDS);
		} finally {
			executor.shutdownNow();
		}
		Assertions.assertEquals(START.plusNanos((long) threads * advancesPerThread), clock.instant());
	}

	@Test
	void everyReadIsNoEarlierThanTheReadBeforeItWhileAnotherThreadMovesTheClock() throws Exception {
		TestClock clock = TestClock.fromInstant(START);
		AtomicBoolean writing = new AtomicBoolean(true);
		ExecutorService executor = Executors.newFixedThreadPool(2);
		try {
			Future<?> writer = executor.submit(() -> {
				try {
					for (int step = 0; step < 20_000; ++step) {
						if (step % 2 == 0)
							clock.advance(Duration.ofNanos(3));
						else
							clock.set(clock.instant().plusNanos(2));
					}
				} finally {
					writing.set(false);
				}
			});
			Future<Integer> reader = executor.submit(() -> {
				Instant previous = clock.instant();
				int reads = 0;
				while (writing.get() || reads == 0) {
					Instant current = clock.instant();
					if (current.isBefore(previous))
						throw new AssertionError("Read " + current + " after " + previous);
					previous = current;
					++reads;
				}
				return reads;
			});
			writer.get(WAIT.toSeconds(), TimeUnit.SECONDS);
			Assertions.assertTrue(reader.get(WAIT.toSeconds(), TimeUnit.SECONDS) > 0);
		} finally {
			executor.shutdownNow();
		}
		Assertions.assertEquals(START.plusNanos(10_000L * 3 + 10_000L * 2), clock.instant());
	}

	/**
	 * A null of any type, so tests can pass one where the signature says non-null.
	 */
	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> @Nullable T nullValue() {
		return null;
	}
}
