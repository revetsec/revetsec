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

import com.revetsec.StoreAdmission;
import com.revetsec.StoreTimeObservation;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/** Focused arithmetic and deterministic caller-order checks for the inactive common time rules. */
final class StoreTimeRulesTests {
	private static final Instant T = Instant.parse("2026-10-29T12:00:00Z");
	private static final String AUTHORITY = identifier(1);
	private static final String RECOVERY = identifier(2);
	private static final String GENERATION = identifier(3);

	@Test
	void admissionComparesBothDistinctIdentityDomainsByValue() {
		StoreAdmission admission = admission(AUTHORITY, RECOVERY);
		Assertions.assertTrue(StoreTimeRules.sameAdmission(admission, admission(AUTHORITY, RECOVERY)));
		Assertions.assertFalse(StoreTimeRules.sameAdmission(admission, admission(RECOVERY, AUTHORITY)));
		Assertions.assertFalse(StoreTimeRules.sameAdmission(admission, admission(identifier(4), RECOVERY)));
		Assertions.assertFalse(StoreTimeRules.sameAdmission(admission, admission(AUTHORITY, identifier(4))));
	}

	@Test
	void profileComparisonIncludesAllIdentitiesAndGenerationErrorButNotTheSampleTime() {
		StoreTimeObservation.Healthy sample = observation(T, Duration.ofMillis(1));
		Assertions.assertTrue(StoreTimeRules.sameProfile(sample, observation(T.plusSeconds(1), Duration.ofMillis(1))));
		Assertions.assertFalse(StoreTimeRules.sameProfile(sample,
				StoreTimeObservation.Healthy.fromObservation(admission(identifier(4), RECOVERY), GENERATION, T, Duration.ofMillis(1))));
		Assertions.assertFalse(StoreTimeRules.sameProfile(sample,
				StoreTimeObservation.Healthy.fromObservation(admission(AUTHORITY, identifier(4)), GENERATION, T, Duration.ofMillis(1))));
		Assertions.assertFalse(StoreTimeRules.sameProfile(sample,
				StoreTimeObservation.Healthy.fromObservation(admission(AUTHORITY, RECOVERY), identifier(4), T, Duration.ofMillis(1))));
		Assertions.assertFalse(StoreTimeRules.sameProfile(sample, observation(T, Duration.ofMillis(2))));
	}

	@Test
	void elapsedSupportsNegativeAnchorsButClosesOnReverseOrSubtractionOverflow() {
		Assertions.assertEquals(Optional.of(Duration.ZERO), StoreTimeRules.elapsed(-5, -5));
		Assertions.assertEquals(Optional.of(Duration.ofNanos(10)), StoreTimeRules.elapsed(-5, 5));
		Assertions.assertEquals(Optional.of(Duration.ofNanos(Long.MAX_VALUE)), StoreTimeRules.elapsed(0, Long.MAX_VALUE));
		Assertions.assertTrue(StoreTimeRules.elapsed(5, -5).isEmpty());
		Assertions.assertTrue(StoreTimeRules.elapsed(Long.MIN_VALUE, Long.MAX_VALUE).isEmpty());
		Assertions.assertTrue(StoreTimeRules.elapsed(Long.MAX_VALUE, Long.MIN_VALUE).isEmpty());
	}

	@Test
	void remainingBudgetUsesOnlyTheOriginalStartAndStrictPositiveRemainder() {
		Duration budget = Duration.ofNanos(20);
		Assertions.assertEquals(Optional.of(Duration.ofNanos(20)), StoreTimeRules.remainingBudget(budget, 100, 100));
		Assertions.assertEquals(Optional.of(Duration.ofNanos(1)), StoreTimeRules.remainingBudget(budget, 100, 119));
		Assertions.assertTrue(StoreTimeRules.remainingBudget(budget, 100, 120).isEmpty());
		Assertions.assertTrue(StoreTimeRules.remainingBudget(budget, 100, 121).isEmpty());
		Assertions.assertTrue(StoreTimeRules.remainingBudget(budget, 100, 99).isEmpty());
		Assertions.assertTrue(StoreTimeRules.remainingBudget(budget, Long.MIN_VALUE, Long.MAX_VALUE).isEmpty());
		Assertions.assertTrue(StoreTimeRules.remainingBudget(Duration.ZERO, 100, 100).isEmpty());
		Assertions.assertTrue(StoreTimeRules.remainingBudget(Duration.ofNanos(-1), 100, 100).isEmpty());
	}

	@Test
	void hugePositiveBudgetNeverConvertsToNanosOrExtendsTheOriginalBudget() {
		Duration huge = Duration.ofSeconds(Long.MAX_VALUE, 999_999_999);
		Duration remainder = StoreTimeRules.remainingBudget(huge, 100, 110).orElseThrow();
		Assertions.assertEquals(huge.minusNanos(10), remainder);
		Assertions.assertTrue(remainder.compareTo(huge) < 0);
	}

	@Test
	void zeroErrorZeroElapsedAllowsBothFiveSecondEdgesExactly() {
		StoreTimeObservation.Healthy sample = observation(T, Duration.ZERO);
		Assertions.assertTrue(StoreTimeRules.isWorkerClockHealthy(sample, T.minusSeconds(5), Duration.ZERO));
		Assertions.assertTrue(StoreTimeRules.isWorkerClockHealthy(sample, T.plusSeconds(5), Duration.ZERO));
		Assertions.assertFalse(StoreTimeRules.isWorkerClockHealthy(sample, T.minusSeconds(5).minusNanos(1), Duration.ZERO));
		Assertions.assertFalse(StoreTimeRules.isWorkerClockHealthy(sample, T.plusSeconds(5).plusNanos(1), Duration.ZERO));
	}

	@Test
	void maximumErrorAndFullElapsedIntervalTightenBothEdgesWithoutRounding() {
		StoreTimeObservation.Healthy sample = observation(T, Duration.ofMillis(250));
		Duration elapsed = Duration.ofMillis(125);
		Assertions.assertTrue(StoreTimeRules.isWorkerClockHealthy(sample, T.minusMillis(4500), elapsed));
		Assertions.assertFalse(StoreTimeRules.isWorkerClockHealthy(sample, T.minusMillis(4500).minusNanos(1), elapsed));
		Assertions.assertTrue(StoreTimeRules.isWorkerClockHealthy(sample, T.plusMillis(4750), elapsed));
		Assertions.assertFalse(StoreTimeRules.isWorkerClockHealthy(sample, T.plusMillis(4750).plusNanos(1), elapsed));
	}

	@Test
	void intervalOverlapCannotReplaceWholeContainment() {
		StoreTimeObservation.Healthy sample = observation(T, Duration.ZERO);
		// [4s,6s] overlaps the allowed [-5s,5s] but is not contained in it.
		Assertions.assertFalse(StoreTimeRules.isWorkerClockHealthy(sample, T.plusSeconds(6), Duration.ofSeconds(1)));
		// [-6s,0s] also overlaps; using a half-RTT or midpoint would admit it incorrectly.
		Assertions.assertFalse(StoreTimeRules.isWorkerClockHealthy(sample, T, Duration.ofSeconds(3)));
	}

	@Test
	void negativeAndOverflowingElapsedHealthArithmeticCloses() {
		StoreTimeObservation.Healthy sample = observation(T, Duration.ofMillis(250));
		Assertions.assertFalse(StoreTimeRules.isWorkerClockHealthy(sample, T, Duration.ofNanos(-1)));
		Assertions.assertFalse(StoreTimeRules.isWorkerClockHealthy(sample, T, Duration.ofSeconds(Long.MAX_VALUE)));
		Assertions.assertFalse(StoreTimeRules.isWorkerClockHealthy(sample, Instant.MIN, Duration.ZERO));
		Assertions.assertFalse(StoreTimeRules.isWorkerClockHealthy(sample, Instant.MAX, Duration.ZERO));
	}

	@Test
	void releaseBoundIsStrictAndUsesFullElapsedRateAndError() {
		StoreTimeObservation.Healthy sample = observation(T, Duration.ofMillis(250));
		Duration elapsed = Duration.ofMillis(125);
		Instant upper = T.plusMillis(500);
		Assertions.assertTrue(StoreTimeRules.isReleaseBefore(sample, elapsed, upper.plusNanos(1)));
		Assertions.assertFalse(StoreTimeRules.isReleaseBefore(sample, elapsed, upper));
		Assertions.assertFalse(StoreTimeRules.isReleaseBefore(sample, elapsed, upper.minusNanos(1)));
		Assertions.assertFalse(StoreTimeRules.isReleaseBefore(sample, Duration.ZERO, T.plusMillis(250)));
	}

	@Test
	void releaseRejectsNegativeOverflowAndUnsupportedEndInstants() {
		StoreTimeObservation.Healthy sample = observation(T, Duration.ZERO);
		Assertions.assertFalse(StoreTimeRules.isReleaseBefore(sample, Duration.ofNanos(-1), T.plusSeconds(1)));
		Assertions.assertFalse(StoreTimeRules.isReleaseBefore(sample, Duration.ofSeconds(Long.MAX_VALUE), T.plusSeconds(1)));
		Assertions.assertFalse(StoreTimeRules.isReleaseBefore(sample, Duration.ofSeconds(Long.MAX_VALUE / 2), T.plusSeconds(1)));
		Assertions.assertFalse(StoreTimeRules.isReleaseBefore(sample, Duration.ZERO, Instant.EPOCH.minusNanos(1)));
		Assertions.assertFalse(StoreTimeRules.isReleaseBefore(sample, Duration.ZERO, Instant.ofEpochSecond(253402300800L)));
	}

	@Test
	void exactSupportedMaximumRemainsAnExclusiveBoundary() {
		Instant maximum = Instant.ofEpochSecond(253402300799L, 999_999_999);
		Assertions.assertTrue(StoreTimeRules.isReleaseBefore(observation(maximum.minusNanos(1), Duration.ZERO), Duration.ZERO, maximum));
		Assertions.assertFalse(StoreTimeRules.isReleaseBefore(observation(maximum, Duration.ZERO), Duration.ZERO, maximum));
		Assertions.assertFalse(StoreTimeRules.isReleaseBefore(observation(maximum, Duration.ofNanos(1)), Duration.ZERO, maximum));
	}

	@Test
	void privateCausalFixtureSamplesWallAfterReplyAndKeepsAuthorityIndependent() {
		List<String> trace = causalTrace(false);
		assertCausalOrder(trace);
		Assertions.assertEquals(List.of("elapsed-start", "store-call", "store-reply", "worker-wall", "elapsed-end"), trace);
		Clock aliased = Clock.fixed(T, ZoneOffset.UTC);
		Assertions.assertThrows(IllegalArgumentException.class, () -> new CausalFixture(aliased, aliased));
	}

	@Test
	void seededPrematureWallSampleFailsTheCallerOrderOracleEvenWithIdenticalNumbers() {
		StoreTimeObservation.Healthy sample = observation(T, Duration.ZERO);
		// Pure arithmetic alone cannot distinguish these identical inputs.
		Assertions.assertTrue(StoreTimeRules.isWorkerClockHealthy(sample, T, Duration.ZERO));
		Assertions.assertThrows(AssertionError.class, () -> assertCausalOrder(causalTrace(true)));
	}

	@SuppressWarnings("NullAway")
	@Test
	void nullArgumentsAreRejectedBeforeArithmetic() {
		StoreAdmission admission = admission(AUTHORITY, RECOVERY);
		StoreTimeObservation.Healthy sample = observation(T, Duration.ZERO);
		Assertions.assertThrows(NullPointerException.class, () -> StoreTimeRules.sameAdmission(nullValue(), admission));
		Assertions.assertThrows(NullPointerException.class, () -> StoreTimeRules.sameAdmission(admission, nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> StoreTimeRules.sameProfile(nullValue(), sample));
		Assertions.assertThrows(NullPointerException.class, () -> StoreTimeRules.sameProfile(sample, nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> StoreTimeRules.remainingBudget(nullValue(), 0, 0));
		Assertions.assertThrows(NullPointerException.class, () -> StoreTimeRules.isWorkerClockHealthy(nullValue(), T, Duration.ZERO));
		Assertions.assertThrows(NullPointerException.class, () -> StoreTimeRules.isWorkerClockHealthy(sample, nullValue(), Duration.ZERO));
		Assertions.assertThrows(NullPointerException.class, () -> StoreTimeRules.isWorkerClockHealthy(sample, T, nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> StoreTimeRules.isReleaseBefore(nullValue(), Duration.ZERO, T));
		Assertions.assertThrows(NullPointerException.class, () -> StoreTimeRules.isReleaseBefore(sample, nullValue(), T));
		Assertions.assertThrows(NullPointerException.class, () -> StoreTimeRules.isReleaseBefore(sample, Duration.ZERO, nullValue()));
	}

	private static @NonNull StoreAdmission admission(@NonNull String authority, @NonNull String recovery) {
		return StoreAdmission.fromIdentifiers(authority, recovery);
	}

	private static StoreTimeObservation.@NonNull Healthy observation(@NonNull Instant time, @NonNull Duration error) {
		return StoreTimeObservation.Healthy.fromObservation(admission(AUTHORITY, RECOVERY), GENERATION, time, error);
	}

	private static @NonNull String identifier(int value) {
		byte[] bytes = new byte[32];
		bytes[0] = (byte) value;
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	private static @NonNull List<@NonNull String> causalTrace(boolean prematureWall) {
		return new CausalFixture(Clock.fixed(T, ZoneOffset.UTC), Clock.fixed(T, ZoneOffset.UTC))
				.sample(prematureWall);
	}

	/** Private orchestration only: each recorded phase comes from an actual source/call operation. */
	private static final class CausalFixture {
		private final @NonNull Clock authorityClock;
		private final @NonNull Clock workerWallClock;
		private final @NonNull List<@NonNull String> trace = new ArrayList<>();
		private final @NonNull ScriptedElapsed elapsed = new ScriptedElapsed();

		@SuppressWarnings("ReferenceEquality") // Independence concerns source identity, not equal clock values.
		private CausalFixture(@NonNull Clock authorityClock, @NonNull Clock workerWallClock) {
			if (authorityClock == workerWallClock)
				throw new IllegalArgumentException("Worker and authority sources must be independent.");
			this.authorityClock = authorityClock;
			this.workerWallClock = workerWallClock;
		}

		private @NonNull List<@NonNull String> sample(boolean prematureWall) {
			long started = this.elapsed.sample(this.trace);
			StoreTimeObservation.Healthy observation;
			Instant workerTime;
			if (prematureWall) {
				workerTime = workerWall();
				observation = storeReply();
			} else {
				observation = storeReply();
				workerTime = workerWall();
			}
			long finished = this.elapsed.sample(this.trace);
			Duration measured = StoreTimeRules.elapsed(started, finished).orElseThrow();
			Assertions.assertTrue(StoreTimeRules.isWorkerClockHealthy(observation, workerTime, measured),
					"Identical numeric inputs remain healthy; separate phase oracle must enforce causal order.");
			return List.copyOf(this.trace);
		}

		private StoreTimeObservation.@NonNull Healthy storeReply() {
			this.trace.add("store-call");
			StoreTimeObservation.Healthy observation = observation(this.authorityClock.instant(), Duration.ZERO);
			this.trace.add("store-reply");
			return observation;
		}

		private @NonNull Instant workerWall() {
			Instant sampled = this.workerWallClock.instant();
			this.trace.add("worker-wall");
			return sampled;
		}
	}

	/** A third independent source, with an exact scripted zero interval to keep both numeric examples identical. */
	private static final class ScriptedElapsed {
		private int samples;

		private long sample(@NonNull List<@NonNull String> trace) {
			Assertions.assertTrue(this.samples < 2, "Only the original start/end samples are permitted");
			trace.add(this.samples++ == 0 ? "elapsed-start" : "elapsed-end");
			return 100;
		}
	}

	private static void assertCausalOrder(@NonNull List<@NonNull String> trace) {
		Assertions.assertEquals(List.of("elapsed-start", "store-call", "store-reply", "worker-wall", "elapsed-end"), trace,
				"SC-CLK-03 caller must sample worker wall after the authority reply");
	}

	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> @Nullable T nullValue() {
		return null;
	}
}
