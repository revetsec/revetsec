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

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.StoreAdmission;
import com.revetsec.StoreTimeObservation;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Pure arithmetic and matching rules for admitted store time.
 * <p>
 * These functions neither acquire nor authenticate an observation. The engine owns the causal order
 * {@code elapsed start -> store reply -> worker wall sample -> elapsed end}, generation admission,
 * permit currentness and cumulative effects. A numeric argument cannot establish that its caller
 * took a sample in the required order. Invalid elapsed time and arithmetic overflow close eligibility;
 * they never reset a deadline or change a known transaction effect.
 * <p>
 * TOTP, WebAuthn and issuer use these rules after their coordinated transitions.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
@CheckReturnValue
public final class StoreTimeRules {
	private StoreTimeRules() {
		// Pure shared rules only.
	}

	/**
	 * Compares authority and recovery identities by value, without authenticating them.
	 *
	 * @param expected the attempted admission
	 * @param actual the observed admission
	 * @return whether both identity domains match
	 * @throws NullPointerException if either argument is {@code null}
	 */
	public static boolean sameAdmission(@NonNull StoreAdmission expected, @NonNull StoreAdmission actual) {
		requireNonNull(expected);
		requireNonNull(actual);
		return expected.getAuthorityId().equals(actual.getAuthorityId())
				&& expected.getRecoveryGeneration().equals(actual.getRecoveryGeneration());
	}

	/**
	 * Compares the entire admitted identity tuple and fixed generation profile. Observation times may differ.
	 *
	 * @param expected the attempted observation
	 * @param actual the later observation
	 * @return whether admission, clock generation, UTC error, rate and worker offset match
	 * @throws NullPointerException if either argument is {@code null}
	 */
	public static boolean sameProfile(StoreTimeObservation.@NonNull Healthy expected,
			StoreTimeObservation.@NonNull Healthy actual) {
		requireNonNull(expected);
		requireNonNull(actual);
		return sameAdmission(expected.getAdmission(), actual.getAdmission())
				&& expected.getClockGeneration().equals(actual.getClockGeneration())
				&& expected.getMaximumUtcError().equals(actual.getMaximumUtcError())
				&& expected.getMaximumUtcAdvanceRate().equals(actual.getMaximumUtcAdvanceRate())
				&& expected.getMaximumWorkerClockOffset().equals(actual.getMaximumWorkerClockOffset());
	}

	/**
	 * Calculates an elapsed interval from ordered samples of one continuously running elapsed source.
	 * <p>
	 * A negative difference or signed subtraction overflow returns empty. Numeric wrap is conservatively
	 * unavailable rather than inferred to be valid continuity. This rule cannot detect a stopped or reset
	 * source whose numbers happen to look valid; its platform continuity remains the caller's obligation.
	 *
	 * @param startedNanos the sample at the start of the measured interval
	 * @param finishedNanos the sample at the end of the same interval
	 * @return the exact nonnegative interval, or empty for invalid/unrepresentable elapsed time
	 */
	public static @NonNull Optional<@NonNull Duration> elapsed(long startedNanos, long finishedNanos) {
		try {
			long nanos = Math.subtractExact(finishedNanos, startedNanos);
			return nanos < 0 ? Optional.empty() : Optional.of(Duration.ofNanos(nanos));
		} catch (ArithmeticException exception) {
			return Optional.empty();
		}
	}

	/**
	 * Subtracts elapsed time from the original full-operation budget, without converting a large duration to nanos.
	 * This does not apply an operational cap: each backend retains its own cap without enlarging this remainder.
	 *
	 * @param originalBudget the one original operation budget, never a newly reset retry budget
	 * @param startedNanos the original operation's elapsed start
	 * @param nowNanos the current sample of that same elapsed source
	 * @return a strictly positive remainder, or empty for exhausted/invalid time or a nonpositive budget
	 * @throws NullPointerException if {@code originalBudget} is {@code null}
	 */
	public static @NonNull Optional<@NonNull Duration> remainingBudget(@NonNull Duration originalBudget,
			long startedNanos, long nowNanos) {
		requireNonNull(originalBudget);
		if (originalBudget.isNegative() || originalBudget.isZero())
			return Optional.empty();
		Optional<Duration> measured = elapsed(startedNanos, nowNanos);
		if (measured.isEmpty() || measured.get().compareTo(originalBudget) >= 0)
			return Optional.empty();
		return Optional.of(originalBudget.minus(measured.get()));
	}

	/**
	 * Checks containment of the full possible worker offset interval in the declared tolerance.
	 * <p>
	 * The caller must measure the causal sequence {@code m0 -> store reply(T) -> W -> m1}, then supply
	 * {@code measuredElapsed = m1 - m0} and {@code workerWallAfterReply = W}. With error {@code delta} and
	 * advance rate {@code r}, the interval is {@code [W - T - r*D - delta, W - T + delta]}. Mere overlap
	 * with {@code [-epsilon,+epsilon]} is insufficient. This is separate from the original deadline.
	 *
	 * @param observation the admitted store observation
	 * @param workerWallAfterReply the worker wall sample obtained after this observation's reply
	 * @param measuredElapsed the complete causal interval, not half its round-trip duration
	 * @return whether the whole interval fits, or false for negative/overflowing elapsed arithmetic
	 * @throws NullPointerException if an argument is {@code null}
	 */
	public static boolean isWorkerClockHealthy(StoreTimeObservation.@NonNull Healthy observation,
			@NonNull Instant workerWallAfterReply, @NonNull Duration measuredElapsed) {
		requireNonNull(observation);
		requireNonNull(workerWallAfterReply);
		requireNonNull(measuredElapsed);
		if (measuredElapsed.isNegative())
			return false;
		try {
			Duration offset = Duration.between(observation.getObservedAt(), workerWallAfterReply);
			Duration error = observation.getMaximumUtcError();
			Duration tolerance = observation.getMaximumWorkerClockOffset();
			Duration advance = measuredElapsed.multipliedBy(observation.getMaximumUtcAdvanceRate());
			Duration lower = offset.minus(advance).minus(error);
			Duration upper = offset.plus(error);
			return lower.compareTo(tolerance.negated()) >= 0 && upper.compareTo(tolerance) <= 0;
		} catch (ArithmeticException exception) {
			return false;
		}
	}

	/**
	 * Checks that a conservative authority release bound precedes a finite original expiry, strictly.
	 * <p>
	 * The bound is {@code finalReadAt + delta + r * elapsed(finalReadCallStart, release)}. The caller
	 * separately checks a fresh same-profile final admission, causal worker health, original deadline,
	 * permit and known requested commitment. This function does not establish any of those facts or
	 * bound the time of a subsequent socket delivery. A supported bound has epoch seconds in
	 * {@code 0..253402300799}; invalid elapsed time, out-of-range expiry and overflow return false.
	 *
	 * @param finalObservation the fresh final root observation
	 * @param elapsedFromCallStart the full measured interval from final-read call start to release check
	 * @param validBeforeExclusive the original finite exclusive upper bound
	 * @return whether the conservative bound is strictly before the supported expiry
	 * @throws NullPointerException if an argument is {@code null}
	 */
	public static boolean isReleaseBefore(StoreTimeObservation.@NonNull Healthy finalObservation,
			@NonNull Duration elapsedFromCallStart, @NonNull Instant validBeforeExclusive) {
		requireNonNull(finalObservation);
		requireNonNull(elapsedFromCallStart);
		requireNonNull(validBeforeExclusive);
		if (elapsedFromCallStart.isNegative() || validBeforeExclusive.getEpochSecond() < 0
				|| validBeforeExclusive.getEpochSecond() > 253402300799L)
			return false;
		try {
			Duration advance = elapsedFromCallStart.multipliedBy(finalObservation.getMaximumUtcAdvanceRate());
			Instant upper = finalObservation.getObservedAt().plus(finalObservation.getMaximumUtcError()).plus(advance);
			return upper.isBefore(validBeforeExclusive);
		} catch (ArithmeticException | DateTimeException exception) {
			return false;
		}
	}
}
