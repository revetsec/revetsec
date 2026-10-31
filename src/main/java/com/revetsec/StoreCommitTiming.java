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

package com.revetsec;

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.internal.StoreTimeRules;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Immutable factual validation timing and optional timing after known durable acknowledgement.
 * <p>
 * Validation time is not physical commit time. Completion acquisition may fail without changing a known commit;
 * the backend then supplies absent completion. This factory rejects a supplied inconsistent completion instead of
 * silently dropping it. Neither observation proves authenticity, effect certainty or service-release eligibility.
 *
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class StoreCommitTiming {
	private final StoreTimeObservation.@NonNull Healthy validatedTime;
	private final StoreTimeObservation.@Nullable Healthy completedTime;

	private StoreCommitTiming(StoreTimeObservation.@NonNull Healthy validatedTime,
			StoreTimeObservation.@Nullable Healthy completedTime) {
		this.validatedTime = requireNonNull(validatedTime);
		if (completedTime != null) {
			if (!StoreTimeRules.sameProfile(validatedTime, completedTime)
					|| completedTime.getObservedAt().isBefore(validatedTime.getObservedAt()))
				throw new IllegalArgumentException("Inconsistent store commit timing.");
		}
		this.completedTime = completedTime;
	}

	/**
	 * Validates the supplied observations without authenticating their timing or transaction outcome.
	 *
	 * @param validatedTime the fresh observation under final transaction locks before the mutation decision
	 * @param completedTime a same-admission/generation/profile observation after known durable acknowledgement,
	 *                      no earlier than validation, or {@code null} when unavailable
	 * @return the immutable timing
	 * @throws NullPointerException if {@code validatedTime} is {@code null}
	 * @throws IllegalArgumentException if supplied completion differs in admission, generation or profile,
	 *                                  or precedes validation
	 * @since 1.0.0
	 */
	public static @NonNull StoreCommitTiming fromTimes(StoreTimeObservation.@NonNull Healthy validatedTime,
			StoreTimeObservation.@Nullable Healthy completedTime) {
		return new StoreCommitTiming(validatedTime, completedTime);
	}

	/**
	 * Returns the observation from final transaction validation.
	 * @return the validation observation
	 * @since 1.0.0
	 */
	public StoreTimeObservation.@NonNull Healthy getValidatedTime() {
		return this.validatedTime;
	}

	/**
	 * Returns the optional post-acknowledgement observation.
	 * @return the optional completion observation
	 * @since 1.0.0
	 */
	public @NonNull Optional<StoreTimeObservation.@NonNull Healthy> getCompletedTime() {
		return Optional.ofNullable(this.completedTime);
	}

	/**
	 * Returns a fixed description that discloses no timing or identities.
	 * @return the redacted description
	 * @since 1.0.0
	 */
	@Override
	public @NonNull String toString() {
		return "StoreCommitTiming{timing=<redacted>}";
	}
}
