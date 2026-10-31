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
import com.revetsec.internal.StoreTimeAccess;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.time.Instant;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * An engine-created exact time predicate, inspected by the backend inside its final atomic context.
 * <p>
 * The lower bound is inclusive and the optional upper bound is exclusive. The engine must additionally include
 * its authenticated namespace minimum, relevant entity floors and original business expiries. Absence of an upper
 * bound is reserved for nonexpiring maintenance/barriers and never removes the operation's monotonic deadline,
 * healthy time, worker-health or final-admission requirements. Construction alone establishes no trust.
 *
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class StoreTemporalCondition {
	private final @NonNull StoreAdmission admission;
	private final @NonNull String clockGeneration;
	private final @NonNull Instant notBeforeInclusive;
	private final @Nullable Instant validBeforeExclusive;

	static {
		StoreTimeAccess.set(new AccessOperations());
	}

	private StoreTemporalCondition(StoreTimeObservation.@NonNull Healthy observation,
			@NonNull Instant notBeforeInclusive, @Nullable Instant validBeforeExclusive) {
		requireNonNull(observation);
		StoreTimeObservation.Healthy.validateInstant(notBeforeInclusive);
		if (notBeforeInclusive.isBefore(observation.getObservedAt()))
			throw new IllegalArgumentException("Store-time lower bound precedes its observation.");
		if (validBeforeExclusive != null) {
			StoreTimeObservation.Healthy.validateInstant(validBeforeExclusive);
			if (!validBeforeExclusive.isAfter(notBeforeInclusive))
				throw new IllegalArgumentException("Invalid store-time exclusive upper bound.");
		}
		this.admission = observation.getAdmission();
		this.clockGeneration = observation.getClockGeneration();
		this.notBeforeInclusive = notBeforeInclusive;
		this.validBeforeExclusive = validBeforeExclusive;
	}

	/**
	 * Returns the expected authority and data/recovery identities.
	 * @return the admission metadata
	 * @since 1.0.0
	 */
	public @NonNull StoreAdmission getAdmission() {
		return this.admission;
	}

	/**
	 * Returns the expected admitted time incarnation.
	 * @return the clock-generation identifier
	 * @since 1.0.0
	 */
	public @NonNull String getClockGeneration() {
		return this.clockGeneration;
	}

	/**
	 * Returns the exact inclusive lower bound to check after all final lock waits.
	 * @return the lower bound
	 * @since 1.0.0
	 */
	public @NonNull Instant getNotBeforeInclusive() {
		return this.notBeforeInclusive;
	}

	/**
	 * Returns the original exclusive upper bound, when this operation is expiring.
	 * @return the optional exclusive upper bound
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull Instant> getValidBeforeExclusive() {
		return Optional.ofNullable(this.validBeforeExclusive);
	}

	/**
	 * Returns a fixed description that discloses no identities or bounds.
	 * @return the redacted description
	 * @since 1.0.0
	 */
	@Override
	public @NonNull String toString() {
		return "StoreTemporalCondition{condition=<redacted>}";
	}

	private static final class AccessOperations implements StoreTimeAccess.Operations {
		@Override
		public @NonNull StoreTemporalCondition fromObservation(StoreTimeObservation.@NonNull Healthy observation,
				@NonNull Instant notBeforeInclusive, @Nullable Instant validBeforeExclusive) {
			return new StoreTemporalCondition(observation, notBeforeInclusive, validBeforeExclusive);
		}
	}
}
