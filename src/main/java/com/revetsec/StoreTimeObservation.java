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
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import java.time.Duration;
import java.time.Instant;

import static java.util.Objects.requireNonNull;

/**
 * A backend's immutable time statement, bound to the active data/recovery admission.
 * <p>
 * A healthy statement advertises a deployment capability; it is not itself proof of trusted UTC, current
 * admission, causal worker-clock health or an operation's eligibility. Unavailable time retains only admission
 * identities and never substitutes worker time or an earlier healthy sample.
 *
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public sealed interface StoreTimeObservation
		permits StoreTimeObservation.Healthy, StoreTimeObservation.Unavailable {
	/**
	 * Returns the active authority and data/recovery identities.
	 * @return the admission metadata
	 * @since 1.0.0
	 */
	@NonNull StoreAdmission getAdmission();

	/**
	 * An admitted UTC observation with a fixed generation profile.
	 * <p>
	 * The profile is maximum advance rate 2, maximum worker offset five seconds and a declared UTC-error bound
	 * from zero through 250 milliseconds. Engines must authenticate the root binding and verify the profile,
	 * floors, causal health and original operation budget before using this statement.
	 *
	 * @since 1.0.0
	 */
	@Immutable
	@CheckReturnValue
	final class Healthy implements StoreTimeObservation {
		private static final @NonNull Duration MAXIMUM_UTC_ERROR = Duration.ofMillis(250);
		private static final @NonNull Duration MAXIMUM_WORKER_CLOCK_OFFSET = Duration.ofSeconds(5);
		private final @NonNull StoreAdmission admission;
		private final @NonNull String clockGeneration;
		private final @NonNull Instant observedAt;
		private final @NonNull Duration maximumUtcError;

		private Healthy(@NonNull StoreAdmission admission, @NonNull String clockGeneration,
				@NonNull Instant observedAt, @NonNull Duration maximumUtcError) {
			this.admission = requireNonNull(admission);
			StoreAdmission.validateIdentifier(clockGeneration);
			validateInstant(observedAt);
			requireNonNull(maximumUtcError);
			if (maximumUtcError.isNegative() || maximumUtcError.compareTo(MAXIMUM_UTC_ERROR) > 0)
				throw new IllegalArgumentException("Invalid store-time UTC-error bound.");
			this.clockGeneration = clockGeneration;
			this.observedAt = observedAt;
			this.maximumUtcError = maximumUtcError;
		}

		/**
		 * Validates a backend's UTC statement without authenticating or admitting it.
		 *
		 * @param admission the active authority and data/recovery identities
		 * @param clockGeneration canonical unpadded Base64URL encoding of exactly 32 bytes
		 * @param observedAt UTC instant with epoch seconds in 0 through 253402300799, preserving nanoseconds
		 * @param maximumUtcError the fixed generation's declared bound, zero through 250 milliseconds inclusive
		 * @return the immutable observation
		 * @throws NullPointerException if an argument is {@code null}
		 * @throws IllegalArgumentException if an identifier, instant or error bound is outside the supported profile
		 * @since 1.0.0
		 */
		public static StoreTimeObservation.@NonNull Healthy fromObservation(@NonNull StoreAdmission admission,
				@NonNull String clockGeneration, @NonNull Instant observedAt, @NonNull Duration maximumUtcError) {
			return new Healthy(admission, clockGeneration, observedAt, maximumUtcError);
		}

		/**
		 * Returns the active authority and data/recovery identities.
		 * @return the admission metadata
		 * @since 1.0.0
		 */
		@Override
		public @NonNull StoreAdmission getAdmission() {
			return this.admission;
		}

		/**
		 * Returns the admitted time incarnation's identity.
		 * @return the canonical clock-generation identifier
		 * @since 1.0.0
		 */
		public @NonNull String getClockGeneration() {
			return this.clockGeneration;
		}

		/**
		 * Returns the exact UTC observation, without rounding or clamping.
		 * @return the observed instant
		 * @since 1.0.0
		 */
		public @NonNull Instant getObservedAt() {
			return this.observedAt;
		}

		/**
		 * Returns the declared UTC-error bound fixed for this generation.
		 * @return the maximum error
		 * @since 1.0.0
		 */
		public @NonNull Duration getMaximumUtcError() {
			return this.maximumUtcError;
		}

		/**
		 * Returns the supported maximum UTC advance per measured elapsed second.
		 * @return the fixed boxed rate, 2
		 * @since 1.0.0
		 */
		public @NonNull Integer getMaximumUtcAdvanceRate() {
			return 2;
		}

		/**
		 * Returns the supported maximum worker-wall-clock offset, independent of protocol skew.
		 * @return the fixed five-second bound
		 * @since 1.0.0
		 */
		public @NonNull Duration getMaximumWorkerClockOffset() {
			return MAXIMUM_WORKER_CLOCK_OFFSET;
		}

		/**
		 * Returns a fixed description that discloses no time, profile or identifier.
		 * @return the redacted description
		 * @since 1.0.0
		 */
		@Override
		public @NonNull String toString() {
			return "Healthy{observation=<redacted>}";
		}

		static void validateInstant(@NonNull Instant value) {
			requireNonNull(value);
			if (value.getEpochSecond() < 0 || value.getEpochSecond() > 253402300799L)
				throw new IllegalArgumentException("Invalid store-time instant.");
		}
	}

	/**
	 * Time is unavailable while the authority/data admission metadata remains obtainable.
	 *
	 * @since 1.0.0
	 */
	@Immutable
	@CheckReturnValue
	final class Unavailable implements StoreTimeObservation {
		private final @NonNull StoreAdmission admission;

		private Unavailable(@NonNull StoreAdmission admission) {
			this.admission = requireNonNull(admission);
		}

		/**
		 * Retains active admission metadata without inventing UTC evidence.
		 * @param admission the authority and data/recovery identities
		 * @return the time-unavailable observation
		 * @throws NullPointerException if {@code admission} is {@code null}
		 * @since 1.0.0
		 */
		public static StoreTimeObservation.@NonNull Unavailable fromAdmission(@NonNull StoreAdmission admission) {
			return new Unavailable(admission);
		}

		/**
		 * Returns the active authority and data/recovery identities.
		 * @return the admission metadata
		 * @since 1.0.0
		 */
		@Override
		public @NonNull StoreAdmission getAdmission() {
			return this.admission;
		}

		/**
		 * Returns a fixed description that discloses neither identity.
		 * @return the redacted description
		 * @since 1.0.0
		 */
		@Override
		public @NonNull String toString() {
			return "Unavailable{admission=<redacted>}";
		}
	}
}
