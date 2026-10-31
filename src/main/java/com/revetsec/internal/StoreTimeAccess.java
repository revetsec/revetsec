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
import com.revetsec.StoreTemporalCondition;
import com.revetsec.StoreTimeObservation;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.lang.invoke.MethodHandles;
import java.time.Instant;
import java.util.concurrent.locks.ReentrantLock;

import static java.util.Objects.requireNonNull;

/**
 * Internal shared-secret bridge for engine-created temporal conditions.
 * <p>
 * The root condition installs a private nestmate implementation exactly once. Initialization performs no external
 * I/O, clock reads, randomness or worker creation. This bridge is outside the exported public API, following the
 * existing sealed-state access pattern; it is not a cryptographic capability boundary. Calling the bridge does
 * not authenticate or admit an observation.
 *
 * @since 1.0.0
 */
@ThreadSafe
@CheckReturnValue
public final class StoreTimeAccess {
	private static final @NonNull ReentrantLock SET_LOCK = new ReentrantLock();
	private static volatile @Nullable Operations operations;

	private StoreTimeAccess() {
	}

	/**
	 * The condition's immutable construction operation, shared only with internal engine code.
	 * @since 1.0.0
	 */
	@ThreadSafe
	@CheckReturnValue
	public interface Operations {
		/**
		 * Creates a condition after the caller has authenticated and admitted the observation.
		 *
		 * @param observation the attempt's healthy authority observation
		 * @param notBeforeInclusive the exact lower bound, not before the observation
		 * @param validBeforeExclusive the strictly later upper bound, or {@code null} for nonexpiring work
		 * @return the immutable condition
		 * @throws NullPointerException if observation or lower bound is {@code null}
		 * @throws IllegalArgumentException if a bound is outside the supported UTC range or improperly ordered
		 * @since 1.0.0
		 */
		@NonNull StoreTemporalCondition fromObservation(StoreTimeObservation.@NonNull Healthy observation,
				@NonNull Instant notBeforeInclusive, @Nullable Instant validBeforeExclusive);
	}

	/**
	 * Installs the root condition's own implementation once.
	 *
	 * @param operations the implementation defined by a nestmate of {@code StoreTemporalCondition}
	 * @throws NullPointerException if {@code operations} is {@code null}
	 * @throws IllegalArgumentException if the implementation is not a condition nestmate
	 * @throws IllegalStateException if operations are already installed
	 * @since 1.0.0
	 */
	public static void set(StoreTimeAccess.@NonNull Operations operations) {
		requireNonNull(operations);
		if (operations.getClass().getNestHost() != StoreTemporalCondition.class)
			throw new IllegalArgumentException("Only StoreTemporalCondition installs the store-time operations.");
		SET_LOCK.lock();
		try {
			if (StoreTimeAccess.operations != null)
				throw new IllegalStateException("The store-time operations are already installed.");
			StoreTimeAccess.operations = operations;
		} finally {
			SET_LOCK.unlock();
		}
	}

	/**
	 * Returns the operations after forcing initialization of their owning root class.
	 *
	 * @return the installed operations
	 * @throws IllegalStateException if initialization cannot complete or has not installed operations
	 * @since 1.0.0
	 */
	public static StoreTimeAccess.@NonNull Operations get() {
		try {
			MethodHandles.lookup().ensureInitialized(StoreTemporalCondition.class);
		} catch (IllegalAccessException exception) {
			throw new IllegalStateException("StoreTemporalCondition cannot be initialized.", exception);
		}
		Operations installed = operations;
		if (installed == null)
			throw new IllegalStateException("The store-time operations are not installed.");
		return installed;
	}
}
