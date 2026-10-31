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

package com.revetsec.totp;

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.StoreAdmission;
import com.revetsec.StoreCommitTiming;
import com.revetsec.StoreTemporalCondition;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.StoreTimeRules;
import com.revetsec.internal.crypto.EntropySource;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Explicit bounded, volatile, single-process TOTP demonstration store. Restart loses factors,
 * recovery consumption, replay marks and every recovery/clock fence. Never use it as an automatic
 * fallback, as authoritative storage for established accounts or across independent processes.
 * No record is evicted or expired. A configured namespace begins NEW and activates only through
 * an atomic initialization write. Fresh recovery epochs retain old records and permanently fence
 * old writers; this process-local history is not a substitute for an external durable controller.
 * <p>The first operational call establishes this store's own volatile UTC projection and metadata.
 * The authenticator's worker Clock is not its time source. Healthy time is a fixed projection of
 * that initial store-owned host UTC reading using this process's elapsed clock; no per-operation
 * wall-clock maximum or mutable namespace record is written. This is a local demonstration
 * assertion, not external UTC, restore, device-durability or suspend/rate qualification.
 * @since 1.0.0
 */
@javax.annotation.concurrent.ThreadSafe
@CheckReturnValue
public final class InMemoryTotpStore implements TotpStore {
	private static final int MAXIMUM_ENTRIES = 65536;
	private static final long MAXIMUM_BYTES = 268435456L;
	private static final long MAXIMUM_BUDGET_NANOS = TimeUnit.SECONDS.toNanos(30);
	private static final @NonNull Duration LOCAL_UTC_ERROR = Duration.ofMillis(250);
	private final @NonNull ReentrantLock lock = new ReentrantLock();
	private final @NonNull String credentialNamespace;
	private final int maximumEntries;
	private final long maximumSealedBytes;
	// All mutable store state below is guarded by lock.
	private final @NonNull Set<@NonNull String> usedEpochs = new HashSet<>();
	private @NonNull String recoveryEpoch;
	private volatile boolean activated;
	private @NonNull Map<@NonNull TotpStoreKey, @NonNull TotpStoreRecord> records = Map.of();
	private long sealedBytes;
	private @Nullable EntropySource entropy;
	private @Nullable StoreAdmission admission;
	private @Nullable String clockGeneration;
	private @Nullable Instant authorityAnchor;
	private long authorityStartedNanos;
	private long lastAuthorityNanos;
	private boolean authorityContinuityLost;

	private InMemoryTotpStore(@NonNull Builder builder) {
		this.credentialNamespace = builder.credentialNamespace;
		this.recoveryEpoch = builder.recoveryEpoch;
		this.maximumEntries = builder.maximumEntries;
		this.maximumSealedBytes = builder.maximumSealedBytes;
		this.usedEpochs.add(this.recoveryEpoch);
	}
	/**
	 * Starts configuration for one explicit volatile namespace and fresh recovery epoch.
	 * @param credentialNamespace the visible ASCII namespace
	 * @param recoveryEpoch the never-reused recovery epoch
	 * @return a caller-thread builder
	 * @since 1.0.0
	 */
	public static @NonNull Builder withNamespace(@NonNull String credentialNamespace,
			@NonNull String recoveryEpoch) { return new Builder(credentialNamespace, recoveryEpoch); }

	/**
	 * Provisions and fences to a fresh epoch in this demonstration store. The application must close
	 * admission and drain operations before calling it. Existing records remain retained and count
	 * against capacity. An epoch previously used by this store can never be selected again.
	 * The time projection and authority identity continue; only data recovery admission changes.
	 * This cannot repair lost clock continuity or establish shared-store recovery after restart.
	 * @param recoveryEpoch the fresh never-reused epoch
	 * @param remainingBudget remaining positive administration budget
	 * @return factual COMMITTED, or CAPACITY_REFUSED/UNAVAILABLE before mutation
	 * @since 1.0.0
	 */
	public @NonNull TotpStoreCommitResult provisionRecoveryEpoch(@NonNull String recoveryEpoch,
			@NonNull Duration remainingBudget) {
		TotpStoreKey.validateScope(recoveryEpoch);
		long deadline = deadline(remainingBudget);
		if (!acquire(deadline)) return TotpStoreCommitResult.UNAVAILABLE;
		try {
			if (expired(deadline)) return TotpStoreCommitResult.UNAVAILABLE;
			if (this.usedEpochs.contains(recoveryEpoch))
				throw new IllegalArgumentException("TOTP recovery epochs cannot be reused");
			if (this.usedEpochs.size() >= MAXIMUM_ENTRIES) return TotpStoreCommitResult.CAPACITY_REFUSED;
			StoreAdmission nextAdmission;
			try {
				StoreAdmission current = operationalAdmission();
				nextAdmission = StoreAdmission.fromIdentifiers(current.getAuthorityId(), newIdentity());
			} catch (RuntimeException unavailable) { return TotpStoreCommitResult.UNAVAILABLE; }
			if (expired(deadline)) return TotpStoreCommitResult.UNAVAILABLE;
			this.usedEpochs.add(recoveryEpoch);
			this.recoveryEpoch = recoveryEpoch;
			this.admission = nextAdmission;
			this.activated = false;
			// This process knows the assignment happened; a late acknowledgement cannot erase it.
			return TotpStoreCommitResult.COMMITTED;
		} finally { this.lock.unlock(); }
	}

	@Override public @NonNull TotpStoreReadResult read(@NonNull Set<@NonNull TotpStoreKey> keys,
			@NonNull Duration remainingBudget) {
		validateKeys(keys);
		long deadline = deadline(remainingBudget);
		if (!acquire(deadline)) return TotpStoreReadResult.Unavailable.get();
		try {
			if (expired(deadline)) return TotpStoreReadResult.Unavailable.get();
			TotpStoreKey first = keys.iterator().next();
			if (!isActiveScope(first.getCredentialNamespace(), first.getRecoveryEpoch())) return TotpStoreReadResult.Fenced.get();
			TotpStoreKey root = TotpStoreKey.forNamespace(this.credentialNamespace, this.recoveryEpoch);
			if ((this.activated && !this.records.containsKey(root))
					|| (!this.activated && (keys.size() != 1 || !keys.contains(root)))) return TotpStoreReadResult.Unavailable.get();
			Map<TotpStoreKey, TotpStoreEntry> observed = new HashMap<>();
			for (TotpStoreKey key : keys) {
				TotpStoreRecord record = this.records.get(key);
				observed.put(key, record == null ? TotpStoreEntry.Absent.confirmed() : TotpStoreEntry.Present.fromRecord(record));
			}
			StoreTimeObservation time;
			try { time = observe(); } catch (RuntimeException unavailable) { return TotpStoreReadResult.Unavailable.get(); }
			TotpStoreSnapshot snapshot = TotpStoreSnapshot.fromEntries(keys, observed, time);
			return expired(deadline) ? TotpStoreReadResult.Unavailable.get() : TotpStoreReadResult.Available.fromSnapshot(snapshot);
		} finally { this.lock.unlock(); }
	}

	@Override public @NonNull TotpStoreCommitReceipt compareAndCommit(@NonNull TotpStoreWrite write,
			@NonNull Duration remainingBudget) {
		Objects.requireNonNull(write);
		long deadline = deadline(remainingBudget);
		if (!acquire(deadline)) return refuse(TotpStoreCommitResult.UNAVAILABLE);
		try {
			if (expired(deadline)) return refuse(TotpStoreCommitResult.UNAVAILABLE);
			if (!isActiveScope(write.getCredentialNamespace(), write.getRecoveryEpoch())) return refuse(TotpStoreCommitResult.FENCED);
			StoreAdmission current;
			try { current = operationalAdmission(); } catch (RuntimeException unavailable) { return refuse(TotpStoreCommitResult.UNAVAILABLE); }
			StoreTemporalCondition condition = write.getTemporalCondition();
			if (!StoreTimeRules.sameAdmission(current, condition.getAdmission())
					|| !Objects.equals(this.clockGeneration, condition.getClockGeneration())) return refuse(TotpStoreCommitResult.FENCED);
			TotpStoreKey root = TotpStoreKey.forNamespace(this.credentialNamespace, this.recoveryEpoch);
			if (write.getPurpose() == TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE) {
				if (this.activated) return refuse(this.records.containsKey(root) ? TotpStoreCommitResult.CONFLICT : TotpStoreCommitResult.UNAVAILABLE);
				if (this.records.containsKey(root)) return refuse(TotpStoreCommitResult.UNAVAILABLE);
			} else if (!this.activated || !this.records.containsKey(root)) return refuse(TotpStoreCommitResult.UNAVAILABLE);
			for (Map.Entry<TotpStoreKey, TotpStoreEntry> predicate : write.getSnapshot().getEntries().entrySet()) {
				TotpStoreRecord actual = this.records.get(predicate.getKey());
				TotpStoreEntry expected = predicate.getValue();
				if ((expected instanceof TotpStoreEntry.Absent && actual != null)
						|| (expected instanceof TotpStoreEntry.Present present
								&& (actual == null || !present.getRecord().getVersion().equals(actual.getVersion())))) return refuse(TotpStoreCommitResult.CONFLICT);
			}
			StoreTimeObservation time;
			try { time = observe(); } catch (RuntimeException unavailable) { return refuse(TotpStoreCommitResult.TIME_UNAVAILABLE); }
			if (!(time instanceof StoreTimeObservation.Healthy healthy)) return refuse(TotpStoreCommitResult.TIME_UNAVAILABLE);
			StoreTimeObservation snapshotTime = write.getSnapshot().getTimeObservation();
			if (!(snapshotTime instanceof StoreTimeObservation.Healthy attempted) || !StoreTimeRules.sameProfile(attempted, healthy))
				return refuse(TotpStoreCommitResult.FENCED);
			if (healthy.getObservedAt().isBefore(condition.getNotBeforeInclusive())) return refuse(TotpStoreCommitResult.TIME_BEFORE_FLOOR);
			if (condition.getValidBeforeExclusive().isPresent()
					&& !healthy.getObservedAt().isBefore(condition.getValidBeforeExclusive().get())) return refuse(TotpStoreCommitResult.TIME_EXPIRED);
			if (write.getMutations().isEmpty()) {
				TotpStoreCommitReceipt barrier = TotpStoreCommitReceipt.fromCommittedTiming(StoreCommitTiming.fromTimes(healthy, null));
				return expired(deadline) ? refuse(TotpStoreCommitResult.UNAVAILABLE) : barrier;
			}
			Map<TotpStoreKey, TotpStoreRecord> next = new HashMap<>(this.records);
			long nextBytes = this.sealedBytes;
			for (TotpStoreWrite.Mutation mutation : write.getMutations()) {
				TotpStoreRecord previous = next.put(mutation.getKey(), mutation.getRecord());
				if (previous != null) nextBytes -= previous.getSealedBytes().length;
				nextBytes += mutation.getRecord().getSealedBytes().length;
			}
			if (next.size() > this.maximumEntries || nextBytes > this.maximumSealedBytes) return refuse(TotpStoreCommitResult.CAPACITY_REFUSED);
			TotpStoreCommitReceipt committed = TotpStoreCommitReceipt.fromCommittedTiming(StoreCommitTiming.fromTimes(healthy, null));
			if (expired(deadline)) return refuse(TotpStoreCommitResult.UNAVAILABLE);
			this.records = next;
			this.sealedBytes = nextBytes;
			if (write.getPurpose() == TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE) this.activated = true;
			return committed;
		} finally { this.lock.unlock(); }
	}

	private static @NonNull TotpStoreCommitReceipt refuse(@NonNull TotpStoreCommitResult status) {
		return TotpStoreCommitReceipt.fromRefusal(status);
	}
	// Caller holds lock; first operational use, not construction, establishes metadata.
	private @NonNull StoreAdmission operationalAdmission() {
		StoreAdmission current = this.admission;
		if (current == null) {
			StoreAdmission created = StoreAdmission.fromIdentifiers(newIdentity(), newIdentity());
			String clock = newIdentity();
			this.admission = created;
			this.clockGeneration = clock;
			return created;
		}
		return current;
	}
	// Caller holds lock; the worker's configured Clock is never sampled here.
	private @NonNull StoreTimeObservation observe() {
		StoreAdmission current = operationalAdmission();
		Instant anchor = this.authorityAnchor;
		if (anchor == null && !this.authorityContinuityLost) {
			long before = System.nanoTime();
			Instant captured = Instant.now();
			long after = System.nanoTime();
			Optional<Duration> bracket = StoreTimeRules.elapsed(before, after);
			if (bracket.isEmpty() || bracket.get().compareTo(LOCAL_UTC_ERROR) > 0 || !supported(captured)) {
				this.authorityContinuityLost = true;
			} else {
				this.authorityAnchor = captured;
				this.authorityStartedNanos = after;
				this.lastAuthorityNanos = after;
				anchor = captured;
			}
		}
		if (anchor == null || this.authorityContinuityLost) return StoreTimeObservation.Unavailable.fromAdmission(current);
		long now = System.nanoTime();
		Optional<Duration> elapsed = StoreTimeRules.elapsed(this.authorityStartedNanos, now);
		if (StoreTimeRules.elapsed(this.lastAuthorityNanos, now).isEmpty() || elapsed.isEmpty()) {
			this.authorityContinuityLost = true;
			return StoreTimeObservation.Unavailable.fromAdmission(current);
		}
		this.lastAuthorityNanos = now;
		try {
			Instant point = anchor.plus(elapsed.get());
			if (!supported(point)) {
				this.authorityContinuityLost = true;
				return StoreTimeObservation.Unavailable.fromAdmission(current);
			}
			return StoreTimeObservation.Healthy.fromObservation(current, Objects.requireNonNull(this.clockGeneration), point, LOCAL_UTC_ERROR);
		} catch (DateTimeException | ArithmeticException invalid) {
			this.authorityContinuityLost = true;
			return StoreTimeObservation.Unavailable.fromAdmission(current);
		}
	}
	private static boolean supported(@NonNull Instant time) { return time.getEpochSecond() >= 0 && time.getEpochSecond() <= 253402300799L; }
	private @NonNull String newIdentity() {
		EntropySource source = this.entropy;
		if (source == null) {
			source = EntropySource.fromDefaults();
			this.entropy = source;
		}
		byte[] value = source.nextBytes(32);
		try { return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
		finally { Arrays.fill(value, (byte) 0); }
	}
	private boolean isActiveScope(@NonNull String namespace, @NonNull String epoch) {
		return this.credentialNamespace.equals(namespace) && this.recoveryEpoch.equals(epoch);
	}
	private static void validateKeys(@NonNull Set<@NonNull TotpStoreKey> keys) {
		Objects.requireNonNull(keys);
		if (keys.isEmpty() || keys.size() > 16) throw new IllegalArgumentException("Invalid TOTP read set");
		TotpStoreKey first = Objects.requireNonNull(keys.iterator().next());
		for (TotpStoreKey key : keys) {
			Objects.requireNonNull(key);
			if (!key.getCredentialNamespace().equals(first.getCredentialNamespace()) || !key.getRecoveryEpoch().equals(first.getRecoveryEpoch()))
				throw new IllegalArgumentException("Mixed TOTP read scope");
		}
	}
	private static long deadline(@NonNull Duration budget) {
		Objects.requireNonNull(budget);
		if (budget.isNegative() || budget.isZero()) return 0;
		long nanos = budget.compareTo(Duration.ofSeconds(30)) >= 0 ? MAXIMUM_BUDGET_NANOS : budget.toNanos();
		return System.nanoTime() + nanos;
	}
	private boolean acquire(long deadline) {
		if (deadline == 0) return false;
		long remaining = deadline - System.nanoTime();
		if (remaining <= 0 || Thread.currentThread().isInterrupted()) return false;
		try { return this.lock.tryLock(remaining, TimeUnit.NANOSECONDS); }
		catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); return false; }
	}
	private static boolean expired(long deadline) { return Thread.currentThread().isInterrupted() || deadline - System.nanoTime() <= 0; }
	/**
	 * Redacts stored records and recovery configuration.
	 * @return the fixed redacted description
	 * @since 1.0.0
	 */
	@Override public @NonNull String toString() { return "InMemoryTotpStore{records=<redacted>}"; }

 /**
  * Caller-thread configuration for explicit volatile storage. Defaults allow 1024 permanent
  * records and 16 MiB of sealed payload. Building performs no I/O and creates no threads.
  * @since 1.0.0
  */
 @javax.annotation.concurrent.NotThreadSafe
 @CheckReturnValue
 public static final class Builder {
  private final @NonNull String credentialNamespace;
  private final @NonNull String recoveryEpoch;
  private int maximumEntries = 1024;
  private long maximumSealedBytes = 16777216L;
  private Builder(@NonNull String namespace, @NonNull String epoch) {
   TotpStoreKey.validateScope(namespace); TotpStoreKey.validateScope(epoch);
   this.credentialNamespace = namespace; this.recoveryEpoch = epoch;
  }
  /**
   * Sets the permanent record-count capacity; records are never evicted.
   * @param maximumEntries capacity from 1 to 65536, including namespace and old-epoch records; null restores 1024
   * @return this builder
   * @since 1.0.0
   */
  public @NonNull Builder maximumEntries(@Nullable Integer maximumEntries) {
   if (maximumEntries == null) { this.maximumEntries = 1024; return this; }
   if (maximumEntries < 1 || maximumEntries > MAXIMUM_ENTRIES)
    throw new IllegalArgumentException("Invalid TOTP record capacity");
   this.maximumEntries = maximumEntries; return this;
  }
  /**
   * Sets aggregate sealed-payload capacity.
   * @param maximumSealedBytes capacity from 1 to 268435456 bytes; null restores 16 MiB
   * @return this builder
   * @since 1.0.0
   */
  public @NonNull Builder maximumSealedBytes(@Nullable Long maximumSealedBytes) {
   if (maximumSealedBytes == null) { this.maximumSealedBytes = 16777216L; return this; }
   if (maximumSealedBytes < 1 || maximumSealedBytes > MAXIMUM_BYTES)
    throw new IllegalArgumentException("Invalid TOTP byte capacity");
   this.maximumSealedBytes = maximumSealedBytes; return this;
  }
  /**
   * Creates a fresh process-local store with NEW activation state.
   * @return the explicitly selected volatile store
   * @since 1.0.0
   */
  public @NonNull InMemoryTotpStore build() { return new InMemoryTotpStore(this); }
 }
}
