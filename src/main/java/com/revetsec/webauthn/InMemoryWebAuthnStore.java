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

package com.revetsec.webauthn;

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.StoreAdmission;
import com.revetsec.StoreCommitTiming;
import com.revetsec.StoreTemporalCondition;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.StoreTimeRules;
import com.revetsec.internal.crypto.EntropySource;
import java.nio.ByteBuffer;
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
 * Explicit bounded, volatile, single-process WebAuthn store. Restart loses ceremonies,
 * credentials, ownership tombstones, account fences and every recovery/time fence. Use durable
 * shared authoritative storage for established accounts or deployments with several nodes.
 * No ordinary read, predicate barrier or refusal reclaims records. Expired ceremonies can remain
 * retained until explicit admitted application maintenance; capacity may refuse safely. Permanent
 * records are never evicted to make room.
 * <p>The first operational call establishes this store's own volatile UTC/elapsed projection and
 * admission metadata. The relying party's worker Clock is never its time source. Construction
 * performs no I/O, random acquisition or time sampling. This demonstration does not qualify
 * external UTC, restore, device durability, suspend/rate continuity or a shared deployment.
 * @since 1.0.0
 */
@javax.annotation.concurrent.ThreadSafe
@CheckReturnValue
public final class InMemoryWebAuthnStore implements WebAuthnStore {
	private static final long MAXIMUM_BYTES = 268435456L;
	private static final int MAXIMUM_ENTRIES = 65536;
	private static final long MAXIMUM_BUDGET_NANOS = TimeUnit.SECONDS.toNanos(30);
	private static final @NonNull Duration LOCAL_UTC_ERROR = Duration.ofMillis(250);
	private final @NonNull ReentrantLock lock = new ReentrantLock();
	private final int maximumEntries;
	private final long maximumSealedBytes;
	// Mutable state below is guarded by lock; construction only retains configuration.
	private @NonNull Map<@NonNull WebAuthnStoreKey, @NonNull Stored> entries = Map.of();
	private @NonNull Set<@NonNull String> activatedScopes = Set.of();
	private long sealedBytes;
	private long sequence;
	private byte @Nullable [] versionPrefix;
	private @Nullable EntropySource entropy;
	private @Nullable StoreAdmission admission;
	private @Nullable String clockGeneration;
	private @Nullable Instant authorityAnchor;
	private long authorityStartedNanos;
	private long lastAuthorityNanos;
	private boolean authorityContinuityLost;

	private InMemoryWebAuthnStore(int maximumEntries, long maximumSealedBytes) {
		this.maximumEntries = maximumEntries;
		this.maximumSealedBytes = maximumSealedBytes;
	}

	/**
	 * Creates empty volatile storage with explicit count and aggregate sealed-byte capacity.
	 * No records are automatically evicted or reclaimed; one record may be up to 262144 bytes.
	 * @param maximumEntries capacity from 1 to 65536
	 * @param maximumSealedBytes aggregate capacity from 1 to 268435456 bytes
	 * @return a new empty process-local store
	 * @since 1.0.0
	 */
	public static @NonNull InMemoryWebAuthnStore withLimits(int maximumEntries, long maximumSealedBytes) {
		if (maximumEntries < 1 || maximumEntries > MAXIMUM_ENTRIES
				|| maximumSealedBytes < 1 || maximumSealedBytes > MAXIMUM_BYTES)
			throw new IllegalArgumentException("Invalid WebAuthn store limits");
		return new InMemoryWebAuthnStore(maximumEntries, maximumSealedBytes);
	}

	@Override public @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys,
			@NonNull Duration remainingBudget) {
		WebAuthnStoreSnapshot.validateRequestedKeys(keys);
		long deadline = deadline(remainingBudget);
		if (!acquire(deadline)) return WebAuthnStoreReadResult.Unavailable.get();
		try {
			if (expired(deadline) || missingEstablishedRoot(keys)) return WebAuthnStoreReadResult.Unavailable.get();
			Map<WebAuthnStoreKey, WebAuthnStoreEntry> observed = new HashMap<>();
			for (WebAuthnStoreKey key : keys) {
				Stored stored = this.entries.get(key);
				observed.put(key, stored == null ? WebAuthnStoreEntry.Absent.confirmed()
						: WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(stored.version, stored.sealedBytes));
			}
			StoreTimeObservation time;
			try { time = observe(); } catch (RuntimeException unavailable) { return WebAuthnStoreReadResult.Unavailable.get(); }
			WebAuthnStoreSnapshot snapshot = WebAuthnStoreSnapshot.fromEntries(keys, observed, time);
			return expired(deadline) ? WebAuthnStoreReadResult.Unavailable.get() : WebAuthnStoreReadResult.Available.fromSnapshot(snapshot);
		} finally { this.lock.unlock(); }
	}

	@Override public @NonNull WebAuthnStoreCommitReceipt compareAndCommit(@NonNull WebAuthnStoreWrite write,
			@NonNull Duration remainingBudget) {
		Objects.requireNonNull(write);
		long deadline = deadline(remainingBudget);
		if (!acquire(deadline)) return refuse(WebAuthnStoreCommitResult.UNAVAILABLE);
		try {
			if (expired(deadline) || missingEstablishedRoot(write.getSnapshot().getEntries().keySet())) return refuse(WebAuthnStoreCommitResult.UNAVAILABLE);
			StoreAdmission current;
			try { current = operationalAdmission(); } catch (RuntimeException unavailable) { return refuse(WebAuthnStoreCommitResult.UNAVAILABLE); }
			StoreTemporalCondition condition = write.getTemporalCondition();
			if (!StoreTimeRules.sameAdmission(current, condition.getAdmission())
					|| !Objects.equals(this.clockGeneration, condition.getClockGeneration())) return refuse(WebAuthnStoreCommitResult.FENCED);
			for (Map.Entry<WebAuthnStoreKey, WebAuthnStoreEntry> predicate : write.getSnapshot().getEntries().entrySet()) {
				Stored actual = this.entries.get(predicate.getKey());
				WebAuthnStoreEntry expected = predicate.getValue();
				if ((expected instanceof WebAuthnStoreEntry.Absent && actual != null)
						|| (expected instanceof WebAuthnStoreEntry.Present present
								&& (actual == null || !Arrays.equals(present.getVersion(), actual.version)))) return refuse(WebAuthnStoreCommitResult.CONFLICT);
			}
			StoreTimeObservation time;
			try { time = observe(); } catch (RuntimeException unavailable) { return refuse(WebAuthnStoreCommitResult.TIME_UNAVAILABLE); }
			if (!(time instanceof StoreTimeObservation.Healthy healthy)) return refuse(WebAuthnStoreCommitResult.TIME_UNAVAILABLE);
			if (!(write.getSnapshot().getTimeObservation() instanceof StoreTimeObservation.Healthy original)
					|| !StoreTimeRules.sameProfile(original, healthy)) return refuse(WebAuthnStoreCommitResult.FENCED);
			if (healthy.getObservedAt().isBefore(condition.getNotBeforeInclusive())) return refuse(WebAuthnStoreCommitResult.TIME_BEFORE_FLOOR);
			if (condition.getValidBeforeExclusive().isPresent()
					&& !healthy.getObservedAt().isBefore(condition.getValidBeforeExclusive().orElseThrow())) return refuse(WebAuthnStoreCommitResult.TIME_EXPIRED);
			WebAuthnStoreCommitReceipt committed = WebAuthnStoreCommitReceipt.fromCommittedTiming(StoreCommitTiming.fromTimes(healthy, null));
			if (write.getMutations().isEmpty()) return expired(deadline) ? refuse(WebAuthnStoreCommitResult.UNAVAILABLE) : committed;
			Map<WebAuthnStoreKey, Stored> next = new HashMap<>(this.entries);
			Set<String> nextActivated = new HashSet<>(this.activatedScopes);
			long nextBytes = this.sealedBytes, nextSequence = this.sequence;
			for (WebAuthnStoreWrite.Mutation mutation : write.getMutations()) {
				WebAuthnStoreKey key = mutation.getKey();
				Stored prior = next.get(key);
				if (prior != null) nextBytes -= prior.sealedBytes.length;
				if (mutation.getKind() == WebAuthnStoreWrite.Mutation.Kind.DELETE) next.remove(key);
				else {
					if (nextSequence == Long.MAX_VALUE) return refuse(WebAuthnStoreCommitResult.CAPACITY);
					byte[] prefix = this.versionPrefix;
					if (prefix == null) { prefix = randomBytes(16); this.versionPrefix = prefix; }
					byte[] version = ByteBuffer.allocate(24).put(prefix).putLong(++nextSequence).array();
					byte[] bytes = mutation.getSealedBytes().orElseThrow();
					next.put(key, new Stored(version, bytes)); nextBytes += bytes.length;
					if (key.getKind() == WebAuthnStoreKey.Kind.NAMESPACE_CLOCK) nextActivated.add(WebAuthnStoreSnapshot.scopeOf(key));
				}
			}
			if (next.size() > this.maximumEntries || nextBytes > this.maximumSealedBytes || nextActivated.size() > MAXIMUM_ENTRIES)
				return refuse(WebAuthnStoreCommitResult.CAPACITY);
			if (expired(deadline)) return refuse(WebAuthnStoreCommitResult.UNAVAILABLE);
			this.entries = next; this.sealedBytes = nextBytes; this.sequence = nextSequence; this.activatedScopes = nextActivated;
			// This process knows the assignment happened; lateness cannot erase that factual commitment.
			return committed;
		} finally { this.lock.unlock(); }
	}

	private boolean missingEstablishedRoot(@NonNull Set<@NonNull WebAuthnStoreKey> keys) {
		String scope = WebAuthnStoreSnapshot.scopeOf(keys.iterator().next());
		boolean asksRoot = false, rootPresent = false, hasData = false;
		for (WebAuthnStoreKey key : keys) {
			if (key.getKind() == WebAuthnStoreKey.Kind.NAMESPACE_CLOCK) {
				if (this.entries.containsKey(key)) return false;
				asksRoot = true;
			}
		}
		if (!asksRoot && !this.activatedScopes.contains(scope)) return false;
		for (WebAuthnStoreKey key : this.entries.keySet()) {
			if (!scope.equals(WebAuthnStoreSnapshot.scopeOf(key))) continue;
			hasData = true;
			if (key.getKind() == WebAuthnStoreKey.Kind.NAMESPACE_CLOCK) { rootPresent = true; break; }
		}
		return !rootPresent && (this.activatedScopes.contains(scope) || (asksRoot && hasData));
	}

	private static @NonNull WebAuthnStoreCommitReceipt refuse(@NonNull WebAuthnStoreCommitResult status) { return WebAuthnStoreCommitReceipt.fromRefusal(status); }

	private @NonNull StoreAdmission operationalAdmission() {
		StoreAdmission current = this.admission;
		if (current == null) {
			current = StoreAdmission.fromIdentifiers(newIdentity(), newIdentity());
			this.clockGeneration = newIdentity(); this.admission = current;
		}
		return current;
	}
	private @NonNull StoreTimeObservation observe() {
		StoreAdmission current = operationalAdmission();
		Instant anchor = this.authorityAnchor;
		if (anchor == null && !this.authorityContinuityLost) {
			long before = System.nanoTime(); Instant captured = Instant.now(); long after = System.nanoTime();
			Optional<Duration> bracket = StoreTimeRules.elapsed(before, after);
			if (bracket.isEmpty() || bracket.get().compareTo(LOCAL_UTC_ERROR) > 0 || !supported(captured)) this.authorityContinuityLost = true;
			else { this.authorityAnchor = captured; this.authorityStartedNanos = after; this.lastAuthorityNanos = after; anchor = captured; }
		}
		if (anchor == null || this.authorityContinuityLost) return StoreTimeObservation.Unavailable.fromAdmission(current);
		long now = System.nanoTime(); Optional<Duration> elapsed = StoreTimeRules.elapsed(this.authorityStartedNanos, now);
		if (StoreTimeRules.elapsed(this.lastAuthorityNanos, now).isEmpty() || elapsed.isEmpty()) {
			this.authorityContinuityLost = true; return StoreTimeObservation.Unavailable.fromAdmission(current);
		}
		this.lastAuthorityNanos = now;
		try {
			Instant point = anchor.plus(elapsed.get());
			if (!supported(point)) { this.authorityContinuityLost = true; return StoreTimeObservation.Unavailable.fromAdmission(current); }
			return StoreTimeObservation.Healthy.fromObservation(current, Objects.requireNonNull(this.clockGeneration), point, LOCAL_UTC_ERROR);
		} catch (DateTimeException | ArithmeticException invalid) {
			this.authorityContinuityLost = true; return StoreTimeObservation.Unavailable.fromAdmission(current);
		}
	}
	private static boolean supported(@NonNull Instant time) { return time.getEpochSecond() >= 0 && time.getEpochSecond() <= 253402300799L; }
	private byte @NonNull [] randomBytes(int count) {
		EntropySource source = this.entropy;
		if (source == null) { source = EntropySource.fromDefaults(); this.entropy = source; }
		return source.nextBytes(count);
	}
	private @NonNull String newIdentity() {
		byte[] value = randomBytes(32);
		try { return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
		finally { Arrays.fill(value, (byte) 0); }
	}
	private static long deadline(@NonNull Duration budget) {
		Objects.requireNonNull(budget);
		if (budget.isNegative() || budget.isZero()) return 0;
		return System.nanoTime() + (budget.compareTo(Duration.ofSeconds(30)) >= 0 ? MAXIMUM_BUDGET_NANOS : budget.toNanos());
	}
	private boolean acquire(long deadline) {
		if (deadline == 0) return false;
		long remaining = deadline - System.nanoTime();
		if (remaining <= 0 || Thread.currentThread().isInterrupted()) return false;
		try { return this.lock.tryLock(remaining, TimeUnit.NANOSECONDS); }
		catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); return false; }
	}
	private static boolean expired(long deadline) { return Thread.currentThread().isInterrupted() || deadline - System.nanoTime() <= 0; }

	/** Redacts stored records and admission metadata. @since 1.0.0 */
	@Override public @NonNull String toString() { return "InMemoryWebAuthnStore{records=<redacted>}"; }

	private static final class Stored {
		private final byte @NonNull [] version;
		private final byte @NonNull [] sealedBytes;
		private Stored(byte @NonNull [] version, byte @NonNull [] sealedBytes) { this.version = version; this.sealedBytes = sealedBytes; }
	}
}
