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

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import org.jspecify.annotations.NonNull;

/**
 * Explicit, bounded single-process WebAuthn store. It is volatile: a restart loses ceremonies,
 * credentials, revocation records, account fences and the observed-time fence. Use a durable,
 * shared {@link WebAuthnStore} for established accounts or deployments with more than one node.
 * Records are never evicted, including expired ceremonies and revoked credential IDs; when either
 * configured limit is reached a write returns {@link WebAuthnStoreCommitResult#CAPACITY}.
 *
 * @since 1.0.0
 */
@javax.annotation.concurrent.ThreadSafe
public final class InMemoryWebAuthnStore implements WebAuthnStore {
 private static final long MAXIMUM_BYTES = 268_435_456L;
 private static final int MAXIMUM_ENTRIES = 65_536;
 private static final long MAXIMUM_BUDGET_NANOS = TimeUnit.SECONDS.toNanos(30);
 private static final @NonNull SecureRandom VERSION_RANDOM = new SecureRandom();

 private final @NonNull ReentrantLock lock = new ReentrantLock();
 private final int maximumEntries;
 private final long maximumSealedBytes;
 private final byte @NonNull [] versionPrefix = new byte[16];
 private @NonNull Map<@NonNull WebAuthnStoreKey, @NonNull Stored> entries = Map.of();
 private long sealedBytes;
 private long sequence;

 private InMemoryWebAuthnStore(int maximumEntries, long maximumSealedBytes) {
  this.maximumEntries = maximumEntries;
  this.maximumSealedBytes = maximumSealedBytes;
  VERSION_RANDOM.nextBytes(this.versionPrefix);
 }

 /**
  * Creates a volatile store with explicit record-count and aggregate sealed-byte limits.
  * Neither limit causes eviction. A single sealed record may be up to 262144 bytes.
  * @param maximumEntries capacity from 1 to 65536
  * @param maximumSealedBytes aggregate capacity from 1 to 268435456 bytes
  * @return a new empty, process-local store
  * @since 1.0.0
  */
 public static @NonNull InMemoryWebAuthnStore withLimits(int maximumEntries,
   long maximumSealedBytes) {
  if (maximumEntries < 1 || maximumEntries > MAXIMUM_ENTRIES
    || maximumSealedBytes < 1 || maximumSealedBytes > MAXIMUM_BYTES)
   throw new IllegalArgumentException("Invalid WebAuthn store limits");
  return new InMemoryWebAuthnStore(maximumEntries, maximumSealedBytes);
 }

 @Override public @NonNull WebAuthnStoreReadResult read(
   @NonNull Set<@NonNull WebAuthnStoreKey> keys, @NonNull Duration remainingBudget) {
  Objects.requireNonNull(keys);
  long budget = budgetNanos(remainingBudget);
  if (budget == 0 || Thread.currentThread().isInterrupted())
   return WebAuthnStoreReadResult.Unavailable.get();
  long deadline = System.nanoTime() + budget;
  if (!acquire(deadline)) return WebAuthnStoreReadResult.Unavailable.get();
  try {
   if (expired(deadline)) return WebAuthnStoreReadResult.Unavailable.get();
   Map<WebAuthnStoreKey, WebAuthnStoreEntry> observed = new HashMap<>();
   for (WebAuthnStoreKey key : keys) {
    Stored stored = this.entries.get(key);
    observed.put(key, stored == null ? WebAuthnStoreEntry.Absent.confirmed()
      : WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(stored.version, stored.sealedBytes));
   }
   WebAuthnStoreSnapshot snapshot = WebAuthnStoreSnapshot.fromEntries(keys, observed);
   return expired(deadline) ? WebAuthnStoreReadResult.Unavailable.get()
     : WebAuthnStoreReadResult.Available.fromSnapshot(snapshot);
  } finally {
   this.lock.unlock();
  }
 }

 @Override public @NonNull WebAuthnStoreCommitResult compareAndCommit(
   @NonNull WebAuthnStoreWrite write, @NonNull Duration remainingBudget) {
  Objects.requireNonNull(write);
  long budget = budgetNanos(remainingBudget);
  if (budget == 0 || Thread.currentThread().isInterrupted())
   return WebAuthnStoreCommitResult.UNAVAILABLE;
  long deadline = System.nanoTime() + budget;
  if (!acquire(deadline)) return WebAuthnStoreCommitResult.UNAVAILABLE;
  try {
   if (expired(deadline)) return WebAuthnStoreCommitResult.UNAVAILABLE;
   for (Map.Entry<WebAuthnStoreKey, WebAuthnStoreEntry> predicate
       : write.getSnapshot().getEntries().entrySet()) {
    Stored actual = this.entries.get(predicate.getKey());
    WebAuthnStoreEntry expected = predicate.getValue();
    if ((expected instanceof WebAuthnStoreEntry.Absent && actual != null)
      || (expected instanceof WebAuthnStoreEntry.Present present
        && (actual == null || !Arrays.equals(present.getVersion(), actual.version))))
     return WebAuthnStoreCommitResult.CONFLICT;
   }

   Map<WebAuthnStoreKey, Stored> next = new HashMap<>(this.entries);
   long nextBytes = this.sealedBytes;
   long nextSequence = this.sequence;
   for (WebAuthnStoreWrite.Mutation mutation : write.getMutations()) {
    WebAuthnStoreKey key = mutation.getKey();
    Stored prior = next.get(key);
    if (prior != null) nextBytes -= prior.sealedBytes.length;
    if (mutation.getKind() == WebAuthnStoreWrite.Mutation.Kind.DELETE) {
     next.remove(key);
    } else {
     byte[] bytes = mutation.getSealedBytes().orElseThrow();
     if (nextSequence == Long.MAX_VALUE) return WebAuthnStoreCommitResult.CAPACITY;
     nextSequence++;
     byte[] version = ByteBuffer.allocate(24).put(this.versionPrefix).putLong(nextSequence).array();
     next.put(key, new Stored(version, bytes));
     nextBytes += bytes.length;
    }
   }
   if (next.size() > this.maximumEntries || nextBytes > this.maximumSealedBytes)
    return WebAuthnStoreCommitResult.CAPACITY;
   if (expired(deadline)) return WebAuthnStoreCommitResult.UNAVAILABLE;
   this.entries = next;
   this.sealedBytes = nextBytes;
   this.sequence = nextSequence;
   return expired(deadline) ? WebAuthnStoreCommitResult.UNKNOWN : WebAuthnStoreCommitResult.COMMITTED;
  } finally {
   this.lock.unlock();
  }
 }

 private static long budgetNanos(@NonNull Duration budget) {
  Objects.requireNonNull(budget);
  if (budget.isNegative() || budget.isZero()) return 0;
  return budget.compareTo(Duration.ofSeconds(30)) >= 0
    ? MAXIMUM_BUDGET_NANOS : budget.toNanos();
 }

 private boolean acquire(long deadline) {
  long remaining = deadline - System.nanoTime();
  if (remaining <= 0) return false;
  try {
   return this.lock.tryLock(remaining, TimeUnit.NANOSECONDS);
  } catch (InterruptedException interrupted) {
   Thread.currentThread().interrupt();
   return false;
  }
 }

 private static boolean expired(long deadline) {
  return Thread.currentThread().isInterrupted() || deadline - System.nanoTime() <= 0;
 }

 /** Redacts all stored records. @since 1.0.0 */
 @Override public @NonNull String toString() { return "InMemoryWebAuthnStore{records=<redacted>}"; }

 private static final class Stored {
  private final byte @NonNull [] version;
  private final byte @NonNull [] sealedBytes;
  private Stored(byte @NonNull [] version, byte @NonNull [] sealedBytes) {
   this.version = version;
   this.sealedBytes = sealedBytes;
  }
 }
}
