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
import java.time.Duration;
import java.util.Set;
import org.jspecify.annotations.NonNull;

/**
 * Application-owned authoritative WebAuthn storage. Shared implementations must coordinate all nodes,
 * return a complete versioned snapshot, and atomically compare every predicate before applying
 * all mutations. A confirmed commit must be durable for restart and cross-node continuity;
 * {@link InMemoryWebAuthnStore} is an explicitly selected, volatile single-process option only.
 * Data and admitted time must be one coherent observation. Timed writes compare the current
 * authority, recovery and clock tuple, every predicate, and fresh time after all waits. Ordinary
 * reads, barriers and no-effect refusals perform no hidden reclamation or quota update. Expired
 * ceremonies may remain retained until explicit admitted maintenance; capacity can refuse safely.
 * Permanent credentials, ownership tombstones, indexes, fences and stable namespace roots are
 * never evicted to make room. A lost acknowledgement after
 * a possible write is UNKNOWN, never CONFLICT or UNAVAILABLE. Implementations honor the remaining
 * positive caller-thread budget and preserve interrupt status. Revetsec cannot preempt blocked
 * application code or provide durability through this interface alone.
 *
 * @since 1.0.0
 */
@javax.annotation.concurrent.ThreadSafe
@CheckReturnValue
public interface WebAuthnStore {
 /**
  * Reads every requested key at one authoritative snapshot point. A missing key is represented
  * by an explicit {@link WebAuthnStoreEntry.Absent} entry. Admission retirement is Fenced; a
  * provider failure is Unavailable, never fabricated absence.
  * @param keys the complete bounded read set
  * @param remainingBudget the remaining positive operation budget
  * @return a coherent complete snapshot, fenced result or unavailable result
  * @since 1.0.0
  */
 @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys,
   @NonNull Duration remainingBudget);

 /**
  * Compares all snapshot versions and absences at one linearization point and applies all changes
  * or none. Fresh healthy authority time must satisfy the original inclusive floor and exclusive
  * expiry after all waits and before mutations. An empty mutation set is a timed predicate barrier.
  * A known late commit stays COMMITTED with timing; an uncertain mutation is never safe to retry.
  * @param write the complete predicate and mutation set
  * @param remainingBudget the remaining positive operation budget
  * @return the actual commit outcome
  * @since 1.0.0
  */
 @NonNull WebAuthnStoreCommitReceipt compareAndCommit(@NonNull WebAuthnStoreWrite write,
   @NonNull Duration remainingBudget);
}
