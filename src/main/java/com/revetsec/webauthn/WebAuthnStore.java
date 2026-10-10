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

import java.time.Duration;
import java.util.Set;
import org.jspecify.annotations.NonNull;

/**
 * Application-owned authoritative WebAuthn storage. Shared implementations must coordinate all nodes,
 * return a complete versioned snapshot, and atomically compare every predicate before applying
 * all mutations. A confirmed commit must be durable for restart and cross-node continuity;
 * {@link InMemoryWebAuthnStore} is an explicitly selected, volatile single-process option only.
 * No live ceremony or credential may be
 * evicted to make room; capacity pressure is reported explicitly. A lost acknowledgement after
 * a possible write is UNKNOWN, never CONFLICT or UNAVAILABLE. Implementations honor the remaining
 * positive caller-thread budget and preserve interrupt status. Revetsec cannot preempt blocked
 * application code or provide durability through this interface alone.
 *
 * @since 1.0.0
 */
@javax.annotation.concurrent.ThreadSafe
public interface WebAuthnStore {
 /**
  * Reads every requested key at one authoritative snapshot point. A missing key is represented
  * by an explicit {@link WebAuthnStoreEntry.Absent} entry. A provider failure is UNAVAILABLE.
  * @param keys the complete bounded read set
  * @param remainingBudget the remaining positive operation budget
  * @return a complete snapshot or unavailable result
  * @since 1.0.0
  */
 @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys,
   @NonNull Duration remainingBudget);

 /**
  * Compares all snapshot versions and absences at one linearization point and applies all changes
  * or none. An empty mutation set is still a full predicate barrier. Never retry an uncertain write.
  * @param write the complete predicate and mutation set
  * @param remainingBudget the remaining positive operation budget
  * @return the actual commit outcome
  * @since 1.0.0
  */
 @NonNull WebAuthnStoreCommitResult compareAndCommit(@NonNull WebAuthnStoreWrite write,
   @NonNull Duration remainingBudget);
}
