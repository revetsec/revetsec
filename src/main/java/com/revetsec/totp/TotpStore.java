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
import java.time.Duration;
import java.util.Set;
import org.jspecify.annotations.NonNull;

/**
 * Application-owned, authoritative TOTP storage. Implementations coordinate every node, read a
 * complete immutable snapshot and atomically compare every version, absence and active recovery
 * epoch before applying all mutations or none. A separately performed epoch or time lookup is insufficient.
 * A confirmed commit is durable across restart. {@link InMemoryTotpStore} is an explicitly selected
 * volatile demonstration backend, never an automatic fallback.
 * <p>Both record kinds are permanent. No backend TTL, eviction or automatic deletion is allowed,
 * including after factor removal. Capacity refusal changes nothing. Unknown acknowledgement after
 * a possible mutation is UNKNOWN, never CONFLICT or UNAVAILABLE. Only definite CONFLICT permits
 * bounded recalculation. Honor positive remaining caller-thread budgets and preserve interruption.
 * <p>Namespace activation metadata is application-owned. INITIALIZE_NAMESPACE atomically inserts
 * its root and changes NEW to ACTIVATED once. Updates require ACTIVATED and a present root; a
 * missing root in an activated epoch is unavailability, never permission to initialize again.
 * Recovery provisioning fences all old writers before a fresh, never-reused epoch is initialized.
 * @since 1.0.0
 */
@javax.annotation.concurrent.ThreadSafe
@CheckReturnValue
public interface TotpStore {
 /**
  * Reads exactly the requested nonempty bounded scope at one authoritative snapshot point,
  * checking the active epoch and operational admission in the same transaction. The entries and
  * fresh admitted time or time-only unavailability form one coherent observation. Explicitly
  * represent every absence; no cleanup, quota update or floor write belongs to a read.
  * @param keys one namespace and recovery epoch, at most 16 addresses
  * @param remainingBudget remaining positive operation budget
  * @return a complete snapshot, fenced epoch or unavailable read
  * @since 1.0.0
  */
 @NonNull TotpStoreReadResult read(@NonNull Set<@NonNull TotpStoreKey> keys,
   @NonNull Duration remainingBudget);
 /**
  * Atomically compares current admission, epoch and all snapshot predicates, then validates fresh
  * store-authoritative time after every wait, including for condition-only writes.
  * @param write the exact predicates and complete change set
  * @param remainingBudget remaining positive operation budget
  * @return the factual contextual receipt, with required validation timing for COMMITTED
  * @since 1.0.0
  */
 @NonNull TotpStoreCommitReceipt compareAndCommit(@NonNull TotpStoreWrite write,
   @NonNull Duration remainingBudget);
}
