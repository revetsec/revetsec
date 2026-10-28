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

import java.time.Duration;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Application-owned recovery admission barrier. Before granting admission, compare externally
 * durable recovery state and allowed sealing-key lifecycle with the exact requested context. The
 * controller closes admission, drains outstanding operations, fences old transactions and writers,
 * then restores into a fresh never-reused epoch. Encryption cannot detect database rollback.
 * <p>Implementations are thread-safe; each permit belongs to the acquiring thread. Nested admission
 * on that thread retains the barrier until its outermost permit closes. This allows an application
 * to hold outer admission through its own login/session transaction. Alternatively, that transaction
 * must atomically enforce a recovery epoch fence. A preceding epoch lookup leaves a completion race.
 * Returned proofs cannot revoke themselves; sessions and approvals from earlier epochs must be
 * invalidated by the application. Initialization admission is granted only while provisioning a new
 * epoch, and stops before ordinary traffic opens.
 * @since 1.0.0
 */
@javax.annotation.concurrent.ThreadSafe
public interface TotpRecoveryGate {
 /**
  * Acquires admission within the positive remaining caller-thread budget. The budget establishes
  * a deadline for the complete permit lifetime, including later currentness checks. Return null
  * when admission is closed or cannot be confirmed. Core holds admission through storage and its
  * final result decision. After a possible write, loss of admission requires an indeterminate
  * outcome without releasing proofs or plaintext. If acquisition returns null or throws, the
  * implementation must first release every partially acquired lock, lease, reference count or
  * other admission claim. Such an outcome must leave no admission held by the calling thread;
  * core cannot release a permit it never received. This also applies when acquisition is
  * interrupted or its budget expires. Preserve interruption and never extend a deadline.
  * @param context the exact operation and sealing configuration
  * @param remainingBudget remaining positive operation budget
  * @return a caller-thread permit, or null when admission is unavailable
  * @since 1.0.0
  */
 @Nullable Permit acquire(@NonNull TotpRecoveryContext context, @NonNull Duration remainingBudget);
 /**
  * One caller-thread admission permit, with an idempotent prompt release.
  * @since 1.0.0
  */
 @javax.annotation.concurrent.NotThreadSafe
 interface Permit extends AutoCloseable {
  /**
   * Confirms admission and the original deadline still hold. This check cannot substitute for
   * the store's transactional epoch comparison against stale lease holders.
   * @return true only while this permit remains current
   * @since 1.0.0
   */
  @NonNull Boolean isCurrent();
  /**
   * Releases this nested permit promptly and idempotently. The final close releases admission.
   * @since 1.0.0
   */
  @Override void close();
 }
}
