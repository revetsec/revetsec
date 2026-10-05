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

package com.revetsec.oauth.server;

import com.google.errorprone.annotations.CheckReturnValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import java.time.Instant;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import static java.util.Objects.requireNonNull;

/**
 * Application-owned authoritative issuer persistence. Implementations must be safe across callers and nodes.
 * Reads are linearizable; commits atomically check every condition before applying all mutations and return
 * COMMITTED only after durability under the application's deployment contract. CONFLICT has zero effects;
 * a lost connection with uncertain outcome returns UNKNOWN, never a guessed conflict or success.
 * Condition-only commits are required atomic read-set barriers. No callback executes inside a transaction.
 * Providers honor the remaining budget and preserve permanent fences and retained replay tombstones:
 * capacity pressure rejects work rather than evicting active records. Revetsec cannot forcibly preempt
 * blocked application code. This interface supplies no database, durability or rollback detection by itself.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 *
 * @since 1.0.0
 */
@javax.annotation.concurrent.ThreadSafe
@CheckReturnValue
public interface OAuthAuthorizationServerStore {
 /**
  * Reads an authoritative entry or confirmed absence, preserving every transport field exactly.
  * Infrastructure failure is thrown, never translated into absence. Do not include record data in diagnostics.
  * @param key the exact address
  * @param remainingBudget the remaining positive operation budget
  * @return the authoritative entry or absence
  * @since 1.0.0
  */
 @NonNull Optional<@NonNull OAuthStoreEntry> read(@NonNull OAuthStoreKey key,
   @NonNull Duration remainingBudget);
 /**
  * Atomically checks the complete predicate set and applies the complete mutation set.
  * Zero mutations still checks all predicates at one linearization point. Never partially apply writes.
  * @param transaction the immutable engine-created transaction
  * @param remainingBudget the remaining positive operation budget
  * @return the actual durable, conflict or uncertain outcome
  * @since 1.0.0
  */
 @NonNull OAuthStoreCommitStatus commit(@NonNull OAuthStoreTransaction transaction,
   @NonNull Duration remainingBudget);
}
