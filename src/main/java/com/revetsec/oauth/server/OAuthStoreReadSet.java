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
import java.util.List;
import java.util.Map;
import java.util.Optional;
import static java.util.Objects.requireNonNull;

/**
 * Complete bounded authoritative observations; a barrier includes every observed version or absence.
 * This collector calls no backend and supplies no durability by itself.
 */
final class OAuthStoreReadSet {
 private final @NonNull Map<@NonNull OAuthStoreKey, OAuthStoreTransaction.@NonNull Condition> conditions
   = new java.util.LinkedHashMap<>();
 OAuthStoreReadSet() { }
 void observe(@NonNull OAuthStoreKey key, @NonNull Optional<@NonNull OAuthStoreEntry> entry) {
  requireNonNull(key); requireNonNull(entry);
  if (entry.isPresent() && !key.equals(entry.orElseThrow().getKey())) throw OAuthStoreFormat.invalid();
  OAuthStoreTransaction.Condition condition = entry.isPresent()
    ? OAuthStoreTransaction.Condition.fromVersion(key, entry.orElseThrow().getVersion())
    : OAuthStoreTransaction.Condition.fromAbsent(key);
  OAuthStoreTransaction.Condition previous = this.conditions.get(key);
  if (previous != null && !previous.getExpectedVersion().equals(condition.getExpectedVersion())) throw OAuthStoreFormat.invalid();
  if (previous == null && this.conditions.size() == 16) throw OAuthStoreFormat.invalid();
  this.conditions.put(key, condition);
 }
 @NonNull OAuthStoreTransaction transaction(@NonNull List<OAuthStoreTransaction.@NonNull Mutation> mutations) {
  return OAuthStoreTransaction.fromConditions(List.copyOf(this.conditions.values()), mutations);
 }
}
