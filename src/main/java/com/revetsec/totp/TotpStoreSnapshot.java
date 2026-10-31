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
import com.revetsec.StoreTimeObservation;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.NonNull;

/**
 * Complete immutable authoritative observations within exactly one namespace and recovery epoch.
 * @since 1.0.0
 */
@javax.annotation.concurrent.Immutable
@CheckReturnValue
public final class TotpStoreSnapshot {
 private final @NonNull Map<@NonNull TotpStoreKey, @NonNull TotpStoreEntry> entries;
 private final @NonNull StoreTimeObservation timeObservation;
 private TotpStoreSnapshot(@NonNull Map<@NonNull TotpStoreKey, @NonNull TotpStoreEntry> entries,
   @NonNull StoreTimeObservation timeObservation) {
  this.entries = Map.copyOf(entries);
  this.timeObservation = Objects.requireNonNull(timeObservation);
 }
 /**
  * Constructs a complete, bounded snapshot with one explicit observation per requested address.
  * @param requestedKeys the exact nonempty set of at most 16 keys in one scope
  * @param entries the matching present or absent observations
  * @param timeObservation the admitted time or time-only unavailability coherent with these entries
  * @return the immutable snapshot
  * @since 1.0.0
  */
 public static @NonNull TotpStoreSnapshot fromEntries(@NonNull Set<@NonNull TotpStoreKey> requestedKeys,
   @NonNull Map<@NonNull TotpStoreKey, @NonNull TotpStoreEntry> entries,
   @NonNull StoreTimeObservation timeObservation) {
  Objects.requireNonNull(requestedKeys); Objects.requireNonNull(entries); Objects.requireNonNull(timeObservation);
  if (requestedKeys.isEmpty() || requestedKeys.size() > 16 || !entries.keySet().equals(requestedKeys))
   throw new IllegalArgumentException("Incomplete TOTP store snapshot");
  TotpStoreKey first = Objects.requireNonNull(requestedKeys.iterator().next());
  for (TotpStoreKey key : requestedKeys) {
   Objects.requireNonNull(key);
   if (!key.getCredentialNamespace().equals(first.getCredentialNamespace())
     || !key.getRecoveryEpoch().equals(first.getRecoveryEpoch()))
    throw new IllegalArgumentException("Mixed TOTP snapshot scope");
   TotpStoreEntry entry = Objects.requireNonNull(entries.get(key));
   if (entry instanceof TotpStoreEntry.Present present && !present.getRecord().getKey().equals(key))
    throw new IllegalArgumentException("Mismatched TOTP record address");
  }
  return new TotpStoreSnapshot(entries, timeObservation);
 }
 /**
  * Returns all immutable requested observations.
  * @return the exact read set
  * @since 1.0.0
  */
 public @NonNull Map<@NonNull TotpStoreKey, @NonNull TotpStoreEntry> getEntries() { return this.entries; }
 /**
  * Returns an observation; an unrequested address is invalid.
  * @param key a requested address
  * @return its explicit observation
  * @since 1.0.0
  */
 public @NonNull TotpStoreEntry getEntry(@NonNull TotpStoreKey key) {
  TotpStoreEntry entry = this.entries.get(Objects.requireNonNull(key));
  if (entry == null) throw new IllegalArgumentException("Key not in TOTP snapshot");
  return entry;
 }
 /**
  * Returns the admitted time metadata from the same atomic snapshot as every entry.
  * @return the coherent time observation
  * @since 1.0.0
  */
 public @NonNull StoreTimeObservation getTimeObservation() { return this.timeObservation; }
 /**
  * Redacts all observations.
  * @since 1.0.0
  */
 @Override public @NonNull String toString() { return "TotpStoreSnapshot{entries=<redacted>}"; }
}
