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
import com.revetsec.StoreTimeObservation;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.NonNull;

/** Complete immutable authoritative read set, including explicit absences.
 * @since 1.0.0 */
@javax.annotation.concurrent.Immutable
@CheckReturnValue
public final class WebAuthnStoreSnapshot {
 private final @NonNull Map<@NonNull WebAuthnStoreKey, @NonNull WebAuthnStoreEntry> entries;
 private final @NonNull StoreTimeObservation timeObservation;

 private WebAuthnStoreSnapshot(@NonNull Map<@NonNull WebAuthnStoreKey, @NonNull WebAuthnStoreEntry> entries,
   @NonNull StoreTimeObservation timeObservation) {
  this.entries = Map.copyOf(entries);
  this.timeObservation = timeObservation;
 }

 /**
  * Constructs a complete snapshot. The engine also compares its requested keys with the returned
  * snapshot keys, so a provider cannot represent a missing read as absence by omission.
  * @param requestedKeys the exact requested set
  * @param entries one explicit observation per requested key
  * @param timeObservation the same coherent admission/time observation as the data
  * @return a complete immutable snapshot
  * @since 1.0.0
  */
 public static @NonNull WebAuthnStoreSnapshot fromEntries(
   @NonNull Set<@NonNull WebAuthnStoreKey> requestedKeys,
   @NonNull Map<@NonNull WebAuthnStoreKey, @NonNull WebAuthnStoreEntry> entries,
   @NonNull StoreTimeObservation timeObservation) {
  Objects.requireNonNull(entries); Objects.requireNonNull(timeObservation);
  validateRequestedKeys(requestedKeys);
  if (!entries.keySet().equals(requestedKeys))
   throw new IllegalArgumentException("Incomplete store snapshot");
  return new WebAuthnStoreSnapshot(entries, timeObservation);
 }

 /** Returns the exact immutable key-to-observation map.
  * @return every requested key and its observation
  * @since 1.0.0 */
 public @NonNull Map<@NonNull WebAuthnStoreKey, @NonNull WebAuthnStoreEntry> getEntries() {
  return this.entries;
 }

 /** Returns the explicit observation for a requested key; an unrequested key is invalid.
  * @param key the requested key
  * @return the authoritative observation
  * @since 1.0.0 */
 public @NonNull WebAuthnStoreEntry getEntry(@NonNull WebAuthnStoreKey key) {
  WebAuthnStoreEntry entry = this.entries.get(Objects.requireNonNull(key));
  if (entry == null) throw new IllegalArgumentException("Key not in snapshot");
  return entry;
 }

 /** Returns the admission/time envelope observed coherently with every entry.
  * @return the authoritative time status
  * @since 1.0.0 */
 public @NonNull StoreTimeObservation getTimeObservation() { return this.timeObservation; }

 static void validateRequestedKeys(@NonNull Set<@NonNull WebAuthnStoreKey> keys) {
  Objects.requireNonNull(keys);
  if (keys.isEmpty() || keys.size() > 16) throw new IllegalArgumentException("Invalid WebAuthn read set");
  String scope = scopeOf(Objects.requireNonNull(keys.iterator().next()));
  for (WebAuthnStoreKey key : keys)
   if (!scope.equals(scopeOf(Objects.requireNonNull(key)))) throw new IllegalArgumentException("Mixed WebAuthn read scope");
 }

 // Final key factories establish canonical storage grammar; scope comparison never decrypts a record.
 static @NonNull String scopeOf(@NonNull WebAuthnStoreKey key) {
  String[] pieces = key.getStorageKey().split(":", -1);
  if (pieces.length != 5 || !pieces[0].equals("wa1") || !pieces[3].equals(key.getKind().name())
    || pieces[1].isEmpty() || pieces[2].isEmpty() || pieces[4].length() != 43)
   throw new IllegalArgumentException("Invalid WebAuthn read scope");
  return pieces[1] + ':' + pieces[2];
 }

 /** Redacts all keys and records. @since 1.0.0 */
 @Override public @NonNull String toString() { return "WebAuthnStoreSnapshot{entries=<redacted>}"; }
}
