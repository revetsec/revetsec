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

import java.util.Map;
import java.util.Set;
import org.jspecify.annotations.NonNull;

/** Complete immutable authoritative read set, including explicit absences. @since 1.0.0 */
@javax.annotation.concurrent.Immutable
public final class WebAuthnStoreSnapshot {
 private final @NonNull Map<@NonNull WebAuthnStoreKey, @NonNull WebAuthnStoreEntry> entries;

 private WebAuthnStoreSnapshot(@NonNull Map<@NonNull WebAuthnStoreKey, @NonNull WebAuthnStoreEntry> entries) {
  this.entries = Map.copyOf(entries);
 }

 /**
  * Constructs a complete snapshot. The engine also compares its requested keys with the returned
  * snapshot keys, so a provider cannot represent a missing read as absence by omission.
  * @param requestedKeys the exact requested set
  * @param entries one explicit observation per requested key
  * @return a complete immutable snapshot
  * @since 1.0.0
  */
 public static @NonNull WebAuthnStoreSnapshot fromEntries(
   @NonNull Set<@NonNull WebAuthnStoreKey> requestedKeys,
   @NonNull Map<@NonNull WebAuthnStoreKey, @NonNull WebAuthnStoreEntry> entries) {
  if (requestedKeys.isEmpty() || requestedKeys.size() > 16 || !entries.keySet().equals(requestedKeys))
   throw new IllegalArgumentException("Incomplete store snapshot");
  return new WebAuthnStoreSnapshot(entries);
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
  WebAuthnStoreEntry entry = this.entries.get(key);
  if (entry == null) throw new IllegalArgumentException("Key not in snapshot");
  return entry;
 }

 /** Redacts all keys and records. @since 1.0.0 */
 @Override public @NonNull String toString() { return "WebAuthnStoreSnapshot{entries=<redacted>}"; }
}
