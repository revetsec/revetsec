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
import java.util.Optional;
import static java.util.Objects.requireNonNull;

/**
 * Opaque issuer storage address. Reconstruction checks syntax and grants no protocol authority.
 * Persist the exact storage string; identifiers are sensitive and diagnostics redact them.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 *
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class OAuthStoreKey {
 private final @NonNull String storageKey;
 private final OAuthStoreKey.@NonNull Kind kind;
 private OAuthStoreKey(@NonNull String storageKey, OAuthStoreKey.@NonNull Kind kind) {
  this.storageKey = storageKey; this.kind = kind;
 }
 /**
  * Reconstructs a storage address, bounded to 256 ASCII characters and the current canonical format.
  * The issuer checks its namespace before using this address. This does not authenticate a record.
  * @param storageKey the exact persisted address
  * @return the bounded address
  * @throws NullPointerException if the argument is null
  * @throws IllegalArgumentException if its format is invalid
  * @since 1.0.0
  */
 public static @NonNull OAuthStoreKey fromStoredForm(@NonNull String storageKey) {
  return new OAuthStoreKey(storageKey, OAuthStoreFormat.keyKind(storageKey));
 }
 /**
  * Releases the sensitive opaque address for persistence; never log it.
  * @return the exact storage address
  * @since 1.0.0
  */
 public @NonNull String getStorageKey() { return this.storageKey; }
 /**
  * Returns the storage record kind, which alone confers no authority.
  * @return the record kind
  * @since 1.0.0
  */
 public OAuthStoreKey.@NonNull Kind getKind() { return this.kind; }
 /**
  * Compares exact storage addresses.
  * @param other the possible address
  * @return whether the addresses are equal
  * @since 1.0.0
  */
 @Override public boolean equals(@Nullable Object other) {
  return other instanceof OAuthStoreKey key && this.storageKey.equals(key.storageKey);
 }
 /**
  * Returns the exact address hash.
  * @return the address hash
  * @since 1.0.0
  */
 @Override public int hashCode() { return this.storageKey.hashCode(); }
 /**
  * Redacts the address.
  * @return a fixed description
  * @since 1.0.0
  */
 @Override public @NonNull String toString() { return "OAuthStoreKey{address=<redacted>}"; }
 /**
  * The seven issuer storage record kinds. Permanent fence kinds must never be TTL evicted.
  * @author <a href="https://www.revetkn.com">Mark Allen</a>
  * @since 1.0.0
  */
 @Immutable
 public enum Kind {
  /** Permanent issuer epoch and clock fence.
 * @since 1.0.0 */
  ISSUER_STATE,
  /** Permanent issuer-local subject epoch.
 * @since 1.0.0 */
  SUBJECT_STATE,
  /** Browser-bound authorization interaction.
 * @since 1.0.0 */
  INTERACTION,
  /** Authorization code or retained consumption proof.
 * @since 1.0.0 */
  CODE,
  /** Authorization grant and revocation state.
 * @since 1.0.0 */
  GRANT,
  /** Issued access-token identifier and binding.
 * @since 1.0.0 */
  ACCESS_TOKEN,
  /** Rotating refresh credential or retained reuse proof.
 * @since 1.0.0 */
  REFRESH_TOKEN
 }
}
