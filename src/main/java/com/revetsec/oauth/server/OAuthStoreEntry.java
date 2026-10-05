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
 * Immutable encrypted persistence carrier, not an authenticated authorization proof.
 * The engine authenticates its address, version, retention and schema before using it.
 * Backends preserve all fields exactly and never substitute retention for credential expiry.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 *
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class OAuthStoreEntry {
 private final @NonNull OAuthStoreKey key;
 private final @NonNull String version;
 private final @NonNull Instant retainUntil;
 private final @NonNull String sealedForm;
 private OAuthStoreEntry(@NonNull OAuthStoreKey key, @NonNull String version,
   @NonNull Instant retainUntil, @NonNull String sealedForm) {
  this.key = key; this.version = version; this.retainUntil = retainUntil; this.sealedForm = sealedForm;
 }
 /**
  * Reconstructs bounded persisted transport fields; this does not validate the encrypted payload.
  * Permanent issuer/subject fences require the whole-second Instant.MAX sentinel and must never
  * be TTL deleted. Other kinds require a finite whole-second retention instant.
  * @param key the persisted address
  * @param version the canonical base64url encoding of a 32-byte version nonce
  * @param retainUntil physical cleanup horizon, distinct from credential expiry
  * @param sealedForm encrypted ASCII envelope, at most 16,384 characters
  * @return the bounded storage carrier
  * @throws NullPointerException if an argument is null
  * @throws IllegalArgumentException if a transport field is invalid
  * @since 1.0.0
  */
 public static @NonNull OAuthStoreEntry fromStoredForm(@NonNull OAuthStoreKey key, @NonNull String version,
   @NonNull Instant retainUntil, @NonNull String sealedForm) {
  requireNonNull(key); OAuthStoreFormat.nonce(version); OAuthStoreFormat.retention(key.getKind(), retainUntil);
  OAuthStoreFormat.sealed(sealedForm, 16_384);
  return new OAuthStoreEntry(key, version, retainUntil, sealedForm);
 }
 /** Returns the storage address.
 * @return the address
 * @since 1.0.0 */
 public @NonNull OAuthStoreKey getKey() { return this.key; }
 /** Returns the opaque version for exact CAS comparison.
 * @return the version
 * @since 1.0.0 */
 public @NonNull String getVersion() { return this.version; }
 /** Returns physical cleanup authority only.
 * @return the retention horizon
 * @since 1.0.0 */
 public @NonNull Instant getRetainUntil() { return this.retainUntil; }
 /**
  * Releases the encrypted storage envelope. Keep it out of diagnostics and browser responses.
  * @return the exact encrypted envelope
  * @since 1.0.0
  */
 public @NonNull String toSealedForm() { return this.sealedForm; }
 /** Redacts all persisted fields.
 * @return a fixed description
 * @since 1.0.0 */
 @Override public @NonNull String toString() { return "OAuthStoreEntry{record=<redacted>}"; }
}
