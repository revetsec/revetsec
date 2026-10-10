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

import java.util.Objects;
import org.jspecify.annotations.NonNull;

/** One authoritative read result. No result grants a verified WebAuthn proof. @since 1.0.0 */
@javax.annotation.concurrent.Immutable
public sealed interface WebAuthnStoreReadResult
  permits WebAuthnStoreReadResult.Available, WebAuthnStoreReadResult.Unavailable {
 /** A complete versioned snapshot. @since 1.0.0 */
 @javax.annotation.concurrent.Immutable
 final class Available implements WebAuthnStoreReadResult {
  private final @NonNull WebAuthnStoreSnapshot snapshot;
  private Available(@NonNull WebAuthnStoreSnapshot snapshot) { this.snapshot = Objects.requireNonNull(snapshot); }
  /** Wraps a complete snapshot.
   * @param snapshot the complete read set
   * @return the available result
   * @since 1.0.0 */
  public static WebAuthnStoreReadResult.@NonNull Available fromSnapshot(@NonNull WebAuthnStoreSnapshot snapshot) {
   return new Available(snapshot);
  }
  /** Returns the complete snapshot.
   * @return the read set
   * @since 1.0.0 */
  public @NonNull WebAuthnStoreSnapshot getSnapshot() { return this.snapshot; }
  /** Redacts all observations. @since 1.0.0 */
  @Override public @NonNull String toString() { return "Available{snapshot=<redacted>}"; }
 }

 /** No authoritative read was available. @since 1.0.0 */
 @javax.annotation.concurrent.Immutable
 final class Unavailable implements WebAuthnStoreReadResult {
  private static final WebAuthnStoreReadResult.@NonNull Unavailable INSTANCE = new Unavailable();
  private Unavailable() { }
  /** Returns the unavailable outcome.
   * @return the unavailable result
   * @since 1.0.0 */
  public static WebAuthnStoreReadResult.@NonNull Unavailable get() { return INSTANCE; }
  /** Returns a fixed description. @since 1.0.0 */
  @Override public @NonNull String toString() { return "Unavailable{}"; }
 }
}
