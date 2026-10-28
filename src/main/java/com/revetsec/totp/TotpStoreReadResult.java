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

import java.util.Objects;
import org.jspecify.annotations.NonNull;

/**
 * Authoritative read outcome. No outcome grants a credential proof.
 * @since 1.0.0
 */
@javax.annotation.concurrent.Immutable
public sealed interface TotpStoreReadResult permits TotpStoreReadResult.Available,
  TotpStoreReadResult.Fenced, TotpStoreReadResult.Unavailable {
 /**
  * Complete observations at one authoritative snapshot point.
  * @since 1.0.0
  */
 @javax.annotation.concurrent.Immutable
 final class Available implements TotpStoreReadResult {
  private final @NonNull TotpStoreSnapshot snapshot;
  private Available(@NonNull TotpStoreSnapshot snapshot) { this.snapshot = Objects.requireNonNull(snapshot); }
  /**
   * Wraps a complete snapshot.
   * @param snapshot the authoritative observations
   * @return the available outcome
   * @since 1.0.0
   */
  public static TotpStoreReadResult.@NonNull Available fromSnapshot(@NonNull TotpStoreSnapshot snapshot) {
   return new Available(snapshot);
  }
  /**
   * Returns the immutable snapshot.
   * @return the observations
   * @since 1.0.0
   */
  public @NonNull TotpStoreSnapshot getSnapshot() { return this.snapshot; }
  /**
   * Redacts all observations.
   * @since 1.0.0
   */
  @Override public @NonNull String toString() { return "Available{snapshot=<redacted>}"; }
 }
 /**
  * The requested recovery epoch is no longer authoritative.
  * @since 1.0.0
  */
 @javax.annotation.concurrent.Immutable
 final class Fenced implements TotpStoreReadResult {
  private static final TotpStoreReadResult.@NonNull Fenced INSTANCE = new Fenced();
  private Fenced() { }
  /**
   * Returns the fenced outcome.
   * @return the fenced outcome
   * @since 1.0.0
   */
  public static TotpStoreReadResult.@NonNull Fenced get() { return INSTANCE; }
  /**
   * Returns a fixed description.
   * @since 1.0.0
   */
  @Override public @NonNull String toString() { return "Fenced{}"; }
 }
 /**
  * An authoritative read could not be confirmed.
  * @since 1.0.0
  */
 @javax.annotation.concurrent.Immutable
 final class Unavailable implements TotpStoreReadResult {
  private static final TotpStoreReadResult.@NonNull Unavailable INSTANCE = new Unavailable();
  private Unavailable() { }
  /**
   * Returns the unavailable outcome.
   * @return the unavailable outcome
   * @since 1.0.0
   */
  public static TotpStoreReadResult.@NonNull Unavailable get() { return INSTANCE; }
  /**
   * Returns a fixed description.
   * @since 1.0.0
   */
  @Override public @NonNull String toString() { return "Unavailable{}"; }
 }
}
