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

import org.jspecify.annotations.NonNull;

/** An explicit authoritative observation: a versioned sealed record or confirmed absence. @since 1.0.0 */
@javax.annotation.concurrent.Immutable
public sealed interface WebAuthnStoreEntry permits WebAuthnStoreEntry.Present, WebAuthnStoreEntry.Absent {
 /** A record and its opaque, non-reused compare-and-commit version. @since 1.0.0 */
 @javax.annotation.concurrent.Immutable
 final class Present implements WebAuthnStoreEntry {
  private final byte @NonNull [] version;
  private final byte @NonNull [] sealedBytes;

  private Present(byte @NonNull [] version, byte @NonNull [] sealedBytes) {
   if (version.length == 0 || version.length > 128 || sealedBytes.length == 0
     || sealedBytes.length > 262144) throw new IllegalArgumentException("Invalid store entry length");
   this.version = version.clone(); this.sealedBytes = sealedBytes.clone();
  }

  /** Copies an opaque version and a bounded sealed record.
   * @param version the nonempty, non-reused opaque version
   * @param sealedBytes the bounded sealed record
   * @return the present observation
   * @since 1.0.0 */
  public static WebAuthnStoreEntry.@NonNull Present fromVersionAndSealedBytes(
    byte @NonNull [] version, byte @NonNull [] sealedBytes) {
   return new Present(version, sealedBytes);
  }

  /** Returns a defensive copy of the opaque version.
   * @return the opaque version
   * @since 1.0.0 */
  public byte @NonNull [] getVersion() { return this.version.clone(); }

  /** Returns a defensive copy of the sealed record.
   * @return the sealed bytes
   * @since 1.0.0 */
  public byte @NonNull [] getSealedBytes() { return this.sealedBytes.clone(); }

  /** Redacts the record and version. @since 1.0.0 */
  @Override public @NonNull String toString() { return "Present{record=<redacted>}"; }
 }

 /** Confirmed absence, never an omitted read result. @since 1.0.0 */
 @javax.annotation.concurrent.Immutable
 final class Absent implements WebAuthnStoreEntry {
  private static final WebAuthnStoreEntry.@NonNull Absent INSTANCE = new Absent();
  private Absent() { }

  /** Returns the singleton confirmed-absence observation.
   * @return the confirmed absence
   * @since 1.0.0 */
  public static WebAuthnStoreEntry.@NonNull Absent confirmed() { return INSTANCE; }

  /** Returns a fixed description. @since 1.0.0 */
  @Override public @NonNull String toString() { return "Absent{}"; }
 }
}
