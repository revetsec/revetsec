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
 * One explicit authoritative observation; omission never represents absence.
 * @since 1.0.0
 */
@javax.annotation.concurrent.Immutable
public sealed interface TotpStoreEntry permits TotpStoreEntry.Present, TotpStoreEntry.Absent {
 /**
  * A versioned permanent sealed record.
  * @since 1.0.0
  */
 @javax.annotation.concurrent.Immutable
 final class Present implements TotpStoreEntry {
  private final @NonNull TotpStoreRecord record;
  private Present(@NonNull TotpStoreRecord record) { this.record = Objects.requireNonNull(record); }
  /**
   * Wraps a record read from the exact address.
   * @param record the opaque record
   * @return the present observation
   * @since 1.0.0
   */
  public static TotpStoreEntry.@NonNull Present fromRecord(@NonNull TotpStoreRecord record) {
   return new Present(record);
  }
  /**
   * Returns the immutable opaque record.
   * @return the record
   * @since 1.0.0
   */
  public @NonNull TotpStoreRecord getRecord() { return this.record; }
  /**
   * Redacts the record.
   * @since 1.0.0
   */
  @Override public @NonNull String toString() { return "Present{record=<redacted>}"; }
 }
 /**
  * Confirmed absence at the authoritative snapshot point.
  * @since 1.0.0
  */
 @javax.annotation.concurrent.Immutable
 final class Absent implements TotpStoreEntry {
  private static final TotpStoreEntry.@NonNull Absent INSTANCE = new Absent();
  private Absent() { }
  /**
   * Returns the singleton confirmed absence.
   * @return confirmed absence
   * @since 1.0.0
   */
  public static TotpStoreEntry.@NonNull Absent confirmed() { return INSTANCE; }
  /**
   * Returns a fixed description.
   * @since 1.0.0
   */
  @Override public @NonNull String toString() { return "Absent{}"; }
 }
}
