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
 * Opaque permanent record with an authenticated address and non-reused version. No TTL is allowed.
 * This carrier validates framing only; the authenticator establishes authenticity before use.
 * @since 1.0.0
 */
@javax.annotation.concurrent.Immutable
public final class TotpStoreRecord {
 private final @NonNull TotpStoreKey key;
 private final @NonNull String version;
 private final byte @NonNull [] sealedBytes;
 private TotpStoreRecord(@NonNull TotpStoreKey key, @NonNull String version, byte @NonNull [] sealedBytes) {
  this.key = Objects.requireNonNull(key);
  TotpStoreKey.validateDigest(version);
  if (sealedBytes.length == 0 || sealedBytes.length > 65536)
   throw new IllegalArgumentException("Invalid sealed TOTP record length");
  this.version = version;
  this.sealedBytes = sealedBytes.clone();
 }
 /**
  * Rehydrates an opaque bounded record, without granting protocol authority.
  * @param key the exact address
  * @param version the canonical unpadded base64url encoding of a fresh random 256-bit version
  * @param sealedBytes the sealed payload, from 1 to 65536 bytes
  * @return the immutable record
  * @since 1.0.0
  */
 public static @NonNull TotpStoreRecord fromStoredForm(@NonNull TotpStoreKey key,
   @NonNull String version, byte @NonNull [] sealedBytes) {
  return new TotpStoreRecord(key, version, sealedBytes);
 }
 /**
  * Returns the exact record address.
  * @return the address
  * @since 1.0.0
  */
 public @NonNull TotpStoreKey getKey() { return this.key; }
 /**
  * Returns the exact version to preserve and compare atomically.
  * @return the opaque non-reused version
  * @since 1.0.0
  */
 public @NonNull String getVersion() { return this.version; }
 /**
  * Returns a defensive copy of the sealed payload.
  * @return the sealed record
  * @since 1.0.0
  */
 public byte @NonNull [] getSealedBytes() { return this.sealedBytes.clone(); }
 /**
  * Redacts address, version and payload.
  * @since 1.0.0
  */
 @Override public @NonNull String toString() { return "TotpStoreRecord{record=<redacted>}"; }
}
