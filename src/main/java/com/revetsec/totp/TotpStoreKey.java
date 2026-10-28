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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Canonical, namespace- and recovery-epoch-bound address of permanent TOTP state. Account IDs
 * appear only as domain-separated SHA-256 digests. Constructing an address confers no authority.
 * Storage addresses are sensitive and must not be logged.
 * @since 1.0.0
 */
@javax.annotation.concurrent.Immutable
public final class TotpStoreKey {
 private static final @NonNull String NAMESPACE_DIGEST = "imuTRYmFK91EEVQacqvPSOwL9Fiy6uV9Dlqs7_LkszQ";
 private final @NonNull String storageKey;
 private final @NonNull String credentialNamespace;
 private final @NonNull String recoveryEpoch;
 private final TotpStoreKey.@NonNull Kind kind;

 private TotpStoreKey(@NonNull String namespace, @NonNull String epoch,
   TotpStoreKey.@NonNull Kind kind, @NonNull String digest) {
  validateScope(namespace); validateScope(epoch);
  this.credentialNamespace = namespace;
  this.recoveryEpoch = epoch;
  this.kind = kind;
  this.storageKey = "totp1:" + encode(namespace.getBytes(StandardCharsets.US_ASCII)) + ':'
    + encode(epoch.getBytes(StandardCharsets.US_ASCII)) + ':' + kind.name() + ':' + digest;
 }

 /**
  * Addresses the permanent namespace clock and initialization fence.
  * @param credentialNamespace the visible ASCII namespace, from 1 to 128 characters
  * @param recoveryEpoch the never-reused visible ASCII recovery epoch, from 1 to 128 characters
  * @return the namespace address
  * @since 1.0.0
  */
 public static @NonNull TotpStoreKey forNamespace(@NonNull String credentialNamespace,
   @NonNull String recoveryEpoch) {
  return new TotpStoreKey(credentialNamespace, recoveryEpoch, Kind.NAMESPACE_STATE,
    NAMESPACE_DIGEST);
 }

 /**
  * Addresses the permanent account aggregate without disclosing its identifier in the address.
  * @param credentialNamespace the visible ASCII namespace
  * @param recoveryEpoch the never-reused recovery epoch
  * @param accountId the nonempty, well-formed account identifier, at most 1024 UTF-8 bytes
  * @return the account address
  * @since 1.0.0
  */
 public static @NonNull TotpStoreKey forAccount(@NonNull String credentialNamespace,
   @NonNull String recoveryEpoch, @NonNull String accountId) {
  validateAccount(accountId);
  return new TotpStoreKey(credentialNamespace, recoveryEpoch, Kind.ACCOUNT_STATE,
    digest("revetsec-totp-account-v1\0" + accountId));
 }

 /**
  * Parses a bounded canonical persistence address; authenticity is checked when opening its record.
  * @param storageKey the exact stored address
  * @return the parsed address
  * @since 1.0.0
  */
 public static @NonNull TotpStoreKey fromStoredForm(@NonNull String storageKey) {
  Objects.requireNonNull(storageKey);
  if (storageKey.length() > 430) throw new IllegalArgumentException("Invalid TOTP store address");
  String[] parts = storageKey.split(":", -1);
  if (parts.length != 5 || !parts[0].equals("totp1"))
   throw new IllegalArgumentException("Invalid TOTP store address");
  String namespace = decodeScope(parts[1]);
  String epoch = decodeScope(parts[2]);
  Kind kind;
  try { kind = Kind.valueOf(parts[3]); }
  catch (IllegalArgumentException invalid) { throw new IllegalArgumentException("Invalid TOTP store address"); }
  validateDigest(parts[4]);
  TotpStoreKey key = new TotpStoreKey(namespace, epoch, kind, parts[4]);
  if (!storageKey.equals(key.storageKey)
    || (kind == Kind.NAMESPACE_STATE && !key.equals(forNamespace(namespace, epoch))))
   throw new IllegalArgumentException("Invalid TOTP store address");
  return key;
 }

 /**
  * Returns the exact sensitive persistence address.
  * @return the address; never log it
  * @since 1.0.0
  */
 public @NonNull String getStorageKey() { return this.storageKey; }
 /**
  * Returns the credential namespace.
  * @return the namespace
  * @since 1.0.0
  */
 public @NonNull String getCredentialNamespace() { return this.credentialNamespace; }
 /**
  * Returns the recovery epoch.
  * @return the epoch
  * @since 1.0.0
  */
 public @NonNull String getRecoveryEpoch() { return this.recoveryEpoch; }
 /**
  * Returns the permanent record kind.
  * @return the kind
  * @since 1.0.0
  */
 public TotpStoreKey.@NonNull Kind getKind() { return this.kind; }
 /**
  * Compares the complete persistence address.
  * @since 1.0.0
  */
 @Override public boolean equals(@Nullable Object other) {
  return other instanceof TotpStoreKey key && this.storageKey.equals(key.storageKey);
 }
 /**
  * Returns the complete address hash.
  * @since 1.0.0
  */
 @Override public int hashCode() { return this.storageKey.hashCode(); }
 /**
  * Redacts the address.
  * @since 1.0.0
  */
 @Override public @NonNull String toString() { return "TotpStoreKey{address=<redacted>}"; }

 static void validateScope(@NonNull String value) {
  Objects.requireNonNull(value);
  if (value.isEmpty() || value.length() > 128) throw new IllegalArgumentException("Invalid TOTP scope");
  for (int i = 0; i < value.length(); i++)
   if (value.charAt(i) < 0x21 || value.charAt(i) > 0x7e)
    throw new IllegalArgumentException("Invalid TOTP scope");
 }
 static void validateAccount(@NonNull String value) {
  Objects.requireNonNull(value);
  if (value.isEmpty() || value.length() > 1024)
   throw new IllegalArgumentException("Invalid TOTP account identifier");
  for (int i = 0; i < value.length(); i++) {
   char character = value.charAt(i);
   if (Character.isHighSurrogate(character)) {
    if (i + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(++i)))
     throw new IllegalArgumentException("Invalid TOTP account identifier");
   } else if (Character.isLowSurrogate(character))
    throw new IllegalArgumentException("Invalid TOTP account identifier");
  }
  if (value.getBytes(StandardCharsets.UTF_8).length > 1024)
   throw new IllegalArgumentException("Invalid TOTP account identifier");
 }
 static void validateDigest(@NonNull String value) {
  Objects.requireNonNull(value);
  if (value.length() != 43) throw new IllegalArgumentException("Invalid TOTP digest");
  try {
   byte[] decoded = Base64Url.decode(value);
   if (decoded.length != 32 || !encode(decoded).equals(value))
    throw new IllegalArgumentException("Invalid TOTP digest");
  } catch (EncodingException invalid) { throw new IllegalArgumentException("Invalid TOTP digest"); }
 }
 private static @NonNull String decodeScope(@NonNull String value) {
  if (value.length() > 171) throw new IllegalArgumentException("Invalid TOTP scope");
  byte[] decoded;
  try { decoded = Base64Url.decode(value); }
  catch (EncodingException invalid) { throw new IllegalArgumentException("Invalid TOTP scope"); }
  for (byte character : decoded) if (character < 0x21 || character > 0x7e)
   throw new IllegalArgumentException("Invalid TOTP scope");
  String scope = new String(decoded, StandardCharsets.US_ASCII);
  validateScope(scope);
  if (!encode(decoded).equals(value)) throw new IllegalArgumentException("Invalid TOTP scope");
  return scope;
 }
 private static @NonNull String encode(byte @NonNull [] bytes) {
  return Base64Url.encode(bytes);
 }
 private static @NonNull String digest(@NonNull String text) {
  try { return encode(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8))); }
  catch (NoSuchAlgorithmException unavailable) { throw new IllegalStateException("SHA-256 unavailable", unavailable); }
 }
 /**
  * Permanent record kinds. Neither kind may carry a backend TTL or be evicted.
  * @since 1.0.0
  */
 @javax.annotation.concurrent.Immutable
 public enum Kind {
  /**
   * Namespace initialization and observed-time fences.
   * @since 1.0.0
   */ NAMESPACE_STATE,
  /**
   * Factor, pending enrollment, replay mark, recovery verifiers and account fences.
   * @since 1.0.0
   */ ACCOUNT_STATE
 }
}
