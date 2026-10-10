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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Typed, namespace-bound authoritative address. Binary identifiers are represented only by
 * canonical SHA-256 digests in the stored address. Constructing a key confers no protocol authority.
 * The storage form is sensitive and must not be logged.
 * @since 1.0.0
 */
@javax.annotation.concurrent.Immutable
public final class WebAuthnStoreKey {
 private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
 private final @NonNull String storageKey;
 private final WebAuthnStoreKey.@NonNull Kind kind;

 private WebAuthnStoreKey(@NonNull String namespace, @NonNull String relyingPartyId,
   WebAuthnStoreKey.@NonNull Kind kind, byte @NonNull [] identifier) {
  validateNamespace(namespace);
  validateRelyingPartyId(relyingPartyId);
  this.kind = kind;
  this.storageKey = "wa1:" + encode(namespace.getBytes(StandardCharsets.US_ASCII)) + ':'
    + encode(relyingPartyId.getBytes(StandardCharsets.US_ASCII)) + ':' + kind.name() + ':'
    + encode(sha256(identifier));
 }

 /** Address for a 32-byte random ceremony ID.
  * @param namespace the credential namespace
  * @param relyingPartyId the canonical RP ID
  * @param ceremonyId the decoded random ceremony ID
  * @return the typed address
  * @since 1.0.0 */
 public static @NonNull WebAuthnStoreKey forCeremony(@NonNull String namespace,
   @NonNull String relyingPartyId, byte @NonNull [] ceremonyId) {
  if (ceremonyId.length != 32) throw new IllegalArgumentException("Invalid ceremony ID");
  return new WebAuthnStoreKey(namespace, relyingPartyId, Kind.CEREMONY, ceremonyId);
 }

 /** Address for a credential ID of 1–1023 bytes.
  * @param namespace the credential namespace
  * @param relyingPartyId the canonical RP ID
  * @param credentialId the browser credential ID
  * @return the typed address
  * @since 1.0.0 */
 public static @NonNull WebAuthnStoreKey forCredential(@NonNull String namespace,
   @NonNull String relyingPartyId, byte @NonNull [] credentialId) {
  validateUserIdentifier(credentialId, 1023);
  return new WebAuthnStoreKey(namespace, relyingPartyId, Kind.CREDENTIAL, credentialId);
 }

 /** Address for the credential index of a 1–64-byte account handle.
  * @param namespace the credential namespace
  * @param relyingPartyId the canonical RP ID
  * @param userHandle the opaque account handle
  * @return the typed address
  * @since 1.0.0 */
 public static @NonNull WebAuthnStoreKey forAccountCredentialIndex(@NonNull String namespace,
   @NonNull String relyingPartyId, byte @NonNull [] userHandle) {
  validateUserIdentifier(userHandle, 64);
  return new WebAuthnStoreKey(namespace, relyingPartyId, Kind.ACCOUNT_CREDENTIAL_INDEX, userHandle);
 }

 /** Address for the active state and revocation fence of a 1–64-byte account handle.
  * @param namespace the credential namespace
  * @param relyingPartyId the canonical RP ID
  * @param userHandle the opaque account handle
  * @return the typed address
  * @since 1.0.0 */
 public static @NonNull WebAuthnStoreKey forAccountFence(@NonNull String namespace,
   @NonNull String relyingPartyId, byte @NonNull [] userHandle) {
  validateUserIdentifier(userHandle, 64);
  return new WebAuthnStoreKey(namespace, relyingPartyId, Kind.ACCOUNT_FENCE, userHandle);
 }

 /** Address for the single authoritative observed-time fence of a namespace and RP.
  * @param namespace the credential namespace
  * @param relyingPartyId the canonical RP ID
  * @return the namespace clock address
  * @since 1.0.0 */
 public static @NonNull WebAuthnStoreKey forNamespaceClock(@NonNull String namespace,
   @NonNull String relyingPartyId) {
  return new WebAuthnStoreKey(namespace, relyingPartyId, Kind.NAMESPACE_CLOCK, new byte[0]);
 }

 /** Returns the exact persistence address; do not log it.
  * @return the storage address
  * @since 1.0.0 */
 public @NonNull String getStorageKey() { return this.storageKey; }

 /** Returns the key's record kind.
  * @return the record kind
  * @since 1.0.0 */
 public WebAuthnStoreKey.@NonNull Kind getKind() { return this.kind; }

 /** Compares complete addresses. @since 1.0.0 */
 @Override public boolean equals(@Nullable Object other) {
  return other instanceof WebAuthnStoreKey key && this.storageKey.equals(key.storageKey);
 }

 /** Returns the complete address hash. @since 1.0.0 */
 @Override public int hashCode() { return this.storageKey.hashCode(); }

 /** Redacts the address. @since 1.0.0 */
 @Override public @NonNull String toString() { return "WebAuthnStoreKey{address=<redacted>}"; }

 private static void validateUserIdentifier(byte @NonNull [] identifier, int maximum) {
  if (identifier.length == 0 || identifier.length > maximum)
   throw new IllegalArgumentException("Invalid identifier length");
 }

 private static void validateNamespace(@NonNull String namespace) {
  if (namespace.isEmpty() || namespace.length() > 128) throw new IllegalArgumentException("Invalid namespace");
  for (int i = 0; i < namespace.length(); i++) {
   char character = namespace.charAt(i);
   if (character < 0x21 || character > 0x7e) throw new IllegalArgumentException("Invalid namespace");
  }
 }

 private static void validateRelyingPartyId(@NonNull String relyingPartyId) {
  if (relyingPartyId.length() < 3 || relyingPartyId.length() > 253)
   throw new IllegalArgumentException("Invalid RP ID");
  String[] labels = relyingPartyId.split("\\.", -1);
  if (labels.length < 2) throw new IllegalArgumentException("Invalid RP ID");
  for (String label : labels) {
   if (label.isEmpty() || label.length() > 63 || label.charAt(0) == '-'
     || label.charAt(label.length() - 1) == '-') throw new IllegalArgumentException("Invalid RP ID");
   for (int i = 0; i < label.length(); i++) {
    char character = label.charAt(i);
    if (!((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')
      || character == '-')) throw new IllegalArgumentException("Invalid RP ID");
   }
  }
  boolean allDigits = true;
  for (String label : labels) {
   for (int i = 0; i < label.length(); i++) if (label.charAt(i) < '0' || label.charAt(i) > '9') allDigits = false;
  }
  if (allDigits) throw new IllegalArgumentException("Invalid RP ID");
 }

 private static @NonNull String encode(byte @NonNull [] bytes) { return ENCODER.encodeToString(bytes); }

 private static byte @NonNull [] sha256(byte @NonNull [] bytes) {
  try { return MessageDigest.getInstance("SHA-256").digest(bytes); }
  catch (NoSuchAlgorithmException exception) { throw new IllegalStateException("SHA-256 unavailable", exception); }
 }

 /** The five authoritative record kinds. @since 1.0.0 */
 @javax.annotation.concurrent.Immutable
 public enum Kind {
  /** Single-use ceremony or retained consumption proof. @since 1.0.0 */
  CEREMONY,
  /** Credential state keyed by its unique ID. @since 1.0.0 */
  CREDENTIAL,
  /** Per-account credential index. @since 1.0.0 */
  ACCOUNT_CREDENTIAL_INDEX,
  /** Per-account active state and revocation fence. @since 1.0.0 */
  ACCOUNT_FENCE,
  /** Per-namespace monotonic observed-time fence. @since 1.0.0 */
  NAMESPACE_CLOCK
 }
}
