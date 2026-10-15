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

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * One immutable atomic compare-and-commit request. The complete snapshot is the predicate set:
 * every observed version and every confirmed absence must still match. New versions must be
 * unique across updates to prevent ABA. A condition-only write still checks the whole snapshot.
 * @since 1.0.0
 */
@javax.annotation.concurrent.Immutable
public final class WebAuthnStoreWrite {
 private final @NonNull WebAuthnStoreSnapshot snapshot;
 private final @NonNull List<WebAuthnStoreWrite.@NonNull Mutation> mutations;

 private WebAuthnStoreWrite(@NonNull WebAuthnStoreSnapshot snapshot,
   @NonNull List<WebAuthnStoreWrite.@NonNull Mutation> mutations) {
  this.snapshot = snapshot; this.mutations = List.copyOf(mutations);
 }

 /**
  * Combines an exact snapshot with at most eight distinct mutations of its keys. Insertion
  * requires confirmed absence; replacement and deletion require a present version.
  * @param snapshot the complete predicate set
  * @param mutations the bounded change set, possibly empty
  * @return a validated atomic request
  * @since 1.0.0
  */
 public static @NonNull WebAuthnStoreWrite fromSnapshotAndMutations(
   @NonNull WebAuthnStoreSnapshot snapshot,
   @NonNull List<WebAuthnStoreWrite.@NonNull Mutation> mutations) {
  java.util.Objects.requireNonNull(snapshot);
  if (mutations.size() > 8) throw new IllegalArgumentException("Too many mutations");
  Set<WebAuthnStoreKey> changed = new HashSet<>();
  for (Mutation mutation : mutations) {
   WebAuthnStoreEntry prior = snapshot.getEntry(mutation.key);
   if (!changed.add(mutation.key)
     || (mutation.kind == Mutation.Kind.INSERT && !(prior instanceof WebAuthnStoreEntry.Absent))
     || (mutation.kind != Mutation.Kind.INSERT && !(prior instanceof WebAuthnStoreEntry.Present)))
    throw new IllegalArgumentException("Invalid store mutation");
  }
  return new WebAuthnStoreWrite(snapshot, mutations);
 }

 /** Returns every exact version or absence predicate.
  * @return the read set
  * @since 1.0.0 */
 public @NonNull WebAuthnStoreSnapshot getSnapshot() { return this.snapshot; }

 /** Returns the immutable ordered mutation set.
  * @return the mutations
  * @since 1.0.0 */
 public @NonNull List<WebAuthnStoreWrite.@NonNull Mutation> getMutations() { return this.mutations; }

 /** Redacts predicates and mutations. @since 1.0.0 */
 @Override public @NonNull String toString() { return "WebAuthnStoreWrite{write=<redacted>}"; }

 /** A typed insertion, replacement or deletion of a key from the read set. @since 1.0.0 */
 @javax.annotation.concurrent.Immutable
 public static final class Mutation {
  private final @NonNull WebAuthnStoreKey key;
  private final WebAuthnStoreWrite.Mutation.@NonNull Kind kind;
  private final byte @Nullable [] sealedBytes;
  private final @Nullable Instant expiresAt;

  private Mutation(@NonNull WebAuthnStoreKey key, WebAuthnStoreWrite.Mutation.@NonNull Kind kind,
    byte @Nullable [] sealedBytes, @Nullable Instant expiresAt) {
   this.key = java.util.Objects.requireNonNull(key);
   this.kind = kind;
   this.sealedBytes = sealedBytes == null ? null : sealedBytes.clone();
   this.expiresAt = expiresAt;
  }

  /** Inserts a sealed record only if the read set confirms absence.
   * @param key the absent key
   * @param sealedBytes the new sealed record
   * @return the insertion
   * @since 1.0.0 */
  public static @NonNull Mutation insert(@NonNull WebAuthnStoreKey key,
    byte @NonNull [] sealedBytes) {
   validateSealedBytes(sealedBytes);
   return new Mutation(key, Kind.INSERT, sealedBytes, null);
  }

  /** Inserts a ceremony with a store-visible reclamation deadline. Core also checks the
   * authenticated expiry in the sealed record before accepting a completion.
   * @param key the absent ceremony key
   * @param sealedBytes the sealed ceremony
   * @param expiresAt the deadline after which the store may remove the ceremony
   * @return the insertion
   * @since 1.0.0 */
  public static @NonNull Mutation insertExpiring(@NonNull WebAuthnStoreKey key,
    byte @NonNull [] sealedBytes, @NonNull Instant expiresAt) {
   requireCeremony(key, expiresAt);
   validateSealedBytes(sealedBytes);
   return new Mutation(key, Kind.INSERT, sealedBytes, expiresAt);
  }

  /** Replaces a versioned sealed record.
   * @param key the versioned key
   * @param sealedBytes the new sealed record
   * @return the replacement
   * @since 1.0.0 */
  public static @NonNull Mutation replace(@NonNull WebAuthnStoreKey key,
    byte @NonNull [] sealedBytes) {
   validateSealedBytes(sealedBytes);
   return new Mutation(key, Kind.REPLACE, sealedBytes, null);
  }

  /** Replaces a ceremony while retaining its store-visible reclamation deadline.
   * @param key the versioned ceremony key
   * @param sealedBytes the new sealed ceremony
   * @param expiresAt the deadline after which the store may remove the ceremony
   * @return the replacement
   * @since 1.0.0 */
  public static @NonNull Mutation replaceExpiring(@NonNull WebAuthnStoreKey key,
    byte @NonNull [] sealedBytes, @NonNull Instant expiresAt) {
   requireCeremony(key, expiresAt);
   validateSealedBytes(sealedBytes);
   return new Mutation(key, Kind.REPLACE, sealedBytes, expiresAt);
  }

  /** Deletes a versioned record. Retain a replay tombstone where protocol rules require it.
   * @param key the versioned key
   * @return the deletion
   * @since 1.0.0 */
  public static @NonNull Mutation delete(@NonNull WebAuthnStoreKey key) {
   return new Mutation(key, Kind.DELETE, null, null);
  }

  /** Returns the changed key.
   * @return the key
   * @since 1.0.0 */
  public @NonNull WebAuthnStoreKey getKey() { return this.key; }

  /** Returns the mutation kind.
   * @return the kind
   * @since 1.0.0 */
  public WebAuthnStoreWrite.Mutation.@NonNull Kind getKind() { return this.kind; }

  /** Returns a defensive copy of the sealed payload, or empty for deletion.
   * @return the payload, if any
   * @since 1.0.0 */
  public @NonNull Optional<byte @NonNull []> getSealedBytes() {
   return this.sealedBytes == null ? Optional.empty() : Optional.of(this.sealedBytes.clone());
  }

  /** Returns the ceremony reclamation deadline, if supplied. A store must remove expired
   * ceremonies before evaluating its capacity limit and must treat them as absent on reads.
   * Other record kinds are never reclaimed by this hint.
   * @return the optional maintenance deadline
   * @since 1.0.0 */
  public @NonNull Optional<@NonNull Instant> getExpiresAt() { return Optional.ofNullable(this.expiresAt); }

  /** Redacts the key and payload. @since 1.0.0 */
  @Override public @NonNull String toString() { return "Mutation{change=<redacted>}"; }

  private static void validateSealedBytes(byte @NonNull [] sealedBytes) {
   if (sealedBytes.length == 0 || sealedBytes.length > 262144)
    throw new IllegalArgumentException("Invalid sealed record length");
  }

  private static void requireCeremony(@NonNull WebAuthnStoreKey key, @NonNull Instant expiresAt) {
   java.util.Objects.requireNonNull(expiresAt);
   if (java.util.Objects.requireNonNull(key).getKind() != WebAuthnStoreKey.Kind.CEREMONY)
    throw new IllegalArgumentException("Only ceremonies may carry a reclamation deadline");
  }

  /** The three atomic write operations. @since 1.0.0 */
  @javax.annotation.concurrent.Immutable
  public enum Kind {
   /** Insert after confirmed absence. @since 1.0.0 */ INSERT,
   /** Replace an exact version. @since 1.0.0 */ REPLACE,
   /** Delete an exact version. @since 1.0.0 */ DELETE
  }
 }
}
