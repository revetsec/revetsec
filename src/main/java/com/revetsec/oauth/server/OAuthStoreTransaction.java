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
 * Complete immutable issuer transaction, created only by the engine. Backends compare opaque versions exactly.
 * Every changed key has a condition; absence means ABSENT, never any version. All conditions and mutations
 * must linearize together. An empty mutation list is an authoritative status barrier.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 *
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class OAuthStoreTransaction {
 private final @NonNull List<OAuthStoreTransaction.@NonNull Condition> conditions;
 private final @NonNull List<OAuthStoreTransaction.@NonNull Mutation> mutations;
 private OAuthStoreTransaction(@NonNull List<OAuthStoreTransaction.@NonNull Condition> conditions,
   @NonNull List<OAuthStoreTransaction.@NonNull Mutation> mutations) {
  this.conditions = List.copyOf(conditions); this.mutations = List.copyOf(mutations);
 }
 static @NonNull OAuthStoreTransaction fromConditions(
   @NonNull List<OAuthStoreTransaction.@NonNull Condition> conditions,
   @NonNull List<OAuthStoreTransaction.@NonNull Mutation> mutations) {
  requireNonNull(conditions); requireNonNull(mutations);
  if (conditions.isEmpty() || conditions.size() > 16 || mutations.size() > 8) throw OAuthStoreFormat.invalid();
  var expected = new java.util.HashMap<OAuthStoreKey, Condition>();
  for (Condition condition : conditions) {
   requireNonNull(condition);
   if (expected.put(condition.key, condition) != null) throw OAuthStoreFormat.invalid();
  }
  var changed = new java.util.HashSet<OAuthStoreKey>();
  for (Mutation mutation : mutations) {
   requireNonNull(mutation); Condition condition = expected.get(mutation.key);
   if (condition == null || !changed.add(mutation.key)
     || (mutation.kind == Mutation.Kind.REMOVE && condition.version == null)) throw OAuthStoreFormat.invalid();
  }
  return new OAuthStoreTransaction(conditions, mutations);
 }
 /** Returns the complete immutable predicate set.
 * @return all conditions
 * @since 1.0.0 */
 public @NonNull List<OAuthStoreTransaction.@NonNull Condition> getConditions() { return this.conditions; }
 /** Returns the complete immutable write set, possibly empty.
 * @return all mutations
 * @since 1.0.0 */
 public @NonNull List<OAuthStoreTransaction.@NonNull Mutation> getMutations() { return this.mutations; }
 /** Redacts every predicate and mutation.
 * @return a fixed description
 * @since 1.0.0 */
 @Override public @NonNull String toString() { return "OAuthStoreTransaction{transaction=<redacted>}"; }
 /**
  * An exact version or ABSENT predicate, engine-created and checked atomically with every other predicate.
  * @author <a href="https://www.revetkn.com">Mark Allen</a>
  * @since 1.0.0
  */
 @Immutable
 @CheckReturnValue
 public static final class Condition {
  private final @NonNull OAuthStoreKey key;
  private final @Nullable String version;
  private Condition(@NonNull OAuthStoreKey key, @Nullable String version) {
   this.key = requireNonNull(key); this.version = version;
  }
  static OAuthStoreTransaction.@NonNull Condition fromAbsent(@NonNull OAuthStoreKey key) {
   return new Condition(key, null);
  }
  static OAuthStoreTransaction.@NonNull Condition fromVersion(@NonNull OAuthStoreKey key, @NonNull String version) {
   OAuthStoreFormat.nonce(version); return new Condition(key, version);
  }
  /** Returns the conditioned key.
 * @return the key
 * @since 1.0.0 */
  public @NonNull OAuthStoreKey getKey() { return this.key; }
  /**
   * Returns the exact expected version, or empty for ABSENT. Empty never means an unrestricted match.
   * @return the version predicate
   * @since 1.0.0
   */
  public @NonNull Optional<@NonNull String> getExpectedVersion() { return Optional.ofNullable(this.version); }
  /** Redacts the predicate.
 * @return a fixed description
 * @since 1.0.0 */
  @Override public @NonNull String toString() { return "Condition{predicate=<redacted>}"; }
 }
 /**
  * An engine-created PUT or REMOVE; PUT carries its exact key-matched entry and REMOVE carries no entry.
  * @author <a href="https://www.revetkn.com">Mark Allen</a>
  * @since 1.0.0
  */
 @Immutable
 @CheckReturnValue
 public static final class Mutation {
  private final @NonNull OAuthStoreKey key;
  private final OAuthStoreTransaction.Mutation.@NonNull Kind kind;
  private final @Nullable OAuthStoreEntry entry;
  private Mutation(@NonNull OAuthStoreKey key, OAuthStoreTransaction.Mutation.@NonNull Kind kind,
    @Nullable OAuthStoreEntry entry) { this.key = key; this.kind = kind; this.entry = entry; }
  static OAuthStoreTransaction.@NonNull Mutation fromPut(@NonNull OAuthStoreEntry entry) {
   requireNonNull(entry); return new Mutation(entry.getKey(), Kind.PUT, entry);
  }
  static OAuthStoreTransaction.@NonNull Mutation fromRemove(@NonNull OAuthStoreKey key) {
   return new Mutation(requireNonNull(key), Kind.REMOVE, null);
  }
  /** Returns the changed key.
 * @return the key
 * @since 1.0.0 */
  public @NonNull OAuthStoreKey getKey() { return this.key; }
  /** Returns PUT or REMOVE.
 * @return the mutation kind
 * @since 1.0.0 */
  public OAuthStoreTransaction.Mutation.@NonNull Kind getKind() { return this.kind; }
  /** Returns the exact PUT entry or empty for REMOVE.
 * @return the entry
 * @since 1.0.0 */
  public @NonNull Optional<@NonNull OAuthStoreEntry> getEntry() { return Optional.ofNullable(this.entry); }
  /** Redacts the mutation.
 * @return a fixed description
 * @since 1.0.0 */
  @Override public @NonNull String toString() { return "Mutation{change=<redacted>}"; }
  /**
   * The two mutation operations.
   * @author <a href="https://www.revetkn.com">Mark Allen</a>
   * @since 1.0.0
   */
  @Immutable
  public enum Kind {
   /** Store the supplied entry.
 * @since 1.0.0 */
   PUT,
   /** Remove the version-conditioned entry.
 * @since 1.0.0 */
   REMOVE
  }
 }
}
