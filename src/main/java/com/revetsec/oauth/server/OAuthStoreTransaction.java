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
import com.revetsec.StoreAdmission;
import com.revetsec.StoreTemporalCondition;
import com.revetsec.internal.StoreTimeRules;
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
 private final OAuthStoreTransaction.@NonNull Purpose purpose;
 private final @NonNull StoreAdmission expectedAdmission;
 private final @Nullable StoreTemporalCondition temporalCondition;
 private final @NonNull List<OAuthStoreTransaction.@NonNull Condition> conditions;
 private final @NonNull List<OAuthStoreTransaction.@NonNull Mutation> mutations;
 private OAuthStoreTransaction(OAuthStoreTransaction.@NonNull Purpose purpose,
   @NonNull StoreAdmission expectedAdmission, @Nullable StoreTemporalCondition temporalCondition,
   @NonNull List<OAuthStoreTransaction.@NonNull Condition> conditions,
   @NonNull List<OAuthStoreTransaction.@NonNull Mutation> mutations) {
  this.purpose=purpose; this.expectedAdmission=expectedAdmission; this.temporalCondition=temporalCondition;
  this.conditions = List.copyOf(conditions); this.mutations = List.copyOf(mutations);
 }
 static @NonNull OAuthStoreTransaction fromConditions(
   OAuthStoreTransaction.@NonNull Purpose purpose, @NonNull StoreAdmission expectedAdmission,
   @Nullable StoreTemporalCondition temporalCondition,
   @NonNull List<OAuthStoreTransaction.@NonNull Condition> conditions,
   @NonNull List<OAuthStoreTransaction.@NonNull Mutation> mutations) {
  requireNonNull(purpose); requireNonNull(expectedAdmission); requireNonNull(conditions); requireNonNull(mutations);
  if(purpose==Purpose.TIMED) {
   if(temporalCondition==null || !StoreTimeRules.sameAdmission(expectedAdmission,temporalCondition.getAdmission())) throw OAuthStoreFormat.invalid();
  } else if(temporalCondition!=null) throw OAuthStoreFormat.invalid();
  if (conditions.isEmpty() || conditions.size() > 16 || mutations.size() > 8) throw OAuthStoreFormat.invalid();
  var expected = new java.util.HashMap<OAuthStoreKey, Condition>();
  String namespace=null;
  for (Condition condition : conditions) {
   requireNonNull(condition);
   String scope=OAuthStoreFormat.namespace(condition.key);
   if(namespace==null) namespace=scope; else if(!namespace.equals(scope)) throw OAuthStoreFormat.invalid();
   if (expected.put(condition.key, condition) != null) throw OAuthStoreFormat.invalid();
  }
  var changed = new java.util.HashSet<OAuthStoreKey>();
  for (Mutation mutation : mutations) {
   requireNonNull(mutation); Condition condition = expected.get(mutation.key);
   if (condition == null || !changed.add(mutation.key)
     || (mutation.kind == Mutation.Kind.REMOVE && condition.version == null)
     || (mutation.kind == Mutation.Kind.PUT && mutation.entry!=null && mutation.entry.getVersion().equals(condition.version))) throw OAuthStoreFormat.invalid();
  }
  if(purpose==Purpose.FENCE_ONLY) validateFence(conditions,mutations);
  return new OAuthStoreTransaction(purpose,expectedAdmission,temporalCondition,conditions, mutations);
 }
 private static void validateFence(@NonNull List<OAuthStoreTransaction.@NonNull Condition> conditions,
   @NonNull List<OAuthStoreTransaction.@NonNull Mutation> mutations) {
  if(mutations.size()!=1) throw OAuthStoreFormat.invalid();
  Mutation mutation=mutations.get(0);
  if(mutation.kind!=Mutation.Kind.PUT || mutation.entry==null || !mutation.entry.getRetainUntil().equals(OAuthStoreFormat.PERMANENT)) throw OAuthStoreFormat.invalid();
  boolean issuer=false,subject=false;
  for(Condition condition:conditions) {
   if(condition.version==null) throw OAuthStoreFormat.invalid();
   if(condition.key.getKind()==OAuthStoreKey.Kind.ISSUER_STATE) issuer=true;
   else if(condition.key.getKind()==OAuthStoreKey.Kind.SUBJECT_STATE && condition.key.equals(mutation.key)) subject=true;
   else throw OAuthStoreFormat.invalid();
  }
  if(!issuer || (mutation.key.getKind()==OAuthStoreKey.Kind.ISSUER_STATE ? conditions.size()!=1
    : mutation.key.getKind()!=OAuthStoreKey.Kind.SUBJECT_STATE || conditions.size()!=2 || !subject)) throw OAuthStoreFormat.invalid();
 }
 /** Returns TIMED or the narrow existing permanent-fence transition purpose.
  * @return the purpose
  * @since 1.0.0 */
 public OAuthStoreTransaction.@NonNull Purpose getPurpose(){return this.purpose;}
 /** Returns the admitted authority/recovery identities required by every condition.
  * @return expected admission
  * @since 1.0.0 */
 public @NonNull StoreAdmission getExpectedAdmission(){return this.expectedAdmission;}
 /** Returns the required TIMED condition, or empty only for FENCE_ONLY.
  * @return the temporal condition
  * @since 1.0.0 */
 public @NonNull Optional<@NonNull StoreTemporalCondition> getTemporalCondition(){return Optional.ofNullable(this.temporalCondition);}
 /** The two explicit transaction modes. FENCE_ONLY grants no generic clock-off write authority.
  * @since 1.0.0 */
 @Immutable
 public enum Purpose {
  /** Normal timed validation including initialization, issuance and maintenance.
   * @since 1.0.0 */
  TIMED,
  /** Exactly one existing permanent issuer/subject epoch advance; no temporal condition.
   * @since 1.0.0 */
  FENCE_ONLY
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
