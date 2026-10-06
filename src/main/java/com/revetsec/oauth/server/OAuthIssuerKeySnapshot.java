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
import java.security.PublicKey;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import static java.util.Objects.requireNonNull;

/**
 * Immutable application declaration of active, published and retained public keys. The active projection is
 * always included. Identifiers must never be reused for different material. A new generation has a strictly
 * later publication instant; keep its published keys available for the configured metadata freshness before
 * signing. Retirement boundaries cannot precede outstanding token expiries plus skew, deadline and cache margins.
 * Applications persist these obligations across nodes, restarts and restores; an initial snapshot is a trusted
 * declaration, not evidence of external distribution. At most 100 keys and 128 KiB of aggregate configuration
 * are accepted; response limits apply separately. No provider lookup or signing occurs during construction.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class OAuthIssuerKeySnapshot {
 private final @NonNull OAuthIssuerSigningKey activeKey;
 private final @NonNull Map<@NonNull String,@NonNull PublicKey> verificationKeys;
 private final @NonNull String generation;
 private final @NonNull Instant publishedAt;
 private final @NonNull Map<@NonNull String,@NonNull Instant> retirementNotBefore;
 private OAuthIssuerKeySnapshot(@NonNull Builder builder) {
  if(builder.generation==null || builder.publishedAt==null) throw new IllegalStateException("Issuer key lifecycle declarations are required.");
  this.activeKey=builder.activeKey; this.generation=builder.generation;this.publishedAt=builder.publishedAt;
  Map<String,PublicKey> keys=new LinkedHashMap<>(builder.verificationKeys);
  PublicKey previous=keys.put(this.activeKey.getKeyId(),this.activeKey.getPublicKey());
  if(previous!=null && !OAuthIssuerPublicKeys.material(previous).equals(OAuthIssuerPublicKeys.material(this.activeKey.getPublicKey())))
   throw OAuthStoreFormat.invalid();
  if(keys.size()>100 || !keys.keySet().containsAll(builder.retirementNotBefore.keySet())) throw OAuthStoreFormat.invalid();
  int size=OAuthServerConfiguration.utf8Length(this.generation);
  for(Map.Entry<String,PublicKey> entry:keys.entrySet()) { size=OAuthServerConfiguration.addBytes(size,entry.getKey());
   size=OAuthServerConfiguration.addBytes(size,OAuthIssuerPublicKeys.material(entry.getValue())); }
  for(Instant retirement:builder.retirementNotBefore.values()) if(retirement.isBefore(this.publishedAt)) throw OAuthStoreFormat.invalid();
  this.verificationKeys=Map.copyOf(keys);this.retirementNotBefore=Map.copyOf(builder.retirementNotBefore);
 }
 /**
  * Starts a builder around the required active signing key.
  * @param activeKey required immutable signing key
  * @return a new builder
  * @throws NullPointerException if activeKey is null
  * @since 1.0.0
  */
 @CheckReturnValue
 public static @NonNull Builder withActiveKey(@NonNull OAuthIssuerSigningKey activeKey) { return new Builder(requireNonNull(activeKey)); }
 /** Returns the active signing holder.
  * @return the active signing holder
  * @since 1.0.0
  */
 public @NonNull OAuthIssuerSigningKey getActiveKey() { return this.activeKey; }
 /** Returns the published and retained public verification keys.
  * @return unmodifiable checked public keys, including the active key
  * @since 1.0.0
  */
 public @NonNull Map<@NonNull String,@NonNull PublicKey> getVerificationKeys() { return this.verificationKeys; }
 /** Returns the application lifecycle generation declaration.
  * @return the exact application lifecycle generation
  * @since 1.0.0
  */
 public @NonNull String getGeneration() { return this.generation; }
 /** Returns the declared publication instant for this generation.
  * @return when this generation was published to independent resources
  * @since 1.0.0
  */
 public @NonNull Instant getPublishedAt() { return this.publishedAt; }
 /** Returns the declared earliest removal instants for retained public keys.
  * @return unmodifiable earliest retirement instants; absence declares no planned retirement
  * @since 1.0.0
  */
 public @NonNull Map<@NonNull String,@NonNull Instant> getRetirementNotBefore() { return this.retirementNotBefore; }
 /** @return a description without identifiers or key material
  * @since 1.0.0
  */
 @Override public @NonNull String toString() { return "OAuthIssuerKeySnapshot{<redacted>}"; }
 /**
  * Builds a checked immutable declaration without signing or provider lookup.
  * @author <a href="https://www.revetkn.com">Mark Allen</a>
  * @since 1.0.0
  */
 @NotThreadSafe
 @CheckReturnValue
 public static final class Builder {
  private final @NonNull OAuthIssuerSigningKey activeKey;
  private @NonNull Map<@NonNull String,@NonNull PublicKey> verificationKeys=Map.of();
  private @Nullable String generation;
  private @Nullable Instant publishedAt;
  private @NonNull Map<@NonNull String,@NonNull Instant> retirementNotBefore=Map.of();
  private Builder(@NonNull OAuthIssuerSigningKey activeKey) { this.activeKey=activeKey; }
  /**
   * Sets additional public keys; an equal active duplicate is allowed, different material for its ID is refused.
   * @param value at most 100 checked public RSA keys, or null to reset empty
   * @return this builder
   * @throws IllegalArgumentException if supplied configuration is invalid
   * @since 1.0.0
   */
  @CheckReturnValue
  public @NonNull Builder verificationKeys(@Nullable Map<@NonNull String,@NonNull PublicKey> value) {
   if(value==null) this.verificationKeys=Map.of();
   else {
    if(value.size()>100) throw OAuthStoreFormat.invalid();
    Map<String,PublicKey> copy=new LinkedHashMap<>();
    for(Map.Entry<String,PublicKey> entry:value.entrySet()) {
     String id=OAuthServerConfiguration.text(entry.getKey(),256);
     if(copy.put(id,OAuthIssuerPublicKeys.snapshot(entry.getValue()))!=null) throw OAuthStoreFormat.invalid();
    }
    this.verificationKeys=Map.copyOf(copy);
   }
   return this;
  }
  /**
   * Sets the required generation declaration.
   * @param value nonempty text of at most 256 characters, or null to clear required
   * @return this builder
   * @throws IllegalArgumentException if supplied text is invalid
   * @since 1.0.0
   */
  @CheckReturnValue
  public @NonNull Builder generation(@Nullable String value) { this.generation=value==null ? null : OAuthServerConfiguration.text(value,256); return this; }
  /**
   * Sets the required publication instant.
   * @param value an instant before the permanent storage sentinel, or null to clear required
   * @return this builder
   * @throws IllegalArgumentException if the supplied instant is invalid
   * @since 1.0.0
   */
  @CheckReturnValue
  public @NonNull Builder publishedAt(@Nullable Instant value) {
   if(value!=null && !value.isBefore(OAuthStoreFormat.PERMANENT)) throw OAuthStoreFormat.invalid();
   this.publishedAt=value;return this;
  }
  /**
   * Declares the earliest removal instants for published keys; it does not retire them automatically.
   * @param value at most 100 key IDs to finite instants, or null to reset empty
   * @return this builder
   * @throws IllegalArgumentException if supplied configuration is invalid
   * @since 1.0.0
   */
  @CheckReturnValue
  public @NonNull Builder retirementNotBefore(@Nullable Map<@NonNull String,@NonNull Instant> value) {
   if(value==null) this.retirementNotBefore=Map.of();
   else {
    if(value.size()>100) throw OAuthStoreFormat.invalid();
    Map<String,Instant> copy=new LinkedHashMap<>();
    for(Map.Entry<String,Instant> entry:value.entrySet()) {
     String id=OAuthServerConfiguration.text(entry.getKey(),256);Instant instant=requireNonNull(entry.getValue());
     if(!instant.isBefore(OAuthStoreFormat.PERMANENT) || copy.put(id,instant)!=null) throw OAuthStoreFormat.invalid();
    }
    this.retirementNotBefore=Map.copyOf(copy);
   }
   return this;
  }
  /**
   * Checks and snapshots the configuration.
   * @return immutable lifecycle declaration
   * @throws IllegalStateException if generation or publishedAt is missing
   * @throws IllegalArgumentException if supplied configuration is inconsistent
   * @since 1.0.0
   */
  @CheckReturnValue
  public @NonNull OAuthIssuerKeySnapshot build() { return new OAuthIssuerKeySnapshot(this); }
 }
}
