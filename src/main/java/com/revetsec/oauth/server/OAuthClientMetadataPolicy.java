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
import com.revetsec.internal.Limits;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.net.URI;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import static java.util.Objects.requireNonNull;

/**
 * Immutable opt-in configuration for public client metadata documents.
 * The default is disabled. Enabling requires a trusted bounded address resolver; no build performs
 * DNS, HTTP, signing, provider calls or thread creation. This policy is configuration, not client
 * authorization or evidence of identity. Retrieved client names are untrusted display text.
 * Origin restrictions can narrow public HTTPS eligibility, never permit private destinations.
 * Actual retrieval also requires Revetsec's pinned transport and complete operation admission.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class OAuthClientMetadataPolicy {
 private static final @NonNull OAuthClientMetadataPolicy DISABLED = new OAuthClientMetadataPolicy(null);
 private final @Nullable OAuthClientMetadataAddressResolver addressResolver;
 private final @Nullable OAuthClientMetadataCache cache;
 private final @Nullable Set<@NonNull URI> allowedOrigins;
 private final @NonNull Integer maximumDocumentBytes;
 private final @NonNull Integer maximumCacheEntries;
 private final @NonNull Duration maximumFreshness;
 private final @NonNull Integer maximumConcurrentFetches;
 private final @NonNull Integer maximumResolvedAddresses;
 private OAuthClientMetadataPolicy(@Nullable Builder builder) {
  this.addressResolver = builder == null ? null : requireNonNull(builder.addressResolver);
  this.cache = builder == null ? null : builder.cache;
  this.allowedOrigins = builder == null ? null : builder.allowedOrigins;
  this.maximumDocumentBytes = builder == null ? Integer.valueOf(Limits.CIMD_MAXIMUM_DOCUMENT_BYTES.getDefaultIntValue()) : builder.maximumDocumentBytes;
  this.maximumCacheEntries = builder == null ? Integer.valueOf(Limits.CIMD_MAXIMUM_CACHE_ENTRIES.getDefaultIntValue()) : builder.maximumCacheEntries;
  this.maximumFreshness = builder == null ? Limits.CIMD_MAXIMUM_FRESHNESS.getDefaultDuration() : builder.maximumFreshness;
  this.maximumConcurrentFetches = builder == null ? Integer.valueOf(Limits.CIMD_MAXIMUM_CONCURRENT_FETCHES.getDefaultIntValue()) : builder.maximumConcurrentFetches;
  this.maximumResolvedAddresses = builder == null ? Integer.valueOf(Limits.CIMD_MAXIMUM_RESOLVED_ADDRESSES.getDefaultIntValue()) : builder.maximumResolvedAddresses;
 }
 /**
  * Returns the disabled default configuration.
  * @return the disabled policy
  * @since 1.0.0
  */
 @CheckReturnValue public static @NonNull OAuthClientMetadataPolicy disabledInstance() { return DISABLED; }
 /**
  * Starts an enabled policy with its required trusted resolver.
  * @param addressResolver the bounded resolver
  * @return the builder
  * @throws NullPointerException if addressResolver is null
  * @since 1.0.0
  */
 @CheckReturnValue public static @NonNull Builder withAddressResolver(@NonNull OAuthClientMetadataAddressResolver addressResolver) {
  return new Builder(requireNonNull(addressResolver));
 }
 /**
  * Builds an enabled policy with the reviewed defaults and no callback or I/O.
  * @param addressResolver the bounded resolver
  * @return the enabled policy
  * @throws NullPointerException if addressResolver is null
  * @since 1.0.0
  */
 @CheckReturnValue public static @NonNull OAuthClientMetadataPolicy fromAddressResolver(@NonNull OAuthClientMetadataAddressResolver addressResolver) {
  return withAddressResolver(addressResolver).build();
 }
 /**
  * Returns whether metadata retrieval is configured.
  * @return the enabled flag, not a transport availability or authorization proof
  * @since 1.0.0
  */
 public @NonNull Boolean getEnabled() { return this.addressResolver != null; }
 /**
  * Returns the required resolver when enabled.
  * @return empty only for the disabled policy
  * @since 1.0.0
  */
 public @NonNull Optional<@NonNull OAuthClientMetadataAddressResolver> getAddressResolver() { return Optional.ofNullable(this.addressResolver); }
 /**
  * Returns explicitly supplied storage; empty selects a deferred engine-owned bounded in-memory default.
  * Sharing a policy object does not share default storage. An explicit instance may be shared by applications.
  * maximumCacheEntries governs the default only; a custom provider owns its capacity and eviction policy.
  * @return the explicitly configured storage, or empty for the local default
  * @since 1.0.0
  */
 public @NonNull Optional<@NonNull OAuthClientMetadataCache> getCache() { return Optional.ofNullable(this.cache); }
 @NonNull OAuthClientMetadataCache cacheForEngine() {
  if(!getEnabled())throw new IllegalStateException("Client metadata retrieval is disabled.");
  return this.cache==null?InMemoryOAuthClientMetadataCache.fromMaximumEntries(this.maximumCacheEntries):this.cache;
 }
 /**
  * Returns the exact origin restriction snapshot.
  * @return empty for all eligible public HTTPS origins; a present empty set denies every origin
  * @since 1.0.0
  */
 public @NonNull Optional<@NonNull Set<@NonNull URI>> getAllowedOrigins() { return Optional.ofNullable(this.allowedOrigins); }
 /**
  * Returns the configured bytes bound for maximumDocumentBytes.
  * @return the configured limit
  * @since 1.0.0
  */
 public @NonNull Integer getMaximumDocumentBytes() { return this.maximumDocumentBytes; }
 /**
  * Returns the engine-owned default cache entry bound; custom provider capacity is backend-owned.
  * @return the configured limit
  * @since 1.0.0
  */
 public @NonNull Integer getMaximumCacheEntries() { return this.maximumCacheEntries; }
 /**
  * Returns the configured time bound for maximumFreshness.
  * @return the configured limit
  * @since 1.0.0
  */
 public @NonNull Duration getMaximumFreshness() { return this.maximumFreshness; }
 /**
  * Returns the configured fetches bound for maximumConcurrentFetches.
  * @return the configured limit
  * @since 1.0.0
  */
 public @NonNull Integer getMaximumConcurrentFetches() { return this.maximumConcurrentFetches; }
 /**
  * Returns the configured addresses bound for maximumResolvedAddresses.
  * @return the configured limit
  * @since 1.0.0
  */
 public @NonNull Integer getMaximumResolvedAddresses() { return this.maximumResolvedAddresses; }
 @Override public @NonNull String toString() { return "OAuthClientMetadataPolicy{enabled=" + getEnabled() + ", configuration=redacted}"; }
 /**
  * Builds an enabled policy; null property values reset defaults, except resolver null clears a required property.
  * @author <a href="https://www.revetkn.com">Mark Allen</a>
  * @since 1.0.0
  */
 @NotThreadSafe @CheckReturnValue
 public static final class Builder {
  private @Nullable OAuthClientMetadataAddressResolver addressResolver;
  private @Nullable OAuthClientMetadataCache cache;
  private @Nullable Set<@NonNull URI> allowedOrigins;
  private @NonNull Integer maximumDocumentBytes = Limits.CIMD_MAXIMUM_DOCUMENT_BYTES.getDefaultIntValue();
  private @NonNull Integer maximumCacheEntries = Limits.CIMD_MAXIMUM_CACHE_ENTRIES.getDefaultIntValue();
  private @NonNull Duration maximumFreshness = Limits.CIMD_MAXIMUM_FRESHNESS.getDefaultDuration();
  private @NonNull Integer maximumConcurrentFetches = Limits.CIMD_MAXIMUM_CONCURRENT_FETCHES.getDefaultIntValue();
  private @NonNull Integer maximumResolvedAddresses = Limits.CIMD_MAXIMUM_RESOLVED_ADDRESSES.getDefaultIntValue();
  private Builder(@NonNull OAuthClientMetadataAddressResolver resolver) { this.addressResolver = resolver; }
  /**
   * Sets the trusted resolver; null clears it and makes build fail.
   * @param value the resolver, or null to clear
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder addressResolver(@Nullable OAuthClientMetadataAddressResolver value) { this.addressResolver = value; return this; }
  /**
   * Selects application storage. Null resets deferred engine-local defaults; build invokes no provider method.
   * Shared providers must honor atomic comparison, namespaces, record bounds and remaining budgets.
   * @param value the custom storage, or null for the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder cache(@Nullable OAuthClientMetadataCache value) { this.cache=value;return this; }
  /**
   * Sets a complete exact origin restriction snapshot. Null resets all eligible public HTTPS origins;
   * an empty set denies every origin. Origins have HTTPS scheme, host and optional port only, without path,
   * query, fragment or userinfo. At most 4096 origins and 128 KiB aggregate text are accepted.
   * @param value the restriction, or null to reset
   * @return this builder
   * @throws IllegalArgumentException if a supplied origin or aggregate is invalid
   * @throws NullPointerException if a set element is null
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder allowedOrigins(@Nullable Set<@NonNull URI> value) {
   if (value == null) { this.allowedOrigins = null; return this; }
   if (value.size() > 4096) throw OAuthServerConfiguration.invalid();
   Set<URI> copy = new LinkedHashSet<>(); int used = 0;
   for (URI origin : value) {
    requireNonNull(origin); OAuthClientMetadataUri.origin(origin);
    used = OAuthServerConfiguration.addBytes(used, origin.toString());
    copy.add(origin); if (copy.size() > 4096) throw OAuthServerConfiguration.invalid();
   }
   this.allowedOrigins = Collections.unmodifiableSet(copy); return this;
  }
  /**
   * Sets maximumDocumentBytes, bounded from {@code 1024} through {@code 5120}, inclusive.
   * @param value the limit, or null to reset to {@code 5120}
   * @return this builder
   * @throws IllegalArgumentException if outside the allowed interval
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumDocumentBytes(@Nullable Integer value) {
   this.maximumDocumentBytes = value == null ? Limits.CIMD_MAXIMUM_DOCUMENT_BYTES.getDefaultIntValue() : Limits.CIMD_MAXIMUM_DOCUMENT_BYTES.require(value); return this;
  }
  /**
   * Sets the engine-owned default cache maximumCacheEntries, bounded from {@code 1} through {@code 4096}, inclusive.
   * @param value the limit, or null to reset to {@code 128}
   * @return this builder
   * @throws IllegalArgumentException if outside the allowed interval
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumCacheEntries(@Nullable Integer value) {
   this.maximumCacheEntries = value == null ? Limits.CIMD_MAXIMUM_CACHE_ENTRIES.getDefaultIntValue() : Limits.CIMD_MAXIMUM_CACHE_ENTRIES.require(value); return this;
  }
  /**
   * Sets maximumFreshness, bounded from {@code Duration.ZERO} through {@code Duration.ofHours(1)}, inclusive.
   * @param value the limit, or null to reset to {@code Duration.ofSeconds(300)}
   * @return this builder
   * @throws IllegalArgumentException if outside the allowed interval
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumFreshness(@Nullable Duration value) {
   this.maximumFreshness = value == null ? Limits.CIMD_MAXIMUM_FRESHNESS.getDefaultDuration() : Limits.CIMD_MAXIMUM_FRESHNESS.require(value); return this;
  }
  /**
   * Sets maximumConcurrentFetches, bounded from {@code 1} through {@code 64}, inclusive.
   * @param value the limit, or null to reset to {@code 8}
   * @return this builder
   * @throws IllegalArgumentException if outside the allowed interval
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumConcurrentFetches(@Nullable Integer value) {
   this.maximumConcurrentFetches = value == null ? Limits.CIMD_MAXIMUM_CONCURRENT_FETCHES.getDefaultIntValue() : Limits.CIMD_MAXIMUM_CONCURRENT_FETCHES.require(value); return this;
  }
  /**
   * Sets maximumResolvedAddresses, bounded from {@code 1} through {@code 64}, inclusive.
   * @param value the limit, or null to reset to {@code 16}
   * @return this builder
   * @throws IllegalArgumentException if outside the allowed interval
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumResolvedAddresses(@Nullable Integer value) {
   this.maximumResolvedAddresses = value == null ? Limits.CIMD_MAXIMUM_RESOLVED_ADDRESSES.getDefaultIntValue() : Limits.CIMD_MAXIMUM_RESOLVED_ADDRESSES.require(value); return this;
  }
  /**
   * Builds a complete immutable enabled configuration without invoking the resolver.
   * @return the configured policy
   * @throws IllegalStateException if the required resolver was cleared
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull OAuthClientMetadataPolicy build() {
   if (this.addressResolver == null) throw new IllegalStateException("Client metadata requires an address resolver.");
   return new OAuthClientMetadataPolicy(this);
  }
 }
}
