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

import com.revetsec.OutboundUriPolicy;
import com.revetsec.StateSealer;
import com.revetsec.internal.http.ClientMetadataFreshness;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.http.HttpExchangeException;
import com.revetsec.internal.http.PinnedHttpsTransport;
import com.revetsec.internal.http.RawResponse;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicReference;
import static java.util.Objects.requireNonNull;
import static com.revetsec.oauth.server.OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE;
import static com.revetsec.oauth.server.OAuthServerAdmissionFailure.Reason.INVALID_CLIENT;

/** Synchronous optional reuse/fetch coordination, outside authoritative transactions; owns no threads. */
final class OAuthClientMetadataFetcher {
 @FunctionalInterface interface Transport {
  @NonNull RawResponse fetch(@NonNull URI uri, @NonNull Deadline deadline) throws HttpExchangeException;
 }
 private static final class PinnedTransport implements Transport {
  private final @NonNull OAuthClientMetadataPolicy policy;
  private final @NonNull Duration requestTimeout;
  private PinnedTransport(@NonNull OAuthClientMetadataPolicy policy, @NonNull Duration requestTimeout) {
   this.policy=requireNonNull(policy);this.requestTimeout=requireNonNull(requestTimeout);
   if(requestTimeout.isNegative() || requestTimeout.isZero()) throw OAuthServerConfiguration.invalid();
  }
  @Override public @NonNull RawResponse fetch(@NonNull URI uri, @NonNull Deadline deadline) throws HttpExchangeException {
   return PinnedHttpsTransport.fetch(uri,this.policy.getAddressResolver().orElseThrow()::resolve,
    this.policy.getMaximumResolvedAddresses(),this.policy.getMaximumDocumentBytes(),this.requestTimeout,deadline);
  }
 }
 private final @NonNull OAuthClientMetadataPolicy policy;
 private final @NonNull OAuthClientMetadataCache cache;
 private final @NonNull OAuthClientMetadataCacheCodec codec;
 private final @NonNull OAuthServerIngressLimits limits;
 private final @NonNull OutboundUriPolicy outbound;
 private final @NonNull Clock clock;
 private final @NonNull Transport transport;
 private final boolean nativeLoopback, localhost;
 private final @NonNull Semaphore fetches;
 private final @NonNull AtomicReference<@Nullable Instant> observedTime = new AtomicReference<>();
 OAuthClientMetadataFetcher(@NonNull String issuer, @NonNull StateSealer sealer, @NonNull OAuthClientMetadataPolicy policy,
   @NonNull OAuthServerIngressLimits limits, boolean nativeLoopback, boolean localhost,
   @NonNull OutboundUriPolicy outbound, @NonNull Clock clock, @NonNull Duration requestTimeout) {
  this(issuer, sealer, policy, limits, nativeLoopback, localhost, outbound, clock,new PinnedTransport(policy,requestTimeout));
 }
 // Package-private deterministic transport seam; production constructor always selects the pinned driver.
 OAuthClientMetadataFetcher(@NonNull String issuer, @NonNull StateSealer sealer, @NonNull OAuthClientMetadataPolicy policy,
   @NonNull OAuthServerIngressLimits limits, boolean nativeLoopback, boolean localhost,
   @NonNull OutboundUriPolicy outbound, @NonNull Clock clock, @NonNull Transport transport) {
  this.policy = requireNonNull(policy); this.limits = requireNonNull(limits);
  this.codec = new OAuthClientMetadataCacheCodec(issuer, sealer, policy, limits, nativeLoopback, localhost);
  this.cache = policy.cacheForEngine(); this.nativeLoopback = nativeLoopback; this.localhost = localhost;
  this.outbound = requireNonNull(outbound); this.clock = requireNonNull(clock); this.transport = requireNonNull(transport);
  this.fetches = new Semaphore(policy.getMaximumConcurrentFetches());
 }
 @NonNull OAuthClientMetadataDocument reusable(@NonNull String clientId, @NonNull Deadline deadline) { return retrieve(clientId, deadline, false); }
 // A bypass returns admitted metadata, not a transferable credential-transition capability.
 @NonNull OAuthClientMetadataDocument fresh(@NonNull String clientId, @NonNull Deadline deadline) { return retrieve(clientId, deadline, true); }
 private @NonNull OAuthClientMetadataDocument retrieve(@NonNull String clientId, @NonNull Deadline deadline, boolean bypass) {
  remaining(deadline); URI uri;
  try { uri = OAuthClientMetadataUri.clientId(clientId, this.policy, this.limits.clientIdLength); }
  catch (IllegalArgumentException failure) { throw fail(INVALID_CLIENT); }
  if (!this.outbound.permits(uri)) throw fail(INVALID_CLIENT);
  OAuthClientMetadataCacheKey key = this.codec.key(clientId);
  Instant before = now(deadline); boolean rollback = rollback(before);
  Optional<OAuthClientMetadataCacheEntry> old = Optional.empty(); boolean observed = false;
  if (!bypass) {
   try { old = requireNonNull(this.cache.read(key, remaining(deadline))); observed = true; }
   catch (OAuthClientMetadataCacheException failure) { interrupted(failure); }
   catch (RuntimeException failure) { /* Optional cache fault; no backend diagnostics escape. */ }
   remaining(deadline); Instant checked = now(deadline); rollback |= rollback(checked);
   if (!rollback && old.isPresent()) {
    Optional<OAuthClientMetadataCacheCodec.Cached> cached = this.codec.open(clientId, old.get(), checked);
    if (cached.isPresent()) { remaining(deadline); Instant released = now(deadline);
     if (!rollback(released) && !released.isBefore(checked) && released.isBefore(cached.get().expiresAt())) return cached.get().document();
    }
   }
  }
  remaining(deadline);
  if (!this.fetches.tryAcquire()) throw fail(INFRASTRUCTURE);
  try {
   remaining(deadline); RawResponse response;
   try { response = requireNonNull(this.transport.fetch(uri, deadline)); }
   catch (HttpExchangeException | RuntimeException failure) { throw fail(INFRASTRUCTURE); }
   remaining(deadline); Instant fetchedAt = now(deadline); rollback |= rollback(fetchedAt) || fetchedAt.isBefore(before);
   if (response.status() != 200) throw fail(INFRASTRUCTURE);
   byte[] body = response.body();
   try {
    OAuthClientMetadataDocument document = OAuthClientMetadataDocument.parse(clientId, body, this.policy,
      this.limits, this.nativeLoopback, this.localhost);
    Duration ttl = ClientMetadataFreshness.remaining(response, fetchedAt, this.policy.getMaximumFreshness());
    boolean newer = old.flatMap(entry -> this.codec.authenticatedFetchedAt(clientId, entry))
      .map(time -> time.isAfter(fetchedAt)).orElse(false);
    if (!bypass && observed && !rollback && !newer) {
     OAuthClientMetadataCacheEntry replacement = null;
     if (!ttl.isZero()) {
      try { Instant expires = Instant.ofEpochSecond(fetchedAt.plus(ttl).getEpochSecond());
       if (fetchedAt.isBefore(expires)) replacement = this.codec.seal(clientId, body, fetchedAt, expires);
      } catch (IllegalArgumentException | IllegalStateException | java.time.DateTimeException | ArithmeticException failure) { /* Successful fetch may skip optional storage. */ }
     }
     // CAS is against the pre-fetch observation only: a slow older fetch cannot replace any intervening write.
     // Invalid/no-reuse success deletes only that observed version, never a concurrent replacement.
     if (old.isPresent() || replacement != null) {
      try { if (!requireNonNull(this.cache.compareAndSet(key, old.map(OAuthClientMetadataCacheEntry::getVersion).orElse(null), replacement, remaining(deadline)))) remaining(deadline); }
      catch (OAuthClientMetadataCacheException failure) { interrupted(failure); }
      catch (RuntimeException failure) { /* Optional write may have applied; never retry blindly. */ }
     }
    }
    remaining(deadline); now(deadline); return document;
   } finally { Arrays.fill(body, (byte)0); }
  } finally { this.fetches.release(); }
 }
 private @NonNull Instant now(@NonNull Deadline deadline) {
  remaining(deadline);
  try { Instant result = requireNonNull(this.clock.instant()); remaining(deadline); return result; }
  catch (RuntimeException failure) { throw fail(INFRASTRUCTURE); }
 }
 private boolean rollback(@NonNull Instant now) {
  Instant highest = this.observedTime.accumulateAndGet(now, (previous, current) -> previous == null || current.isAfter(previous) ? current : previous);
  return now.isBefore(requireNonNull(highest));
 }
 private static void interrupted(@NonNull OAuthClientMetadataCacheException failure) {
  if (failure.getReason() == OAuthClientMetadataCacheException.Reason.INTERRUPTED) {
   Thread.currentThread().interrupt(); throw fail(INFRASTRUCTURE);
  }
 }
 private static @NonNull Duration remaining(@NonNull Deadline deadline) { return OAuthServerClientAdmission.remaining(deadline); }
 private static @NonNull OAuthServerAdmissionFailure fail(OAuthServerAdmissionFailure.@NonNull Reason reason) { return OAuthServerClientAdmission.failure(reason); }
}
