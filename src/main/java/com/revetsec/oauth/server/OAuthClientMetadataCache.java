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

import java.time.Duration;
import java.util.Optional;

import javax.annotation.concurrent.ThreadSafe;

/**
 * Thread-safe storage for bounded encrypted client-metadata carriers. Applications may use shared
 * infrastructure. Revetsec retains namespace/provenance, parsing, eligibility, HTTP freshness and
 * operation-specific fresh-fetch checks. This interface provides no loader, parser, TTL override,
 * client authority or authorization-store fallback. Calls honor the shrinking positive budget and
 * interruption; providers run outside authoritative transactions. Revetsec cannot forcibly preempt
 * application code. Failures throw rather than pretending to be misses/conflicts; an optional-cache
 * failure permits only a bounded fresh retrieval within the original budget, never stale use.
 * Providers bound capacity and storage work; eviction/expiry may create misses. The policy's
 * maximumCacheEntries configures only its engine-owned default, not a cluster-wide limit on a
 * custom provider. Shared key namespaces must be stable across compatible engines and distinct
 * across issuer/configuration identities. Persist fields exactly.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
@CheckReturnValue
public interface OAuthClientMetadataCache {
    /**
     * Reads storage data or a confirmed miss; a hit is not a validated document or fresh200 proof.
     *
     * @param key the exact bounded address
     * @param remainingBudget the positive remaining budget
     * @return the carrier or a confirmed miss
     * @throws OAuthClientMetadataCacheException for provider failure, timeout or interruption
     * @since 1.0.0
     */
    @NonNull Optional<@NonNull OAuthClientMetadataCacheEntry> read(
            @NonNull OAuthClientMetadataCacheKey key, @NonNull Duration remainingBudget);

    /**
     * Atomically compares the exact current version/absence and then replaces/removes the carrier
     * at one key. Null expectedVersion requires absence; null replacement removes the matched
     * entry. False changes nothing. Replacement keys must match and replacement versions must be
     * fresh and differ from expectedVersion. A competing write cannot be overwritten using an
     * obsolete version. After eviction/expiry, absence can permit a new insertion; this is not
     * durable historical ordering. A failure may leave a mutation applied. This is optional
     * storage, not credential consumption or a distributed lock; no outcome satisfies a fresh200
     * requirement.
     *
     * @param key the exact address
     * @param expectedVersion the canonical comparison version, or null for absence
     * @param replacement the bounded replacement, or null to remove
     * @param remainingBudget the positive remaining budget
     * @return whether the atomic comparison matched and the operation completed
     * @throws IllegalArgumentException for an invalid version, mismatched key or reused comparison
     *     version
     * @throws OAuthClientMetadataCacheException for provider failure, timeout or interruption
     * @since 1.0.0
     */
    @NonNull Boolean compareAndSet(
            @NonNull OAuthClientMetadataCacheKey key,
            @Nullable String expectedVersion,
            @Nullable OAuthClientMetadataCacheEntry replacement,
            @NonNull Duration remainingBudget);
}
