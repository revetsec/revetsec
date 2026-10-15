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

package com.revetsec.saml;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import javax.annotation.concurrent.Immutable;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * Atomic SAML assertion replay admission. A shared implementation must make one key visible to all nodes before
 * reporting {@link MarkResult#MARKED}; an uncertain write must report {@link MarkResult#INDETERMINATE}. The key is a
 * SHA-256, URL-safe encoding of length-prefixed SP, connection, IdP and assertion identifiers, not raw identity data.
 * Live entries must not be evicted to make room. This interface never validates an assertion by itself.
 *
 * @since 1.0.0
 */
@ThreadSafe
public interface SamlReplayCache {
    /**
     * Atomically admit a previously unseen key until its final possible acceptance time across
     * supported request bindings and time policies. A backend must retain the key through the
     * supplied absolute expiry without rounding that expiry down.
     *
     * @param key the Revetsec-generated replay key
     * @param expiresAt the final possible acceptance time across supported completion contexts
     * @param remaining positive time budget for this operation
     * @return an explicit outcome; only MARKED permits identity release
     * @since 1.0.0
     */
    @NonNull MarkResult markIfAbsent(@NonNull String key, @NonNull Instant expiresAt,
            @NonNull Duration remaining);

    /**
     * Atomically admit a replay key within a connection's capacity namespace. The key
     * itself already binds the connection, SP and IdP identifiers. Implementations
     * shared by mutually untrusted IdP connections should override this method and
     * reserve capacity per connection. The default preserves source compatibility
     * for existing stores but supplies no such capacity isolation.
     *
     * @param connectionId application-approved IdP connection namespace
     * @param key the Revetsec-generated replay key
     * @param expiresAt the final possible acceptance time
     * @param remaining positive time budget
     * @return an explicit atomic outcome
     * @since 1.0.0
     */
    default @NonNull MarkResult markIfAbsent(@NonNull String connectionId, @NonNull String key,
            @NonNull Instant expiresAt, @NonNull Duration remaining) {
        if (Objects.requireNonNull(connectionId).isEmpty())
            throw new IllegalArgumentException("Empty SAML connection namespace");
        return markIfAbsent(key, expiresAt, remaining);
    }

    /**
     * Outcomes of an atomic replay admission. A retry after INDETERMINATE cannot be interpreted as fresh.
     *
     * @since 1.0.0
     */
    @Immutable
    enum MarkResult {
        /** This call atomically established the replay fence. */ MARKED,
        /** The key was already fenced. */ ALREADY_PRESENT,
        /** The cache cannot accept another live record. */ CAPACITY_REFUSED,
        /** The cache could not attempt the write. */ UNAVAILABLE,
        /** The backend may or may not have completed the write. */ INDETERMINATE
    }
}
