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
     * Atomically admit a previously unseen key until its final possible acceptance time.
     *
     * @param key the Revetsec-generated replay key
     * @param expiresAt the final possible acceptance time
     * @param remaining positive time budget for this operation
     * @return an explicit outcome; only MARKED permits identity release
     * @since 1.0.0
     */
    @NonNull MarkResult markIfAbsent(@NonNull String key, @NonNull Instant expiresAt,
            @NonNull Duration remaining);

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
