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
import java.time.Duration;
import java.time.Instant;
import java.util.function.Predicate;

/**
 * Atomic storage for browser-bound SAML login and logout attempts. A shared implementation must consume a
 * record at most once across all nodes. The record is sealed by Revetsec and is opaque to the
 * provider. A process-local provider is suitable only for a single node.
 *
 * @since 1.0.0
 */
@ThreadSafe
public interface PendingSamlAuthenticationStore {
    /**
     * Saves a fresh record without replacing a live record with the same binding and handle.
     *
     * @param browserBinding browser-specific secret
     * @param relayStateHandle generated opaque lookup handle
     * @param sealedRecord Revetsec-sealed record
     * @param expiresAt exact expiry
     * @param remaining positive operation budget
     * @return the save outcome
     * @since 1.0.0
     */
    @NonNull SamlPendingSaveResult save(@NonNull String browserBinding, @NonNull String relayStateHandle,
            @NonNull String sealedRecord, @NonNull Instant expiresAt, @NonNull Duration remaining);

    /**
     * Atomically removes and returns one matching record. An uncertain removal is indeterminate.
     *
     * @param browserBinding browser-specific secret
     * @param relayStateHandle generated opaque lookup handle
     * @param remaining positive operation budget
     * @return the consume outcome
     * @since 1.0.0
     */
    @NonNull SamlPendingConsumeResult consume(@NonNull String browserBinding, @NonNull String relayStateHandle,
            @NonNull Duration remaining);

    /**
     * Validates one live sealed record before atomically removing that same record. The predicate
     * must accept the exact record returned by a successful consume; a replacement record must
     * be validated separately. A false predicate returns {@link SamlPendingConsumeResult.Missing}
     * without removing the record. A predicate exception or exhausted operation budget returns
     * {@link SamlPendingConsumeResult.Unavailable} without removal. An uncertain removal is
     * indeterminate.
     * <p>
     * The default implementation returns unavailable without reading, validating or consuming
     * state. Implementations must supply an atomic conditional consume to support this operation;
     * falling back to {@link #consume(String, String, Duration)} cannot preserve rejected state.
     * Logout completion requires this operation and fails closed until the store overrides it.
     * The predicate should perform only bounded validation and must not mutate store state.
     *
     * @param browserBinding browser-specific secret
     * @param relayStateHandle generated opaque lookup handle
     * @param sealedRecordMatches validation of the exact live sealed record
     * @param remaining positive budget including validation and removal
     * @return conditional consume outcome
     * @since 1.0.0
     */
    default @NonNull SamlPendingConsumeResult consumeIfMatches(@NonNull String browserBinding,
            @NonNull String relayStateHandle, @NonNull Predicate<@NonNull String> sealedRecordMatches,
            @NonNull Duration remaining) {
        return SamlPendingConsumeResult.Unavailable.INSTANCE;
    }
}
