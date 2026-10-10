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
import javax.annotation.concurrent.Immutable;
import java.util.Objects;

/**
 * Storage provider outcomes when consuming a pending login.
 *
 * @since 1.0.0
 */
@Immutable
public sealed interface SamlPendingConsumeResult permits SamlPendingConsumeResult.Consumed,
        SamlPendingConsumeResult.Missing, SamlPendingConsumeResult.Unavailable,
        SamlPendingConsumeResult.Indeterminate {
    /**
     * A record removed atomically.
     *
     * @since 1.0.0
     */
    @Immutable
    final class Consumed implements SamlPendingConsumeResult {
        private final @NonNull String sealedRecord;
        private Consumed(@NonNull String sealedRecord) { this.sealedRecord = Objects.requireNonNull(sealedRecord); }
        /**
         * Creates a provider result for an atomically removed record.
         *
         * @param sealedRecord opaque Revetsec record
         * @return a consumed outcome
         * @since 1.0.0
         */
        public static @NonNull Consumed fromSealedRecord(@NonNull String sealedRecord) {
            return new Consumed(sealedRecord);
        }
        /**
         * Returns the sealed record for Revetsec to authenticate.
         *
         * @return sealed record
         * @since 1.0.0
         */
        public @NonNull String getSealedRecord() { return sealedRecord; }
        /**
         * Redacts the record.
         *
         * @return redacted description
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "SamlPendingConsumeResult.Consumed{<redacted>}"; }
    }
    /**
     * No live record matches the binding and handle.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Missing implements SamlPendingConsumeResult { /** Confirmed absence. */ INSTANCE }
    /**
     * The store failed before a mutation.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Unavailable implements SamlPendingConsumeResult { /** No mutation occurred. */ INSTANCE }
    /**
     * The consume outcome cannot be determined.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Indeterminate implements SamlPendingConsumeResult { /** Reconciliation is required. */ INSTANCE }
}
