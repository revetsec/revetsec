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

package com.revetsec.totp;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/** Non-secret account status at an authoritative read point; no authentication proof is conferred.
 * @since 1.0.0 */
@Immutable
public final class TotpStatus {
    private final @Nullable TotpFactor activeFactor;
    private final @Nullable TotpPendingEnrollment pendingEnrollment;
    private final @Nullable String recoveryBatchId;
    private final @NonNull Integer remainingRecoveryCodeCount;

    TotpStatus(@Nullable TotpFactor activeFactor, @Nullable TotpPendingEnrollment pendingEnrollment,
            @Nullable String recoveryBatchId, @NonNull Integer remainingRecoveryCodeCount) {
        this.activeFactor = activeFactor;
        this.pendingEnrollment = pendingEnrollment;
        this.recoveryBatchId = recoveryBatchId;
        this.remainingRecoveryCodeCount = requireNonNull(remainingRecoveryCodeCount);
    }

    /** Returns the current active factor generation when enrolled.
     * @return active factor
     * @since 1.0.0 */
    public @NonNull Optional<@NonNull TotpFactor> getActiveFactor() {
        return Optional.ofNullable(this.activeFactor);
    }

    /** Returns the pending enrollment for reconciling management operations.
     * @return pending enrollment
     * @since 1.0.0 */
    public @NonNull Optional<@NonNull TotpPendingEnrollment> getPendingEnrollment() {
        return Optional.ofNullable(this.pendingEnrollment);
    }

    /** Returns the current recovery-code batch generation.
     * @return recovery batch identifier
     * @since 1.0.0 */
    public @NonNull Optional<@NonNull String> getRecoveryBatchId() {
        return Optional.ofNullable(this.recoveryBatchId);
    }

    /** Returns the number of currently usable recovery codes.
     * @return remaining count, zero when no batch is active
     * @since 1.0.0 */
    public @NonNull Integer getRemainingRecoveryCodeCount() { return this.remainingRecoveryCodeCount; }

    /** Redacts account and generation information.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "TotpStatus{<redacted>}"; }
}
