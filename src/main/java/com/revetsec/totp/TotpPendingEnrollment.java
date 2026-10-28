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
import javax.annotation.concurrent.Immutable;
import java.time.Instant;

import static java.util.Objects.requireNonNull;

/** Non-secret pending-enrollment information for reconciling an uncertain management operation.
 * @since 1.0.0 */
@Immutable
public final class TotpPendingEnrollment {
    private final @NonNull String enrollmentId;
    private final @NonNull String factorId;
    private final @NonNull Instant expiresAt;

    TotpPendingEnrollment(@NonNull String enrollmentId, @NonNull String factorId, @NonNull Instant expiresAt) {
        this.enrollmentId = requireNonNull(enrollmentId);
        this.factorId = requireNonNull(factorId);
        this.expiresAt = requireNonNull(expiresAt);
    }

    /** The pending enrollment identifier.
     * @return enrollmentId
     * @since 1.0.0 */
    public @NonNull String getEnrollmentId() { return this.enrollmentId; }

    /** The candidate factor generation identifier.
     * @return factorId
     * @since 1.0.0 */
    public @NonNull String getFactorId() { return this.factorId; }

    /** The pending enrollment expiry.
     * @return expiresAt
     * @since 1.0.0 */
    public @NonNull Instant getExpiresAt() { return this.expiresAt; }

    /** Redacts all account, operation and secret data.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "TotpPendingEnrollment{<redacted>}"; }
}
