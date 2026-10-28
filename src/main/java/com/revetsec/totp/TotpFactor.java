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

/** An active factor generation; this value contains no TOTP secret.
 * @since 1.0.0 */
@Immutable
public final class TotpFactor {
    private final @NonNull String credentialNamespace;
    private final @NonNull String recoveryEpoch;
    private final @NonNull String accountId;
    private final @NonNull String factorId;
    private final @NonNull Instant enrolledAt;

    TotpFactor(@NonNull String credentialNamespace, @NonNull String recoveryEpoch, @NonNull String accountId, @NonNull String factorId, @NonNull Instant enrolledAt) {
        this.credentialNamespace = requireNonNull(credentialNamespace);
        this.recoveryEpoch = requireNonNull(recoveryEpoch);
        this.accountId = requireNonNull(accountId);
        this.factorId = requireNonNull(factorId);
        this.enrolledAt = requireNonNull(enrolledAt);
    }

    /** The application credential namespace.
     * @return credentialNamespace
     * @since 1.0.0 */
    public @NonNull String getCredentialNamespace() { return this.credentialNamespace; }

    /** The recovery epoch in which this factor is authoritative.
     * @return recoveryEpoch
     * @since 1.0.0 */
    public @NonNull String getRecoveryEpoch() { return this.recoveryEpoch; }

    /** The application-approved account identifier.
     * @return accountId
     * @since 1.0.0 */
    public @NonNull String getAccountId() { return this.accountId; }

    /** The active factor generation identifier.
     * @return factorId
     * @since 1.0.0 */
    public @NonNull String getFactorId() { return this.factorId; }

    /** The confirmed enrollment instant.
     * @return enrolledAt
     * @since 1.0.0 */
    public @NonNull Instant getEnrolledAt() { return this.enrolledAt; }

    /** Redacts all account, operation and secret data.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "TotpFactor{<redacted>}"; }
}
