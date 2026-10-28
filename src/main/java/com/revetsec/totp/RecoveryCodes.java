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
import java.util.List;
import java.time.Instant;

import static java.util.Objects.requireNonNull;

/** A newly committed recovery-code batch; plaintext codes cannot be retrieved again from durable storage.
 * @since 1.0.0 */
@Immutable
public final class RecoveryCodes {
    private final @NonNull String credentialNamespace;
    private final @NonNull String recoveryEpoch;
    private final @NonNull String accountId;
    private final @NonNull String factorId;
    private final @NonNull String batchId;
    private final @NonNull Instant issuedAt;
    private final @NonNull List<@NonNull String> codes;

    RecoveryCodes(@NonNull String credentialNamespace, @NonNull String recoveryEpoch, @NonNull String accountId, @NonNull String factorId, @NonNull String batchId, @NonNull Instant issuedAt, @NonNull List<@NonNull String> codes) {
        this.credentialNamespace = requireNonNull(credentialNamespace);
        this.recoveryEpoch = requireNonNull(recoveryEpoch);
        this.accountId = requireNonNull(accountId);
        this.factorId = requireNonNull(factorId);
        this.batchId = requireNonNull(batchId);
        this.issuedAt = requireNonNull(issuedAt);
        this.codes = List.copyOf(requireNonNull(codes));
    }

    /** The application credential namespace.
     * @return credentialNamespace
     * @since 1.0.0 */
    public @NonNull String getCredentialNamespace() { return this.credentialNamespace; }

    /** The admitted recovery epoch.
     * @return recoveryEpoch
     * @since 1.0.0 */
    public @NonNull String getRecoveryEpoch() { return this.recoveryEpoch; }

    /** The application-approved account identifier.
     * @return accountId
     * @since 1.0.0 */
    public @NonNull String getAccountId() { return this.accountId; }

    /** The active factor generation for this batch.
     * @return factorId
     * @since 1.0.0 */
    public @NonNull String getFactorId() { return this.factorId; }

    /** The recovery-code batch generation identifier.
     * @return batchId
     * @since 1.0.0 */
    public @NonNull String getBatchId() { return this.batchId; }

    /** The confirmed issue instant.
     * @return issuedAt
     * @since 1.0.0 */
    public @NonNull Instant getIssuedAt() { return this.issuedAt; }

    /** The immutable secret-bearing list of plaintext recovery codes.
     * @return codes
     * @since 1.0.0 */
    public @NonNull List<@NonNull String> getCodes() { return this.codes; }

    /** Redacts all account, operation and secret data.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "RecoveryCodes{<redacted>}"; }
}
