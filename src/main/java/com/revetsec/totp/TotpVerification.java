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

/** Library-created proof of a committed fresh TOTP acceptance; application login completion remains separate.
 * @since 1.0.0 */
@Immutable
public final class TotpVerification {
    private final @NonNull String credentialNamespace;
    private final @NonNull String recoveryEpoch;
    private final @NonNull String accountId;
    private final @NonNull String factorId;
    private final @NonNull Instant verifiedAt;
    private final @NonNull String operationBinding;

    TotpVerification(@NonNull String credentialNamespace, @NonNull String recoveryEpoch, @NonNull String accountId, @NonNull String factorId, @NonNull Instant verifiedAt, @NonNull String operationBinding) {
        this.credentialNamespace = requireNonNull(credentialNamespace);
        this.recoveryEpoch = requireNonNull(recoveryEpoch);
        this.accountId = requireNonNull(accountId);
        this.factorId = requireNonNull(factorId);
        this.verifiedAt = requireNonNull(verifiedAt);
        this.operationBinding = requireNonNull(operationBinding);
    }

    /** The application credential namespace.
     * @return credentialNamespace
     * @since 1.0.0 */
    public @NonNull String getCredentialNamespace() { return this.credentialNamespace; }

    /** The admitted recovery epoch; session completion must enforce it.
     * @return recoveryEpoch
     * @since 1.0.0 */
    public @NonNull String getRecoveryEpoch() { return this.recoveryEpoch; }

    /** The application-approved account identifier.
     * @return accountId
     * @since 1.0.0 */
    public @NonNull String getAccountId() { return this.accountId; }

    /** The verified active factor generation.
     * @return factorId
     * @since 1.0.0 */
    public @NonNull String getFactorId() { return this.factorId; }

    /** The confirmed verification instant.
     * @return verifiedAt
     * @since 1.0.0 */
    public @NonNull Instant getVerifiedAt() { return this.verifiedAt; }

    /** The server-owned pending operation binding.
     * @return operationBinding
     * @since 1.0.0 */
    public @NonNull String getOperationBinding() { return this.operationBinding; }

    /** Returns the verified method provenance.
     * @return authentication method
     * @since 1.0.0 */
    public @NonNull TotpAuthenticationMethod getMethod() { return TotpAuthenticationMethod.TOTP; }

    /** Redacts all account, operation and secret data.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "TotpVerification{<redacted>}"; }
}
