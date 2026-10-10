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

package com.revetsec.webauthn;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.time.Duration;

/**
 * Application-owned admission barrier for authoritative WebAuthn operations. Before granting a
 * permit, the application must compare its independent durable recovery marker and sealing-key
 * state with the authoritative store. A database snapshot that is internally consistent can
 * still be old, so checking only WebAuthn records is insufficient. Restore must stop new
 * admission and drain every outstanding permit before reopening traffic. Implementations must
 * honor the remaining positive caller-thread budget and preserve interrupt status. This gate
 * never creates a verification proof.
 *
 * @since 1.0.0
 */
@ThreadSafe
public interface WebAuthnRecoveryGate {
    /**
     * Acquires an admission permit held through the entire operation, including the store write.
     * Return {@code null} when traffic is closed or the external marker cannot be confirmed.
     * A failure to acquire is an infrastructure outcome, not an invalid-credential verdict.
     *
     * @param remainingBudget the remaining positive operation budget
     * @return an admitted permit, or {@code null} when admission is unavailable
     * @since 1.0.0
     */
    @Nullable Permit acquire(@NonNull Duration remainingBudget);

    /**
     * One caller-thread permit. A restore barrier must wait for its close before replacing
     * authoritative state. {@link #isCurrent()} can revoke admission while an operation runs;
     * after a possible write, that condition requires reconciliation rather than success.
     *
     * @since 1.0.0
     */
    @NotThreadSafe
    interface Permit extends AutoCloseable {
        /**
         * Checks that the external durable recovery marker and key state remain admitted.
         * @return true only while this permit still admits traffic
         * @since 1.0.0
         */
        boolean isCurrent();

        /** Releases this operation's restore barrier. @since 1.0.0 */
        @Override void close();
    }
}
